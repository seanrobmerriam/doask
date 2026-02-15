package main

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/syslog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/seanrobmerriam/doask/internal/auth"
	"github.com/seanrobmerriam/doask/internal/proto"
)

const (
	defaultSocketPath     = "/var/run/dk.sock"
	defaultAuthorizedKeys = "/etc/dk/authorized_keys"
	authTimeout           = 10 * time.Second
	defaultPath           = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

type config struct {
	socketPath     string
	authorizedKeys string
}

type logger struct {
	stderr *log.Logger
	syslog *syslog.Writer
}

func (l *logger) infof(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.stderr.Printf("INFO: %s", msg)
	if l.syslog != nil {
		_ = l.syslog.Info(msg)
	}
}

func (l *logger) warningf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.stderr.Printf("WARN: %s", msg)
	if l.syslog != nil {
		_ = l.syslog.Warning(msg)
	}
}

func (l *logger) errorf(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.stderr.Printf("ERROR: %s", msg)
	if l.syslog != nil {
		_ = l.syslog.Err(msg)
	}
}

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("dkd", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	cfg := config{}
	fs.StringVar(&cfg.socketPath, "s", defaultSocketPath, "path to unix socket")
	fs.StringVar(&cfg.authorizedKeys, "a", defaultAuthorizedKeys, "path to authorized_keys allowlist")
	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dkd: %v\n", err)
		printUsage()
		return 1
	}

	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "dkd: must be run as root")
		return 1
	}

	sysLogger, err := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "dkd")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dkd: failed to initialize syslog: %v\n", err)
	}
	logr := &logger{
		stderr: log.New(os.Stderr, "", log.LstdFlags),
		syslog: sysLogger,
	}
	defer func() {
		if sysLogger != nil {
			_ = sysLogger.Close()
		}
	}()

	if err := os.MkdirAll(filepath.Dir(cfg.socketPath), 0o755); err != nil {
		logr.errorf("failed to create socket directory: %v", err)
		return 1
	}
	_ = os.Remove(cfg.socketPath)

	listener, err := net.Listen("unix", cfg.socketPath)
	if err != nil {
		logr.errorf("failed to listen on %s: %v", cfg.socketPath, err)
		return 1
	}
	defer listener.Close()
	if err := os.Chmod(cfg.socketPath, 0o666); err != nil {
		logr.errorf("failed to chmod socket: %v", err)
		return 1
	}
	logr.infof("listening on %s", cfg.socketPath)

	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	shutdown := make(chan struct{})
	go func() {
		<-signals
		logr.infof("received shutdown signal")
		close(shutdown)
		_ = listener.Close()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-shutdown:
				wg.Wait()
				_ = os.Remove(cfg.socketPath)
				logr.infof("socket cleaned up")
				return 0
			default:
				logr.warningf("accept failed: %v", err)
				continue
			}
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleConnection(c, cfg, logr)
		}(conn)
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: dkd [-a <authorized_keys>] [-s <socket>]")
}

func handleConnection(conn net.Conn, cfg config, logr *logger) {
	defer conn.Close()
	pconn := proto.NewConn(conn)

	if err := conn.SetDeadline(time.Now().Add(authTimeout)); err != nil {
		logr.warningf("failed setting auth deadline: %v", err)
	}
	challenge := proto.Challenge{Nonce: make([]byte, 32)}
	if _, err := rand.Read(challenge.Nonce); err != nil {
		logr.errorf("failed generating nonce: %v", err)
		return
	}
	if err := pconn.Send(&proto.Message{
		Type:      proto.TypeChallenge,
		Challenge: &challenge,
	}); err != nil {
		logr.warningf("failed sending challenge: %v", err)
		return
	}

	msg, err := pconn.Recv()
	if err != nil {
		logr.warningf("failed receiving auth request: %v", err)
		return
	}
	if msg.Type != proto.TypeAuthRequest || msg.AuthRequest == nil {
		logr.warningf("invalid auth message type: %q", msg.Type)
		_ = sendAuthFailed(pconn)
		return
	}

	authReq := msg.AuthRequest
	if ok, reason := verifyAuthRequest(authReq, challenge.Nonce, cfg.authorizedKeys); !ok {
		logr.warningf("authentication failed user=%q key=%q reason=%s", authReq.Username, truncateKey(authReq.PublicKey), reason)
		_ = sendAuthFailed(pconn)
		return
	}
	logr.infof("authentication succeeded user=%q key=%q command=%q", authReq.Username, truncateKey(authReq.PublicKey), strings.Join(authReq.Command, " "))

	if err := conn.SetDeadline(time.Time{}); err != nil {
		logr.warningf("failed clearing deadlines: %v", err)
	}

	result := executeCommand(pconn, authReq)
	if err := pconn.Send(&proto.Message{
		Type:       proto.TypeExecResult,
		ExecResult: &result,
	}); err != nil {
		logr.warningf("failed sending exec result: %v", err)
	}
}

func sendAuthFailed(pconn *proto.Conn) error {
	return pconn.Send(&proto.Message{
		Type: proto.TypeExecResult,
		ExecResult: &proto.ExecResult{
			ExitCode: 1,
			Error:    "authentication failed",
		},
	})
}

func verifyAuthRequest(req *proto.AuthRequest, nonce []byte, authorizedKeysPath string) (bool, string) {
	pubKey, err := auth.ParsePublicKeyLine(req.PublicKey)
	if err != nil {
		return false, "invalid public key"
	}

	allowed, err := auth.PublicKeyAuthorized(authorizedKeysPath, pubKey)
	if err != nil {
		return false, fmt.Sprintf("cannot read allowlist: %v", err)
	}
	if !allowed {
		return false, "public key not authorized"
	}

	if err := auth.VerifySignature(pubKey, nonce, req.Signature); err != nil {
		return false, "signature verification failed"
	}

	if len(req.Command) == 0 {
		return false, "missing command"
	}

	return true, ""
}

func executeCommand(pconn *proto.Conn, req *proto.AuthRequest) proto.ExecResult {
	cmd := exec.Command(req.Command[0], req.Command[1:]...)
	cmd.Dir = pickWorkingDirectory(req.WorkDir)
	cmd.Env = buildEnv(req.Env)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return proto.ExecResult{ExitCode: 1, Error: fmt.Sprintf("failed to set stdin: %v", err)}
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return proto.ExecResult{ExitCode: 1, Error: fmt.Sprintf("failed to set stdout: %v", err)}
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return proto.ExecResult{ExitCode: 1, Error: fmt.Sprintf("failed to set stderr: %v", err)}
	}

	if err := cmd.Start(); err != nil {
		return startErrorResult(err)
	}

	// Receive stdin frames while command runs.
	go func() {
		defer stdinPipe.Close()
		for {
			msg, err := pconn.Recv()
			if err != nil {
				return
			}
			if msg.Type != proto.TypeStream || msg.Stream == nil || msg.Stream.Stream != "stdin" {
				continue
			}
			if len(msg.Stream.Data) > 0 {
				if _, err := stdinPipe.Write(msg.Stream.Data); err != nil {
					return
				}
			}
			if msg.Stream.EOF {
				return
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = forwardOutput(pconn, "stdout", stdoutPipe)
	}()
	go func() {
		defer wg.Done()
		_ = forwardOutput(pconn, "stderr", stderrPipe)
	}()

	waitErr := cmd.Wait()
	wg.Wait()

	if waitErr == nil {
		return proto.ExecResult{ExitCode: 0}
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return proto.ExecResult{ExitCode: exitErr.ExitCode()}
	}
	return proto.ExecResult{
		ExitCode: 1,
		Error:    waitErr.Error(),
	}
}

func forwardOutput(pconn *proto.Conn, streamName string, r io.Reader) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if sendErr := pconn.Send(&proto.Message{
				Type: proto.TypeStream,
				Stream: &proto.StreamChunk{
					Stream: streamName,
					Data:   chunk,
				},
			}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func startErrorResult(err error) proto.ExecResult {
	var pathErr *os.PathError
	if errors.Is(err, exec.ErrNotFound) || errors.As(err, &pathErr) {
		return proto.ExecResult{
			ExitCode: 127,
			Error:    err.Error(),
		}
	}
	return proto.ExecResult{
		ExitCode: 1,
		Error:    err.Error(),
	}
}

func pickWorkingDirectory(workDir string) string {
	if workDir == "" {
		return "/root"
	}
	info, err := os.Stat(workDir)
	if err != nil || !info.IsDir() {
		return "/root"
	}
	return workDir
}

func buildEnv(rawEnv []string) []string {
	allowed := map[string]bool{
		"PATH": true,
		"TERM": true,
		"LANG": true,
	}

	selected := map[string]string{}
	for _, entry := range rawEnv {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if allowed[key] {
			selected[key] = value
		}
	}
	if selected["PATH"] == "" {
		selected["PATH"] = defaultPath
	}
	selected["HOME"] = "/root"
	selected["USER"] = "root"
	selected["LOGNAME"] = "root"

	keys := make([]string, 0, len(selected))
	for k := range selected {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s=%s", k, selected[k]))
	}
	return out
}

func truncateKey(keyLine string) string {
	if len(keyLine) <= 48 {
		return keyLine
	}
	return keyLine[:48] + "..."
}
