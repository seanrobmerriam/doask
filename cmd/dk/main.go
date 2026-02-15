package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strings"
	"sync"

	"github.com/seanrobmerriam/doask/internal/auth"
	"github.com/seanrobmerriam/doask/internal/proto"
	"golang.org/x/term"
)

const defaultSocketPath = "/var/run/dk.sock"

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("dk", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	privateKeyPath := fs.String("k", "", "path to SSH private key")
	socketPath := fs.String("s", defaultSocketPath, "path to dkd socket")

	if err := fs.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "dk: %v\n", err)
		printUsage()
		return 1
	}
	command := fs.Args()
	if len(command) == 0 {
		printUsage()
		return 1
	}

	keyPath := *privateKeyPath
	if keyPath == "" {
		var err error
		keyPath, err = auth.DefaultPrivateKeyPath()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dk: %v\n", err)
			return 1
		}
	}

	signer, err := auth.LoadSignerFromFile(keyPath, func(_ string) ([]byte, error) {
		fmt.Fprintf(os.Stderr, "Enter passphrase for %s: ", keyPath)
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return pass, err
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dk: %v\n", err)
		return 1
	}

	conn, err := net.Dial("unix", *socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dk: %v\n", err)
		return 1
	}
	defer conn.Close()

	pconn := proto.NewConn(conn)
	msg, err := pconn.Recv()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dk: failed to receive challenge: %v\n", err)
		return 1
	}
	if msg.Type != proto.TypeChallenge || msg.Challenge == nil {
		fmt.Fprintln(os.Stderr, "dk: invalid daemon response")
		return 1
	}

	sigBlob, err := auth.SignNonce(signer, msg.Challenge.Nonce)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dk: %v\n", err)
		return 1
	}

	wd, err := os.Getwd()
	if err != nil {
		wd = "/"
	}

	username := os.Getenv("USER")
	if currentUser, err := user.Current(); err == nil && currentUser.Username != "" {
		username = currentUser.Username
	}

	req := &proto.AuthRequest{
		Username:  username,
		PublicKey: auth.PublicKeyToAuthorizedLine(signer.PublicKey()),
		Signature: sigBlob,
		Command:   command,
		WorkDir:   wd,
		Env:       os.Environ(),
	}
	if err := pconn.Send(&proto.Message{
		Type:        proto.TypeAuthRequest,
		AuthRequest: req,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "dk: failed to send auth request: %v\n", err)
		return 1
	}

	var sendErrMu sync.Mutex
	var sendErr error
	go func() {
		if err := streamStdin(pconn); err != nil && !errors.Is(err, io.EOF) {
			sendErrMu.Lock()
			sendErr = err
			sendErrMu.Unlock()
		}
	}()

	for {
		in, err := pconn.Recv()
		if err != nil {
			sendErrMu.Lock()
			errOut := sendErr
			sendErrMu.Unlock()
			if errOut != nil {
				fmt.Fprintf(os.Stderr, "dk: %v\n", errOut)
			}
			fmt.Fprintf(os.Stderr, "dk: %v\n", err)
			return 1
		}

		switch in.Type {
		case proto.TypeStream:
			if in.Stream == nil {
				continue
			}
			switch in.Stream.Stream {
			case "stdout":
				if len(in.Stream.Data) > 0 {
					if _, err := os.Stdout.Write(in.Stream.Data); err != nil {
						fmt.Fprintf(os.Stderr, "dk: %v\n", err)
						return 1
					}
				}
			case "stderr":
				if len(in.Stream.Data) > 0 {
					if _, err := os.Stderr.Write(in.Stream.Data); err != nil {
						fmt.Fprintf(os.Stderr, "dk: %v\n", err)
						return 1
					}
				}
			}
		case proto.TypeExecResult:
			if in.ExecResult == nil {
				fmt.Fprintln(os.Stderr, "dk: missing execution result")
				return 1
			}
			return handleExecResult(in.ExecResult)
		default:
			fmt.Fprintf(os.Stderr, "dk: unexpected message type %q\n", in.Type)
			return 1
		}
	}
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "Usage: dk [-k <private-key>] [-s <socket>] <command> [args...]")
}

func streamStdin(pconn *proto.Conn) error {
	buf := make([]byte, 32*1024)
	for {
		n, err := os.Stdin.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			if sendErr := pconn.Send(&proto.Message{
				Type: proto.TypeStream,
				Stream: &proto.StreamChunk{
					Stream: "stdin",
					Data:   chunk,
				},
			}); sendErr != nil {
				return sendErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return pconn.Send(&proto.Message{
					Type: proto.TypeStream,
					Stream: &proto.StreamChunk{
						Stream: "stdin",
						EOF:    true,
					},
				})
			}
			return err
		}
	}
}

func handleExecResult(result *proto.ExecResult) int {
	if result.Error != "" {
		if strings.EqualFold(result.Error, "authentication failed") {
			fmt.Fprintln(os.Stderr, "dk: authentication failed")
			return 1
		}
		fmt.Fprintf(os.Stderr, "dk: %s\n", result.Error)
	}
	if result.ExitCode < 0 {
		return 1
	}
	return result.ExitCode
}
