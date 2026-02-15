package proto

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

const (
	TypeChallenge   = "challenge"
	TypeAuthRequest = "auth_request"
	TypeStream      = "stream"
	TypeExecResult  = "exec_result"
)

const maxMessageSize = 16 << 20 // 16 MiB

// Sent by daemon to client after connection.
type Challenge struct {
	Nonce []byte `json:"nonce"` // 32 random bytes, base64-encoded by JSON
}

// Sent by client to daemon.
type AuthRequest struct {
	Username  string   `json:"username"`
	PublicKey string   `json:"public_key"` // authorized_keys line format
	Signature []byte   `json:"signature"`  // base64-encoded SSH signature over nonce
	Command   []string `json:"command"`    // e.g. ["ls", "-la", "/root"]
	WorkDir   string   `json:"work_dir"`   // current working directory of client
	Env       []string `json:"env"`        // environment variables to forward
}

// Sent by daemon to client.
type ExecResult struct {
	ExitCode int    `json:"exit_code"`
	Error    string `json:"error,omitempty"`
}

// StreamChunk carries stdin/stdout/stderr data through the framed protocol.
type StreamChunk struct {
	Stream string `json:"stream"`         // stdin|stdout|stderr
	Data   []byte `json:"data,omitempty"` // base64-encoded by JSON
	EOF    bool   `json:"eof,omitempty"`
}

// Message is an envelope for all length-prefixed JSON protocol traffic.
type Message struct {
	Type        string       `json:"type"`
	Challenge   *Challenge   `json:"challenge,omitempty"`
	AuthRequest *AuthRequest `json:"auth_request,omitempty"`
	Stream      *StreamChunk `json:"stream,omitempty"`
	ExecResult  *ExecResult  `json:"exec_result,omitempty"`
}

// WriteJSON encodes v as JSON and writes it with a 4-byte big-endian length prefix.
func WriteJSON(w io.Writer, v any) error {
	payload, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if len(payload) > maxMessageSize {
		return fmt.Errorf("message too large: %d", len(payload))
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return fmt.Errorf("write header: %w", err)
	}
	if _, err := w.Write(payload); err != nil {
		return fmt.Errorf("write payload: %w", err)
	}
	return nil
}

// ReadJSON reads a 4-byte big-endian length prefix and decodes the JSON payload into v.
func ReadJSON(r io.Reader, v any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 {
		return errors.New("invalid zero-length message")
	}
	if size > maxMessageSize {
		return fmt.Errorf("message too large: %d", size)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	if err := json.Unmarshal(buf, v); err != nil {
		return fmt.Errorf("unmarshal json: %w", err)
	}
	return nil
}

// Conn wraps an io.ReadWriter for framed message send/recv.
type Conn struct {
	rw io.ReadWriter
	mu sync.Mutex
}

func NewConn(rw io.ReadWriter) *Conn {
	return &Conn{rw: rw}
}

func (c *Conn) Send(msg *Message) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return WriteJSON(c.rw, msg)
}

func (c *Conn) Recv() (*Message, error) {
	var msg Message
	if err := ReadJSON(c.rw, &msg); err != nil {
		return nil, err
	}
	return &msg, nil
}
