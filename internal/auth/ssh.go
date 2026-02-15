package auth

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

type PassphrasePrompt func(prompt string) ([]byte, error)

func DefaultPrivateKeyPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	candidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("no default key found (checked %s and %s)", candidates[0], candidates[1])
}

func LoadSignerFromFile(path string, prompt PassphrasePrompt) (ssh.Signer, error) {
	keyData, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	raw, err := parsePrivateKey(keyData, prompt)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(raw)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, nil
}

func parsePrivateKey(keyData []byte, prompt PassphrasePrompt) (any, error) {
	raw, err := ssh.ParseRawPrivateKey(keyData)
	if err == nil {
		return raw, nil
	}

	var passphraseMissing *ssh.PassphraseMissingError
	if !errors.As(err, &passphraseMissing) {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	if prompt == nil {
		return nil, fmt.Errorf("private key is passphrase-protected")
	}

	passphrase, err := prompt("Enter passphrase: ")
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}
	defer zero(passphrase)

	raw, err = ssh.ParseRawPrivateKeyWithPassphrase(keyData, passphrase)
	if err != nil {
		return nil, fmt.Errorf("parse private key with passphrase: %w", err)
	}
	return raw, nil
}

func SignNonce(signer ssh.Signer, nonce []byte) ([]byte, error) {
	sig, err := signer.Sign(rand.Reader, nonce)
	if err != nil {
		return nil, fmt.Errorf("sign nonce: %w", err)
	}
	return ssh.Marshal(sig), nil
}

func VerifySignature(pubKey ssh.PublicKey, nonce, signatureBlob []byte) error {
	var sig ssh.Signature
	if err := ssh.Unmarshal(signatureBlob, &sig); err != nil {
		return fmt.Errorf("parse signature: %w", err)
	}
	if err := pubKey.Verify(nonce, &sig); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}
	return nil
}

func ParsePublicKeyLine(line string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(line)))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return pub, nil
}

func PublicKeyToAuthorizedLine(pubKey ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pubKey)))
}

func PublicKeyAuthorized(path string, candidate ssh.PublicKey) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read authorized_keys: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, err := ParsePublicKeyLine(line)
		if err != nil {
			continue
		}
		if bytes.Equal(pub.Marshal(), candidate.Marshal()) {
			return true, nil
		}
	}
	return false, nil
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
