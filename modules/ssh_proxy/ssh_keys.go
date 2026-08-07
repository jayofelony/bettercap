package ssh_proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"golang.org/x/crypto/ssh"
)

// generateHostKey creates an ephemeral ECDSA P-256 host key for the proxy.
func generateHostKey() (ssh.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %v", err)
	}
	return signer, nil
}

// loadHostKey loads a PEM-encoded private key from disk.
// Supports PEM (RSA, ECDSA, PKCS8) and OpenSSH format keys.
func loadHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %v", err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from %s: %v", path, err)
	}

	return signer, nil
}
