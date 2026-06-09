package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// GenerateDEK returns a new random 32-byte data encryption key. Each account
// gets its own DEK; the DEK encrypts that account's PII and is itself stored
// only in wrapped (KEK-encrypted) form.
func GenerateDEK() ([]byte, error) {
	dek := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generate dek: %w", err)
	}
	return dek, nil
}

// KEK wraps and unwraps account DEKs. The Phase-1 implementation is a local
// master key injected from config (MasterKEK); a KMS/HSM adapter can implement
// the same interface without changing the DB schema or storage contract.
type KEK interface {
	// ID and Version identify this KEK so a wrapped DEK can be unwrapped by the
	// exact key version that produced it (supports rotation).
	ID() string
	Version() string
	// Wrap encrypts a DEK; Unwrap reverses it.
	Wrap(dek []byte) ([]byte, error)
	Unwrap(wrapped []byte) ([]byte, error)
}

// MasterKEK is a local AES-256 key-encryption key. Wrapping is AES-256-GCM, so
// a wrapped DEK is self-describing: nonce || ciphertext.
type MasterKEK struct {
	key     []byte
	id      string
	version string
}

// NewMasterKEK builds a local KEK from a 32-byte key plus an id/version label.
func NewMasterKEK(key []byte, id, version string) (*MasterKEK, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: KEK must be %d bytes, got %d", KeySize, len(key))
	}
	if id == "" || version == "" {
		return nil, errors.New("crypto: KEK id and version are required")
	}
	return &MasterKEK{key: key, id: id, version: version}, nil
}

func (k *MasterKEK) ID() string      { return k.id }
func (k *MasterKEK) Version() string { return k.version }

// Wrap returns nonce || ciphertext for the given DEK.
func (k *MasterKEK) Wrap(dek []byte) ([]byte, error) {
	ciphertext, nonce, err := Encrypt(k.key, dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: wrap dek: %w", err)
	}
	return append(nonce, ciphertext...), nil
}

// Unwrap reverses Wrap, splitting the leading nonce from the ciphertext.
func (k *MasterKEK) Unwrap(wrapped []byte) ([]byte, error) {
	if len(wrapped) < NonceSize {
		return nil, errors.New("crypto: wrapped dek too short")
	}
	nonce, ciphertext := wrapped[:NonceSize], wrapped[NonceSize:]
	dek, err := Decrypt(k.key, ciphertext, nonce)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap dek: %w", err)
	}
	return dek, nil
}
