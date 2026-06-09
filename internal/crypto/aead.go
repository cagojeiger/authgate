// Package crypto provides the at-rest encryption/hashing primitives for
// authgate's sensitive-data protection policy (ADR-002): AES-256-GCM field
// encryption, keyed HMAC lookup hashing, and per-account DEK wrapping under a
// key-encryption key. Key material lives outside the database; callers pass it
// in. These are low-level primitives — field wiring lives in the storage layer.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the required AES-256 key length in bytes.
const KeySize = 32

// NonceSize is the AES-GCM nonce length in bytes (standard 96-bit nonce).
const NonceSize = 12

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// Encrypt seals plaintext with AES-256-GCM under key and returns the ciphertext
// together with the fresh random nonce it generated. A new nonce is produced on
// every call; callers MUST persist the returned nonce and MUST NOT reuse it.
func Encrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

// Decrypt opens an AES-256-GCM ciphertext produced by Encrypt. It returns an
// error if the key or nonce is wrong or the ciphertext was tampered with.
func Decrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("crypto: invalid nonce size")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
