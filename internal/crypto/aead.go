// Package crypto implements authgate's at-rest encryption/hashing primitives
// (ADR-002), following notegate's crypto_key_epochs model: two env-injected
// domain roots (enc, lookup) whose purpose-specific subkeys are derived via
// HKDF-SHA256. Raw key material lives outside the database; the DB stores only
// key_id/version references and epoch metadata. These are low-level primitives —
// field wiring lives in the storage layer.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KeySize is the required AES-256 / subkey length in bytes.
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

// Encrypt seals plaintext with AES-256-GCM under key, binding the additional
// authenticated data (aad). It returns the ciphertext and the fresh random
// nonce. A new nonce is generated on every call; callers MUST persist it and
// MUST NOT reuse it. The same aad must be supplied to Decrypt.
func Encrypt(key, plaintext, aad []byte) (ciphertext, nonce []byte, err error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, fmt.Errorf("crypto: read nonce: %w", err)
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return ciphertext, nonce, nil
}

// Decrypt opens an AES-256-GCM ciphertext produced by Encrypt. It fails if the
// key, nonce, or aad is wrong, or the ciphertext was tampered with.
func Decrypt(key, ciphertext, nonce, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("crypto: invalid nonce size")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return plaintext, nil
}
