package idgen

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
)

// IDGenerator creates IDs and opaque tokens.
// device_code/user_code are NOT here — zitadel generates them internally.
type IDGenerator interface {
	NewUUID() string
	NewOpaqueToken() (string, error)
}

// CryptoGenerator uses crypto/rand for production-grade randomness.
type CryptoGenerator struct{}

func (CryptoGenerator) NewUUID() string {
	return uuid.NewString()
}

func (CryptoGenerator) NewOpaqueToken() (string, error) {
	b := make([]byte, 32) // 256-bit entropy
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// SequentialGenerator returns predictable values for tests.
type SequentialGenerator struct {
	counter int
}

func (g *SequentialGenerator) NewUUID() string {
	g.counter++
	return fmt.Sprintf("00000000-0000-0000-0000-%012d", g.counter)
}

func (g *SequentialGenerator) NewOpaqueToken() (string, error) {
	g.counter++
	return fmt.Sprintf("token-%d", g.counter), nil
}
