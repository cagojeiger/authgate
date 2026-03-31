package idgen

import (
	"testing"
)

func TestCryptoGenerator_NewUUID(t *testing.T) {
	g := CryptoGenerator{}
	id := g.NewUUID()
	if len(id) != 36 { // UUID format: 8-4-4-4-12
		t.Errorf("NewUUID() length = %d, want 36", len(id))
	}
}

func TestCryptoGenerator_NewOpaqueToken(t *testing.T) {
	g := CryptoGenerator{}
	tok, err := g.NewOpaqueToken()
	if err != nil {
		t.Fatalf("NewOpaqueToken() error: %v", err)
	}
	if len(tok) < 40 { // base64url of 32 bytes = 43 chars
		t.Errorf("NewOpaqueToken() length = %d, want >= 40", len(tok))
	}
}

func TestSequentialGenerator(t *testing.T) {
	g := &SequentialGenerator{}

	id1 := g.NewUUID()
	id2 := g.NewUUID()
	if id1 == id2 {
		t.Error("sequential UUIDs should be different")
	}

	tok1, _ := g.NewOpaqueToken()
	tok2, _ := g.NewOpaqueToken()
	if tok1 == tok2 {
		t.Error("sequential tokens should be different")
	}
}
