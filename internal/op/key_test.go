package op

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v4"
	zop "github.com/zitadel/oidc/v3/pkg/op"
)

func TestSigningKey_Interface(t *testing.T) {
	var _ zop.SigningKey = &signingKey{}
}

func TestPublicKey_Interface(t *testing.T) {
	var _ zop.Key = &publicKey{}
}

func TestSigningKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	sk := &signingKey{id: "key-1", key: key}

	if sk.ID() != "key-1" {
		t.Errorf("ID() = %q, want key-1", sk.ID())
	}
	if sk.SignatureAlgorithm() != jose.RS256 {
		t.Errorf("SignatureAlgorithm() = %v, want RS256", sk.SignatureAlgorithm())
	}
	if sk.Key() != key {
		t.Error("Key() did not return the expected key")
	}
}

func TestPublicKey(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	pk := &publicKey{id: "key-1", key: &key.PublicKey}

	if pk.ID() != "key-1" {
		t.Errorf("ID() = %q, want key-1", pk.ID())
	}
	if pk.Algorithm() != jose.RS256 {
		t.Errorf("Algorithm() = %v, want RS256", pk.Algorithm())
	}
	if pk.Use() != "sig" {
		t.Errorf("Use() = %q, want sig", pk.Use())
	}
	if pk.Key() != &key.PublicKey {
		t.Error("Key() did not return the expected public key")
	}
}
