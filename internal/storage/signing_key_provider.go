package storage

import (
	"crypto/rsa"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// signingKeyProvider owns the RSA signing material for JWT issuance and JWKS
// publication, including the 2-slot current/previous rotation overlap. Storage
// holds one and its op.Storage signing methods delegate here, keeping key
// management out of the Storage adapter (#301).
type signingKeyProvider struct {
	current    *rsa.PrivateKey
	currentID  string
	previous   *rsa.PrivateKey
	previousID string
}

// SetCurrent sets the current RSA signing key used for JWT issuance.
func (p *signingKeyProvider) SetCurrent(key *rsa.PrivateKey, keyID string) {
	p.current = key
	p.currentID = keyID
}

// SetPrevious sets the previous signing key for 2-slot rotation. JWKS returns
// both keys; JWTs are signed with the current key only.
func (p *signingKeyProvider) SetPrevious(key *rsa.PrivateKey, keyID string) {
	p.previous = key
	p.previousID = keyID
}

// SigningKey returns the current key for JWT signing, or an error when no key
// is configured.
func (p *signingKeyProvider) SigningKey() (op.SigningKey, error) {
	if p.current == nil {
		return nil, errors.New("no signing key configured")
	}
	return &signingKeyModel{
		id:        p.currentID,
		algorithm: jose.RS256,
		key:       p.current,
	}, nil
}

func (p *signingKeyProvider) SignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256}
}

// KeySet returns the public keys for JWKS: the current key, plus the previous
// key while a 2-slot rotation overlap is configured.
func (p *signingKeyProvider) KeySet() []op.Key {
	if p.current == nil {
		return nil
	}
	keys := []op.Key{
		&publicKeyModel{
			id:        p.currentID,
			algorithm: jose.RS256,
			key:       &p.current.PublicKey,
		},
	}
	if p.previous != nil {
		keys = append(keys, &publicKeyModel{
			id:        p.previousID,
			algorithm: jose.RS256,
			key:       &p.previous.PublicKey,
		})
	}
	return keys
}
