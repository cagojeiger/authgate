package op

import (
	"crypto/rsa"

	"github.com/go-jose/go-jose/v4"
)

type signingKey struct {
	id  string
	key *rsa.PrivateKey
}

func (s *signingKey) SignatureAlgorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (s *signingKey) Key() any {
	return s.key
}

func (s *signingKey) ID() string {
	return s.id
}

type publicKey struct {
	id  string
	key *rsa.PublicKey
}

func (p *publicKey) Algorithm() jose.SignatureAlgorithm {
	return jose.RS256
}

func (p *publicKey) Use() string {
	return "sig"
}

func (p *publicKey) Key() any {
	return p.key
}

func (p *publicKey) ID() string {
	return p.id
}
