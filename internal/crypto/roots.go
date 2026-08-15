package crypto

import (
	"crypto/hkdf"
	"crypto/sha256"
	"errors"
	"fmt"
)

// Domains separate decryptable PII (enc) from comparison/verification values
// (lookup). The same raw root secret is never reused across domains.
const (
	DomainEnc    = "enc"
	DomainLookup = "lookup"
)

// HKDF purpose labels — code constants, NOT secrets. They provide domain
// separation between subkeys derived from the same root. Bump the trailing /vN
// only together with a crypto material version migration.
const (
	LabelEncEpochVerify    = "authgate/enc/epoch-verify/v1"
	LabelPIIField          = "authgate/enc/pii-field/v1"
	LabelLookupEpochVerify = "authgate/lookup/epoch-verify/v1"
	LabelProviderSub       = "authgate/lookup/provider-sub/v1"
	LabelEmail             = "authgate/lookup/email/v1"
	LabelCode              = "authgate/lookup/code/v1"
	LabelSession           = "authgate/lookup/session/v1"
	LabelRefresh           = "authgate/lookup/refresh/v1"
)

// Root is a domain root secret (loaded from env). Its raw bytes are never used
// directly for crypto — only HKDF-derived purpose subkeys are.
type Root struct {
	domain string
	keyID  string
	secret []byte
}

// NewRoot validates and wraps a domain root secret.
func NewRoot(domain, keyID string, secret []byte) (*Root, error) {
	if domain != DomainEnc && domain != DomainLookup {
		return nil, fmt.Errorf("crypto: unknown domain %q", domain)
	}
	if keyID == "" {
		return nil, errors.New("crypto: root key_id is required")
	}
	if len(secret) < KeySize {
		return nil, fmt.Errorf("crypto: %s root secret must be >= %d bytes, got %d", domain, KeySize, len(secret))
	}
	return &Root{domain: domain, keyID: keyID, secret: secret}, nil
}

// subkey derives a 32-byte purpose subkey via HKDF-SHA256 for the given label.
func (r *Root) subkey(label string) ([]byte, error) {
	key, err := hkdf.Key(sha256.New, r.secret, nil, label, KeySize)
	if err != nil {
		return nil, fmt.Errorf("crypto: hkdf derive %q: %w", label, err)
	}
	return key, nil
}
