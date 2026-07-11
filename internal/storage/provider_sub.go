package storage

import (
	"database/sql"
	"errors"

	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// ErrEncryptionNotConfigured is returned when an operation requires the PII
// crypto keys but none are wired in.
var ErrEncryptionNotConfigured = errors.New("storage: encryption not configured")

// providerSubVersion is the crypto material format version stored alongside
// provider_sub hash/ciphertext. Bump only with a matching migration.
const providerSubVersion = 1

// providerSubAADField is the stable crypto field id used in the AEAD AAD.
const providerSubAADField = "user_identities.provider_sub"

type providerSubColumns struct {
	hash       string
	hashKeyID  string
	ciphertext []byte
	nonce      []byte
	encKeyID   string
}

// encryptProviderSub lives on piiCodec (pii_codec.go); providerSubColumns and
// its applyTo mapping stay here with the other user-identity column code.

// applyTo fills the encrypted provider_sub columns of an insert params struct.
func (c providerSubColumns) applyTo(p *storeq.InsertUserIdentityParams) {
	p.ProviderSubHash = sql.NullString{String: c.hash, Valid: true}
	p.ProviderSubHashKeyID = sql.NullString{String: c.hashKeyID, Valid: true}
	p.ProviderSubHashVersion = sql.NullInt32{Int32: providerSubVersion, Valid: true}
	p.ProviderSubCiphertext = c.ciphertext
	p.ProviderSubNonce = c.nonce
	p.ProviderSubEncKeyID = sql.NullString{String: c.encKeyID, Valid: true}
	p.ProviderSubEncVersion = sql.NullInt32{Int32: providerSubVersion, Valid: true}
}
