package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// ErrEncryptionNotConfigured is returned when an operation requires the PII
// crypto keys but none are wired in.
var ErrEncryptionNotConfigured = errors.New("storage: encryption not configured")

// providerSubVersion is the crypto material format version stored alongside
// provider_sub hash/ciphertext. Bump only with a matching migration.
const providerSubVersion = 1

// providerSubBackfillBatch bounds how many rows a single backfill query loads.
const providerSubBackfillBatch = 500

// providerSubAADField is the stable crypto field id used in the AEAD AAD.
const providerSubAADField = "user_identities.provider_sub"

type providerSubColumns struct {
	hash       string
	hashKeyID  string
	ciphertext []byte
	nonce      []byte
	encKeyID   string
}

// encryptProviderSub derives the lookup hash and AEAD ciphertext columns for a
// provider subject under the configured keys. The AAD binds the ciphertext to
// the owning user_id so it cannot be replayed onto another row.
func (s *Storage) encryptProviderSub(userID, provider, sub string) (providerSubColumns, error) {
	aad := crypto.FieldAAD(providerSubAADField, userID, s.keys.EncKeyID(), providerSubVersion)
	ciphertext, nonce, err := s.keys.EncryptPII([]byte(sub), aad)
	if err != nil {
		return providerSubColumns{}, fmt.Errorf("encrypt provider sub: %w", err)
	}
	return providerSubColumns{
		hash:       s.keys.ProviderSubHash(provider, sub),
		hashKeyID:  s.keys.LookupKeyID(),
		ciphertext: ciphertext,
		nonce:      nonce,
		encKeyID:   s.keys.EncKeyID(),
	}, nil
}

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

// ProviderSubBackfillRemaining counts identity rows still holding a plaintext
// provider_user_id without an encrypted hash — the gate that must reach 0 before
// the plaintext column can be dropped.
func (s *Storage) ProviderSubBackfillRemaining(ctx context.Context) (int64, error) {
	return storeq.New(s.db).CountProviderSubUnbackfilled(ctx)
}

// BackfillProviderSub encrypts every legacy plaintext provider_user_id into the
// provider_sub_hash/ciphertext columns. Idempotent (only touches rows missing a
// hash) and resumable (batched). Returns the number of rows backfilled.
func (s *Storage) BackfillProviderSub(ctx context.Context) (int, error) {
	if s.keys == nil {
		return 0, ErrEncryptionNotConfigured
	}
	q := storeq.New(s.db)
	total := 0
	for {
		rows, err := q.ListProviderSubBackfill(ctx, providerSubBackfillBatch)
		if err != nil {
			return total, fmt.Errorf("list provider_sub backfill: %w", err)
		}
		if len(rows) == 0 {
			return total, nil
		}
		for _, r := range rows {
			cols, err := s.encryptProviderSub(r.UserID, r.Provider, r.ProviderUserID.String)
			if err != nil {
				return total, err
			}
			if err := q.BackfillProviderSub(ctx, storeq.BackfillProviderSubParams{
				ID:                     r.ID,
				ProviderSubHash:        sql.NullString{String: cols.hash, Valid: true},
				ProviderSubHashKeyID:   sql.NullString{String: cols.hashKeyID, Valid: true},
				ProviderSubHashVersion: sql.NullInt32{Int32: providerSubVersion, Valid: true},
				ProviderSubCiphertext:  cols.ciphertext,
				ProviderSubNonce:       cols.nonce,
				ProviderSubEncKeyID:    sql.NullString{String: cols.encKeyID, Valid: true},
				ProviderSubEncVersion:  sql.NullInt32{Int32: providerSubVersion, Valid: true},
			}); err != nil {
				return total, fmt.Errorf("backfill provider_sub %s: %w", r.ID, err)
			}
			total++
		}
	}
}
