package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// SetKeys wires the PII at-rest crypto subkeys derived from the env roots
// (ADR-002). Called once at startup after EnsureCryptoEpochs succeeds; until
// then encryption is inert.
func (s *Storage) SetKeys(k *crypto.Keys) { s.keys = k }

// Keys returns the configured crypto subkeys, or nil if encryption is
// unconfigured (the encrypting consumers must guard on this).
func (s *Storage) Keys() *crypto.Keys { return s.keys }

// EnsureCryptoEpochs registers/validates the active crypto_key_epochs rows for
// the enc and lookup domains against the configured roots (ADR-002). It is
// idempotent: it creates the active epoch on first run, and on later runs
// verifies the configured key_id and verify_tag match the stored active epoch.
// A mismatch (wrong root secret) or a different active key_id (runtime rotation
// attempt) returns an error so startup fails before any data is touched.
//
// No-op when keys are unset (encryption inert).
func (s *Storage) EnsureCryptoEpochs(ctx context.Context) error {
	if s.keys == nil {
		return nil
	}
	q := storeq.New(s.db)
	domains := []struct{ domain, keyID string }{
		{crypto.DomainEnc, s.keys.EncKeyID()},
		{crypto.DomainLookup, s.keys.LookupKeyID()},
	}
	for _, d := range domains {
		tag, err := s.keys.VerifyTag(d.domain)
		if err != nil {
			return err
		}
		row, err := q.GetActiveEpoch(ctx, d.domain)
		if errors.Is(err, sql.ErrNoRows) {
			// First run: register the active epoch. ON CONFLICT DO NOTHING makes
			// concurrent startups safe; we re-read the persisted winner.
			if err := q.InsertActiveEpoch(ctx, storeq.InsertActiveEpochParams{
				KeyID:     d.keyID,
				Domain:    d.domain,
				VerifyTag: tag,
				CreatedAt: s.clock.Now(),
			}); err != nil {
				return fmt.Errorf("insert %s epoch: %w", d.domain, err)
			}
			row, err = q.GetActiveEpoch(ctx, d.domain)
			if err != nil {
				return fmt.Errorf("reload %s epoch: %w", d.domain, err)
			}
		} else if err != nil {
			return fmt.Errorf("get %s epoch: %w", d.domain, err)
		}

		if row.KeyID != d.keyID {
			return fmt.Errorf("crypto: active %s epoch key_id=%q but configured key_id=%q; runtime rotation is not supported", d.domain, row.KeyID, d.keyID)
		}
		if row.VerifyTag != tag {
			return fmt.Errorf("crypto: %s epoch %q verify_tag mismatch; wrong root secret injected for this key_id", d.domain, d.keyID)
		}
	}
	return nil
}
