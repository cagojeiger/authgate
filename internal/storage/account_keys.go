package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

var (
	// ErrEncryptionNotConfigured is returned by the DEK manager when no KEK
	// provider has been wired in (PII encryption is inert).
	ErrEncryptionNotConfigured = errors.New("storage: encryption not configured")
	// ErrAccountKeyDestroyed is returned when an account's DEK has been
	// crypto-shredded; its PII ciphertext is permanently unrecoverable.
	ErrAccountKeyDestroyed = errors.New("storage: account encryption key destroyed")
)

// SetKEKProvider wires the key-encryption-key provider used to wrap/unwrap
// per-account DEKs (ADR-002). Called once at startup; until then the DEK
// manager is inert and authgate runs unchanged.
func (s *Storage) SetKEKProvider(p *crypto.KEKProvider) {
	s.kekProvider = p
}

// GetOrCreateAccountDEK returns the unwrapped per-account data encryption key,
// generating and persisting a fresh wrapped DEK on first use. It is safe under
// concurrent first-use: ON CONFLICT DO NOTHING means a concurrent caller may
// win the insert, and we always return the DEK that was actually persisted.
func (s *Storage) GetOrCreateAccountDEK(ctx context.Context, accountID string) ([]byte, error) {
	if s.kekProvider == nil {
		return nil, ErrEncryptionNotConfigured
	}
	q := storeq.New(s.db)

	dek, err := s.loadAccountDEK(ctx, q, accountID)
	if err == nil {
		return dek, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}

	// First use: generate a DEK, wrap it under the current KEK, persist it.
	newDEK, err := crypto.GenerateDEK()
	if err != nil {
		return nil, err
	}
	kek := s.kekProvider.Current()
	wrapped, err := kek.Wrap(newDEK)
	if err != nil {
		return nil, fmt.Errorf("wrap account dek: %w", err)
	}
	if err := q.InsertAccountEncryptionKey(ctx, storeq.InsertAccountEncryptionKeyParams{
		AccountID:  accountID,
		WrappedDek: wrapped,
		KekID:      kek.ID(),
		KekVersion: kek.Version(),
		CreatedAt:  s.clock.Now(),
	}); err != nil {
		return nil, fmt.Errorf("insert account dek: %w", err)
	}
	// Re-load so a concurrent winner's DEK (not ours) is the one we return.
	return s.loadAccountDEK(ctx, q, accountID)
}

func (s *Storage) loadAccountDEK(ctx context.Context, q *storeq.Queries, accountID string) ([]byte, error) {
	row, err := q.GetAccountEncryptionKey(ctx, accountID)
	if err != nil {
		return nil, err // includes sql.ErrNoRows when absent
	}
	if row.DestroyedAt.Valid {
		return nil, ErrAccountKeyDestroyed
	}
	kek, err := s.kekProvider.ByVersion(row.KekVersion)
	if err != nil {
		return nil, err
	}
	dek, err := kek.Unwrap(row.WrappedDek)
	if err != nil {
		return nil, fmt.Errorf("unwrap account dek: %w", err)
	}
	return dek, nil
}

// DestroyAccountDEK crypto-shreds an account's key: the wrapped DEK is cleared
// and destroyed_at is set, after which the account's PII ciphertext can never be
// decrypted again. Idempotent — destroying an already-destroyed key is a no-op.
// Must be called explicitly in the deletion path; ON DELETE CASCADE does not
// fire because account deletion is a soft UPDATE, not a row DELETE.
func (s *Storage) DestroyAccountDEK(ctx context.Context, accountID string) error {
	_, err := storeq.New(s.db).DestroyAccountEncryptionKey(ctx, storeq.DestroyAccountEncryptionKeyParams{
		AccountID:   accountID,
		DestroyedAt: sql.NullTime{Time: s.clock.Now(), Valid: true},
	})
	if err != nil {
		return fmt.Errorf("destroy account dek: %w", err)
	}
	return nil
}
