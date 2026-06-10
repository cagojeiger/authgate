package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"golang.org/x/text/unicode/norm"

	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

const (
	emailAADField     = "users.email"
	nameAADField      = "users.name"
	userPIIVersion    = 1
	userPIIBatch      = 500
	usersEmailHashKey = "users_email_hash_key"
)

// normalizeEmail canonicalizes an email for the lookup hash: Unicode NFC +
// trim + lowercase (ADR-002, provider-independent — no dot/plus handling).
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(norm.NFC.String(email)))
}

func nullStr(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
func nullI32(i int) sql.NullInt32     { return sql.NullInt32{Int32: int32(i), Valid: true} }

// applyUserPIIEncryption fills the encrypted email/name + email_hash columns of
// an insert params struct from plaintext, leaving the plaintext columns NULL.
// Requires keys configured.
func (s *Storage) applyUserPIIEncryption(p *storeq.InsertUserParams, userID, email, name string) error {
	emailCT, emailNonce, err := s.keys.EncryptPII([]byte(email), crypto.FieldAAD(emailAADField, userID, s.keys.EncKeyID(), userPIIVersion))
	if err != nil {
		return fmt.Errorf("encrypt email: %w", err)
	}
	p.EmailCiphertext = emailCT
	p.EmailNonce = emailNonce
	p.EmailEncKeyID = nullStr(s.keys.EncKeyID())
	p.EmailEncVersion = nullI32(userPIIVersion)
	p.EmailHash = nullStr(s.keys.EmailHash(normalizeEmail(email)))
	p.EmailHashKeyID = nullStr(s.keys.LookupKeyID())
	p.EmailHashVersion = nullI32(userPIIVersion)

	if name != "" {
		nameCT, nameNonce, err := s.keys.EncryptPII([]byte(name), crypto.FieldAAD(nameAADField, userID, s.keys.EncKeyID(), userPIIVersion))
		if err != nil {
			return fmt.Errorf("encrypt name: %w", err)
		}
		p.NameCiphertext = nameCT
		p.NameNonce = nameNonce
		p.NameEncKeyID = nullStr(s.keys.EncKeyID())
		p.NameEncVersion = nullI32(userPIIVersion)
	}
	return nil
}

// resolveUserPII returns the plaintext email and name for a user row, decrypting
// when keys are configured and the ciphertext is present, otherwise falling back
// to the legacy plaintext columns (keys-gated). The argument order matches the
// SELECTed column order so every user-returning query maps to it in one line.
func (s *Storage) resolveUserPII(
	userID string,
	emailPlain sql.NullString, emailCipher, emailNonce []byte, emailEncKeyID sql.NullString, emailEncVersion sql.NullInt32,
	namePlain sql.NullString, nameCipher, nameNonce []byte, nameEncKeyID sql.NullString, nameEncVersion sql.NullInt32,
) (email string, name sql.NullString, err error) {
	if s.keys != nil && len(emailCipher) > 0 {
		pt, derr := s.keys.DecryptPII(emailCipher, emailNonce, crypto.FieldAAD(emailAADField, userID, emailEncKeyID.String, int(emailEncVersion.Int32)))
		if derr != nil {
			return "", sql.NullString{}, fmt.Errorf("decrypt email: %w", derr)
		}
		email = string(pt)
	} else {
		email = emailPlain.String
	}

	if s.keys != nil && len(nameCipher) > 0 {
		pt, derr := s.keys.DecryptPII(nameCipher, nameNonce, crypto.FieldAAD(nameAADField, userID, nameEncKeyID.String, int(nameEncVersion.Int32)))
		if derr != nil {
			return "", sql.NullString{}, fmt.Errorf("decrypt name: %w", derr)
		}
		name = nullStr(string(pt))
	} else {
		name = namePlain
	}
	return email, name, nil
}

// UserPIIBackfillRemaining counts users still holding a plaintext email without
// an email_hash — the gate that must reach 0 before dropping plaintext columns.
func (s *Storage) UserPIIBackfillRemaining(ctx context.Context) (int64, error) {
	return storeq.New(s.db).CountUsersUnbackfilled(ctx)
}

// BackfillUserPII encrypts every legacy plaintext email/name into the ciphertext
// + email_hash columns. Idempotent (only rows missing email_hash) and batched.
func (s *Storage) BackfillUserPII(ctx context.Context) (int, error) {
	if s.keys == nil {
		return 0, ErrEncryptionNotConfigured
	}
	q := storeq.New(s.db)
	total := 0
	for {
		rows, err := q.ListUsersBackfill(ctx, userPIIBatch)
		if err != nil {
			return total, fmt.Errorf("list user backfill: %w", err)
		}
		if len(rows) == 0 {
			return total, nil
		}
		for _, r := range rows {
			var p storeq.InsertUserParams // reuse for column carriers only
			if err := s.applyUserPIIEncryption(&p, r.ID, r.Email.String, r.Name.String); err != nil {
				return total, err
			}
			if err := q.BackfillUserPII(ctx, storeq.BackfillUserPIIParams{
				ID:               r.ID,
				EmailCiphertext:  p.EmailCiphertext,
				EmailNonce:       p.EmailNonce,
				EmailEncKeyID:    p.EmailEncKeyID,
				EmailEncVersion:  p.EmailEncVersion,
				EmailHash:        p.EmailHash,
				EmailHashKeyID:   p.EmailHashKeyID,
				EmailHashVersion: p.EmailHashVersion,
				NameCiphertext:   p.NameCiphertext,
				NameNonce:        p.NameNonce,
				NameEncKeyID:     p.NameEncKeyID,
				NameEncVersion:   p.NameEncVersion,
			}); err != nil {
				return total, fmt.Errorf("backfill user %s: %w", r.ID, err)
			}
			total++
		}
	}
}
