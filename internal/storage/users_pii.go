package storage

import (
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

// resolveUserPII returns the plaintext email and name for a user row by
// decrypting the AEAD ciphertext columns. Keys are mandatory (ADR-002); the
// email is always present, while name is optional (empty when no ciphertext).
// The argument order matches the SELECTed column order so every user-returning
// query maps to it in one line.
func (s *Storage) resolveUserPII(
	userID string,
	emailCipher, emailNonce []byte, emailEncKeyID sql.NullString, emailEncVersion sql.NullInt32,
	nameCipher, nameNonce []byte, nameEncKeyID sql.NullString, nameEncVersion sql.NullInt32,
) (email string, name sql.NullString, err error) {
	if s.keys == nil {
		return "", sql.NullString{}, ErrEncryptionNotConfigured
	}

	pt, derr := s.keys.DecryptPII(emailCipher, emailNonce, crypto.FieldAAD(emailAADField, userID, emailEncKeyID.String, int(emailEncVersion.Int32)))
	if derr != nil {
		return "", sql.NullString{}, fmt.Errorf("decrypt email: %w", derr)
	}
	email = string(pt)

	if len(nameCipher) > 0 {
		npt, derr := s.keys.DecryptPII(nameCipher, nameNonce, crypto.FieldAAD(nameAADField, userID, nameEncKeyID.String, int(nameEncVersion.Int32)))
		if derr != nil {
			return "", sql.NullString{}, fmt.Errorf("decrypt name: %w", derr)
		}
		name = nullStr(string(npt))
	}
	return email, name, nil
}
