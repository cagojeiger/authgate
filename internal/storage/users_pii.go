package storage

import (
	"database/sql"
	"strings"

	"golang.org/x/text/unicode/norm"
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

// PII encrypt/decrypt/hash logic lives on piiCodec (pii_codec.go); the
// constants and small null helpers below stay package-level as they are shared
// with other user-column mapping code.
