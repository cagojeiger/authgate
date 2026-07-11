package storage

import (
	"database/sql"
	"fmt"

	"github.com/kangheeyong/authgate/internal/crypto"
	"github.com/kangheeyong/authgate/internal/db/storeq"
)

// piiCodec encrypts, decrypts and hashes user PII (email, name, provider
// subject) with the crypto subkeys (ADR-002). It owns only the keys, so the PII
// encrypt/decrypt/hash rules are unit-testable without a full Storage. Storage
// holds no codec state — it constructs one from its current keys per call via
// Storage.pii() — so key wiring stays single-sourced.
type piiCodec struct {
	keys *crypto.Keys
}

// applyUserEncryption fills the encrypted email/name + email_hash columns of an
// insert params struct from plaintext, leaving the plaintext columns NULL.
// Requires keys configured.
func (c piiCodec) applyUserEncryption(p *storeq.InsertUserParams, userID, email, name string) error {
	emailCT, emailNonce, err := c.keys.EncryptPII([]byte(email), crypto.FieldAAD(emailAADField, userID, c.keys.EncKeyID(), userPIIVersion))
	if err != nil {
		return fmt.Errorf("encrypt email: %w", err)
	}
	p.EmailCiphertext = emailCT
	p.EmailNonce = emailNonce
	p.EmailEncKeyID = nullStr(c.keys.EncKeyID())
	p.EmailEncVersion = nullI32(userPIIVersion)
	p.EmailHash = nullStr(c.keys.EmailHash(normalizeEmail(email)))
	p.EmailHashKeyID = nullStr(c.keys.LookupKeyID())
	p.EmailHashVersion = nullI32(userPIIVersion)

	if name != "" {
		nameCT, nameNonce, err := c.keys.EncryptPII([]byte(name), crypto.FieldAAD(nameAADField, userID, c.keys.EncKeyID(), userPIIVersion))
		if err != nil {
			return fmt.Errorf("encrypt name: %w", err)
		}
		p.NameCiphertext = nameCT
		p.NameNonce = nameNonce
		p.NameEncKeyID = nullStr(c.keys.EncKeyID())
		p.NameEncVersion = nullI32(userPIIVersion)
	}
	return nil
}

// resolveUser returns the plaintext email and name for a user row by decrypting
// the AEAD ciphertext columns. Keys are mandatory (ADR-002); the email is
// always present, while name is optional (empty when no ciphertext). The
// argument order matches the SELECTed column order so every user-returning
// query maps to it in one line.
func (c piiCodec) resolveUser(
	userID string,
	emailCipher, emailNonce []byte, emailEncKeyID sql.NullString, emailEncVersion sql.NullInt32,
	nameCipher, nameNonce []byte, nameEncKeyID sql.NullString, nameEncVersion sql.NullInt32,
) (email string, name sql.NullString, err error) {
	if c.keys == nil {
		return "", sql.NullString{}, ErrEncryptionNotConfigured
	}

	pt, derr := c.keys.DecryptPII(emailCipher, emailNonce, crypto.FieldAAD(emailAADField, userID, emailEncKeyID.String, int(emailEncVersion.Int32)))
	if derr != nil {
		return "", sql.NullString{}, fmt.Errorf("decrypt email: %w", derr)
	}
	email = string(pt)

	if len(nameCipher) > 0 {
		npt, derr := c.keys.DecryptPII(nameCipher, nameNonce, crypto.FieldAAD(nameAADField, userID, nameEncKeyID.String, int(nameEncVersion.Int32)))
		if derr != nil {
			return "", sql.NullString{}, fmt.Errorf("decrypt name: %w", derr)
		}
		name = nullStr(string(npt))
	}
	return email, name, nil
}

// encryptProviderSub derives the lookup hash and AEAD ciphertext columns for a
// provider subject under the configured keys. The AAD binds the ciphertext to
// the owning user_id so it cannot be replayed onto another row.
func (c piiCodec) encryptProviderSub(userID, provider, sub string) (providerSubColumns, error) {
	aad := crypto.FieldAAD(providerSubAADField, userID, c.keys.EncKeyID(), providerSubVersion)
	ciphertext, nonce, err := c.keys.EncryptPII([]byte(sub), aad)
	if err != nil {
		return providerSubColumns{}, fmt.Errorf("encrypt provider sub: %w", err)
	}
	return providerSubColumns{
		hash:       c.keys.ProviderSubHash(provider, sub),
		hashKeyID:  c.keys.LookupKeyID(),
		ciphertext: ciphertext,
		nonce:      nonce,
		encKeyID:   c.keys.EncKeyID(),
	}, nil
}
