package storage

// Keys-at-rest model (ADR-002), documented in one place per #305.
//
// Since keys became mandatory (#311, migration 014 dropped plaintext PII), the
// two hashing/encryption paths differ only in their nil-key handling:
//
//   - Short-lived lookups (codeAtRest / sessionAtRest below): unconditional.
//     A device_code / user_code / session token is always hashed with the
//     lookup HMAC. There is no `s.keys != nil` gate anymore — a nil key is a
//     wiring bug in production, not a supported state, so these panic-by-deref
//     rather than silently storing plaintext. Rows written under an old key
//     epoch stop resolving the instant the lookup root rotates; that is
//     acceptable because they are short-lived and self-heal within their TTL
//     (a re-login / re-issue mints a row under the current key).
//
//   - Durable PII (resolveUserPII in users_pii.go): defensive. It returns
//     ErrEncryptionNotConfigured when s.keys is nil rather than dereferencing,
//     because a user row outlives key wiring and must fail closed, and it
//     decrypts each field only when ciphertext is present (the optional `name`
//     may be absent) so a partially-populated row still resolves.

// codeAtRest hashes a short-lived code (device_code / user_code / OAuth
// authorization code) for storage and lookup with the lookup HMAC subkey
// (ADR-002). Keys are mandatory, so this is unconditional. Returned models carry
// the plaintext code the caller supplied, never the stored hash.
func (s *Storage) codeAtRest(code string) string {
	return s.keys.CodeHash(code)
}

// sessionAtRest hashes a session bearer token for storage/lookup with the
// lookup/session HMAC subkey (ADR-002). Used for sessions.token_hash and the
// audit session_id so both correlate. Keys are mandatory, so this is
// unconditional.
func (s *Storage) sessionAtRest(token string) string {
	return s.keys.SessionHash(token)
}
