package storage

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
