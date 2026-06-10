package storage

// codeAtRest hashes a short-lived code (device_code / user_code / OAuth
// authorization code) for storage and lookup when crypto keys are configured
// (ADR-002, keys-gated). These codes are short-lived, so the rollout drains
// naturally — no backfill. Returned models carry the plaintext code the caller
// supplied, never the stored hash.
func (s *Storage) codeAtRest(code string) string {
	if s.keys != nil {
		return s.keys.CodeHash(code)
	}
	return code
}
