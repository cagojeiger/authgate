package domain

// ContainsScope checks if a scope exists in the provided scope list.
// This function performs an exact string match (case-sensitive).
// This function is pure - it has no side effects and always returns the same output for the same input.
//
// Examples:
//   - ContainsScope([]string{"openid", "profile"}, "profile") -> true
//   - ContainsScope([]string{"openid", "profile"}, "email") -> false
//   - ContainsScope([]string{"openid"}, "Profile") -> false (case-sensitive)
//   - ContainsScope(nil, "openid") -> false
func ContainsScope(scopes []string, scope string) bool {
	for _, s := range scopes {
		if s == scope {
			return true
		}
	}
	return false
}
