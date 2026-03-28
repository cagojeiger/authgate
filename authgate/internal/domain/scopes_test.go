package domain

import (
	"testing"
)

func TestContainsScope(t *testing.T) {
	tests := []struct {
		name     string
		scopes   []string
		scope    string
		expected bool
	}{
		{
			name:     "exists",
			scopes:   []string{"openid", "profile", "email"},
			scope:    "profile",
			expected: true,
		},
		{
			name:     "not-exists",
			scopes:   []string{"openid", "profile"},
			scope:    "email",
			expected: false,
		},
		{
			name:     "empty-list",
			scopes:   []string{},
			scope:    "openid",
			expected: false,
		},
		{
			name:     "nil-list",
			scopes:   nil,
			scope:    "openid",
			expected: false,
		},
		{
			name:     "empty-scope",
			scopes:   []string{"openid"},
			scope:    "",
			expected: false,
		},
		{
			name:     "substring-no-match",
			scopes:   []string{"profile_email"},
			scope:    "email",
			expected: false,
		},
		{
			name:     "case-sensitive",
			scopes:   []string{"openid", "Profile"},
			scope:    "profile",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ContainsScope(tt.scopes, tt.scope)
			if result != tt.expected {
				t.Errorf("ContainsScope(%v, %q) = %v, want %v",
					tt.scopes, tt.scope, result, tt.expected)
			}
		})
	}
}

func TestContainsScope_OpenID(t *testing.T) {
	standardScopes := []string{"openid", "profile", "email"}
	if !ContainsScope(standardScopes, "openid") {
		t.Error("Expected to find 'openid' in standard scopes")
	}

	noOpenID := []string{"profile", "email"}
	if ContainsScope(noOpenID, "openid") {
		t.Error("Should not find 'openid' when not present")
	}
}
