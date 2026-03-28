package domain

import (
	"testing"
	"time"
)

func TestGenerateState(t *testing.T) {
	now := time.Now()
	state := GenerateState("req123", "client1", "http://localhost/callback", "openid profile", "challenge123", "nonce456")

	if state == "" {
		t.Error("GenerateState() returned empty string")
	}

	parsed := ParseState(state)

	if parsed.OriginalReq != "req123" {
		t.Errorf("ParseState().OriginalReq = %q, want %q", parsed.OriginalReq, "req123")
	}
	if parsed.ClientID != "client1" {
		t.Errorf("ParseState().ClientID = %q, want %q", parsed.ClientID, "client1")
	}
	if parsed.RedirectURI != "http://localhost/callback" {
		t.Errorf("ParseState().RedirectURI = %q, want %q", parsed.RedirectURI, "http://localhost/callback")
	}
	if parsed.Scope != "openid profile" {
		t.Errorf("ParseState().Scope = %q, want %q", parsed.Scope, "openid profile")
	}
	if parsed.Challenge != "challenge123" {
		t.Errorf("ParseState().Challenge = %q, want %q", parsed.Challenge, "challenge123")
	}
	if parsed.Nonce != "nonce456" {
		t.Errorf("ParseState().Nonce = %q, want %q", parsed.Nonce, "nonce456")
	}

	if parsed.Timestamp.Before(now.Add(-time.Second)) || parsed.Timestamp.After(now.Add(time.Second)) {
		t.Errorf("ParseState().Timestamp = %v, expected around %v", parsed.Timestamp, now)
	}
}

func TestParseState_Invalid(t *testing.T) {
	tests := []struct {
		name  string
		state string
	}{
		{"empty", ""},
		{"invalid_base64", "!!!"},
		{"wrong_format", "dGVzdA=="},
		{"too_few_parts", "cGFydDF8cGFydDI="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseState(tt.state)
			if result != (StateData{}) {
				t.Errorf("ParseState(%q) = %+v, expected zero value", tt.state, result)
			}
		})
	}
}

func TestStateData_Empty(t *testing.T) {
	data := StateData{}
	if data.OriginalReq != "" {
		t.Error("Expected empty OriginalReq")
	}
	if data.ClientID != "" {
		t.Error("Expected empty ClientID")
	}
	if !data.Timestamp.IsZero() {
		t.Error("Expected zero timestamp")
	}
}
