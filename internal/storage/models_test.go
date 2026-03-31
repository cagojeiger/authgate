package storage

import "testing"

func TestAuthRequestAudience_UsesResourceWhenPresent(t *testing.T) {
	req := &AuthRequestModel{ClientID: "browser-client"}
	if got := req.GetAudience(); len(got) != 1 || got[0] != "browser-client" {
		t.Fatalf("audience without resource = %v, want [browser-client]", got)
	}

	req.Resource = "https://mcp.example.com"
	if got := req.GetAudience(); len(got) != 1 || got[0] != "https://mcp.example.com" {
		t.Fatalf("audience with resource = %v, want [https://mcp.example.com]", got)
	}
}

func TestRefreshTokenAudience_UsesResourceWhenPresent(t *testing.T) {
	req := &RefreshTokenModel{ClientID: "mcp-client"}
	if got := req.GetAudience(); len(got) != 1 || got[0] != "mcp-client" {
		t.Fatalf("audience without resource = %v, want [mcp-client]", got)
	}

	req.Resource = "https://mcp.example.com"
	if got := req.GetAudience(); len(got) != 1 || got[0] != "https://mcp.example.com" {
		t.Fatalf("audience with resource = %v, want [https://mcp.example.com]", got)
	}
}
