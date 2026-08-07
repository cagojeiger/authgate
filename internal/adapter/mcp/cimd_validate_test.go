package mcp

import (
	"strings"
	"testing"
)

// These exercise the CIMD schema rules directly against a document body, with
// no HTTP server, cache or rate limiter — the isolation #303 aimed for.
func TestValidateCIMDMetadata_Valid(t *testing.T) {
	const id = "https://app.example.com/client.json"
	body := []byte(`{
		"client_id": "https://app.example.com/client.json",
		"client_name": "Example",
		"redirect_uris": ["https://app.example.com/cb"],
		"grant_types": ["authorization_code", "refresh_token"]
	}`)
	client, err := validateCIMDMetadata(body, id)
	if err != nil {
		t.Fatalf("validateCIMDMetadata() error = %v, want nil", err)
	}
	if client.ID != id {
		t.Errorf("client.ID = %q, want %q", client.ID, id)
	}
	if client.LoginChannel != "mcp" || client.Type != "public" {
		t.Errorf("client = %+v, want mcp/public", client)
	}
	if len(client.AllowedGrantTypeList) != 2 {
		t.Errorf("grant types = %v, want [authorization_code refresh_token]", client.AllowedGrantTypeList)
	}
}

// A query-string client_id whose document omits the query is accepted, and the
// requested (query-full) id stays the identity (ChatGPT case, #319).
func TestValidateCIMDMetadata_QueryClientIDMatchesQuerylessDocument(t *testing.T) {
	requested := "https://chatgpt.com/oauth/x/client.json?token_endpoint_auth_method=none"
	body := []byte(`{
		"client_id": "https://chatgpt.com/oauth/x/client.json",
		"client_name": "ChatGPT",
		"redirect_uris": ["https://chatgpt.com/cb"]
	}`)
	client, err := validateCIMDMetadata(body, requested)
	if err != nil {
		t.Fatalf("validateCIMDMetadata() error = %v, want nil", err)
	}
	if client.ID != requested {
		t.Errorf("client.ID = %q, want requested %q", client.ID, requested)
	}
}

func TestValidateCIMDMetadata_AcceptsNoneWhenClientOffersIt(t *testing.T) {
	// ChatGPT connectors publish token_endpoint_auth_method=private_key_jwt but list
	// "none" in token_endpoint_auth_methods_supported and request it via the
	// client_id query. authgate must negotiate down to a public ("none") client
	// instead of rejecting with "unable to retrieve client by id".
	cases := []struct {
		name string
		id   string
		body string
	}{
		{
			"via client_id query",
			"https://chatgpt.com/oauth/x/client.json?token_endpoint_auth_method=none",
			`{"client_id":"https://chatgpt.com/oauth/x/client.json","client_name":"ChatGPT","redirect_uris":["https://chatgpt.com/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"]}`,
		},
		{
			"via supported list only",
			"https://chatgpt.com/oauth/x/client.json",
			`{"client_id":"https://chatgpt.com/oauth/x/client.json","client_name":"ChatGPT","redirect_uris":["https://chatgpt.com/cb"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["private_key_jwt","none"]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, err := validateCIMDMetadata([]byte(tc.body), tc.id)
			if err != nil {
				t.Fatalf("validateCIMDMetadata() error = %v, want nil", err)
			}
			if client.Type != "public" {
				t.Errorf("client.Type = %q, want public", client.Type)
			}
		})
	}
}

func TestValidateCIMDMetadata_Rejects(t *testing.T) {
	cases := []struct {
		name    string
		body    string
		id      string
		wantErr string
	}{
		{"invalid json", `{`, "https://a/c.json", "invalid JSON"},
		{"client_id mismatch", `{"client_id":"https://b/c.json","client_name":"n","redirect_uris":["https://a/cb"]}`, "https://a/c.json", "client_id mismatch"},
		{"missing client_name", `{"client_id":"https://a/c.json","redirect_uris":["https://a/cb"]}`, "https://a/c.json", "client_name is required"},
		{"no redirect_uris", `{"client_id":"https://a/c.json","client_name":"n"}`, "https://a/c.json", "redirect_uris is required"},
		{"grant without auth_code", `{"client_id":"https://a/c.json","client_name":"n","redirect_uris":["https://a/cb"],"grant_types":["refresh_token"]}`, "https://a/c.json", "must include authorization_code"},
		{"bad auth method", `{"client_id":"https://a/c.json","client_name":"n","redirect_uris":["https://a/cb"],"token_endpoint_auth_method":"client_secret_post"}`, "https://a/c.json", "token_endpoint_auth_method"},
		{"bad response_type", `{"client_id":"https://a/c.json","client_name":"n","redirect_uris":["https://a/cb"],"response_types":["token"]}`, "https://a/c.json", "response_type"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateCIMDMetadata([]byte(tc.body), tc.id)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want one containing %q", err, tc.wantErr)
			}
		})
	}
}
