//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestIntegration_MCPDisabled_MetadataAndRoutes(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})

	resp, err := http.Get(ts.BaseURL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata request: %v", err)
	}
	defer resp.Body.Close()

	var metadata map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if v, ok := metadata["client_id_metadata_document_supported"].(bool); !ok || v {
		t.Fatalf("client_id_metadata_document_supported = %v, want false", metadata["client_id_metadata_document_supported"])
	}

	mcpResp, err := http.Get(ts.BaseURL + "/mcp/login?authRequestID=test")
	if err != nil {
		t.Fatalf("mcp login request: %v", err)
	}
	defer mcpResp.Body.Close()
	if mcpResp.StatusCode != http.StatusNotFound {
		t.Fatalf("/mcp/login status=%d, want 404", mcpResp.StatusCode)
	}
}

func TestIntegration_MCPDisabled_BrowserFlowStillWorks(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})
	client := NewOAuthClientFor(t, ts.BaseURL, "test-client", "/login/callback")

	code := completeLoginFlowToCode(t, ts, client)
	if code == "" {
		t.Fatal("expected authorization code for browser flow")
	}

	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("browser token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
}

func TestIntegration_MCPDisabled_MCPClientRejected(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: false})
	client := NewOAuthClientFor(t, ts.BaseURL, "mcp-client", "/mcp/callback")

	resp := client.StartAuthorize()
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusFound {
		loc := resp.Header.Get("Location")
		if strings.Contains(loc, "/mcp/login") {
			t.Fatalf("unexpected redirect to MCP login when MCP disabled: %s", loc)
		}
	}
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("mcp client should be rejected when MCP disabled")
	}
}
