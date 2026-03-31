package storage

import (
	"net/http/httptest"
	"testing"
)

func TestResourceFromRequest(t *testing.T) {
	req := httptest.NewRequest("GET", "/authorize?client_id=test&resource=https://mcp.example.com", nil)
	if got := ResourceFromRequest(req); got != "https://mcp.example.com" {
		t.Fatalf("resource = %q, want https://mcp.example.com", got)
	}
}

func TestWithResourceRoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/authorize", nil)
	ctx := WithResource(req.Context(), "https://mcp.example.com")
	if got := ResourceFromContext(ctx); got != "https://mcp.example.com" {
		t.Fatalf("resource from context = %q, want https://mcp.example.com", got)
	}
}
