package storage

import (
	"net/http/httptest"
	"testing"
)

func TestWithResourceRoundTrip(t *testing.T) {
	req := httptest.NewRequest("GET", "/authorize", nil)
	ctx := WithResource(req.Context(), "https://mcp.example.com")
	if got := ResourceFromContext(ctx); got != "https://mcp.example.com" {
		t.Fatalf("resource from context = %q, want https://mcp.example.com", got)
	}
}
