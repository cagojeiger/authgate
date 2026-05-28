package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/upstream"
)

func newTestMCPLoginHandler(devMode bool) *MCPLoginHandler {
	svc := service.NewMCPLoginService(nil, "", 0)
	// FakeProvider.Callback delivers the (empty) state to CompleteMCPLogin,
	// which returns the 400 "missing code or state" the callback test asserts.
	provider := &upstream.FakeProvider{User: &upstream.UserInfo{Sub: "sub"}}
	return NewMCPLoginHandler(svc, provider, devMode, "authgate")
}

func TestMCPLogin_MissingAuthRequestID_ReturnsBadRequest(t *testing.T) {
	h := newTestMCPLoginHandler(true)
	req := httptest.NewRequest(http.MethodGet, "/mcp/login", nil)
	w := httptest.NewRecorder()

	h.HandleLogin(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestMCPCallback_MissingCodeOrState_ReturnsBadRequest(t *testing.T) {
	h := newTestMCPLoginHandler(true)
	req := httptest.NewRequest(http.MethodGet, "/mcp/callback", nil)
	w := httptest.NewRecorder()

	h.HandleCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}
