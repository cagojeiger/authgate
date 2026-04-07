package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kangheeyong/authgate/internal/service"
)

func newTestMCPLoginHandler(devMode bool) *MCPLoginHandler {
	svc := service.NewLoginService(nil, nil, nil, 0)
	return NewMCPLoginHandler(svc, devMode)
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

