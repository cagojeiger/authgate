package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/kangheeyong/authgate/internal/service"
)

// newTestAccountHandler creates an AccountHandler with nil service.
// Safe for tests that exit before the service call (method check, origin check).
func newTestAccountHandler() *AccountHandler {
	return NewAccountHandler(nil, "http://authgate.example.com")
}

// ── Method guard ──────────────────────────────────────────────────────────────

// DELETE 외 메서드는 405를 반환해야 한다.
func TestDeleteAccount_NonDelete_MethodNotAllowed(t *testing.T) {
	h := newTestAccountHandler()
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch} {
		req := httptest.NewRequest(method, "/account", nil)
		w := httptest.NewRecorder()
		h.HandleDeleteAccount(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want 405", method, w.Code)
		}
	}
}

// ── Origin guard ──────────────────────────────────────────────────────────────

// Origin이 publicURL과 다르면 403 + JSON error body를 반환해야 한다.
func TestDeleteAccount_OriginMismatch_Forbidden(t *testing.T) {
	h := newTestAccountHandler()
	req := httptest.NewRequest(http.MethodDelete, "/account", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	w := httptest.NewRecorder()
	h.HandleDeleteAccount(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 for origin mismatch", w.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Error("response JSON should contain non-empty error field")
	}
}

// Origin이 publicURL과 정확히 일치하면 origin 체크를 통과해야 한다.
// (이후 service 호출까지 진행 — nil service이므로 panic; recover로 확인)
func TestDeleteAccount_OriginMatch_PassesOriginCheck(t *testing.T) {
	h := newTestAccountHandler()
	req := httptest.NewRequest(http.MethodDelete, "/account", nil)
	req.Header.Set("Origin", "http://authgate.example.com") // matches publicURL
	w := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true // nil service panics — expected in this unit test
			}
		}()
		h.HandleDeleteAccount(w, req)
	}()

	// Origin check passes → must not have returned 403
	if w.Code == http.StatusForbidden {
		t.Error("origin matched publicURL but got 403 — origin check is too strict")
	}
	// Either panicked at service call or returned normally; both confirm origin check passed
	_ = panicked
}

func TestDeleteAccount_NoSession_Unauthorized(t *testing.T) {
	svc := service.NewAccountService(nil)
	h := NewAccountHandler(svc, "http://authgate.example.com")

	req := httptest.NewRequest(http.MethodDelete, "/account", nil)
	w := httptest.NewRecorder()
	h.HandleDeleteAccount(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", w.Code)
	}

	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("response body is not valid JSON: %v", err)
	}
	if body["error"] == "" {
		t.Fatal("error field should be present")
	}
}
