package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/kangheeyong/authgate/internal/service"
)

// newTestDeviceHandler creates a DeviceHandler with a minimal DeviceService.
// nil storage is safe as long as the code path under test exits before touching it.
func newTestDeviceHandler() *DeviceHandler {
	svc := service.NewDeviceService(nil, nil, "", 0, nil)
	return NewDeviceHandler(svc, true, "authgate") // devMode=true
}

// ── Method guard ──────────────────────────────────────────────────────────────

// POST 외 메서드는 /device/approve에서 405를 반환해야 한다.
func TestDeviceApprove_NonPost_MethodNotAllowed(t *testing.T) {
	h := newTestDeviceHandler()
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch} {
		req := httptest.NewRequest(method, "/device/approve", nil)
		w := httptest.NewRecorder()
		h.HandleDeviceApprove(w, req)
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("method %s: status = %d, want 405", method, w.Code)
		}
	}
}

// ── CSRF guard ────────────────────────────────────────────────────────────────

// csrf_token 폼 필드가 없으면 403.
func TestDeviceApprove_CSRF_MissingFormToken_Forbidden(t *testing.T) {
	h := newTestDeviceHandler()
	form := url.Values{"user_code": {"TEST-CODE"}, "action": {"approve"}}
	// no csrf_token in form, no cookie
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleDeviceApprove(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (missing CSRF form token)", w.Code)
	}
}

// 폼 토큰과 쿠키 토큰이 다르면 403.
func TestDeviceApprove_CSRF_TokenMismatch_Forbidden(t *testing.T) {
	h := newTestDeviceHandler()
	form := url.Values{
		"user_code":  {"TEST-CODE"},
		"action":     {"approve"},
		"csrf_token": {"form-token-abc"},
	}
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "different-token-xyz"})
	w := httptest.NewRecorder()
	h.HandleDeviceApprove(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (CSRF token mismatch)", w.Code)
	}
}

// 쿠키가 없으면 cookieToken="" → 폼 토큰과 불일치 → 403.
func TestDeviceApprove_CSRF_NoCookie_Forbidden(t *testing.T) {
	h := newTestDeviceHandler()
	form := url.Values{
		"user_code":  {"TEST-CODE"},
		"action":     {"approve"},
		"csrf_token": {"some-token"},
	}
	req := httptest.NewRequest(http.MethodPost, "/device/approve", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// no csrf_token cookie
	w := httptest.NewRecorder()
	h.HandleDeviceApprove(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (no CSRF cookie)", w.Code)
	}
}

// ── GET /device 렌더 ──────────────────────────────────────────────────────────

// user_code 없는 GET /device → 200 HTML 입력 폼 렌더.
// DeviceService.HandleDevicePage("") early-returns DeviceShowEntry (no DB touch).
func TestDevicePage_NoUserCode_Renders200HTML(t *testing.T) {
	h := newTestDeviceHandler()
	req := httptest.NewRequest(http.MethodGet, "/device", nil)
	w := httptest.NewRecorder()
	h.HandleDevicePage(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
}

// /device/auth/callback에서 code/state 누락 시 400 에러 페이지를 반환해야 한다.
func TestDeviceCallback_MissingCodeOrState_ReturnsBadRequest(t *testing.T) {
	h := newTestDeviceHandler()
	req := httptest.NewRequest(http.MethodGet, "/device/auth/callback", nil)
	w := httptest.NewRecorder()

	h.HandleDeviceCallback(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("Content-Type = %q, want text/html", ct)
	}
}
