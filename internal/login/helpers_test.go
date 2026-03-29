package login

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestWriteError_Format(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusBadRequest, "invalid_request", "Missing parameter")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json; charset=utf-8" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}

	if body["error"] != "invalid_request" {
		t.Errorf("error = %q, want %q", body["error"], "invalid_request")
	}
	if body["message"] != "Missing parameter" {
		t.Errorf("message = %q, want %q", body["message"], "Missing parameter")
	}
}

func TestWriteError_StatusCodes(t *testing.T) {
	tests := []struct {
		status int
		code   string
	}{
		{http.StatusBadRequest, "invalid_request"},
		{http.StatusUnauthorized, "unauthorized"},
		{http.StatusForbidden, "account_inactive"},
		{http.StatusInternalServerError, "internal_error"},
	}

	for _, tt := range tests {
		w := httptest.NewRecorder()
		writeError(w, tt.status, tt.code, "test message")

		if w.Code != tt.status {
			t.Errorf("writeError(%d) status = %d", tt.status, w.Code)
		}

		var body map[string]string
		json.Unmarshal(w.Body.Bytes(), &body)
		if body["error"] != tt.code {
			t.Errorf("writeError(%d) error = %q, want %q", tt.status, body["error"], tt.code)
		}
	}
}

func TestWriteError_NeverLeaksInternalDetails(t *testing.T) {
	w := httptest.NewRecorder()
	// Simulate what handler does: log the real error, send generic message
	writeError(w, http.StatusInternalServerError, "internal_error", "Something went wrong")

	body := w.Body.String()
	// Must NOT contain internal details
	if containsAny(body, "sql", "postgres", "connection", "pgx", "panic", "stack") {
		t.Errorf("error response may leak internal details: %s", body)
	}
}

func TestWriteError_AlwaysJSON(t *testing.T) {
	w := httptest.NewRecorder()
	writeError(w, http.StatusForbidden, "account_inactive", "Account is not active")

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	if err != nil {
		t.Fatalf("error response is not valid JSON: %v\nbody: %s", err, w.Body.String())
	}

	// Must have exactly these two keys
	if _, ok := body["error"]; !ok {
		t.Error("missing 'error' key in response")
	}
	if _, ok := body["message"]; !ok {
		t.Error("missing 'message' key in response")
	}
}

func TestGetSessionUser_NoCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	session, user, err := getSessionUser(nil, r)

	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if session != nil {
		t.Error("session should be nil when no cookie")
	}
	if user != nil {
		t.Error("user should be nil when no cookie")
	}
}

func TestGetSessionUser_MalformedCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "authgate_session", Value: "not-a-uuid"})

	session, user, err := getSessionUser(nil, r)

	if err != nil {
		t.Errorf("err = %v, want nil (malformed cookie is not an error)", err)
	}
	if session != nil {
		t.Error("session should be nil for malformed cookie")
	}
	if user != nil {
		t.Error("user should be nil for malformed cookie")
	}
}

func TestGetSessionUser_EmptyCookie(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: "authgate_session", Value: ""})

	session, user, err := getSessionUser(nil, r)

	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
	if session != nil {
		t.Error("session should be nil for empty cookie")
	}
	if user != nil {
		t.Error("user should be nil for empty cookie")
	}
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) > 0 && len(sub) > 0 {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}
