package pages

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderer_RenderConsent(t *testing.T) {
	r := NewRenderer(nil)
	w := httptest.NewRecorder()

	data := ConsentData{
		Title:       "Authorize Test App",
		ClientName:  "Test App",
		ClientID:    "test-client",
		UserName:    "John Doe",
		UserEmail:   "john@example.com",
		Scopes:      []string{"openid", "profile", "email"},
		State:       "state123",
		RedirectURI: "http://localhost/callback",
		ReqID:       "req123",
	}

	r.RenderConsent(w, data)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "John Doe") {
		t.Error("Expected body to contain user name")
	}
	if !strings.Contains(body, "openid") {
		t.Error("Expected body to contain scope")
	}
	if !strings.Contains(body, "req123") {
		t.Error("Expected body to contain request ID")
	}
}

func TestRenderer_RenderDeviceEntry(t *testing.T) {
	r := NewRenderer(nil)
	w := httptest.NewRecorder()

	r.RenderDeviceEntry(w)

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Device Authorization") {
		t.Error("Expected body to contain title")
	}
	if !strings.Contains(body, "user_code") {
		t.Error("Expected body to contain user_code input")
	}
}

func TestRenderer_RenderDeviceApproval(t *testing.T) {
	r := NewRenderer(nil)
	w := httptest.NewRecorder()

	r.RenderDeviceApproval(w, DeviceApprovalData{UserCode: "ABCD-EFGH"})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "ABCD-EFGH") {
		t.Error("Expected body to contain user code")
	}
}

func TestRenderer_RenderSuccess(t *testing.T) {
	tests := []struct {
		name     string
		data     SuccessData
		contains string
	}{
		{
			name:     "approved",
			data:     SuccessData{Title: "Access Approved", Message: "Success!"},
			contains: "✅",
		},
		{
			name:     "denied",
			data:     SuccessData{Title: "Access Denied", Message: "Denied!"},
			contains: "❌",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := NewRenderer(nil)
			w := httptest.NewRecorder()

			r.RenderSuccess(w, tt.data)

			if w.Code != 200 {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			body := w.Body.String()
			if !strings.Contains(body, tt.data.Title) {
				t.Error("Expected body to contain title")
			}
			if !strings.Contains(body, tt.contains) {
				t.Errorf("Expected body to contain %s", tt.contains)
			}
		})
	}
}

func TestRenderer_RenderError(t *testing.T) {
	r := NewRenderer(nil)
	w := httptest.NewRecorder()

	r.RenderError(w, ErrorData{Message: "Something went wrong"})

	if w.Code != 200 {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "Something went wrong") {
		t.Error("Expected body to contain error message")
	}
	if !strings.Contains(body, "❌") {
		t.Error("Expected body to contain error icon")
	}
}
