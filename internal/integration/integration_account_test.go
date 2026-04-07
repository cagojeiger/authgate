//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestIntegration_DeleteAccount_WrongOrigin_Rejected(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Create user + get session
	user, _ := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "origin-test@test.com", EmailVerified: true, Name: "Test", AvatarURL: "", Provider: "google", ProviderUserID: "test-google-sub", ProviderEmail: "o@test.com"})
	sessionID, _ := ts.Store.CreateSession(ctx, user.ID, 24*3600*1e9)

	req, _ := http.NewRequest("DELETE", ts.BaseURL+"/account", nil)
	req.Header.Set("Origin", "https://evil.com")
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DELETE /account with wrong origin status = %d, want 403", resp.StatusCode)
	}
}

// account-005: disabled/deleted users must be rejected on DELETE /account.
func TestIntegration_DeleteAccount_InactiveUser_Rejected(t *testing.T) {
	tests := []struct {
		name      string
		userState string
	}{
		{name: "disabled", userState: "disabled"},
		{name: "deleted", userState: "deleted"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := SetupTestServer(t)
			ctx := context.Background()

			user, err := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "inactive-delete-"+tt.name+"@test.com", EmailVerified: true, Name: "Inactive Delete", AvatarURL: "", Provider: "google", ProviderUserID: "inactive-delete-sub-"+tt.name, ProviderEmail: "inactive-delete-"+tt.name+"@test.com"})
			if err != nil {
				t.Fatalf("create user: %v", err)
			}
			sessionID, err := ts.Store.CreateSession(ctx, user.ID, 24*3600*1e9)
			if err != nil {
				t.Fatalf("create session: %v", err)
			}

			if _, err := ts.DB.ExecContext(ctx, `UPDATE users SET status = $1 WHERE id = $2`, tt.userState, user.ID); err != nil {
				t.Fatalf("set user state: %v", err)
			}

			req, _ := http.NewRequest(http.MethodDelete, ts.BaseURL+"/account", nil)
			req.Header.Set("Origin", ts.BaseURL)
			req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("request: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusForbidden {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("status=%d, want 403 body=%s", resp.StatusCode, body)
			}

			var body map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if body["error"] != "account_inactive" {
				t.Fatalf("error=%q, want account_inactive", body["error"])
			}
		})
	}
}

// handler-login: session cookie HttpOnly / SameSite=Lax / Secure=false(devMode) 속성 검증
func TestIntegration_DeleteAccount_ResponseShape(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	user, _ := ts.Store.CreateUserWithIdentity(ctx, storage.CreateUserWithIdentityInput{Email: "shape@test.com", EmailVerified: true, Name: "Shape", AvatarURL: "", Provider: "google", ProviderUserID: "shape-sub", ProviderEmail: "shape@test.com"})
	sessionID, _ := ts.Store.CreateSession(ctx, user.ID, 24*3600*1e9)

	req, _ := http.NewRequest(http.MethodDelete, ts.BaseURL+"/account", nil)
	req.Header.Set("Origin", ts.BaseURL)
	req.AddCookie(&http.Cookie{Name: "authgate_session", Value: sessionID})

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body["status"] != "pending_deletion" {
		t.Errorf("status = %q, want pending_deletion", body["status"])
	}
	if body["message"] == "" {
		t.Error("message field should not be empty")
	}
}

// refresh/revocation: refresh token revoke 후 재사용은 실패해야 한다.
