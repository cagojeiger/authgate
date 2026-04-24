//go:build integration

package integration

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

// TestAuditEvents verifies that token.refresh and token.revoked events
// are recorded in audit_log after the corresponding operations.
func TestAuditEvents(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	// Complete login flow to get initial tokens.
	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatalf("initial login failed: %s", tokens.RawBody)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("refresh_token should not be empty after login")
	}

	// Fetch the user ID from the DB to query audit_log.
	user, err := ts.Store.GetUserByProviderIdentity(ctx, "google", "test-google-sub")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	t.Run("token.refresh recorded after refresh grant", func(t *testing.T) {
		client := NewOAuthClient(t, ts.BaseURL)
		refreshed := client.RefreshToken(tokens.RefreshToken)
		if refreshed.StatusCode != 200 {
			t.Fatalf("refresh failed: status=%d body=%s", refreshed.StatusCode, refreshed.RawBody)
		}

		var count int
		err := ts.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE user_id = $1::uuid AND event_type = 'token.refresh'`,
			user.ID,
		).Scan(&count)
		if err != nil {
			t.Fatalf("query audit_log for token.refresh: %v", err)
		}
		if count == 0 {
			t.Error("expected at least one token.refresh audit_log row, got 0")
		}
	})

	t.Run("token.revoked recorded after explicit revocation", func(t *testing.T) {
		// Get a fresh set of tokens for revocation test.
		freshTokens := completeLoginFlow(t, ts)
		if freshTokens.StatusCode != 200 {
			t.Fatalf("second login failed: %s", freshTokens.RawBody)
		}

		// Revoke the refresh token.
		revokeForm := url.Values{
			"token":           {freshTokens.RefreshToken},
			"token_type_hint": {"refresh_token"},
			"client_id":       {"test-client"},
		}
		resp, err := ts.Server.Client().Post(
			ts.BaseURL+"/oauth/revoke",
			"application/x-www-form-urlencoded",
			strings.NewReader(revokeForm.Encode()),
		)
		if err != nil {
			t.Fatalf("revoke request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Fatalf("revoke status=%d, want 200", resp.StatusCode)
		}

		// Re-fetch user (same provider identity, same user ID).
		var count int
		err = ts.DB.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM audit_log WHERE user_id = $1::uuid AND event_type = 'token.revoked'`,
			user.ID,
		).Scan(&count)
		if err != nil {
			t.Fatalf("query audit_log for token.revoked: %v", err)
		}
		if count == 0 {
			t.Error("expected at least one token.revoked audit_log row, got 0")
		}
	})
}
