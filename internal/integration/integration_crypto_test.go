//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// TestIntegration_Crypto_DeviceUserCodeLookup verifies the device flow still
// resolves a user_code end-to-end through the real server when PII/code
// encryption is enabled (ADR-002): StoreDeviceAuthorization hashes the codes at
// rest, and the device callback's user_code lookup must hash the incoming code
// to match. Reaching the post-lookup 403 (account_not_found) proves the lookup
// succeeded — a broken hash path would fail the user_code lookup earlier.
func TestIntegration_Crypto_DeviceUserCodeLookup(t *testing.T) {
	ts := SetupTestServerWithOptions(t, SetupOptions{EnableMCP: true, EnableCrypto: true})
	ctx := context.Background()

	if err := ts.Store.StoreDeviceAuthorization(ctx, "test-client", "fresh-dc", "TEST-CODE", ts.Clock.Now().Add(5*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("seed device_code: %v", err)
	}

	resp, err := http.Get(ts.BaseURL + "/device/auth/callback?code=fake-code&state=TEST-CODE")
	if err != nil {
		t.Fatalf("device callback: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d, want 403 (post-lookup account check) body=%s", resp.StatusCode, string(body))
	}
}
