//go:build integration

package integration

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
)

func TestIntegration_RefreshAfterLogin(t *testing.T) {
	ts := SetupTestServer(t)

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != 200 {
		t.Fatalf("initial login failed: %s", tokens.RawBody)
	}

	// Refresh
	client := NewOAuthClient(t, ts.BaseURL)
	refreshResult := client.RefreshToken(tokens.RefreshToken)

	if refreshResult.StatusCode != 200 {
		t.Errorf("refresh failed: status=%d body=%s", refreshResult.StatusCode, refreshResult.RawBody)
	}
	if refreshResult.AccessToken == "" {
		t.Error("refreshed access_token should not be empty")
	}
}

// refresh-004: same refresh token polled concurrently -> exactly one success.
func TestIntegration_RefreshConcurrent_ExactlyOneSuccess(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClient(t, ts.BaseURL)

	tokens := completeLoginFlow(t, ts)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("initial login failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	var wg sync.WaitGroup
	results := make(chan *TokenResponse, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- client.RefreshToken(tokens.RefreshToken)
		}()
	}
	wg.Wait()
	close(results)

	success := 0
	fail := 0
	for result := range results {
		if result.StatusCode == http.StatusOK {
			success++
		} else {
			fail++
		}
	}
	if success != 1 || fail != 1 {
		t.Fatalf("expected exactly one success and one failure, got success=%d fail=%d", success, fail)
	}
}

// refresh-002/003: refresh token issued, then user becomes recoverable/inactive -> invalid_grant
func TestIntegration_Refresh_StateChange_InvalidGrant(t *testing.T) {
	tests := []struct {
		name      string
		mutateSQL string
	}{
		{name: "pending_deletion", mutateSQL: `UPDATE users SET status = 'pending_deletion' WHERE id = $1`}, // refresh-002
		{name: "disabled", mutateSQL: `UPDATE users SET status = 'disabled' WHERE id = $1`},                 // refresh-003
		{name: "deleted", mutateSQL: `UPDATE users SET status = 'deleted' WHERE id = $1`},                   // refresh-003
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := SetupTestServer(t)
			client := NewOAuthClient(t, ts.BaseURL)
			ctx := context.Background()

			tokens := completeLoginFlow(t, ts)
			if tokens.StatusCode != http.StatusOK {
				t.Fatalf("initial login failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
			}

			user, err := ts.Store.GetUserByProviderIdentity(ctx, "google", "test-google-sub")
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
			if _, err := ts.DB.ExecContext(ctx, tt.mutateSQL, user.ID); err != nil {
				t.Fatalf("mutate user state: %v", err)
			}

			refresh := client.RefreshToken(tokens.RefreshToken)
			if refresh.StatusCode == http.StatusOK {
				t.Fatalf("refresh should fail after state change: %+v", refresh)
			}
			if !strings.Contains(refresh.RawBody, "invalid_grant") {
				t.Fatalf("expected invalid_grant, got body=%s", refresh.RawBody)
			}
		})
	}
}

// mcp-token-004: refresh token exchange must use the same MCP resource.
func TestIntegration_RefreshTokenRevocation_RejectsReuse(t *testing.T) {
	ts := SetupTestServer(t)

	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK {
		t.Fatalf("initial token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}
	if tokens.RefreshToken == "" {
		t.Fatal("refresh_token should not be empty")
	}

	revokeForm := url.Values{
		"token":           {tokens.RefreshToken},
		"token_type_hint": {"refresh_token"},
		"client_id":       {client.ClientID},
	}
	revokeResp, err := http.Post(ts.BaseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(revokeForm.Encode()))
	if err != nil {
		t.Fatalf("revoke request: %v", err)
	}
	defer revokeResp.Body.Close()

	// RFC7009: revocation endpoint는 성공 시 200
	if revokeResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(revokeResp.Body)
		t.Fatalf("revoke status=%d, want 200; body=%s", revokeResp.StatusCode, body)
	}

	// revoked refresh token 재사용은 실패해야 한다.
	refresh := client.RefreshToken(tokens.RefreshToken)
	if refresh.StatusCode == http.StatusOK {
		t.Fatalf("refresh with revoked token should fail, got 200 body=%s", refresh.RawBody)
	}
	if !strings.Contains(refresh.RawBody, "invalid_grant") && !strings.Contains(refresh.RawBody, "invalid_refresh_token") {
		t.Fatalf("expected invalid_grant/invalid_refresh_token, got body=%s", refresh.RawBody)
	}
}

// refresh-005: reused refresh token must trigger family revoke and invalidate descendant tokens.
func TestIntegration_RefreshReuseDetection_FamilyRevokesDescendants(t *testing.T) {
	ts := SetupTestServer(t)
	client := NewOAuthClient(t, ts.BaseURL)

	// initial login -> rt0
	code := completeLoginFlowToCode(t, ts, client)
	tokens0 := client.ExchangeCode(code)
	if tokens0.StatusCode != http.StatusOK {
		t.Fatalf("initial token exchange failed: status=%d body=%s", tokens0.StatusCode, tokens0.RawBody)
	}
	if tokens0.RefreshToken == "" {
		t.Fatal("initial refresh_token should not be empty")
	}

	// first refresh with rt0 -> rt1
	tokens1 := client.RefreshToken(tokens0.RefreshToken)
	if tokens1.StatusCode != http.StatusOK {
		t.Fatalf("first refresh failed: status=%d body=%s", tokens1.StatusCode, tokens1.RawBody)
	}
	if tokens1.RefreshToken == "" {
		t.Fatal("rotated refresh_token should not be empty")
	}

	// reuse old rt0 -> must fail (reuse detection)
	reused := client.RefreshToken(tokens0.RefreshToken)
	if reused.StatusCode == http.StatusOK {
		t.Fatalf("reused refresh token should fail, got 200 body=%s", reused.RawBody)
	}
	if !strings.Contains(reused.RawBody, "invalid_grant") && !strings.Contains(reused.RawBody, "invalid_refresh_token") {
		t.Fatalf("expected invalid_grant/invalid_refresh_token for reused token, got body=%s", reused.RawBody)
	}

	// descendant rt1 should also be unusable after family revoke
	descendant := client.RefreshToken(tokens1.RefreshToken)
	if descendant.StatusCode == http.StatusOK {
		t.Fatalf("descendant refresh token should fail after family revoke, got 200 body=%s", descendant.RawBody)
	}
	if !strings.Contains(descendant.RawBody, "invalid_grant") && !strings.Contains(descendant.RawBody, "invalid_refresh_token") {
		t.Fatalf("expected invalid_grant/invalid_refresh_token for descendant token, got body=%s", descendant.RawBody)
	}
}

// revocation 멱등성: 동일 refresh token을 두 번 revoke해도 200이어야 한다.
func TestIntegration_RefreshTokenRevocation_Idempotent(t *testing.T) {
	ts := SetupTestServer(t)

	client := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, client)
	tokens := client.ExchangeCode(code)
	if tokens.StatusCode != http.StatusOK || tokens.RefreshToken == "" {
		t.Fatalf("initial token exchange failed: status=%d body=%s", tokens.StatusCode, tokens.RawBody)
	}

	revoke := func(token string) int {
		form := url.Values{
			"token":           {token},
			"token_type_hint": {"refresh_token"},
			"client_id":       {client.ClientID},
		}
		resp, err := http.Post(ts.BaseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatalf("revoke request: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	if code := revoke(tokens.RefreshToken); code != http.StatusOK {
		t.Fatalf("first revoke status=%d, want 200", code)
	}
	if code := revoke(tokens.RefreshToken); code != http.StatusOK {
		t.Fatalf("second revoke status=%d, want 200", code)
	}
}

// RFC7009: 존재하지 않는 token revoke 요청도 200으로 응답해야 한다.
func TestIntegration_Revocation_UnknownToken_Returns200(t *testing.T) {
	ts := SetupTestServer(t)

	form := url.Values{
		"token":           {"not-a-real-token"},
		"token_type_hint": {"refresh_token"},
		"client_id":       {"test-client"},
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("revoke unknown token: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d, want 200; body=%s", resp.StatusCode, body)
	}
}

// RFC7009 + CIMD: revocation must return 200 even when CIMD client lookup/fetch fails.
func TestIntegration_Revocation_CIMDFetchFailure_Returns200(t *testing.T) {
	ts := SetupTestServer(t)

	// .invalid TLD is reserved and should fail DNS resolution.
	invalidCIMDClientID := "https://cimd-client.invalid/oauth/client.json"
	form := url.Values{
		"token":           {"not-a-real-token"},
		"token_type_hint": {"refresh_token"},
		"client_id":       {invalidCIMDClientID},
	}
	resp, err := http.Post(ts.BaseURL+"/oauth/revoke", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("revoke with invalid CIMD client_id: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d, want 200; body=%s", resp.StatusCode, body)
	}
}
