//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func postTokenForm(t *testing.T, ts *TestServer, form url.Values) *TokenResponse {
	t.Helper()
	resp, err := http.Post(ts.BaseURL+"/oauth/token", "application/x-www-form-urlencoded", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	result := &TokenResponse{StatusCode: resp.StatusCode, RawBody: string(body)}
	if err := json.Unmarshal(body, result); err != nil {
		t.Fatal(err)
	}
	return result
}

func codeForm(c *OAuthClient, code string) url.Values {
	return url.Values{"grant_type": {"authorization_code"}, "client_id": {c.ClientID}, "redirect_uri": {c.RedirectURI}, "code": {code}, "code_verifier": {c.CodeVerifier}}
}

func TestIntegration_AuthCodeConcurrentOneShot(t *testing.T) {
	for _, scope := range []string{"openid", "openid offline_access"} {
		t.Run(scope, func(t *testing.T) {
			ts := SetupTestServer(t)
			c := NewOAuthClient(t, ts.BaseURL)
			c.Scope = scope
			code := completeLoginFlowToCode(t, ts, c)
			ctx := context.Background()
			tx, err := ts.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			if _, err := tx.ExecContext(ctx, "LOCK TABLE auth_requests IN SHARE MODE"); err != nil {
				t.Fatal(err)
			}
			const concurrent = 4
			results := make(chan *TokenResponse, concurrent)
			for i := 0; i < concurrent; i++ {
				go func() { results <- c.ExchangeCode(code) }()
			}
			// Wait for all requests at the DB write boundary before unlocking.
			// This also overlaps the old implementation's final DELETEs.
			deadline := time.Now().Add(10 * time.Second)
			var waiting int
			for time.Now().Before(deadline) {
				if err := ts.DB.QueryRowContext(ctx, "SELECT count(*) FROM pg_stat_activity WHERE wait_event_type='Lock' AND query LIKE '%auth_requests%'").Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting >= concurrent {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			var success int
			for i := 0; i < concurrent; i++ {
				r := <-results
				if r.StatusCode == 200 {
					success++
				} else if r.StatusCode != 400 || !strings.Contains(r.RawBody, "invalid_grant") {
					t.Errorf("unexpected response: %d %s", r.StatusCode, r.RawBody)
				}
			}
			if waiting < concurrent {
				t.Fatalf("only %d requests reached DB barrier", waiting)
			}
			if success != 1 {
				t.Fatalf("successful exchanges = %d, want 1", success)
			}
			var grants int
			if err := ts.DB.QueryRowContext(ctx, "SELECT count(*) FROM refresh_tokens").Scan(&grants); err != nil {
				t.Fatal(err)
			}
			want := 0
			if strings.Contains(scope, "offline_access") {
				want = 1
			}
			if grants != want {
				t.Fatalf("refresh grants = %d, want %d", grants, want)
			}
			if r := c.ExchangeCode(code); r.StatusCode != 400 {
				t.Fatalf("sequential replay status %d", r.StatusCode)
			}
		})
	}
}

func TestIntegration_InvalidCodeRequestPreservesCode(t *testing.T) {
	for _, field := range []string{"code_verifier", "redirect_uri", "client_id"} {
		t.Run(field, func(t *testing.T) {
			ts := SetupTestServer(t)
			c := NewOAuthClient(t, ts.BaseURL)
			code := completeLoginFlowToCode(t, ts, c)
			form := codeForm(c, code)
			form.Set(field, "wrong-value")
			if r := postTokenForm(t, ts, form); r.StatusCode == 200 {
				t.Fatal("invalid request accepted")
			}
			if r := c.ExchangeCode(code); r.StatusCode != 200 {
				t.Fatalf("valid retry failed: %s", r.RawBody)
			}
		})
	}
}

func TestIntegration_AuthCodeConsumptionRollsBackWithGrant(t *testing.T) {
	ts := SetupTestServer(t)
	c := NewOAuthClient(t, ts.BaseURL)
	code := completeLoginFlowToCode(t, ts, c)
	ctx := context.Background()
	// Inject an insert failure without changing the auth request or provider.
	if _, err := ts.DB.ExecContext(ctx, "ALTER TABLE refresh_tokens ADD CONSTRAINT test_reject_refresh CHECK (false) NOT VALID"); err != nil {
		t.Fatal(err)
	}
	if r := c.ExchangeCode(code); r.StatusCode == 200 {
		t.Fatal("insert failure returned success")
	}
	if _, err := ts.DB.ExecContext(ctx, "ALTER TABLE refresh_tokens DROP CONSTRAINT test_reject_refresh"); err != nil {
		t.Fatal(err)
	}
	if r := c.ExchangeCode(code); r.StatusCode != 200 {
		t.Fatalf("code lost after rollback: %s", r.RawBody)
	}
}
