//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/service"
	"github.com/kangheeyong/authgate/internal/storage"
)

// newRetentionCleanup builds a cleanup service driven by the fixture clock so a
// test can move time forward and observe the retention windows taking effect.
func newRetentionCleanup(t *testing.T, ts *TestServer) *service.CleanupService {
	t.Helper()
	svc := service.NewCleanupService(storage.NewCleanupRunner(ts.DB), ts.Clock, time.Hour)
	svc.SetRefreshTokenTTL(30 * 24 * time.Hour)
	return svc
}

// retention-001: end-user activity records lose their identifying columns on
// the short investigation horizon, while operator actions keep theirs for the
// statutory access-record period.
func TestIntegration_Retention_AnonymizesUserAndAdminOnDifferentClocks(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	completeLoginFlow(t, ts)
	user, err := ts.Store.GetUserByProviderIdentity(ctx, "google", "test-google-sub")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}

	// An operator action alongside the user's own login. No code emits admin.*
	// events yet, so the row is inserted directly: what is under test is the
	// retention split keyed on the event-type prefix, not the emission path.
	if _, err := ts.DB.ExecContext(ctx,
		`INSERT INTO audit_log (user_id, event_type, ip_address, user_agent, metadata, created_at)
		 VALUES ($1::uuid, 'admin.account_disabled', '10.0.0.9'::inet, 'grpc', '{}'::jsonb, $2)`,
		user.ID, ts.Clock.Now(),
	); err != nil {
		t.Fatalf("insert operator audit row: %v", err)
	}

	cleanup := newRetentionCleanup(t, ts)
	cleanup.SetAuditLogPIIRetention(90 * 24 * time.Hour)
	cleanup.SetAdminAuditLogPIIRetention(730 * 24 * time.Hour)

	// 120 days later: past the user horizon, well inside the operator one.
	ts.Clock.T = ts.Clock.T.Add(120 * 24 * time.Hour)
	cleanup.RunOnce(ctx)

	var userIdentified, adminIdentified int
	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log
		 WHERE event_type NOT LIKE 'admin.%' AND (user_id IS NOT NULL OR ip_address IS NOT NULL)`,
	).Scan(&userIdentified); err != nil {
		t.Fatalf("query user rows: %v", err)
	}
	if userIdentified != 0 {
		t.Errorf("%d end-user rows still carry identifiers after 120 days, want 0", userIdentified)
	}

	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log
		 WHERE event_type LIKE 'admin.%' AND user_id IS NOT NULL AND ip_address IS NOT NULL`,
	).Scan(&adminIdentified); err != nil {
		t.Fatalf("query admin rows: %v", err)
	}
	if adminIdentified == 0 {
		t.Error("operator action lost its identifiers before the statutory period elapsed")
	}

	// Past two years the operator record is anonymized too.
	ts.Clock.T = ts.Clock.T.Add(700 * 24 * time.Hour)
	cleanup.RunOnce(ctx)

	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM audit_log
		 WHERE event_type LIKE 'admin.%' AND (user_id IS NOT NULL OR ip_address IS NOT NULL)`,
	).Scan(&adminIdentified); err != nil {
		t.Fatalf("query admin rows: %v", err)
	}
	if adminIdentified != 0 {
		t.Errorf("%d operator rows still carry identifiers after the retention period, want 0", adminIdentified)
	}
}

// retention-002: rotated-out refresh tokens are removed on the short window,
// and replay is still detected afterwards through the family tombstone.
func TestIntegration_Retention_PurgesRevokedTokensButKeepsReplayDetection(t *testing.T) {
	ts := SetupTestServer(t)
	ctx := context.Background()

	tokens := completeLoginFlow(t, ts)
	oauth := NewOAuthClient(t, ts.BaseURL)

	// Rotate once, then replay the old token to tombstone the family.
	if rotated := oauth.RefreshToken(tokens.RefreshToken); rotated.AccessToken == "" {
		t.Fatal("rotation failed")
	}
	if replayed := oauth.RefreshToken(tokens.RefreshToken); replayed.AccessToken != "" {
		t.Fatal("replay of a rotated token should be rejected")
	}

	var families int
	if err := ts.DB.QueryRowContext(ctx, `SELECT count(*) FROM refresh_token_families`).Scan(&families); err != nil {
		t.Fatalf("query families: %v", err)
	}
	if families == 0 {
		t.Fatal("replay did not tombstone the family")
	}

	cleanup := newRetentionCleanup(t, ts)

	// 10 days on: revoked token rows are gone, the tombstone is not.
	ts.Clock.T = ts.Clock.T.Add(10 * 24 * time.Hour)
	cleanup.RunOnce(ctx)

	var revoked, remainingFamilies int
	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM refresh_tokens WHERE revoked_at IS NOT NULL`).Scan(&revoked); err != nil {
		t.Fatalf("query revoked: %v", err)
	}
	if revoked != 0 {
		t.Errorf("%d revoked tokens survived the 7-day window", revoked)
	}
	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM refresh_token_families`).Scan(&remainingFamilies); err != nil {
		t.Fatalf("query families: %v", err)
	}
	if remainingFamilies == 0 {
		t.Error("family tombstone was dropped while its tokens could still be replayed")
	}

	// Past the token lifetime plus margin the tombstone can no longer match
	// anything and is dropped too.
	ts.Clock.T = ts.Clock.T.Add(40 * 24 * time.Hour)
	cleanup.RunOnce(ctx)

	if err := ts.DB.QueryRowContext(ctx,
		`SELECT count(*) FROM refresh_token_families`).Scan(&remainingFamilies); err != nil {
		t.Fatalf("query families: %v", err)
	}
	if remainingFamilies != 0 {
		t.Errorf("%d stale tombstones survived, want 0", remainingFamilies)
	}
}
