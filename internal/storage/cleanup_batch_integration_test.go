//go:build integration

package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/testutil"
)

// TestCleanupRunner_DeleteInBatches_DrainsBacklog verifies the batch loop drains
// more rows than a single batch holds. With batch size 2 and 5 expired rows the
// loop must iterate three times (2+2+1) and still delete every eligible row.
func TestCleanupRunner_DeleteInBatches_DrainsBacklog(t *testing.T) {
	db := testutil.SetupPostgres(t)
	ctx := context.Background()
	runner := NewCleanupRunner(db)

	now := time.Date(2026, 3, 30, 0, 0, 0, 0, time.UTC)
	const n = 5
	for i := 0; i < n; i++ {
		if _, err := db.ExecContext(ctx,
			`INSERT INTO device_codes (id, device_code, user_code, client_id, expires_at, created_at)
			 VALUES (uuid_generate_v4(), $1, $2, 'test-client', $3, $4)`,
			fmt.Sprintf("dc-%d", i), fmt.Sprintf("uc-%d", i), now.Add(-2*time.Hour), now.Add(-3*time.Hour),
		); err != nil {
			t.Fatalf("insert device_code %d: %v", i, err)
		}
	}

	prev := cleanupBatchSize
	cleanupBatchSize = 2
	defer func() { cleanupBatchSize = prev }()

	deleted, err := runner.DeleteExpiredDeviceCodesBefore(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("DeleteExpiredDeviceCodesBefore: %v", err)
	}
	if deleted != n {
		t.Fatalf("deleted = %d, want %d", deleted, n)
	}

	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM device_codes`).Scan(&remaining); err != nil {
		t.Fatalf("count device_codes: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining device_codes = %d, want 0", remaining)
	}
}
