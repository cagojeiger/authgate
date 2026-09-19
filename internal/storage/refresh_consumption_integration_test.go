//go:build integration

package storage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/idgen"
	"github.com/zitadel/oidc/v3/pkg/op"
)

// Storage tests must execute both provider callbacks to redeem a token. Lookup
// alone intentionally has no consumption/reuse side effects.
func redeemRefreshForTest(ctx context.Context, s *Storage, token string) (op.RefreshTokenRequest, error) {
	request, err := s.TokenRequestByRefreshToken(ctx, token)
	if err != nil {
		return nil, err
	}
	_, _, _, err = s.CreateAccessAndRefreshTokens(ctx, request, token)
	return request, err
}

func TestRefreshLookupDoesNotConsume(t *testing.T) {
	f, child := newGraceFixture(t, 0)
	for i := 0; i < 2; i++ {
		if _, err := f.store.TokenRequestByRefreshToken(context.Background(), child); err != nil {
			t.Fatal(err)
		}
	}
	if f.liveTokens(t) != 1 || f.tombstoned(t) {
		t.Fatal("lookup mutated grant")
	}
	if _, err := f.redeem(t, child); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshAndRevokeSerializeAcrossStorageInstances(t *testing.T) {
	for _, revokeFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("revoke_first_%v", revokeFirst), func(t *testing.T) {
			f, child := newGraceFixture(t, 0)
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			request, err := f.store.TokenRequestByRefreshToken(ctx, child)
			if err != nil {
				t.Fatal(err)
			}
			other := New(f.store.DB(), f.clk, idgen.CryptoGenerator{}, nil, 15*time.Minute, 30*24*time.Hour)
			other.SetKeys(f.store.Keys())
			barrier, err := f.store.DB().BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer barrier.Rollback()
			if _, err := barrier.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))`, f.familyID); err != nil {
				t.Fatal(err)
			}
			rotate := make(chan error, 1)
			revoke := make(chan error, 1)
			rotateFn := func() { _, _, _, err := f.store.CreateAccessAndRefreshTokens(ctx, request, child); rotate <- err }
			revokeFn := func() { _, _, err := other.revokeRefreshGrant(ctx, child, "test-client"); revoke <- err }
			waiters := func(want int) {
				t.Helper()
				for {
					var count int
					if err := f.store.DB().QueryRowContext(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%pg_advisory_xact_lock%'`).Scan(&count); err != nil {
						t.Fatal(err)
					}
					if count >= want {
						return
					}
					select {
					case <-ctx.Done():
						t.Fatal(ctx.Err())
					case <-time.After(10 * time.Millisecond):
					}
				}
			}
			if revokeFirst {
				go revokeFn()
			} else {
				go rotateFn()
			}
			waiters(1)
			if revokeFirst {
				go rotateFn()
			} else {
				go revokeFn()
			}
			waiters(2)
			if err := barrier.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-revoke; err != nil {
				t.Fatal(err)
			}
			rotationErr := <-rotate
			if revokeFirst && !isInvalidGrant(rotationErr) {
				t.Fatalf("rotation after revoke: %v", rotationErr)
			}
			if !revokeFirst && rotationErr != nil {
				t.Fatalf("rotation before revoke: %v", rotationErr)
			}
			if f.liveTokens(t) != 0 || !f.tombstoned(t) {
				t.Fatal("revocation missed an issued child")
			}
			want := 2
			if !revokeFirst {
				want = 3
			}
			if n := f.count(t, `SELECT count(*) FROM refresh_tokens WHERE family_id=$1`); n != want {
				t.Fatalf("rows=%d want %d", n, want)
			}
		})
	}
}
