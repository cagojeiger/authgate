package service

import (
	"context"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type cleanupRunnerStub struct {
	lockAcquired    bool
	lockErr         error
	lockCalls       int
	cleanupCallHits int
}

func (s *cleanupRunnerStub) WithExclusiveLock(ctx context.Context, fn func(context.Context) error) (bool, error) {
	s.lockCalls++
	if s.lockErr != nil {
		return false, s.lockErr
	}
	if !s.lockAcquired {
		return false, nil
	}
	return true, fn(ctx)
}

func (s *cleanupRunnerStub) DeleteRevokedRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) DeleteExpiredRefreshTokensBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) DeleteExpiredOrRevokedSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) DeleteExpiredAuthRequestsBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) DeleteExpiredDeviceCodesBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) ListPendingDeletionUserIDsBefore(ctx context.Context, cutoff time.Time) ([]string, error) {
	s.cleanupCallHits++
	return nil, nil
}

func (s *cleanupRunnerStub) AnonymizeAuditLogBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	s.cleanupCallHits++
	return 0, nil
}

func (s *cleanupRunnerStub) DeleteUser(ctx context.Context, userID string, now time.Time, hook func(ctx context.Context, userID string) error) error {
	s.cleanupCallHits++
	return nil
}

func TestCleanupRunAll_SkipsWhenAdvisoryLockNotAcquired(t *testing.T) {
	runner := &cleanupRunnerStub{lockAcquired: false}
	svc := NewCleanupService(runner, &clock.FixedClock{T: time.Now()}, time.Minute)

	svc.RunOnce(context.Background())

	if runner.lockCalls != 1 {
		t.Fatalf("lock calls = %d, want 1", runner.lockCalls)
	}
	if runner.cleanupCallHits != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when lock not acquired", runner.cleanupCallHits)
	}
}

func TestCleanupRunAll_ReleasesLockAfterRun(t *testing.T) {
	runner := &cleanupRunnerStub{lockAcquired: true}
	svc := NewCleanupService(runner, &clock.FixedClock{T: time.Now()}, time.Minute)

	svc.RunOnce(context.Background())

	if runner.lockCalls != 1 {
		t.Fatalf("lock calls = %d, want 1", runner.lockCalls)
	}
	if runner.cleanupCallHits == 0 {
		t.Fatal("cleanup calls = 0, want > 0 when lock acquired")
	}
}
