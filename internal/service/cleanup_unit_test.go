package service

import (
	"context"
	"testing"
	"time"

	"github.com/kangheeyong/authgate/internal/clock"
)

type cleanupRunnerStub struct {
	tryLockOK       bool
	tryLockErr      error
	releaseErr      error
	tryLockCalls    int
	releaseCalls    int
	cleanupCallHits int
}

func (s *cleanupRunnerStub) TryAdvisoryLock(ctx context.Context) (bool, error) {
	s.tryLockCalls++
	return s.tryLockOK, s.tryLockErr
}

func (s *cleanupRunnerStub) ReleaseAdvisoryLock(ctx context.Context) error {
	s.releaseCalls++
	return s.releaseErr
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
	runner := &cleanupRunnerStub{tryLockOK: false}
	svc := NewCleanupService(runner, &clock.FixedClock{T: time.Now()}, time.Minute)

	svc.RunOnce(context.Background())

	if runner.tryLockCalls != 1 {
		t.Fatalf("try lock calls = %d, want 1", runner.tryLockCalls)
	}
	if runner.cleanupCallHits != 0 {
		t.Fatalf("cleanup calls = %d, want 0 when lock not acquired", runner.cleanupCallHits)
	}
	if runner.releaseCalls != 0 {
		t.Fatalf("release calls = %d, want 0 when lock not acquired", runner.releaseCalls)
	}
}

func TestCleanupRunAll_ReleasesLockAfterRun(t *testing.T) {
	runner := &cleanupRunnerStub{tryLockOK: true}
	svc := NewCleanupService(runner, &clock.FixedClock{T: time.Now()}, time.Minute)

	svc.RunOnce(context.Background())

	if runner.tryLockCalls != 1 {
		t.Fatalf("try lock calls = %d, want 1", runner.tryLockCalls)
	}
	if runner.cleanupCallHits == 0 {
		t.Fatal("cleanup calls = 0, want > 0 when lock acquired")
	}
	if runner.releaseCalls != 1 {
		t.Fatalf("release calls = %d, want 1", runner.releaseCalls)
	}
}
