package mcp

import (
	"fmt"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	// cimdFailureLimit / cimdFailureWindow form a per-client_id failure quota.
	// Once a single client_id produces this many failures inside the window,
	// the fetcher rejects further attempts without an outbound call until the
	// window passes (see #156).
	cimdFailureLimit  = 5
	cimdFailureWindow = 5 * time.Minute
)

// errCIMDRateLimited is returned when a client_id exceeds cimdFailureLimit
// failures inside cimdFailureWindow.
var errCIMDRateLimited = fmt.Errorf("cimd: too many recent failures, retry later")

// cimdFailureRecord tracks the timestamps of recent failures for a single
// client_id; entries outside cimdFailureWindow are pruned on access.
type cimdFailureRecord struct {
	times []time.Time
}

// failureTracker is the per-client_id failure quota: a bounded (LRU) map of
// recent failure timestamps used to short-circuit repeated fetches of a
// failing client_id (#156). It owns its own mutex and takes the current time
// as a method arg so it holds no clock dependency.
type failureTracker struct {
	mu  sync.Mutex
	lru *lru.Cache[string, *cimdFailureRecord]
}

func newFailureTracker(maxEntries int) *failureTracker {
	c, _ := lru.New[string, *cimdFailureRecord](maxEntries)
	return &failureTracker{lru: c}
}

// IsRateLimited reports whether clientID has exceeded cimdFailureLimit failures
// inside cimdFailureWindow as of now, pruning timestamps that have aged out.
func (t *failureTracker) IsRateLimited(clientID string, now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.lru.Get(clientID)
	if !ok {
		return false
	}
	rec.times = pruneOldTimestamps(rec.times, now, cimdFailureWindow)
	return len(rec.times) >= cimdFailureLimit
}

// Record appends a failure timestamp for clientID, pruning any that have aged
// out of cimdFailureWindow.
func (t *failureTracker) Record(clientID string, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	rec, ok := t.lru.Get(clientID)
	if !ok {
		rec = &cimdFailureRecord{}
		t.lru.Add(clientID, rec)
	}
	rec.times = append(pruneOldTimestamps(rec.times, now, cimdFailureWindow), now)
}

func pruneOldTimestamps(times []time.Time, now time.Time, window time.Duration) []time.Time {
	cutoff := now.Add(-window)
	kept := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}
