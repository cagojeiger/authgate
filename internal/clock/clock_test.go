package clock

import (
	"testing"
	"time"
)

func TestRealClock(t *testing.T) {
	c := RealClock{}
	before := time.Now()
	got := c.Now()
	after := time.Now()

	if got.Before(before) || got.After(after) {
		t.Errorf("RealClock.Now() = %v, not between %v and %v", got, before, after)
	}
}

func TestFixedClock(t *testing.T) {
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c := FixedClock{T: fixed}

	if got := c.Now(); !got.Equal(fixed) {
		t.Errorf("FixedClock.Now() = %v, want %v", got, fixed)
	}
}
