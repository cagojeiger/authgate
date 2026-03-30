package clock

import "time"

// Clock abstracts time source for deterministic testing.
type Clock interface {
	Now() time.Time
}

// RealClock uses the system clock.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// FixedClock returns a fixed time. For tests only.
type FixedClock struct {
	T time.Time
}

func (c FixedClock) Now() time.Time { return c.T }
