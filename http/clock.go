package http

import "time"

// Clock provides the current time for timestamp generation.
type Clock interface {
	Now() time.Time
}

// SystemClock uses the system time.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}

// fixedClock always returns the same time, useful for testing.
type fixedClock struct {
	time time.Time
}

func (c fixedClock) Now() time.Time {
	return c.time
}

// FixedClock returns a Clock that always returns the same time.
// This is useful for testing to ensure deterministic timestamps.
func FixedClock(t time.Time) Clock {
	return fixedClock{time: t}
}
