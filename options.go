package htmsig

import (
	"time"

	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// VerifyOption configures signature verification behavior
type VerifyOption interface {
	Option
	verifyOption()
}

type verifyOption struct {
	Option
}

func (v verifyOption) verifyOption() {}

// WithValidateExpires returns a VerifyOption that enables or disables expiration validation
func WithValidateExpires(validate bool) VerifyOption {
	return verifyOption{option.New(identValidateExpires{}, validate)}
}

// WithClock returns a VerifyOption that sets the clock for expiration checking
func WithClock(clock Clock) VerifyOption {
	return verifyOption{option.New(identClock{}, clock)}
}

type identValidateExpires struct{}

func (identValidateExpires) String() string { return "WithValidateExpires" }

type identClock struct{}

func (identClock) String() string { return "WithClock" }

// Clock provides the current time for timestamp operations.
type Clock interface {
	Now() time.Time
}

// SystemClock uses the system time.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}