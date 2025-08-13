package http

import (
	"context"
)

// Context key types for storing values in request context
type verificationErrorKey struct{}
type signingErrorKey struct{}

// WithVerificationError adds a verification error to the context.
func WithVerificationError(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, verificationErrorKey{}, err)
}

// VerificationErrorFromContext retrieves a verification error from the context.
func VerificationErrorFromContext(ctx context.Context) error {
	if err, ok := ctx.Value(verificationErrorKey{}).(error); ok {
		return err
	}
	return nil
}

// WithSigningError adds a signing error to the context.
func WithSigningError(ctx context.Context, err error) context.Context {
	return context.WithValue(ctx, signingErrorKey{}, err)
}

// SigningErrorFromContext retrieves a signing error from the context.
func SigningErrorFromContext(ctx context.Context) error {
	if err, ok := ctx.Value(signingErrorKey{}).(error); ok {
		return err
	}
	return nil
}
