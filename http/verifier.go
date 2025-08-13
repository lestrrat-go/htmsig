package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
)

// VerifyRequest verifies the request signature using the provided context and header.
// This method is meant to be used in the server-side verification process.
func (v *Verifier) VerifyRequest(ctx context.Context, req *http.Request) error {
	ctx = component.WithMode(ctx, component.ModeRequest)
	ctx = component.WithRequestInfoFromHTTP(ctx, req)
	return v.verify(ctx, req.Header)
}

// VerifyResponse verifies the response signature using the provided context and header.
// This method is meant to be used in the client-side verification process.
func (v *Verifier) VerifyResponse(ctx context.Context, res *http.Response) error {
	ctx = component.WithMode(ctx, component.ModeResponse)
	ctx = component.WithResponseInfoFromHTTP(ctx, res)

	// the context object MUST contain a request info object. If not,
	// the response object must contain a request object. If neither
	// is present, we cannot verify the response, and so we return an error.
	if _, ok := component.RequestInfoFromContext(ctx); !ok {
		if res.Request == nil {
			return fmt.Errorf("no request info available for response verification, and no request object in response")
		}
		ctx = component.WithRequestInfoFromHTTP(ctx, res.Request)
	}
	return v.verify(ctx, res.Header)
}

func (v *Verifier) verify(ctx context.Context, hdr http.Header) error {
	// Check if signature headers are present
	sigHeader := hdr.Get(htmsig.SignatureHeader)
	sigInputHeader := hdr.Get(htmsig.SignatureInputHeader)

	if sigHeader == "" && sigInputHeader == "" {
		if v.skipOnMissing {
			return nil // Skip verification, allow request to continue
		}
		// No signature present, treat as verification failure
		return fmt.Errorf("missing signature headers")
	}

	// Check the context mode to determine which verification function to call
	mode := component.ModeFromContext(ctx)
	switch mode {
	case component.ModeRequest:
		return htmsig.VerifyRequest(ctx, hdr, v.keyResolver)
	case component.ModeResponse:
		return htmsig.VerifyResponse(ctx, hdr, v.keyResolver)
	default:
		// Default to request verification for backward compatibility
		return htmsig.VerifyRequest(ctx, hdr, v.keyResolver)
	}
}

// KeyResolver resolves keys for signature verification.
// It can return the key directly or use a KeyID-based lookup.
type KeyResolver interface {
	ResolveKey(keyID string) (any, error)
}

// KeyResolverFunc is a function adapter for KeyResolver.
type KeyResolverFunc func(keyID string) (any, error)

func (f KeyResolverFunc) ResolveKey(keyID string) (any, error) {
	return f(keyID)
}

type staticKeyResolver struct {
	Key any // The static key to return for all lookups
}

// StaticKeyResolver provides a single static key for all verifications.
func StaticKeyResolver(key any) KeyResolver {
	return staticKeyResolver{Key: key}
}

func (s staticKeyResolver) ResolveKey(keyID string) (any, error) {
	return s.Key, nil
}

// MapKeyResolver provides key lookup from a map.
type MapKeyResolver struct {
	Keys map[string]any
}

func (m *MapKeyResolver) ResolveKey(keyID string) (any, error) {
	if key, exists := m.Keys[keyID]; exists {
		return key, nil
	}
	return nil, fmt.Errorf("key not found: %s", keyID)
}

// Verifier verifies incoming HTTP request signatures according to RFC 9421.
//
// For most use cases, prefer using Wrap() with WithVerification() which provides
// a more convenient API. Use Verifier directly only when you need verification-only
// middleware or want to integrate with existing middleware chains.
type Verifier struct {
	// keyResolver resolves keys for signature verification
	keyResolver KeyResolver

	// errorHandler is called when signature verification fails.
	// If nil, DefaultVerificationErrorHandler is used (returns 401 Unauthorized).
	errorHandler http.Handler

	// skipOnMissing determines behavior when no Signature header is present.
	// If true, verification is skipped and request continues.
	// If false (default), missing signature is treated as verification failure.
	skipOnMissing bool
}

// NewVerifier creates a new Verifier with the given key resolver.
//
// For most use cases, prefer using Wrap() with WithVerification() instead:
//
//	handler := http.Wrap(yourHandler, http.WithVerification(resolver, options...))
//
// Use NewVerifier directly only when you need a reusable verifier or
// verification-only middleware.
func NewVerifier(resolver KeyResolver, options ...VerifierOption) *Verifier {
	verifier := &Verifier{
		keyResolver:  resolver,
		errorHandler: DefaultVerificationErrorHandler(),
		skipOnMissing: false,
	}

	for _, option := range options {
		switch option.Ident() {
		case identSkipOnMissing{}:
			verifier.skipOnMissing = option.Value().(bool)
		case identVerifierErrorHandler{}:
			verifier.errorHandler = option.Value().(http.Handler)
		}
	}

	return verifier
}

// DefaultVerificationErrorHandler returns a handler that responds with 401 Unauthorized
// and includes the error message in the response body.
func DefaultVerificationErrorHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := GetError(r)
		errorMsg := "Signature verification failed"
		if err != nil {
			errorMsg = err.Error()
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, "401 Unauthorized: %s\n", errorMsg)
	})
}
