package http

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/option"
)

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

// StaticKeyResolver provides a single static key for all verifications.
type StaticKeyResolver struct {
	Key any
}

func (s *StaticKeyResolver) ResolveKey(keyID string) (any, error) {
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
	// KeyResolver resolves keys for signature verification
	KeyResolver KeyResolver

	// ErrorHandler is called when signature verification fails.
	// If nil, DefaultErrorHandler is used (returns 401 Unauthorized).
	ErrorHandler http.Handler

	// RequiredSignatures specifies minimum number of valid signatures required.
	// If 0, at least one valid signature is required.
	RequiredSignatures int

	// SkipOnMissing determines behavior when no Signature header is present.
	// If true, verification is skipped and request continues.
	// If false (default), missing signature is treated as verification failure.
	SkipOnMissing bool

	// MaxSignatureAge specifies the maximum age of signatures to accept.
	// If zero, signature age is not validated.
	// This helps prevent replay attacks with old signatures.
	MaxSignatureAge time.Duration

	// RequiredComponents specifies components that must be present in signatures.
	// If nil, no specific components are required.
	RequiredComponents []component.Identifier

	// AllowedAlgorithms restricts which signature algorithms are accepted.
	// If nil, all supported algorithms are allowed.
	AllowedAlgorithms []string
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
		KeyResolver:        resolver,
		ErrorHandler:       DefaultErrorHandler(),
		RequiredSignatures: 1,
		SkipOnMissing:      false,
	}

	for _, option := range options {
		switch option.Ident() {
		case identMaxSignatureAge{}:
			verifier.MaxSignatureAge = option.Value().(time.Duration)
		case identRequiredComponents{}:
			verifier.RequiredComponents = option.Value().([]component.Identifier)
		case identAllowedAlgorithms{}:
			verifier.AllowedAlgorithms = option.Value().([]string)
		case identSkipOnMissing{}:
			verifier.SkipOnMissing = option.Value().(bool)
		case identVerifierErrorHandler{}:
			verifier.ErrorHandler = option.Value().(http.Handler)
		}
	}

	return verifier
}

// ServeHTTP implements http.Handler for signature verification.
// It verifies the request signature and calls the error handler if verification fails.
// On successful verification, it does nothing (allowing the request to continue).
func (v *Verifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if signature headers are present
	sigHeader := r.Header.Get("Signature")
	sigInputHeader := r.Header.Get("Signature-Input")

	if sigHeader == "" && sigInputHeader == "" {
		if v.SkipOnMissing {
			return // Skip verification, allow request to continue
		}
		// No signature present, treat as verification failure
		v.handleError(w, r, fmt.Errorf("missing signature headers"))
		return
	}

	// Verify the signature using the new VerifyRequest API
	ctx := component.WithRequestInfoFromHTTP(context.Background(), r)
	err := htmsig.VerifyRequest(ctx, r.Header, v.KeyResolver)
	if err != nil {
		v.handleError(w, r, fmt.Errorf("signature verification failed: %w", err))
		return
	}

	// Verification successful - do nothing, let request continue
}

// handleError calls the configured error handler or the default if none is set.
func (v *Verifier) handleError(w http.ResponseWriter, r *http.Request, err error) {
	handler := v.ErrorHandler
	if handler == nil {
		handler = DefaultErrorHandler()
	}

	// Store error in request context so error handler can access it
	ctx := context.WithValue(r.Context(), errorContextKey, err)
	r = r.WithContext(ctx)

	handler.ServeHTTP(w, r)
}

// contextKey type for storing error in request context
type contextKey string

const errorContextKey contextKey = "htmsig_error"

// GetError retrieves the verification error from the request context.
// This can be used by custom error handlers to access the specific error.
func GetError(r *http.Request) error {
	if err, ok := r.Context().Value(errorContextKey).(error); ok {
		return err
	}
	return nil
}

// DefaultErrorHandler returns a handler that responds with 401 Unauthorized
// and includes the error message in the response body.
func DefaultErrorHandler() http.Handler {
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

// VerifierOption configures a Verifier.
type VerifierOption = option.Interface

// WithMaxSignatureAge configures maximum signature age for replay protection.
func WithMaxSignatureAge(maxAge time.Duration) VerifierOption {
	return option.New(identMaxSignatureAge{}, maxAge)
}

type identMaxSignatureAge struct{}

func (identMaxSignatureAge) String() string { return "WithMaxSignatureAge" }

// WithRequiredComponents configures components that must be present in signatures.
func WithRequiredComponents(components ...component.Identifier) VerifierOption {
	return option.New(identRequiredComponents{}, components)
}

type identRequiredComponents struct{}

func (identRequiredComponents) String() string { return "WithRequiredComponents" }

// WithAllowedAlgorithms restricts which algorithms are accepted.
func WithAllowedAlgorithms(algorithms ...string) VerifierOption {
	return option.New(identAllowedAlgorithms{}, algorithms)
}

type identAllowedAlgorithms struct{}

func (identAllowedAlgorithms) String() string { return "WithAllowedAlgorithms" }

// WithSkipOnMissing configures whether to skip verification when no signature is present.
func WithSkipOnMissing(skip bool) VerifierOption {
	return option.New(identSkipOnMissing{}, skip)
}

type identSkipOnMissing struct{}

func (identSkipOnMissing) String() string { return "WithSkipOnMissing" }

// WithVerifierErrorHandler configures custom error handling.
func WithVerifierErrorHandler(handler http.Handler) VerifierOption {
	return option.New(identVerifierErrorHandler{}, handler)
}

type identVerifierErrorHandler struct{}

func (identVerifierErrorHandler) String() string { return "WithVerifierErrorHandler" }
