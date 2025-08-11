package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/option"
)

// Wrapper wraps an http.Handler to add signature verification and/or response signing.
type Wrapper struct {
	handler      http.Handler
	verifier     *Verifier       // For request verification
	signer       *responseSigner // For response signing
	errorHandler http.Handler    // Custom error handler, defaults to 401
}

// WrapperOption configures a Wrapper.
type WrapperOption = option.Interface

// WithResolver enables request verification with the provided key resolver.
// The presence of this option enables verification functionality.
func WithResolver(resolver KeyResolver, options ...VerifierOption) WrapperOption {
	return option.New(identResolver{}, resolverConfig{resolver: resolver, options: options})
}

type identResolver struct{}

func (identResolver) String() string { return "WithResolver" }

type resolverConfig struct {
	resolver KeyResolver
	options  []VerifierOption
}

// WithSigningKey enables response signing with the provided key and key ID.
// The presence of this option enables signing functionality.
func WithSigningKey(keyID string, key any, options ...signerOption) WrapperOption {
	return option.New(identSigningKey{}, signingKeyConfig{keyID: keyID, key: key, options: options})
}

type identSigningKey struct{}

func (identSigningKey) String() string { return "WithSigningKey" }

type signingKeyConfig struct {
	keyID   string
	key     any
	options []signerOption
}

// WithErrorHandler configures a custom error handler for verification failures.
func WithErrorHandler(handler http.Handler) WrapperOption {
	return option.New(identWrapperErrorHandler{}, handler)
}

type identWrapperErrorHandler struct{}

func (identWrapperErrorHandler) String() string { return "WithErrorHandler" }

// Wrap wraps an HTTP handler with signature verification and/or signing capabilities.
func Wrap(h http.Handler, options ...WrapperOption) http.Handler {
	w := &Wrapper{
		handler:      h,
		errorHandler: DefaultErrorHandler(),
	}

	for _, opt := range options {
		switch opt.Ident() {
		case identResolver{}:
			config := opt.Value().(resolverConfig)
			w.verifier = NewVerifier(config.resolver, config.options...)
			w.verifier.SkipOnMissing = true // Default to skip when no signature present
		case identSigningKey{}:
			config := opt.Value().(signingKeyConfig)
			w.signer = newResponseSigner(config.key, config.keyID, config.options...)
		case identWrapperErrorHandler{}:
			w.errorHandler = opt.Value().(http.Handler)
		}
	}

	return w
}

// verify performs signature verification on the incoming request.
// Returns an error if verification fails.
func (wrp *Wrapper) verify(r *http.Request) error {
	if wrp.verifier == nil {
		return nil // No verification configured
	}

	// Check if signature headers are present
	sigHeader := r.Header.Get("Signature")
	sigInputHeader := r.Header.Get("Signature-Input")

	if sigHeader == "" && sigInputHeader == "" {
		if wrp.verifier.SkipOnMissing {
			return nil // Skip verification, allow request to continue
		}
		// No signature present, treat as verification failure
		return fmt.Errorf("missing signature headers")
	}

	// Use the new VerifyRequest API
	ctx := component.WithRequestInfoFromHTTP(context.Background(), r)
	return htmsig.VerifyRequest(ctx, r.Header, wrp.verifier.KeyResolver)
}

// ServeHTTP implements http.Handler.
func (wrp *Wrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Step 1: Verify incoming request signature if verifier is configured
	if err := wrp.verify(r); err != nil {
		// Handle error using configured error handler
		wrp.handleError(w, r, err)
		return
	}

	// Step 2: Wrap ResponseWriter for response signing if signer is configured
	responseWriter := w
	if wrp.signer != nil {
		responseWriter = newSigningResponseWriter(w, r, wrp.signer)
	} // Step 3: Execute the main handler
	wrp.handler.ServeHTTP(responseWriter, r)
}

// handleError calls the configured error handler.
func (wrp *Wrapper) handleError(w http.ResponseWriter, r *http.Request, err error) {
	handler := wrp.errorHandler
	if handler == nil {
		handler = DefaultErrorHandler()
	}

	// Store error in request context so error handler can access it
	ctx := context.WithValue(r.Context(), errorContextKey, err)
	r = r.WithContext(ctx)

	handler.ServeHTTP(w, r)
}

