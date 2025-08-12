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

// WithVerifier enables request verification with a pre-configured verifier.
func WithVerifier(verifier *Verifier) WrapperOption {
	return option.New(identVerifier{}, verifier)
}

type identVerifier struct{}

func (identVerifier) String() string { return "WithVerifier" }

// WithSigner enables response signing with a pre-configured signer.
func WithSigner(signer *ResponseSigner) WrapperOption {
	return option.New(identSigner{}, signer)
}

type identSigner struct{}

func (identSigner) String() string { return "WithSigner" }

// WithErrorHandler configures a custom error handler for verification failures.
func WithErrorHandler(handler http.Handler) WrapperOption {
	return option.New(identErrorHandler{}, handler)
}

type identErrorHandler struct{}

func (identErrorHandler) String() string { return "WithErrorHandler" }

// Wrap wraps an HTTP handler with signature verification and/or signing capabilities.
func Wrap(h http.Handler, options ...WrapperOption) http.Handler {
	w := &Wrapper{
		handler:      h,
		errorHandler: DefaultErrorHandler(),
	}

	for _, opt := range options {
		switch opt.Ident() {
		case identVerifier{}:
			w.verifier = opt.Value().(*Verifier)
		case identSigner{}:
			w.signer = opt.Value().(*responseSigner)
		case identErrorHandler{}:
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

