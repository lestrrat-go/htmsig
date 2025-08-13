package http

import (
	"net/http"
)

// Middleware wraps an http.Handler to add signature verification and/or response signing.
type Middleware struct {
	handler  http.Handler
	verifier *Verifier // For request verification
	signer   Signer    // For response signing
}

// Wrap wraps an HTTP handler with signature verification and/or signing capabilities.
func Wrap(h http.Handler, options ...MiddlewareOption) http.Handler {
	w := &Middleware{
		handler: h,
	}

	for _, opt := range options {
		switch opt.Ident() {
		case identVerifier{}:
			w.verifier = opt.Value().(*Verifier)
		case identSigner{}:
			w.signer = opt.Value().(Signer)
		}
	}

	return w
}

// ServeHTTP implements http.Handler.
func (wrp *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Step 1: Verify incoming request signature if verifier is configured
	if verifier := wrp.verifier; verifier != nil {
		if err := wrp.verifier.VerifyRequest(r.Context(), r); err != nil {
			r = r.WithContext(WithVerificationError(r.Context(), err))
			wrp.verifier.errorHandler.ServeHTTP(w, r)
			return
		}
	}

	// Wrap ResponseWriter for response signing if signer is configured
	responseWriter := w
	if wrp.signer != nil {
		responseWriter = wrp.signer.ResponseWriter(w, r)
	}

	// Execute the main handler
	wrp.handler.ServeHTTP(responseWriter, r)
}
