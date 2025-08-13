package http

import (
	"net/http"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/option"
)

type Option = option.Interface

// Identifier types for options
type identVerifier struct{}

func (identVerifier) String() string { return "WithVerifier" }

type identSigner struct{}

func (identSigner) String() string { return "WithSigner" }


type identSkipOnMissing struct{}

func (identSkipOnMissing) String() string { return "WithSkipOnMissing" }

type identVerifierErrorHandler struct{}

func (identVerifierErrorHandler) String() string { return "WithVerifierErrorHandler" }

type identValidateExpires struct{}

func (identValidateExpires) String() string { return "WithValidateExpires" }

type identTransport struct{}

func (identTransport) String() string { return "WithTransport" }

type identAlgorithm struct{}

func (identAlgorithm) String() string { return "WithAlgorithm" }

type identTag struct{}

func (identTag) String() string { return "WithTag" }

type identClock struct{}

func (identClock) String() string { return "WithClock" }

type identSigningErrorHandler struct{}

func (identSigningErrorHandler) String() string { return "WithSigningErrorHandler" }

type identLabel struct{}

func (identLabel) String() string { return "WithLabel" }

type identIncludeCreated struct{}

func (identIncludeCreated) String() string { return "WithIncludeCreated" }

type identComponents struct{}

func (identComponents) String() string { return "WithComponents" }

// MiddlewareOption configures a Wrapper.
type MiddlewareOption interface {
	Option
	wrapperOption()
}

type RoundTripperOption interface {
	Option
	roundTripperOption()
}

type MiddlewareRoundTripperOption interface {
	MiddlewareOption
	RoundTripperOption
}

type middlewareRoundTripperOption struct {
	Option
}

func (middlewareRoundTripperOption) roundTripperOption() {}
func (middlewareRoundTripperOption) wrapperOption()      {}

// WithVerifier specifies the verifier to use for request/response signature verification.
func WithVerifier(verifier *Verifier) MiddlewareRoundTripperOption {
	return middlewareRoundTripperOption{option.New(identVerifier{}, verifier)}
}

// WithSigner specifies the signer to use for request/response signature signing.
func WithSigner(signer Signer) MiddlewareRoundTripperOption {
	return middlewareRoundTripperOption{option.New(identSigner{}, signer)}
}

// VerifierOption configures a Verifier.
type VerifierOption = option.Interface


// WithSkipOnMissing configures whether to skip verification when no signature is present.
func WithSkipOnMissing(skip bool) VerifierOption {
	return option.New(identSkipOnMissing{}, skip)
}

// WithVerifierErrorHandler configures custom error handling.
func WithVerifierErrorHandler(handler http.Handler) VerifierOption {
	return option.New(identVerifierErrorHandler{}, handler)
}

// WithValidateExpires configures whether to validate signature expiration times.
// When enabled, signatures with expired 'expires' parameters will be rejected.
func WithValidateExpires(validate bool) VerifierOption {
	return option.New(identValidateExpires{}, validate)
}

// TransportOption configures a SigningTransport.
type TransportOption = option.Interface

// WithTransport sets the underlying transport.
func WithTransport(transport http.RoundTripper) TransportOption {
	return option.New(identTransport{}, transport)
}

// WithAlgorithm sets the signature algorithm.
func WithAlgorithm(algorithm string) TransportOption {
	return option.New(identAlgorithm{}, algorithm)
}

// WithTag sets the application-specific tag.
func WithTag(tag string) TransportOption {
	return option.New(identTag{}, tag)
}


// SignVerifyOption can be used with both signing and verification operations.
type SignVerifyOption interface {
	transportOption()
	signerOption()
	option.Interface
}

type signVerifyOption struct {
	Option
}

func (signVerifyOption) transportOption() {}
func (signVerifyOption) signerOption()    {}

func WithClock(clock Clock) SignVerifyOption {
	return &signVerifyOption{option.New(identClock{}, clock)}
}

// WithSigningErrorHandler configures error handling for signature failures.
func WithSigningErrorHandler(handler http.Handler) signerOption {
	return signerOption{option.New(identSigningErrorHandler{}, handler)}
}

// WithLabel sets the signature label for responses.
func WithLabel(label string) SignerOption {
	return signerOption{option.New(identLabel{}, label)}
}

type SignerOption interface {
	Option
	signerOption()
}

type signerOption struct {
	Option
}

func (signerOption) signerOption() {}

// WithIncludeCreated controls whether to include the created parameter for responses.
func WithIncludeCreated(include bool) SignerOption {
	return signerOption{option.New(identIncludeCreated{}, include)}
}

func WithComponents(components ...component.Identifier) SignerOption {
	return signerOption{option.New(identComponents{}, components)}
}
