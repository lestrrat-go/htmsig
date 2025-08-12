package http

import (
	"context"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/option"
)

// ResponseSigner signs HTTP responses according to RFC 9421.
// Use NewResponseSigner to create instances.
type ResponseSigner = responseSigner

// responseSigner signs HTTP responses according to RFC 9421.
type responseSigner struct {
	// Key is the private key used for signing responses.
	// Can be RSA, ECDSA, Ed25519 private key, or HMAC shared secret.
	Key any

	// KeyID identifies the key used for signing.
	KeyID string

	// Algorithm specifies the signature algorithm.
	// If empty, algorithm will be determined from the key type.
	Algorithm string

	// Components specifies the components to include in signatures.
	// If nil, a sensible default set will be used for responses.
	Components []component.Identifier

	// SignatureLabel is the label for the signature.
	// If empty, defaults to "sig".
	SignatureLabel string

	// IncludeCreated adds the created parameter with current timestamp.
	IncludeCreated bool

	// Tag is an application-specific tag to include in the signature.
	Tag string

	// ErrorHandler is called when signature generation fails.
	// If nil, errors are silently ignored.
	ErrorHandler func(error)

	// FailOnError determines whether to fail the response when signing fails.
	// If false (default), signing errors are handled by ErrorHandler but don't abort the response.
	FailOnError bool

	// Clock provides timestamps. If nil, SystemClock is used.
	Clock Clock
}

// NewResponseSigner creates a new responseSigner with the given key and key ID.
// This is the public constructor for creating reusable response signers.
func NewResponseSigner(key any, keyID string, options ...signerOption) *responseSigner {
	return newResponseSigner(key, keyID, options...)
}

// newResponseSigner creates a new responseSigner with the given key and key ID.
func newResponseSigner(key any, keyID string, options ...signerOption) *responseSigner {
	signer := &responseSigner{
		Key:               key,
		KeyID:             keyID,
		Components: DefaultResponseComponents(),
		SignatureLabel:    "sig",
		IncludeCreated:    true,
	}
	
	for _, option := range options {
		switch option.Ident() {
		case identSignerErrorHandler{}:
			signer.ErrorHandler = option.Value().(func(error))
		case identFailOnError{}:
			signer.FailOnError = option.Value().(bool)
		case identSignerComponents{}:
			signer.Components = option.Value().([]component.Identifier)
		case identSignerSignatureLabel{}:
			signer.SignatureLabel = option.Value().(string)
		case identSignerCreated{}:
			signer.IncludeCreated = option.Value().(bool)
		case identClockOption{}:
			signer.Clock = option.Value().(Clock)
		}
	}
	
	return signer
}

// DefaultResponseComponents returns a sensible default set of components
// for response signatures.
func DefaultResponseComponents() []component.Identifier {
	return []component.Identifier{
		component.Status(),
		component.New("content-type"),
		component.New("content-length"),
		component.New("date"),
	}
}


// createSignatureDefinition creates a signature definition based on the signer configuration.
func (s *responseSigner) createSignatureDefinition() *input.Definition {
	builder := input.NewDefinitionBuilder().
		Label(s.SignatureLabel).
		KeyID(s.KeyID).
		Components(s.getComponents()...)

	if s.Algorithm != "" {
		builder = builder.Algorithm(s.Algorithm)
	}

	if s.IncludeCreated {
		clock := s.Clock
		if clock == nil {
			clock = SystemClock{}
		}
		builder = builder.Created(clock.Now().Unix())
	}

	if s.Tag != "" {
		builder = builder.Tag(s.Tag)
	}

	return builder.MustBuild()
}

// getComponents returns the components to include in the signature.
func (s *responseSigner) getComponents() []component.Identifier {
	if s.Components != nil {
		return s.Components
	}
	return DefaultResponseComponents()
}

// signingResponseWriter captures response details needed for signing.
type signingResponseWriter struct {
	http.ResponseWriter
	signer     *responseSigner
	request    *http.Request
	written    bool
	statusCode int
}

// newSigningResponseWriter creates a wrapper that captures response details.
func newSigningResponseWriter(w http.ResponseWriter, r *http.Request, signer *responseSigner) *signingResponseWriter {
	return &signingResponseWriter{
		ResponseWriter: w,
		signer:         signer,
		request:        r,
		written:        false,
		statusCode:     200, // Default status
	}
}

// WriteHeader captures the status code and adds signature headers before writing.
func (w *signingResponseWriter) WriteHeader(statusCode int) {
	if w.written {
		return // Already written
	}

	w.statusCode = statusCode
	w.written = true

	// Generate and add signature headers before writing the response
	w.addSignatureHeaders()

	w.ResponseWriter.WriteHeader(statusCode)
}

// addSignatureHeaders generates the signature and adds it to the response headers.
func (w *signingResponseWriter) addSignatureHeaders() {
	// Create signature definition
	def := w.signer.createSignatureDefinition()

	// Create input value with the definition
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()

	// Prepare context with response information
	ctx := component.WithResponseInfo(context.Background(), w.ResponseWriter.Header(), w.statusCode, 
		component.RequestInfoFromHTTP(w.request))

	// Sign the response using the new SignResponse API
	err := htmsig.SignResponse(ctx, w.ResponseWriter.Header(), inputValue, w.signer.Key)
	if err != nil {
		// Handle signing error based on configuration
		if w.signer.ErrorHandler != nil {
			w.signer.ErrorHandler(err)
		}
		
		if w.signer.FailOnError {
			// Fail the response by writing an error status
			w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
			return
		}
		// Otherwise continue with unsigned response
	}
}

// Write captures that content was written.
func (w *signingResponseWriter) Write(data []byte) (int, error) {
	if !w.written {
		w.WriteHeader(w.statusCode)
	}
	return w.ResponseWriter.Write(data)
}

// signerOption configures a responseSigner.
type signerOption = option.Interface

// WithSignerErrorHandler configures error handling for signature failures.
func WithSignerErrorHandler(handler func(error)) signerOption {
	return option.New(identSignerErrorHandler{}, handler)
}

type identSignerErrorHandler struct{}

func (identSignerErrorHandler) String() string { return "WithSignerErrorHandler" }

// WithFailOnError configures whether to fail responses on signature errors.
func WithFailOnError(fail bool) signerOption {
	return option.New(identFailOnError{}, fail)
}

type identFailOnError struct{}

func (identFailOnError) String() string { return "WithFailOnError" }

// WithSignerComponents configures the signature components for responses.
func WithSignerComponents(components ...component.Identifier) signerOption {
	return option.New(identSignerComponents{}, components)
}

type identSignerComponents struct{}

func (identSignerComponents) String() string { return "WithSignerComponents" }

// WithSignerSignatureLabel sets the signature label for responses.
func WithSignerSignatureLabel(label string) signerOption {
	return option.New(identSignerSignatureLabel{}, label)
}

type identSignerSignatureLabel struct{}

func (identSignerSignatureLabel) String() string { return "WithSignerSignatureLabel" }

// WithSignerCreated controls whether to include the created parameter for responses.
func WithSignerCreated(include bool) signerOption {
	return option.New(identSignerCreated{}, include)
}

type identSignerCreated struct{}

func (identSignerCreated) String() string { return "WithSignerCreated" }


