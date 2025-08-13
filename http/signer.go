package http

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
)

type Signer interface {
	SignRequest(context.Context, *http.Request) error

	// ResponseWriter wraps the http.ResponseWriter to capture response details for signing,
	// and signs the response before it is sent.
	ResponseWriter(http.ResponseWriter, *http.Request) http.ResponseWriter
}

type signerConfig struct {
	key            any
	kid            string
	components     []component.Identifier
	tag            string
	label          string
	alg            string
	includeCreated bool
	clock          Clock

	// response writer specific
	errorHandler http.Handler
}

// SingleKeySingner is a signer that is assigned a single key (and key ID) to sign requests
// or responses.
type SingleKeySigner struct {
	config signerConfig
}

// signingResponseWriter captures response details needed for signing.
type signingResponseWriter struct {
	rw         http.ResponseWriter
	request    *http.Request
	written    bool
	statusCode int
	config     signerConfig
}

func NewSigner(key any, kid string, options ...SignerOption) *SingleKeySigner {
	var alg string
	var clock Clock = SystemClock{} // Default clock
	label := "sig"
	errh := DefaultSigningErrorHandler()
	includeCreated := true
	tag := ""
	components := []component.Identifier{
		component.Status(),
		component.TargetURI().WithParameter("req", true),
		component.New("content-type"),
	}
	for _, option := range options {
		switch option.Ident() {
		case identAlgorithm{}:
			alg = option.Value().(string)
		case identLabel{}:
			label = option.Value().(string)
		case identClock{}:
			clock = option.Value().(Clock)
		case identComponents{}:
			components = option.Value().([]component.Identifier)
		case identSigningErrorHandler{}:
			errh = option.Value().(http.Handler)
		case identIncludeCreated{}:
			includeCreated = option.Value().(bool)
		case identTag{}:
			tag = option.Value().(string)
		}
	}
	return &SingleKeySigner{
		config: signerConfig{
			alg:            alg,
			key:            key,
			kid:            kid,
			components:     components,
			label:          label,
			includeCreated: includeCreated,
			tag:            tag,
			clock:          clock,
			errorHandler:   errh,
		},
	}
}

func (s *SingleKeySigner) SignRequest(ctx context.Context, req *http.Request) error {
	// Create signature definition
	def, err := createSignatureDefinition(s.config)
	if err != nil {
		return fmt.Errorf("failed to create signature definition: %w", err)
	}

	// Create input value with the definition
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()

	ctx = component.WithRequestInfoFromHTTP(ctx, req)
	return htmsig.SignRequest(ctx, req.Header, inputValue, s.config.key)
}

// ResponseWriter creates a ResponseWriter that captures response details for signing,
// and allows the response to be signed before being sent.
func (s *SingleKeySigner) ResponseWriter(w http.ResponseWriter, r *http.Request) http.ResponseWriter {
	return &signingResponseWriter{
		rw:         w,
		request:    r,
		statusCode: http.StatusOK, // Default status
		config:     s.config,
	}
}

var signingErrorHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	// you can get the root cause of the failure from
	// err := SigningErrorFromContext(r.Context())
	// Default error handler simply writes a 401
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
})

func DefaultSigningErrorHandler() http.Handler {
	return signingErrorHandler
}

func (s *signingResponseWriter) Header() http.Header {
	return s.rw.Header()
}

func (s *signingResponseWriter) WriteHeader(statusCode int) {
	if s.written {
		return // Already written
	}

	s.statusCode = statusCode
	s.written = true

	// Generate and add signature headers before writing the response
	s.addSignatureHeaders()
	s.rw.WriteHeader(statusCode)
}

func (s *signingResponseWriter) Write(data []byte) (int, error) {
	if !s.written {
		s.WriteHeader(s.statusCode)
	}
	return s.rw.Write(data)
}

// createSignatureDefinition creates a signature definition based on the signer configuration.
func createSignatureDefinition(c signerConfig) (*input.Definition, error) {
	builder := input.NewDefinitionBuilder().
		Label(c.label).
		KeyID(c.kid).
		Components(c.components...)

	if c.alg != "" {
		builder = builder.Algorithm(c.alg)
	}

	if c.includeCreated {
		builder = builder.Created(c.clock.Now().Unix())
	}

	if c.tag != "" {
		builder = builder.Tag(c.tag)
	}

	return builder.Build()
}

// addSignatureHeaders generates the signature and adds it to the response headers.
func (w *signingResponseWriter) addSignatureHeaders() {
	// Create signature definition
	def, err := createSignatureDefinition(w.config)
	if err != nil {
		w.config.errorHandler.ServeHTTP(w, w.request.WithContext(WithSigningError(w.request.Context(), err)))
		return
	}

	// Create input value with the definition
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()

	// Prepare context with response information
	ctx := component.WithResponseInfo(w.request.Context(), w.Header(), w.statusCode,
		component.RequestInfoFromHTTP(w.request))

	// Sign the response using the new SignResponse API
	if err := htmsig.SignResponse(ctx, w.Header(), inputValue, w.config.key); err != nil {
		w.config.errorHandler.ServeHTTP(w, w.request.WithContext(WithSigningError(ctx, err)))
	}
}
