package http

import (
	"context"
	"net/http"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
)

// SigningTransport is an http.RoundTripper that signs HTTP requests.
type SigningTransport struct {
	// Transport is the underlying RoundTripper.
	// If nil, http.DefaultTransport is used.
	Transport http.RoundTripper

	// Key is the private key used for signing requests.
	// Can be RSA, ECDSA, Ed25519 private key, or HMAC shared secret.
	Key any

	// KeyID identifies the key used for signing.
	KeyID string

	// Algorithm specifies the signature algorithm.
	// If empty, algorithm will be determined from the key type.
	Algorithm string

	// DefaultComponents specifies the default components to include in signatures.
	// If nil, a sensible default set will be used for requests.
	DefaultComponents []component.Identifier

	// SignatureLabel is the label for the signature.
	// If empty, defaults to "sig".
	SignatureLabel string

	// IncludeCreated adds the created parameter with current timestamp.
	IncludeCreated bool

	// Tag is an application-specific tag to include in the signature.
	Tag string
}

// NewSigningTransport creates a new SigningTransport with the given configuration.
func NewSigningTransport(key any, keyID string) *SigningTransport {
	return &SigningTransport{
		Transport:         http.DefaultTransport,
		Key:               key,
		KeyID:             keyID,
		DefaultComponents: DefaultRequestComponents(),
		SignatureLabel:    "sig",
		IncludeCreated:    true,
	}
}

// DefaultRequestComponents returns a sensible default set of components
// for request signatures.
func DefaultRequestComponents() []component.Identifier {
	return []component.Identifier{
		component.Method(),
		component.New("@target-uri"),
		// Note: Only include mandatory derived components by default
		// Optional headers like content-type should be added explicitly if needed
	}
}

// RoundTrip implements http.RoundTripper by signing the request before sending it.
func (t *SigningTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone the request to avoid modifying the original
	signedReq := req.Clone(req.Context())

	// Add Date header if not present
	if signedReq.Header.Get("Date") == "" {
		signedReq.Header.Set("Date", time.Now().UTC().Format(http.TimeFormat))
	}

	// Create signature definition
	def := t.createSignatureDefinition()

	// Create input value with the definition
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()

	// Sign the request using the new SignRequest API
	ctx := component.WithRequestInfoFromHTTP(context.Background(), signedReq)
	err := htmsig.SignRequest(ctx, signedReq.Header, inputValue, t.Key)
	if err != nil {
		return nil, err
	}

	// Use the underlying transport to send the signed request
	transport := t.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	return transport.RoundTrip(signedReq)
}

// createSignatureDefinition creates a signature definition based on the transport configuration.
func (t *SigningTransport) createSignatureDefinition() *input.Definition {
	builder := input.NewDefinitionBuilder().
		Label(t.SignatureLabel).
		KeyID(t.KeyID).
		Components(t.getComponents()...)

	if t.Algorithm != "" {
		builder = builder.Algorithm(t.Algorithm)
	}

	if t.IncludeCreated {
		builder = builder.Created(time.Now().Unix())
	}

	if t.Tag != "" {
		builder = builder.Tag(t.Tag)
	}

	return builder.MustBuild()
}

// getComponents returns the components to include in the signature.
func (t *SigningTransport) getComponents() []component.Identifier {
	if t.DefaultComponents != nil {
		return t.DefaultComponents
	}
	return DefaultRequestComponents()
}

// NewClient creates an http.Client that signs requests using the provided configuration.
// This is similar to oauth2.NewClient() in approach.
func NewClient(key any, keyID string, options ...TransportOption) *http.Client {
	transport := NewSigningTransport(key, keyID)

	// Apply options
	for _, option := range options {
		option(transport)
	}

	return &http.Client{
		Transport: transport,
	}
}

// TransportOption configures a SigningTransport.
type TransportOption func(*SigningTransport)

// WithTransport sets the underlying transport.
func WithTransport(transport http.RoundTripper) TransportOption {
	return func(t *SigningTransport) {
		t.Transport = transport
	}
}

// WithAlgorithm sets the signature algorithm.
func WithAlgorithm(algorithm string) TransportOption {
	return func(t *SigningTransport) {
		t.Algorithm = algorithm
	}
}

// WithComponents sets the signature components.
func WithComponents(components ...component.Identifier) TransportOption {
	return func(t *SigningTransport) {
		t.DefaultComponents = components
	}
}

// WithSignatureLabel sets the signature label.
func WithSignatureLabel(label string) TransportOption {
	return func(t *SigningTransport) {
		t.SignatureLabel = label
	}
}

// WithoutCreated disables the created parameter.
func WithoutCreated() TransportOption {
	return func(t *SigningTransport) {
		t.IncludeCreated = false
	}
}

// WithTag sets the application-specific tag.
func WithTag(tag string) TransportOption {
	return func(t *SigningTransport) {
		t.Tag = tag
	}
}
