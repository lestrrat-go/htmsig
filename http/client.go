package http

import (
	"context"
	"net/http"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/option"
)

// Clock provides the current time for timestamp generation.
type Clock interface {
	Now() time.Time
}

// SystemClock uses the system time.
type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}

// fixedClock always returns the same time, useful for testing.
type fixedClock struct {
	time time.Time
}

func (c fixedClock) Now() time.Time {
	return c.time
}

// FixedClock returns a Clock that always returns the same time.
// This is useful for testing to ensure deterministic timestamps.
func FixedClock(t time.Time) Clock {
	return fixedClock{time: t}
}

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

	// Components specifies the components to include in signatures.
	// If nil, a sensible default set will be used for requests.
	Components []component.Identifier

	// SignatureLabel is the label for the signature.
	// If empty, defaults to "sig".
	SignatureLabel string

	// IncludeCreated adds the created parameter with current timestamp.
	IncludeCreated bool

	// Tag is an application-specific tag to include in the signature.
	Tag string

	// Clock provides timestamps. If nil, SystemClock is used.
	Clock Clock
}

// NewSigningTransport creates a new SigningTransport with the given configuration.
func NewSigningTransport(key any, keyID string) *SigningTransport {
	return &SigningTransport{
		Transport:      http.DefaultTransport,
		Key:            key,
		KeyID:          keyID,
		Components:     DefaultRequestComponents(),
		SignatureLabel: "sig",
		IncludeCreated: true,
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
		clock := t.Clock
		if clock == nil {
			clock = SystemClock{}
		}
		builder = builder.Created(clock.Now().Unix())
	}

	if t.Tag != "" {
		builder = builder.Tag(t.Tag)
	}

	return builder.MustBuild()
}

// getComponents returns the components to include in the signature.
func (t *SigningTransport) getComponents() []component.Identifier {
	if t.Components != nil {
		return t.Components
	}
	return DefaultRequestComponents()
}

// NewClient creates an http.Client that signs requests using the provided configuration.
// This is similar to oauth2.NewClient() in approach.
func NewClient(key any, keyID string, options ...TransportOption) *http.Client {
	transport := NewSigningTransport(key, keyID)

	// Apply options
	for _, option := range options {
		switch option.Ident() {
		case identTransport{}:
			transport.Transport = option.Value().(http.RoundTripper)
		case identAlgorithm{}:
			transport.Algorithm = option.Value().(string)
		case identComponents{}:
			transport.Components = option.Value().([]component.Identifier)
		case identSignatureLabel{}:
			transport.SignatureLabel = option.Value().(string)
		case identCreated{}:
			transport.IncludeCreated = option.Value().(bool)
		case identTag{}:
			transport.Tag = option.Value().(string)
		case identClockOption{}:
			transport.Clock = option.Value().(Clock)
		}
	}

	return &http.Client{
		Transport: transport,
	}
}

// TransportOption configures a SigningTransport.
type TransportOption = option.Interface

// WithTransport sets the underlying transport.
func WithTransport(transport http.RoundTripper) TransportOption {
	return option.New(identTransport{}, transport)
}

type identTransport struct{}

func (identTransport) String() string { return "WithTransport" }

// WithAlgorithm sets the signature algorithm.
func WithAlgorithm(algorithm string) TransportOption {
	return option.New(identAlgorithm{}, algorithm)
}

type identAlgorithm struct{}

func (identAlgorithm) String() string { return "WithAlgorithm" }

// WithComponents sets the signature components.
func WithComponents(components ...component.Identifier) TransportOption {
	return option.New(identComponents{}, components)
}

type identComponents struct{}

func (identComponents) String() string { return "WithComponents" }

// WithSignatureLabel sets the signature label.
func WithSignatureLabel(label string) TransportOption {
	return option.New(identSignatureLabel{}, label)
}

type identSignatureLabel struct{}

func (identSignatureLabel) String() string { return "WithSignatureLabel" }

// WithCreated controls whether to include the created parameter.
func WithCreated(include bool) TransportOption {
	return option.New(identCreated{}, include)
}

type identCreated struct{}

func (identCreated) String() string { return "WithCreated" }

// WithTag sets the application-specific tag.
func WithTag(tag string) TransportOption {
	return option.New(identTag{}, tag)
}

type identTag struct{}

func (identTag) String() string { return "WithTag" }

// SignVerifyOption can be used with both signing and verification operations.
type SignVerifyOption interface {
	transportOption()
	signerOption()
	option.Interface
}

// clockOption implements SignVerifyOption
type clockOption struct {
	clock Clock
}

func (c clockOption) Ident() any       { return identClockOption{} }
func (c clockOption) Value() any       { return c.clock }
func (c clockOption) transportOption() {}
func (c clockOption) signerOption()    {}

type identClockOption struct{}

func (identClockOption) String() string { return "WithClock" }

// WithClock sets the clock used for timestamp generation.
// This option works for both TransportOption and signerOption.
func WithClock(clock Clock) SignVerifyOption {
	return clockOption{clock: clock}
}
