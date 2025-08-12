# htmsig - RFC 9421 HTTP Message Signatures for Go

![Build Status](https://github.com/lestrrat-go/htmsig/workflows/CI/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/htmsig.svg)](https://pkg.go.dev/github.com/lestrrat-go/htmsig) [![codecov.io](https://codecov.io/github/lestrrat-go/htmsig/coverage.svg?branch=main)](https://codecov.io/github/lestrrat-go/htmsig?branch=main)

A complete Go implementation of [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), providing cryptographic signing and verification for HTTP requests and responses.

## Installation

```bash
go get github.com/lestrrat-go/htmsig
```

## Quick Start

### Basic Request Signing

<!-- INCLUDE(example_test.go) -->
```go
package htmsig_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
)

// ExampleSign demonstrates how to sign an HTTP request
func ExampleSign() {
	// Generate an RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}

	// Create an HTTP request to sign
	req, err := http.NewRequest(http.MethodPost, "https://example.com/api/data", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")

	// Create signature definition
	def, err := input.NewDefinitionBuilder().
		Label("my-signature").
		Components(
			component.Method(),
			component.TargetURI(),
			component.Authority(),
			component.New("content-type"),
			component.New("date"),
		).
		KeyID("my-key-id").
		Algorithm("rsa-pss-sha512").
		Build()
	if err != nil {
		panic(err)
	}

	// Create input value containing the signature definition
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()

	// Sign the request
	ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
	err = htmsig.SignRequest(ctx, req.Header, inputValue, privateKey)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Signed request has Signature-Input: %t\n", req.Header.Get("Signature-Input") != "")
	fmt.Printf("Signed request has Signature: %t\n", req.Header.Get("Signature") != "")
	// Output:
	// Signed request has Signature-Input: true
	// Signed request has Signature: true
}

// ExampleVerify demonstrates how to verify an HTTP request signature
func ExampleVerify() {
	// Generate an RSA key pair for the example
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	publicKey := &privateKey.PublicKey

	// Create and sign a request first
	req, err := http.NewRequest("POST", "https://example.com/api/data", nil)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")

	def, err := input.NewDefinitionBuilder().
		Label("my-signature").
		Components(
			component.Method(),
			component.TargetURI(),
			component.Authority(),
			component.New("content-type"),
			component.New("date"),
		).
		KeyID("my-key-id").
		Algorithm("rsa-pss-sha512").
		Build()
	if err != nil {
		panic(err)
	}

	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
	err = htmsig.SignRequest(ctx, req.Header, inputValue, privateKey)
	if err != nil {
		panic(err)
	}

	// Create a key resolver that can resolve keys by ID
	keyResolver := &exampleKeyResolver{
		keys: map[string]any{
			"my-key-id": publicKey,
		},
	}

	// Verify the request signature
	ctx = component.WithRequestInfoFromHTTP(context.Background(), req)
	err = htmsig.VerifyRequest(ctx, req.Header, keyResolver)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}

	fmt.Println("Signature verification successful")
	// Output:
	// Signature verification successful
}

// exampleKeyResolver is a simple key resolver for the example
type exampleKeyResolver struct {
	keys map[string]any
}

func (r *exampleKeyResolver) ResolveKey(keyID string) (any, error) {
	key, exists := r.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %q not found", keyID)
	}
	return key, nil
}

```
source: [example_test.go](https://github.com/lestrrat-go/htmsig/blob/main/example_test.go)
<!-- END INCLUDE -->

### HTTP Server with Signature Verification

<!-- INCLUDE(http/http_example_test.go) -->
```go
package http_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/lestrrat-go/htmsig/component"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
)

// ExampleWrap demonstrates how to create an HTTP handler with signature verification and response signing.
func ExampleWrap() {
	// Use HMAC key for deterministic signatures
	hmacKey := []byte("test-hmac-secret-key")

	// Create verifier that skips missing signatures for demo
	verifier := htmsighttp.NewVerifier(
		&htmsighttp.StaticKeyResolver{Key: hmacKey},
		htmsighttp.WithSkipOnMissing(true), // Allow unsigned requests for demo
	)

	// Create the main application handler
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Mon, 01 Jan 2024 00:00:00 GMT") // Fixed date for testing
		_, _ = fmt.Fprint(w, `{"message": "Hello, signed world!"}`)
	})

	// Create fixed clock for deterministic timestamps
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := htmsighttp.FixedClock(fixedTime)

	// Create response signer with specific components
	signer := htmsighttp.NewResponseSigner(hmacKey, "server-key-1",
		htmsighttp.WithSignerComponents(
			component.Status(),
			component.New("content-type"),
			component.New("date"),
		),
		htmsighttp.WithSignerSignatureLabel("server-key-1"),
		htmsighttp.WithClock(clock))

	// Wrap with both verification and signing
	wrappedHandler := htmsighttp.Wrap(appHandler,
		htmsighttp.WithVerifier(verifier),
		htmsighttp.WithSigner(signer))

	// Test the wrapped handler
	req := httptest.NewRequest("GET", "/api/data", nil)
	w := httptest.NewRecorder()
	wrappedHandler.ServeHTTP(w, req)

	fmt.Printf("Status: %d\n", w.Code)
	fmt.Printf("Content-Type: %s\n", w.Header().Get("Content-Type"))
	fmt.Printf("Signature: %s\n", w.Header().Get("Signature"))
	fmt.Printf("Signature-Input: %s\n", w.Header().Get("Signature-Input"))
	fmt.Printf("Body: %s\n", w.Body.String())

	// Output:
	// Status: 200
	// Content-Type: application/json
	// Signature: server-key-1=:JohOBV+tyheV58LS0h5rT3TfHynbV6bncnEG0jP5vnE=:
	// Signature-Input: server-key-1=("@status" "content-type" "date");created=1704067200;keyid="server-key-1"
	// Body: {"message": "Hello, signed world!"}
}

// ExampleNewClient demonstrates how to create an HTTP client that automatically signs requests
// and communicates with a server that both verifies incoming signatures and signs responses.
func ExampleNewClient() {
	// Use HMAC key for deterministic signatures
	hmacKey := []byte("shared-hmac-secret")

	// Create fixed clock for deterministic timestamps
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := htmsighttp.FixedClock(fixedTime)

	// Create a response signer for outgoing responses
	signer := htmsighttp.NewResponseSigner(hmacKey, "server-key",
		htmsighttp.WithSignerComponents(
			component.Status(),
			component.New("content-type"),
		),
		htmsighttp.WithClock(clock))

	// Create the application handler
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"status": "success"}`)
	})

	// Wrap with just response signing for now (verification can be added separately)
	wrappedHandler := htmsighttp.Wrap(appHandler,
		htmsighttp.WithSigner(signer))

	// Create test server with the wrapped handler
	server := httptest.NewServer(wrappedHandler)
	defer server.Close()

	// Create HTTP client with HMAC signing
	client := htmsighttp.NewClient(
		hmacKey,
		"client-key",
		htmsighttp.WithAlgorithm("hmac-sha256"),
		htmsighttp.WithComponents(
			component.Method(),
			component.TargetURI(),
		),
		htmsighttp.WithClock(clock))

	// Make a signed request to the server
	resp, err := client.Get(server.URL + "/api/test")
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Only print if something went wrong
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Unexpected status: %d\n", resp.StatusCode)
		return
	}

	// Check the actual signature value
	signature := resp.Header.Get("Signature")
	expectedSignature := "sig=:yK6Vo4nyKwMLjsL9qPmXo87yb4FAuUT7ZFmo9duC8QY=:"
	if signature != expectedSignature {
		fmt.Printf("Unexpected signature: %s\n", signature)
		return
	}

	// Check the signature input value
	signatureInput := resp.Header.Get("Signature-Input")
	expectedSignatureInput := "sig=(\"@status\" \"content-type\");created=1704067200;keyid=\"server-key\""
	if signatureInput != expectedSignatureInput {
		fmt.Printf("Unexpected signature input: %s\n", signatureInput)
		return
	}

	// Output:
}

```
source: [http/http_example_test.go](https://github.com/lestrrat-go/htmsig/blob/main/http/http_example_test.go)
<!-- END INCLUDE -->

## Components

### Core Package (`htmsig`)

The main package provides low-level signing and verification functions:

- `SignRequest(ctx, headers, inputValue, key)` - Sign HTTP requests
- `SignResponse(ctx, headers, inputValue, key)` - Sign HTTP responses  
- `VerifyRequest(ctx, headers, keyOrResolver)` - Verify HTTP requests
- `VerifyResponse(ctx, headers, keyOrResolver)` - Verify HTTP responses

### HTTP Package (`htmsig/http`)

High-level HTTP integration with handlers, middleware, and clients:

- **Server Components**:
  - `Verifier` - Middleware for verifying incoming signatures
  - `ResponseSigner` - Middleware for signing outgoing responses
  - `Wrap()` - Combine verification and signing around handlers

- **Client Components**:
  - `SigningTransport` - HTTP transport that signs requests
  - `NewClient()` - Create HTTP client with automatic signing

- **Key Resolution**:
  - `StaticKeyResolver` - Single key for all signatures
  - `MapKeyResolver` - Map-based key lookup
  - `KeyResolverFunc` - Custom key resolution function

### Component Package (`htmsig/component`)

Define which parts of HTTP messages to include in signatures:

- **Derived Components**: `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, `@status`
- **HTTP Fields**: Any HTTP header (e.g., `content-type`, `date`, `authorization`)
- **Structured Fields**: Support for structured field parsing

### Input Package (`htmsig/input`)

Build signature input specifications:

- `DefinitionBuilder` - Create signature definitions
- `ValueBuilder` - Combine multiple signature definitions
- Support for all RFC 9421 parameters: `created`, `expires`, `keyid`, `alg`, `nonce`, `tag`

## Supported Algorithms

| Algorithm | RFC 9421 Name | Description |
|-----------|---------------|-------------|
| RSA-PSS with SHA-512 | `rsa-pss-sha512` | Recommended RSA algorithm |
| RSA PKCS#1 v1.5 with SHA-256 | `rsa-v1_5-sha256` | Legacy RSA algorithm |
| ECDSA with P-256 and SHA-256 | `ecdsa-p256-sha256` | NIST P-256 curve |
| ECDSA with P-384 and SHA-384 | `ecdsa-p384-sha384` | NIST P-384 curve |
| Ed25519 | `ed25519` | Edwards curve signature |
| HMAC with SHA-256 | `hmac-sha256` | Symmetric key algorithm |

## Advanced Usage

### Custom Component Selection

```go
// Sign specific headers and derived components
def, _ := input.NewDefinitionBuilder().
    Components(
        component.Method(),                    // @method
        component.TargetURI(),                // @target-uri  
        component.New("authorization"),        // authorization header
        component.New("content-digest"),       // content-digest header
        component.New("date"),                // date header
    ).
    Created(time.Now().Unix()).               // Add creation timestamp
    Expires(time.Now().Add(time.Hour).Unix()). // Add expiration
    Build()
```

### Key Resolution with Multiple Keys

```go
keyResolver := &htmsighttp.MapKeyResolver{
    Keys: map[string]any{
        "rsa-key-2021":    rsaPublicKey,
        "ecdsa-key-2022":  ecdsaPublicKey,
        "hmac-secret":     []byte("shared-secret"),
    },
}

verifier := htmsighttp.NewVerifier(keyResolver)
```

### Response Signing

```go
// Sign HTTP responses
signer := htmsighttp.NewResponseSigner(privateKey, "response-key",
    htmsighttp.WithSignerComponents(
        component.Status(),              // @status
        component.New("content-type"),   // content-type header
        component.New("content-length"), // content-length header
    ),
)

handler := htmsighttp.Wrap(appHandler, htmsighttp.WithSigner(signer))
```

### Error Handling and Configuration

```go
verifier := htmsighttp.NewVerifier(keyResolver,
    htmsighttp.WithMaxSignatureAge(5*time.Minute),     // Reject old signatures
    htmsighttp.WithRequiredComponents(                  // Require specific components
        component.Method(),
        component.New("date"),
    ),
    htmsighttp.WithAllowedAlgorithms("rsa-pss-sha512"), // Restrict algorithms
    htmsighttp.WithSkipOnMissing(false),               // Require signatures
)
```

## Examples

See the [examples directory](./examples/) for complete working examples:

- Basic request/response signing
- HTTP server with verification
- HTTP client with signing
- Multiple signature scenarios
- Custom key resolution

## RFC 9421 Compliance

This implementation follows RFC 9421 specifications including:

- ✅ Signature base construction (Section 2.5)
- ✅ Signature creation and verification (Section 3)
- ✅ All standard algorithms (Section 3.3)
- ✅ Component identifiers (Section 2.1-2.3)
- ✅ Signature parameters (Section 2.4)
- ✅ Multiple signatures (Section 4.1)
- ✅ Test vectors from RFC examples

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass: `go test ./...`
2. Code is formatted: `go fmt ./...`
3. Linting passes: `golangci-lint run`
4. New features include tests and documentation

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [github.com/lestrrat-go/sfv](https://github.com/lestrrat-go/sfv) - Structured Field Values (RFC 8941)
- [github.com/lestrrat-go/dsig](https://github.com/lestrrat-go/dsig) - Digital Signatures for Go

## References

- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 8941: Structured Field Values](https://www.rfc-editor.org/rfc/rfc8941.html)
- [HTTP Message Signatures IANA Registry](https://www.iana.org/assignments/http-message-signatures/)