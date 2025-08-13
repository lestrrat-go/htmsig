# htmsig - RFC 9421 HTTP Message Signatures for Go

![Build Status](https://github.com/lestrrat-go/htmsig/workflows/CI/badge.svg) [![Go Reference](https://pkg.go.dev/badge/github.com/lestrrat-go/htmsig.svg)](https://pkg.go.dev/github.com/lestrrat-go/htmsig) [![codecov.io](https://codecov.io/github/lestrrat-go/htmsig/coverage.svg?branch=main)](https://codecov.io/github/lestrrat-go/htmsig?branch=main)

A complete Go implementation of [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), providing cryptographic signing and verification for HTTP requests and responses.

## Installation

```bash
go get github.com/lestrrat-go/htmsig
```

## Quick Start

### Client/Server Example

The easiest way to get started is using the `http` package for automatic signing and verification:

<!-- INCLUDE(examples/client_server_example_test.go) -->
```go
package htmsig_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/lestrrat-go/htmsig/component"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
)

// Example demonstrates a complete client/server interaction
// with HTTP message signatures using the http package.
func Example() {
	// Use HMAC key for deterministic signatures
	hmacKey := []byte("shared-hmac-secret")

	// Create fixed clock for deterministic timestamps
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := htmsighttp.FixedClock(fixedTime)

	// Create response signer for outgoing responses
	responseSigner := htmsighttp.NewResponseSigner(hmacKey, "server-key",
		htmsighttp.WithSignerComponents(
			component.Status(),
			component.New("content-type"),
		),
		htmsighttp.WithClock(clock))

	// Create the application handler
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"message": "Hello, signed world!"}`)
	})

	// Wrap handler with response signing
	wrappedHandler := htmsighttp.Wrap(appHandler,
		htmsighttp.WithSigner(responseSigner))

	// Create test server
	server := httptest.NewServer(wrappedHandler)
	defer server.Close()

	// Create HTTP client with automatic request signing
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
	resp, err := client.Post(server.URL+"/api/data", "application/json",
		strings.NewReader(`{"data": "test"}`))
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	fmt.Printf("Response Status: %d\n", resp.StatusCode)
	fmt.Printf("Response has Signature: %t\n", resp.Header.Get("Signature") != "")
	fmt.Printf("Response has Signature-Input: %t\n", resp.Header.Get("Signature-Input") != "")

	// Output:
	// Response Status: 200
	// Response has Signature: true
	// Response has Signature-Input: true
}

```
source: [client_server_example_test.go](https://github.com/lestrrat-go/htmsig/blob/main/client_server_example_test.go)
<!-- END INCLUDE -->

For more detailed examples showing manual signing and verification using the core `htmsig` package, see [manual_example_test.go](https://github.com/lestrrat-go/htmsig/blob/main/manual_example_test.go).

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

You can specify exactly which parts of the HTTP message to include in signatures:

- **Derived Components**: `@method`, `@target-uri`, `@authority`, `@scheme`, `@request-target`, `@path`, `@query`, `@status`
- **HTTP Fields**: Any HTTP header (e.g., `content-type`, `date`, `authorization`)
- **Signature Parameters**: `created`, `expires`, `keyid`, `alg`, `nonce`, `tag`

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Related Projects

- [github.com/lestrrat-go/sfv](https://github.com/lestrrat-go/sfv) - Structured Field Values (RFC 8941)
- [github.com/lestrrat-go/dsig](https://github.com/lestrrat-go/dsig) - Digital Signatures for Go

## References

- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [RFC 8941: Structured Field Values](https://www.rfc-editor.org/rfc/rfc8941.html)
- [HTTP Message Signatures IANA Registry](https://www.iana.org/assignments/http-message-signatures/)