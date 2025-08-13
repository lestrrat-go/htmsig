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
  "bytes"
  "fmt"
  "io"
  "net/http"
  "net/http/httptest"
  "strings"
  "time"

  "github.com/lestrrat-go/htmsig/component"
  htmsighttp "github.com/lestrrat-go/htmsig/http"
)

func createApp(payload string, hmacKey []byte, clock htmsighttp.Clock) http.Handler {
  // Create a key resolver for verifying incoming requests
  keyResolver := htmsighttp.StaticKeyResolver(hmacKey)

  // Create reqVerifier for incoming requests
  reqVerifier := htmsighttp.NewVerifier(keyResolver)

  // Create response signer for outgoing responses
  responseSigner := htmsighttp.NewSigner(hmacKey, "server-key",
    htmsighttp.WithComponents(
      component.Method().WithParameter("req", true),    // ;req is required for response verification
      component.TargetURI().WithParameter("req", true), // ;req is required for response verification
      component.Status(),
      component.New("content-type"),
    ),
    htmsighttp.WithClock(clock))

  // Create the application handler
  app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusOK)
    _, _ = fmt.Fprint(w, payload)
  })

  // Wrap handler with both verification and signing. This will cause the
  // handler to both verify incoming requests and sign outgoing responses.
  wrappedHandler := htmsighttp.Wrap(
    app,
    htmsighttp.WithVerifier(reqVerifier),
    htmsighttp.WithSigner(responseSigner),
  )

  return wrappedHandler
}

// Example_client_server demonstrates client/server interaction
// with both request verification and response signing.
func Example_client_server() {
  const payload = `{"message": "Request verified and response signed"}`

  // Use HMAC key for deterministic signatures
  hmacKey := []byte("shared-hmac-secret")
  // Create fixed clock for deterministic timestamps
  fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
  clock := htmsighttp.FixedClock(fixedTime)

  app := createApp(payload, hmacKey, clock)
  // Create test server
  server := httptest.NewServer(app)
  defer server.Close()

  { // Using a client with no signing abilities - the server will attempt to verify
    // the request, but since the client does not sign, it will fail.
    client := &http.Client{}
    resp, err := client.Get(server.URL + "/test")
    if err != nil {
      fmt.Printf("request failed: %v\n", err)
      return
    }
    defer resp.Body.Close() //nolint:errcheck

    // We will get a 401 Unauthorized response
    if resp.StatusCode != http.StatusUnauthorized {
      fmt.Printf("Expected status 401 Unauthorized, got %d\n", resp.StatusCode)
      return
    }
  }

  { // To make this work, we create a new client with signing/verification features
    // Create request signer
    requestSigner := htmsighttp.NewSigner(hmacKey, "client-key",
      htmsighttp.WithComponents(
        component.Method(),
        component.TargetURI(),
      ),
      htmsighttp.WithClock(clock))

    // Create response verifier
    responseVerifier := htmsighttp.NewVerifier(
      htmsighttp.StaticKeyResolver(hmacKey),
    )

    client := htmsighttp.NewClient(
      htmsighttp.WithSigner(requestSigner),
      htmsighttp.WithVerifier(responseVerifier),
    )

    resp, err := client.Get(server.URL + "/test")
    if err != nil {
      fmt.Printf("request failed: %v\n", err)
      return
    }
    defer resp.Body.Close() //nolint:errcheck

    buf, err := io.ReadAll(resp.Body)
    if err != nil {
      fmt.Printf("Failed to read response body: %v\n", err)
      return
    }

    if resp.StatusCode != http.StatusOK {
      fmt.Printf("Expected status 200, got %d\n", resp.StatusCode)
      return
    }

    if !bytes.Equal(buf, []byte(payload)) {
      fmt.Printf("Expected response body %q, got %q\n", payload, string(buf))
      return
    }

    sig := resp.Header.Get("Signature")
    if sig == "" {
      fmt.Printf("Expected response to have Signature header, but got empty\n")
      return
    }

    // Signature should start with "sig=:" and end with ":"
    if !strings.HasPrefix(sig, "sig=:") || !strings.HasSuffix(sig, ":") {
      fmt.Printf("Expected response signature format 'sig=:...:', got %q\n", sig)
      return
    }
  }
  // Output:
}
```
source: [examples/client_server_example_test.go](https://github.com/lestrrat-go/htmsig/blob/main/examples/client_server_example_test.go)
<!-- END INCLUDE -->

The baove example shows how to use this module for http.Handlers, but you can certainly
do more low-level processing manually. Please read the documentation for `htmsig` package,
the `input` package, and `component` package for more details.

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