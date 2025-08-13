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
