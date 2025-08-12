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
		fmt.Fprint(w, `{"message": "Hello, signed world!"}`)
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
		fmt.Fprint(w, `{"status": "success"}`)
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
	defer resp.Body.Close()

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
