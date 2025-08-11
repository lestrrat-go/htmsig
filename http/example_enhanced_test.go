package http_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/lestrrat-go/htmsig/component"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
)

// ExampleVerifier_enhanced demonstrates the enhanced HTTP package features
func ExampleVerifier_enhanced() {
	// Generate a key pair for the example
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	// Create enhanced verifier with additional security features
	verifier := htmsighttp.NewVerifier(
		&htmsighttp.StaticKeyResolver{Key: publicKey},
		htmsighttp.WithMaxSignatureAge(5*time.Minute), // Prevent replay attacks
		htmsighttp.WithRequiredComponents( // Require specific components
			component.Method(),
			component.New("@target-uri"),
			component.New("date"),
		),
		htmsighttp.WithAllowedAlgorithms("rsa-pss-sha512"), // Restrict to specific algorithms
		htmsighttp.WithSkipOnMissing(false),                // Require signatures
	)

	// Create the main application handler
	appHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		fmt.Fprint(w, `{"message": "Hello, signed world!", "verified": true}`)
	})

	// Wrap with both verification and signing using the new API
	wrappedHandler := htmsighttp.Wrap(appHandler,
		htmsighttp.WithResolver(verifier.KeyResolver),
		htmsighttp.WithSigningKey("server-key-1", privateKey))

	// Start server
	fmt.Println("Enhanced HTTP Message Signatures server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", wrappedHandler))
}

// ExampleNewClient_enhanced demonstrates the enhanced client features
func ExampleNewClient_enhanced() {
	// Generate a key pair for the example
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// Create enhanced HTTP client with custom options
	client := htmsighttp.NewClient(
		privateKey,
		"client-key-1",
		htmsighttp.WithAlgorithm("rsa-pss-sha512"),
		htmsighttp.WithComponents(
			component.Method(),
			component.New("@target-uri"),
			component.New("content-type"),
			component.New("date"),
		),
		htmsighttp.WithSignatureLabel("my-sig"),
		htmsighttp.WithTag("example-client"),
	)

	// Make a signed request
	req, _ := http.NewRequest("POST", "https://api.example.com/data", nil)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Request failed: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Response status: %s\n", resp.Status)
	// The request was automatically signed with the specified components
}
