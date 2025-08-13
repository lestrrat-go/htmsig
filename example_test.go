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
		Algorithm(htmsig.AlgorithmRSAPSSSHA512).
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
		Algorithm(htmsig.AlgorithmRSAPSSSHA512).
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
