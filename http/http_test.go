package http_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
	"github.com/stretchr/testify/require"
)

var staticClock = htmsighttp.FixedClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
var helloworldApp = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprint(w, "Hello, world!")
})

func TestSignResponse(t *testing.T) {
	key := []byte("top-secret-key")

	signer := htmsighttp.NewSigner(key, "test-key",
		htmsighttp.WithClock(staticClock),
		htmsighttp.WithComponents(
			component.Status(),
			component.New("content-type"),
		),
	)

	srv := httptest.NewServer(htmsighttp.Wrap(helloworldApp, htmsighttp.WithSigner(signer)))
	defer srv.Close()

	res, err := http.Get(srv.URL)
	require.NoError(t, err, `http.Get should succeed`)
	defer res.Body.Close() //nolint:errcheck

	require.Equal(t, http.StatusOK, res.StatusCode, `response status should be 200 OK`)
	sig := res.Header.Get(htmsig.SignatureHeader)
	require.NotEmpty(t, sig, `response should have a signature header`)
	expectedSig := "sig=:AKApfLNQ4PSqy0a+kFAEiJmlNrZ3n/PQ6PrSPwPf/Mo=:"
	require.Equal(t, expectedSig, sig, `response signature should match expected value`)
}

func TestVerifyRequest(t *testing.T) {
	key := []byte("top-secret-key")

	signer := htmsighttp.NewSigner(
		key,
		"test-key",
		htmsighttp.WithComponents(
			component.Method(),
			component.New("content-type"),
		),
		htmsighttp.WithClock(staticClock),
	)
	verifier := htmsighttp.NewVerifier(
		htmsighttp.StaticKeyResolver(key),
	)

	srv := httptest.NewServer(htmsighttp.Wrap(helloworldApp, htmsighttp.WithVerifier(verifier)))
	defer srv.Close()

	{
		// first request without signature should fail
		res, err := http.Get(srv.URL)
		require.NoError(t, err, `http.Get should succeed`)
		require.Equal(t, http.StatusUnauthorized, res.StatusCode)
	}

	{
		// second request will use the signature-enabled client
		client := htmsighttp.NewClient(
			htmsighttp.WithSigner(signer),
		)

		req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
		require.NoError(t, err, `http.NewRequest should succeed`)

		req.Header.Set("Content-Type", "application/json")

		res, err := client.Do(req)
		require.NoError(t, err, `client.Do should succeed`)
		defer res.Body.Close() //nolint:errcheck
		require.Equal(t, http.StatusOK, res.StatusCode, `response status should be 200 OK`)
	}
}

func TestRoundTrip(t *testing.T) {
	key := []byte("top-secret-key")

	// request signer.
	reqSigner := htmsighttp.NewSigner(
		key,
		"test-key",
		htmsighttp.WithComponents(
			component.Method(),
			component.TargetURI(),
			component.New("content-type"),
		),
		htmsighttp.WithClock(staticClock),
	)
	// response signer. Note that we have a response-specific component, @status,
	// and we have a TargetURI component with the "req" parameter set to true.
	resSigner := htmsighttp.NewSigner(
		key,
		"test-key",
		htmsighttp.WithComponents(
			component.Method().WithParameter("req", true),
			component.TargetURI().WithParameter("req", true),
			component.Status(),
			component.New("content-type"),
		),
		htmsighttp.WithClock(staticClock),
	)

	verifier := htmsighttp.NewVerifier(
		htmsighttp.StaticKeyResolver(key),
		htmsighttp.WithClock(staticClock),
	)

	srv := httptest.NewServer(
		htmsighttp.Wrap(
			helloworldApp,
			htmsighttp.WithSigner(resSigner),
			htmsighttp.WithVerifier(verifier),
		),
	)
	defer srv.Close()

	client := htmsighttp.NewClient(
		htmsighttp.WithSigner(reqSigner),
		htmsighttp.WithVerifier(verifier),
	)

	req, err := http.NewRequest(http.MethodGet, srv.URL, nil)
	require.NoError(t, err, `http.NewRequest should succeed`)
	req.Header.Set("Content-Type", "text/plain")

	res, err := client.Do(req)
	require.NoError(t, err, `client.Do should succeed`)
	defer res.Body.Close() //nolint:errcheck
	require.Equal(t, http.StatusOK, res.StatusCode, `response status should be 200 OK`)
	sig := res.Header.Get(htmsig.SignatureHeader)
	require.NotEmpty(t, sig, `response should have a signature header`)
}

func TestHTTPVerifierExpiration(t *testing.T) {
	// Generate RSA key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create expired signature
	req, err := http.NewRequest("GET", "https://example.com/test", nil)
	require.NoError(t, err)
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")

	// Use a fixed time for deterministic testing
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	staticClock := htmsighttp.FixedClock(fixedTime)

	// Sign with expiration 1 hour in the past (relative to fixed time)
	def, err := input.NewDefinitionBuilder().
		Label("test-sig").
		Components(component.Method(), component.TargetURI()).
		KeyID("test-key").
		ExpiresTime(fixedTime.Add(-time.Hour)).
		Build()
	require.NoError(t, err)

	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
	err = htmsig.SignRequest(ctx, req.Header, inputValue, privateKey)
	require.NoError(t, err)

	keyResolver := htmsighttp.StaticKeyResolver(&privateKey.PublicKey)

	t.Run("HTTP verifier with expiration validation disabled", func(t *testing.T) {
		verifier := htmsighttp.NewVerifier(keyResolver,
			htmsighttp.WithValidateExpires(false),
			htmsighttp.WithClock(staticClock))
		err := verifier.VerifyRequest(context.Background(), req)
		require.NoError(t, err, "Should succeed when expiration validation is disabled")
	})

	t.Run("HTTP verifier with expiration validation enabled", func(t *testing.T) {
		verifier := htmsighttp.NewVerifier(keyResolver,
			htmsighttp.WithValidateExpires(true),
			htmsighttp.WithClock(staticClock))
		err := verifier.VerifyRequest(context.Background(), req)
		require.Error(t, err, "Should fail when expiration validation is enabled")
		require.Contains(t, err.Error(), "signature expired")
	})
}

