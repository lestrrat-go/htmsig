package http_test

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	htmsig "github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/stretchr/testify/require"
)

// Test keys - generated for testing purposes only
var (
	testPrivateKey *rsa.PrivateKey
	testPublicKey  *rsa.PublicKey
)

func init() {
	// Generate test RSA key pair
	var err error
	testPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("failed to generate test key: %v", err))
	}
	testPublicKey = &testPrivateKey.PublicKey
}

// Test helper to create a simple test handler
func testHandler(message string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, message)
	})
}

func TestVerifier(t *testing.T) {
	t.Run("Missing signature with SkipOnMissing=false", func(t *testing.T) {
		verifier := htmsighttp.NewVerifier(&htmsighttp.StaticKeyResolver{Key: testPublicKey})
		verifier.SkipOnMissing = false

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		verifier.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "missing signature headers")
	})

	t.Run("Missing signature with SkipOnMissing=true", func(t *testing.T) {
		verifier := htmsighttp.NewVerifier(&htmsighttp.StaticKeyResolver{Key: testPublicKey})
		verifier.SkipOnMissing = true

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		verifier.ServeHTTP(w, req)

		// Should not write any response (allows request to continue)
		require.Equal(t, http.StatusOK, w.Code) // Default response writer status
		require.Empty(t, w.Body.String())
	})

	t.Run("Valid signature", func(t *testing.T) {
		// Create a signed request using the main htmsig package
		req := httptest.NewRequest("GET", "/test", nil)

		// Sign the request first
		inputValue := createBasicSignatureInput()
		ctx := component.WithRequestInfoFromHTTP(req.Context(), req)
		err := htmsig.SignRequest(ctx, req.Header, inputValue, testPrivateKey)
		require.NoError(t, err)

		// Now verify it
		verifier := htmsighttp.NewVerifier(&htmsighttp.StaticKeyResolver{Key: testPublicKey})
		w := httptest.NewRecorder()

		verifier.ServeHTTP(w, req)

		// Should not write any response (verification successful)
		require.Equal(t, http.StatusOK, w.Code)
		require.Empty(t, w.Body.String())
	})
}

func TestWrapper(t *testing.T) {
	t.Run("Verification only", func(t *testing.T) {
		keyResolver := &htmsighttp.StaticKeyResolver{Key: testPublicKey}

		verifier := htmsighttp.NewVerifier(keyResolver, htmsighttp.WithSkipOnMissing(true))
		handler := htmsighttp.Wrap(testHandler("success"), htmsighttp.WithVerifier(verifier))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "success", w.Body.String())
	})

	t.Run("Full workflow with verification and signing", func(t *testing.T) {
		// Create key resolver
		keyResolver := &htmsighttp.StaticKeyResolver{Key: testPublicKey}

		// Wrap the handler with both verification and signing
		verifier := htmsighttp.NewVerifier(keyResolver, htmsighttp.WithSkipOnMissing(true))
		signer := htmsighttp.NewResponseSigner(testPrivateKey, "test-key")
		handler := htmsighttp.Wrap(testHandler("success"),
			htmsighttp.WithVerifier(verifier),
			htmsighttp.WithSigner(signer))

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Code)
		require.Equal(t, "success", w.Body.String())

		// Note: Response signing is complex due to the need to capture response details
		// The actual signature verification would require more complex setup
	})
}

func TestSigningTransport(t *testing.T) {
	t.Run("Basic request signing", func(t *testing.T) {
		// Create a test server that echoes request headers
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Echo back signature headers
			w.Header().Set("X-Signature", r.Header.Get("Signature"))
			w.Header().Set("X-Signature-Input", r.Header.Get("Signature-Input"))
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, "ok")
		}))
		defer server.Close()

		// Create signing transport
		transport := htmsighttp.NewSigningTransport(testPrivateKey, "test-key")
		client := &http.Client{Transport: transport}

		// Make a request
		resp, err := client.Get(server.URL + "/test")
		require.NoError(t, err)
		defer func() { _ = resp.Body.Close() }()

		// Check that signature headers were added
		require.NotEmpty(t, resp.Header.Get("X-Signature"))
		require.NotEmpty(t, resp.Header.Get("X-Signature-Input"))

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, "ok", string(body))
	})
}

func TestNewClient(t *testing.T) {
	t.Run("Client with custom options", func(t *testing.T) {
		client := htmsighttp.NewClient(testPrivateKey, "test-key",
			htmsighttp.WithAlgorithm("rsa-pss-sha512"),
			htmsighttp.WithSignatureLabel("custom-sig"),
			htmsighttp.WithTag("test-client"),
		)

		require.NotNil(t, client)
		require.NotNil(t, client.Transport)

		transport, ok := client.Transport.(*htmsighttp.SigningTransport)
		require.True(t, ok)
		require.Equal(t, "rsa-pss-sha512", transport.Algorithm)
		require.Equal(t, "custom-sig", transport.SignatureLabel)
		require.Equal(t, "test-client", transport.Tag)
	})
}

func TestKeyResolvers(t *testing.T) {
	t.Run("StaticKeyResolver", func(t *testing.T) {
		resolver := &htmsighttp.StaticKeyResolver{Key: testPublicKey}

		key, err := resolver.ResolveKey("any-key-id")
		require.NoError(t, err)
		require.Equal(t, testPublicKey, key)
	})

	t.Run("MapKeyResolver", func(t *testing.T) {
		resolver := &htmsighttp.MapKeyResolver{
			Keys: map[string]any{
				"key1": testPublicKey,
				"key2": "another-key",
			},
		}

		key, err := resolver.ResolveKey("key1")
		require.NoError(t, err)
		require.Equal(t, testPublicKey, key)

		_, err = resolver.ResolveKey("nonexistent")
		require.Error(t, err)
		require.Contains(t, err.Error(), "key not found")
	})

	t.Run("KeyResolverFunc", func(t *testing.T) {
		resolver := htmsighttp.KeyResolverFunc(func(keyID string) (any, error) {
			if keyID == "test-key" {
				return testPublicKey, nil
			}
			return nil, fmt.Errorf("unknown key: %s", keyID)
		})

		key, err := resolver.ResolveKey("test-key")
		require.NoError(t, err)
		require.Equal(t, testPublicKey, key)

		_, err = resolver.ResolveKey("unknown")
		require.Error(t, err)
	})
}

func TestErrorHandling(t *testing.T) {
	t.Run("Default error handler", func(t *testing.T) {
		handler := htmsighttp.DefaultErrorHandler()

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnauthorized, w.Code)
		require.Contains(t, w.Body.String(), "401 Unauthorized")
		require.Equal(t, "text/plain; charset=utf-8", w.Header().Get("Content-Type"))
	})

	t.Run("Custom error handler", func(t *testing.T) {
		customHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, "Custom error response")
		})

		verifier := htmsighttp.NewVerifier(&htmsighttp.StaticKeyResolver{Key: testPublicKey})
		verifier.ErrorHandler = customHandler
		verifier.SkipOnMissing = false

		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()

		verifier.ServeHTTP(w, req)

		require.Equal(t, http.StatusForbidden, w.Code)
		require.Equal(t, "Custom error response", w.Body.String())
	})
}

// Helper function to create a basic signature input for testing
func createBasicSignatureInput() *input.Value {
	def := input.NewDefinitionBuilder().
		Label("test-sig").
		KeyID("test-key").
		Components(
			component.Method(),
			component.New("@target-uri"),
		).
		MustBuild()

	return input.NewValueBuilder().AddDefinition(def).MustBuild()
}
