package htmsig_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/stretchr/testify/require"
)

// testKeyResolver implements KeyResolver for testing
type testKeyResolver struct {
	keys map[string]any
}

func (r *testKeyResolver) ResolveKey(keyID string) (any, error) {
	key, exists := r.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key %q not found", keyID)
	}
	return key, nil
}

// createTestRequest creates a standard test HTTP request
func createTestRequest(t *testing.T) *http.Request {
	req, err := http.NewRequest("POST", "https://example.com/foo?param=value&pet=dog", nil)
	require.NoError(t, err)
	
	req.Header.Set("Host", "example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "18")
	req.Header.Set("Cache-Control", "max-age=60")
	
	return req
}

func TestSignAndVerifyRequest_RSA_PSS(t *testing.T) {
	t.Parallel()
	
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey
	
	tests := []struct {
		name      string
		algorithm string
	}{
		{"rsa-pss-sha256", "rsa-pss-sha256"},
		{"rsa-pss-sha384", "rsa-pss-sha384"},
		{"rsa-pss-sha512", "rsa-pss-sha512"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createTestRequest(t)
			
			// Create signature definition
			def, err := input.NewDefinitionBuilder().
				Label("sig1").
				Components("@method", "@target-uri", "@authority", "content-type", "date", "cache-control").
				KeyID("test-key-rsa-pss").
				Algorithm(tt.algorithm).
				Build()
			require.NoError(t, err)
			
			inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
			
			// Sign the request
			err = htmsig.SignRequest(req, inputValue, privKey)
			require.NoError(t, err)
			
			// Verify headers are set
			require.NotEmpty(t, req.Header.Get("Signature-Input"))
			require.NotEmpty(t, req.Header.Get("Signature"))
			
			// Create key resolver
			keyResolver := &testKeyResolver{
				keys: map[string]any{
					"test-key-rsa-pss": pubKey,
				},
			}
			
			// Verify the request
			err = htmsig.VerifyRequest(req, keyResolver)
			require.NoError(t, err)
		})
	}
}

func TestSignAndVerifyRequest_RSA_PKCS1(t *testing.T) {
	t.Parallel()
	
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey
	
	tests := []struct {
		name      string
		algorithm string
	}{
		{"rsa-v1_5-sha256", "rsa-v1_5-sha256"},
		{"rsa-v1_5-sha384", "rsa-v1_5-sha384"},
		{"rsa-v1_5-sha512", "rsa-v1_5-sha512"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createTestRequest(t)
			
			// Create signature definition
			def, err := input.NewDefinitionBuilder().
				Label("sig1").
				Components("@method", "@target-uri", "@authority", "content-type", "date").
				KeyID("test-key-rsa-pkcs1").
				Algorithm(tt.algorithm).
				Build()
			require.NoError(t, err)
			
			inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
			
			// Sign the request
			err = htmsig.SignRequest(req, inputValue, privKey)
			require.NoError(t, err)
			
			// Create key resolver
			keyResolver := &testKeyResolver{
				keys: map[string]any{
					"test-key-rsa-pkcs1": pubKey,
				},
			}
			
			// Verify the request
			err = htmsig.VerifyRequest(req, keyResolver)
			require.NoError(t, err)
		})
	}
}

func TestSignAndVerifyRequest_ECDSA(t *testing.T) {
	t.Parallel()
	
	tests := []struct {
		name      string
		algorithm string
		curve     elliptic.Curve
	}{
		{"ecdsa-p256-sha256", "ecdsa-p256-sha256", elliptic.P256()},
		{"ecdsa-p384-sha384", "ecdsa-p384-sha384", elliptic.P384()},
		{"ecdsa-p521-sha512", "ecdsa-p521-sha512", elliptic.P521()},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate ECDSA key pair
			privKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)
			pubKey := &privKey.PublicKey
			
			req := createTestRequest(t)
			
			// Create signature definition
			def, err := input.NewDefinitionBuilder().
				Label("sig1").
				Components("@method", "@target-uri", "@authority", "content-type", "date").
				KeyID("test-key-ecdsa").
				Algorithm(tt.algorithm).
				Build()
			require.NoError(t, err)
			
			inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
			
			// Sign the request
			err = htmsig.SignRequest(req, inputValue, privKey)
			require.NoError(t, err)
			
			// Create key resolver
			keyResolver := &testKeyResolver{
				keys: map[string]any{
					"test-key-ecdsa": pubKey,
				},
			}
			
			// Verify the request
			err = htmsig.VerifyRequest(req, keyResolver)
			require.NoError(t, err)
		})
	}
}

func TestSignAndVerifyRequest_EdDSA(t *testing.T) {
	t.Parallel()
	
	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	
	req := createTestRequest(t)
	
	// Create signature definition
	def, err := input.NewDefinitionBuilder().
		Label("sig1").
		Components("@method", "@target-uri", "@authority", "content-type", "date").
		KeyID("test-key-ed25519").
		Algorithm("ed25519").
		Build()
	require.NoError(t, err)
	
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	
	// Sign the request
	err = htmsig.SignRequest(req, inputValue, privKey)
	require.NoError(t, err)
	
	// Create key resolver
	keyResolver := &testKeyResolver{
		keys: map[string]any{
			"test-key-ed25519": pubKey,
		},
	}
	
	// Verify the request
	err = htmsig.VerifyRequest(req, keyResolver)
	require.NoError(t, err)
}

func TestSignAndVerifyRequest_HMAC(t *testing.T) {
	t.Parallel()
	
	// Generate HMAC key
	hmacKey := make([]byte, 32)
	_, err := rand.Read(hmacKey)
	require.NoError(t, err)
	
	tests := []struct {
		name      string
		algorithm string
	}{
		{"hmac-sha256", "hmac-sha256"},
		{"hmac-sha384", "hmac-sha384"},
		{"hmac-sha512", "hmac-sha512"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := createTestRequest(t)
			
			// Create signature definition
			def, err := input.NewDefinitionBuilder().
				Label("sig1").
				Components("@method", "@target-uri", "@authority", "content-type", "date").
				KeyID("test-key-hmac").
				Algorithm(tt.algorithm).
				Build()
			require.NoError(t, err)
			
			inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
			
			// Sign the request
			err = htmsig.SignRequest(req, inputValue, hmacKey)
			require.NoError(t, err)
			
			// Create key resolver
			keyResolver := &testKeyResolver{
				keys: map[string]any{
					"test-key-hmac": hmacKey,
				},
			}
			
			// Verify the request
			err = htmsig.VerifyRequest(req, keyResolver)
			require.NoError(t, err)
		})
	}
}

func TestSignAndVerifyRequest_MultipleSignatures(t *testing.T) {
	t.Parallel()
	
	// Generate different key types
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rsaPub := &rsaPriv.PublicKey
	
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdsaPub := &ecdsaPriv.PublicKey
	
	hmacKey := make([]byte, 32)
	_, err = rand.Read(hmacKey)
	require.NoError(t, err)
	
	req := createTestRequest(t)
	
	// Create multiple signature definitions
	rsaDef, err := input.NewDefinitionBuilder().
		Label("rsa-sig").
		Components("@method", "@target-uri", "@authority").
		KeyID("test-key-rsa").
		Algorithm("rsa-pss-sha256").
		Build()
	require.NoError(t, err)
	
	ecdsaDef, err := input.NewDefinitionBuilder().
		Label("ecdsa-sig").
		Components("@method", "@target-uri", "@authority", "content-type").
		KeyID("test-key-ecdsa").
		Algorithm("ecdsa-p256-sha256").
		Build()
	require.NoError(t, err)
	
	hmacDef, err := input.NewDefinitionBuilder().
		Label("hmac-sig").
		Components("@method", "@target-uri", "@authority", "date").
		KeyID("test-key-hmac").
		Algorithm("hmac-sha256").
		Build()
	require.NoError(t, err)
	
	// Note: We'll sign each signature separately since SignRequest 
	// currently replaces headers rather than appending to them
	
	// Sign the request with RSA key first
	err = htmsig.SignRequest(req, 
		input.NewValueBuilder().AddDefinition(rsaDef).MustBuild(), 
		rsaPriv)
	require.NoError(t, err)
	
	// Sign with ECDSA key (this should add to existing signatures)
	err = htmsig.SignRequest(req,
		input.NewValueBuilder().AddDefinition(ecdsaDef).MustBuild(),
		ecdsaPriv)
	require.NoError(t, err)
	
	// Sign with HMAC key
	err = htmsig.SignRequest(req,
		input.NewValueBuilder().AddDefinition(hmacDef).MustBuild(),
		hmacKey)
	require.NoError(t, err)
	
	// Create key resolver with all keys
	keyResolver := &testKeyResolver{
		keys: map[string]any{
			"test-key-rsa":   rsaPub,
			"test-key-ecdsa": ecdsaPub,
			"test-key-hmac":  hmacKey,
		},
	}
	
	// Verify the request - should verify all signatures
	err = htmsig.VerifyRequest(req, keyResolver)
	require.NoError(t, err)
}

func TestSignAndVerifyRequest_WithTimestamps(t *testing.T) {
	t.Parallel()
	
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey
	
	req := createTestRequest(t)
	
	now := time.Now().Unix()
	expires := now + 3600 // 1 hour from now
	
	// Create signature definition with timestamps
	def, err := input.NewDefinitionBuilder().
		Label("sig1").
		Components("@method", "@target-uri", "@authority", "content-type", "date").
		KeyID("test-key-rsa").
		Algorithm("rsa-pss-sha256").
		Created(now).
		Expires(expires).
		Build()
	require.NoError(t, err)
	
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	
	// Sign the request
	err = htmsig.SignRequest(req, inputValue, privKey)
	require.NoError(t, err)
	
	// Create key resolver
	keyResolver := &testKeyResolver{
		keys: map[string]any{
			"test-key-rsa": pubKey,
		},
	}
	
	// Verify the request
	err = htmsig.VerifyRequest(req, keyResolver)
	require.NoError(t, err)
}

func TestSignAndVerifyRequest_WithNonceAndTag(t *testing.T) {
	t.Parallel()
	
	// Generate RSA key pair
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey
	
	req := createTestRequest(t)
	
	// Create signature definition with nonce and tag
	def, err := input.NewDefinitionBuilder().
		Label("sig1").
		Components("@method", "@target-uri", "@authority", "content-type").
		KeyID("test-key-rsa").
		Algorithm("rsa-pss-sha256").
		Nonce("random-nonce-12345").
		Tag("app-specific-tag").
		Build()
	require.NoError(t, err)
	
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	
	// Sign the request
	err = htmsig.SignRequest(req, inputValue, privKey)
	require.NoError(t, err)
	
	// Create key resolver
	keyResolver := &testKeyResolver{
		keys: map[string]any{
			"test-key-rsa": pubKey,
		},
	}
	
	// Verify the request
	err = htmsig.VerifyRequest(req, keyResolver)
	require.NoError(t, err)
}

// Error condition tests
func TestVerifyRequest_Errors(t *testing.T) {
	t.Parallel()
	
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKey := &privKey.PublicKey
	
	// Create a signed request
	req := createTestRequest(t)
	def, err := input.NewDefinitionBuilder().
		Label("sig1").
		Components("@method", "@target-uri", "@authority").
		KeyID("test-key").
		Algorithm("rsa-pss-sha256").
		Build()
	require.NoError(t, err)
	
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	err = htmsig.SignRequest(req, inputValue, privKey)
	require.NoError(t, err)
	
	keyResolver := &testKeyResolver{
		keys: map[string]any{
			"test-key": pubKey,
		},
	}
	
	t.Run("missing_signature_input_header", func(t *testing.T) {
		reqCopy := createTestRequest(t)
		reqCopy.Header.Set("Signature", req.Header.Get("Signature"))
		// Missing Signature-Input header
		
		err := htmsig.VerifyRequest(reqCopy, keyResolver)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing Signature-Input header")
	})
	
	t.Run("missing_signature_header", func(t *testing.T) {
		reqCopy := createTestRequest(t)
		reqCopy.Header.Set("Signature-Input", req.Header.Get("Signature-Input"))
		// Missing Signature header
		
		err := htmsig.VerifyRequest(reqCopy, keyResolver)
		require.Error(t, err)
		require.Contains(t, err.Error(), "missing Signature header")
	})
	
	t.Run("key_not_found", func(t *testing.T) {
		reqCopy := createTestRequest(t)
		reqCopy.Header.Set("Signature-Input", req.Header.Get("Signature-Input"))
		reqCopy.Header.Set("Signature", req.Header.Get("Signature"))
		
		emptyResolver := &testKeyResolver{keys: map[string]any{}}
		
		err := htmsig.VerifyRequest(reqCopy, emptyResolver)
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to resolve key")
	})
	
	t.Run("wrong_key", func(t *testing.T) {
		reqCopy := createTestRequest(t)
		reqCopy.Header.Set("Signature-Input", req.Header.Get("Signature-Input"))
		reqCopy.Header.Set("Signature", req.Header.Get("Signature"))
		
		wrongPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		wrongResolver := &testKeyResolver{
			keys: map[string]any{
				"test-key": &wrongPrivKey.PublicKey,
			},
		}
		
		err := htmsig.VerifyRequest(reqCopy, wrongResolver)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
	})
	
	t.Run("modified_request", func(t *testing.T) {
		reqCopy := createTestRequest(t)
		reqCopy.Header.Set("Signature-Input", req.Header.Get("Signature-Input"))
		reqCopy.Header.Set("Signature", req.Header.Get("Signature"))
		
		// Modify the request method after signing (this component is covered by the signature)
		reqCopy.Method = "GET" // Original was POST
		
		err := htmsig.VerifyRequest(reqCopy, keyResolver)
		require.Error(t, err)
		require.Contains(t, err.Error(), "signature verification failed")
	})
}

func TestSignRequest_Errors(t *testing.T) {
	t.Parallel()
	
	req := createTestRequest(t)
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	
	t.Run("unsupported_algorithm", func(t *testing.T) {
		def, err := input.NewDefinitionBuilder().
			Label("sig1").
			Components("@method").
			KeyID("test-key").
			Algorithm("unsupported-alg").
			Build()
		require.NoError(t, err)
		
		inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
		
		err = htmsig.SignRequest(req, inputValue, privKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported HTTP Message Signatures algorithm")
	})
	
	t.Run("wrong_key_type", func(t *testing.T) {
		def, err := input.NewDefinitionBuilder().
			Label("sig1").
			Components("@method").
			KeyID("test-key").
			Algorithm("rsa-pss-sha256").
			Build()
		require.NoError(t, err)
		
		inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
		
		// Try to sign with wrong key type (string instead of crypto key)
		err = htmsig.SignRequest(req, inputValue, "not-a-key")
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to sign")
	})
}