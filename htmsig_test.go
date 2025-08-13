package htmsig_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	htmsighttp "github.com/lestrrat-go/htmsig/http"
	"github.com/stretchr/testify/require"
)

func TestParseInput(t *testing.T) {
	t.Parallel()
	t.Run("Sanity (RFC942 #4.1)", func(t *testing.T) {
		t.Parallel()
		const src1 = `Signature-Input: sig1=("@method" "@target-uri" "@authority" \
  "content-digest" "cache-control");\
  created=1618884475;keyid="test-key-rsa-pss"`

		const src2 = `sig=("@target-uri" "@authority" "date" "cache-control");keyid="test-key-rsa-pss";alg="rsa-pss-sha512"; created=1618884475;expires=1618884775`

		// Use the constants to avoid unused variable warnings
		_ = src1
		_ = src2
	})
}

// TestTargetURIComponentDerivation tests the @target-uri derived component
// according to RFC 9421 Section 2.2.2
func TestTargetURIComponentDerivation(t *testing.T) {
	testCases := []struct {
		name              string
		method            string
		urlStr            string
		host              string
		expectedTargetURI string
		description       string
	}{
		{
			name:              "RFC 9421 Example - HTTPS POST with query",
			method:            "POST",
			urlStr:            "https://www.example.com/path?param=value",
			host:              "www.example.com",
			expectedTargetURI: "https://www.example.com/path?param=value",
			description:       "Example from RFC 9421 Section 2.2.2",
		},
		{
			name:              "Simple GET request",
			method:            "GET",
			urlStr:            "https://api.example.com/users",
			host:              "api.example.com",
			expectedTargetURI: "https://api.example.com/users",
			description:       "Simple HTTPS GET without query parameters",
		},
		{
			name:              "HTTP with port",
			method:            "GET",
			urlStr:            "http://localhost:8080/api/v1/test",
			host:              "localhost:8080",
			expectedTargetURI: "http://localhost:8080/api/v1/test",
			description:       "HTTP request with explicit port",
		},
		{
			name:              "HTTPS with non-default port",
			method:            "POST",
			urlStr:            "https://secure.example.com:8443/secure/endpoint?token=abc123",
			host:              "secure.example.com:8443",
			expectedTargetURI: "https://secure.example.com:8443/secure/endpoint?token=abc123",
			description:       "HTTPS with non-default port and query parameters",
		},
		{
			name:              "Root path with query",
			method:            "GET",
			urlStr:            "https://www.example.com/?search=test&page=1",
			host:              "www.example.com",
			expectedTargetURI: "https://www.example.com/?search=test&page=1",
			description:       "Root path with multiple query parameters",
		},
		{
			name:              "Complex query parameters",
			method:            "POST",
			urlStr:            "https://api.example.com/search?q=hello%20world&filter=active&sort=date",
			host:              "api.example.com",
			expectedTargetURI: "https://api.example.com/search?q=hello%20world&filter=active&sort=date",
			description:       "URL with encoded characters in query parameters",
		},
		{
			name:              "Path with encoded characters",
			method:            "GET",
			urlStr:            "https://example.com/users/john%20doe/profile",
			host:              "example.com",
			expectedTargetURI: "https://example.com/users/john%20doe/profile",
			description:       "Path with percent-encoded characters",
		},
		{
			name:              "Empty query parameter",
			method:            "GET",
			urlStr:            "https://example.com/test?empty=&value=123",
			host:              "example.com",
			expectedTargetURI: "https://example.com/test?empty=&value=123",
			description:       "URL with empty query parameter value",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: %s", tc.description)

			// Parse the URL to extract components
			parsedURL, err := url.Parse(tc.urlStr)
			require.NoError(t, err, "Failed to parse test URL")

			// Create an HTTP request for testing
			req, err := http.NewRequest(tc.method, tc.urlStr, nil)
			require.NoError(t, err, "Failed to create HTTP request")

			// Set the Host header
			req.Host = tc.host
			req.Header.Set("Host", tc.host)

			// Test 1: Resolve @target-uri from HTTP request using context
			ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
			targetURIComp := component.TargetURI()

			value, err := component.Resolve(ctx, targetURIComp)
			require.NoError(t, err, "Failed to resolve @target-uri component")
			require.Equal(t, tc.expectedTargetURI, value, "@target-uri component value mismatch")

			t.Logf("✓ @target-uri resolved correctly: %s", value)

			// Test 2: Resolve @target-uri using manual context setup
			ctx2 := component.WithRequestInfo(context.Background(),
				req.Header,
				req.Method,
				parsedURL.Scheme,
				parsedURL.Host,
				parsedURL.Path,
				parsedURL.RawQuery,
				tc.expectedTargetURI,
			)

			value2, err := component.Resolve(ctx2, targetURIComp)
			require.NoError(t, err, "Failed to resolve @target-uri with manual context")
			require.Equal(t, tc.expectedTargetURI, value2, "@target-uri value mismatch with manual context")

			t.Logf("✓ @target-uri resolved correctly with manual context: %s", value2)
		})
	}
}

// TestTargetURIInResponse tests @target-uri derivation in response context with req parameter
func TestTargetURIInResponse(t *testing.T) {
	// Create a test request
	req, err := http.NewRequest("POST", "https://www.example.com/api/submit?token=abc123", strings.NewReader(`{"data":"test"}`))
	require.NoError(t, err)
	req.Host = "www.example.com"
	req.Header.Set("Host", "www.example.com")
	req.Header.Set("Content-Type", "application/json")

	// Create a test response
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    req,
	}
	resp.Header.Set("Content-Type", "application/json")
	resp.Header.Set("Date", "Tue, 20 Apr 2021 02:07:56 GMT")

	// Test resolving @target-uri in response context with req parameter
	ctx := component.WithMode(context.Background(), component.ModeResponse)
	ctx = component.WithResponseInfoFromHTTP(ctx, resp)

	// This should work - @target-uri with req parameter in response
	targetURIComp := component.TargetURI().WithParameter("req", true)

	value, err := component.Resolve(ctx, targetURIComp)
	require.NoError(t, err, "Failed to resolve @target-uri;req in response")
	require.Equal(t, "https://www.example.com/api/submit?token=abc123", value)

	t.Logf("✓ @target-uri;req resolved correctly in response: %s", value)

	// This should fail - @target-uri without req parameter in response context
	// Create a fresh context to avoid any pollution
	freshCtx := component.WithMode(context.Background(), component.ModeResponse)
	freshCtx = component.WithResponseInfoFromHTTP(freshCtx, resp)

	targetURICompNoReq := component.TargetURI()

	// Debug the context
	mode := component.ModeFromContext(freshCtx)
	_, hasReqInfo := component.RequestInfoFromContext(freshCtx)
	_, hasRespInfo := component.ResponseInfoFromContext(freshCtx)
	t.Logf("Debug context: mode=%v, hasReqInfo=%v, hasRespInfo=%v", mode, hasReqInfo, hasRespInfo)

	value2, err2 := component.Resolve(freshCtx, targetURICompNoReq)
	t.Logf("Debug: value2=%q, err2=%v", value2, err2)
	require.Error(t, err2, "@target-uri without req parameter should fail in response context")

	t.Logf("✓ @target-uri correctly rejected without req parameter in response context")
}

// TestTargetURIEdgeCases tests edge cases and error conditions
func TestTargetURIEdgeCases(t *testing.T) {
	t.Run("Missing request info in context", func(t *testing.T) {
		ctx := context.Background()
		targetURIComp := component.TargetURI()

		_, err := component.Resolve(ctx, targetURIComp)
		require.Error(t, err, "Should fail when no request info in context")
		require.Contains(t, err.Error(), "no request information available")
	})

	t.Run("Nil request", func(t *testing.T) {
		ctx := component.WithRequestInfoFromHTTP(context.Background(), nil)
		targetURIComp := component.TargetURI()

		_, err := component.Resolve(ctx, targetURIComp)
		require.Error(t, err, "Should fail with nil request")
	})

	t.Run("Request with nil URL", func(t *testing.T) {
		req := &http.Request{
			Method: "GET",
			URL:    nil,
			Header: make(http.Header),
		}

		ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
		targetURIComp := component.TargetURI()

		_, err := component.Resolve(ctx, targetURIComp)
		require.Error(t, err, "Should fail with nil URL")
	})
}

// TestTargetURISignatureBase tests @target-uri in actual signature base generation
func TestTargetURISignatureBase(t *testing.T) {
	// Create a test request matching RFC 9421 example
	req, err := http.NewRequest("POST", "https://www.example.com/path?param=value", nil)
	require.NoError(t, err)
	req.Host = "www.example.com"
	req.Header.Set("Host", "www.example.com")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:56 GMT")

	// Test that @target-uri component can be resolved in signature base context
	ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
	targetURIComp := component.TargetURI()

	value, err := component.Resolve(ctx, targetURIComp)
	require.NoError(t, err)
	require.Equal(t, "https://www.example.com/path?param=value", value)

	// Verify this matches the RFC 9421 Section 2.2.2 example
	expectedValue := "https://www.example.com/path?param=value"
	require.Equal(t, expectedValue, value, "Should match RFC 9421 Section 2.2.2 example")

	t.Logf("✓ @target-uri component value matches RFC 9421 example: %s", value)
}

// TestTargetURIWithDifferentSchemes tests @target-uri with different URL schemes
func TestTargetURIWithDifferentSchemes(t *testing.T) {
	testCases := []struct {
		name     string
		url      string
		expected string
	}{
		{
			name:     "HTTP scheme",
			url:      "http://example.com/test",
			expected: "http://example.com/test",
		},
		{
			name:     "HTTPS scheme",
			url:      "https://example.com/test",
			expected: "https://example.com/test",
		},
		{
			name:     "HTTP with default port",
			url:      "http://example.com:80/test",
			expected: "http://example.com:80/test",
		},
		{
			name:     "HTTPS with default port",
			url:      "https://example.com:443/test",
			expected: "https://example.com:443/test",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tc.url, nil)
			require.NoError(t, err)

			ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
			targetURIComp := component.TargetURI()

			value, err := component.Resolve(ctx, targetURIComp)
			require.NoError(t, err)
			require.Equal(t, tc.expected, value)
		})
	}
}

// TestServerSideTargetURIDerivation tests @target-uri component derivation
// from server-side perspective as per RFC 9421 Section 2.2.2
func TestServerSideTargetURIDerivation(t *testing.T) {
	testCases := []struct {
		name              string
		method            string
		path              string
		query             string
		host              string
		scheme            string
		expectedTargetURI string
		description       string
	}{
		{
			name:              "RFC 9421 Example - Server side POST",
			method:            "POST",
			path:              "/path",
			query:             "param=value",
			host:              "www.example.com",
			scheme:            "https",
			expectedTargetURI: "https://www.example.com/path?param=value",
			description:       "Server receives POST /path?param=value HTTP/1.1\\nHost: www.example.com",
		},
		{
			name:              "Server side GET with port",
			method:            "GET",
			path:              "/api/v1/users",
			query:             "",
			host:              "localhost:8080",
			scheme:            "http",
			expectedTargetURI: "http://localhost:8080/api/v1/users",
			description:       "Server receives GET request with port in Host header",
		},
		{
			name:              "HTTPS server with query parameters",
			method:            "POST",
			path:              "/search",
			query:             "q=test&filter=active",
			host:              "api.example.com",
			scheme:            "https",
			expectedTargetURI: "https://api.example.com/search?q=test&filter=active",
			description:       "HTTPS server receiving POST with query parameters",
		},
		{
			name:              "Root path request",
			method:            "GET",
			path:              "/",
			query:             "page=1",
			host:              "www.example.com",
			scheme:            "https",
			expectedTargetURI: "https://www.example.com/?page=1",
			description:       "Root path with query parameters",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("Testing: %s", tc.description)

			// Create a server-side handler to test @target-uri derivation
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Logf("Server received: %s %s", r.Method, r.RequestURI)
				t.Logf("Host header: %s", r.Host)
				t.Logf("URL Path: %s", r.URL.Path)
				t.Logf("URL RawQuery: %s", r.URL.RawQuery)
				t.Logf("URL String: %s", r.URL.String())

				// This is what happens on the server side - we need to derive @target-uri
				ctx := component.WithRequestInfoFromHTTP(context.Background(), r)
				targetURIComp := component.TargetURI()

				value, err := component.Resolve(ctx, targetURIComp)
				t.Logf("Resolved @target-uri: %q (err: %v)", value, err)

				require.NoError(t, err, "Failed to resolve @target-uri on server side")
				require.Equal(t, tc.expectedTargetURI, value, "@target-uri component value mismatch")

				w.WriteHeader(http.StatusOK)
			})

			// Create test server
			server := httptest.NewUnstartedServer(handler)

			// Configure for HTTPS if needed
			if tc.scheme == "https" {
				server.StartTLS()
			} else {
				server.Start()
			}
			defer server.Close()

			// Build the request using the test server's URL but set Host header
			serverURL := server.URL + tc.path
			if tc.query != "" {
				serverURL += "?" + tc.query
			}

			// Create client request
			req, err := http.NewRequest(tc.method, serverURL, strings.NewReader("test"))
			require.NoError(t, err)
			req.Host = tc.host // Set Host header to expected value

			// Make the request to trigger server-side handling
			client := server.Client()
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close() //nolint:errcheck

			require.Equal(t, http.StatusOK, resp.StatusCode)
			t.Logf("✓ Server-side @target-uri resolved correctly: %s", tc.expectedTargetURI)
		})
	}
}

// TestServerSideTargetURIVsClientSide compares server-side vs client-side derivation
func TestServerSideTargetURIVsClientSide(t *testing.T) {
	// Test case from RFC 9421
	method := "POST"
	path := "/path"
	query := "param=value"
	host := "www.example.com"
	expectedTargetURI := "https://www.example.com/path?param=value"

	// Server-side handler
	var serverSideValue string
	var serverSideError error

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := component.WithRequestInfoFromHTTP(context.Background(), r)
		targetURIComp := component.TargetURI()
		serverSideValue, serverSideError = component.Resolve(ctx, targetURIComp)
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewTLSServer(handler)
	defer server.Close()

	// Make request to server - use server's URL but set Host header to expected value
	serverURL := server.URL + path
	if query != "" {
		serverURL += "?" + query
	}
	req, err := http.NewRequest(method, serverURL, nil)
	require.NoError(t, err)
	req.Host = host // Set the Host header to what we expect

	client := server.Client()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close() //nolint:errcheck

	// Check server-side derivation
	require.NoError(t, serverSideError, "Server-side @target-uri resolution failed")
	t.Logf("Server-side @target-uri: %q", serverSideValue)

	// Compare with client-side derivation (what the test was doing before)
	clientRequestURL := "https://" + host + path + "?" + query
	clientReq, err := http.NewRequest(method, clientRequestURL, nil)
	require.NoError(t, err)
	clientReq.Host = host

	ctx := component.WithRequestInfoFromHTTP(context.Background(), clientReq)
	targetURIComp := component.TargetURI()
	clientSideValue, err := component.Resolve(ctx, targetURIComp)
	require.NoError(t, err)
	t.Logf("Client-side @target-uri: %q", clientSideValue)

	// They should match the RFC expectation
	require.Equal(t, expectedTargetURI, clientSideValue, "Client-side should match RFC")
	require.Equal(t, expectedTargetURI, serverSideValue, "Server-side should match RFC")
	require.Equal(t, clientSideValue, serverSideValue, "Server-side and client-side should match")
}

func TestSignatureExpirationChecking(t *testing.T) {
	// Generate RSA key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create an HTTP request
	req, err := http.NewRequest("POST", "https://example.com/test", nil)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")

	// Use a fixed time for deterministic testing
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	staticClock := htmsighttp.FixedClock(fixedTime)

	// Test cases
	tests := []struct {
		name            string
		expiresOffset   time.Duration // offset from now to set expiration
		validateExpires bool          // whether to enable expiration validation
		expectError     bool          // whether verification should fail
	}{
		{
			name:            "Valid signature without expiration",
			expiresOffset:   0, // no expiration set
			validateExpires: true,
			expectError:     false,
		},
		{
			name:            "Valid signature with future expiration",
			expiresOffset:   time.Hour, // expires in 1 hour from fixed time
			validateExpires: true,
			expectError:     false,
		},
		{
			name:            "Expired signature with validation enabled",
			expiresOffset:   -time.Hour, // expired 1 hour before fixed time
			validateExpires: true,
			expectError:     true,
		},
		{
			name:            "Expired signature with validation disabled",
			expiresOffset:   -time.Hour, // expired 1 hour before fixed time
			validateExpires: false,
			expectError:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create signature definition
			builder := input.NewDefinitionBuilder().
				Label("test-sig").
				Components(
					component.Method(),
					component.TargetURI(),
					component.New("content-type"),
					component.New("date"),
				).
				KeyID("test-key-id")

			// Set expiration if specified
			if tt.expiresOffset != 0 {
				expiresTime := fixedTime.Add(tt.expiresOffset)
				builder = builder.ExpiresTime(expiresTime)
			}

			def, err := builder.Build()
			require.NoError(t, err)

			// Create input value and sign the request
			inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
			ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
			err = htmsig.SignRequest(ctx, req.Header, inputValue, privateKey)
			require.NoError(t, err)

			// Create key resolver - use StaticKeyResolver since we only have one key
			keyResolver := htmsighttp.StaticKeyResolver(&privateKey.PublicKey)

			// Create verification options
			var options []htmsig.VerifyOption
			if tt.validateExpires {
				options = append(options, htmsig.WithValidateExpires(true))
			}
			options = append(options, htmsig.WithClock(staticClock))

			// Verify the signature
			ctx = component.WithRequestInfoFromHTTP(context.Background(), req)
			err = htmsig.VerifyRequest(ctx, req.Header, keyResolver, options...)

			if tt.expectError {
				require.Error(t, err, "Expected verification to fail for expired signature")
				require.Contains(t, err.Error(), "signature expired", "Error should mention expiration")
			} else {
				require.NoError(t, err, "Expected verification to succeed")
			}
		})
	}
}

