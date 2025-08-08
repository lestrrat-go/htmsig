package sigbase_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/sigbase"
	"github.com/stretchr/testify/require"
)

func TestRequestBuilder(t *testing.T) {
	// Create a test HTTP request
	reqURL, err := url.Parse("https://www.example.com/path?param=value")
	require.NoError(t, err, "Failed to parse URL")

	req := &http.Request{
		Method: "POST",
		URL:    reqURL,
		Header: http.Header{
			"Host":         []string{"www.example.com"},
			"Content-Type": []string{"application/json"},
			"User-Agent":   []string{"MyApp/1.0"},
		},
	}

	t.Run("Components only", func(t *testing.T) {
		base, err := sigbase.Request(req).
			Components(htmsig.MethodComponent(), "@target-uri", "host").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Should contain the expected components
		require.Contains(t, baseStr, `"@method": POST`, "Expected @method component")
		require.Contains(t, baseStr, `"@target-uri": https://www.example.com/path?param=value`, "Expected @target-uri component")
		require.Contains(t, baseStr, `"host": www.example.com`, "Expected host component")

		// Should NOT contain signature params line (no definition provided)
		require.NotContains(t, baseStr, "@signature-params", "Should not contain @signature-params without definition")
	})

	t.Run("With signature parameters", func(t *testing.T) {
		// sigbase now properly handles signature parameters again
		base, err := sigbase.Request(req).
			Components("@method", "host").
			Created(1618884473).
			KeyID("test-key").
			Algorithm("rsa-pss-sha512").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Should contain the expected components
		require.Contains(t, baseStr, `"@method": POST`, "Expected @method component")
		require.Contains(t, baseStr, `"host": www.example.com`, "Expected host component")

		// Should contain signature params line (sigbase now handles this properly)
		require.Contains(t, baseStr, `"@signature-params":`, "sigbase should contain @signature-params line")
		require.Contains(t, baseStr, `created=1618884473`, "Expected created parameter")
		require.Contains(t, baseStr, `keyid="test-key"`, "Expected keyid parameter")
		require.Contains(t, baseStr, `alg="rsa-pss-sha512"`, "Expected alg parameter")

		// Verify it has component lines plus signature parameters line
		lines := strings.Split(strings.TrimSpace(baseStr), "\n")
		require.Equal(t, 3, len(lines), "Should have 2 component lines + 1 signature-params line")
		require.True(t, strings.HasPrefix(lines[0], `"@method":`), "First line should be @method")
		require.True(t, strings.HasPrefix(lines[1], `"host":`), "Second line should be host")
		require.True(t, strings.HasPrefix(lines[2], `"@signature-params":`), "Third line should be @signature-params")
	})

	t.Run("Error cases", func(t *testing.T) {
		// No request
		_, err := sigbase.Request(nil).Components("@method").Build()
		require.Error(t, err, "Expected error for nil request")
		require.Contains(t, err.Error(), "HTTP request is required", "Error message should mention missing HTTP request")

		// No components
		_, err = sigbase.Request(req).Build()
		require.Error(t, err, "Expected error for no components")
		require.Contains(t, err.Error(), "at least one component is required", "Error message should mention missing components")

		// Duplicate components
		_, err = sigbase.Request(req).Components("@method", "@method").Build()
		require.Error(t, err, "Expected error for duplicate components")
		require.Contains(t, err.Error(), "duplicate component identifier", "Error message should mention duplicate components")
	})
}

func TestResponseBuilder(t *testing.T) {
	// Create a test HTTP request
	reqURL, err := url.Parse("https://example.com/foo?param=value&pet=dog")
	require.NoError(t, err, "Failed to parse URL")

	req := &http.Request{
		Method: "POST",
		URL:    reqURL,
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"18"},
			"User-Agent":     []string{"MyApp/1.0"},
		},
	}

	// Create a test HTTP response
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"23"},
			"Server":         []string{"nginx/1.18.0"},
			"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
		},
	}

	t.Run("Response components only", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Components("@status", "content-type", "server").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Should contain the expected response components
		require.Contains(t, baseStr, `"@status": 200`, "Expected @status component")
		require.Contains(t, baseStr, `"content-type": application/json`, "Expected content-type component")
		require.Contains(t, baseStr, `"server": nginx/1.18.0`, "Expected server component")

		// Should NOT contain signature params line
		require.NotContains(t, baseStr, "@signature-params", "Should not contain @signature-params without parameters")
	})

	t.Run("Response with signature parameters", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Components("@status", "content-type").
			Created(1618884473).
			KeyID("test-key-ecc-p256").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Should contain the expected components
		require.Contains(t, baseStr, `"@status": 200`, "Expected @status component")
		require.Contains(t, baseStr, `"content-type": application/json`, "Expected content-type component")

		// Should contain signature params line
		require.Contains(t, baseStr, `"@signature-params":`, "Should contain @signature-params line")
		require.Contains(t, baseStr, `created=1618884473`, "Expected created parameter")
		require.Contains(t, baseStr, `keyid="test-key-ecc-p256"`, "Expected keyid parameter")

		// Verify structure: 2 component lines + 1 signature-params line
		lines := strings.Split(strings.TrimSpace(baseStr), "\n")
		require.Equal(t, 3, len(lines), "Should have 2 component lines + 1 signature-params line")
		require.True(t, strings.HasPrefix(lines[0], `"@status":`), "First line should be @status")
		require.True(t, strings.HasPrefix(lines[1], `"content-type":`), "Second line should be content-type")
		require.True(t, strings.HasPrefix(lines[2], `"@signature-params":`), "Third line should be @signature-params")
	})

	t.Run("Response with request components (req parameter)", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Request(req).
			Components("@status", "content-type", "@method;req", "@authority;req", "content-type;req").
			Created(1618884473).
			KeyID("test-key-ecc-p256").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Should contain response components
		require.Contains(t, baseStr, `"@status": 200`, "Expected @status component")
		require.Contains(t, baseStr, `"content-type": application/json`, "Expected response content-type")

		// Should contain request components (with req parameter)
		require.Contains(t, baseStr, `"@method;req": POST`, "Expected @method from request")
		require.Contains(t, baseStr, `"@authority;req": example.com`, "Expected @authority from request")
		require.Contains(t, baseStr, `"content-type;req": application/json`, "Expected content-type from request")

		// Should contain signature params line
		require.Contains(t, baseStr, `"@signature-params":`, "Should contain @signature-params line")
		require.Contains(t, baseStr, `"@method";req`, "Should list @method;req in signature params")
		require.Contains(t, baseStr, `"@authority";req`, "Should list @authority;req in signature params")
		require.Contains(t, baseStr, `"content-type";req`, "Should list content-type;req in signature params")

		// Verify structure
		lines := strings.Split(strings.TrimSpace(baseStr), "\n")
		require.Equal(t, 6, len(lines), "Should have 5 component lines + 1 signature-params line")
	})

	t.Run("Response status codes", func(t *testing.T) {
		testCases := []struct {
			statusCode int
			expected   string
		}{
			{200, "200"},
			{404, "404"},
			{500, "500"},
			{503, "503"},
		}

		for _, tc := range testCases {
			t.Run(string(rune(tc.statusCode)), func(t *testing.T) {
				testResp := &http.Response{
					StatusCode: tc.statusCode,
					Header: http.Header{
						"Content-Type": []string{"application/json"},
					},
				}

				base, err := sigbase.Response(testResp).
					Components("@status").
					Build()
				require.NoError(t, err, "Failed to build signature base")

				baseStr := string(base)
				require.Contains(t, baseStr, `"@status": `+tc.expected, "Expected @status: "+tc.expected)
			})
		}
	})

	t.Run("Error cases", func(t *testing.T) {
		// No response
		_, err := sigbase.Response(nil).Components("@status").Build()
		require.Error(t, err, "Expected error for nil response")
		require.Contains(t, err.Error(), "HTTP response is required", "Error message should mention missing HTTP response")

		// No components
		_, err = sigbase.Response(resp).Build()
		require.Error(t, err, "Expected error for no components")
		require.Contains(t, err.Error(), "at least one component is required", "Error message should mention missing components")

		// Duplicate components
		_, err = sigbase.Response(resp).Components("@status", "@status").Build()
		require.Error(t, err, "Expected error for duplicate components")
		require.Contains(t, err.Error(), "duplicate component identifier", "Error message should mention duplicate components")

		// req parameter without request
		_, err = sigbase.Response(resp).Components("@method;req").Build()
		require.Error(t, err, "Expected error for req parameter without request")
		require.Contains(t, err.Error(), "requires req parameter but no request was provided", "Error message should mention missing request for req parameter")

		// Unknown derived component
		_, err = sigbase.Response(resp).Components("@unknown").Build()
		require.Error(t, err, "Expected error for unknown derived component")
		require.Contains(t, err.Error(), "unknown response derived component", "Error message should mention unknown derived component")

		// Missing header field
		_, err = sigbase.Response(resp).Components("missing-header").Build()
		require.Error(t, err, "Expected error for missing header field")
		require.Contains(t, err.Error(), "header field \"missing-header\" not found in response", "Error message should mention missing header field")
	})
}

func TestResponseBuilder_RFC9421_Examples(t *testing.T) {
	// Test against examples from RFC 9421

	// Create request from RFC 9421 example
	reqURL, err := url.Parse("https://example.com/foo")
	require.NoError(t, err, "Failed to parse URL")

	req := &http.Request{
		Method: "POST",
		URL:    reqURL,
		Header: http.Header{
			"Host":           []string{"example.com"},
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"18"},
		},
	}

	// Create response from RFC 9421 example
	resp := &http.Response{
		StatusCode: 503, // Service Unavailable
		Header: http.Header{
			"Date":           []string{"Tue, 20 Apr 2021 02:07:56 GMT"},
			"Content-Type":   []string{"application/json"},
			"Content-Length": []string{"62"},
		},
	}

	t.Run("RFC 9421 B.2.4 Response Signing", func(t *testing.T) {
		// This recreates the example from RFC 9421 Section B.2.4
		base, err := sigbase.Response(resp).
			Request(req).
			Components(
				"@status",
				"content-type",
				"@authority;req",
				"@method;req",
				"@path;req",
			).
			Created(1618884479).
			KeyID("test-key-ecc-p256").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)

		// Verify the signature base matches RFC 9421 expectations
		require.Contains(t, baseStr, `"@status": 503`, "Expected @status: 503")
		require.Contains(t, baseStr, `"content-type": application/json`, "Expected content-type from response")
		require.Contains(t, baseStr, `"@authority;req": example.com`, "Expected @authority from request")
		require.Contains(t, baseStr, `"@method;req": POST`, "Expected @method from request")
		require.Contains(t, baseStr, `"@path;req": /foo`, "Expected @path from request")

		require.Contains(t, baseStr, `"@signature-params":`, "Should contain signature params")
		require.Contains(t, baseStr, `created=1618884479`, "Expected created timestamp")
		require.Contains(t, baseStr, `keyid="test-key-ecc-p256"`, "Expected keyid")

		// Verify the component ordering (should match the Components() order)
		lines := strings.Split(strings.TrimSpace(baseStr), "\n")
		require.Equal(t, 6, len(lines), "Should have 5 component lines + 1 signature-params line")
		require.True(t, strings.HasPrefix(lines[0], `"@status":`), "First line should be @status")
		require.True(t, strings.HasPrefix(lines[1], `"content-type":`), "Second line should be content-type")
		require.True(t, strings.HasPrefix(lines[2], `"@authority;req":`), "Third line should be @authority;req")
		require.True(t, strings.HasPrefix(lines[3], `"@method;req":`), "Fourth line should be @method;req")
		require.True(t, strings.HasPrefix(lines[4], `"@path;req":`), "Fifth line should be @path;req")
		require.True(t, strings.HasPrefix(lines[5], `"@signature-params":`), "Sixth line should be @signature-params")
	})
}

func TestResponseBuilder_HeaderHandling(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache", "no-store"},
			"Set-Cookie":    []string{"session=abc123", "theme=dark"},
		},
	}

	t.Run("Single header value", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Components("content-type").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)
		require.Contains(t, baseStr, `"content-type": application/json`, "Expected single header value")
	})

	t.Run("Multiple header values", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Components("cache-control").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)
		// Multiple values should be joined with ", "
		require.Contains(t, baseStr, `"cache-control": no-cache, no-store`, "Expected multiple header values joined")
	})

	t.Run("Multiple header instances", func(t *testing.T) {
		base, err := sigbase.Response(resp).
			Components("set-cookie").
			Build()
		require.NoError(t, err, "Failed to build signature base")

		baseStr := string(base)
		// Multiple header instances should be joined with ", "
		require.Contains(t, baseStr, `"set-cookie": session=abc123, theme=dark`, "Expected multiple header instances joined")
	})
}
