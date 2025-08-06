package sigbase_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

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
			Components("@method", "@target-uri", "host").
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