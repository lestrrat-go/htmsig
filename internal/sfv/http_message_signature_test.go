package sfv_test

import (
	"bytes"
	"testing"

	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/stretchr/testify/require"
)

// TestHTTPMessageSignatureComponentIdentifiers tests parsing and marshaling
// of component identifiers as used in HTTP Message Signatures (RFC 9421)
func TestHTTPMessageSignatureComponentIdentifiers(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Component identifier with req parameter",
			input:    `"@method";req`,
			expected: `"@method";req`,
		},
		{
			name:     "Another component with req parameter",
			input:    `"@authority";req`,
			expected: `"@authority";req`,
		},
		{
			name:     "Component with string parameter",
			input:    `"@query-param";name="Pet"`,
			expected: `"@query-param";name="Pet"`,
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Test parsing
			parsed, err := sfv.Parse([]byte(tt.input))
			require.NoError(t, err, "Parse failed for input: %s", tt.input)

			// Test marshaling back with HTTP Message Signature formatting (no spaces)
			var buf bytes.Buffer
			encoder := sfv.NewEncoder(&buf)
			encoder.SetParameterSpacing("") // HTTP Message Signature format
			require.NoError(t, encoder.Encode(parsed), "HTTP Message Signature encoder failed for input: %s", tt.input)

			// Should match expected format (RFC 9421 style without spaces)
			require.Equal(t, tt.expected, buf.String(), "Marshal result should match expected format")

			// Also test that standard marshaling produces spaces (to verify the difference)
			standardMarshaled, err := sfv.Marshal(parsed)
			require.NoError(t, err, "Standard Marshal failed for input: %s", tt.input)
			require.Contains(t, string(standardMarshaled), "; ", "Standard marshal should contain spaces after semicolons")
		})
	}
}

// TestInnerListWithHTTPMessageSignatureComponents tests inner lists containing
// HTTP Message Signature component identifiers
func TestInnerListWithHTTPMessageSignatureComponents(t *testing.T) {
	input := `("@status" "content-type" "@method";req "@authority";req)`
	expected := `("@status" "content-type" "@method";req "@authority";req)`

	// Test parsing
	parsed, err := sfv.Parse([]byte(input))
	require.NoError(t, err, "Parse failed for input: %s", input)

	// Test marshaling back with HTTP Message Signature formatting (no spaces)
	var buf bytes.Buffer
	encoder := sfv.NewEncoder(&buf)
	encoder.SetParameterSpacing("") // HTTP Message Signature format
	require.NoError(t, encoder.Encode(parsed), "HTTP Message Signature encoder failed for input: %s", input)

	// Should match expected format (RFC 9421 style without spaces)
	require.Equal(t, expected, buf.String(), "Marshal result should match expected format")
}

// TestComponentIdentifierStructure verifies that SFV parsing correctly extracts
// component names and parameters for HTTP Message Signature component identifiers
func TestComponentIdentifierStructure(t *testing.T) {
	testCases := []struct {
		name              string
		input             string
		expectedComponent string
		expectedParams    map[string]any
	}{
		{
			name:              "Component with req parameter",
			input:             `"@method";req`,
			expectedComponent: "@method",
			expectedParams:    map[string]any{"req": true},
		},
		{
			name:              "Component with string parameter",
			input:             `"@query-param";name="Pet"`,
			expectedComponent: "@query-param",
			expectedParams:    map[string]any{"name": "Pet"},
		},
		{
			name:              "Component with multiple parameters",
			input:             `"content-type";req;sf`,
			expectedComponent: "content-type",
			expectedParams:    map[string]any{"req": true, "sf": true},
		},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the component identifier
			parsed, err := sfv.Parse([]byte(tt.input))
			require.NoError(t, err, "Parse failed for input: %s", tt.input)

			// Should parse as a List containing one Item
			list, ok := parsed.(*sfv.List)
			require.True(t, ok, "Should parse as List, got %T", parsed)
			require.Equal(t, 1, list.Len(), "List should contain one item")

			// Extract the Item
			firstItem, exists := list.Get(0)
			require.True(t, exists, "Should have first item")

			item, ok := firstItem.(sfv.Item)
			require.True(t, ok, "First item should be Item, got %T", firstItem)

			// Verify component name
			var componentName string
			err = item.GetValue(&componentName)
			require.NoError(t, err, "Should be able to extract component name")
			require.Equal(t, tt.expectedComponent, componentName, "Component name should match")

			// Verify parameters
			params := item.Parameters()
			require.NotNil(t, params, "Should have parameters")

			for expectedKey, expectedValue := range tt.expectedParams {
				paramValue, exists := params.Values[expectedKey]
				require.True(t, exists, "Should have parameter %q", expectedKey)

				switch expected := expectedValue.(type) {
				case bool:
					var actualBool bool
					err = paramValue.GetValue(&actualBool)
					require.NoError(t, err, "Should extract boolean value for param %q", expectedKey)
					require.Equal(t, expected, actualBool, "Boolean parameter %q should match", expectedKey)
				case string:
					var actualString string
					err = paramValue.GetValue(&actualString)
					require.NoError(t, err, "Should extract string value for param %q", expectedKey)
					require.Equal(t, expected, actualString, "String parameter %q should match", expectedKey)
				}
			}
		})
	}
}
