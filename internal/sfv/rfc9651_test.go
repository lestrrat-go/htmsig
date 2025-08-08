package sfv_test

import (
	"strings"
	"testing"

	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/stretchr/testify/require"
)

// TestRFC9651Examples tests all examples from RFC 9651
func TestRFC9651Examples(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		fieldType string // "list", "dictionary", "item"
		expected  any    // expected value for validation
	}{
		// Section 2.1 - Foo-Example Header Field
		{
			name:      "Foo-Example Item with parameters",
			input:     `2; foourl="https://foo.example.com/"`,
			fieldType: "item",
			expected:  int64(2),
		},

		// Section 3.1 - Lists examples
		{
			name:      "Token List",
			input:     "sugar, tea, rum",
			fieldType: "list",
			expected:  []any{"sugar", "tea", "rum"},
		},
		{
			name:      "Token List - multiple lines equivalent",
			input:     "sugar, tea, rum",
			fieldType: "list",
			expected:  []any{"sugar", "tea", "rum"},
		},

		// Section 3.1.1 - Inner Lists examples
		{
			name:      "Inner List of Strings",
			input:     `("foo" "bar"), ("baz"), ("bat" "one"), ()`,
			fieldType: "list",
			// Inner lists are complex - we'll validate structure separately
		},
		{
			name:      "Inner List with Parameters",
			input:     `("foo"; a=1; b=2); lvl=5, ("bar" "baz"); lvl=1`,
			fieldType: "list",
			// Inner lists with parameters are complex - we'll validate structure separately
		},

		// Section 3.1.2 - Parameters examples
		{
			name:      "List with Parameters",
			input:     "abc; a=1; b=2; cde_456, (ghi; jk=4 l); q=\"9\"; r=w",
			fieldType: "list",
			// Complex with parameters - we'll validate structure separately
		},
		{
			name:      "Boolean Parameters",
			input:     "1; a; b=?0",
			fieldType: "item",
			expected:  int64(1),
		},

		// Section 3.2 - Dictionaries examples
		{
			name:      "Dictionary with String and Byte Sequence",
			input:     `en="Applepie", da=:w4ZibGV0w6ZydGU=:`,
			fieldType: "dictionary",
			expected: map[string]any{
				"en": "Applepie",
				"da": []byte("Æbletærte"), // base64 decoded
			},
		},
		{
			name:      "Dictionary with Boolean values",
			input:     "a=?0, b, c; foo=bar",
			fieldType: "dictionary",
			expected: map[string]any{
				"a": false,
				"b": true, // bare key defaults to true
				"c": true, // bare key defaults to true
			},
		},
		{
			name:      "Dictionary with Inner List",
			input:     "rating=1.5, feelings=(joy sadness)",
			fieldType: "dictionary",
			expected: map[string]any{
				"rating": 1.5,
				// feelings will be an inner list - validate separately
			},
		},
		{
			name:      "Dictionary with mixed Items and Inner Lists",
			input:     "a=(1 2), b=3, c=4; aa=bb, d=(5 6); valid",
			fieldType: "dictionary",
			expected: map[string]any{
				"b": int64(3),
				"c": int64(4),
				// a and d are inner lists - validate separately
			},
		},

		// Section 3.3.1 - Integers examples
		{
			name:      "Integer Item",
			input:     "42",
			fieldType: "item",
			expected:  int64(42),
		},

		// Section 3.3.2 - Decimals examples
		{
			name:      "Decimal Item",
			input:     "4.5",
			fieldType: "item",
			expected:  4.5,
		},

		// Section 3.3.3 - Strings examples
		{
			name:      "String Item",
			input:     `"hello world"`,
			fieldType: "item",
			expected:  "hello world",
		},

		// Section 3.3.4 - Tokens examples
		{
			name:      "Token Item",
			input:     "foo123/456",
			fieldType: "item",
			expected:  "foo123/456",
		},

		// Section 3.3.5 - Byte Sequences examples
		{
			name:      "Byte Sequence Item",
			input:     ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:",
			fieldType: "item",
			expected:  []byte("pretend this is binary content."),
		},

		// Section 3.3.6 - Booleans examples
		{
			name:      "Boolean true Item",
			input:     "?1",
			fieldType: "item",
			expected:  true,
		},

		// Section 3.3.7 - Dates examples
		{
			name:      "Date Item",
			input:     "@1659578233",
			fieldType: "item",
			expected:  int64(1659578233),
		},

		// Section 3.3.8 - Display Strings examples
		{
			name:      "Display String Item",
			input:     `%"This is intended for display to %c3%bcsers."`,
			fieldType: "item",
			expected:  "This is intended for display to üsers.",
		},

		// Section 3.3 - Items examples
		{
			name:      "Integer Item with parameters",
			input:     "5; foo=bar",
			fieldType: "item",
			expected:  int64(5),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)
			require.NotNil(t, result, "Parse result should not be nil")

			// Validate result type and values
			switch test.fieldType {
			case "list":
				list, ok := result.(*sfv.List)
				require.True(t, ok, "Expected *sfv.List for input: %s, got %T", test.input, result)

				// If we have expected list values, validate them
				if expectedList, ok := test.expected.([]any); ok {
					require.Equal(t, len(expectedList), list.Len(), "Wrong number of list items")
					for i, expectedValue := range expectedList {
						value, ok := list.Get(i)
						require.True(t, ok, "Failed to get list item %d", i)
						item, ok := value.(sfv.Item)
						require.True(t, ok, "List item %d should be Item, got %T", i, value)
						var actual interface{}
						err := item.GetValue(&actual)
						require.NoError(t, err, "Failed to get value from item %d", i)
						require.Equal(t, expectedValue, actual, "List item %d has wrong value", i)
					}
				}

			case "item":
				list, ok := result.(*sfv.List) // Our parser returns List for single items too
				require.True(t, ok, "Expected *List for single item input: %s, got %T", test.input, result)
				require.Equal(t, 1, list.Len(), "Expected single item")

				value, ok := list.Get(0)
				require.True(t, ok, "Failed to get first item")
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Item should be Item, got %T", value)

				// If we have expected item value, validate it
				if test.expected != nil {
					var actual interface{}
					err := item.GetValue(&actual)
					require.NoError(t, err, "Failed to get value from item")
					require.Equal(t, test.expected, actual, "Item has wrong value")
				}

			case "dictionary":
				dict, ok := result.(*sfv.Dictionary)
				require.True(t, ok, "Expected *sfv.Dictionary for input: %s, got %T", test.input, result)

				// If we have expected dictionary values, validate them
				if expectedDict, ok := test.expected.(map[string]any); ok {
					for expectedKey, expectedValue := range expectedDict {
						actualValue, exists := dict.Get(expectedKey)
						require.True(t, exists, "Dictionary missing expected key: %s", expectedKey)

						// For simple items, compare the value directly
						if item, ok := actualValue.(sfv.Item); ok {
							var actual interface{}
							err := item.GetValue(&actual)
							require.NoError(t, err, "Failed to get value from dictionary item %s", expectedKey)
							require.Equal(t, expectedValue, actual, "Dictionary key %s has wrong value", expectedKey)
						}
						// For inner lists, we'd need more complex validation (handled in separate tests)
					}
				}
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

// TestRFC9651SpecificExamples tests specific examples with expected values
func TestRFC9651SpecificExamples(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedType   int
		expectedValue  any
		expectedParams map[string]any
	}{
		{
			name:          "Token List - sugar, tea, rum",
			input:         "sugar, tea, rum",
			expectedType:  sfv.TokenType,
			expectedValue: []string{"sugar", "tea", "rum"},
		},
		{
			name:          "Integer 42",
			input:         "42",
			expectedType:  sfv.IntegerType,
			expectedValue: int64(42),
		},
		{
			name:          "Decimal 4.5",
			input:         "4.5",
			expectedType:  sfv.DecimalType,
			expectedValue: 4.5,
		},
		{
			name:          "String hello world",
			input:         `"hello world"`,
			expectedType:  sfv.StringType,
			expectedValue: "hello world",
		},
		{
			name:          "Token foo123/456",
			input:         "foo123/456",
			expectedType:  sfv.TokenType,
			expectedValue: "foo123/456",
		},
		{
			name:          "Boolean true",
			input:         "?1",
			expectedType:  sfv.BooleanType,
			expectedValue: true,
		},
		{
			name:          "Boolean false",
			input:         "?0",
			expectedType:  sfv.BooleanType,
			expectedValue: false,
		},
		{
			name:          "Date",
			input:         "@1659578233",
			expectedType:  sfv.DateType,
			expectedValue: int64(1659578233),
		},
		{
			name:          "Display String",
			input:         `%"This is intended for display to %c3%bcsers."`,
			expectedType:  sfv.DisplayStringType,
			expectedValue: "This is intended for display to üsers.",
		},
		{
			name:          "Byte Sequence",
			input:         ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:",
			expectedType:  sfv.ByteSequenceType,
			expectedValue: []byte("pretend this is binary content."),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse result should be *sfv.List, got %T", result)

			if strings.Contains(test.input, ",") {
				// Multi-item list
				require.Greater(t, list.Len(), 1, "Expected multiple items")
				// Check each item matches expected type
				for i := 0; i < list.Len(); i++ {
					value, ok := list.Get(i)
					require.True(t, ok, "Failed to get list item %d", i)
					item, ok := value.(sfv.Item)
					require.True(t, ok, "List item should be Item, got %T", value)
					require.Equal(t, test.expectedType, item.Type(), "Item has wrong type")
				}
			} else {
				// Single item
				require.Equal(t, 1, list.Len(), "Expected single item")
				value, ok := list.Get(0)
				require.True(t, ok, "Failed to get first item")
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Item should be Item, got %T", value)
				require.Equal(t, test.expectedType, item.Type(), "Item has wrong type")

				// Check specific values for non-list inputs
				if !strings.Contains(test.input, ",") {
					var actual interface{}
					err := item.GetValue(&actual)
					require.NoError(t, err, "Failed to get value from item")
					require.Equal(t, test.expectedValue, actual, "Item has wrong value")
				}
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

// TestRFC9651InnerLists tests Inner List examples from RFC 9651
func TestRFC9651InnerLists(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		description string
	}{
		{
			name:        "Inner List with Strings",
			input:       `("foo" "bar"), ("baz"), ("bat" "one"), ()`,
			description: "List of Inner Lists of Strings with empty Inner List",
		},
		{
			name:        "Inner List with Parameters",
			input:       `("foo"; a=1; b=2); lvl=5, ("bar" "baz"); lvl=1`,
			description: "Inner Lists with Parameters at both levels",
		},
		{
			name:        "Simple Inner List",
			input:       "(1 2 3)",
			description: "Simple inner list with integers",
		},
		{
			name:        "Multiple Inner Lists",
			input:       "(1 2), (3 4)",
			description: "Multiple inner lists",
		},
		{
			name:        "Empty Inner List",
			input:       "()",
			description: "Empty inner list",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse result should be *sfv.List, got %T", result)
			require.Greater(t, list.Len(), 0, "Expected non-empty list for: %s", test.description)

			// Verify that we have inner lists
			for i := 0; i < list.Len(); i++ {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				innerList, ok := value.(*sfv.InnerList)
				require.True(t, ok, "Item %d should be *InnerList (inner list), got %T", i, value)

				// For empty inner list test, check that one of the lists is empty
				if test.name == "Empty Inner List" {
					require.Equal(t, 0, innerList.Len(), "Expected empty inner list")
				} else if test.name == "Simple Inner List" {
					require.Equal(t, 3, innerList.Len(), "Expected 3 items in inner list")
				}
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

// TestRFC9651Parameters tests Parameter examples from RFC 9651
func TestRFC9651Parameters(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Item with Parameters",
			input: "abc; a=1; b=2",
		},
		{
			name:  "Boolean Parameters",
			input: "1; a; b=?0",
		},
		{
			name:  "Complex Parameters",
			input: "abc; a=1; b=2; cde_456, (ghi; jk=4 l); q=\"9\"; r=w",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse result should be *sfv.List, got %T", result)
			require.Greater(t, list.Len(), 0, "Expected non-empty list")

			// Check that at least one item has parameters
			foundParams := false
			for i := 0; i < list.Len(); i++ {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				if item, ok := value.(sfv.Item); ok {
					if params := item.Parameters(); params != nil && params.Len() > 0 {
						foundParams = true
						break
					}
				}
			}
			require.True(t, foundParams, "Expected to find parameters in parsed result")

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

// TestRFC9651ErrorCases tests error cases mentioned in RFC 9651
func TestRFC9651ErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Trailing comma in list",
			input: "sugar, tea,",
		},
		{
			name:  "Unclosed inner list",
			input: "(foo bar",
		},
		{
			name:  "Invalid string escape",
			input: `"hello\world"`,
		},
		{
			name:  "Invalid boolean",
			input: "?2",
		},
		{
			name:  "Invalid date (decimal)",
			input: "@123.45",
		},
		{
			name:  "Unclosed string",
			input: `"hello world`,
		},
		{
			name:  "Invalid byte sequence",
			input: ":invalid base64!:",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := sfv.Parse([]byte(test.input))
			require.Error(t, err, "Expected parsing to fail for input: %s", test.input)
		})
	}
}

// TestRFC9651EdgeCases tests edge cases from RFC 9651
func TestRFC9651EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "Empty input",
			input: "",
		},
		{
			name:  "Only whitespace",
			input: "   ",
		},
		{
			name:  "Single token",
			input: "foo",
		},
		{
			name:  "Single integer",
			input: "123",
		},
		{
			name:  "Negative integer",
			input: "-999",
		},
		{
			name:  "Zero",
			input: "0",
		},
		{
			name:  "Empty string",
			input: `""`,
		},
		{
			name:  "Empty byte sequence",
			input: "::",
		},
		{
			name:  "Token with special chars",
			input: "foo123/456:bar",
		},
		{
			name:  "Large integer",
			input: "999999999999999",
		},
		{
			name:  "Small decimal",
			input: "0.001",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))

			if test.name == "Empty input" || test.name == "Only whitespace" {
				require.NoError(t, err, "Empty input should parse successfully")
				list, ok := result.(*sfv.List)
				require.True(t, ok, "Result should be *sfv.List")
				require.Equal(t, 0, list.Len(), "Empty input should result in empty list")

				// Roundtrip test: marshal should produce the same serialization
				marshaled, err := sfv.Marshal(result)
				require.NoError(t, err, "Marshal(%q) failed", test.input)
				require.Equal(t, "", string(marshaled), "Marshal result should match original input")
			} else {
				require.NoError(t, err, "Parse should succeed for: %s", test.input)
				require.NotNil(t, result, "Parse result should not be nil")

				// Roundtrip test: marshal should produce the same serialization
				marshaled, err := sfv.Marshal(result)
				require.NoError(t, err, "Marshal(%q) failed", test.input)
				require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
			}
		})
	}
}
