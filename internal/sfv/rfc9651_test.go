package sfv

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRFC9651Examples tests all examples from RFC 9651
func TestRFC9651Examples(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  interface{}
		fieldType string // "list", "dictionary", "item"
	}{
		// Section 2.1 - Foo-Example Header Field
		{
			name:      "Foo-Example Item with parameters",
			input:     `2; foourl="https://foo.example.com/"`,
			fieldType: "item",
		},

		// Section 3.1 - Lists examples
		{
			name:      "Token List",
			input:     "sugar, tea, rum",
			fieldType: "list",
		},
		{
			name:      "Token List - multiple lines equivalent",
			input:     "sugar, tea, rum",
			fieldType: "list",
		},

		// Section 3.1.1 - Inner Lists examples
		{
			name:      "Inner List of Strings",
			input:     `("foo" "bar"), ("baz"), ("bat" "one"), ()`,
			fieldType: "list",
		},
		{
			name:      "Inner List with Parameters",
			input:     `("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1`,
			fieldType: "list",
		},

		// Section 3.1.2 - Parameters examples
		{
			name:      "List with Parameters",
			input:     "abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w",
			fieldType: "list",
		},
		{
			name:      "Boolean Parameters",
			input:     "1; a; b=?0",
			fieldType: "item",
		},

		// Section 3.2 - Dictionaries examples
		{
			name:      "Dictionary with String and Byte Sequence",
			input:     `en="Applepie", da=:w4ZibGV0w6ZydGU=:`,
			fieldType: "dictionary",
		},
		{
			name:      "Dictionary with Boolean values",
			input:     "a=?0, b, c; foo=bar",
			fieldType: "dictionary",
		},
		{
			name:      "Dictionary with Inner List",
			input:     "rating=1.5, feelings=(joy sadness)",
			fieldType: "dictionary",
		},
		{
			name:      "Dictionary with mixed Items and Inner Lists",
			input:     "a=(1 2), b=3, c=4;aa=bb, d=(5 6);valid",
			fieldType: "dictionary",
		},

		// Section 3.3.1 - Integers examples
		{
			name:      "Integer Item",
			input:     "42",
			fieldType: "item",
		},

		// Section 3.3.2 - Decimals examples
		{
			name:      "Decimal Item",
			input:     "4.5",
			fieldType: "item",
		},

		// Section 3.3.3 - Strings examples
		{
			name:      "String Item",
			input:     `"hello world"`,
			fieldType: "item",
		},

		// Section 3.3.4 - Tokens examples
		{
			name:      "Token Item",
			input:     "foo123/456",
			fieldType: "item",
		},

		// Section 3.3.5 - Byte Sequences examples
		{
			name:      "Byte Sequence Item",
			input:     ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:",
			fieldType: "item",
		},

		// Section 3.3.6 - Booleans examples
		{
			name:      "Boolean true Item",
			input:     "?1",
			fieldType: "item",
		},

		// Section 3.3.7 - Dates examples
		{
			name:      "Date Item",
			input:     "@1659578233",
			fieldType: "item",
		},

		// Section 3.3.8 - Display Strings examples
		{
			name:      "Display String Item",
			input:     `%"This is intended for display to %c3%bcsers."`,
			fieldType: "item",
		},

		// Section 3.3 - Items examples
		{
			name:      "Integer Item with parameters",
			input:     "5; foo=bar",
			fieldType: "item",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)
			require.NotNil(t, result, "Parse result should not be nil")

			// Basic validation that we got some result
			// More specific validation would need to be added based on expected types
			switch test.fieldType {
			case "list":
				_, ok := result.(*List)
				require.True(t, ok, "Expected *List for input: %s, got %T", test.input, result)
			case "item":
				_, ok := result.(*List) // Our parser returns List for single items too
				require.True(t, ok, "Expected *List for single item input: %s, got %T", test.input, result)
			case "dictionary":
				_, ok := result.(*Dictionary)
				require.True(t, ok, "Expected *Dictionary for input: %s, got %T", test.input, result)
			}
		})
	}
}

// TestRFC9651SpecificExamples tests specific examples with expected values
func TestRFC9651SpecificExamples(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedType   int
		expectedValue  interface{}
		expectedParams map[string]interface{}
	}{
		{
			name:          "Token List - sugar, tea, rum",
			input:         "sugar, tea, rum",
			expectedType:  TokenType,
			expectedValue: []string{"sugar", "tea", "rum"},
		},
		{
			name:          "Integer 42",
			input:         "42",
			expectedType:  IntegerType,
			expectedValue: 42,
		},
		{
			name:          "Decimal 4.5",
			input:         "4.5",
			expectedType:  DecimalType,
			expectedValue: 4.5,
		},
		{
			name:          "String hello world",
			input:         `"hello world"`,
			expectedType:  StringType,
			expectedValue: "hello world",
		},
		{
			name:          "Token foo123/456",
			input:         "foo123/456",
			expectedType:  TokenType,
			expectedValue: "foo123/456",
		},
		{
			name:          "Boolean true",
			input:         "?1",
			expectedType:  BooleanType,
			expectedValue: true,
		},
		{
			name:          "Boolean false",
			input:         "?0",
			expectedType:  BooleanType,
			expectedValue: false,
		},
		{
			name:          "Date",
			input:         "@1659578233",
			expectedType:  DateType,
			expectedValue: int64(1659578233),
		},
		{
			name:          "Display String",
			input:         `%"This is intended for display to %c3%bcsers."`,
			expectedType:  DisplayStringType,
			expectedValue: "This is intended for display to üsers.",
		},
		{
			name:          "Byte Sequence",
			input:         ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:",
			expectedType:  ByteSequenceType,
			expectedValue: []byte("pretend this is binary content."),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			if strings.Contains(test.input, ",") {
				// Multi-item list
				require.Greater(t, len(list.values), 1, "Expected multiple items")
				// Check each item matches expected type
				for _, value := range list.values {
					item, ok := value.(*Item)
					require.True(t, ok, "List item should be *Item, got %T", value)
					require.Equal(t, test.expectedType, item.Type, "Item has wrong type")
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.expectedType, item.Type, "Item has wrong type")

				// Check specific values for non-list inputs
				if !strings.Contains(test.input, ",") {
					require.Equal(t, test.expectedValue, item.Value, "Item has wrong value")
				}
			}
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
			input:       `("foo"; a=1;b=2);lvl=5, ("bar" "baz");lvl=1`,
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
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)
			require.NotEmpty(t, list.values, "Expected non-empty list for: %s", test.description)

			// Verify that we have inner lists
			for i, value := range list.values {
				innerList, ok := value.(*List)
				require.True(t, ok, "Item %d should be *List (inner list), got %T", i, value)

				// For empty inner list test, check that one of the lists is empty
				if test.name == "Empty Inner List" {
					require.Empty(t, innerList.values, "Expected empty inner list")
				} else if test.name == "Simple Inner List" {
					require.Len(t, innerList.values, 3, "Expected 3 items in inner list")
				}
			}
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
			input: "abc;a=1;b=2",
		},
		{
			name:  "Boolean Parameters",
			input: "1; a; b=?0",
		},
		{
			name:  "Complex Parameters",
			input: "abc;a=1;b=2; cde_456, (ghi;jk=4 l);q=\"9\";r=w",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed for input: %s", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)
			require.NotEmpty(t, list.values, "Expected non-empty list")

			// Check that at least one item has parameters
			foundParams := false
			for _, value := range list.values {
				if item, ok := value.(*Item); ok {
					if item.Parameters != nil && item.Parameters.Len() > 0 {
						foundParams = true
						break
					}
				}
			}
			require.True(t, foundParams, "Expected to find parameters in parsed result")
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
			_, err := Parse([]byte(test.input))
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
			result, err := Parse([]byte(test.input))

			if test.name == "Empty input" || test.name == "Only whitespace" {
				require.NoError(t, err, "Empty input should parse successfully")
				list, ok := result.(*List)
				require.True(t, ok, "Result should be *List")
				require.Empty(t, list.values, "Empty input should result in empty list")
			} else {
				require.NoError(t, err, "Parse should succeed for: %s", test.input)
				require.NotNil(t, result, "Parse result should not be nil")
			}
		})
	}
}
