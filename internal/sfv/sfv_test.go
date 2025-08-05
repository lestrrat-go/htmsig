package sfv

import (
	"encoding/base64"
	"testing"
)

func TestParseDecimal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "positive integer",
			input:    "123",
			expected: 123,
			wantErr:  false,
		},
		{
			name:     "negative integer",
			input:    "-456",
			expected: -456,
			wantErr:  false,
		},
		{
			name:     "positive decimal",
			input:    "123.456",
			expected: 123.456,
			wantErr:  false,
		},
		{
			name:     "negative decimal",
			input:    "-789.123",
			expected: -789.123,
			wantErr:  false,
		},
		{
			name:     "zero",
			input:    "0",
			expected: 0,
			wantErr:  false,
		},
		{
			name:     "zero decimal",
			input:    "0.0",
			expected: 0.0,
			wantErr:  false,
		},
		{
			name:    "too many integer digits",
			input:   "1234567890123456", // 16 digits
			wantErr: true,
		},
		{
			name:    "too many decimal digits",
			input:   "123456789012345.123", // >12 integer digits
			wantErr: true,
		},
		{
			name:    "too many fractional digits",
			input:   "123.1234", // >3 fractional digits
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid character",
			input:   "12a3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseDecimal()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDecimal() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseDecimal() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseDecimal() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple string",
			input:    `"hello"`,
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "empty string",
			input:    `""`,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "string with spaces",
			input:    `"hello world"`,
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "escaped quote",
			input:    `"hello \"world\""`,
			expected: `hello "world"`,
			wantErr:  false,
		},
		{
			name:     "escaped backslash",
			input:    `"hello\\world"`,
			expected: `hello\world`,
			wantErr:  false,
		},
		{
			name:    "missing opening quote",
			input:   `hello"`,
			wantErr: true,
		},
		{
			name:    "missing closing quote",
			input:   `"hello`,
			wantErr: true,
		},
		{
			name:    "invalid escape sequence",
			input:   `"hello\n"`,
			wantErr: true,
		},
		{
			name:    "control character",
			input:   "\"hello\x01world\"",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseString()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseString() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseToken(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple token",
			input:    "hello",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "token with asterisk",
			input:    "*hello",
			expected: "*hello",
			wantErr:  false,
		},
		{
			name:     "token with numbers",
			input:    "hello123",
			expected: "hello123",
			wantErr:  false,
		},
		{
			name:     "token with special chars",
			input:    "hello-world_test.com",
			expected: "hello-world_test.com",
			wantErr:  false,
		},
		{
			name:     "token with colon and slash",
			input:    "application/json",
			expected: "application/json",
			wantErr:  false,
		},
		{
			name:    "token starting with number",
			input:   "123hello",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseToken()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseToken() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseToken() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseByteSequence(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "simple byte sequence",
			input:    ":aGVsbG8=:",
			expected: []byte("hello"),
			wantErr:  false,
		},
		{
			name:     "empty byte sequence",
			input:    "::",
			expected: []byte{},
			wantErr:  false,
		},
		{
			name:     "binary data",
			input:    ":SGVsbG8gV29ybGQ=:",
			expected: []byte("Hello World"),
			wantErr:  false,
		},
		{
			name:    "missing opening colon",
			input:   "aGVsbG8=:",
			wantErr: true,
		},
		{
			name:    "missing closing colon",
			input:   ":aGVsbG8=",
			wantErr: true,
		},
		{
			name:    "invalid base64 character",
			input:   ":invalid@base64:",
			wantErr: true,
		},
		{
			name:    "invalid base64 format",
			input:   ":aGVsbG8:",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseByteSequence()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseByteSequence() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseByteSequence() unexpected error: %v", err)
				return
			}

			if string(result) != string(tt.expected) {
				t.Errorf("parseByteSequence() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseBoolean(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected bool
		wantErr  bool
	}{
		{
			name:     "true boolean",
			input:    "?1",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "false boolean",
			input:    "?0",
			expected: false,
			wantErr:  false,
		},
		{
			name:    "missing question mark",
			input:   "1",
			wantErr: true,
		},
		{
			name:    "invalid boolean value",
			input:   "?2",
			wantErr: true,
		},
		{
			name:    "missing value",
			input:   "?",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseBoolean()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBoolean() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseBoolean() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseBoolean() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseDate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{
			name:     "positive timestamp",
			input:    "@1659578233",
			expected: 1659578233,
			wantErr:  false,
		},
		{
			name:     "negative timestamp",
			input:    "@-62135596800",
			expected: -62135596800,
			wantErr:  false,
		},
		{
			name:     "zero timestamp",
			input:    "@0",
			expected: 0,
			wantErr:  false,
		},
		{
			name:    "missing @ symbol",
			input:   "1659578233",
			wantErr: true,
		},
		{
			name:    "decimal value",
			input:   "@123.456",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
		{
			name:    "invalid integer",
			input:   "@abc",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseDate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDate() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseDate() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseDate() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseDisplayString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "simple display string",
			input:    `%"hello"`,
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "empty display string",
			input:    `%""`,
			expected: "",
			wantErr:  false,
		},
		{
			name:     "display string with percent encoding",
			input:    `%"hello%20world"`,
			expected: "hello world",
			wantErr:  false,
		},
		{
			name:     "display string with UTF-8",
			input:    `%"caf%c3%a9"`,
			expected: "café",
			wantErr:  false,
		},
		{
			name:    "missing percent",
			input:   `"hello"`,
			wantErr: true,
		},
		{
			name:    "missing quote after percent",
			input:   `%hello"`,
			wantErr: true,
		},
		{
			name:    "invalid hex sequence",
			input:   `%"hello%zz"`,
			wantErr: true,
		},
		{
			name:    "incomplete hex sequence",
			input:   `%"hello%2"`,
			wantErr: true,
		},
		{
			name:    "missing closing quote",
			input:   `%"hello`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseDisplayString()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDisplayString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseDisplayString() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseDisplayString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseBareItem(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "integer",
			input:    "123",
			expected: 123,
			wantErr:  false,
		},
		{
			name:     "decimal",
			input:    "123.456",
			expected: 123.456,
			wantErr:  false,
		},
		{
			name:     "string",
			input:    `"hello"`,
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "token",
			input:    "hello",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "byte sequence",
			input:    ":aGVsbG8=:",
			expected: []byte("hello"),
			wantErr:  false,
		},
		{
			name:     "boolean true",
			input:    "?1",
			expected: true,
			wantErr:  false,
		},
		{
			name:     "boolean false",
			input:    "?0",
			expected: false,
			wantErr:  false,
		},
		{
			name:     "date",
			input:    "@1659578233",
			expected: int64(1659578233),
			wantErr:  false,
		},
		{
			name:     "display string",
			input:    `%"hello"`,
			expected: "hello",
			wantErr:  false,
		},
		{
			name:    "unrecognized character",
			input:   "#invalid",
			wantErr: true,
		},
		{
			name:    "empty input",
			input:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseBareItem()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBareItem() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseBareItem() unexpected error: %v", err)
				return
			}

			// Special handling for byte sequences
			if expectedBytes, ok := tt.expected.([]byte); ok {
				if resultBytes, ok := result.([]byte); ok {
					if string(resultBytes) != string(expectedBytes) {
						t.Errorf("parseBareItem() = %v, want %v", result, tt.expected)
					}
				} else {
					t.Errorf("parseBareItem() expected []byte, got %T", result)
				}
				return
			}

			if result != tt.expected {
				t.Errorf("parseBareItem() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseItem(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "simple item",
			input:   "123",
			wantErr: false,
		},
		{
			name:    "string item",
			input:   `"hello"`,
			wantErr: false,
		},
		{
			name:    "token item",
			input:   "hello",
			wantErr: false,
		},
		{
			name:    "boolean item",
			input:   "?1",
			wantErr: false,
		},
		{
			name:    "date item",
			input:   "@1659578233",
			wantErr: false,
		},
		{
			name:    "invalid item",
			input:   "#invalid",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseItem()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseItem() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseItem() unexpected error: %v", err)
				return
			}

			// Verify that result is a map with expected structure
			itemMap, ok := result.(map[string]interface{})
			if !ok {
				t.Errorf("parseItem() expected map[string]interface{}, got %T", result)
				return
			}

			if _, hasValue := itemMap["value"]; !hasValue {
				t.Errorf("parseItem() result missing 'value' key")
			}

			if _, hasParams := itemMap["parameters"]; !hasParams {
				t.Errorf("parseItem() result missing 'parameters' key")
			}
		})
	}
}

func TestIsDigit(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected bool
	}{
		{"zero", '0', true},
		{"nine", '9', true},
		{"five", '5', true},
		{"letter a", 'a', false},
		{"letter Z", 'Z', false},
		{"space", ' ', false},
		{"dash", '-', false},
		{"period", '.', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isDigit(tt.input)
			if result != tt.expected {
				t.Errorf("isDigit(%c) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestIsAlpha(t *testing.T) {
	tests := []struct {
		name     string
		input    byte
		expected bool
	}{
		{"lowercase a", 'a', true},
		{"lowercase z", 'z', true},
		{"uppercase A", 'A', true},
		{"uppercase Z", 'Z', true},
		{"digit 0", '0', false},
		{"digit 9", '9', false},
		{"space", ' ', false},
		{"dash", '-', false},
		{"asterisk", '*', false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isAlpha(tt.input)
			if result != tt.expected {
				t.Errorf("isAlpha(%c) = %v, want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestParseContextBasicOperations(t *testing.T) {
	t.Run("eof detection", func(t *testing.T) {
		var pctx parseContext
		pctx.init([]byte("abc"))

		if pctx.eof() {
			t.Error("expected not EOF at start")
		}

		pctx.advance()
		pctx.advance()
		pctx.advance()

		if !pctx.eof() {
			t.Error("expected EOF after advancing past end")
		}
	})

	t.Run("current and advance", func(t *testing.T) {
		var pctx parseContext
		pctx.init([]byte("abc"))

		if pctx.current() != 'a' {
			t.Errorf("expected 'a', got %c", pctx.current())
		}

		pctx.advance()
		if pctx.current() != 'b' {
			t.Errorf("expected 'b', got %c", pctx.current())
		}

		pctx.advance()
		if pctx.current() != 'c' {
			t.Errorf("expected 'c', got %c", pctx.current())
		}

		pctx.advance()
		if pctx.current() != 0 {
			t.Errorf("expected 0 (EOF), got %c", pctx.current())
		}
	})

	t.Run("stripWhitespace", func(t *testing.T) {
		var pctx parseContext
		pctx.init([]byte("  \t  abc"))

		pctx.stripWhitespace()
		if pctx.current() != 'a' {
			t.Errorf("expected 'a' after stripping whitespace, got %c", pctx.current())
		}
	})
}

func TestParametersLen(t *testing.T) {
	t.Run("nil parameters", func(t *testing.T) {
		var p *Parameters
		if p.Len() != 0 {
			t.Errorf("expected 0 for nil parameters, got %d", p.Len())
		}
	})

	t.Run("empty parameters", func(t *testing.T) {
		p := &Parameters{}
		if p.Len() != 0 {
			t.Errorf("expected 0 for empty parameters, got %d", p.Len())
		}
	})

	t.Run("parameters with keys", func(t *testing.T) {
		p := &Parameters{
			keys: []string{"a", "b", "c"},
		}
		if p.Len() != 3 {
			t.Errorf("expected 3 for parameters with 3 keys, got %d", p.Len())
		}
	})
}

// Helper function to create base64 encoded test data
func createBase64TestData(input string) string {
	encoded := base64.StdEncoding.EncodeToString([]byte(input))
	return ":" + encoded + ":"
}

// Test edge cases and integration scenarios
func TestParseDecimalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "decimal with trailing period",
			input:   "123.",
			wantErr: true,
		},
		{
			name:    "multiple decimal points",
			input:   "12.34.56",
			wantErr: false, // Should parse as 12.34 and stop
		},
		{
			name:    "just negative sign",
			input:   "-",
			wantErr: true,
		},
		{
			name:    "max integer digits",
			input:   "999999999999999", // 15 digits - should pass
			wantErr: false,
		},
		{
			name:    "max decimal digits",
			input:   "999999999999.999", // 12 integer + 3 fractional - should pass
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			_, err := pctx.parseDecimal()

			if tt.wantErr && err == nil {
				t.Errorf("parseDecimal() expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("parseDecimal() unexpected error: %v", err)
			}
		})
	}
}

func TestParseStringEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "string with all printable ASCII",
			input:    `" !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_` + "`" + `abcdefghijklmnopqrstuvwxyz{|}~"`,
			expected: ` !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_` + "`" + `abcdefghijklmnopqrstuvwxyz{|}~`,
			wantErr:  false,
		},
		{
			name:    "string with tab character",
			input:   "\"hello\tworld\"",
			wantErr: true,
		},
		{
			name:    "string with newline",
			input:   "\"hello\nworld\"",
			wantErr: true,
		},
		{
			name:    "incomplete escape at end",
			input:   "\"hello\\",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseString()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseString() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseTokenEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "token with all valid characters",
			input:    "*abcDEF123!#$%&'*+-.^_`|~:/",
			expected: "*abcDEF123!#$%&'*+-.^_`|~:/",
			wantErr:  false,
		},
		{
			name:     "single asterisk",
			input:    "*",
			expected: "*",
			wantErr:  false,
		},
		{
			name:     "single letter",
			input:    "a",
			expected: "a",
			wantErr:  false,
		},
		{
			name:    "token with parentheses",
			input:   "hello(world)",
			wantErr: false, // should stop at '('
		},
		{
			name:    "token with comma",
			input:   "hello,world",
			wantErr: false, // should stop at ','
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseToken()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseToken() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseToken() unexpected error: %v", err)
				return
			}

			if tt.expected != "" && result != tt.expected {
				t.Errorf("parseToken() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseByteSequenceEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "byte sequence with padding",
			input:    ":SGVsbG8gV29ybGQ=:",
			expected: []byte("Hello World"),
			wantErr:  false,
		},
		{
			name:     "byte sequence without padding",
			input:    ":SGVsbG8=:",
			expected: []byte("Hello"),
			wantErr:  false,
		},
		{
			name:    "byte sequence with space",
			input:   ":SGVs bG8=:",
			wantErr: true,
		},
		{
			name:    "nested colons",
			input:   "::SGVsbG8=::",
			wantErr: false, // should parse as empty sequence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseByteSequence()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseByteSequence() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseByteSequence() unexpected error: %v", err)
				return
			}

			if string(result) != string(tt.expected) {
				t.Errorf("parseByteSequence() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestParseDisplayStringEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		wantErr  bool
	}{
		{
			name:     "display string with mixed encoding",
			input:    `%"Hello%20%c3%a9%20World"`,
			expected: "Hello é World",
			wantErr:  false,
		},
		{
			name:     "display string with uppercase hex",
			input:    `%"Hello%2C%20World"`,
			expected: "Hello, World",
			wantErr:  false,
		},
		{
			name:     "display string with invalid UTF-8 sequence",
			input:    `%"Hello%c0%ae"`, // Invalid UTF-8
			expected: "Hello\xc0\xae",  // Parser doesn't validate UTF-8, just decodes hex
			wantErr:  false,
		},
		{
			name:     "display string with uppercase hex chars",
			input:    `%"Hello%2C"`,
			expected: "Hello,",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseDisplayString()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseDisplayString() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseDisplayString() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseDisplayString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestParseBareItemWhitespace(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected interface{}
		wantErr  bool
	}{
		{
			name:     "integer with leading whitespace",
			input:    "   123",
			expected: 123,
			wantErr:  false,
		},
		{
			name:     "string with leading whitespace",
			input:    "  \"hello\"",
			expected: "hello",
			wantErr:  false,
		},
		{
			name:     "token with leading whitespace",
			input:    "\t\nhello",
			expected: "hello",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			result, err := pctx.parseBareItem()

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseBareItem() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("parseBareItem() unexpected error: %v", err)
				return
			}

			if result != tt.expected {
				t.Errorf("parseBareItem() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Integration test with RFC 9651 examples
func TestRFCExamples(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "RFC example - integer",
			input:   "42",
			wantErr: false,
		},
		{
			name:    "RFC example - decimal",
			input:   "4.5",
			wantErr: false,
		},
		{
			name:    "RFC example - string",
			input:   `"hello world"`,
			wantErr: false,
		},
		{
			name:    "RFC example - token",
			input:   "sugar",
			wantErr: false,
		},
		{
			name:    "RFC example - byte sequence",
			input:   ":cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50:",
			wantErr: false,
		},
		{
			name:    "RFC example - boolean true",
			input:   "?1",
			wantErr: false,
		},
		{
			name:    "RFC example - boolean false",
			input:   "?0",
			wantErr: false,
		},
		{
			name:    "RFC example - date",
			input:   "@1659578233",
			wantErr: false,
		},
		{
			name:    "RFC example - display string",
			input:   `%"This is intended for display to %c3%bcsers."`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pctx parseContext
			pctx.init([]byte(tt.input))

			_, err := pctx.parseBareItem()

			if tt.wantErr && err == nil {
				t.Errorf("parseBareItem() expected error, got nil")
			} else if !tt.wantErr && err != nil {
				t.Errorf("parseBareItem() unexpected error: %v", err)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseDecimal(b *testing.B) {
	input := []byte("123.456")
	var pctx parseContext

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pctx.init(input)
		_, _ = pctx.parseDecimal()
	}
}

func BenchmarkParseString(b *testing.B) {
	input := []byte(`"hello world"`)
	var pctx parseContext

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pctx.init(input)
		_, _ = pctx.parseString()
	}
}

func BenchmarkParseToken(b *testing.B) {
	input := []byte("hello-world_test")
	var pctx parseContext

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pctx.init(input)
		_, _ = pctx.parseToken()
	}
}

func BenchmarkParseBareItem(b *testing.B) {
	input := []byte("123")
	var pctx parseContext

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pctx.init(input)
		_, _ = pctx.parseBareItem()
	}
}
