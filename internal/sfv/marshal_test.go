package sfv_test

import (
	"testing"
	"time"

	"github.com/lestrrat-go/htmsig/internal/sfv"
)

func TestMarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		expected string
		wantErr  bool
	}{
		// Basic types
		{
			name:     "Boolean true",
			input:    true,
			expected: "?1",
		},
		{
			name:     "Boolean false",
			input:    false,
			expected: "?0",
		},
		{
			name:     "Integer",
			input:    42,
			expected: "42",
		},
		{
			name:     "Negative integer",
			input:    -42,
			expected: "-42",
		},
		{
			name:     "Float",
			input:    3.14,
			expected: "3.14",
		},
		{
			name:     "Zero float",
			input:    0.0,
			expected: "0.0",
		},
		{
			name:     "String",
			input:    "hello world",
			expected: `"hello world"`,
		},
		{
			name:     "Token string",
			input:    "token",
			expected: "token",
		},
		{
			name: "Token with parameters",
			input: sfv.Token().Value("token").Parameter("param",
				sfv.Token().Value("value").MustBuild()).MustBuild(),
			expected: "token; param=value",
		},
		{
			name:     "Token with numbers",
			input:    "token123",
			expected: "token123",
		},
		{
			name:     "String with quotes",
			input:    `hello "world"`,
			expected: `"hello \"world\""`,
		},
		{
			name:     "Byte sequence",
			input:    []byte("hello"),
			expected: ":aGVsbG8=:",
		},
		{
			name:     "Empty byte sequence",
			input:    []byte{},
			expected: "::",
		},

		// Time
		{
			name:     "Unix timestamp",
			input:    time.Unix(1659578233, 0),
			expected: "@1659578233",
		},

		// Lists
		{
			name:     "String list",
			input:    []string{"sugar", "tea", "rum"},
			expected: "sugar, tea, rum",
		},
		{
			name:     "Mixed list",
			input:    []any{42, "hello", true},
			expected: `42, "hello", ?1`,
		},
		{
			name:     "Integer slice",
			input:    []int{1, 2, 3},
			expected: "1, 2, 3",
		},
		{
			name:     "Empty slice",
			input:    []string{},
			expected: "",
		},

		// Maps (become dictionaries)
		{
			name:     "Simple map",
			input:    map[string]string{"foo": "bar", "baz": "qux"},
			expected: "baz=\"qux\", foo=\"bar\"", // Dictionary keys are sorted
		},
		{
			name:     "Map with boolean",
			input:    map[string]bool{"enabled": true, "disabled": false},
			expected: "disabled=?0, enabled", // Boolean true can be bare key, keys sorted
		},
		{
			name:     "Map with numbers",
			input:    map[string]int{"count": 42, "total": 100},
			expected: "count=42, total=100", // Keys sorted
		},

		// Structs (become dictionaries)
		{
			name: "Simple struct",
			input: struct {
				Name string
				Age  int
			}{"John", 30},
			expected: "name=\"John\", age=30", // Field order matches struct definition
		},
		{
			name: "Struct with tags",
			input: struct {
				Name    string `sfv:"full_name"`
				Age     int    `sfv:"years"`
				Ignored string `sfv:"-"`
			}{"John", 30, "ignored"},
			expected: "full_name=\"John\", years=30",
		},

		// Error cases
		{
			name:    "Nil pointer",
			input:   (*string)(nil),
			wantErr: true,
		},
		{
			name:    "Unsupported type",
			input:   make(chan int),
			wantErr: true,
		},
		{
			name:    "Large uint64",
			input:   uint64(9223372036854775808), // max int64 + 1
			wantErr: true,
		},
		{
			name:     "Uint64 with 15 digits - should work",
			input:    uint64(999999999999999), // exactly 15 digits
			expected: "999999999999999",
		},
		{
			name:    "Uint64 with 16 digits - should fail",
			input:   uint64(1000000000000000), // 16 digits
			wantErr: true,
		},
		{
			name:     "Int64 with 15 digits positive - should work",
			input:    int64(999999999999999), // exactly 15 digits
			expected: "999999999999999",
		},
		{
			name:     "Int64 with 15 digits negative - should work",
			input:    int64(-999999999999999), // exactly 15 digits
			expected: "-999999999999999",
		},
		{
			name:    "Int64 with 16 digits - should fail",
			input:   int64(1000000000000000), // 16 digits
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sfv.Marshal(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Marshal() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}

			if string(result) != tt.expected {
				t.Errorf("Marshal() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}

type CustomType struct {
	value string
}

func (c CustomType) MarshalSFV() ([]byte, error) {
	return []byte("custom:" + c.value), nil
}

func TestMarshalWithCustomMarshaler(t *testing.T) {
	custom := CustomType{value: "test"}
	result, err := sfv.Marshal(custom)
	if err != nil {
		t.Errorf("Marshal() unexpected error: %v", err)
		return
	}

	expected := "custom:test"
	if string(result) != expected {
		t.Errorf("Marshal() = %q, want %q", string(result), expected)
	}
}

func TestMarshalNil(t *testing.T) {
	result, err := sfv.Marshal(nil)
	if err != nil {
		t.Errorf("Marshal(nil) unexpected error: %v", err)
		return
	}

	if result != nil {
		t.Errorf("Marshal(nil) = %v, want nil", result)
	}
}

func TestMarshalItem(t *testing.T) {
	// Test marshaling an SFV Item directly
	item := sfv.String().Value("hello").MustBuild().ToItem()
	result, err := sfv.Marshal(item)
	if err != nil {
		t.Errorf("Marshal() unexpected error: %v", err)
		return
	}

	expected := `"hello"`
	if string(result) != expected {
		t.Errorf("Marshal() = %q, want %q", string(result), expected)
	}
}

func TestMarshalList(t *testing.T) {
	// Test marshaling an SFV List directly
	var list sfv.List

	list.Add(sfv.String().Value("hello").MustBuild().ToItem())
	list.Add(sfv.Integer().Value(42).MustBuild().ToItem())
	list.Add(sfv.True().ToItem())

	result, err := sfv.Marshal(list)
	if err != nil {
		t.Errorf("Marshal() unexpected error: %v", err)
		return
	}

	expected := `"hello", 42, ?1`
	if string(result) != expected {
		t.Errorf("Marshal() = %q, want %q", string(result), expected)
	}
}

func TestItemMarshalSFVMethods(t *testing.T) {
	tests := []struct {
		name     string
		item     sfv.BareItem
		expected string
	}{
		{
			name:     "Boolean true",
			item:     sfv.True(),
			expected: "?1",
		},
		{
			name:     "Boolean false",
			item:     sfv.False(),
			expected: "?0",
		},
		{
			name:     "Integer",
			item:     sfv.Integer().Value(42).MustBuild(),
			expected: "42",
		},
		{
			name:     "Decimal",
			item:     sfv.Decimal().Value(3.14).MustBuild(),
			expected: "3.14",
		},
		{
			name:     "String",
			item:     sfv.String().Value("hello").MustBuild(),
			expected: `"hello"`,
		},
		{
			name:     "Token",
			item:     sfv.Token().Value("token").MustBuild(),
			expected: "token",
		},
		{
			name:     "ByteSequence",
			item:     sfv.ByteSequence().Value([]byte("hello")).MustBuild(),
			expected: ":aGVsbG8=:",
		},
		{
			name:     "Date",
			item:     sfv.Date().Value(1659578233).MustBuild(),
			expected: "@1659578233",
		},
		{
			name:     "DisplayString",
			item:     sfv.DisplayString().Value("hello").MustBuild(),
			expected: `%"hello"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.item.MarshalSFV()
			if err != nil {
				t.Errorf("MarshalSFV() unexpected error: %v", err)
				return
			}

			if string(result) != tt.expected {
				t.Errorf("MarshalSFV() = %q, want %q", string(result), tt.expected)
			}
		})
	}
}

func TestCollectionMarshalSFVMethods(t *testing.T) {
	// Test List.MarshalSFV()
	var list sfv.List
	list.Add(sfv.String().Value("hello").MustBuild().ToItem())
	list.Add(sfv.Integer().Value(42).MustBuild().ToItem())
	list.Add(sfv.True().ToItem())

	result, err := list.MarshalSFV()
	if err != nil {
		t.Errorf("List.MarshalSFV() unexpected error: %v", err)
		return
	}

	expected := `"hello", 42, ?1`
	if string(result) != expected {
		t.Errorf("List.MarshalSFV() = %q, want %q", string(result), expected)
	}

	// Test Dictionary.MarshalSFV()
	dict := sfv.NewDictionary()
	dict.Set("name", sfv.String().Value("John").MustBuild().ToItem())
	dict.Set("age", sfv.Integer().Value(30).MustBuild().ToItem())
	dict.Set("active", sfv.True().ToItem())

	result, err = dict.MarshalSFV()
	if err != nil {
		t.Errorf("Dictionary.MarshalSFV() unexpected error: %v", err)
		return
	}

	expected = `name="John", age=30, active`
	if string(result) != expected {
		t.Errorf("Dictionary.MarshalSFV() = %q, want %q", string(result), expected)
	}

	// Test InnerList.MarshalSFV()
	var innerList sfv.InnerList

	innerList.Add(sfv.String().Value("foo").MustBuild().ToItem())
	innerList.Add(sfv.String().Value("bar").MustBuild().ToItem())

	result, err = innerList.MarshalSFV()
	if err != nil {
		t.Errorf("InnerList.MarshalSFV() unexpected error: %v", err)
		return
	}

	expected = `("foo" "bar")`
	if string(result) != expected {
		t.Errorf("InnerList.MarshalSFV() = %q, want %q", string(result), expected)
	}
}

func TestMarshalDictionary(t *testing.T) {
	// Test marshaling an SFV Dictionary directly
	dict := sfv.NewDictionary()
	dict.Set("name", sfv.String().Value("John").MustBuild().ToItem())
	dict.Set("age", sfv.Integer().Value(30).MustBuild().ToItem())

	result, err := sfv.Marshal(dict)
	if err != nil {
		t.Errorf("Marshal() unexpected error: %v", err)
		return
	}

	expected := `name="John", age=30`
	if string(result) != expected {
		t.Errorf("Marshal() = %q, want %q", string(result), expected)
	}
}
