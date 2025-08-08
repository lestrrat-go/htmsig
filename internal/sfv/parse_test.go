package sfv_test

import (
	"reflect"
	"testing"

	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/stretchr/testify/require"
)

func TestParseIntegerList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"123", []any{int64(123)}, []int{sfv.IntegerType}},
		{"123, 456", []any{int64(123), int64(456)}, []int{sfv.IntegerType, sfv.IntegerType}},
		{"-999", []any{int64(-999)}, []int{sfv.IntegerType}},
		{"0", []any{int64(0)}, []int{sfv.IntegerType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseDecimalList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"123.456", []any{123.456}, []int{sfv.DecimalType}},
		{"123.456, 789.123", []any{123.456, 789.123}, []int{sfv.DecimalType, sfv.DecimalType}},
		{"-123.456", []any{-123.456}, []int{sfv.DecimalType}},
		{"0.0", []any{0.0}, []int{sfv.DecimalType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{`"hello"`, []any{"hello"}, []int{sfv.StringType}},
		{`"hello", "world"`, []any{"hello", "world"}, []int{sfv.StringType, sfv.StringType}},
		{`"hello \"world\""`, []any{`hello "world"`}, []int{sfv.StringType}},
		{`""`, []any{""}, []int{sfv.StringType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseTokenList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"foo", []any{"foo"}, []int{sfv.TokenType}},
		{"foo, bar", []any{"foo", "bar"}, []int{sfv.TokenType, sfv.TokenType}},
		{"*", []any{"*"}, []int{sfv.TokenType}},
		{"foo123", []any{"foo123"}, []int{sfv.TokenType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseByteSequenceList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{":aGVsbG8=:", []any{[]byte("hello")}, []int{sfv.ByteSequenceType}},
		{":aGVsbG8=:, :d29ybGQ=:", []any{[]byte("hello"), []byte("world")}, []int{sfv.ByteSequenceType, sfv.ByteSequenceType}},
		{"::", []any{[]byte{}}, []int{sfv.ByteSequenceType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseBooleanList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"?1", []any{true}, []int{sfv.BooleanType}},
		{"?0", []any{false}, []int{sfv.BooleanType}},
		{"?1, ?0", []any{true, false}, []int{sfv.BooleanType, sfv.BooleanType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseDateList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"@1659578233", []any{int64(1659578233)}, []int{sfv.DateType}},
		{"@0", []any{int64(0)}, []int{sfv.DateType}},
		{"@1659578233, @1659578234", []any{int64(1659578233), int64(1659578234)}, []int{sfv.DateType, sfv.DateType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseDisplayStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{`%"hello"`, []any{"hello"}, []int{sfv.DisplayStringType}},
		{`%"hello", %"world"`, []any{"hello", "world"}, []int{sfv.DisplayStringType, sfv.DisplayStringType}},
		{`%"This is intended for display to %c3%bcsers."`, []any{"This is intended for display to üsers."}, []int{sfv.DisplayStringType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), list.Len(), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), list.Len())

			for i, expected := range test.expected {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.GetValue(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseMixedList(t *testing.T) {
	tests := []struct {
		input         string
		expectedTypes []int
		expectedLen   int
	}{
		{`123, "hello", foo, :aGVsbG8=:, ?1, @1659578233`, []int{sfv.IntegerType, sfv.StringType, sfv.TokenType, sfv.ByteSequenceType, sfv.BooleanType, sfv.DateType}, 6},
		{`123.456, "world"`, []int{sfv.DecimalType, sfv.StringType}, 2},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, test.expectedLen, list.Len(), "Parse(%q) expected %d items, got %d", test.input, test.expectedLen, list.Len())

			for i, expectedType := range test.expectedTypes {
				value, ok := list.Get(i)
				require.True(t, ok, "Failed to get list item %d", i)
				item, ok := value.(sfv.Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, value)

				require.Equal(t, expectedType, item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, expectedType, item.Type())
			}

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}

func TestParseEmptyList(t *testing.T) {
	result, err := sfv.Parse([]byte(""))
	require.NoError(t, err, "Parse(\"\") failed")

	list, ok := result.(*sfv.List)
	require.True(t, ok, "Parse(\"\") expected *List, got %T", result)

	require.Equal(t, 0, list.Len(), "Parse(\"\") expected empty list, got %d items", list.Len())

	// Roundtrip test: marshal should produce the same serialization
	marshaled, err := sfv.Marshal(result)
	require.NoError(t, err, "Marshal(\"\") failed")
	require.Equal(t, "", string(marshaled), "Marshal result should match original input")
}

func TestParseInnerList(t *testing.T) {
	tests := []struct {
		input       string
		description string
	}{
		{"(1 2 3)", "simple inner list with integers"},
		{"(1 2), (3 4)", "multiple inner lists"},
		{"()", "empty inner list"},
		{`("hello" "world")`, "inner list with strings"},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			result, err := sfv.Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*sfv.List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			// Just check that parsing succeeds for now
			// More detailed inner list testing would require more complex validation
			require.Greater(t, list.Len(), 0, "Parse(%q) expected non-empty list", test.input)

			// Roundtrip test: marshal should produce the same serialization
			marshaled, err := sfv.Marshal(result)
			require.NoError(t, err, "Marshal(%q) failed", test.input)
			require.Equal(t, test.input, string(marshaled), "Marshal result should match original input")
		})
	}
}
