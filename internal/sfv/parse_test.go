package sfv

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIntegerList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"123", []any{int64(123)}, []int{IntegerType}},
		{"123, 456", []any{int64(123), int64(456)}, []int{IntegerType, IntegerType}},
		{"-999", []any{int64(-999)}, []int{IntegerType}},
		{"0", []any{int64(0)}, []int{IntegerType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseDecimalList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"123.456", []any{123.456}, []int{DecimalType}},
		{"123.456, 789.123", []any{123.456, 789.123}, []int{DecimalType, DecimalType}},
		{"-123.456", []any{-123.456}, []int{DecimalType}},
		{"0.0", []any{0.0}, []int{DecimalType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{`"hello"`, []any{"hello"}, []int{StringType}},
		{`"hello", "world"`, []any{"hello", "world"}, []int{StringType, StringType}},
		{`"hello \"world\""`, []any{`hello "world"`}, []int{StringType}},
		{`""`, []any{""}, []int{StringType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseTokenList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"foo", []any{"foo"}, []int{TokenType}},
		{"foo, bar", []any{"foo", "bar"}, []int{TokenType, TokenType}},
		{"*", []any{"*"}, []int{TokenType}},
		{"foo123", []any{"foo123"}, []int{TokenType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseByteSequenceList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{":aGVsbG8=:", []any{[]byte("hello")}, []int{ByteSequenceType}},
		{":aGVsbG8=:, :d29ybGQ=:", []any{[]byte("hello"), []byte("world")}, []int{ByteSequenceType, ByteSequenceType}},
		{"::", []any{[]byte{}}, []int{ByteSequenceType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseBooleanList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"?1", []any{true}, []int{BooleanType}},
		{"?0", []any{false}, []int{BooleanType}},
		{"?1, ?0", []any{true, false}, []int{BooleanType, BooleanType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseDateList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{"@1659578233", []any{int64(1659578233)}, []int{DateType}},
		{"@0", []any{int64(0)}, []int{DateType}},
		{"@1659578233, @1659578234", []any{int64(1659578233), int64(1659578234)}, []int{DateType, DateType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseDisplayStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected []any
		types    []int
	}{
		{`%"hello"`, []any{"hello"}, []int{DisplayStringType}},
		{`%"hello", %"world"`, []any{"hello", "world"}, []int{DisplayStringType, DisplayStringType}},
		{`%"This is intended for display to %c3%bcsers."`, []any{"This is intended for display to üsers."}, []int{DisplayStringType}},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, len(test.expected), len(list.values), "Parse(%q) expected %d items, got %d", test.input, len(test.expected), len(list.values))

			for i, expected := range test.expected {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, test.types[i], item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, test.types[i], item.Type())

				var actual interface{}
				err := item.Value(&actual)
				require.NoError(t, err, "Parse(%q) item %d failed to get value", test.input, i)

				require.True(t, reflect.DeepEqual(actual, expected), "Parse(%q) item %d expected %v, got %v", test.input, i, expected, actual)
			}
		})
	}
}

func TestParseMixedList(t *testing.T) {
	tests := []struct {
		input         string
		expectedTypes []int
		expectedLen   int
	}{
		{`123, "hello", foo, :aGVsbG8=:, ?1, @1659578233`, []int{IntegerType, StringType, TokenType, ByteSequenceType, BooleanType, DateType}, 6},
		{`123.456, "world"`, []int{DecimalType, StringType}, 2},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			require.Equal(t, test.expectedLen, len(list.values), "Parse(%q) expected %d items, got %d", test.input, test.expectedLen, len(list.values))

			for i, expectedType := range test.expectedTypes {
				item, ok := list.values[i].(Item)
				require.True(t, ok, "Parse(%q) item %d expected Item, got %T", test.input, i, list.values[i])

				require.Equal(t, expectedType, item.Type(), "Parse(%q) item %d expected type %d, got %d", test.input, i, expectedType, item.Type())
			}
		})
	}
}

func TestParseEmptyList(t *testing.T) {
	result, err := Parse([]byte(""))
	require.NoError(t, err, "Parse(\"\") failed")

	list, ok := result.(*List)
	require.True(t, ok, "Parse(\"\") expected *List, got %T", result)

	require.Equal(t, 0, len(list.values), "Parse(\"\") expected empty list, got %d items", len(list.values))
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
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse(%q) failed", test.input)

			list, ok := result.(*List)
			require.True(t, ok, "Parse(%q) expected *List, got %T", test.input, result)

			// Just check that parsing succeeds for now
			// More detailed inner list testing would require more complex validation
			require.Greater(t, len(list.values), 0, "Parse(%q) expected non-empty list", test.input)
		})
	}
}
