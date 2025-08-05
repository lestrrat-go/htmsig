package sfv

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIntegerList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{"123", 123, IntegerType},
		{"123, 456", []any{123, 456}, IntegerType},
		{"-999", -999, IntegerType},
		{"0", 0, IntegerType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseDecimalList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{"123.456", 123.456, DecimalType},
		{"123.456, 789.123", []any{123.456, 789.123}, DecimalType},
		{"-123.456", -123.456, DecimalType},
		{"0.0", 0.0, DecimalType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{`"hello"`, "hello", StringType},
		{`"hello", "world"`, []any{"hello", "world"}, StringType},
		{`"hello \"world\""`, `hello "world"`, StringType},
		{`""`, "", StringType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseTokenList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{"foo", "foo", TokenType},
		{"foo, bar", []any{"foo", "bar"}, TokenType},
		{"*", "*", TokenType},
		{"foo123", "foo123", TokenType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseByteSequenceList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{":aGVsbG8=:", []byte("hello"), ByteSequenceType},
		{":aGVsbG8=:, :d29ybGQ=:", []any{[]byte("hello"), []byte("world")}, ByteSequenceType},
		{"::", []byte{}, ByteSequenceType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseBooleanList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{"?1", true, BooleanType},
		{"?0", false, BooleanType},
		{"?1, ?0", []any{true, false}, BooleanType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseDateList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{"@1659578233", int64(1659578233), DateType},
		{"@0", int64(0), DateType},
		{"@1659578233, @1659578234", []any{int64(1659578233), int64(1659578234)}, DateType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
			}
		})
	}
}

func TestParseDisplayStringList(t *testing.T) {
	tests := []struct {
		input    string
		expected any
		itemType int
	}{
		{`%"hello"`, "hello", DisplayStringType},
		{`%"hello", %"world"`, []any{"hello", "world"}, DisplayStringType},
		{`%"This is intended for display to %c3%bcsers."`, "This is intended for display to üsers.", DisplayStringType},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			result, err := Parse([]byte(test.input))
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)

			// Handle both single items and lists
			if expectedSlice, ok := test.expected.([]any); ok {
				// Multiple items
				require.Len(t, list.values, len(expectedSlice), "Unexpected number of items")
				for i, expectedValue := range expectedSlice {
					item, ok := list.values[i].(*Item)
					require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
					require.Equal(t, test.itemType, item.Type, "Item %d has wrong type", i)
					require.Equal(t, expectedValue, item.Value, "Item %d has wrong value", i)
				}
			} else {
				// Single item
				require.Len(t, list.values, 1, "Expected single item")
				item, ok := list.values[0].(*Item)
				require.True(t, ok, "Item should be *Item, got %T", list.values[0])
				require.Equal(t, test.itemType, item.Type, "Item has wrong type")
				require.Equal(t, test.expected, item.Value, "Item has wrong value")
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
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)
			require.Len(t, list.values, test.expectedLen, "Unexpected number of items")

			for i, expectedType := range test.expectedTypes {
				item, ok := list.values[i].(*Item)
				require.True(t, ok, "Item %d should be *Item, got %T", i, list.values[i])
				require.Equal(t, expectedType, item.Type, "Item %d has wrong type", i)
			}
		})
	}
}

func TestParseEmptyList(t *testing.T) {
	result, err := Parse([]byte(""))
	require.NoError(t, err, "Parse failed")

	list, ok := result.(*List)
	require.True(t, ok, "Parse result should be *List, got %T", result)
	require.Empty(t, list.values, "Expected empty list")
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
			require.NoError(t, err, "Parse failed")

			list, ok := result.(*List)
			require.True(t, ok, "Parse result should be *List, got %T", result)
			require.NotEmpty(t, list.values, "Expected non-empty list")
		})
	}
}
