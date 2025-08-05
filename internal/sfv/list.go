package sfv

import (
	"bytes"
	"strings"
)

type InnerList struct {
	values []Item
	params *Parameters
}

// Len returns the number of values in the inner list
func (il *InnerList) Len() int {
	if il == nil {
		return 0
	}
	return len(il.values)
}

// Get returns the value at the specified index
func (il *InnerList) Get(index int) (Item, bool) {
	if il == nil || index < 0 || index >= len(il.values) {
		return nil, false
	}
	return il.values[index], true
}

// MarshalSFV implements the Marshaler interface for InnerList
func (il *InnerList) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('(')

	for i := 0; i < il.Len(); i++ {
		if i > 0 {
			buf.WriteByte(' ')
		}

		item, ok := il.Get(i)
		if !ok {
			continue
		}

		itemBytes, err := item.MarshalSFV()
		if err != nil {
			return nil, err
		}

		buf.Write(itemBytes)
	}

	buf.WriteByte(')')

	// Add parameters if any
	if il.params != nil && il.params.Len() > 0 {
		paramBytes, err := il.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

// Parameters returns the parameters associated with this InnerList
func (il *InnerList) Parameters() *Parameters {
	if il == nil {
		return nil
	}
	return il.params
}

type List struct {
	values []any
}

// MarshalSFV implements the Marshaler interface for List
func (l *List) MarshalSFV() ([]byte, error) {
	if l.Len() == 0 {
		return []byte{}, nil
	}

	var parts []string
	for i := 0; i < l.Len(); i++ {
		value, ok := l.Get(i)
		if !ok {
			continue
		}

		var itemBytes []byte
		var err error

		switch v := value.(type) {
		case Item:
			itemBytes, err = v.MarshalSFV()
		case *InnerList:
			itemBytes, err = v.MarshalSFV()
		default:
			// This shouldn't happen with properly constructed Lists
			continue
		}

		if err != nil {
			return nil, err
		}

		parts = append(parts, string(itemBytes))
	}

	return []byte(strings.Join(parts, ", ")), nil
}

// Len returns the number of values in the list
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.values)
}

// Get returns the value at the specified index
func (l *List) Get(index int) (any, bool) {
	if l == nil || index < 0 || index >= len(l.values) {
		return nil, false
	}
	return l.values[index], true
}
