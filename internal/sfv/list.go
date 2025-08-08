package sfv

import (
	"bytes"
	"fmt"
	"strings"
)

// InnerListBuilder helps build InnerList objects with proper parameter handling
type InnerListBuilder struct {
	innerList *InnerList
	err       error
}

// NewInnerListBuilder creates a new InnerListBuilder
func NewInnerListBuilder() *InnerListBuilder {
	return &InnerListBuilder{
		innerList: &InnerList{
			values: make([]Item, 0),
			params: nil,
		},
	}
}

// Add adds an item to the inner list
func (ilb *InnerListBuilder) Add(item any) *InnerListBuilder {
	if ilb.err != nil {
		return ilb
	}

	if err := ilb.innerList.Add(item); err != nil {
		ilb.err = fmt.Errorf("failed to add item to inner list: %w", err)
	}
	return ilb
}

// Parameter adds a parameter to the inner list
func (ilb *InnerListBuilder) Parameter(key string, value BareItem) *InnerListBuilder {
	if ilb.err != nil {
		return ilb
	}

	if ilb.innerList.params == nil {
		ilb.innerList.params = &Parameters{Values: make(map[string]BareItem)}
	}

	if err := ilb.innerList.params.Set(key, value); err != nil {
		ilb.err = fmt.Errorf("failed to set parameter %q: %w", key, err)
	}
	return ilb
}

// Build creates the InnerList
func (ilb *InnerListBuilder) Build() (*InnerList, error) {
	if ilb.err != nil {
		return nil, ilb.err
	}
	return ilb.innerList, nil
}

// MustBuild creates the InnerList and panics on error
func (ilb *InnerListBuilder) MustBuild() *InnerList {
	if ilb.err != nil {
		panic(ilb.err)
	}
	return ilb.innerList
}

type InnerList struct {
	values []Item
	params *Parameters
}

func (il *InnerList) Add(in any) error {
	var item Item
	switch v := in.(type) {
	case Item:
		item = v
	case BareItem:
		item = v.ToItem()
	default:
		return fmt.Errorf("item must be of type Item or BareItem, got %T", item)
	}
	il.values = append(il.values, item)
	return nil
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

func (l *List) Add(in any) error {
	// Process the input to ensure it's a proper SFV item
	switch v := in.(type) {
	case Item:
		l.values = append(l.values, v)
	case BareItem:
		l.values = append(l.values, v.ToItem())
	case *InnerList:
		l.values = append(l.values, v)
	default:
		return fmt.Errorf("list item must be of type Item, BareItem, or *InnerList, got %T", in)
	}
	return nil
}

// MarshalSFV implements the Marshaler interface for List
func (l List) MarshalSFV() ([]byte, error) {
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
