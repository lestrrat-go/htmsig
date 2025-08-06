package sfv

import (
	"fmt"

	"github.com/lestrrat-go/blackmagic"
)

// This is the actual value, and we're only providing this to avoid
// having to write a lot of boilerplate code for each type.
type itemValue[T any] struct {
	value T
}

func (iv *itemValue[T]) SetValue(value T) {
	iv.value = value
}

func (iv itemValue[T]) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, iv.value)
}

type fullItem struct {
	BareItem
	params *Parameters
}

func (fi *fullItem) Parameters() *Parameters {
	return fi.params
}

func (item *fullItem) MarshalSFV() ([]byte, error) {
	bi, err := item.BareItem.MarshalSFV()
	if err != nil {
		return nil, fmt.Errorf("error marshaling bare item: %w", err)
	}

	// Add parameters if any
	if item.params != nil && item.params.Len() > 0 {
		paramBytes, err := item.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		bi = append(bi, paramBytes...)
	}

	return bi, nil
}

// A BareItem represents a bare item, which is the itemValue plus the item
// type. A bare item cannot carry parameters. However, it _can_ be upgraded
// to a full Item by calling With().
type BareItem interface {
	Marshaler

	Type() int
	Value(dst any) error

	// Creates a new Item with the given parameters
	With(*Parameters) Item
}

// Item represents a single item in the SFV (Structured Field Value) format.
// It is essentially a bare item with parameters
type Item interface {
	BareItem

	Parameters() *Parameters
}
