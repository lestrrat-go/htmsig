package sfv

import (
	"fmt"

	"github.com/lestrrat-go/blackmagic"
)

func BareItemFrom(value any) (BareItem, error) {
	switch v := value.(type) {
	case BareItem:
		return v, nil
	case string:
		return String().Value(v).Build()
	case bool:
		return Boolean().Value(v).Build()
	case int:
		return Integer().Value(int64(v)).Build()
	case int64:
		return Integer().Value(v).Build()
	case float64:
		return Decimal().Value(v).Build()
	case float32:
		return Decimal().Value(float64(v)).Build()
	default:
		return nil, fmt.Errorf("unsupported bare item type %T", v)
	}
}

// This is the actual value, and we're only providing this to avoid
// having to write a lot of boilerplate code for each type.
type itemValue[T any] struct {
	value T
}

func (iv *itemValue[T]) SetValue(value T) {
	iv.value = value
}

func (iv *itemValue[T]) Value() T {
	return iv.value
}

func (iv itemValue[T]) GetValue(dst any) error {
	return blackmagic.AssignIfCompatible(dst, iv.value)
}

type fullItem[T BareItem] struct {
	bare   T
	params *Parameters
}

func (fi *fullItem[T]) Parameters() *Parameters {
	return fi.params
}

func (item *fullItem[T]) MarshalSFV() ([]byte, error) {
	bi, err := item.bare.MarshalSFV()
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

func (item *fullItem[T]) GetValue(dst any) error {
	return item.bare.GetValue(dst)
}

func (item *fullItem[T]) Type() int {
	return item.bare.Type()
}

func (item *fullItem[T]) With(params *Parameters) Item {
	return &fullItem[T]{
		bare:   item.bare,
		params: params,
	}
}

// A BareItem represents a bare item, which is the itemValue plus the item
// type. A bare item cannot carry parameters. However, it _can_ be upgraded
// to a full Item by calling With().
type BareItem interface {
	Marshaler

	Type() int

	// GetValue is a method that assigns the underlying value of the item to dst.
	// It is used to retrieve the value without needing to know the type, or
	// without having to go through type conversion.
	//
	// If you already know the type of the value, you could use the Value() method
	// instead, which returns the value directly.
	GetValue(dst any) error

	// Creates a new Item with the given parameters
	With(*Parameters) Item
}

// Item represents a single item in the SFV (Structured Field Value) format.
// It is essentially a bare item with parameters
type Item interface {
	BareItem

	Parameters() *Parameters
}
