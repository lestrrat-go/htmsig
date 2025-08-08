package sfv

import "fmt"

// BareItemBuilder is used to build a BareItem with a specific type.
type BareItemBuilder[B BareItem, T any] struct {
	value B
	// This is a horrible hack to allow us to
	setter func(T) error
	err    error
}

type ItemBuilder struct {
	value Item
	err   error
}

func (bb *BareItemBuilder[B, T]) ToItem() *ItemBuilder {
	if bb.err != nil {
		return &ItemBuilder{err: bb.err}
	}

	return &ItemBuilder{
		value: bb.value.With(NewParameters()),
	}
}

func (bb *BareItemBuilder[B, T]) Value(value T) *BareItemBuilder[B, T] {
	if bb.err != nil {
		return bb
	}
	if err := bb.setter(value); err != nil {
		bb.err = fmt.Errorf("error setting value: %w", err)
	}
	return bb
}

func (bb *BareItemBuilder[B, T]) Build() (B, error) {
	if bb.err != nil {
		var zero B
		return zero, bb.err
	}
	return bb.value, nil
}

func (bb *BareItemBuilder[B, T]) MustBuild() B {
	if bb.err != nil {
		panic(bb.err)
	}
	return bb.value
}

// Parameter adds a parameter to the item being built, and in the meanwhile
// upgrades the builder to an ItemBuilder from a BareItemBuilder.
// If there was an error in the builder to start with, the error will be
// carried over to the ItemBuilder (and the building process will not continue
// internally).
func (bb *BareItemBuilder[B, T]) Parameter(k string, v BareItem) *ItemBuilder {
	var ib ItemBuilder
	if bb.err != nil {
		ib.err = bb.err
		return &ib
	}

	ib.value = bb.value.With(NewParameters())
	if err := ib.value.Parameters().Set(k, v); err != nil {
		ib.err = fmt.Errorf("error setting parameter %q: %w", k, err)
		return &ib
	}

	return &ib
}

func (ib *ItemBuilder) Build() (Item, error) {
	if ib.err != nil {
		return nil, ib.err
	}
	return ib.value, nil
}

func (ib *ItemBuilder) MustBuild() Item {
	if ib.err != nil {
		panic(ib.err)
	}
	return ib.value
}

func (ib *ItemBuilder) Parameter(k string, v BareItem) *ItemBuilder {
	if ib.err != nil {
		return ib
	}
	if err := ib.value.Parameters().Set(k, v); err != nil {
		ib.err = fmt.Errorf("error setting parameter %q: %w", k, err)
	}
	return ib
}
