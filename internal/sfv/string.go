package sfv

import (
	"strconv"

	"github.com/lestrrat-go/blackmagic"
)

// StringBareItem represents a string value in the SFV format.
type StringBareItem struct {
	itemValue[string]
}

// String creates a new StringBareItem builder for you to construct a string item with.
func String() *BareItemBuilder[*StringBareItem, string] {
	var v StringBareItem
	return &BareItemBuilder[*StringBareItem, string]{
		value:  &v,
		setter: v.setValue,
	}
}

func (s *StringBareItem) setValue(value string) error {
	s.value = value
	return nil
}

func (s StringBareItem) MarshalSFV() ([]byte, error) {
	quoted := strconv.Quote(s.value)
	return []byte(quoted), nil
}

func (s StringBareItem) Type() int {
	return StringType
}

func (s StringBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, s.value)
}

func (s *StringBareItem) With(params *Parameters) Item {
	return &fullItem{
		BareItem: s,
		params:   params,
	}
}
