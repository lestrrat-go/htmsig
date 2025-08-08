package sfv

import (
	"strconv"
)

type StringItem = fullItem[*StringBareItem, string]

// StringBareItem represents a string value in the SFV format.
type StringBareItem struct {
	uvalue[string]
}

// String creates a new StringBareItem builder for you to construct a string item with.
func String() *BareItemBuilder[*StringBareItem, string] {
	var v StringBareItem
	return &BareItemBuilder[*StringBareItem, string]{
		value:  &v,
		setter: v.SetValue,
	}
}

func (s StringBareItem) MarshalSFV() ([]byte, error) {
	quoted := strconv.Quote(s.value)
	return []byte(quoted), nil
}

func (s StringBareItem) Type() int {
	return StringType
}

func (s *StringBareItem) ToItem() Item {
	return &StringItem{
		bare:   s,
		params: NewParameters(),
	}
}
