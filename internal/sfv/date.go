package sfv

import (
	"bytes"
	"strconv"

	"github.com/lestrrat-go/blackmagic"
)

type DateItem = fullItem[*DateBareItem, int64]
type DateBareItem struct {
	uvalue[int64]
}

// Date creates a new DateBareItem builder for you to construct a date item with.
func Date() *BareItemBuilder[*DateBareItem, int64] {
	var v DateBareItem
	return &BareItemBuilder[*DateBareItem, int64]{
		value:  &v,
		setter: (&v).SetValue,
	}
}

func NewDate() *DateBareItem {
	return &DateBareItem{}
}

func (d DateBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('@')
	buf.WriteString(strconv.FormatInt(d.value, 10))
	return buf.Bytes(), nil
}

func (d DateBareItem) Type() int {
	return DateType
}

func (d DateBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, d.value)
}

func (d *DateBareItem) ToItem() Item {
	return &fullItem[*DateBareItem, int64]{
		bare:   d,
		params: NewParameters(),
	}
}
