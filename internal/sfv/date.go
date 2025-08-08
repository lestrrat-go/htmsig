package sfv

import (
	"bytes"
	"strconv"

	"github.com/lestrrat-go/blackmagic"
)

type DateItem = fullItem[*DateBareItem]
type DateBareItem struct {
	itemValue[int64]
}

// Date creates a new DateBareItem builder for you to construct a date item with.
func Date() *BareItemBuilder[*DateBareItem, int64] {
	var v DateBareItem
	return &BareItemBuilder[*DateBareItem, int64]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (d *DateBareItem) setValue(value int64) error {
	d.value = value
	return nil
}

func NewDate() *DateBareItem {
	return &DateBareItem{}
}

func (d *DateBareItem) SetValue(value int64) *DateBareItem {
	d.value = value
	return d
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

func (d *DateBareItem) With(params *Parameters) Item {
	return &fullItem[*DateBareItem]{
		bare:   d,
		params: params,
	}
}
