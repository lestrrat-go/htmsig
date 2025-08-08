package sfv

import (
	"bytes"
	"strconv"
	"strings"
)

// DecimalItem represents a decimal item with parameters.
type DecimalItem = fullItem[*DecimalBareItem, float64]

// DecimalBareItem represents a bare decimal item without parameters.
type DecimalBareItem struct {
	uvalue[float64]
}

var _ Item = (*DecimalItem)(nil)
var _ BareItem = (*DecimalBareItem)(nil)

// Decimal creates a new DecimalBareItem builder for you to construct a decimal item with.
func Decimal() *BareItemBuilder[*DecimalBareItem, float64] {
	var v DecimalBareItem
	return &BareItemBuilder[*DecimalBareItem, float64]{
		value:  &v,
		setter: (&v).SetValue,
	}
}

func (d DecimalBareItem) Type() int {
	return DecimalType
}

func (d DecimalBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer

	// Format with up to 3 decimal places, removing trailing zeros
	str := strconv.FormatFloat(d.value, 'f', 3, 64)
	str = strings.TrimRight(str, "0")
	if str[len(str)-1] == '.' {
		// If the last character is a dot, we need to add a zero
		// to avoid an invalid format
		str += "0"
	}
	buf.WriteString(str)
	return buf.Bytes(), nil
}

func (d *DecimalBareItem) ToItem() Item {
	return &DecimalItem{
		bare: d,
	}
}

type IntegerItem = fullItem[*IntegerBareItem, int64]
type IntegerBareItem struct {
	uvalue[int64]
}

// Integer creates a new IntegerBareItem builder for you to construct an integer item with.
func Integer() *BareItemBuilder[*IntegerBareItem, int64] {
	var v IntegerBareItem
	return &BareItemBuilder[*IntegerBareItem, int64]{
		value:  &v,
		setter: (&v).SetValue,
	}
}

func (i IntegerBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(strconv.FormatInt(i.value, 10))
	return buf.Bytes(), nil
}

func (i IntegerBareItem) Type() int {
	return IntegerType
}

func (i *IntegerBareItem) ToItem() Item {
	return &IntegerItem{
		bare:   i,
		params: NewParameters(),
	}
}
