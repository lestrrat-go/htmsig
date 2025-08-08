package sfv

import (
	"bytes"
	"strconv"
	"strings"

	"github.com/lestrrat-go/blackmagic"
)

type DecimalItem = fullItem[*DecimalBareItem]
type DecimalBareItem struct {
	itemValue[float64]
}

// Decimal creates a new DecimalBareItem builder for you to construct a decimal item with.
func Decimal() *BareItemBuilder[*DecimalBareItem, float64] {
	var v DecimalBareItem
	return &BareItemBuilder[*DecimalBareItem, float64]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (d *DecimalBareItem) setValue(value float64) error {
	d.value = value
	return nil
}

func NewDecimal() *DecimalBareItem {
	return &DecimalBareItem{}
}

func (d *DecimalBareItem) SetValue(value float64) *DecimalBareItem {
	d.value = value
	return d
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

func (d DecimalBareItem) Type() int {
	return DecimalType
}

func (d DecimalBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, d.value)
}

func (d *DecimalBareItem) With(params *Parameters) Item {
	return &DecimalItem{
		bare:   d,
		params: params,
	}
}

type IntegerItem = fullItem[*IntegerBareItem]
type IntegerBareItem struct {
	itemValue[int64]
}

// Integer creates a new IntegerBareItem builder for you to construct an integer item with.
func Integer() *BareItemBuilder[*IntegerBareItem, int64] {
	var v IntegerBareItem
	return &BareItemBuilder[*IntegerBareItem, int64]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (i *IntegerBareItem) setValue(value int64) error {
	i.value = value
	return nil
}

func NewInteger() *IntegerBareItem {
	return &IntegerBareItem{}
}

func (i *IntegerBareItem) SetValue(value int64) *IntegerBareItem {
	i.value = value
	return i
}

func (i IntegerBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(strconv.FormatInt(i.value, 10))
	return buf.Bytes(), nil
}

func (i IntegerBareItem) Type() int {
	return IntegerType
}

func (i IntegerBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, i.value)
}

func (i *IntegerBareItem) With(params *Parameters) Item {
	return &IntegerItem{
		bare:   i,
		params: params,
	}
}
