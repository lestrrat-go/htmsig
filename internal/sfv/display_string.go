package sfv

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/blackmagic"
)

type DisplayStringItem = fullItem[*DisplayStringBareItem]
type DisplayStringBareItem struct {
	uvalue[string]
}

// DisplayString creates a new DisplayStringBareItem builder for you to construct a display string item with.
func DisplayString() *BareItemBuilder[*DisplayStringBareItem, string] {
	var v DisplayStringBareItem
	return &BareItemBuilder[*DisplayStringBareItem, string]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (d *DisplayStringBareItem) setValue(value string) error {
	d.value = value
	return nil
}

func NewDisplayString() *DisplayStringBareItem {
	return &DisplayStringBareItem{}
}

func (d *DisplayStringBareItem) SetValue(value string) *DisplayStringBareItem {
	d.value = value
	return d
}

func (d DisplayStringBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('%')
	buf.WriteByte('"')
	// Percent-encode non-ASCII characters
	for _, r := range d.value {
		if r <= 127 && r >= 32 && r != '%' {
			// ASCII printable characters except %
			buf.WriteRune(r)
		} else {
			// Percent-encode everything else
			utf8Bytes := []byte(string(r))
			for _, b := range utf8Bytes {
				buf.WriteString(fmt.Sprintf("%%%.2x", b))
			}
		}
	}
	buf.WriteByte('"')
	return buf.Bytes(), nil
}

func (d DisplayStringBareItem) Type() int {
	return DisplayStringType
}

func (d DisplayStringBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, d.value)
}

func (d *DisplayStringBareItem) With(params *Parameters) Item {
	return &DisplayStringItem{
		bare:   d,
		params: params,
	}
}
