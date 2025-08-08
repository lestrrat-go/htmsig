package sfv

import (
	"bytes"
	"fmt"
)

type DisplayStringItem = fullItem[*DisplayStringBareItem, string]
type DisplayStringBareItem struct {
	uvalue[string]
}

// DisplayString creates a new DisplayStringBareItem builder for you to construct a display string item with.
func DisplayString() *BareItemBuilder[*DisplayStringBareItem, string] {
	var v DisplayStringBareItem
	return &BareItemBuilder[*DisplayStringBareItem, string]{
		value:  &v,
		setter: (&v).SetValue,
	}
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

func (d *DisplayStringBareItem) ToItem() Item {
	return &DisplayStringItem{
		bare:   d,
		params: NewParameters(),
	}
}
