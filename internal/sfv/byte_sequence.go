package sfv

import (
	"bytes"
	"encoding/base64"
)

type ByteSequenceItem = fullItem[*ByteSequenceBareItem, []byte]

// ByteSequenceBareItem represents a bare byte sequence in the SFV format.
type ByteSequenceBareItem struct {
	uvalue[[]byte]
}

// ByteSequence creates a new ByteSequenceBareItem builder for you to construct a byte sequence item with.
func ByteSequence() *BareItemBuilder[*ByteSequenceBareItem, []byte] {
	var v ByteSequenceBareItem
	return &BareItemBuilder[*ByteSequenceBareItem, []byte]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (b *ByteSequenceBareItem) setValue(value []byte) error {
	b.value = value
	return nil
}

func (b ByteSequenceBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(':')
	buf.WriteString(base64.StdEncoding.EncodeToString(b.value))
	buf.WriteByte(':')
	return buf.Bytes(), nil
}

func (b ByteSequenceBareItem) Type() int {
	return ByteSequenceType
}

func (b *ByteSequenceBareItem) ToItem() Item {
	return &ByteSequenceItem{
		bare:   b,
		params: NewParameters(),
	}
}
