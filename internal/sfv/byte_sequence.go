package sfv

import (
	"bytes"
	"encoding/base64"

	"github.com/lestrrat-go/blackmagic"
)

type ByteSequenceItem = fullItem[*ByteSequenceBareItem]

// ByteSequenceBareItem represents a bare byte sequence in the SFV format.
type ByteSequenceBareItem struct {
	itemValue[[]byte]
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

func NewByteSequence() *ByteSequenceBareItem {
	return &ByteSequenceBareItem{}
}

func (b *ByteSequenceBareItem) SetValue(value []byte) *ByteSequenceBareItem {
	b.value = value
	return b
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

func (b ByteSequenceBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, b.value)
}

func (b *ByteSequenceBareItem) With(params *Parameters) Item {
	return &ByteSequenceItem{
		bare:   b,
		params: params,
	}
}
