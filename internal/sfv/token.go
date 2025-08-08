package sfv

import (
	"bytes"

	"github.com/lestrrat-go/blackmagic"
)

type TokenItem = fullItem[*TokenBareItem]
type TokenBareItem struct {
	itemValue[string]
}

// Token creates a new TokenBareItem builder for you to construct a token item with.
func Token() *BareItemBuilder[*TokenBareItem, string] {
	var v TokenBareItem
	return &BareItemBuilder[*TokenBareItem, string]{
		value:  &v,
		setter: (&v).setValue,
	}
}

func (t *TokenBareItem) setValue(value string) error {
	t.value = value
	return nil
}

func NewToken() *TokenBareItem {
	return &TokenBareItem{}
}

func (t *TokenBareItem) SetValue(value string) *TokenBareItem {
	t.value = value
	return t
}

func (t TokenBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(t.value)
	return buf.Bytes(), nil
}

func (t TokenBareItem) Type() int {
	return TokenType
}

func (t TokenBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, t.value)
}

func (t *TokenBareItem) With(params *Parameters) Item {
	return &TokenItem{
		bare:   t,
		params: params,
	}
}
