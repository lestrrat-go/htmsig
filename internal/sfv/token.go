package sfv

import (
	"bytes"
)

type TokenItem = fullItem[*TokenBareItem, string]
type TokenBareItem struct {
	uvalue[string]
}

// Token creates a new TokenBareItem builder for you to construct a token item with.
func Token() *BareItemBuilder[*TokenBareItem, string] {
	var v TokenBareItem
	return &BareItemBuilder[*TokenBareItem, string]{
		value:  &v,
		setter: (&v).SetValue,
	}
}

func (t TokenBareItem) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(t.value)
	return buf.Bytes(), nil
}

func (t TokenBareItem) Type() int {
	return TokenType
}

func (t *TokenBareItem) ToItem() Item {
	return &TokenItem{
		bare:   t,
		params: NewParameters(),
	}
}
