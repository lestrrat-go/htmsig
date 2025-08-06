package sfv

import "github.com/lestrrat-go/blackmagic"

// BooleanBareItem represents a bare boolean value in the SFV format.
type BooleanBareItem bool

var _ BareItem = True()

// Boolean creates a new BooleanBareItem builder for you to construct a boolean item with.
func Boolean() *BareItemBuilder[BooleanBareItem, bool] {
	v := False()
	bb := &BareItemBuilder[BooleanBareItem, bool]{
		value: v,
	}
	bb.setter = func(value bool) error {
		if value {
			bb.value = True()
		} else {
			bb.value = False()
		}
		return nil
	}
	return bb
}

func True() BooleanBareItem {
	return BooleanBareItem(true)
}

func False() BooleanBareItem {
	return BooleanBareItem(false)
}

func (b BooleanBareItem) SetValue(value bool) BooleanBareItem {
	if value {
		return True()
	}
	return False()
}

func (b BooleanBareItem) Type() int {
	return BooleanType
}

func (b BooleanBareItem) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, bool(b))
}

var trueBareItemBytes = []byte("?1")
var falseBareItemBytes = []byte("?0")

func (b BooleanBareItem) MarshalSFV() ([]byte, error) {
	if bool(b) {
		return trueBareItemBytes, nil
	}
	return falseBareItemBytes, nil
}

func (b BooleanBareItem) With(params *Parameters) Item {
	return &fullItem{
		BareItem: b,
		params:   params,
	}
}
