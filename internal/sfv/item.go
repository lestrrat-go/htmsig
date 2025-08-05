package sfv

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"github.com/lestrrat-go/blackmagic"
)

// Item represents a single item in the SFV (Structured Field Value) format.
type Item interface {
	Marshaler

	Type() int
	Value(dst any) error
	Parameters() *Parameters
	With(params *Parameters) Item
}

// Boolean represents a boolean value in the SFV format.
type Boolean struct {
	value  bool
	params *Parameters
}

func NewBoolean() *Boolean {
	return &Boolean{}
}

func (b *Boolean) SetValue(value bool) *Boolean {
	b.value = value
	return b
}

func (b Boolean) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	if b.value {
		buf.WriteString("?1")
	} else {
		buf.WriteString("?0")
	}

	// Add parameters if any
	if b.params != nil && b.params.Len() > 0 {
		paramBytes, err := b.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (b Boolean) Type() int {
	return BooleanType
}

func (b Boolean) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, b.value)
}

func (b Boolean) Parameters() *Parameters {
	return b.params
}

func (b *Boolean) With(params *Parameters) Item {
	b.params = params
	return b
}

type ByteSequence struct {
	value  []byte
	params *Parameters
}

func NewByteSequence() *ByteSequence {
	return &ByteSequence{}
}

func (b *ByteSequence) SetValue(value []byte) *ByteSequence {
	b.value = value
	return b
}

func (b ByteSequence) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(':')
	buf.WriteString(base64.StdEncoding.EncodeToString(b.value))
	buf.WriteByte(':')

	// Add parameters if any
	if b.params != nil && b.params.Len() > 0 {
		paramBytes, err := b.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (b ByteSequence) Type() int {
	return ByteSequenceType
}

func (b ByteSequence) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, b.value)
}

func (b ByteSequence) Parameters() *Parameters {
	return b.params
}

func (b *ByteSequence) With(params *Parameters) Item {
	b.params = params
	return b
}

type Date struct {
	value  int64
	params *Parameters
}

func NewDate() *Date {
	return &Date{}
}

func (d *Date) SetValue(value int64) *Date {
	d.value = value
	return d
}

func (d Date) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('@')
	buf.WriteString(strconv.FormatInt(d.value, 10))

	// Add parameters if any
	if d.params != nil && d.params.Len() > 0 {
		paramBytes, err := d.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (d Date) Type() int {
	return DateType
}

func (d Date) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, d.value)
}

func (d Date) Parameters() *Parameters {
	return d.params
}

func (d *Date) With(params *Parameters) Item {
	d.params = params
	return d
}

type Decimal struct {
	value  float64
	params *Parameters
}

func NewDecimal() *Decimal {
	return &Decimal{}
}

func (d *Decimal) SetValue(value float64) *Decimal {
	d.value = value
	return d
}

func (d Decimal) MarshalSFV() ([]byte, error) {
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

	// Add parameters if any
	if d.params != nil && d.params.Len() > 0 {
		paramBytes, err := d.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (d Decimal) Type() int {
	return DecimalType
}

func (d Decimal) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, d.value)
}

func (d Decimal) Parameters() *Parameters {
	return d.params
}

func (d *Decimal) With(params *Parameters) Item {
	d.params = params
	return d
}

type Integer struct {
	value  int64
	params *Parameters
}

func NewInteger() *Integer {
	return &Integer{}
}

func (i *Integer) SetValue(value int64) *Integer {
	i.value = value
	return i
}

func (i Integer) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(strconv.FormatInt(i.value, 10))

	// Add parameters if any
	if i.params != nil && i.params.Len() > 0 {
		paramBytes, err := i.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (i Integer) Type() int {
	return IntegerType
}

func (i Integer) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, i.value)
}

func (i Integer) Parameters() *Parameters {
	return i.params
}

func (i *Integer) With(params *Parameters) Item {
	i.params = params
	return i
}

// String represents a string value in the SFV format.
type String struct {
	value  string
	params *Parameters
}

func NewString() *String {
	return &String{}
}

func (s *String) SetValue(value string) *String {
	s.value = value
	return s
}

func (s String) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('"')
	// Escape quotes and backslashes
	for _, r := range s.value {
		if r == '"' || r == '\\' {
			buf.WriteByte('\\')
		}
		buf.WriteRune(r)
	}
	buf.WriteByte('"')

	// Add parameters if any
	if s.params != nil && s.params.Len() > 0 {
		paramBytes, err := s.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (s String) Type() int {
	return StringType
}

func (s String) Value(dst any) error {
	return blackmagic.AssignIfCompatible(dst, s.value)
}

func (s String) Parameters() *Parameters {
	return s.params
}

func (s *String) With(params *Parameters) Item {
	s.params = params
	return s
}

type Token struct {
	str String
}

func NewToken() *Token {
	return &Token{}
}

func (t *Token) SetValue(value string) *Token {
	t.str.value = value
	return t
}

func (t Token) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(t.str.value)

	// Add parameters if any
	if t.str.params != nil && t.str.params.Len() > 0 {
		paramBytes, err := t.str.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (t Token) Type() int {
	return TokenType
}

func (t Token) Value(dst any) error {
	return t.str.Value(dst)
}

func (t Token) Parameters() *Parameters {
	return t.str.Parameters()
}

func (t *Token) With(params *Parameters) Item {
	t.str.params = params
	return t
}

type DisplayString struct {
	str String
}

func NewDisplayString() *DisplayString {
	return &DisplayString{}
}

func (d *DisplayString) SetValue(value string) *DisplayString {
	d.str.value = value
	return d
}

func (d DisplayString) MarshalSFV() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('%')
	buf.WriteByte('"')
	// Percent-encode non-ASCII characters
	for _, r := range d.str.value {
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

	// Add parameters if any
	if d.str.params != nil && d.str.params.Len() > 0 {
		paramBytes, err := d.str.params.MarshalSFV()
		if err != nil {
			return nil, err
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}

func (d DisplayString) Type() int {
	return DisplayStringType
}

func (d DisplayString) Value(dst any) error {
	return d.str.Value(dst)
}

func (d DisplayString) Parameters() *Parameters {
	return d.str.Parameters()
}

func (d *DisplayString) With(params *Parameters) Item {
	d.str.params = params
	return d
}
