package sfv

import (
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/lestrrat-go/htmsig/internal/sfv/internal/tokens"
)

type Value interface {
}

type parseContext struct {
	idx   int // current index in the data
	size  int // size of the data
	data  []byte
	value Value // the parsed value, if any
}

func Parse(data []byte) (Value, error) {
	var pctx parseContext
	pctx.init(data)
	if err := pctx.do(); err != nil {
		return nil, err
	}
	return pctx.value, nil
}

func (pctx *parseContext) init(data []byte) {
	pctx.data = data
	pctx.size = len(data)
	pctx.idx = 0
}

func (p *parseContext) eof() bool {
	return p.idx >= p.size
}

func (p *parseContext) current() byte {
	if p.eof() {
		return 0 // EOF
	}
	return p.data[p.idx]
}

func (p *parseContext) advance() {
	if p.eof() {
		return
	}
	p.idx++
}

func (p *parseContext) stripWhitespace() {
	for !p.eof() && unicode.IsSpace(rune(p.data[p.idx])) {
		p.advance()
	}
}

// isDictionary checks if the input looks like a dictionary by looking for key=value patterns
func (p *parseContext) isDictionary() bool {
	// Save current position
	savedIdx := p.idx
	defer func() { p.idx = savedIdx }()

	p.stripWhitespace()
	if p.eof() {
		return false
	}

	// Look for key=value pattern
	// First, try to find a token (key)
	if !isAlpha(p.current()) && p.current() != '*' {
		return false
	}

	// Skip token characters
	for !p.eof() && (isAlpha(p.current()) || isDigit(p.current()) ||
		p.current() == '_' || p.current() == '-' || p.current() == '.' ||
		p.current() == ':' || p.current() == '/' || p.current() == '*') {
		p.advance()
	}

	p.stripWhitespace()

	// Check if we have '=' which indicates dictionary
	return !p.eof() && p.current() == '='
}

func (p *parseContext) do() error {
	// RFC 9651 Section 4.2: Parsing Structured Fields algorithm

	// 1. Convert input_bytes into an ASCII string input_string; if conversion fails, fail parsing.
	// (This is already done in init() since we're working with []byte)

	// 2. Discard any leading SP characters from input_string.
	p.stripWhitespace()

	// Check if this looks like a dictionary or a list
	var output Value
	var err error

	if p.isDictionary() {
		// 3. Parse as sf-dictionary
		output, err = p.parseDictionary()
		if err != nil {
			return fmt.Errorf("sfv: failed to parse dictionary: %w", err)
		}
	} else {
		// 3. Parse as sf-list (the primary structured field type)
		output, err = p.parseList()
		if err != nil {
			return fmt.Errorf("sfv: failed to parse list: %w", err)
		}
	}

	// 6. Discard any leading SP characters from input_string.
	p.stripWhitespace()

	// 7. If input_string is not empty, fail parsing.
	if !p.eof() {
		return fmt.Errorf("sfv: unexpected trailing characters")
	}

	// 8. Otherwise, return output.
	p.value = output
	return nil
}

// parseList implements the List parsing algorithm from RFC 9651 Section 4.2.1
func (p *parseContext) parseList() (*List, error) {
	var members []Value

	for !p.eof() {
		// Parse an Item or Inner List - check first character to determine which
		var item Value
		var err error

		if p.current() == tokens.OpenParen {
			// Parse Inner List
			item, err = p.parseInnerList()
			if err != nil {
				return nil, fmt.Errorf("sfv: parse list: expected inner list: %w", err)
			}
		} else {
			// Parse Item
			item, err = p.parseItem()
			if err != nil {
				return nil, fmt.Errorf("sfv: parse list: expected item: %w", err)
			}
		}

		members = append(members, item)

		// Discard any leading OWS characters (optional whitespace)
		p.stripWhitespace()

		// If input is empty, return the list
		if p.eof() {
			return &List{values: members}, nil
		}

		// Consume comma; if not comma, fail parsing
		if p.current() != tokens.Comma {
			return nil, fmt.Errorf("sfv: parse list: expected comma, got '%c'", p.current())
		}
		p.advance() // consume comma

		// Discard any leading OWS characters
		p.stripWhitespace()

		// If input is empty after comma, there is a trailing comma; fail parsing
		if p.eof() {
			return nil, fmt.Errorf("sfv: parse list: trailing comma")
		}
	}

	// No structured data has been found; return empty list
	return &List{values: members}, nil
}

// parseDictionary implements the Dictionary parsing algorithm from RFC 9651 Section 4.2.2
func (p *parseContext) parseDictionary() (*Dictionary, error) {
	dict := NewDictionary()
	for !p.eof() {
		// Parse the key (must be a token)
		key, err := p.parseKey()
		if err != nil {
			return nil, fmt.Errorf("sfv: parse dictionary: %w", err)
		}

		var value Value

		// Check for '=' to see if there's a value
		if !p.eof() && p.current() == '=' {
			p.advance() // consume '='

			// Parse the value (Item or Inner List)
			if p.current() == tokens.OpenParen {
				// Parse Inner List
				value, err = p.parseInnerList()
				if err != nil {
					return nil, fmt.Errorf("sfv: parse dictionary value: %w", err)
				}
			} else {
				// Parse Item
				value, err = p.parseItem()
				if err != nil {
					return nil, fmt.Errorf("sfv: parse dictionary value: %w", err)
				}
			}
		} else {
			// No value specified, create a boolean Item with true value
			value = NewBoolean().SetValue(true)
		}

		// Parse parameters for the dictionary member
		params, err := p.parseParameters()
		if err != nil {
			return nil, fmt.Errorf("sfv: parse dictionary parameters: %w", err)
		}

		// If the value is an Item, add parameters to it
		if item, ok := value.(Item); ok && params.Len() > 0 {
			item.With(params)
		}

		dict.keys = append(dict.keys, key)
		dict.values[key] = value

		// Discard any leading OWS characters
		p.stripWhitespace()

		// If input is empty, return the dictionary
		if p.eof() {
			return dict, nil
		}

		// Consume comma; if not comma, fail parsing
		if p.current() != tokens.Comma {
			return nil, fmt.Errorf("sfv: parse dictionary: expected comma, got '%c'", p.current())
		}
		p.advance() // consume comma

		// Discard any leading OWS characters
		p.stripWhitespace()

		// If input is empty after comma, there is a trailing comma; fail parsing
		if p.eof() {
			return nil, fmt.Errorf("sfv: parse dictionary: trailing comma")
		}
	}

	return dict, nil
}

type Parameters struct {
	keys   []string
	Values map[string]Value // Exported field
}

func (p *Parameters) Len() int {
	if p == nil {
		return 0
	}
	return len(p.keys)
}

type InnerList struct {
	values []Item
	params *Parameters
}

// Len returns the number of values in the inner list
func (il *InnerList) Len() int {
	if il == nil {
		return 0
	}
	return len(il.values)
}

// Get returns the value at the specified index
func (il *InnerList) Get(index int) (Item, bool) {
	if il == nil || index < 0 || index >= len(il.values) {
		return nil, false
	}
	return il.values[index], true
}

type List struct {
	values []Value
}

// Len returns the number of values in the list
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.values)
}

// Get returns the value at the specified index
func (l *List) Get(index int) (Value, bool) {
	if l == nil || index < 0 || index >= len(l.values) {
		return nil, false
	}
	return l.values[index], true
}

func (p *parseContext) parseInnerList() (*InnerList, error) {
	p.stripWhitespace()
	if p.current() != tokens.OpenParen {
		return nil, fmt.Errorf(`sfv: parse inner list: expected '%c', got '%c'`, tokens.OpenParen, p.current())
	}
	p.advance() // consume opening parenthesis

	var list InnerList
	for !p.eof() {
		p.stripWhitespace()
		if p.current() == tokens.CloseParen {
			// done with this list, consume this character
			p.advance()
			params, err := p.parseParameters()
			if err != nil {
				return nil, fmt.Errorf("sfv: parse inner list: %w", err)
			}

			if params.Len() > 0 {
				list.params = params
			}
			return &list, nil
		}

		// otherwise, parse an Item
		item, err := p.parseItem()
		if err != nil {
			return nil, fmt.Errorf("sfv: parse inner list: %w", err)
		}
		list.values = append(list.values, item)

		// This must be followed by a space or a close paren
		if !p.eof() {
			if c := p.current(); !unicode.IsSpace(rune(c)) && c != tokens.CloseParen {
				return nil, fmt.Errorf("sfv: parse inner list: expected space or '%c' after item, got '%c'", tokens.CloseParen, c)
			}
		}
	}
	// If we reach here, we've reached EOF without finding a closing paren
	return nil, fmt.Errorf("sfv: parse inner list: unexpected end of input, expected closing paren")
}

// parseKey implements the Key parsing algorithm from RFC 9651 Section 4.2.3.3
func (p *parseContext) parseKey() (string, error) {
	// 1. If the first character of input_string is not lcalpha or "*", fail parsing.
	if p.eof() {
		return "", fmt.Errorf("sfv: unexpected end of input while parsing key")
	}

	c := p.current()
	if !isLowerAlpha(c) && c != tokens.Asterisk {
		return "", fmt.Errorf("sfv: key must start with lowercase letter or asterisk, got '%c'", c)
	}

	// 2. Let output_string be an empty string.
	var sb strings.Builder

	// 3. While input_string is not empty:
	for !p.eof() {
		c := p.current()

		// 3.1. If the first character of input_string is not one of lcalpha, DIGIT, "_", "-", ".", or "*", return output_string.
		if !isLowerAlpha(c) && !isDigit(c) && c != tokens.Underscore && c != tokens.Dash && c != tokens.Period && c != tokens.Asterisk {
			break
		}

		// 3.2. Let char be the result of consuming the first character of input_string.
		p.advance()

		// 3.3. Append char to output_string.
		sb.WriteByte(c)
	}

	// 4. Return output_string.
	result := sb.String()
	if result == "" {
		return "", fmt.Errorf("sfv: empty key")
	}
	return result, nil
}

func isLowerAlpha(c byte) bool {
	return c >= 'a' && c <= 'z'
}

func (p *parseContext) parseParameters() (*Parameters, error) {
	// RFC 9651 Section 4.2.3.2: Parsing Parameters
	var keys []string
	var values map[string]Value

	for !p.eof() {
		// 1. If the first character of input_string is not ";", exit the loop.
		if p.current() != tokens.Semicolon {
			break
		}

		// 2. Consume the ";" character from the beginning of input_string.
		p.advance()

		// 3. Discard any leading SP characters from input_string.
		p.stripWhitespace()

		// 4. Let param_key be the result of running Parsing a Key with input_string.
		paramKey, err := p.parseKey()
		if err != nil {
			return nil, fmt.Errorf("sfv: failed to parse parameter key: %w", err)
		}

		// 5. Let param_value be Boolean true.
		var paramValue Value = true

		// 6. If the first character of input_string is "=":
		if !p.eof() && p.current() == tokens.Equals {
			// 6.1. Consume the "=" character at the beginning of input_string.
			p.advance()

			// 6.2. Let param_value be the result of running Parsing a Bare Item with input_string.
			bareItem, err := p.parseBareItem()
			if err != nil {
				return nil, fmt.Errorf("sfv: failed to parse parameter value: %w", err)
			}
			paramValue = bareItem
		}

		// Initialize maps on first parameter
		if values == nil {
			values = make(map[string]Value)
		}

		// 7. If parameters already contains a key param_key (comparing character for character),
		//    overwrite its value with param_value.
		// 8. Otherwise, append key param_key with value param_value to parameters.
		if _, exists := values[paramKey]; !exists {
			// Only add to keys slice if it's a new key
			keys = append(keys, paramKey)
		}
		values[paramKey] = paramValue
	}

	// Only create Parameters object if we actually have parameters
	if len(keys) == 0 {
		return &Parameters{Values: make(map[string]Value)}, nil
	}

	return &Parameters{
		keys:   keys,
		Values: values,
	}, nil
}

const (
	InvalidType = iota
	IntegerType
	DecimalType
	StringType
	TokenType
	ByteSequenceType
	BooleanType
	DateType
	DisplayStringType
)

func (p *parseContext) parseItem() (Item, error) {
	bareItem, err := p.parseBareItem()
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to parse bare item: %w", err)
	}

	params, err := p.parseParameters()
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to parse parameters: %w", err)
	}

	return bareItem.With(params), nil
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func (p *parseContext) parseBareItem() (Item, error) {
	p.stripWhitespace()
	switch c := p.current(); {
	case c == '-' || isDigit(c):
		v, err := p.parseDecimal()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (decimal): %w`, err)
		}
		return v, nil
	case c == tokens.DoubleQuote:
		v, err := p.parseString()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (quoted string): %w`, err)
		}
		return v, nil
	case c == tokens.Asterisk || isAlpha(c):
		v, err := p.parseToken()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (token): %w`, err)
		}
		return v, nil
	case c == tokens.Colon:
		v, err := p.parseByteSequence()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (byte sequence): %w`, err)
		}
		return v, nil
	case c == tokens.QuestionMark:
		v, err := p.parseBoolean()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (boolean): %w`, err)
		}
		return v, nil
	case c == tokens.AtMark:
		v, err := p.parseDate()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (date): %w`, err)
		}
		return v, nil
	case c == tokens.Percent:
		v, err := p.parseDisplayString()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (display string): %w`, err)
		}
		return v, nil
	default:
		return nil, fmt.Errorf(`sfv: unrecognized character while parsing bare item: %c`, c)
	}
}

func (p *parseContext) parseDecimal() (Item, error) {
	var decimal bool
	sign := 1

	if c := p.current(); c == tokens.Dash {
		p.advance()
		sign = -1
	}

	if p.eof() {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit`)
	}

	var sb strings.Builder
LOOP:
	for !p.eof() {
		c := p.current()

		if sb.Len() == 0 && !isDigit(c) {
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit at the start`)
		}

		switch {
		case c == tokens.Period:
			if decimal {
				// If we already have a decimal point we consider this
				// the end of the number
				break LOOP
			}

			// 12 digits of precision is all we can do
			if sb.Len() > 12 {
				return nil, fmt.Errorf(`sfv: failed to parse numeric value: too many (%d) digits for decimal number`, sb.Len())
			}
			decimal = true
		case !isDigit(c):
			// End of number - break out of loop
			break LOOP
		default:

		}

		p.advance()
		sb.WriteByte(c)
	}

	if decimal {
		if sb.Len() > 16 {
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: too many (%d) digits for decimal number`, sb.Len())
		}

		s := sb.String()
		if s[sb.Len()-1] == tokens.Period {
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit after decimal point`)
		}
		i := strings.IndexByte(s, tokens.Period)
		if sb.Len()-i > 4 { // decimal point + max 3 fractional digits
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: too many (%d) digits after decimal point`, sb.Len()-i-1)
		}

		v, err := strconv.ParseFloat(sb.String(), 64)
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse numeric value as float: %w`, err)
		}
		return NewDecimal().SetValue(v * float64(sign)), nil
	}

	if sb.Len() > 15 {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value: too many (%d) digits for integer number`, sb.Len())
	}

	v, err := strconv.Atoi(sb.String())
	if err != nil {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value as integer: %w`, err)
	}
	return NewInteger().SetValue(int64(v * sign)), nil
}

// parseString parses a quoted string according to RFC 9651 Section 4.2.5
func (p *parseContext) parseString() (*String, error) {
	if p.current() != tokens.DoubleQuote {
		return nil, fmt.Errorf("sfv: expected quote at start of string")
	}
	p.advance() // consume opening quote

	var sb strings.Builder
	for !p.eof() {
		c := p.current()
		p.advance()

		if c == tokens.Backslash {
			if p.eof() {
				return nil, fmt.Errorf("sfv: unexpected end of input after backslash")
			}
			next := p.current()
			if next != tokens.DoubleQuote && next != tokens.Backslash {
				return nil, fmt.Errorf("sfv: invalid escape sequence \\%c", next)
			}
			p.advance()
			sb.WriteByte(next)
		} else if c == tokens.DoubleQuote {
			s := NewString().SetValue(sb.String())
			return s, nil
		} else if c <= 0x1f || c >= 0x7f {
			return nil, fmt.Errorf("sfv: invalid character in string: %c", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return nil, fmt.Errorf("sfv: unexpected end of input, expected closing quote")
}

// parseToken parses a token according to RFC 9651 Section 4.2.6
func (p *parseContext) parseToken() (*Token, error) {
	c := p.current()
	if !isAlpha(c) && c != tokens.Asterisk {
		return nil, fmt.Errorf("sfv: token must start with alpha or asterisk")
	}

	var sb strings.Builder
	for !p.eof() {
		c := p.current()
		// tchar from RFC 5234 plus : and /
		if isAlpha(c) || isDigit(c) || c == tokens.Exclamation || c == tokens.Hash || c == tokens.Dollar || c == tokens.Percent ||
			c == tokens.Ampersand || c == tokens.SingleQuote || c == tokens.Asterisk || c == tokens.Plus || c == tokens.Dash || c == tokens.Period ||
			c == tokens.Caret || c == tokens.Underscore || c == tokens.Backtick || c == tokens.Pipe || c == tokens.Tilde || c == tokens.Colon || c == tokens.Slash {
			sb.WriteByte(c)
			p.advance()
		} else {
			break
		}
	}

	if sb.Len() == 0 {
		return nil, fmt.Errorf("sfv: empty token")
	}
	return NewToken().SetValue(sb.String()), nil
}

// parseByteSequence parses a byte sequence according to RFC 9651 Section 4.2.7
func (p *parseContext) parseByteSequence() (*ByteSequence, error) {
	if p.current() != tokens.Colon {
		return nil, fmt.Errorf("sfv: expected colon at start of byte sequence")
	}
	p.advance() // consume opening colon

	var sb strings.Builder
	foundClosingColon := false
	for !p.eof() {
		c := p.current()
		if c == tokens.Colon {
			p.advance() // consume closing colon
			foundClosingColon = true
			break
		}
		// Valid base64 characters
		if isAlpha(c) || isDigit(c) || c == tokens.Plus || c == tokens.Slash || c == tokens.Equals {
			sb.WriteByte(c)
			p.advance()
		} else {
			return nil, fmt.Errorf("sfv: invalid character in byte sequence: %c", c)
		}
	}

	if !foundClosingColon {
		return nil, fmt.Errorf("sfv: expected closing colon in byte sequence")
	}

	// Decode base64
	decoded, err := base64.StdEncoding.DecodeString(sb.String())
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to decode base64: %w", err)
	}
	return NewByteSequence().SetValue(decoded), nil
}

// parseBoolean parses a boolean according to RFC 9651 Section 4.2.8
func (p *parseContext) parseBoolean() (*Boolean, error) {
	if p.current() != tokens.QuestionMark {
		return nil, fmt.Errorf("sfv: expected question mark at start of boolean")
	}
	p.advance() // consume question mark

	if p.eof() {
		return nil, fmt.Errorf("sfv: unexpected end of input, expected boolean value")
	}

	c := p.current()
	p.advance()

	switch c {
	case tokens.One:
		return &Boolean{value: true}, nil
	case tokens.Zero:
		return &Boolean{value: false}, nil
	default:
		return nil, fmt.Errorf("sfv: invalid boolean value, expected '0' or '1', got %c", c)
	}
}

// parseDate parses a date according to RFC 9651 Section 4.2.9
func (p *parseContext) parseDate() (*Date, error) {
	if p.current() != tokens.AtMark {
		return nil, fmt.Errorf("sfv: expected @ at start of date")
	}
	p.advance() // consume @ mark

	// Parse the integer value
	value, err := p.parseDecimal()
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to parse date integer: %w", err)
	}

	// Date must be an integer, not a decimal
	if value.Type() != IntegerType {
		return nil, fmt.Errorf("sfv: date must be an integer")
	}

	var intValue int64
	if err := value.Value(&intValue); err != nil {
		return nil, fmt.Errorf("sfv: failed to convert date value to int64: %w", err)
	}

	return NewDate().SetValue(intValue), nil
}

// parseDisplayString parses a display string according to RFC 9651 Section 4.2.10
func (p *parseContext) parseDisplayString() (*DisplayString, error) {
	// Expect %"
	if p.current() != tokens.Percent {
		return nil, fmt.Errorf("sfv: expected %% at start of display string")
	}
	p.advance()

	if p.eof() || p.current() != tokens.DoubleQuote {
		return nil, fmt.Errorf("sfv: expected quote after %% in display string")
	}
	p.advance() // consume quote

	var byteArray []byte
	for !p.eof() {
		c := p.current()
		p.advance()

		if c <= 0x1f || c >= 0x7f {
			return nil, fmt.Errorf("sfv: invalid character in display string: %c", c)
		}

		if c == tokens.Percent {
			// Percent-encoded byte
			if p.eof() {
				return nil, fmt.Errorf("sfv: unexpected end after %% in display string")
			}
			hex1 := p.current()
			p.advance()
			if p.eof() {
				return nil, fmt.Errorf("sfv: incomplete hex sequence in display string")
			}
			hex2 := p.current()
			p.advance()

			// Decode hex - ParseUint will validate the hex characters for us
			hexStr := string([]byte{hex1, hex2})
			val, err := strconv.ParseUint(hexStr, 16, 8)
			if err != nil {
				return nil, fmt.Errorf("sfv: invalid hex sequence %%%c%c in display string: %w", hex1, hex2, err)
			}
			byteArray = append(byteArray, byte(val))
		} else if c == tokens.DoubleQuote {
			// End of display string
			// Decode as UTF-8
			return NewDisplayString().SetValue(string(byteArray)), nil
		} else {
			// Regular ASCII character
			byteArray = append(byteArray, c)
		}
	}
	return nil, fmt.Errorf("sfv: unexpected end of input, expected closing quote in display string")
}
