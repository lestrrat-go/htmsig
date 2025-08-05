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
	if err := pctx.Do(); err != nil {
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

func (p *parseContext) Do() error {
	list, err := p.parseList()
	if err != nil {
		return err
	}
	p.value = list
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
		if p.current() != ',' {
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

type List struct {
	values []Value
	params *Parameters
}

func (p *parseContext) parseInnerList() (*List, error) {
	p.stripWhitespace()
	if p.current() != tokens.OpenParen {
		return nil, fmt.Errorf(`sfv: parse inner list: expected '%c', got '%c'`, tokens.OpenParen, p.current())
	}

	var list List
	for !p.eof() {
		p.stripWhitespace()
		switch c := p.current(); c {
		case tokens.CloseParen:
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
		default:
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
	}
	// If we reach here, we've reached EOF without finding a closing paren
	return nil, fmt.Errorf("sfv: parse inner list: unexpected end of input, expected closing paren")
}

func (p *parseContext) parseParameters() (*Parameters, error) {
	return &Parameters{}, nil // TODO: implement parameter parsing
}

func (p *parseContext) parseItem() (Value, error) {
	bareItem, err := p.parseBareItem()
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to parse bare item: %w", err)
	}

	params, err := p.parseParameters()
	if err != nil {
		return nil, fmt.Errorf("sfv: failed to parse parameters: %w", err)
	}

	// For now, we'll return a simple structure with the bare item and parameters
	// In a complete implementation, you might want to create a proper Item type
	return map[string]interface{}{
		"value":      bareItem,
		"parameters": params,
	}, nil
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func (p *parseContext) parseBareItem() (any, error) {
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

func (p *parseContext) parseDecimal() (any, error) {
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
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit`)
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
		return v * float64(sign), nil
	}

	if sb.Len() > 15 {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value: too many (%d) digits for integer number`, sb.Len())
	}

	v, err := strconv.Atoi(sb.String())
	if err != nil {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value as integer: %w`, err)
	}
	return v * sign, nil
}

// parseString parses a quoted string according to RFC 9651 Section 4.2.5
func (p *parseContext) parseString() (string, error) {
	if p.current() != tokens.DoubleQuote {
		return "", fmt.Errorf("sfv: expected quote at start of string")
	}
	p.advance() // consume opening quote

	var sb strings.Builder
	for !p.eof() {
		c := p.current()
		p.advance()

		if c == '\\' {
			if p.eof() {
				return "", fmt.Errorf("sfv: unexpected end of input after backslash")
			}
			next := p.current()
			if next != tokens.DoubleQuote && next != '\\' {
				return "", fmt.Errorf("sfv: invalid escape sequence \\%c", next)
			}
			p.advance()
			sb.WriteByte(next)
		} else if c == tokens.DoubleQuote {
			return sb.String(), nil
		} else if c <= 0x1f || c >= 0x7f {
			return "", fmt.Errorf("sfv: invalid character in string: %c", c)
		} else {
			sb.WriteByte(c)
		}
	}
	return "", fmt.Errorf("sfv: unexpected end of input, expected closing quote")
}

// parseToken parses a token according to RFC 9651 Section 4.2.6
func (p *parseContext) parseToken() (string, error) {
	c := p.current()
	if !isAlpha(c) && c != tokens.Asterisk {
		return "", fmt.Errorf("sfv: token must start with alpha or asterisk")
	}

	var sb strings.Builder
	for !p.eof() {
		c := p.current()
		// tchar from RFC 5234 plus : and /
		if isAlpha(c) || isDigit(c) || c == '!' || c == '#' || c == '$' || c == '%' ||
			c == '&' || c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
			c == '^' || c == '_' || c == '`' || c == '|' || c == '~' || c == ':' || c == '/' {
			sb.WriteByte(c)
			p.advance()
		} else {
			break
		}
	}

	if sb.Len() == 0 {
		return "", fmt.Errorf("sfv: empty token")
	}
	return sb.String(), nil
}

// parseByteSequence parses a byte sequence according to RFC 9651 Section 4.2.7
func (p *parseContext) parseByteSequence() ([]byte, error) {
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
		if isAlpha(c) || isDigit(c) || c == '+' || c == '/' || c == '=' {
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
	return decoded, nil
}

// parseBoolean parses a boolean according to RFC 9651 Section 4.2.8
func (p *parseContext) parseBoolean() (bool, error) {
	if p.current() != tokens.QuestionMark {
		return false, fmt.Errorf("sfv: expected question mark at start of boolean")
	}
	p.advance() // consume question mark

	if p.eof() {
		return false, fmt.Errorf("sfv: unexpected end of input, expected boolean value")
	}

	c := p.current()
	p.advance()

	switch c {
	case '1':
		return true, nil
	case '0':
		return false, nil
	default:
		return false, fmt.Errorf("sfv: invalid boolean value, expected '0' or '1', got %c", c)
	}
}

// parseDate parses a date according to RFC 9651 Section 4.2.9
func (p *parseContext) parseDate() (int64, error) {
	if p.current() != tokens.AtMark {
		return 0, fmt.Errorf("sfv: expected @ at start of date")
	}
	p.advance() // consume @ mark

	// Parse the integer value
	value, err := p.parseDecimal()
	if err != nil {
		return 0, fmt.Errorf("sfv: failed to parse date integer: %w", err)
	}

	// Date must be an integer, not a decimal
	intValue, ok := value.(int)
	if !ok {
		return 0, fmt.Errorf("sfv: date must be an integer")
	}

	return int64(intValue), nil
}

// parseDisplayString parses a display string according to RFC 9651 Section 4.2.10
func (p *parseContext) parseDisplayString() (string, error) {
	// Expect %"
	if p.current() != tokens.Percent {
		return "", fmt.Errorf("sfv: expected %% at start of display string")
	}
	p.advance()

	if p.eof() || p.current() != tokens.DoubleQuote {
		return "", fmt.Errorf("sfv: expected quote after %% in display string")
	}
	p.advance() // consume quote

	var byteArray []byte
	for !p.eof() {
		c := p.current()
		p.advance()

		if c <= 0x1f || c >= 0x7f {
			return "", fmt.Errorf("sfv: invalid character in display string: %c", c)
		}

		if c == '%' {
			// Percent-encoded byte
			if p.eof() {
				return "", fmt.Errorf("sfv: unexpected end after %% in display string")
			}
			hex1 := p.current()
			p.advance()
			if p.eof() {
				return "", fmt.Errorf("sfv: incomplete hex sequence in display string")
			}
			hex2 := p.current()
			p.advance()

			// Validate hex characters (0-9, a-f, A-F)
			if !((hex1 >= '0' && hex1 <= '9') || (hex1 >= 'a' && hex1 <= 'f') || (hex1 >= 'A' && hex1 <= 'F')) ||
				!((hex2 >= '0' && hex2 <= '9') || (hex2 >= 'a' && hex2 <= 'f') || (hex2 >= 'A' && hex2 <= 'F')) {
				return "", fmt.Errorf("sfv: invalid hex sequence %%%c%c in display string", hex1, hex2)
			}

			// Decode hex
			hexStr := string([]byte{hex1, hex2})
			val, err := strconv.ParseUint(hexStr, 16, 8)
			if err != nil {
				return "", fmt.Errorf("sfv: failed to parse hex sequence: %w", err)
			}
			byteArray = append(byteArray, byte(val))
		} else if c == tokens.DoubleQuote {
			// End of display string
			// Decode as UTF-8
			return string(byteArray), nil
		} else {
			// Regular ASCII character
			byteArray = append(byteArray, c)
		}
	}
	return "", fmt.Errorf("sfv: unexpected end of input, expected closing quote in display string")
}
