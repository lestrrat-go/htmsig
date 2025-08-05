package sfv

import (
	"fmt"
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
	p.parseInnerList()
	return nil
}

type Parameters struct {
	keys   []string
	values map[string]Value
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
}

func (p *parseContext) parseParameters() (*Parameters, error) {
	return &Parameters{}, nil // TODO: implement parameter parsing
}

func (p *parseContext) parseItem() (Value, error) {
}

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c >= 'Z')
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
		v, err := p.parseDiplayString()
		if err != nil {
			return nil, fmt.Errorf(`sfv: failed to parse bare item (display string): %w`, err)
		}
		return v, nil
	default:
		return nil, fmt.Errorf(`sfv: unrecognized character while parsing bare item: %c`, c)
	}
}

func (p *parseContext) parseDecimal() (any, error) {
	sign := 1

	if c := p.current(); c == tokens.Dash {
		p.advance()
		sign = -1
	}

	if p.eof() {
		return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit`)
	}

	for !p.eof() {
		c := p.current()
		if !isDigit(c) {
			return nil, fmt.Errorf(`sfv: failed to parse numeric value: expected digit`)
		}
	}
}
