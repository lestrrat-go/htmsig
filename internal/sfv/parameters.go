package sfv

import (
	"bytes"
	"fmt"
)

type Parameters struct {
	keys []string

	// Values are a map of parameters to their values, where values are
	// bare items
	Values map[string]BareItem
}

func NewParameters() *Parameters {
	return &Parameters{
		keys:   make([]string, 0),
		Values: make(map[string]BareItem),
	}
}

func (p *Parameters) Len() int {
	if p == nil {
		return 0
	}
	// Use Values map length if keys slice is empty but Values has data
	if len(p.keys) == 0 && len(p.Values) > 0 {
		return len(p.Values)
	}
	return len(p.keys)
}

func (p *Parameters) Set(key string, value BareItem) error {
	if p == nil {
		return fmt.Errorf("cannot set parameter on nil Parameters")
	}

	if value == nil {
		return fmt.Errorf("value cannot be nil")
	}

	if _, exists := p.Values[key]; !exists {
		p.keys = append(p.keys, key)
	}
	p.Values[key] = value
	return nil
}

func (p *Parameters) MarshalSFV() ([]byte, error) {
	if p == nil || p.Len() == 0 {
		return []byte{}, nil
	}

	var buf bytes.Buffer
	// Ensure keys slice is populated from Values map if needed
	if len(p.keys) == 0 && len(p.Values) > 0 {
		for key := range p.Values {
			p.keys = append(p.keys, key)
		}
	}

	for _, key := range p.keys {
		buf.WriteByte(';')
		buf.WriteByte(' ') // Always add space after semicolon for consistency
		buf.WriteString(key)

		value, exists := p.Values[key]
		if !exists {
			continue
		}

		// Only add '=' if the value is not Boolean true
		if value.Type() == BooleanType {
			var boolVal bool
			if err := value.Value(&boolVal); err != nil {
				return nil, fmt.Errorf("error getting boolean value for parameter %q: %w", key, err)
			}
			if boolVal {
				// Boolean true parameters can be represented as bare keys
				continue
			}
		}

		buf.WriteByte('=')
		marshaledParam, err := value.MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("error marshaling parameter value %q: %w", key, err)
		}
		buf.Write(marshaledParam)
	}

	return buf.Bytes(), nil
}
