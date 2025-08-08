package component

import (
	"fmt"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/htmsig/internal/sfv"
)

// Identifier represents an HTTP Message Signature component identifier
// with its name and parameters according to RFC 9421
type Identifier struct {
	name       string // Component name (e.g., "@method", "content-type")
	parameters map[string]any
}

// New creates a new Identifier with the given name
func New(name string) Identifier {
	return Identifier{
		name:       name,
		parameters: make(map[string]any),
	}
}

func (c Identifier) Name() string {
	return c.name
}

func (c Identifier) Parameters() []string {
	keys := make([]string, 0, len(c.parameters))
	for k := range c.parameters {
		keys = append(keys, k)
	}
	return keys
}

// WithParameter creates a new component with the parameter addedto the component.
func (c Identifier) WithParameter(key string, value any) Identifier {
	c.parameters[key] = value
	return c
}

// HasParameter checks if the component has a specific parameter
func (c *Identifier) HasParameter(key string) bool {
	_, exists := c.parameters[key]
	return exists
}

// GetParameter gets a parameter value
func (c *Identifier) GetParameter(key string, dst any) error {
	return blackmagic.AssignIfCompatible(c.parameters[key], dst)
}

func (c *Identifier) SFV() (sfv.Item, error) {
	// Create a new SFV item with the component name
	builder := sfv.String().Value(c.name).ToItem()

	// Add parameters to the item
	for k, v := range c.parameters {
		bi, err := sfv.BareItemFrom(v)
		if err != nil {
			return nil, fmt.Errorf("failed to convert parameter %q: %w", k, err)
		}
		builder = builder.Parameter(k, bi)
	}

	return builder.Build()
}

// String returns the RFC 9421 string representation of the component identifier
func (c *Identifier) MarshalSFV() ([]byte, error) {
	// Identifier names are always strings
	s := sfv.String().Value(c.name)
	for k, v := range c.parameters {
		var bi sfv.BareItem
		switch v := v.(type) {
		case bool:
			if v {
				bi = sfv.True()
			} else {
				bi = sfv.False()
			}
		case int64:
			bi = sfv.Integer().Value(v).MustBuild()
		case float64:
			bi = sfv.Decimal().Value(v).MustBuild()
		case string:
			bi = sfv.String().Value(v).MustBuild()
		default:
			return nil, fmt.Errorf("unsupported parameter type %T for key %s", v, k)
		}
		s.Parameter(k, bi)
	}
	sfvc, err := s.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build SFV component: %w", err)
	}

	enc := sfv.NewEncoder()
	enc.SetParameterSpacing("")
	return enc.Encode(sfvc)
}

func Parse(input []byte) (Identifier, error) {
	// Use the SFV parser to parse the input
	item, err := sfv.ParseItem(input)
	if err != nil {
		return Identifier{}, fmt.Errorf("failed to parse SFV input: %w", err)
	}

	// Convert the parsed item to an Identifier
	var name string
	if err := item.Value(&name); err != nil {
		return Identifier{}, fmt.Errorf("failed to get component name: %w", err)
	}
	id := Identifier{
		name:       name,
		parameters: make(map[string]any),
	}

	params := item.Parameters()
	for _, pname := range params.Keys() {
		var value sfv.BareItem
		if err := params.Get(pname, &value); err != nil {
			return Identifier{}, fmt.Errorf("failed to get parameter value for %q: %w", pname, err)
		}
		id.parameters[pname] = value.Value()
	}

	return id, nil
}
