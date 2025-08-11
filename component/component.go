package component

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/sfv"
)

var (
	derivedMethod     = New("@method")
	derivedQueryParam = New("@query-param")
	derivedAuthority  = New("@authority")
	derivedTargetURI  = New("@target-uri")
	derivedStatus     = New("@status")
)

func Method() Identifier {
	return derivedMethod
}

func QueryParam() Identifier {
	return derivedQueryParam
}

func TargetURI() Identifier {
	return derivedTargetURI
}

func Authority() Identifier {
	return derivedAuthority
}

func Status() Identifier {
	return derivedStatus
}

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
	return blackmagic.AssignIfCompatible(dst, c.parameters[key])
}

func (c *Identifier) SFV() (sfv.Item, error) {
	// Create a new SFV item with the component name
	item := sfv.String(c.name)

	// Add parameters to the item
	for k, v := range c.parameters {
		if err := item.Parameter(k, v); err != nil {
			return nil, fmt.Errorf("failed to add parameter %q: %w", k, err)
		}
	}

	return item, nil
}

// String returns the RFC 9421 string representation of the component identifier
func (c *Identifier) MarshalSFV() ([]byte, error) {
	sfvc, err := c.SFV()
	if err != nil {
		return nil, fmt.Errorf("failed to create SFV item: %w", err)
	}

	var buf bytes.Buffer
	enc := sfv.NewEncoder(&buf)
	enc.SetParameterSpacing("")
	if err := enc.Encode(sfvc); err != nil {
		return nil, fmt.Errorf("failed to encode SFV: %w", err)
	}
	return buf.Bytes(), nil
}

func Parse(input []byte) (Identifier, error) {
	// Use the SFV parser to parse the input
	item, err := sfv.ParseItem(input)
	if err != nil {
		return Identifier{}, fmt.Errorf("failed to parse SFV input: %w", err)
	}

	return FromItem(item)
}

func FromItem(item sfv.Item) (Identifier, error) {
	// Convert the parsed item to an Identifier
	var name string
	if err := item.GetValue(&name); err != nil {
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
		var val any
		if err := value.GetValue(&val); err != nil {
			return Identifier{}, fmt.Errorf("failed to convert parameter %q value: %w", pname, err)
		}
		id.parameters[pname] = val
	}

	return id, nil
}
