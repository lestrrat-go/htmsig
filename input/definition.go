package input

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lestrrat-go/htmsig/internal/sfv"
)

// Definition represents a single signature definition within a Value.
// A Definition must contain:
//   - a label (the signature label)
//   - a list of components (the signature components)
//     this list needs to have at least one member at the time of signing
//   - a key ID (the identifier for the key material used to sign)
//   - an algorithm (the algorithm used to sign)
//
// Everything else is optional, but can be used to provide additional
// information about the signature.
type Definition struct {
	// Required fields
	label      string   // Signature label
	components []string // List of covered components
	keyid      string   // Key identifier
	algorithm  string   // Signature algorithm

	// Optional signature parameters from RFC 9421 Section 2.3
	created *int64  // Creation time as UNIX timestamp
	expires *int64  // Expiration time as UNIX timestamp
	nonce   *string // Random unique value
	tag     *string // Application-specific tag

	// Additional parameters.
	additionalParams *sfv.Parameters
}

// DefinitionBuilder helps build Definition objects
type DefinitionBuilder struct {
	def *Definition
}

// NewDefinitionBuilder creates a new DefinitionBuilder
func NewDefinitionBuilder() *DefinitionBuilder {
	return &DefinitionBuilder{
		def: &Definition{
			additionalParams: &sfv.Parameters{Values: make(map[string]sfv.BareItem)},
		},
	}
}

// Label sets the signature label
func (b *DefinitionBuilder) Label(label string) *DefinitionBuilder {
	b.def.label = label
	return b
}

// Components sets the covered components
func (b *DefinitionBuilder) Components(components ...string) *DefinitionBuilder {
	b.def.components = components
	return b
}

// KeyID sets the key identifier
func (b *DefinitionBuilder) KeyID(keyid string) *DefinitionBuilder {
	b.def.keyid = keyid
	return b
}

// Algorithm sets the signature algorithm
func (b *DefinitionBuilder) Algorithm(algorithm string) *DefinitionBuilder {
	b.def.algorithm = algorithm
	return b
}

// Created sets the created timestamp
func (b *DefinitionBuilder) Created(timestamp int64) *DefinitionBuilder {
	b.def.created = &timestamp
	return b
}

// CreatedTime sets the created timestamp from a time.Time
func (b *DefinitionBuilder) CreatedTime(t time.Time) *DefinitionBuilder {
	timestamp := t.Unix()
	b.def.created = &timestamp
	return b
}

// Expires sets the expires timestamp
func (b *DefinitionBuilder) Expires(timestamp int64) *DefinitionBuilder {
	b.def.expires = &timestamp
	return b
}

// ExpiresTime sets the expires timestamp from a time.Time
func (b *DefinitionBuilder) ExpiresTime(t time.Time) *DefinitionBuilder {
	timestamp := t.Unix()
	b.def.expires = &timestamp
	return b
}

// Nonce sets the nonce parameter
func (b *DefinitionBuilder) Nonce(nonce string) *DefinitionBuilder {
	b.def.nonce = &nonce
	return b
}

// Tag sets the application-specific tag
func (b *DefinitionBuilder) Tag(tag string) *DefinitionBuilder {
	b.def.tag = &tag
	return b
}

// Parameter sets an additional parameter
func (b *DefinitionBuilder) Parameter(key string, value any) *DefinitionBuilder {
	if b.def.additionalParams == nil {
		b.def.additionalParams = &sfv.Parameters{Values: make(map[string]sfv.BareItem)}
	}
	
	// Convert any value to sfv.BareItem
	var bareItem sfv.BareItem
	var err error
	switch v := value.(type) {
	case sfv.BareItem:
		bareItem = v
	case sfv.Item:
		bareItem = v // Item implements BareItem interface
	case bool:
		if v {
			bareItem = sfv.True()
		} else {
			bareItem = sfv.False()
		}
	case int:
		bareItem, err = sfv.Integer().Value(int64(v)).Build()
		if err != nil {
			return b // silently fail for now
		}
	case int64:
		bareItem, err = sfv.Integer().Value(v).Build()
		if err != nil {
			return b
		}
	case float64:
		bareItem, err = sfv.Decimal().Value(v).Build()
		if err != nil {
			return b
		}
	case string:
		bareItem, err = sfv.String().Value(v).Build()
		if err != nil {
			return b
		}
	case []byte:
		bareItem, err = sfv.ByteSequence().Value(v).Build()
		if err != nil {
			return b
		}
	default:
		// Default to string conversion
		bareItem, err = sfv.String().Value(fmt.Sprintf("%v", v)).Build()
		if err != nil {
			return b
		}
	}
	
	b.def.additionalParams.Values[key] = bareItem
	return b
}

// Build creates the Definition with validation
func (b *DefinitionBuilder) Build() (*Definition, error) {
	// Validate required fields
	if b.def.label == "" {
		return nil, fmt.Errorf("label is required")
	}
	if len(b.def.components) == 0 {
		return nil, fmt.Errorf("at least one component is required")
	}
	if b.def.keyid == "" {
		return nil, fmt.Errorf("keyid is required")
	}
	// Note: algorithm is optional per RFC 9421 Section 3.2 step 6.2-6.4
	// It can be determined from key material, configuration, or the alg parameter

	return b.def, nil
}

// MustBuild creates the Definition and panics if validation fails
func (b *DefinitionBuilder) MustBuild() *Definition {
	def, err := b.Build()
	if err != nil {
		panic(err)
	}
	return def
}


// Label returns the signature label
func (d *Definition) Label() string {
	return d.label
}

// SetLabel sets the signature label
func (d *Definition) SetLabel(label string) *Definition {
	d.label = label
	return d
}

// Components returns the list of covered components
func (d *Definition) Components() []string {
	return d.components
}

// SetComponents sets the list of covered components
func (d *Definition) SetComponents(components []string) *Definition {
	d.components = components
	return d
}

// KeyID returns the key identifier
func (d *Definition) KeyID() string {
	return d.keyid
}

// SetKeyID sets the key identifier
func (d *Definition) SetKeyID(keyid string) *Definition {
	d.keyid = keyid
	return d
}

// Algorithm returns the signature algorithm
func (d *Definition) Algorithm() string {
	return d.algorithm
}

// SetAlgorithm sets the signature algorithm
func (d *Definition) SetAlgorithm(algorithm string) *Definition {
	d.algorithm = algorithm
	return d
}

// Created returns the created timestamp
func (d *Definition) Created() (int64, bool) {
	if d.created == nil {
		return 0, false
	}
	return *d.created, true
}

// SetCreated sets the created timestamp
func (d *Definition) SetCreated(timestamp int64) *Definition {
	d.created = &timestamp
	return d
}

// Expires returns the expires timestamp
func (d *Definition) Expires() (int64, bool) {
	if d.expires == nil {
		return 0, false
	}
	return *d.expires, true
}

// SetExpires sets the expires timestamp
func (d *Definition) SetExpires(timestamp int64) *Definition {
	d.expires = &timestamp
	return d
}

// Nonce returns the nonce parameter
func (d *Definition) Nonce() (string, bool) {
	if d.nonce == nil {
		return "", false
	}
	return *d.nonce, true
}

// SetNonce sets the nonce parameter
func (d *Definition) SetNonce(nonce string) *Definition {
	d.nonce = &nonce
	return d
}

// Tag returns the application-specific tag
func (d *Definition) Tag() (string, bool) {
	if d.tag == nil {
		return "", false
	}
	return *d.tag, true
}

// SetTag sets the application-specific tag
func (d *Definition) SetTag(tag string) *Definition {
	d.tag = &tag
	return d
}

// Parameter returns an additional parameter
func (d *Definition) Parameter(key string) any {
	if d.additionalParams == nil || d.additionalParams.Values == nil {
		return nil
	}
	item, exists := d.additionalParams.Values[key]
	if !exists {
		return nil
	}
	
	// Convert sfv.Item back to Go value
	switch item.Type() {
	case sfv.BooleanType:
		var b bool
		if err := item.Value(&b); err == nil {
			return b
		}
	case sfv.IntegerType:
		var i int64
		if err := item.Value(&i); err == nil {
			return i
		}
	case sfv.DecimalType:
		var f float64
		if err := item.Value(&f); err == nil {
			return f
		}
	case sfv.StringType:
		var s string
		if err := item.Value(&s); err == nil {
			return s
		}
	case sfv.TokenType:
		var s string
		if err := item.Value(&s); err == nil {
			return s
		}
	case sfv.ByteSequenceType:
		var b []byte
		if err := item.Value(&b); err == nil {
			return b
		}
	case sfv.DateType:
		var i int64
		if err := item.Value(&i); err == nil {
			return i
		}
	case sfv.DisplayStringType:
		var s string
		if err := item.Value(&s); err == nil {
			return s
		}
	}
	
	// Return the item itself if conversion fails
	return item
}

// SetParameter sets an additional parameter
func (d *Definition) SetParameter(key string, value any) *Definition {
	if d.additionalParams == nil {
		d.additionalParams = &sfv.Parameters{Values: make(map[string]sfv.BareItem)}
	}
	
	// Convert any value to sfv.BareItem
	var bareItem sfv.BareItem
	var err error
	switch v := value.(type) {
	case sfv.BareItem:
		bareItem = v
	case sfv.Item:
		bareItem = v // Item implements BareItem interface
	case bool:
		if v {
			bareItem = sfv.True()
		} else {
			bareItem = sfv.False()
		}
	case int:
		bareItem, err = sfv.Integer().Value(int64(v)).Build()
		if err != nil {
			return d // silently fail for now
		}
	case int64:
		bareItem, err = sfv.Integer().Value(v).Build()
		if err != nil {
			return d
		}
	case float64:
		bareItem, err = sfv.Decimal().Value(v).Build()
		if err != nil {
			return d
		}
	case string:
		bareItem, err = sfv.String().Value(v).Build()
		if err != nil {
			return d
		}
	case []byte:
		bareItem, err = sfv.ByteSequence().Value(v).Build()
		if err != nil {
			return d
		}
	default:
		// Default to string conversion
		bareItem, err = sfv.String().Value(fmt.Sprintf("%v", v)).Build()
		if err != nil {
			return d
		}
	}
	
	d.additionalParams.Values[key] = bareItem
	return d
}

// Parameters returns the additional parameters as *sfv.Parameters
func (d *Definition) Parameters() *sfv.Parameters {
	return d.additionalParams
}

// SetParameters sets the additional parameters directly
func (d *Definition) SetParameters(params *sfv.Parameters) *Definition {
	d.additionalParams = params
	return d
}

// Convenience methods for time.Time

// CreatedTime returns the created timestamp as a time.Time
func (d *Definition) CreatedTime() (time.Time, bool) {
	timestamp, ok := d.Created()
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(timestamp, 0), true
}

// SetCreatedTime sets the created timestamp from a time.Time
func (d *Definition) SetCreatedTime(t time.Time) *Definition {
	return d.SetCreated(t.Unix())
}

// ExpiresTime returns the expires timestamp as a time.Time
func (d *Definition) ExpiresTime() (time.Time, bool) {
	timestamp, ok := d.Expires()
	if !ok {
		return time.Time{}, false
	}
	return time.Unix(timestamp, 0), true
}

// SetExpiresTime sets the expires timestamp from a time.Time
func (d *Definition) SetExpiresTime(t time.Time) *Definition {
	return d.SetExpires(t.Unix())
}

// MarshalSFV implements the sfv.Marshaler interface for Definition
// A Definition marshals to an InnerList with components and parameters
func (d *Definition) MarshalSFV() ([]byte, error) {
	// Create parameters
	params := &sfv.Parameters{Values: make(map[string]sfv.BareItem)}
	
	// Add standard parameters
	if d.created != nil {
		params.Values["created"] = sfv.Integer().Value(*d.created).MustBuild()
	}
	if d.expires != nil {
		params.Values["expires"] = sfv.Integer().Value(*d.expires).MustBuild()
	}
	if d.keyid != "" {
		params.Values["keyid"] = sfv.String().Value(d.keyid).MustBuild()
	}
	if d.algorithm != "" {
		params.Values["alg"] = sfv.String().Value(d.algorithm).MustBuild()
	}
	if d.nonce != nil {
		params.Values["nonce"] = sfv.String().Value(*d.nonce).MustBuild()
	}
	if d.tag != nil {
		params.Values["tag"] = sfv.String().Value(*d.tag).MustBuild()
	}
	
	// Add additional parameters
	if d.additionalParams != nil && d.additionalParams.Values != nil {
		for key, value := range d.additionalParams.Values {
			params.Values[key] = value
		}
	}
	
	// Marshal as InnerList manually
	var buf bytes.Buffer
	buf.WriteByte('(')
	
	for i, component := range d.components {
		if i > 0 {
			buf.WriteByte(' ')
		}
		componentBytes, err := sfv.String().Value(component).MustBuild().MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal component %q: %w", component, err)
		}
		buf.Write(componentBytes)
	}
	
	buf.WriteByte(')')
	
	// Add parameters if any exist
	if len(params.Values) > 0 {
		paramBytes, err := params.MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parameters: %w", err)
		}
		buf.Write(paramBytes)
	}
	
	return buf.Bytes(), nil
}
