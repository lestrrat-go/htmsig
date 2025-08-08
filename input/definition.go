package input

import (
	"bytes"
	"fmt"
	"time"

	"github.com/lestrrat-go/blackmagic"
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
	params map[string]any
}

// DefinitionBuilder helps build Definition objects
type DefinitionBuilder struct {
	def *Definition
}

// NewDefinitionBuilder creates a new DefinitionBuilder
func NewDefinitionBuilder() *DefinitionBuilder {
	return &DefinitionBuilder{
		def: &Definition{
			params: make(map[string]any),
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
	b.def.params[key] = value
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
func (d *Definition) GetParameter(key string, dst any) error {
	v, ok := d.params[key]
	if !ok {
		return fmt.Errorf("parameter %q not found", key)
	}

	return blackmagic.AssignIfCompatible(dst, v)
}

func (d *Definition) Parameters() []string {
	keys := make([]string, 0, len(d.params))
	for key := range d.params {
		keys = append(keys, key)
	}
	return keys
}

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
	params := sfv.NewParameters()

	// Add standard parameters
	if d.created != nil {
		created, err := sfv.Integer().Value(*d.created).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create created parameter: %w", err)
		}
		params.Set("created", created)
	}

	if d.expires != nil {
		expires, err := sfv.Integer().Value(*d.expires).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create expires parameter: %w", err)
		}
		params.Set("expires", expires)
	}

	if d.keyid != "" {
		kid, err := sfv.String().Value(d.keyid).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create keyid parameter: %w", err)
		}
		params.Set("keyid", kid)
	}

	if d.algorithm != "" {
		alg, err := sfv.String().Value(d.algorithm).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create algorithm parameter: %w", err)
		}
		params.Set("alg", alg)
	}

	if d.nonce != nil {
		nonce, err := sfv.String().Value(*d.nonce).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create nonce parameter: %w", err)
		}
		params.Set("nonce", nonce)
	}

	if d.tag != nil {
		tag, err := sfv.String().Value(*d.tag).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create tag parameter: %w", err)
		}
		params.Set("tag", tag)
	}

	// Add additional parameters
	if len(d.params) > 0 {
		for key, value := range d.params {
			bi, err := sfv.BareItemFrom(value)
			if err != nil {
				return nil, fmt.Errorf("failed to convert parameter %q: %w", key, err)
			}
			params.Set(key, bi)

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
	if len(params.Keys()) > 0 {
		paramBytes, err := params.MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal parameters: %w", err)
		}
		buf.Write(paramBytes)
	}

	return buf.Bytes(), nil
}
