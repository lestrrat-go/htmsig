package input

import (
	"bytes"
	"fmt"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/sfv"
)

// Value is a single signature input value (i.e. a single entry in
// the Signature-Input header field). A Value can contain multiple
// signature definitions.
type Value struct {
	definitions []*Definition
}

// ValueBuilder helps build Value objects
type ValueBuilder struct {
	val *Value
}

// NewValueBuilder creates a new ValueBuilder
func NewValueBuilder() *ValueBuilder {
	return &ValueBuilder{
		val: &Value{
			definitions: make([]*Definition, 0),
		},
	}
}

// AddDefinition adds a signature definition
func (b *ValueBuilder) AddDefinition(def *Definition) *ValueBuilder {
	b.val.definitions = append(b.val.definitions, def)
	return b
}

// Build creates the Value with validation
func (b *ValueBuilder) Build() (*Value, error) {
	// Validate that we have at least one definition
	if len(b.val.definitions) == 0 {
		return nil, fmt.Errorf("at least one definition is required")
	}

	return b.val, nil
}

// MustBuild creates the Value and panics if validation fails
func (b *ValueBuilder) MustBuild() *Value {
	val, err := b.Build()
	if err != nil {
		panic(err)
	}
	return val
}

// Definitions returns all signature definitions
func (v *Value) Definitions() []*Definition {
	return v.definitions
}

// AddDefinition adds a signature definition
func (v *Value) AddDefinition(def *Definition) *Value {
	v.definitions = append(v.definitions, def)
	return v
}

// GetDefinition returns a definition by label
func (v *Value) GetDefinition(label string) (*Definition, bool) {
	for _, def := range v.definitions {
		if def.Label() == label {
			return def, true
		}
	}
	return nil, false
}

// Len returns the number of definitions
func (v *Value) Len() int {
	return len(v.definitions)
}

func Parse(data []byte) (*Value, error) {
	// Parse the Signature-Input header field using sfv package
	dict, err := sfv.ParseDictionary(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input header: %w", err)
	}

	// Create Value and extract all signature definitions
	builder := NewValueBuilder()

	// Iterate through dictionary keys (signature labels)
	for _, key := range dict.Keys() {
		var list sfv.InnerList
		if err := dict.GetValue(key, &list); err != nil {
			continue // Should not happen, but be safe
		}

		// Extract components from InnerList
		components := make([]component.Identifier, list.Len())
		for i := 0; i < list.Len(); i++ {
			item, ok := list.Get(i)
			if !ok {
				return nil, fmt.Errorf("failed to get component %d from signature %q", i, key)
			}

			comp, err := component.FromItem(item)
			if err != nil {
				return nil, fmt.Errorf("failed to convert component %d in signature %q: %w", i, key, err)
			}
			components[i] = comp
		}

		// Create definition builder with label and components
		defBuilder := NewDefinitionBuilder().
			Label(key).
			Components(components...)

		// Extract parameters from InnerList
		params := list.Parameters()
		if params != nil {
			// Extract standard parameters using params.Get with correct SFV types
			var created *sfv.IntegerBareItem
			if err := params.Get("created", &created); err == nil {
				defBuilder.Created(created.Value())
			}

			var expires *sfv.IntegerBareItem
			if err := params.Get("expires", &expires); err == nil {
				defBuilder.Expires(expires.Value())
			}

			var keyid *sfv.StringBareItem
			if err := params.Get("keyid", &keyid); err == nil {
				defBuilder.KeyID(keyid.Value())
			}

			var alg *sfv.StringBareItem
			if err := params.Get("alg", &alg); err == nil {
				defBuilder.Algorithm(alg.Value())
			}

			var nonce *sfv.StringBareItem
			if err := params.Get("nonce", &nonce); err == nil {
				defBuilder.Nonce(nonce.Value())
			}

			var tag *sfv.StringBareItem
			if err := params.Get("tag", &tag); err == nil {
				defBuilder.Tag(tag.Value())
			}

			// Handle arbitrary parameters by iterating through all keys
			for _, paramKey := range params.Keys() {
				switch paramKey {
				case "created", "expires", "keyid", "alg", "nonce", "tag":
					// Already handled above
					continue
				default:
					// Arbitrary parameter - get the BareItem and extract its native value
					var paramValue sfv.BareItem
					if err := params.Get(paramKey, &paramValue); err == nil {
						// Extract native Go value based on SFV type
						switch paramValue.Type() {
						case sfv.IntegerType:
							var intVal int64
							if err := paramValue.GetValue(&intVal); err == nil {
								defBuilder.Parameter(paramKey, intVal)
							}
						case sfv.StringType:
							var strVal string
							if err := paramValue.GetValue(&strVal); err == nil {
								defBuilder.Parameter(paramKey, strVal)
							}
						case sfv.BooleanType:
							var boolVal bool
							if err := paramValue.GetValue(&boolVal); err == nil {
								defBuilder.Parameter(paramKey, boolVal)
							}
						case sfv.DecimalType:
							var decVal float64
							if err := paramValue.GetValue(&decVal); err == nil {
								defBuilder.Parameter(paramKey, decVal)
							}
						case sfv.ByteSequenceType:
							var bytesVal []byte
							if err := paramValue.GetValue(&bytesVal); err == nil {
								defBuilder.Parameter(paramKey, bytesVal)
							}
						case sfv.TokenType:
							var tokenVal string
							if err := paramValue.GetValue(&tokenVal); err == nil {
								defBuilder.Parameter(paramKey, tokenVal)
							}
						default:
							// For unknown types, store the BareItem as-is
							defBuilder.Parameter(paramKey, paramValue)
						}
					}
				}
			}
		}

		// Build the definition with proper validation
		def, err := defBuilder.Build()
		if err != nil {
			return nil, fmt.Errorf("invalid signature definition %q: %w", key, err)
		}

		builder.AddDefinition(def)
	}

	return builder.Build()
}

// MarshalSFV implements the sfv.Marshaler interface for Value
// A Value marshals to a Dictionary with signature labels as keys and InnerLists as values
func (v *Value) MarshalSFV() ([]byte, error) {
	// Create a dictionary
	dict := sfv.NewDictionary()

	// Add each definition to the dictionary
	for _, def := range v.definitions {
		// Marshal the definition to get the InnerList bytes
		defBytes, err := def.MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal definition %q: %w", def.Label(), err)
		}

		// Parse the definition bytes as an InnerList
		// Since we know it's an InnerList from our MarshalSFV implementation,
		// we can parse it back
		result, err := sfv.Parse(defBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse marshaled definition %q: %w", def.Label(), err)
		}

		// The parser returns a List, but for single InnerList, we need to extract it
		var innerList *sfv.InnerList
		switch v := result.(type) {
		case *sfv.InnerList:
			innerList = v
		case *sfv.List:
			// Extract the first (and only) element if it's an InnerList
			if v.Len() == 1 {
				if elem, ok := v.Get(0); ok {
					if il, ok := elem.(*sfv.InnerList); ok {
						innerList = il
					}
				}
			}
		}

		if innerList == nil {
			return nil, fmt.Errorf("expected InnerList for definition %q, got %T", def.Label(), result)
		}

		// Set the definition in the dictionary
		if err := dict.Set(def.Label(), innerList); err != nil {
			return nil, fmt.Errorf("failed to set definition %q in dictionary: %w", def.Label(), err)
		}
	}

	// Use custom encoder with no parameter spacing to match RFC 9421 format
	var buf bytes.Buffer
	encoder := sfv.NewEncoder(&buf)
	encoder.SetParameterSpacing("")
	if err := encoder.Encode(dict); err != nil {
		return nil, fmt.Errorf("failed to encode value dictionary with custom spacing: %w", err)
	}
	return buf.Bytes(), nil
}
