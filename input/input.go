package input

import (
	"fmt"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/internal/sfv"
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
			// Extract standard parameters
			var created sfv.IntegerItem
			if err := params.Get("created", &created); err == nil {
				defBuilder.Created(created.Value())
			}

			if expires, exists := params.Values["expires"]; exists {
				if expires.Type() == sfv.IntegerType {
					var timestamp int64
					if err := expires.GetValue(&timestamp); err == nil {
						defBuilder.Expires(timestamp)
					}
				}
			}

			if keyid, exists := params.Values["keyid"]; exists {
				if keyid.Type() == sfv.StringType {
					var keyID string
					if err := keyid.GetValue(&keyID); err == nil {
						defBuilder.KeyID(keyID)
					}
				}
			}

			if alg, exists := params.Values["alg"]; exists {
				if alg.Type() == sfv.StringType {
					var algorithm string
					if err := alg.GetValue(&algorithm); err == nil {
						defBuilder.Algorithm(algorithm)
					}
				}
			}

			if nonce, exists := params.Values["nonce"]; exists {
				if nonce.Type() == sfv.StringType {
					var nonceVal string
					if err := nonce.GetValue(&nonceVal); err == nil {
						defBuilder.Nonce(nonceVal)
					}
				}
			}

			if tag, exists := params.Values["tag"]; exists {
				if tag.Type() == sfv.StringType {
					var tagVal string
					if err := tag.GetValue(&tagVal); err == nil {
						defBuilder.Tag(tagVal)
					}
				}
			}

			// Handle additional parameters
			for paramKey, paramValue := range params.Values {
				switch paramKey {
				case "created", "expires", "keyid", "alg", "nonce", "tag":
					// Already handled above
					continue
				default:
					// Additional parameter - store as-is
					defBuilder.Parameter(paramKey, paramValue)
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

	return dict.MarshalSFV()
}
