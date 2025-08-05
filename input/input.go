package input

import (
	"fmt"
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
	result, err := sfv.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Signature-Input header: %w", err)
	}
	
	// Signature-Input must be a Dictionary
	dict, ok := result.(*sfv.Dictionary)
	if !ok {
		return nil, fmt.Errorf("Signature-Input must be a Dictionary, got %T", result)
	}
	
	// Create Value and extract all signature definitions
	builder := NewValueBuilder()
	
	// Iterate through dictionary keys (signature labels)
	for _, key := range dict.Keys() {
		value, exists := dict.Get(key)
		if !exists {
			continue // Should not happen, but be safe
		}
		
		// Each signature must be an InnerList
		innerList, ok := value.(*sfv.InnerList)
		if !ok {
			return nil, fmt.Errorf("signature %q must be an InnerList, got %T", key, value)
		}
		
		// Extract components from InnerList
		components := make([]string, innerList.Len())
		for i := 0; i < innerList.Len(); i++ {
			item, ok := innerList.Get(i)
			if !ok {
				return nil, fmt.Errorf("failed to get component %d from signature %q", i, key)
			}
			
			var component string
			if err := item.Value(&component); err != nil {
				return nil, fmt.Errorf("failed to extract component %d from signature %q: %w", i, key, err)
			}
			components[i] = component
		}
		
		// Create definition builder with label and components
		defBuilder := NewDefinitionBuilder().
			Label(key).
			Components(components...)
		
		// Extract parameters from InnerList
		params := innerList.Parameters()
		if params != nil {
			// Extract standard parameters
			if created, exists := params.Values["created"]; exists {
				if createdInt, ok := created.(*sfv.Integer); ok {
					var timestamp int64
					if err := createdInt.Value(&timestamp); err == nil {
						defBuilder.Created(timestamp)
					}
				}
			}
			
			if expires, exists := params.Values["expires"]; exists {
				if expiresInt, ok := expires.(*sfv.Integer); ok {
					var timestamp int64
					if err := expiresInt.Value(&timestamp); err == nil {
						defBuilder.Expires(timestamp)
					}
				}
			}
			
			if keyid, exists := params.Values["keyid"]; exists {
				if keyidStr, ok := keyid.(*sfv.String); ok {
					var keyID string
					if err := keyidStr.Value(&keyID); err == nil {
						defBuilder.KeyID(keyID)
					}
				}
			}
			
			if alg, exists := params.Values["alg"]; exists {
				if algStr, ok := alg.(*sfv.String); ok {
					var algorithm string
					if err := algStr.Value(&algorithm); err == nil {
						defBuilder.Algorithm(algorithm)
					}
				}
			}
			
			if nonce, exists := params.Values["nonce"]; exists {
				if nonceStr, ok := nonce.(*sfv.String); ok {
					var nonceVal string
					if err := nonceStr.Value(&nonceVal); err == nil {
						defBuilder.Nonce(nonceVal)
					}
				}
			}
			
			if tag, exists := params.Values["tag"]; exists {
				if tagStr, ok := tag.(*sfv.String); ok {
					var tagVal string
					if err := tagStr.Value(&tagVal); err == nil {
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
		
		// For parsing, we use BuildWithoutValidation to be lenient
		// The validation will happen later when someone tries to use the definition
		def := defBuilder.BuildWithoutValidation()
		
		builder.AddDefinition(def)
	}
	
	return builder.Build()
}