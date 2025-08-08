package htmsig

import (
	"bytes"
	"context"
	"fmt"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/internal/sfv"
)

const (
	SignatureInputHeader = "Signature-Input"
	SignatureHeader      = "Signature"
)

type SignerBuilder struct {
	components []component.Identifier

	// Signature parameters
	created   *int64
	expires   *int64
	keyid     string
	algorithm string
	nonce     *string
	tag       *string
	params    map[string]string
	err       error
}

func NewSignerBuilder() *SignerBuilder {
	return &SignerBuilder{
		components: make([]component.Identifier, 0),
		params:     make(map[string]string),
	}
}

// Components sets the list of components to include in the signature base
func (rb *SignerBuilder) Components(components ...component.Identifier) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.components = components
	return rb
}

// Created sets the created timestamp for signature parameters
func (rb *SignerBuilder) Created(timestamp int64) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.created = &timestamp
	return rb
}

// Expires sets the expires timestamp for signature parameters
func (rb *SignerBuilder) Expires(timestamp int64) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.expires = &timestamp
	return rb
}

// KeyID sets the key identifier for signature parameters
func (rb *SignerBuilder) KeyID(keyid string) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.keyid = keyid
	return rb
}

// Algorithm sets the algorithm for signature parameters
func (rb *SignerBuilder) Algorithm(alg string) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.algorithm = alg
	return rb
}

// Nonce sets the nonce for signature parameters
func (rb *SignerBuilder) Nonce(nonce string) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.nonce = &nonce
	return rb
}

// Tag sets the tag for signature parameters
func (rb *SignerBuilder) Tag(tag string) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	rb.tag = &tag
	return rb
}

// Parameter sets a custom parameter for signature parameters
func (rb *SignerBuilder) Parameter(key, value string) *SignerBuilder {
	if rb.err != nil {
		return rb
	}
	if rb.params == nil {
		rb.params = make(map[string]string)
	}
	rb.params[key] = value
	return rb
}

type ComponentResolver interface {
	Resolve(name string) (string, error)
}

// Build constructs the signature base according to RFC 9421 Section 2.5
func (rb *SignerBuilder) Build() ([]byte, error) {
	if rb.err != nil {
		return nil, rb.err
	}

	if len(rb.components) == 0 {
		return nil, fmt.Errorf("at least one component is required")
	}

	var list sfv.List
	for _, comp := range rb.components {
		sfvcomp, err := comp.SFV()
		if err != nil {
			return nil, fmt.Errorf("failed to convert component %q to SFV: %w", comp.Name(), err)
		}
		list.Add(sfvcomp)
	}

	var output bytes.Buffer
	seenComponents := make(map[string]struct{})

	// Process each covered component
	ctx := context.Background()
	ctx = component.WithMode(ctx, component.ModeRequest)
	ctx = component.WithRequest(ctx, rb.req)
	for _, comp := range rb.components {
		// Check for duplicates
		if _, ok := seenComponents[comp.Name()]; ok {
			return nil, fmt.Errorf("duplicate component identifier: %s", comp.Name())
		}
		seenComponents[comp.Name()] = struct{}{}

		// Get component value
		value, err := component.Resolve(ctx, comp)
		if err != nil {
			return nil, fmt.Errorf("failed to get component value for %q: %w", comp.Name(), err)
		}

		// Append to signature base: "component-name": value
		fmt.Fprintf(&output, "%q: %s\n", comp.Name(), value)
	}

	// Add signature parameters line if we have signature parameters
	if rb.hasSignatureParams() {
		sigParamsLine, err := rb.buildSignatureParamsLine()
		if err != nil {
			return nil, fmt.Errorf("failed to build signature params line: %w", err)
		}
		output.WriteString(sigParamsLine)
		return output.Bytes(), nil
	}

	// Remove trailing newline if no signature params
	result := output.Bytes()
	if len(result) > 0 && result[len(result)-1] == '\n' {
		result = result[:len(result)-1]
	}
	return result, nil
}

// hasSignatureParams checks if signature parameters are set
func (rb *SignerBuilder) hasSignatureParams() bool {
	return rb.created != nil || rb.expires != nil || rb.keyid != "" || rb.algorithm != "" || rb.nonce != nil || rb.tag != nil || len(rb.params) > 0
}

// buildSignatureParamsLine creates the @signature-params line using SFV serialization
func (rb *SignerBuilder) buildSignatureParamsLine() (string, error) {
	// Use the InnerList builder to create the signature params line
	builder := sfv.NewInnerListBuilder()

	// Add each component as a string item to the inner list
	for _, comp := range rb.components {
		sfvitem, err := comp.SFV()
		if err != nil {
			return "", fmt.Errorf("failed to convert component %q to SFV: %w", comp.Name(), err)
		}
		builder.Add(sfvitem)
	}

	// Add standard parameters
	if rb.created != nil {
		createdItem, err := sfv.Integer().Value(*rb.created).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create created parameter: %w", err)
		}
		builder.Parameter("created", createdItem)
	}

	if rb.expires != nil {
		expiresItem, err := sfv.Integer().Value(*rb.expires).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create expires parameter: %w", err)
		}
		builder.Parameter("expires", expiresItem)
	}

	if rb.keyid != "" {
		keyidItem, err := sfv.String().Value(rb.keyid).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create keyid parameter: %w", err)
		}
		builder.Parameter("keyid", keyidItem)
	}

	if rb.algorithm != "" {
		algItem, err := sfv.String().Value(rb.algorithm).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create alg parameter: %w", err)
		}
		builder.Parameter("alg", algItem)
	}

	if rb.nonce != nil {
		nonceItem, err := sfv.String().Value(*rb.nonce).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create nonce parameter: %w", err)
		}
		builder.Parameter("nonce", nonceItem)
	}

	if rb.tag != nil {
		tagItem, err := sfv.String().Value(*rb.tag).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create tag parameter: %w", err)
		}
		builder.Parameter("tag", tagItem)
	}

	// Add additional parameters
	for key, value := range rb.params {
		// Skip standard parameters to avoid duplicates (shouldn't happen but be safe)
		switch key {
		case "created", "expires", "keyid", "alg", "nonce", "tag":
			continue
		}
		stringItem, err := sfv.String().Value(value).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create parameter %q: %w", key, err)
		}
		builder.Parameter(key, stringItem)
	}

	// Build the inner list
	innerList, err := builder.Build()
	if err != nil {
		return "", fmt.Errorf("failed to build signature params inner list: %w", err)
	}

	// Marshal the inner list using HTTP Message Signature formatting (no spaces after semicolons)
	encoder := sfv.NewEncoder()
	encoder.SetParameterSpacing("") // HTTP Message Signature format
	innerListBytes, err := encoder.Encode(innerList)
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature params inner list: %w", err)
	}

	// Build the final line: "@signature-params": (components);params
	return fmt.Sprintf("\"@signature-params\": %s", string(innerListBytes)), nil
}
