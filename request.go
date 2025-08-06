package htmsig

import (
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/lestrrat-go/htmsig/sigbase"
)

type sigreqContext struct {
	req *http.Request
}

// newSigreqContext creates a new signature request context
func newSigreqContext(req *http.Request) *sigreqContext {
	return &sigreqContext{
		req: req,
	}
}

// configureBuilderWithDefinition configures a fresh builder with the given definition
func (ctx *sigreqContext) configureBuilderWithDefinition(def *input.Definition) *sigbase.RequestBuilder {
	// Start with a fresh builder for this definition
	builder := sigbase.Request(ctx.req)
	
	// Configure builder with components
	builder = builder.Components(def.Components()...)
	
	// Configure signature parameters
	if created, ok := def.Created(); ok {
		builder = builder.Created(created)
	}
	if expires, ok := def.Expires(); ok {
		builder = builder.Expires(expires)
	}
	if keyid := def.KeyID(); keyid != "" {
		builder = builder.KeyID(keyid)
	}
	if alg := def.Algorithm(); alg != "" {
		builder = builder.Algorithm(alg)
	}
	if nonce, ok := def.Nonce(); ok {
		builder = builder.Nonce(nonce)
	}
	if tag, ok := def.Tag(); ok {
		builder = builder.Tag(tag)
	}
	
	// Add additional parameters from the definition
	if defParams := def.Parameters(); defParams != nil {
		for key, value := range defParams.Values {
			// Skip standard parameters to avoid duplicates
			switch key {
			case "created", "expires", "keyid", "alg", "nonce", "tag":
				continue
			}
			// Convert SFV value to string for the builder
			var paramValue string
			if err := value.Value(&paramValue); err == nil {
				builder = builder.Parameter(key, paramValue)
			}
		}
	}
	
	return builder
}

// buildSignatureBase creates the signature base for a specific definition
func (ctx *sigreqContext) buildSignatureBase(def *input.Definition) ([]byte, error) {
	// Configure a fresh builder for this definition
	builder := ctx.configureBuilderWithDefinition(def)
	
	// Build the complete signature base (including signature-params line)
	base, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build signature base: %w", err)
	}
	
	return base, nil
}


// SignRequest signs the given HTTP request using the provided Signature-Input definition.
func SignRequest(req *http.Request, def *input.Value) error {
	definitions := def.Definitions()
	if len(definitions) == 0 {
		return fmt.Errorf("no signature definitions found")
	}
	
	// Create context 
	srctx := newSigreqContext(req)
	
	// Process each signature definition
	for _, definition := range definitions {
		// Build signature base for this definition
		signatureBase, err := srctx.buildSignatureBase(definition)
		if err != nil {
			return fmt.Errorf("failed to build signature base for definition %s: %w", definition.Label(), err)
		}
		
		// TODO: Use signatureBase for actual signature generation for this definition
		_ = signatureBase
		
		// TODO: Generate and add the signature to the Signature header
		// For now, we're just building the signature bases
	}

	// Marshal signature input and add to headers
	inputBytes, err := sfv.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal signature input: %w", err)
	}
	req.Header.Set(SignatureInputHeader, string(inputBytes))

	return nil
}