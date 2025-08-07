package htmsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/lestrrat-go/htmsig/sigbase"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

// KeyResolver is the interface for resolving verification keys by key ID
type KeyResolver interface {
	ResolveKey(keyID string) (any, error)
}

type sigreqContext struct {
	req *http.Request
}

// newSigreqContext creates a new signature request context
func newSigreqContext(req *http.Request) *sigreqContext {
	return &sigreqContext{
		req: req,
	}
}

// buildSignatureBase creates the signature base for a specific definition
func (ctx *sigreqContext) buildSignatureBase(def *input.Definition) ([]byte, error) {
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

	// Build the complete signature base (including signature-params line)
	base, err := builder.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build signature base: %w", err)
	}

	return base, nil
}

// detectAlgorithmFromKey determines the default algorithm based on key type
func detectAlgorithmFromKey(key any) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey, *rsa.PublicKey:
		// Default to RSA-PSS with SHA-256 for RSA keys
		return "rsa-pss-sha256", nil
	case *ecdsa.PrivateKey:
		// Determine algorithm based on curve
		switch k.Curve.Params().BitSize {
		case 256:
			return "ecdsa-p256-sha256", nil
		case 384:
			return "ecdsa-p384-sha384", nil
		case 521:
			return "ecdsa-p521-sha512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve bit size: %d", k.Curve.Params().BitSize)
		}
	case *ecdsa.PublicKey:
		// Determine algorithm based on curve
		switch k.Curve.Params().BitSize {
		case 256:
			return "ecdsa-p256-sha256", nil
		case 384:
			return "ecdsa-p384-sha384", nil
		case 521:
			return "ecdsa-p521-sha512", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve bit size: %d", k.Curve.Params().BitSize)
		}
	case ed25519.PrivateKey, ed25519.PublicKey:
		return "ed25519", nil
	case []byte:
		// Assume HMAC with SHA-256 for byte slices
		return "hmac-sha256", nil
	default:
		return "", fmt.Errorf("unable to detect algorithm from key type %T", key)
	}
}

// SignRequest signs the given HTTP request using the provided Signature-Input definition and key.
func SignRequest(req *http.Request, def *input.Value, key any) error {
	definitions := def.Definitions()
	if len(definitions) == 0 {
		return fmt.Errorf("no signature definitions found")
	}

	// Create context
	srctx := newSigreqContext(req)

	// Collect signatures for the Signature header
	signatures := make(map[string][]byte)

	// Process each signature definition
	for _, definition := range definitions {
		// Build signature base for this definition
		signatureBase, err := srctx.buildSignatureBase(definition)
		if err != nil {
			return fmt.Errorf("failed to build signature base for definition %s: %w", definition.Label(), err)
		}

		// Generate signature based on algorithm
		// Map HTTP Message Signatures algorithm names to JWS algorithm names
		algorithm := definition.Algorithm()
		if algorithm == "" {
			// Try to detect algorithm from key type
			detectedAlg, err := detectAlgorithmFromKey(key)
			if err != nil {
				return fmt.Errorf("signature %q missing algorithm parameter and unable to detect from key: %w", definition.Label(), err)
			}
			algorithm = detectedAlg
		}
		var jwsAlgorithm string
		switch algorithm {
		case "rsa-pss-sha256":
			jwsAlgorithm = "PS256"
		case "rsa-pss-sha384":
			jwsAlgorithm = "PS384"
		case "rsa-pss-sha512":
			jwsAlgorithm = "PS512"
		case "rsa-v1_5-sha256":
			jwsAlgorithm = "RS256"
		case "rsa-v1_5-sha384":
			jwsAlgorithm = "RS384"
		case "rsa-v1_5-sha512":
			jwsAlgorithm = "RS512"
		case "hmac-sha256":
			jwsAlgorithm = "HS256"
		case "hmac-sha384":
			jwsAlgorithm = "HS384"
		case "hmac-sha512":
			jwsAlgorithm = "HS512"
		case "ecdsa-p256-sha256":
			jwsAlgorithm = "ES256"
		case "ecdsa-p384-sha384":
			jwsAlgorithm = "ES384"
		case "ecdsa-p521-sha512":
			jwsAlgorithm = "ES512"
		case "ed25519":
			jwsAlgorithm = "EdDSA"
		default:
			return fmt.Errorf("unsupported HTTP Message Signatures algorithm: %s", algorithm)
		}
		
		signature, sigErr := jwsbb.Sign(key, jwsAlgorithm, signatureBase, nil)
		if sigErr != nil {
			return fmt.Errorf("failed to sign with algorithm %s (JWS: %s): %w", algorithm, jwsAlgorithm, sigErr)
		}
		
		// Store signature for this definition
		signatures[definition.Label()] = signature
	}

	// Marshal signature input and add to headers
	inputBytes, err := sfv.Marshal(def)
	if err != nil {
		return fmt.Errorf("failed to marshal signature input: %w", err)
	}
	req.Header.Set(SignatureInputHeader, string(inputBytes))
	
	// Build and add Signature header
	signatureDict := sfv.NewDictionary()
	
	for label, sig := range signatures {
		// Create a byte sequence item for the signature
		sigItem, err := sfv.ByteSequence().Value(sig).Build()
		if err != nil {
			return fmt.Errorf("failed to create signature item for %s: %w", label, err)
		}
		if err := signatureDict.Set(label, sigItem); err != nil {
			return fmt.Errorf("failed to set signature for %s: %w", label, err)
		}
	}
	
	// Marshal the signature dictionary
	signatureBytes, err := signatureDict.MarshalSFV()
	if err != nil {
		return fmt.Errorf("failed to marshal signature header: %w", err)
	}
	req.Header.Set(SignatureHeader, string(signatureBytes))

	return nil
}

// VerifyRequest verifies the HTTP Message Signatures in the given HTTP request.
func VerifyRequest(req *http.Request, keyResolver KeyResolver) error {
	// Step 1: Parse Signature-Input and Signature headers
	signatureInputHeader := req.Header.Get(SignatureInputHeader)
	if signatureInputHeader == "" {
		return fmt.Errorf("missing %s header", SignatureInputHeader)
	}
	
	signatureHeader := req.Header.Get(SignatureHeader)
	if signatureHeader == "" {
		return fmt.Errorf("missing %s header", SignatureHeader)
	}
	
	// Parse the Signature-Input field
	inputValue, err := input.Parse([]byte(signatureInputHeader))
	if err != nil {
		return fmt.Errorf("failed to parse %s header: %w", SignatureInputHeader, err)
	}
	
	// Parse the Signature field
	signatureDict, err := sfv.Parse([]byte(signatureHeader))
	if err != nil {
		return fmt.Errorf("failed to parse %s header: %w", SignatureHeader, err)
	}
	
	sigDict, ok := signatureDict.(*sfv.Dictionary)
	if !ok {
		return fmt.Errorf("%s header must be a Dictionary, got %T", SignatureHeader, signatureDict)
	}
	
	// Verify each signature
	for _, definition := range inputValue.Definitions() {
		label := definition.Label()
		
		// Step 1.2: Check corresponding signature exists
		sigValue, exists := sigDict.Get(label)
		if !exists {
			return fmt.Errorf("no signature found for label %q", label)
		}
		
		// Extract signature bytes
		var signatureBytes []byte
		if err := sigValue.(sfv.BareItem).Value(&signatureBytes); err != nil {
			return fmt.Errorf("failed to extract signature bytes for label %q: %w", label, err)
		}
		
		// Step 5: Resolve verification key
		keyID := definition.KeyID()
		if keyID == "" {
			return fmt.Errorf("signature %q missing keyid parameter", label)
		}
		
		verificationKey, err := keyResolver.ResolveKey(keyID)
		if err != nil {
			return fmt.Errorf("failed to resolve key %q: %w", keyID, err)
		}
		
		// Step 6: Determine algorithm
		algorithm := definition.Algorithm()
		if algorithm == "" {
			// Try to detect algorithm from key type
			detectedAlg, err := detectAlgorithmFromKey(verificationKey)
			if err != nil {
				return fmt.Errorf("signature %q missing algorithm parameter and unable to detect from key: %w", label, err)
			}
			algorithm = detectedAlg
		}
		
		// Map HTTP Message Signatures algorithm to JWS algorithm
		var jwsAlgorithm string
		switch algorithm {
		case "rsa-pss-sha256":
			jwsAlgorithm = "PS256"
		case "rsa-pss-sha384":
			jwsAlgorithm = "PS384"
		case "rsa-pss-sha512":
			jwsAlgorithm = "PS512"
		case "rsa-v1_5-sha256":
			jwsAlgorithm = "RS256"
		case "rsa-v1_5-sha384":
			jwsAlgorithm = "RS384"
		case "rsa-v1_5-sha512":
			jwsAlgorithm = "RS512"
		case "hmac-sha256":
			jwsAlgorithm = "HS256"
		case "hmac-sha384":
			jwsAlgorithm = "HS384"
		case "hmac-sha512":
			jwsAlgorithm = "HS512"
		case "ecdsa-p256-sha256":
			jwsAlgorithm = "ES256"
		case "ecdsa-p384-sha384":
			jwsAlgorithm = "ES384"
		case "ecdsa-p521-sha512":
			jwsAlgorithm = "ES512"
		case "ed25519":
			jwsAlgorithm = "EdDSA"
		default:
			return fmt.Errorf("unsupported HTTP Message Signatures algorithm: %s", algorithm)
		}
		
		// Step 7: Recreate signature base
		srctx := newSigreqContext(req)
		signatureBase, err := srctx.buildSignatureBase(definition)
		if err != nil {
			return fmt.Errorf("failed to rebuild signature base for %q: %w", label, err)
		}
		
		// Step 8: Verify signature using jwsbb
		if err := jwsbb.Verify(verificationKey, jwsAlgorithm, signatureBase, signatureBytes); err != nil {
			return fmt.Errorf("signature verification failed for %q (algorithm %s, JWS %s): %w", label, algorithm, jwsAlgorithm, err)
		}
	}
	
	return nil
}
