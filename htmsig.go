package htmsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/htmsig/internal/sfv"
	"github.com/lestrrat-go/jwx/v3/jws/jwsbb"
)

const (
	SignatureInputHeader = "Signature-Input"
	SignatureHeader      = "Signature"
)

// KeyResolver interface allows resolving cryptographic keys by their ID
type KeyResolver interface {
	ResolveKey(keyID string) (any, error)
}

func Sign(ctx context.Context, target any, inputValue *input.Value, key any) error {
	var hdr http.Header

	switch t := target.(type) {
	case *http.Request:
		ctx = component.WithMode(ctx, component.ModeRequest)
		ctx = component.WithRequest(ctx, t)
		hdr = t.Header
	case *http.Response:
		ctx = component.WithMode(ctx, component.ModeResponse)
		ctx = component.WithResponse(ctx, t)
		if t.Request != nil {
			ctx = component.WithRequest(ctx, t.Request)
		}
		hdr = t.Header
	default:
		return fmt.Errorf("unsupported target type %T", target)
	}

	dict := sfv.NewDictionary()
	for _, def := range inputValue.Definitions() {
		sigbase, err := buildSignatureBase(ctx, def)
		if err != nil {
			return fmt.Errorf("failed to build signature base: %w", err)
		}

		signature, err := generateSignature(ctx, sigbase, def, key)
		if err != nil {
			return fmt.Errorf("failed to generate signature: %w", err)
		}

		sfvsig, err := sfv.ByteSequence().Value(signature).Build()
		if err != nil {
			return fmt.Errorf("failed to build SFV byte sequence: %w", err)
		}

		dict.Set(def.Label(), sfvsig)
	}

	var sib strings.Builder
	if err := sfv.NewEncoder(&sib).Encode(inputValue); err != nil {
		return fmt.Errorf("failed to encode SFV input: %w", err)
	}
	hdr.Set(SignatureInputHeader, sib.String())

	var sb strings.Builder
	if err := sfv.NewEncoder(&sb).Encode(dict); err != nil {
		return fmt.Errorf("failed to encode SFV signature dictionary: %w", err)
	}
	hdr.Set(SignatureHeader, sb.String())

	return nil
}

// buildSignatureBase creates the signature base according to RFC 9421 Section 2.5
func buildSignatureBase(ctx context.Context, def *input.Definition) ([]byte, error) {
	var output strings.Builder
	seenComponents := make(map[string]struct{})

	// Process each covered component
	for _, comp := range def.Components() {
		// Check for duplicates (RFC 9421 Section 2.5, step 2.1)
		// Components with different parameters should be considered different
		sfvBytes, err := comp.MarshalSFV()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal component %q: %w", comp.Name(), err)
		}
		compKey := string(sfvBytes)
		if _, seen := seenComponents[compKey]; seen {
			return nil, fmt.Errorf("duplicate component identifier: %s", compKey)
		}
		seenComponents[compKey] = struct{}{}

		// Append component identifier (RFC 9421 Section 2.5, step 2.2)
		// Component names are serialized as quoted strings with parameters
		// (sfvBytes already computed above)

		// Append colon and space (RFC 9421 Section 2.5, steps 2.3, 2.4)
		output.Write(sfvBytes)
		output.WriteString(": ")

		// Determine and append component value (RFC 9421 Section 2.5, step 2.5)
		value, err := component.Resolve(ctx, comp)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve component %q: %w", comp.Name(), err)
		}

		// Append the component value (RFC 9421 Section 2.5, step 2.6)
		output.WriteString(value)

		// Append newline (RFC 9421 Section 2.5, step 2.7)
		output.WriteByte('\n')
	}

	// Append signature parameters line (RFC 9421 Section 2.5, step 3)
	// This is the "@signature-params" line that includes the covered components and parameters
	output.WriteString("\"@signature-params\": ")

	// Build the inner list containing the components and their parameters
	innerList := sfv.NewInnerListBuilder()
	for _, comp := range def.Components() {
		sfvComp, err := comp.SFV()
		if err != nil {
			return nil, fmt.Errorf("failed to convert component %q to SFV: %w", comp.Name(), err)
		}
		innerList.Add(sfvComp)
	}

	// Add signature parameters (created, expires, keyid, alg, nonce, tag, etc.)
	if created, ok := def.Created(); ok {
		createdItem, err := sfv.Integer().Value(created).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'created' parameter: %w", err)
		}
		innerList.Parameter("created", createdItem)
	}

	if expires, ok := def.Expires(); ok {
		expiresItem, err := sfv.Integer().Value(expires).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'expires' parameter: %w", err)
		}
		innerList.Parameter("expires", expiresItem)
	}

	if def.KeyID() != "" {
		keyidItem, err := sfv.String().Value(def.KeyID()).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'keyid' parameter: %w", err)
		}
		innerList.Parameter("keyid", keyidItem)
	}

	if def.Algorithm() != "" {
		algItem, err := sfv.String().Value(def.Algorithm()).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'alg' parameter: %w", err)
		}
		innerList.Parameter("alg", algItem)
	}

	if nonce, ok := def.Nonce(); ok {
		nonceItem, err := sfv.String().Value(nonce).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'nonce' parameter: %w", err)
		}
		innerList.Parameter("nonce", nonceItem)
	}

	if tag, ok := def.Tag(); ok {
		tagItem, err := sfv.String().Value(tag).Build()
		if err != nil {
			return nil, fmt.Errorf("failed to create 'tag' parameter: %w", err)
		}
		innerList.Parameter("tag", tagItem)
	}

	// Build the inner list
	builtInnerList, err := innerList.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build inner list: %w", err)
	}

	// Encode the inner list with no parameter spacing (HTTP Message Signature format)
	encoder := sfv.NewEncoder(&output)
	encoder.SetParameterSpacing("")
	encoder.Encode(builtInnerList)

	// Check for non-ASCII characters (RFC 9421 Section 2.5, step 4)
	result := output.String()
	for _, r := range result {
		if r > 127 {
			return nil, fmt.Errorf("signature base contains non-ASCII character: %c", r)
		}
	}

	// Return the signature base as bytes (RFC 9421 Section 2.5, step 5)
	return []byte(result), nil
}

// generateSignature creates a signature over the signature base using the provided key material
// This implements the HTTP_SIGN primitive function from RFC 9421 Section 3.3
// Uses JWX's jwsbb (JWS Bare Bones) for cryptographic signing operations
func generateSignature(ctx context.Context, sigbase []byte, def *input.Definition, key any) ([]byte, error) {
	// Determine the appropriate JWS algorithm, preferring explicit algorithm from Definition
	algorithm, err := determineJWSAlgorithm(def, key)
	if err != nil {
		return nil, fmt.Errorf("failed to determine JWS algorithm: %w", err)
	}

	// Use JWX's jwsbb to sign the signature base directly
	// RFC 9421 Section 3.3.7: "the HTTP message's signature base is used as the entire JWS Signing Input"
	// "The JOSE Header is not used, and the signature base is not first encoded in Base64"
	signature, err := jwsbb.Sign(key, algorithm, sigbase, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with algorithm %s: %w", algorithm, err)
	}

	return signature, nil
}

// determineJWSAlgorithm determines the appropriate JWS algorithm from Definition and key material
// First checks the explicit algorithm parameter in Definition, then falls back to key type detection
func determineJWSAlgorithm(def *input.Definition, key any) (string, error) {
	// First, check if algorithm is explicitly specified in the Definition
	if algorithm := def.Algorithm(); algorithm != "" {
		// Convert RFC 9421 algorithm names to JWS algorithm names
		return convertRFC9421ToJWS(algorithm)
	}

	// Fallback to determining algorithm from key material
	return determineJWSAlgorithmFromKey(key)
}

// convertRFC9421ToJWS converts RFC 9421 algorithm names to JWS algorithm identifiers
// Maps the official RFC 9421 algorithm registry entries to their corresponding JWS algorithm names
func convertRFC9421ToJWS(rfc9421Alg string) (string, error) {
	switch rfc9421Alg {
	// Official RFC 9421 algorithms from Section 6.2.2 Initial Contents
	case "rsa-pss-sha512": // Section 3.3.1
		return "PS512", nil
	case "rsa-v1_5-sha256": // Section 3.3.2
		return "RS256", nil
	case "hmac-sha256": // Section 3.3.3
		return "HS256", nil
	case "ecdsa-p256-sha256": // Section 3.3.4
		return "ES256", nil
	case "ecdsa-p384-sha384": // Section 3.3.5
		return "ES384", nil
	case "ed25519": // Section 3.3.6
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported RFC 9421 algorithm: %s", rfc9421Alg)
	}
}

// determineJWSAlgorithmFromKey determines the appropriate JWS algorithm from key material
// Maps key types to JWS algorithm identifiers for use with jwsbb
func determineJWSAlgorithmFromKey(key any) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		// Use PS512 (RSA-PSS with SHA-512) as per RFC 9421 Section 3.3.1
		return "PS512", nil
	case *rsa.PublicKey:
		// Use PS512 (RSA-PSS with SHA-512) for public key verification
		return "PS512", nil
	case *ecdsa.PrivateKey:
		// Determine curve and select appropriate ECDSA algorithm
		switch k.Curve.Params().Name {
		case "P-256":
			// ES256 (ECDSA using P-256 and SHA-256) as per RFC 9421 Section 3.3.4
			return "ES256", nil
		case "P-384":
			// ES384 (ECDSA using P-384 and SHA-384) as per RFC 9421 Section 3.3.5
			return "ES384", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case *ecdsa.PublicKey:
		// Determine curve and select appropriate ECDSA algorithm for public key
		switch k.Curve.Params().Name {
		case "P-256":
			return "ES256", nil
		case "P-384":
			return "ES384", nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		// EdDSA using Ed25519 as per RFC 9421 Section 3.3.6
		return "EdDSA", nil
	case ed25519.PublicKey:
		// EdDSA using Ed25519 for public key verification
		return "EdDSA", nil
	case []byte:
		// HS256 (HMAC using SHA-256) for raw byte keys as per RFC 9421 Section 3.3.3
		return "HS256", nil
	case string:
		// HS256 (HMAC using SHA-256) for string keys as per RFC 9421 Section 3.3.3
		return "HS256", nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// Verify verifies HTTP message signatures according to RFC 9421 Section 3.2
// keyOrResolver can be either:
//   - A raw cryptographic key (e.g., rsa.PublicKey, ed25519.PublicKey, etc.)
//   - A KeyResolver that can resolve keys by their ID from signature parameters
func Verify(ctx context.Context, target any, keyOrResolver any) error {
	var hdr http.Header

	// Set up context and extract headers based on target type
	switch t := target.(type) {
	case *http.Request:
		ctx = component.WithMode(ctx, component.ModeRequest)
		ctx = component.WithRequest(ctx, t)
		hdr = t.Header
	case *http.Response:
		ctx = component.WithMode(ctx, component.ModeResponse)
		ctx = component.WithResponse(ctx, t)
		if t.Request != nil {
			ctx = component.WithRequest(ctx, t.Request)
		}
		hdr = t.Header
	default:
		return fmt.Errorf("unsupported target type %T", target)
	}

	// Step 1: Parse Signature and Signature-Input fields (RFC 9421 Section 3.2, step 1)
	signatureInputHeader := hdr.Get(SignatureInputHeader)
	if signatureInputHeader == "" {
		return fmt.Errorf("missing %s header", SignatureInputHeader)
	}

	signatureHeader := hdr.Get(SignatureHeader)
	if signatureHeader == "" {
		return fmt.Errorf("missing %s header", SignatureHeader)
	}

	// Parse the Signature-Input header using the input package
	inputValue, err := input.Parse([]byte(signatureInputHeader))
	if err != nil {
		return fmt.Errorf("failed to parse %s header: %w", SignatureInputHeader, err)
	}

	// Parse the Signature field to get signature values
	parsedSignature, err := sfv.ParseDictionary([]byte(signatureHeader))
	if err != nil {
		return fmt.Errorf("failed to parse %s header: %w", SignatureHeader, err)
	}

	// Step 1.1: Determine which signatures to verify
	// We'll verify all signatures present in the input value
	for _, def := range inputValue.Definitions() {
		label := def.Label()

		// Step 1.2: Check if signature has corresponding entry (RFC 9421 Section 3.2, step 1.2)
		var signatureEntry any
		if err := parsedSignature.GetValue(label, &signatureEntry); err != nil {
			return fmt.Errorf("signature label %q not found in %s header: %w", label, SignatureHeader, err)
		}

		// Resolve the key for this signature
		key, err := resolveKey(keyOrResolver, def)
		if err != nil {
			return fmt.Errorf("failed to resolve key for label %q: %w", label, err)
		}

		// Step 3: Extract the signature value (RFC 9421 Section 3.2, step 3)
		// The signature must be a byte sequence (RFC 9421 Section 3.2)
		var signatureBytes []byte

		// Handle both BareItem and Item types
		if bareItem, ok := signatureEntry.(sfv.BareItem); ok {
			if bareItem.Type() != sfv.ByteSequenceType {
				return fmt.Errorf("signature entry for label %q must be a byte sequence, got type %d", label, bareItem.Type())
			}
			if err := bareItem.GetValue(&signatureBytes); err != nil {
				return fmt.Errorf("failed to extract signature bytes for label %q: %w", label, err)
			}
		} else if item, ok := signatureEntry.(sfv.Item); ok {
			if err := item.GetValue(&signatureBytes); err != nil {
				return fmt.Errorf("failed to extract signature bytes for label %q: %w", label, err)
			}
		} else {
			return fmt.Errorf("signature entry for label %q must be a BareItem or Item, got %T", label, signatureEntry)
		}

		// Step 7: Recreate the signature base (RFC 9421 Section 3.2, step 7)
		signatureBase, err := buildSignatureBase(ctx, def)
		if err != nil {
			return fmt.Errorf("failed to recreate signature base for label %q: %w", label, err)
		}

		// Step 8: Verify the signature using HTTP_VERIFY (RFC 9421 Section 3.2, step 8)
		if err := verifySignature(ctx, signatureBase, signatureBytes, def, key); err != nil {
			return fmt.Errorf("signature verification failed for label %q: %w", label, err)
		}
	}

	return nil
}

// resolveKey resolves the cryptographic key for a signature definition
// keyOrResolver can be either a raw key or a KeyResolver
func resolveKey(keyOrResolver any, def *input.Definition) (any, error) {
	// Check if it's a KeyResolver
	if resolver, ok := keyOrResolver.(KeyResolver); ok {
		keyID := def.KeyID()
		if keyID == "" {
			return nil, fmt.Errorf("signature definition requires keyid parameter for key resolution")
		}
		return resolver.ResolveKey(keyID)
	}

	// Otherwise, assume it's a raw key (keyid is not required for raw keys)
	return keyOrResolver, nil
}

// verifySignature verifies a single signature using the HTTP_VERIFY primitive from RFC 9421 Section 3.3
// Uses JWX's jwsbb for cryptographic verification operations
func verifySignature(_ context.Context, signatureBase []byte, signatureBytes []byte, def *input.Definition, key any) error {
	// Determine the appropriate JWS algorithm, preferring explicit algorithm from Definition
	algorithm, err := determineJWSAlgorithm(def, key)
	if err != nil {
		return fmt.Errorf("failed to determine JWS algorithm: %w", err)
	}

	// Use JWX's jwsbb to verify the signature directly
	// RFC 9421 Section 3.3.7: "the HTTP message's signature base is used as the entire JWS Signing Input"
	// "The JOSE Header is not used, and the signature base is not first encoded in Base64"
	err = jwsbb.Verify(key, algorithm, signatureBase, signatureBytes)
	if err != nil {
		return fmt.Errorf("cryptographic verification failed with algorithm %s: %w", algorithm, err)
	}

	return nil
}
