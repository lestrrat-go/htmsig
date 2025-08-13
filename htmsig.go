package htmsig

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/dsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/sfv"
)

const (
	SignatureInputHeader = "Signature-Input"
	SignatureHeader      = "Signature"
)

// RFC 9421 Algorithm Names (Section 6.2.2 Initial Contents)
const (
	AlgorithmRSAPSSSHA512    = "rsa-pss-sha512"    // Section 3.3.1
	AlgorithmRSAV15SHA256    = "rsa-v1_5-sha256"   // Section 3.3.2
	AlgorithmHMACSHA256      = "hmac-sha256"       // Section 3.3.3
	AlgorithmECDSAP256SHA256 = "ecdsa-p256-sha256" // Section 3.3.4
	AlgorithmECDSAP384SHA384 = "ecdsa-p384-sha384" // Section 3.3.5
	AlgorithmEd25519         = "ed25519"           // Section 3.3.6
)

// KeyResolver interface allows resolving cryptographic keys by their ID
type KeyResolver interface {
	ResolveKey(keyID string) (any, error)
}


// SignRequest signs an HTTP request using the provided headers.
// Request information must be provided in context using component.WithRequestInfo.
func SignRequest(ctx context.Context, headers http.Header, inputValue *input.Value, key any) error {
	ctx = component.WithMode(ctx, component.ModeRequest)
	return signWithContext(ctx, headers, inputValue, key)
}

// SignResponse signs an HTTP response using the provided headers.
// Response information must be provided in context using component.WithResponseInfo.
func SignResponse(ctx context.Context, headers http.Header, inputValue *input.Value, key any) error {
	ctx = component.WithMode(ctx, component.ModeResponse)
	return signWithContext(ctx, headers, inputValue, key)
}

// signWithContext performs the actual signing using the prepared context and headers.
func signWithContext(ctx context.Context, hdr http.Header, inputValue *input.Value, key any) error {
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

		sfvsig := sfv.ByteSequence(signature)

		if err := dict.Set(def.Label(), sfvsig); err != nil {
			return fmt.Errorf("failed to set signature in dictionary: %w", err)
		}
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
	innerList := sfv.NewInnerList()
	for _, comp := range def.Components() {
		sfvComp, err := comp.SFV()
		if err != nil {
			return nil, fmt.Errorf("failed to convert component %q to SFV: %w", comp.Name(), err)
		}
		if err := innerList.Add(sfvComp); err != nil {
			return nil, fmt.Errorf("failed to add component to inner list: %w", err)
		}
	}

	// Add signature parameters (created, expires, keyid, alg, nonce, tag, etc.)
	params := innerList.Parameters()
	if created, ok := def.Created(); ok {
		createdItem := sfv.BareInteger(created)
		if err := params.Set("created", createdItem); err != nil {
			return nil, fmt.Errorf("failed to set created parameter: %w", err)
		}
	}

	if expires, ok := def.Expires(); ok {
		expiresItem := sfv.BareInteger(expires)
		if err := params.Set("expires", expiresItem); err != nil {
			return nil, fmt.Errorf("failed to set expires parameter: %w", err)
		}
	}

	if def.KeyID() != "" {
		keyidItem := sfv.BareString(def.KeyID())
		if err := params.Set("keyid", keyidItem); err != nil {
			return nil, fmt.Errorf("failed to set keyid parameter: %w", err)
		}
	}

	if def.Algorithm() != "" {
		algItem := sfv.BareString(def.Algorithm())
		if err := params.Set("alg", algItem); err != nil {
			return nil, fmt.Errorf("failed to set alg parameter: %w", err)
		}
	}

	if nonce, ok := def.Nonce(); ok {
		nonceItem := sfv.BareString(nonce)
		if err := params.Set("nonce", nonceItem); err != nil {
			return nil, fmt.Errorf("failed to set nonce parameter: %w", err)
		}
	}

	if tag, ok := def.Tag(); ok {
		tagItem := sfv.BareString(tag)
		if err := params.Set("tag", tagItem); err != nil {
			return nil, fmt.Errorf("failed to set tag parameter: %w", err)
		}
	}

	// Encode the inner list with no parameter spacing (HTTP Message Signature format)
	encoder := sfv.NewEncoder(&output)
	encoder.SetParameterSpacing("")
	if err := encoder.Encode(innerList); err != nil {
		return nil, fmt.Errorf("failed to encode inner list: %w", err)
	}

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
// Uses DSIG for cryptographic signing operations
func generateSignature(ctx context.Context, sigbase []byte, def *input.Definition, key any) ([]byte, error) {
	// Determine the appropriate algorithm, preferring explicit algorithm from Definition
	algorithm, err := determineAlgorithm(def, key)
	if err != nil {
		return nil, fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Use DSIG to sign the signature base directly
	// RFC 9421 Section 3.3.7: "the HTTP message's signature base is used as the entire JWS Signing Input"
	// "The JOSE Header is not used, and the signature base is not first encoded in Base64"
	signature, err := dsig.Sign(key, algorithm, sigbase, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with algorithm %s: %w", algorithm, err)
	}

	return signature, nil
}

// determineAlgorithm determines the appropriate algorithm from Definition and key material
// First checks the explicit algorithm parameter in Definition, then falls back to key type detection
func determineAlgorithm(def *input.Definition, key any) (string, error) {
	// First, check if algorithm is explicitly specified in the Definition
	if algorithm := def.Algorithm(); algorithm != "" {
		// Convert RFC 9421 algorithm names to DSIG algorithm names
		return convertRFC9421ToDSIG(algorithm)
	}

	// Fallback to determining algorithm from key material
	return determineAlgorithmFromKey(key)
}

// convertRFC9421ToDSIG converts RFC 9421 algorithm names to DSIG algorithm identifiers
// Maps the official RFC 9421 algorithm registry entries to their corresponding DSIG algorithm names
func convertRFC9421ToDSIG(rfc9421Alg string) (string, error) {
	switch rfc9421Alg {
	// Official RFC 9421 algorithms from Section 6.2.2 Initial Contents
	case AlgorithmRSAPSSSHA512: // Section 3.3.1
		return dsig.RSAPSSWithSHA512, nil
	case AlgorithmRSAV15SHA256: // Section 3.3.2
		return dsig.RSAPKCS1v15WithSHA256, nil
	case AlgorithmHMACSHA256: // Section 3.3.3
		return dsig.HMACWithSHA256, nil
	case AlgorithmECDSAP256SHA256: // Section 3.3.4
		return dsig.ECDSAWithP256AndSHA256, nil
	case AlgorithmECDSAP384SHA384: // Section 3.3.5
		return dsig.ECDSAWithP384AndSHA384, nil
	case AlgorithmEd25519: // Section 3.3.6
		return dsig.EdDSA, nil
	default:
		return "", fmt.Errorf("unsupported RFC 9421 algorithm: %s", rfc9421Alg)
	}
}

// determineAlgorithmFromKey determines the appropriate DSIG algorithm from key material
// Maps key types to DSIG algorithm identifiers
func determineAlgorithmFromKey(key any) (string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		// Use RSA-PSS with SHA-512 as per RFC 9421 Section 3.3.1
		return dsig.RSAPSSWithSHA512, nil
	case *rsa.PublicKey:
		// Use RSA-PSS with SHA-512 for public key verification
		return dsig.RSAPSSWithSHA512, nil
	case *ecdsa.PrivateKey:
		// Determine curve and select appropriate ECDSA algorithm
		switch k.Curve.Params().Name {
		case "P-256":
			// ECDSA using P-256 and SHA-256 as per RFC 9421 Section 3.3.4
			return dsig.ECDSAWithP256AndSHA256, nil
		case "P-384":
			// ECDSA using P-384 and SHA-384 as per RFC 9421 Section 3.3.5
			return dsig.ECDSAWithP384AndSHA384, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case *ecdsa.PublicKey:
		// Determine curve and select appropriate ECDSA algorithm for public key
		switch k.Curve.Params().Name {
		case "P-256":
			return dsig.ECDSAWithP256AndSHA256, nil
		case "P-384":
			return dsig.ECDSAWithP384AndSHA384, nil
		default:
			return "", fmt.Errorf("unsupported ECDSA curve: %s", k.Curve.Params().Name)
		}
	case ed25519.PrivateKey:
		// EdDSA using Ed25519 as per RFC 9421 Section 3.3.6
		return dsig.EdDSA, nil
	case ed25519.PublicKey:
		// EdDSA using Ed25519 for public key verification
		return dsig.EdDSA, nil
	case []byte:
		// HMAC using SHA-256 for raw byte keys as per RFC 9421 Section 3.3.3
		return dsig.HMACWithSHA256, nil
	case string:
		// HMAC using SHA-256 for string keys as per RFC 9421 Section 3.3.3
		return dsig.HMACWithSHA256, nil
	default:
		return "", fmt.Errorf("unsupported key type: %T", key)
	}
}

// VerifyRequest verifies HTTP request signatures using the provided headers.
// Request information must be provided in context using component.WithRequestInfo.
func VerifyRequest(ctx context.Context, headers http.Header, keyOrResolver any, options ...VerifyOption) error {
	ctx = component.WithMode(ctx, component.ModeRequest)
	return verifyWithContext(ctx, headers, keyOrResolver, options...)
}

// VerifyResponse verifies HTTP response signatures using the provided headers.
// Response information must be provided in context using component.WithResponseInfo.
func VerifyResponse(ctx context.Context, headers http.Header, keyOrResolver any, options ...VerifyOption) error {
	ctx = component.WithMode(ctx, component.ModeResponse)
	return verifyWithContext(ctx, headers, keyOrResolver, options...)
}

// verifyWithContext performs the actual verification using the prepared context and headers.
func verifyWithContext(ctx context.Context, hdr http.Header, keyOrResolver any, options ...VerifyOption) error {
	// Process options
	var validateExpires bool
	var clock Clock = SystemClock{}
	for _, opt := range options {
		switch opt.Ident() {
		case identValidateExpires{}:
			validateExpires = opt.Value().(bool)
		case identClock{}:
			clock = opt.Value().(Clock)
		}
	}
	// Step 1: Parse Signature and Signature-Input fields (RFC 9421 Section 3.2, step 1)
	signatureInputHeader := hdr.Get(SignatureInputHeader)
	if signatureInputHeader == "" {
		return fmt.Errorf("htmsig.Verify: missing %s header", SignatureInputHeader)
	}

	signatureHeader := hdr.Get(SignatureHeader)
	if signatureHeader == "" {
		return fmt.Errorf("htmsig.Verify: missing %s header", SignatureHeader)
	}

	// Parse the Signature-Input header using the input package
	inputValue, err := input.Parse([]byte(signatureInputHeader))
	if err != nil {
		return fmt.Errorf("htmsig.Verify: failed to parse %s header: %w", SignatureInputHeader, err)
	}

	// Parse the Signature field to get signature values
	parsedSignature, err := sfv.ParseDictionary([]byte(signatureHeader))
	if err != nil {
		return fmt.Errorf("htmsig.Verify: failed to parse %s header: %w", SignatureHeader, err)
	}

	// Step 1.1: Determine which signatures to verify
	// We'll verify all signatures present in the input value
	for _, def := range inputValue.Definitions() {
		label := def.Label()

		// Step 1.2: Check if signature has corresponding entry (RFC 9421 Section 3.2, step 1.2)
		var signatureEntry any
		if err := parsedSignature.GetValue(label, &signatureEntry); err != nil {
			return fmt.Errorf("htmsig.Verify: signature label %q not found in %s header: %w", label, SignatureHeader, err)
		}

		// Resolve the key for this signature
		key, err := resolveKey(keyOrResolver, def)
		if err != nil {
			return fmt.Errorf("htmsig.Verify: failed to resolve key for label %q: %w", label, err)
		}

		// Validate signature expiration if configured
		if validateExpires {
			if err := validateSignatureExpiration(clock, def); err != nil {
				return fmt.Errorf("htmsig.Verify: signature expired for label %q: %w", label, err)
			}
		}

		// Step 3: Extract the signature value (RFC 9421 Section 3.2, step 3)
		// The signature must be a byte sequence (RFC 9421 Section 3.2)
		var signatureBytes []byte

		// Handle both BareItem and Item types
		if bareItem, ok := signatureEntry.(sfv.BareItem); ok {
			if bareItem.Type() != sfv.ByteSequenceType {
				return fmt.Errorf("htmsig.Verify: signature entry for label %q must be a byte sequence, got type %d", label, bareItem.Type())
			}
			if err := bareItem.GetValue(&signatureBytes); err != nil {
				return fmt.Errorf("htmsig.Verify: failed to extract signature bytes for label %q: %w", label, err)
			}
		} else if item, ok := signatureEntry.(sfv.Item); ok {
			if err := item.GetValue(&signatureBytes); err != nil {
				return fmt.Errorf("htmsig.Verify: failed to extract signature bytes for label %q: %w", label, err)
			}
		} else {
			return fmt.Errorf("htmsig.Verify: ignature entry for label %q must be a BareItem or Item, got %T", label, signatureEntry)
		}

		// Step 7: Recreate the signature base (RFC 9421 Section 3.2, step 7)
		signatureBase, err := buildSignatureBase(ctx, def)
		if err != nil {
			return fmt.Errorf("htmsig.Verify: failed to recreate signature base for label %q: %w", label, err)
		}

		// Step 8: Verify the signature using HTTP_VERIFY (RFC 9421 Section 3.2, step 8)
		if err := verifySignature(ctx, signatureBase, signatureBytes, def, key); err != nil {
			return fmt.Errorf("htmsig.Verify: signature verification failed for label %q: %w", label, err)
		}
	}

	return nil
}

// validateSignatureExpiration validates if a signature has expired based on its expires parameter
func validateSignatureExpiration(clock Clock, def *input.Definition) error {
	// Check if the signature has an expires parameter
	expiresTimestamp, hasExpires := def.Expires()
	if !hasExpires {
		return nil // No expiration time set, signature doesn't expire
	}

	// Check if the signature has expired
	now := clock.Now()
	expiresTime := time.Unix(expiresTimestamp, 0)
	if now.After(expiresTime) {
		return fmt.Errorf("signature expired at %v (current time: %v)", expiresTime, now)
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
// Uses DSIG for cryptographic verification operations
func verifySignature(_ context.Context, signatureBase []byte, signatureBytes []byte, def *input.Definition, key any) error {
	// Determine the appropriate algorithm, preferring explicit algorithm from Definition
	algorithm, err := determineAlgorithm(def, key)
	if err != nil {
		return fmt.Errorf("failed to determine algorithm: %w", err)
	}

	// Use DSIG to verify the signature directly
	// RFC 9421 Section 3.3.7: "the HTTP message's signature base is used as the entire JWS Signing Input"
	// "The JOSE Header is not used, and the signature base is not first encoded in Base64"
	err = dsig.Verify(key, algorithm, signatureBase, signatureBytes)
	if err != nil {
		return fmt.Errorf("verification failed with algorithm %s: %w", algorithm, err)
	}

	return nil
}
