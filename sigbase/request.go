package sigbase

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/htmsig/internal/sfv"
)

// RequestBuilder is a builder for constructing a signature base for an
// HTTP request.
// byteSlice, err := sigbase.Request(req).Components(...strings).Build()
type RequestBuilder struct {
	req        *http.Request
	components []string
	
	// Signature parameters
	created   *int64
	expires   *int64
	keyid     string
	algorithm string
	nonce     *string
	tag       *string
	params    map[string]string
	
	err error
}

func Request(req *http.Request) *RequestBuilder {
	return &RequestBuilder{
		req: req,
	}
}

// Components sets the list of components to include in the signature base
func (rb *RequestBuilder) Components(components ...string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.components = components
	return rb
}

// Created sets the created timestamp for signature parameters
func (rb *RequestBuilder) Created(timestamp int64) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.created = &timestamp
	return rb
}

// Expires sets the expires timestamp for signature parameters
func (rb *RequestBuilder) Expires(timestamp int64) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.expires = &timestamp
	return rb
}

// KeyID sets the key identifier for signature parameters
func (rb *RequestBuilder) KeyID(keyid string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.keyid = keyid
	return rb
}

// Algorithm sets the algorithm for signature parameters
func (rb *RequestBuilder) Algorithm(alg string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.algorithm = alg
	return rb
}

// Nonce sets the nonce for signature parameters
func (rb *RequestBuilder) Nonce(nonce string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.nonce = &nonce
	return rb
}

// Tag sets the tag for signature parameters
func (rb *RequestBuilder) Tag(tag string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.tag = &tag
	return rb
}

// Parameter sets a custom parameter for signature parameters
func (rb *RequestBuilder) Parameter(key, value string) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	if rb.params == nil {
		rb.params = make(map[string]string)
	}
	rb.params[key] = value
	return rb
}

// Build constructs the signature base according to RFC 9421 Section 2.5
func (rb *RequestBuilder) Build() ([]byte, error) {
	if rb.err != nil {
		return nil, rb.err
	}

	if rb.req == nil {
		return nil, fmt.Errorf("HTTP request is required")
	}

	// Use explicit components
	components := rb.components

	if len(components) == 0 {
		return nil, fmt.Errorf("at least one component is required")
	}

	var output bytes.Buffer
	seenComponents := make(map[string]bool)

	// Process each covered component
	for _, componentID := range components {
		// Check for duplicates
		if seenComponents[componentID] {
			return nil, fmt.Errorf("duplicate component identifier: %s", componentID)
		}
		seenComponents[componentID] = true

		// Parse component identifier and parameters
		componentName, params, err := rb.parseComponentIdentifier(componentID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse component identifier %q: %w", componentID, err)
		}

		// Get component value
		value, err := rb.getComponentValue(componentName, params)
		if err != nil {
			return nil, fmt.Errorf("failed to get component value for %q: %w", componentID, err)
		}

		// Append to signature base: "component-name": value
		fmt.Fprintf(&output, "%q: %s\n", componentID, value)
	}

	// Add signature parameters line if we have signature parameters
	if rb.hasSignatureParams() {
		sigParamsLine, err := rb.buildSignatureParamsLine()
		if err != nil {
			return nil, fmt.Errorf("failed to build signature params line: %w", err)
		}
		output.WriteString(sigParamsLine)
	} else {
		// Remove trailing newline if no signature params
		result := output.Bytes()
		if len(result) > 0 && result[len(result)-1] == '\n' {
			result = result[:len(result)-1]
		}
		return result, nil
	}

	return output.Bytes(), nil
}

// parseComponentIdentifier parses a component identifier according to RFC 9421
func (rb *RequestBuilder) parseComponentIdentifier(componentID string) (string, map[string]string, error) {
	// Component identifiers are in the format: "component-name" or "component-name";param=value
	// For simple cases without parameters, just return the component name directly
	if !strings.Contains(componentID, ";") {
		// Simple component identifier without parameters
		componentName := strings.Trim(componentID, "\"")
		return componentName, make(map[string]string), nil
	}

	// For components with parameters, parse manually without SFV
	// Format: "component-name";param=value;param2=value2
	parts := strings.Split(componentID, ";")
	if len(parts) < 2 {
		return "", nil, fmt.Errorf("component identifier with ';' must have parameters")
	}

	// First part is component name (remove quotes if present)
	componentName := strings.Trim(parts[0], "\"")
	params := make(map[string]string)

	// Parse parameters
	for i := 1; i < len(parts); i++ {
		paramStr := strings.TrimSpace(parts[i])
		if paramStr == "" {
			continue
		}

		// Split on '=' to get key=value
		if eqIdx := strings.Index(paramStr, "="); eqIdx > 0 {
			key := paramStr[:eqIdx]
			value := strings.Trim(paramStr[eqIdx+1:], "\"")
			params[key] = value
		} else {
			// Parameter without value (boolean true)
			params[paramStr] = "1"
		}
	}

	return componentName, params, nil
}

// getComponentValue retrieves the component value based on the component name
func (rb *RequestBuilder) getComponentValue(componentName string, params map[string]string) (string, error) {
	// Handle derived components (start with @)
	if strings.HasPrefix(componentName, "@") {
		return rb.getDerivedComponentValue(componentName, params)
	}

	// Handle HTTP header fields
	return rb.getHeaderFieldValue(componentName, params)
}

// getDerivedComponentValue handles derived components like @method, @target-uri, etc.
func (rb *RequestBuilder) getDerivedComponentValue(componentName string, params map[string]string) (string, error) {
	switch componentName {
	case "@method":
		return strings.ToUpper(rb.req.Method), nil

	case "@target-uri":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		return rb.req.URL.String(), nil

	case "@authority":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		if rb.req.URL.Host != "" {
			return rb.req.URL.Host, nil
		}
		// Fall back to Host header if URL.Host is empty
		if host := rb.req.Header.Get("Host"); host != "" {
			return host, nil
		}
		return "", fmt.Errorf("no authority found")

	case "@scheme":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		scheme := rb.req.URL.Scheme
		if scheme == "" {
			// Default scheme based on TLS
			if rb.req.TLS != nil {
				scheme = "https"
			} else {
				scheme = "http"
			}
		}
		return strings.ToLower(scheme), nil

	case "@request-target":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}

		// Handle different request target forms
		if rb.req.Method == "OPTIONS" && rb.req.URL.Path == "*" {
			return "*", nil
		}

		path := rb.req.URL.Path
		if path == "" {
			path = "/"
		}

		if rb.req.URL.RawQuery != "" {
			return path + "?" + rb.req.URL.RawQuery, nil
		}
		return path, nil

	case "@path":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		path := rb.req.URL.Path
		if path == "" {
			path = "/"
		}
		return path, nil

	case "@query":
		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		if rb.req.URL.RawQuery == "" {
			return "", fmt.Errorf("query component not found")
		}
		return "?" + rb.req.URL.RawQuery, nil

	case "@query-param":
		paramName, ok := params["name"]
		if !ok {
			return "", fmt.Errorf("@query-param requires name parameter")
		}

		if rb.req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}

		values, err := url.ParseQuery(rb.req.URL.RawQuery)
		if err != nil {
			return "", fmt.Errorf("failed to parse query parameters: %w", err)
		}

		paramValues, exists := values[paramName]
		if !exists {
			return "", fmt.Errorf("query parameter %q not found", paramName)
		}

		// Return the first value (RFC 9421 doesn't specify multiple values handling)
		if len(paramValues) > 0 {
			return paramValues[0], nil
		}
		return "", nil

	default:
		return "", fmt.Errorf("unknown derived component: %s", componentName)
	}
}

// getHeaderFieldValue handles HTTP header fields according to RFC 9421 Section 2.1
func (rb *RequestBuilder) getHeaderFieldValue(fieldName string, params map[string]string) (string, error) {
	// Get header values (case-insensitive)
	values := rb.req.Header.Values(fieldName)
	if len(values) == 0 {
		return "", fmt.Errorf("header field %q not found", fieldName)
	}

	// Handle bs parameter (byte sequence)
	if _, hasBS := params["bs"]; hasBS {
		// For bs parameter, we wrap the field value 
		// The field must contain only a single value for bs to work
		if len(values) > 1 {
			return "", fmt.Errorf("bs parameter requires single header value for field %q", fieldName)
		}
		// Return the value as-is (it should already be properly encoded)
		return values[0], nil
	}

	// Handle sf parameter (structured field)
	if _, hasSF := params["sf"]; hasSF {
		// For sf parameter, structured field serialization must be handled by caller
		return "", fmt.Errorf("structured field (sf) parameter processing requires SFV access from caller")
	}

	// Handle key parameter for Dictionary fields
	if keyName, hasKey := params["key"]; hasKey {
		// For key parameter, dictionary field processing must be handled by caller
		return "", fmt.Errorf("dictionary key parameter processing requires SFV access from caller for key %q", keyName)
	}

	// Default behavior: concatenate multiple instances with ", " per RFC 9421 Section 2.1.1
	// This handles the case where the same field appears multiple times
	var fieldValues []string
	for _, value := range values {
		// Trim leading/trailing whitespace from each value
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			fieldValues = append(fieldValues, trimmed)
		}
	}

	if len(fieldValues) == 0 {
		return "", fmt.Errorf("header field %q has only empty values", fieldName)
	}

	// Join with ", " as per RFC 9421
	return strings.Join(fieldValues, ", "), nil
}


// hasSignatureParams checks if signature parameters are set
func (rb *RequestBuilder) hasSignatureParams() bool {
	return rb.created != nil || rb.expires != nil || rb.keyid != "" || rb.algorithm != "" || rb.nonce != nil || rb.tag != nil || len(rb.params) > 0
}

// buildSignatureParamsLine creates the @signature-params line using SFV serialization
func (rb *RequestBuilder) buildSignatureParamsLine() (string, error) {
	// Use the InnerList builder to create the signature params line
	builder := sfv.NewInnerListBuilder()

	// Add each component as a string item to the inner list
	for _, comp := range rb.components {
		stringItem, err := sfv.String().Value(comp).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create string item for component %q: %w", comp, err)
		}
		builder.Add(stringItem)
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

	// Marshal the inner list
	innerListBytes, err := innerList.MarshalSFV()
	if err != nil {
		return "", fmt.Errorf("failed to marshal signature params inner list: %w", err)
	}

	// Build the final line: "@signature-params": (components);params
	return fmt.Sprintf("\"@signature-params\": %s", string(innerListBytes)), nil
}

// GetSignatureParams returns the raw signature parameter data for SFV serialization
func (rb *RequestBuilder) GetSignatureParams() (components []string, created *int64, expires *int64, keyid, algorithm string, nonce, tag *string, params map[string]string) {
	return rb.components, rb.created, rb.expires, rb.keyid, rb.algorithm, rb.nonce, rb.tag, rb.params
}
