package sigbase

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/lestrrat-go/htmsig/input"
	"github.com/lestrrat-go/htmsig/internal/sfv"
)

// RequestBuilder is a builder for constructing a signature base for an
// HTTP request.
// byteSlice, err := sigbase.Request(req).Components(...strings).Build()
type RequestBuilder struct {
	req        *http.Request
	components []string
	definition *input.Definition
	err        error
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

// Definition sets the signature definition containing components and parameters
func (rb *RequestBuilder) Definition(def *input.Definition) *RequestBuilder {
	if rb.err != nil {
		return rb
	}
	rb.definition = def
	if def != nil {
		rb.components = def.Components()
	}
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

	// Use components from definition or explicit components
	components := rb.components
	if rb.definition != nil {
		components = rb.definition.Components()
	}

	if len(components) == 0 {
		return nil, fmt.Errorf("at least one component is required")
	}

	var output strings.Builder
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
		output.WriteString(fmt.Sprintf("%q: %s\n", componentID, value))
	}

	// Add signature parameters line if we have a definition
	if rb.definition != nil {
		sigParamsLine, err := rb.buildSignatureParamsLine()
		if err != nil {
			return nil, fmt.Errorf("failed to build signature params line: %w", err)
		}
		output.WriteString(sigParamsLine)
	} else {
		// Remove trailing newline if no signature params
		result := output.String()
		if strings.HasSuffix(result, "\n") {
			result = result[:len(result)-1]
		}
		return []byte(result), nil
	}

	return []byte(output.String()), nil
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

	// For components with parameters, we need proper parsing
	// Try to parse as a list with a single item (which should be an SFV string with parameters)
	listStr := fmt.Sprintf("(%s)", componentID)
	parsed, err := sfv.Parse([]byte(listStr))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse component identifier with parameters: %w", err)
	}

	list, ok := parsed.(*sfv.List)
	if !ok {
		return "", nil, fmt.Errorf("expected list, got %T", parsed)
	}

	if list.Len() != 1 {
		return "", nil, fmt.Errorf("expected single item in list, got %d", list.Len())
	}

	listItem, ok := list.Get(0)
	if !ok {
		return "", nil, fmt.Errorf("failed to get first item from list")
	}

	innerList, ok := listItem.(*sfv.InnerList)
	if !ok {
		return "", nil, fmt.Errorf("expected InnerList, got %T", listItem)
	}

	if innerList.Len() != 1 {
		return "", nil, fmt.Errorf("expected single item in inner list, got %d", innerList.Len())
	}

	item, ok := innerList.Get(0)
	if !ok {
		return "", nil, fmt.Errorf("failed to get first item from inner list")
	}

	// Extract component name (should be a string)
	var componentName string
	if err := item.Value(&componentName); err != nil {
		return "", nil, fmt.Errorf("component identifier must be a string: %w", err)
	}

	// Extract parameters
	params := make(map[string]string)
	if itemParams := item.Parameters(); itemParams != nil {
		for key, paramItem := range itemParams.Values {
			var paramValue string
			if err := paramItem.Value(&paramValue); err != nil {
				// Try other types
				switch paramItem.Type() {
				case sfv.IntegerType:
					var intVal int64
					if err := paramItem.Value(&intVal); err == nil {
						paramValue = fmt.Sprintf("%d", intVal)
					}
				case sfv.BooleanType:
					var boolVal bool
					if err := paramItem.Value(&boolVal); err == nil {
						if boolVal {
							paramValue = "1"
						} else {
							paramValue = "0"
						}
					}
				default:
					return "", nil, fmt.Errorf("unsupported parameter type for %q: %v", key, paramItem.Type())
				}
			}
			params[key] = paramValue
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
		// Parse as structured field and re-serialize
		combinedValue := strings.Join(values, ", ")

		// Parse the field as structured field
		parsedSF, err := sfv.Parse([]byte(combinedValue))
		if err != nil {
			return "", fmt.Errorf("failed to parse structured field %q: %w", fieldName, err)
		}

		// Re-marshal to get canonical form
		var canonicalBytes []byte
		switch v := parsedSF.(type) {
		case sfv.Marshaler:
			canonicalBytes, err = v.MarshalSFV()
			if err != nil {
				return "", fmt.Errorf("failed to marshal structured field %q: %w", fieldName, err)
			}
		default:
			return "", fmt.Errorf("parsed structured field %q does not implement Marshaler", fieldName)
		}

		return string(canonicalBytes), nil
	}

	// Handle key parameter for Dictionary fields
	if keyName, hasKey := params["key"]; hasKey {
		// Combine all values first
		combinedValue := strings.Join(values, ", ")

		// Parse as Dictionary
		parsedDict, err := sfv.Parse([]byte(combinedValue))
		if err != nil {
			return "", fmt.Errorf("failed to parse dictionary field %q: %w", fieldName, err)
		}

		dict, ok := parsedDict.(*sfv.Dictionary)
		if !ok {
			return "", fmt.Errorf("field %q is not a Dictionary for key parameter", fieldName)
		}

		// Get the specific key
		value, exists := dict.Get(keyName)
		if !exists {
			return "", fmt.Errorf("key %q not found in dictionary field %q", keyName, fieldName)
		}

		// Marshal the specific value
		var valueBytes []byte
		switch v := value.(type) {
		case sfv.Marshaler:
			valueBytes, err = v.MarshalSFV()
			if err != nil {
				return "", fmt.Errorf("failed to marshal dictionary key %q from field %q: %w", keyName, fieldName, err)
			}
		default:
			return "", fmt.Errorf("dictionary key %q from field %q does not implement Marshaler", keyName, fieldName)
		}

		return string(valueBytes), nil
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

// buildSignatureParamsLine creates the @signature-params line using proper SFV serialization
func (rb *RequestBuilder) buildSignatureParamsLine() (string, error) {
	if rb.definition == nil {
		return "", fmt.Errorf("signature definition is required")
	}

	// Use the InnerList builder to create the signature params line
	builder := sfv.NewInnerListBuilder()

	// Add each component as a string item to the inner list
	for _, comp := range rb.definition.Components() {
		stringItem, err := sfv.String().Value(comp).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create string item for component %q: %w", comp, err)
		}
		builder.Add(stringItem)
	}

	// Add standard parameters
	if created, ok := rb.definition.Created(); ok {
		createdItem, err := sfv.Integer().Value(created).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create created parameter: %w", err)
		}
		builder.Parameter("created", createdItem)
	}

	if expires, ok := rb.definition.Expires(); ok {
		expiresItem, err := sfv.Integer().Value(expires).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create expires parameter: %w", err)
		}
		builder.Parameter("expires", expiresItem)
	}

	if rb.definition.KeyID() != "" {
		keyidItem, err := sfv.String().Value(rb.definition.KeyID()).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create keyid parameter: %w", err)
		}
		builder.Parameter("keyid", keyidItem)
	}

	if rb.definition.Algorithm() != "" {
		algItem, err := sfv.String().Value(rb.definition.Algorithm()).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create alg parameter: %w", err)
		}
		builder.Parameter("alg", algItem)
	}

	if nonce, ok := rb.definition.Nonce(); ok {
		nonceItem, err := sfv.String().Value(nonce).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create nonce parameter: %w", err)
		}
		builder.Parameter("nonce", nonceItem)
	}

	if tag, ok := rb.definition.Tag(); ok {
		tagItem, err := sfv.String().Value(tag).Build()
		if err != nil {
			return "", fmt.Errorf("failed to create tag parameter: %w", err)
		}
		builder.Parameter("tag", tagItem)
	}

	// Add additional parameters from the definition
	if defParams := rb.definition.Parameters(); defParams != nil {
		for key, value := range defParams.Values {
			// Skip standard parameters to avoid duplicates
			switch key {
			case "created", "expires", "keyid", "alg", "nonce", "tag":
				continue
			}
			builder.Parameter(key, value)
		}
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
