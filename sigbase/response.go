package sigbase

import (
	"bytes"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/lestrrat-go/htmsig/internal/common"
	"github.com/lestrrat-go/htmsig/internal/sfv"
)

// ResponseBuilder is a builder for constructing a signature base for an
// HTTP response, with optional binding to the corresponding HTTP request.
// byteSlice, err := sigbase.Response(resp).Request(req).Components(...strings).Build()
type ResponseBuilder struct {
	resp       *http.Response
	req        *http.Request // Optional request for req parameter support
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

// Response creates a new ResponseBuilder for the given HTTP response
func Response(resp *http.Response) *ResponseBuilder {
	rb := &ResponseBuilder{
		resp: resp,
	}
	if resp.Request != nil {
		rb.req = resp.Request
	}
	return rb
}

// Request sets the corresponding HTTP request for req parameter support
func (rb *ResponseBuilder) Request(req *http.Request) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.req = req
	return rb
}

// Components sets the list of components to include in the signature base
func (rb *ResponseBuilder) Components(components ...string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.components = components
	return rb
}

// Created sets the created timestamp for signature parameters
func (rb *ResponseBuilder) Created(timestamp int64) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.created = &timestamp
	return rb
}

// Expires sets the expires timestamp for signature parameters
func (rb *ResponseBuilder) Expires(timestamp int64) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.expires = &timestamp
	return rb
}

// KeyID sets the key identifier for signature parameters
func (rb *ResponseBuilder) KeyID(keyid string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.keyid = keyid
	return rb
}

// Algorithm sets the algorithm for signature parameters
func (rb *ResponseBuilder) Algorithm(alg string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.algorithm = alg
	return rb
}

// Nonce sets the nonce for signature parameters
func (rb *ResponseBuilder) Nonce(nonce string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.nonce = &nonce
	return rb
}

// Tag sets the tag for signature parameters
func (rb *ResponseBuilder) Tag(tag string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	rb.tag = &tag
	return rb
}

// Parameter sets a custom parameter for signature parameters
func (rb *ResponseBuilder) Parameter(key, value string) *ResponseBuilder {
	if rb.err != nil {
		return rb
	}
	if rb.params == nil {
		rb.params = make(map[string]string)
	}
	rb.params[key] = value
	return rb
}

// Build constructs the signature base for an HTTP response according to RFC 9421
func (rb *ResponseBuilder) Build() ([]byte, error) {
	if rb.err != nil {
		return nil, rb.err
	}

	if rb.resp == nil {
		return nil, fmt.Errorf("HTTP response is required")
	}

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

		// Parse component identifier
		component, err := common.ParseComponent(componentID)
		if err != nil {
			return nil, fmt.Errorf("failed to parse component identifier %q: %w", componentID, err)
		}

		// Get component value
		value, err := rb.getComponentValue(component)
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

// getComponentValue retrieves the component value for a response component
func (rb *ResponseBuilder) getComponentValue(component common.Component) (string, error) {
	// Check if this component should be derived from the request (req parameter)
	if component.HasParameter("req") {
		return rb.getRequestComponentValue(component)
	}

	// Handle response-specific derived components (start with @)
	if strings.HasPrefix(component.Name(), "@") {
		return rb.getResponseDerivedComponentValue(component)
	}

	// Handle response header fields
	return rb.getResponseHeaderFieldValue(component)
}

// getRequestComponentValue handles components from the request (req parameter)
func (rb *ResponseBuilder) getRequestComponentValue(component common.Component) (string, error) {
	// Create a temporary request builder to handle request components
	reqBuilder := Request(rb.req)

	// Create a new component without the req parameter for the request builder
	requestComponent := common.NewComponent(component.Name())
	for _, key := range component.Parameters() {
		var value any
		if err := component.GetParameter(key, &value); err != nil {
			return "", fmt.Errorf("failed to get parameter %q: %w", key, err)
		}
		if key != "req" {
			requestComponent.WithParameter(key, value)
		}
	}

	return reqBuilder.getComponentValue(requestComponent)
}

// getResponseDerivedComponentValue handles response-specific derived components
func (rb *ResponseBuilder) getResponseDerivedComponentValue(component common.Component) (string, error) {
	switch component.Name() {
	case "@status":
		// The @status component is the three-digit HTTP status code
		return strconv.Itoa(rb.resp.StatusCode), nil

	default:
		return "", fmt.Errorf("unknown response derived component: %s", component.Name())
	}
}

// getResponseHeaderFieldValue handles HTTP response header fields
func (rb *ResponseBuilder) getResponseHeaderFieldValue(component common.Component) (string, error) {
	// Get header values (case-insensitive)
	values := rb.resp.Header.Values(component.Name())
	if len(values) == 0 {
		return "", fmt.Errorf("header field %q not found in response", component.Name())
	}

	// Handle bs parameter (byte sequence)
	if component.HasParameter("bs") {
		if len(values) > 1 {
			return "", fmt.Errorf("bs parameter requires single header value for field %q", component.Name())
		}
		return values[0], nil
	}

	// Handle sf parameter (structured field)
	if component.HasParameter("sf") {
		return "", fmt.Errorf("cannot retrieve structured field value for header %q with sf parameter", component.Name())
	}

	// Handle key parameter for Dictionary fields
	var keyName string
	if err := component.GetParameter("key", &keyName); err == nil && keyName != "" {
		return "", fmt.Errorf("cannot retrieve dictionary key %q from header field %q", keyName, component.Name())
	}

	// Default behavior: concatenate multiple instances with ", " per RFC 9421 Section 2.1.1
	var fieldValues []string
	for _, value := range values {
		// Trim leading/trailing whitespace from each value
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			fieldValues = append(fieldValues, trimmed)
		}
	}

	if len(fieldValues) == 0 {
		return "", fmt.Errorf("header field %q has only empty values", component.Name())
	}

	// Join with ", " as per RFC 9421
	return strings.Join(fieldValues, ", "), nil
}

// hasSignatureParams checks if signature parameters are set
func (rb *ResponseBuilder) hasSignatureParams() bool {
	return rb.created != nil || rb.expires != nil || rb.keyid != "" || rb.algorithm != "" || rb.nonce != nil || rb.tag != nil || len(rb.params) > 0
}

// buildSignatureParamsLine creates the @signature-params line for responses
func (rb *ResponseBuilder) buildSignatureParamsLine() (string, error) {
	// Use the InnerList builder to create the signature params line
	builder := sfv.NewInnerListBuilder()

	// Add each component as a string item to the inner list
	for _, comp := range rb.components {
		// Parse the component to separate the identifier from its parameters
		component, err := common.ParseComponent(comp)
		if err != nil {
			return "", fmt.Errorf("failed to parse component identifier %q: %w", comp, err)
		}

		// Create the SFV string item with the component name
		stringItemBuilder := sfv.String().Value(component.Name())

		// Add any component parameters as SFV parameters
		var itemBuilder *sfv.ItemBuilder
		for _, key := range component.Parameters() {
			var value any
			if err := component.GetParameter(key, &value); err != nil {
				return "", fmt.Errorf("failed to get parameter %q: %w", key, err)
			}

			// Convert the parameter value to an SFV item
			if boolVal, ok := value.(bool); ok && boolVal {
				// Boolean parameter (no value)
				boolItem, err := sfv.Boolean().Value(true).Build()
				if err != nil {
					return "", fmt.Errorf("failed to create boolean parameter %q for component %q: %w", key, comp, err)
				}
				if itemBuilder == nil {
					itemBuilder = stringItemBuilder.Parameter(key, boolItem)
				} else {
					itemBuilder = itemBuilder.Parameter(key, boolItem)
				}
			} else {
				// String parameter with value
				paramItem, err := sfv.String().Value(fmt.Sprintf("%v", value)).Build()
				if err != nil {
					return "", fmt.Errorf("failed to create parameter %q=%v for component %q: %w", key, value, comp, err)
				}
				if itemBuilder == nil {
					itemBuilder = stringItemBuilder.Parameter(key, paramItem)
				} else {
					itemBuilder = itemBuilder.Parameter(key, paramItem)
				}
			}
		}

		// Build the final item (with or without parameters)
		var stringItem any
		if itemBuilder != nil {
			// Has parameters - use ItemBuilder
			stringItem, err = itemBuilder.Build()
			if err != nil {
				return "", fmt.Errorf("failed to create string item for component %q: %w", comp, err)
			}
		} else {
			// No parameters - use BareItemBuilder
			bareItem, buildErr := stringItemBuilder.Build()
			if buildErr != nil {
				return "", fmt.Errorf("failed to create string item for component %q: %w", comp, buildErr)
			}
			stringItem = bareItem
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
		// Skip standard parameters to avoid duplicates
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
