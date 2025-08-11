package component

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type modeKey struct{}
type requestInfoKey struct{}
type responseInfoKey struct{}

type Mode int

const (
	ModeRequest Mode = iota
	ModeResponse
)

// RequestInfo contains the discrete components needed for request signature resolution
type RequestInfo struct {
	Headers   http.Header
	Method    string
	Scheme    string
	Authority string
	Path      string
	RawQuery  string
	TargetURI string
}

// ResponseInfo contains the discrete components needed for response signature resolution  
type ResponseInfo struct {
	Headers    http.Header
	StatusCode int
	Request    *RequestInfo // For response components that need request info
}

// WithMode adds a mode to the context for later retrieval. IF unspecified,
// the default mode is to resolve components for HTTP requests.
func WithMode(ctx context.Context, mode Mode) context.Context {
	return context.WithValue(ctx, modeKey{}, mode)
}

func ModeFromContext(ctx context.Context) Mode {
	mode, ok := ctx.Value(modeKey{}).(Mode)
	if !ok {
		return ModeRequest // Default to ModeRequest if not set
	}
	return mode
}


// WithRequestInfo adds request information to the context using discrete values
func WithRequestInfo(ctx context.Context, headers http.Header, method, scheme, authority, path, rawQuery, targetURI string) context.Context {
	info := &RequestInfo{
		Headers:   headers,
		Method:    method,
		Scheme:    scheme,
		Authority: authority,
		Path:      path,
		RawQuery:  rawQuery,
		TargetURI: targetURI,
	}
	return context.WithValue(ctx, requestInfoKey{}, info)
}

func RequestInfoFromContext(ctx context.Context) (*RequestInfo, bool) {
	info, ok := ctx.Value(requestInfoKey{}).(*RequestInfo)
	return info, ok
}

// WithResponseInfo adds response information to the context using discrete values
func WithResponseInfo(ctx context.Context, headers http.Header, statusCode int, requestInfo *RequestInfo) context.Context {
	info := &ResponseInfo{
		Headers:    headers,
		StatusCode: statusCode,
		Request:    requestInfo,
	}
	return context.WithValue(ctx, responseInfoKey{}, info)
}

func ResponseInfoFromContext(ctx context.Context) (*ResponseInfo, bool) {
	info, ok := ctx.Value(responseInfoKey{}).(*ResponseInfo)
	return info, ok
}

// Helper function to create RequestInfo from http.Request
func RequestInfoFromHTTP(req *http.Request) *RequestInfo {
	if req == nil || req.URL == nil {
		return nil
	}
	
	return &RequestInfo{
		Headers:   req.Header,
		Method:    req.Method,
		Scheme:    req.URL.Scheme,
		Authority: req.URL.Host,
		Path:      req.URL.Path,
		RawQuery:  req.URL.RawQuery,
		TargetURI: req.URL.String(),
	}
}

// WithRequestInfoFromHTTP is a convenience function that extracts request info from an http.Request
// and adds it to the context.
func WithRequestInfoFromHTTP(ctx context.Context, req *http.Request) context.Context {
	reqInfo := RequestInfoFromHTTP(req)
	if reqInfo == nil {
		return ctx
	}
	return WithRequestInfo(ctx, reqInfo.Headers, reqInfo.Method, reqInfo.Scheme,
		reqInfo.Authority, reqInfo.Path, reqInfo.RawQuery, reqInfo.TargetURI)
}

// Helper function to create ResponseInfo from http.Response
func ResponseInfoFromHTTP(resp *http.Response) *ResponseInfo {
	if resp == nil {
		return nil
	}
	
	var requestInfo *RequestInfo
	if resp.Request != nil {
		requestInfo = RequestInfoFromHTTP(resp.Request)
	}
	
	return &ResponseInfo{
		Headers:    resp.Header,
		StatusCode: resp.StatusCode,
		Request:    requestInfo,
	}
}

// WithResponseInfoFromHTTP is a convenience function that extracts response info from an http.Response
// and adds it to the context.
func WithResponseInfoFromHTTP(ctx context.Context, resp *http.Response) context.Context {
	respInfo := ResponseInfoFromHTTP(resp)
	if respInfo == nil {
		return ctx
	}
	return WithResponseInfo(ctx, respInfo.Headers, respInfo.StatusCode, respInfo.Request)
}

// Resolve resolves the component identifier to its value. Since the resolution
// process requires different input for different modes/components, this function
// must be called after the context object has been properly set up.
func Resolve(ctx context.Context, comp Identifier) (string, error) {
	mode := ModeFromContext(ctx)
	switch mode {
	case ModeRequest:
		return resolveRequest(ctx, comp)
	case ModeResponse:
		return resolveResponse(ctx, comp)
	default:
		return "", fmt.Errorf("unknown mode: %d", mode)
	}
}

func resolveRequest(ctx context.Context, comp Identifier) (string, error) {
	reqInfo, ok := RequestInfoFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no request information available in context")
	}

	compName := comp.name
	if strings.HasPrefix(compName, "@") {
		return resolveRequestDerivedComponentFromInfo(ctx, comp, reqInfo)
	}
	return resolveHeader(ctx, comp, reqInfo.Headers)
}

func resolveRequestDerivedComponentFromInfo(ctx context.Context, comp Identifier, reqInfo *RequestInfo) (string, error) {
	switch comp.name {
	case "@method":
		return reqInfo.Method, nil
	case "@scheme":
		return reqInfo.Scheme, nil
	case "@authority":
		return reqInfo.Authority, nil
	case "@path":
		return reqInfo.Path, nil
	case "@query":
		if reqInfo.RawQuery == "" {
			return "", fmt.Errorf("query component not found")
		}
		return "?" + reqInfo.RawQuery, nil
	case "@target-uri":
		return reqInfo.TargetURI, nil
	case "@query-param":
		// Get the "name" parameter
		var paramName string
		if err := comp.GetParameter("name", &paramName); err != nil {
			return "", fmt.Errorf("@query-param requires 'name' parameter: %w", err)
		}
		
		// Parse query string to extract parameter
		queryValues, err := url.ParseQuery(reqInfo.RawQuery)
		if err != nil {
			return "", fmt.Errorf("failed to parse query: %w", err)
		}
		
		values := queryValues[paramName]
		if len(values) == 0 {
			return "", fmt.Errorf("query parameter %q not found", paramName)
		}
		return values[0], nil
	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.name)
	}
}


func resolveResponse(ctx context.Context, comp Identifier) (string, error) {
	respInfo, ok := ResponseInfoFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no response information available in context")
	}

	compName := comp.name
	if strings.HasPrefix(compName, "@") {
		return resolveResponseDerivedComponentFromInfo(ctx, comp, respInfo)
	}
	return resolveHeader(ctx, comp, respInfo.Headers)
}

func resolveResponseDerivedComponentFromInfo(ctx context.Context, comp Identifier, respInfo *ResponseInfo) (string, error) {
	switch comp.name {
	case "@method", "@scheme", "@authority", "@path", "@query":
		// Make sure that the ;req parameter is set
		var req bool
		if err := comp.GetParameter("req", &req); err != nil {
			return "", fmt.Errorf("missing 'req' parameter for %q component", comp.name)
		}
		if !req {
			return "", fmt.Errorf("'req' parameter must be true for %q component", comp.name)
		}

		if respInfo.Request == nil {
			return "", fmt.Errorf("no request information available for %q component", comp.name)
		}
		return resolveRequestDerivedComponentFromInfo(ctx, comp, respInfo.Request)
	case "@status":
		return fmt.Sprintf("%d", respInfo.StatusCode), nil
	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.name)
	}
}


func resolveHeader(_ context.Context, comp Identifier, hdr http.Header) (string, error) {
	// Get header values (case-insensitive)
	values := hdr.Values(comp.name)
	if len(values) == 0 {
		return "", fmt.Errorf("header field %q not found", comp.name)
	}

	// Handle bs parameter (byte sequence)
	if comp.HasParameter("bs") {
		// For bs parameter, we wrap the field value
		if len(values) > 1 {
			return "", fmt.Errorf("bs parameter requires single header value for field %q", comp.name)
		}
		return values[0], nil
	}

	// Return the first value (RFC 9421 doesn't specify multiple values handling)
	return values[0], nil
}

