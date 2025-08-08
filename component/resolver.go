package component

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

type modeKey struct{}
type requestKey struct{}
type responseKey struct{}

type Mode int

const (
	ModeRequest Mode = iota
	ModeResponse
)

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

// WithRequest adds an HTTP request to the context for later retrieval.
func WithRequest(ctx context.Context, req *http.Request) context.Context {
	return context.WithValue(ctx, requestKey{}, req)
}

func RequestFromContext(ctx context.Context) (*http.Request, bool) {
	req, ok := ctx.Value(requestKey{}).(*http.Request)
	return req, ok
}

func WithResponse(ctx context.Context, resp *http.Response) context.Context {
	return context.WithValue(ctx, responseKey{}, resp)
}

func ResponseFromContext(ctx context.Context) (*http.Response, bool) {
	resp, ok := ctx.Value(responseKey{}).(*http.Response)
	return resp, ok
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
	req, ok := RequestFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no request available in context")
	}

	compName := comp.name
	if strings.HasPrefix(compName, "@") {
		return resolveRequestDerivedComponent(ctx, comp)
	}

	return resolveHeader(ctx, comp, req)
}

func resolveRequestDerivedComponent(ctx context.Context, comp Identifier) (string, error) {
	req, ok := RequestFromContext(ctx)
	if !ok {
		return "", fmt.Errorf("no request available in context")
	}

	switch comp.name {
	case "@method":
		return req.Method, nil
	case "@scheme":
		if req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		return req.URL.Scheme, nil
	case "@authority":
		if req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		return req.URL.Host, nil
	case "@path":
		if req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		return req.URL.Path, nil
	case "@query":
		if req.URL == nil {
			return "", fmt.Errorf("request URL is nil")
		}
		if req.URL.RawQuery == "" {
			return "", fmt.Errorf("query component not found")
		}
		return "?" + req.URL.RawQuery, nil
	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.name)
	}
}

func resolveResponse(ctx context.Context, comp Identifier) (string, error) {
	resp, ok := ctx.Value(requestKey{}).(*http.Response)
	if !ok || resp == nil {
		return "", fmt.Errorf("no response available in context")
	}

	compName := comp.name
	if strings.HasPrefix(compName, "@") {
		return resolveResponseDerivedComponent(ctx, comp)
	}

	return resolveHeader(ctx, comp, resp.Request)
}

func resolveResponseDerivedComponent(ctx context.Context, comp Identifier) (string, error) {
	resp, ok := ctx.Value(requestKey{}).(*http.Response)
	if !ok || resp == nil {
		return "", fmt.Errorf("no response available in context")
	}

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

		if _, ok := RequestFromContext(ctx); !ok {
			ctx = context.WithValue(ctx, requestKey{}, resp.Request)
		}
		return resolveRequestDerivedComponent(ctx, comp)
	case "@status":
		return fmt.Sprintf("%d", resp.StatusCode), nil
	default:
		return "", fmt.Errorf("unknown derived component: %s", comp.name)
	}
}

func resolveHeader(_ context.Context, comp Identifier, req *http.Request) (string, error) {
	// Get header values (case-insensitive)
	values := req.Header.Values(comp.name)
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
