package http should implement HTTP handlers that implement a rudimentary RFC 9421 sever component and a client component.

Server should implement a http.Handler that generates does the right thing, and a wrapper.
User should be allowed to choose between 1. verify incoming messages, 2. sign outgoing messages, and 3. do both.

Server components Verifier / Signer should have fields that configure their behavior, key resolvers, error handler, etc. You  should come up with a list.

Particularly for error handling, there should be an error handler that the user can set. it should probably be yet another http.Handler, so they have maximum flexibility. The default should probably return 401 status.

## Implementation Status

The wrapper has been implemented with the following API:

```go
// Basic wrapper with options
func Wrap(h http.Handler, options ...WrapperOption) http.Handler

// Options for configuration
func WithVerifier(verifier *Verifier) WrapperOption
func WithSigner(signer *ResponseSigner) WrapperOption  
func WithErrorHandler(handler http.Handler) WrapperOption

// Convenience functions
func VerifyOnly(handler http.Handler, keyResolver KeyResolver) http.Handler
func SignOnly(handler http.Handler, key any, keyID string) http.Handler
func VerifyAndSign(handler http.Handler, verifyResolver KeyResolver, signKey any, signKeyID string) http.Handler
```

The implementation follows the pattern described in the original spec:
- `Wrapper.ServeHTTP()` verifies incoming requests and handles errors
- Response signing is done through a signing response writer  
- Configurable error handling with default 401 responses
- Uses the main htmsig package for actual signature operations

The client side should create an http.Client with an appropriate http.RoundTripper that adds signature generation.

Refer to how golang.org/x/oauth2 does this in oauth2.NewClient(). There should be per-client configuration.

---

All of the above should be using features from the main repository (htmsig and its subpackages)
