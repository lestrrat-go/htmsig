package http

import (
	"context"
	"fmt"
	"net/http"
)

type Transport struct {
	signer   Signer            // For response signing
	verifier *Verifier         // For request verification
	wrapped  http.RoundTripper // The underlying transport
}

// NewClient creates an http.Client that signs requests using the provided configuration.
// This is similar to oauth2.NewClient() in approach.
func NewClient(options ...TransportOption) *http.Client {
	//nolint:staticcheck
	var rt http.RoundTripper = http.DefaultTransport
	for _, option := range options {
		switch option.Ident() {
		case identTransport{}:
			rt = option.Value().(http.RoundTripper)
		}
	}

	transport := NewTransport(rt, options...)
	return &http.Client{
		Transport: transport,
	}
}

func NewTransport(xport http.RoundTripper, options ...TransportOption) *Transport {
	t := &Transport{
		wrapped: xport,
	}

	for _, option := range options {
		switch option.Ident() {
		case identSigner{}:
			signer := option.Value().(Signer)
			t.signer = signer
		case identVerifier{}:
			verifier := option.Value().(*Verifier)
			t.verifier = verifier
		}
	}

	return t
}

func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Perform request signing if configured
	if t.signer != nil {
		if err := t.signer.SignRequest(req.Context(), req); err != nil {
			return nil, err
		}
	}

	res, err := t.wrapped.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	// Perform request verification if configured
	if t.verifier != nil {
		if err := t.verifier.VerifyResponse(context.Background(), res); err != nil {
			return nil, fmt.Errorf(`htmsig.Transport: verification failed during RoundTrip: %w`, err)
		}
	}

	return res, nil
}
