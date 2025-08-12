// Package http provides HTTP handlers and clients that implement RFC 9421 HTTP Message Signatures.
//
// This package offers both server-side and client-side components for working with HTTP message signatures:
//
// Server Components:
//   - Verifier: Verifies incoming request signatures
//   - ResponseSigner: Signs outgoing responses  
//   - Wrapper: Orchestrates verification and signing around existing handlers
//
// Client Components:
//   - SigningTransport: RoundTripper that signs outgoing requests
//   - NewClient: Creates an http.Client with automatic request signing
//
// # Basic Server Usage
//
//	// Create a verifier with key resolver
//	verifier := http.NewVerifier(&http.StaticKeyResolver{Key: publicKey})
//	
//	// Create a response signer
//	signer := http.NewResponseSigner(privateKey, "my-key-id")
//	
//	// Wrap your handler to verify requests and sign responses
//	handler := http.Wrap(myHandler,
//		http.WithVerifier(verifier),
//		http.WithSigner(signer))
//	
//	http.ListenAndServe(":8080", handler)
//
// # Basic Client Usage
//
//	// Create a signing client
//	client := http.NewClient(privateKey, "my-key-id")
//	
//	// All requests will be automatically signed
//	resp, err := client.Get("https://example.com/api")
//
// # Custom Configuration
//
// Both server and client components support extensive configuration:
//
//	// Custom verifier with specific components and error handling
//	verifier := http.NewVerifier(keyResolver,
//		http.WithMaxSignatureAge(5*time.Minute),
//		http.WithRequiredComponents(
//			component.Method(),
//			component.New("@target-uri"),
//			component.New("date"),
//		),
//		http.WithAllowedAlgorithms("rsa-pss-sha512"),
//	)
//	
//	// Custom response signer
//	signer := http.NewResponseSigner(privateKey, "key-id",
//		http.WithSignerComponents(
//			component.Status(),
//			component.New("content-type"),
//		),
//		http.WithFailOnError(true),
//	)
//	
//	// Use in wrapper
//	handler := http.Wrap(myHandler,
//		http.WithVerifier(verifier),
//		http.WithSigner(signer))
//	
//	// Custom client with specific signature components
//	client := http.NewClient(privateKey, "key-id",
//		http.WithComponents(
//			component.Method(),
//			component.New("@target-uri"),
//			component.New("date"),
//		),
//		http.WithAlgorithm("rsa-pss-sha512"),
//	)
//
// All components integrate seamlessly with the core htmsig package and follow RFC 9421 specifications.
package http