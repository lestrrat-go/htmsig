package http

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/htmsig"
	"github.com/lestrrat-go/htmsig/component"
	"github.com/lestrrat-go/htmsig/input"
)

// Example demonstrates how to use the new SignResponse API directly in a handler.
func ExampleSignResponse() {
	// Generate a key pair for the example
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set response headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
		
		// Write status code (this would normally be done by WriteHeader)
		statusCode := 200
		
		// Create signature input - defining what to sign
		def := input.NewDefinitionBuilder().
			Label("sig").
			KeyID("server-key-1").
			Components(
				component.Status(),                    // @status
				component.New("content-type"),        // content-type header  
				component.New("date"),               // date header
			).
			MustBuild()
		
		inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
		
		// Sign the response using the new API - this works with ResponseWriter!
		ctx := component.WithResponseInfo(context.Background(), w.Header(), statusCode, 
			component.RequestInfoFromHTTP(r))
		err := htmsig.SignResponse(ctx, w.Header(), inputValue, privateKey)
		if err != nil {
			http.Error(w, "Failed to sign response", http.StatusInternalServerError)
			return
		}
		
		// Now write the response
		w.WriteHeader(statusCode)
		fmt.Fprint(w, `{"message": "Hello, signed world!"}`)
	})
	
	// The handler now automatically signs responses with the specified components
	_ = handler
}

// Example demonstrates signing a request on the client side
func ExampleSignRequest() {
	// Generate a key pair for the example  
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	
	// Create an HTTP request
	req, _ := http.NewRequest("POST", "https://api.example.com/data", nil)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
	
	// Create signature input
	def := input.NewDefinitionBuilder().
		Label("sig").
		KeyID("client-key-1").  
		Components(
			component.Method(),                   // @method
			component.New("@target-uri"),        // @target-uri
			component.New("content-type"),       // content-type header
			component.New("date"),              // date header
		).
		MustBuild()
		
	inputValue := input.NewValueBuilder().AddDefinition(def).MustBuild()
	
	// Sign the request using the new API
	ctx := component.WithRequestInfoFromHTTP(context.Background(), req)
	err := htmsig.SignRequest(ctx, req.Header, inputValue, privateKey)
	if err != nil {
		panic(err)
	}
	
	// Request is now signed and ready to send
	_ = req
}