package ssokenizer

import (
	"net/http"
	"net/url"
)

type provider struct {
	handler   http.Handler
	returnURL *url.URL
}

// Arbitrary configuration type for providers to implement.
type ProviderConfig interface {
	// Register should validate the provider configuration and return a handler
	// for requests to the provider. The provider can call GetTransaction to
	// receive user state from the in-progress SSO transaction. The Transaction
	// can be used to return data or error messages to the relying party.
	Register(sealKey string, rpAuth string) (http.Handler, error)
}
