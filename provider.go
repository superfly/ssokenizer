package ssokenizer

import (
	"net/http"
	"net/url"
)

type provider struct {
	handler   http.Handler
	returnURL *url.URL
}

type ProviderConfig interface {
	Register(sealKey string, rpAuth string) (http.Handler, error)
}
