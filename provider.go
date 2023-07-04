package ssokenizer

import "net/http"

type ProviderConfig interface {
	Register(sealKey string, rpAuth string) (http.Handler, error)
}
