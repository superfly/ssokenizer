package ssokenizer

import (
	"github.com/gorilla/mux"
)

type ProviderConfig interface {
	Register(r *mux.Router, sealKey string, rpAuth string) error
}
