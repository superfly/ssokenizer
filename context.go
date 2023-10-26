package ssokenizer

import (
	"context"
	"net/http"
)

type contextKey string

const (
	contextKeyTransaction contextKey = "transaction"
	contextKeyProvider    contextKey = "provider"
)

func withTransaction(r *http.Request, t *Transaction) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKeyTransaction, t))
}

func GetTransaction(r *http.Request) *Transaction {
	return r.Context().Value(contextKeyTransaction).(*Transaction)
}

func withProvider(r *http.Request, p *provider) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKeyProvider, p))
}

func getProvider(r *http.Request) *provider {
	return r.Context().Value(contextKeyProvider).(*provider)
}
