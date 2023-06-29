package ssokenizer

import (
	"context"
	"net/http"
)

type contextKey string

const (
	contextKeyTransaction contextKey = "transaction"
)

func withTransaction(ctx context.Context, t *Transaction) context.Context {
	return context.WithValue(ctx, contextKeyTransaction, t)
}

func GetTransaction(r *http.Request) (*Transaction, bool) {
	return transactionFromContext(r.Context())
}

func transactionFromContext(ctx context.Context) (*Transaction, bool) {
	if t, ok := ctx.Value(contextKeyTransaction).(*Transaction); ok {
		return t, true
	}
	return nil, false
}
