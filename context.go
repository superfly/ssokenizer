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

func GetTransaction(r *http.Request) *Transaction {
	return transactionFromContext(r.Context())
}

func transactionFromContext(ctx context.Context) *Transaction {
	return ctx.Value(contextKeyTransaction).(*Transaction)
}
