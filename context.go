package ssokenizer

import (
	"context"
	"net/http"

	"github.com/sirupsen/logrus"
)

type contextKey string

const (
	contextKeyTransaction contextKey = "transaction"
	contextKeyProvider    contextKey = "provider"
	contextKeyLog         contextKey = "log"
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

// Updates the logrus.FieldLogger in the context with added data. Requests are
// logged by Transaction.ReturnData/ReturnError.
func WithLog(r *http.Request, l logrus.FieldLogger) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), contextKeyLog, l))
}

// Updates the logrus.FieldLogger in the context with "error" field. Requests
// are logged by Transaction.ReturnData/ReturnError.
func WithError(r *http.Request, err error) *http.Request {
	return WithLog(r, GetLog(r).WithError(err))
}

// Updates the logrus.FieldLogger in the context with added field. Requests
// are logged by Transaction.ReturnData/ReturnError.
func WithField(r *http.Request, key string, value any) *http.Request {
	return WithLog(r, GetLog(r).WithField(key, value))
}

// Updates the logrus.FieldLogger in the context with added fields. Requests
// are logged by Transaction.ReturnData/ReturnError.
func WithFields(r *http.Request, fields logrus.Fields) *http.Request {
	return WithLog(r, GetLog(r).WithFields(fields))
}

// Gets the logrus.FieldLogger from the context. Requests are logged by
// Transaction.ReturnData/ReturnError.
func GetLog(r *http.Request) logrus.FieldLogger {
	if l, ok := r.Context().Value(contextKeyLog).(logrus.FieldLogger); ok {
		return l
	}
	return logrus.StandardLogger()
}
