package ssokenizer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
	"golang.org/x/exp/slices"
)

const (
	transactionCookieName = "transaction"
	transactionTTL        = time.Hour
	returnToParam         = "return_to"
)

type Transaction struct {
	ReturnTo    string    `json:"return_to"`
	ReturnState string    `json:"return_state"`
	Nonce       string    `json:"nonce"`
	Expiry      time.Time `json:"expiry"`
}

func (t *Transaction) ReturnData(w http.ResponseWriter, r *http.Request, data string) {
	t.returnDataOrError(w, r, &data, nil)
}

func (t *Transaction) ReturnError(w http.ResponseWriter, r *http.Request, msg string) {
	t.returnDataOrError(w, r, nil, &msg)
}

func (t *Transaction) returnDataOrError(w http.ResponseWriter, r *http.Request, data *string, errorMsg *string) {
	clearTransactionCookie(w)

	u, err := url.Parse(t.ReturnTo)
	if err != nil {
		logrus.WithError(err).Warn("bad return to")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	q := u.Query()

	if data != nil {
		q.Set("data", *data)
	}
	if errorMsg != nil {
		q.Set("error", *errorMsg)
	}
	if t.ReturnState != "" {
		q.Set("state", t.ReturnState)
	}

	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func transactionMiddleware(tls bool, allowedReturnTo []string) mux.MiddlewareFunc {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var t *Transaction

			params := r.URL.Query()

			badRequest := func() {
				clearTransactionCookie(w)
				http.Error(w, "bad request", http.StatusBadRequest)
			}

			if rt := params.Get(returnToParam); rt != "" {
				logrus.Debug("new transaction: return_to in query")
				if !slices.Contains(allowedReturnTo, rt) {
					logrus.WithField("return_to", rt).Warn("non allowed return_to param")
					badRequest()
					return
				}

				t = &Transaction{
					ReturnTo:    rt,
					ReturnState: params.Get("state"),
					Expiry:      time.Now().Add(transactionTTL),
					Nonce:       randHex(16),
				}
			} else if tc, err := r.Cookie(transactionCookieName); err != http.ErrNoCookie {
				logrus.Debug("old transaction: found cookie")
				mpt, err := base64.StdEncoding.DecodeString(tc.Value)
				if err != nil {
					logrus.WithError(err).Warn("bad transaction cookie b64")
					badRequest()
				}

				t = new(Transaction)
				if err = msgpack.Unmarshal(mpt, t); err != nil {
					logrus.WithError(err).Warn("bad transaction cookie msgpack")
					badRequest()
					return
				}

				if time.Now().After(t.Expiry) {
					logrus.Warn("expired transaction")
					t.ReturnError(w, r, "expired")
					return
				}
			} else {
				logrus.Debug("new transaction: default return-to")
				// first rt is default
				t = &Transaction{
					ReturnTo:    allowedReturnTo[0],
					ReturnState: params.Get("state"),
					Expiry:      time.Now().Add(transactionTTL),
					Nonce:       randHex(16),
				}
			}

			mpt, err := msgpack.Marshal(t)
			if err != nil {
				logrus.WithError(err).Warn("marshal transaction cookie")
				w.WriteHeader(http.StatusInternalServerError)
				return
			}

			http.SetCookie(w, &http.Cookie{
				Name:     transactionCookieName,
				Value:    base64.StdEncoding.EncodeToString(mpt),
				Secure:   tls,
				HttpOnly: true,
				SameSite: http.SameSiteLaxMode,
			})

			r = r.WithContext(withTransaction(r.Context(), t))

			next.ServeHTTP(w, r)
		})
	}
}

func clearTransactionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: transactionCookieName, Value: "", MaxAge: -1})
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
