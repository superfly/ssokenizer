package ssokenizer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/url"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	transactionCookieName = "transaction"
	transactionTTL        = time.Hour
)

type Transaction struct {
	ReturnState string
	Nonce       string
	Expiry      time.Time
	returnURL   *url.URL
	cookiePath  string
}

func (t *Transaction) ReturnData(w http.ResponseWriter, r *http.Request, data map[string]string) {
	t.returnData(w, r, data)
}

func (t *Transaction) ReturnError(w http.ResponseWriter, r *http.Request, msg string) {
	t.returnData(w, r, map[string]string{"error": msg})
}

func (t *Transaction) returnData(w http.ResponseWriter, r *http.Request, data map[string]string) {
	t.setCookie(w, r, "")

	returnURL := *t.returnURL
	q := returnURL.Query()

	for k, v := range data {
		q.Set(k, v)
	}

	if t.ReturnState != "" {
		q.Set("state", t.ReturnState)
	}

	returnURL.RawQuery = q.Encode()
	http.Redirect(w, r, returnURL.String(), http.StatusFound)
}

func unmarshalTransaction(t *Transaction, s string) error {
	m, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return err
	}

	return msgpack.Unmarshal(m, t)
}

func (t *Transaction) marshal() (string, error) {
	m, err := msgpack.Marshal(t)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(m), nil
}

func (t *Transaction) setCookie(w http.ResponseWriter, r *http.Request, v string) {
	tls := r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"

	var maxAge int
	if v == "" {
		maxAge = -1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     transactionCookieName,
		Value:    v,
		Path:     t.cookiePath,
		Secure:   tls,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
