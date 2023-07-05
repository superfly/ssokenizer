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
	ReturnState string    `json:"return_state"`
	Nonce       string    `json:"nonce"`
	Expiry      time.Time `json:"expiry"`
	returnURL   *url.URL
	cookiePath  string
}

func (t *Transaction) ReturnData(w http.ResponseWriter, r *http.Request, data string) {
	t.returnDataOrError(w, r, &data, nil)
}

func (t *Transaction) ReturnError(w http.ResponseWriter, r *http.Request, msg string) {
	t.returnDataOrError(w, r, nil, &msg)
}

func (t *Transaction) returnDataOrError(w http.ResponseWriter, r *http.Request, data *string, errorMsg *string) {
	t.setCookie(w, r, "")

	returnURL := *t.returnURL
	q := returnURL.Query()

	if data != nil {
		q.Set("data", *data)
	}
	if errorMsg != nil {
		q.Set("error", *errorMsg)
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

	if err = msgpack.Unmarshal(m, t); err != nil {
		return err
	}

	return nil
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
