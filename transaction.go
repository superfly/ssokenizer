package ssokenizer

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	transactionCookieName = "transaction"
	transactionTTL        = time.Hour
)

// State about the user's SSO attempt that is stored as a cookie. Cookies are
// set with per-provider paths to prevent transactions from different providers
// from interfering with each other.
type Transaction struct {
	// Random state string that will be returned in our redirect to the relying
	//  party. This is used to prevent login-CSRF attacks.
	ReturnState string

	// Random string that provider implementations can use as the state
	// parameter for downstream SSO flows.
	Nonce string

	// Time after which this transaction cookie will be ignored.
	Expiry time.Time
}

// Return the user to the returnURL with the provided data set as query string
// parameters.
func (t *Transaction) ReturnData(w http.ResponseWriter, r *http.Request, data map[string]string) {
	t.returnData(w, r, data)
}

// Return the user to the returnURL with the provided msg set in the `error`
// query string parameter.
func (t *Transaction) ReturnError(w http.ResponseWriter, r *http.Request, msg string) {
	t.returnData(w, r, map[string]string{"error": msg})
}

func (t *Transaction) returnData(w http.ResponseWriter, r *http.Request, data map[string]string) {
	defer GetLog(r).WithField("status", http.StatusFound).Info()

	t.setCookie(w, r, "")

	// important that this is a copy!
	returnURL := getProvider(r).PC().ReturnURL
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

func StartTransaction(w http.ResponseWriter, r *http.Request) *Transaction {
	t := &Transaction{
		ReturnState: r.URL.Query().Get("state"),
		Nonce:       randHex(16),
		Expiry:      time.Now().Add(transactionTTL),
	}

	ts, err := t.marshal()
	if err != nil {
		r = WithError(r, fmt.Errorf("marshal transaction cookie: %w", err))
		t.ReturnError(w, r, "unexpected error")
		return nil
	}

	t.setCookie(w, r, ts)
	return t
}

func RestoreTransaction(w http.ResponseWriter, r *http.Request) *Transaction {
	var t Transaction

	tc, err := r.Cookie(transactionCookieName)
	if err != nil || tc.Value == "" {
		r = WithError(r, fmt.Errorf("missing transaction cookie: %w", err))
		t.ReturnError(w, r, "bad request")
		return nil
	}

	if err := unmarshalTransaction(&t, tc.Value); err != nil {
		r = WithError(r, fmt.Errorf("bad transaction cookie: %w", err))
		t.ReturnError(w, r, "bad request")
		return nil
	}

	if time.Now().After(t.Expiry) {
		r = WithError(r, errors.New("expired transaction"))
		t.ReturnError(w, r, "expired")
		return nil
	}

	return &t
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
	providerURL := &getProvider(r).PC().URL

	var maxAge int
	if v == "" {
		maxAge = -1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     transactionCookieName,
		Value:    v,
		Path:     providerURL.Path,
		Secure:   strings.EqualFold(providerURL.Scheme, "https"),
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
