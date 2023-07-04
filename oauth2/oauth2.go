package oauth2

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
	"golang.org/x/oauth2"
)

type Config struct {
	oauth2.Config

	// Where tokenizer should request refreshes
	// (https://ssokenizer/<name>/refresh)
	RefreshURL string

	// Request validators to add to the tokenizer secret. This allows limiting
	// what hosts the secret can be used with.
	RequestValidators []tokenizer.RequestValidator
}

var _ ssokenizer.ProviderConfig = Config{}

func (c Config) Register(sealKey string, rpAuth string) (http.Handler, error) {
	switch {
	case c.ClientID == "":
		return nil, errors.New("missing client_id")
	case c.ClientSecret == "":
		return nil, errors.New("missing client_secret")
	case c.ClientSecret == "":
		return nil, errors.New("missing refresh_url")
	}

	return &provider{
		sealKey:           sealKey,
		rpAuth:            rpAuth,
		requestValidators: c.RequestValidators,
		Config:            c,
	}, nil
}

type provider struct {
	sealKey           string
	rpAuth            string
	requestValidators []tokenizer.RequestValidator
	Config
}

const (
	startPath    = "/start"
	callbackPath = "/callback"
	refreshPath  = "/refresh"
)

func (p *provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch path := strings.TrimSuffix(r.URL.Path, "/"); path {
	case startPath:
		p.handleStart(w, r)
	case callbackPath:
		p.handleCallback(w, r)
	case refreshPath:
		p.handleRefresh(w, r)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (p *provider) handleStart(w http.ResponseWriter, r *http.Request) {
	tr, ok := ssokenizer.GetTransaction(r)
	if !ok {
		logrus.Warn("no transaction for request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, p.AuthCodeURL(tr.Nonce, oauth2.AccessTypeOffline), http.StatusFound)
}

func (p *provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	tr, ok := ssokenizer.GetTransaction(r)
	if !ok {
		logrus.Warn("no transaction for request")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	params := r.URL.Query()

	if errParam := params.Get("error"); errParam != "" {
		tr.ReturnError(w, r, errParam)
		return
	}

	state := params.Get("state")
	if state == "" {
		logrus.Warn("missing state")
		tr.ReturnError(w, r, "bad response")
		return
	}

	if subtle.ConstantTimeCompare([]byte(tr.Nonce), []byte(state)) != 1 {
		logrus.WithFields(logrus.Fields{"have": state, "want": tr.Nonce}).Warn("bad state")
		tr.ReturnError(w, r, "bad response")
		return
	}

	code := params.Get("code")
	if code == "" {
		logrus.Warn("missing code")
		tr.ReturnError(w, r, "bad response")
		return
	}

	tok, err := p.Exchange(r.Context(), code, oauth2.AccessTypeOffline)
	if err != nil {
		logrus.WithError(err).Warn("failed exchange")
		tr.ReturnError(w, r, "bad response")
		return
	}

	secret := &tokenizer.Secret{
		AuthConfig: tokenizer.NewBearerAuthConfig(p.rpAuth),
		ProcessorConfig: &tokenizer.OAuth2ProcessorConfig{
			RefreshURL: p.RefreshURL,
			Token:      tok,
		},
		RequestValidators: p.requestValidators,
	}

	sealed, err := secret.Seal(p.sealKey)
	if err != nil {
		logrus.WithError(err).Warn("failed seal")
		tr.ReturnError(w, r, "seal error")
		return
	}

	tr.ReturnData(w, r, sealed)
}

func (p *provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	t := new(oauth2.Token)
	if err := json.NewDecoder(r.Body).Decode(t); err != nil {
		logrus.WithError(err).Warn("decode refresh request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ret, err := p.TokenSource(r.Context(), t).Token()
	if err != nil {
		logrus.WithError(err).Warn("do refresh")
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	if err := json.NewEncoder(w).Encode(ret); err != nil {
		logrus.WithError(err).Warn("write response")
		// status already written
		return
	}
}
