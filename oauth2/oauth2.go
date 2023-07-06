package oauth2

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
	"golang.org/x/oauth2"
)

type Config struct {
	oauth2.Config

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
		ProcessorConfig: &tokenizer.OAuthProcessorConfig{
			Token: &tokenizer.OAuthToken{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken},
		},
		RequestValidators: p.requestValidators,
	}

	sealed, err := secret.Seal(p.sealKey)
	if err != nil {
		logrus.WithError(err).Warn("failed seal")
		tr.ReturnError(w, r, "seal error")
		return
	}

	tr.ReturnData(w, r, map[string]string{
		"data":    sealed, // remove this
		"sealed":  sealed,
		"expires": strconv.FormatInt(tok.Expiry.Unix(), 10),
	})
}

func (p *provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		logrus.Warn("refresh: missing token")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tok, err := p.TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		logrus.WithError(err).Warn("refresh")
		w.WriteHeader(http.StatusBadGateway)
		return
	}

	secret := &tokenizer.Secret{
		AuthConfig: tokenizer.NewBearerAuthConfig(p.rpAuth),
		ProcessorConfig: &tokenizer.OAuthProcessorConfig{
			Token: &tokenizer.OAuthToken{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
			},
		},
		RequestValidators: p.requestValidators,
	}

	sealed, err := secret.Seal(p.sealKey)
	if err != nil {
		logrus.WithError(err).Warn("refresh: failed seal")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", time.Until(tok.Expiry)/time.Second))

	if _, err := w.Write([]byte(sealed)); err != nil {
		// status already written
		logrus.WithError(err).Warn("refresh: write response")
		return
	}
}
