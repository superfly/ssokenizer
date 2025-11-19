package oauth2

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
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

type Provider struct {
	ssokenizer.ProviderConfig
	OAuthConfig oauth2.Config

	// ForwardParams are the parameters that should be forwarded from the start
	// request to the auth URL.
	ForwardParams []string

	// Params to add to the auth request.
	AuthRequestParams map[string]string

	// Params to add to the token request.
	TokenRequestParams map[string]string
}

var _ ssokenizer.Provider = (*Provider)(nil)

const (
	startPath    = "/start"
	callbackPath = "/callback"
	refreshPath  = "/refresh"
)

// PC implements the ssokenizer.Provider interface.
func (p *Provider) PC() *ssokenizer.ProviderConfig {
	return &p.ProviderConfig
}

// Validate implements the ssokenizer.Provider interface.
func (p *Provider) Validate() error {
	switch err := p.ProviderConfig.Validate(); {
	case err != nil:
		return err
	case p.OAuthConfig.ClientID == "":
		return errors.New("missing client_id")
	case p.OAuthConfig.ClientSecret == "":
		return errors.New("missing client_secret")
	case p.OAuthConfig.Endpoint.AuthURL == "":
		return errors.New("missing auth_url")
	case p.OAuthConfig.Endpoint.TokenURL == "":
		return errors.New("missing token_url")
	default:
		return nil
	}
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

func (p *Provider) handleStart(w http.ResponseWriter, r *http.Request) {
	defer getLog(r).WithField("status", http.StatusFound).Info()

	tr := ssokenizer.StartTransaction(w, r)
	if tr == nil {
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	for _, param := range p.ForwardParams {
		if value := r.URL.Query().Get(param); value != "" {
			opts = append(opts, oauth2.SetAuthURLParam(param, value))
		}
	}

	for key, value := range p.AuthRequestParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	if p.OAuthConfig.RedirectURL == "" {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", p.URL.JoinPath(callbackPath).String()))
	}

	url := p.OAuthConfig.AuthCodeURL(tr.Nonce, opts...)
	http.Redirect(w, r, url, http.StatusFound)
}

func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	tr := ssokenizer.RestoreTransaction(w, r)
	if tr == nil {
		return
	}
	params := r.URL.Query()

	if errParam := params.Get("error"); errParam != "" {
		r = withError(r, fmt.Errorf("error param: %s", errParam))
		tr.ReturnError(w, r, errParam)
		return
	}

	state := params.Get("state")
	if state == "" {
		r = withError(r, errors.New("missing state"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	if subtle.ConstantTimeCompare([]byte(tr.Nonce), []byte(state)) != 1 {
		r = withError(r, errors.New("bad state"))
		r = withFields(r, logrus.Fields{"have": state, "want": tr.Nonce})
		tr.ReturnError(w, r, "bad response")
		return
	}

	code := params.Get("code")
	if code == "" {
		r = withError(r, errors.New("missing code"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	for key, value := range p.TokenRequestParams {
		opts = append(opts, oauth2.SetAuthURLParam(key, value))
	}

	if p.OAuthConfig.RedirectURL == "" {
		opts = append(opts, oauth2.SetAuthURLParam("redirect_uri", p.URL.JoinPath(callbackPath).String()))
	}

	tok, err := p.OAuthConfig.Exchange(r.Context(), code, opts...)
	if err != nil {
		r = withError(r, fmt.Errorf("failed exchange: %w", err))
		tr.ReturnError(w, r, "bad response")
		return
	}

	r = withIdToken(r, tok)

	if t := tok.Type(); t != "Bearer" {
		r = withField(r, "type", t)
		r = withError(r, errors.New("unrecognized token type"))
		tr.ReturnError(w, r, "bad response")
		return
	}

	sealed, err := p.Tokenizer.SealedSecret(&tokenizer.OAuthProcessorConfig{
		Token: &tokenizer.OAuthToken{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken},
	})
	if err != nil {
		r = withError(r, fmt.Errorf("failed seal: %w", err))
		tr.ReturnError(w, r, "seal error")
		return
	}

	tr.ReturnData(w, r, map[string]string{
		"sealed":  sealed,
		"expires": strconv.FormatInt(tok.Expiry.Unix(), 10),
	})
}

func (p *Provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		getLog(r).
			WithField("status", http.StatusUnauthorized).
			Info("refresh: missing token")

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tok, err := p.OAuthConfig.TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshToken}).Token()
	if err != nil {
		getLog(r).
			WithField("status", http.StatusBadGateway).
			WithError(err).
			Info("refresh")

		w.WriteHeader(http.StatusBadGateway)
		return
	}

	r = withIdToken(r, tok)

	if t := tok.Type(); t != "Bearer" {
		getLog(r).
			WithField("status", http.StatusInternalServerError).
			WithField("type", t).
			Info("unrecognized token type")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	sealed, err := p.Tokenizer.SealedSecret(&tokenizer.OAuthProcessorConfig{
		Token: &tokenizer.OAuthToken{
			AccessToken:  tok.AccessToken,
			RefreshToken: tok.RefreshToken,
		},
	})
	if err != nil {
		getLog(r).
			WithField("status", http.StatusInternalServerError).
			WithError(err).
			Info("refresh: failed seal")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Cache-Control", fmt.Sprintf("private, max-age=%d", time.Until(tok.Expiry)/time.Second))

	if _, err := w.Write([]byte(sealed)); err != nil {
		// status already written
		getLog(r).
			WithError(err).
			Info("refresh: write response")

		return
	}

	getLog(r).
		WithField("status", http.StatusOK).
		Info()
}

// logging helpers. aliased for convenience
var (
	getLog     = ssokenizer.GetLog
	withError  = ssokenizer.WithError
	withField  = ssokenizer.WithField
	withFields = ssokenizer.WithFields
)

// logging helper. Tries to find and parse user info from id token.
func withIdToken(r *http.Request, tok *oauth2.Token) *http.Request {
	idToken, ok := tok.Extra("id_token").(string)
	if !ok {
		return r
	}

	parts := strings.Split(idToken, ".")
	if len(parts) < 2 {
		return r
	}

	jbody, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return r
	}

	var body struct {
		Sub   string `json:"sub"`
		HD    string `json:"hd"`
		Email string `json:"email"`
	}
	if err := json.Unmarshal(jbody, &body); err != nil {
		return r
	}

	if body.Sub != "" {
		r = withField(r, "sub", body.Sub)
	}
	if body.HD != "" {
		r = withField(r, "hd", body.HD)
	}
	if body.Email != "" {
		r = withField(r, "email", body.Email)
	}

	return r
}
