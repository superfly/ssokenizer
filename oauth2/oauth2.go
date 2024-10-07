package oauth2

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
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

	// Path where this provider is mounted
	Path string

	// Regexp of hosts that oauth tokens are allowed to be used with. There is
	// no need to anchor regexes.
	AllowedHostPattern string
}

var _ ssokenizer.ProviderConfig = Config{}

// implements ssokenizer.ProviderConfig
func (c Config) Register(sealKey string, auth tokenizer.AuthConfig) (http.Handler, error) {
	switch {
	case c.ClientID == "":
		return nil, errors.New("missing client_id")
	case c.ClientSecret == "":
		return nil, errors.New("missing client_secret")
	}

	return &provider{
		sealKey:                  sealKey,
		auth:                     auth,
		AllowedHostPattern:       c.AllowedHostPattern,
		configWithoutRedirectURL: c,
	}, nil
}

type provider struct {
	sealKey                  string
	auth                     tokenizer.AuthConfig
	AllowedHostPattern       string
	configWithoutRedirectURL Config
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
	defer getLog(r).WithField("status", http.StatusFound).Info()

	tr := ssokenizer.StartTransaction(w, r)
	if tr == nil {
		return
	}

	opts := []oauth2.AuthCodeOption{oauth2.AccessTypeOffline}

	if hd := r.URL.Query().Get("hd"); hd != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", hd))
	}

	http.Redirect(w, r, p.config(r).AuthCodeURL(tr.Nonce, opts...), http.StatusFound)
}

func (p *provider) handleCallback(w http.ResponseWriter, r *http.Request) {
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

	tok, err := p.config(r).Exchange(r.Context(), code, oauth2.AccessTypeOffline)
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

	secret := &tokenizer.Secret{
		AuthConfig: p.auth,
		ProcessorConfig: &tokenizer.OAuthProcessorConfig{
			Token: &tokenizer.OAuthToken{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken},
		},
		RequestValidators: p.requestValidators(r),
	}

	sealed, err := secret.Seal(p.sealKey)
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

func (p *provider) handleRefresh(w http.ResponseWriter, r *http.Request) {
	refreshToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		getLog(r).
			WithField("status", http.StatusUnauthorized).
			Info("refresh: missing token")

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tok, err := p.config(r).TokenSource(r.Context(), &oauth2.Token{RefreshToken: refreshToken}).Token()
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

	secret := &tokenizer.Secret{
		AuthConfig: p.auth,
		ProcessorConfig: &tokenizer.OAuthProcessorConfig{
			Token: &tokenizer.OAuthToken{
				AccessToken:  tok.AccessToken,
				RefreshToken: tok.RefreshToken,
			},
		},
		RequestValidators: p.requestValidators(r),
	}

	sealed, err := secret.Seal(p.sealKey)
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

func (p *provider) config(r *http.Request) *Config {
	scheme := "http://"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https://"
	}
	cfg := p.configWithoutRedirectURL
	cfg.RedirectURL = scheme + r.Host + cfg.Path + callbackPath

	return &cfg
}

func (p *provider) requestValidators(r *http.Request) []tokenizer.RequestValidator {
	if p.AllowedHostPattern == "" {
		return nil
	}
	// clients need to be able to send refresh tokens to ssokenizer itself, so
	// we add ourself to the allowed-host pattern.
	re := regexp.MustCompile(fmt.Sprintf("^(%s|%s)$", regexp.QuoteMeta(r.Host), p.AllowedHostPattern))
	return []tokenizer.RequestValidator{tokenizer.AllowHostPattern(re)}
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
