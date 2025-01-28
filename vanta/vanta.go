package vanta

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	xoauth2 "golang.org/x/oauth2"
)

const (
	invalidatePath = "/invalidate"
	invalidateURL  = "https://api.vanta.com/v1/oauth/token/suspend"
)

type Provider struct {
	oauth2.Provider
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSuffix(r.URL.Path, "/") != invalidatePath {
		p.Provider.ServeHTTP(w, r)
		return
	}

	var (
		ctx = r.Context()
		log = ssokenizer.GetLog(r)
	)

	accessToken, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		log.WithField("status", http.StatusUnauthorized).
			Info("invalidate: missing token")

		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	tok, err := p.OAuthConfig.TokenSource(ctx, &xoauth2.Token{AccessToken: accessToken}).Token()
	if err != nil {
		log.WithField("status", http.StatusForbidden).
			WithError(err).
			Info("invalidate: failed to get token")

		w.WriteHeader(http.StatusForbidden)
		return
	}

	if typ := tok.Type(); typ != "Bearer" {
		log.WithField("status", http.StatusForbidden).
			WithField("type", typ).
			WithError(err).
			Info("invalidate: bad token type")

		w.WriteHeader(http.StatusForbidden)
		return
	}

	body, err := json.Marshal(map[string]string{
		"token":         tok.AccessToken,
		"client_id":     p.OAuthConfig.ClientID,
		"client_secret": p.OAuthConfig.ClientSecret,
	})
	if err != nil {
		log.WithField("status", http.StatusInternalServerError).
			WithError(err).
			Info("invalidate: marshal json")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, invalidateURL, bytes.NewBuffer(body))
	if err != nil {
		log.WithField("status", http.StatusInternalServerError).
			WithError(err).
			Info("invalidate: make request")

		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client := http.Client{Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		log.WithField("status", http.StatusServiceUnavailable).
			WithError(err).
			Info("invalidate: send request")

		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}

	log.WithField("status", resp.Status).
		Info("invalidate: success")
}
