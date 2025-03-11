package musickit

import (
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/http"

	"github.com/sirupsen/logrus"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/tokenizer"
)

var (
	//go:embed templates/start.html
	startHTML     string
	startTemplate = template.Must(template.New("start").Parse(startHTML))

	//go:embed static/*
	statics embed.FS
)

type Provider struct {
	ssokenizer.ProviderConfig
	DeveloperToken string
}

var _ ssokenizer.Provider = (*Provider)(nil)

func (p *Provider) PC() *ssokenizer.ProviderConfig {
	return &p.ProviderConfig
}

func (p *Provider) Validate() error {
	switch err := p.ProviderConfig.Validate(); {
	case err != nil:
		return err
	case p.DeveloperToken == "":
		return errors.New("missing developer token")
	default:
		return nil
	}
}

func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m := http.NewServeMux()
	m.Handle("GET /static/", http.FileServer(http.FS(statics)))
	m.HandleFunc("GET /start", p.handleStart)
	m.HandleFunc("POST /callback", p.handleCallback)

	m.ServeHTTP(w, r)
}

func (p *Provider) handleStart(w http.ResponseWriter, r *http.Request) {
	tr := ssokenizer.StartTransaction(w, r)
	if tr == nil {
		return
	}

	td := struct {
		DeveloperToken string
		State          string
	}{p.DeveloperToken, tr.Nonce}

	if err := startTemplate.Execute(w, &td); err != nil {
		getLog(r).WithError(err).Error("failed to execute start template")
	}
}

func (p *Provider) handleCallback(w http.ResponseWriter, r *http.Request) {
	tr := ssokenizer.RestoreTransaction(w, r)
	if tr == nil {
		return
	}

	state := r.FormValue("state")
	if state == "" {
		r = withError(r, errors.New("missing state"))
		tr.ReturnError(w, r, "missing state")
		return
	}

	if subtle.ConstantTimeCompare([]byte(tr.Nonce), []byte(state)) != 1 {
		r = withError(r, errors.New("bad state"))
		r = withFields(r, logrus.Fields{"have": state, "want": tr.Nonce})
		tr.ReturnError(w, r, "bad response")
		return
	}

	token := r.FormValue("token")
	if token == "" {
		r = withError(r, errors.New("missing token"))
		tr.ReturnError(w, r, "missing token")
		return
	}

	sealed, err := p.Tokenizer.SealedSecret(&tokenizer.MultiProcessorConfig{
		&tokenizer.InjectProcessorConfig{
			Token: p.DeveloperToken,
			DstProcessor: tokenizer.DstProcessor{
				Dst: "Authorization",
			},
			FmtProcessor: tokenizer.FmtProcessor{
				Fmt: "Bearer %s",
			},
		},
		&tokenizer.InjectProcessorConfig{
			Token: token,
			DstProcessor: tokenizer.DstProcessor{
				Dst: "Music-User-Token",
			},
			FmtProcessor: tokenizer.FmtProcessor{
				Fmt: "%s",
			},
		},
	})
	if err != nil {
		r = withError(r, fmt.Errorf("failed seal: %w", err))
		tr.ReturnError(w, r, "seal error")
		return
	}

	tr.ReturnData(w, r, map[string]string{"sealed": sealed})
}

// logging helpers. aliased for convenience
var (
	getLog     = ssokenizer.GetLog
	withError  = ssokenizer.WithError
	withFields = ssokenizer.WithFields
)
