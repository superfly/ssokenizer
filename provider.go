package ssokenizer

import (
	"context"
	"errors"
	"net/http"
	"net/url"

	"github.com/superfly/tokenizer"
)

type ProviderRegistry interface {
	Get(ctx context.Context, name string) (Provider, error)
}

type StaticProviderRegistry map[string]Provider

var ErrProviderNotFound = errors.New("provider not found")

func (r StaticProviderRegistry) Get(ctx context.Context, name string) (Provider, error) {
	if p, ok := r[name]; ok {
		return p, nil
	}

	return nil, ErrProviderNotFound
}

type Provider interface {
	http.Handler
	Validate() error
	PC() *ProviderConfig
}

type ProviderConfig struct {
	Tokenizer TokenizerConfig

	// URL is the full URL where this provider is served from.
	URL url.URL

	// ReturnURL is the URL that the provider should redirect to after
	// authenticating the user.
	ReturnURL url.URL
}

func (p *ProviderConfig) Validate() error {
	switch err := p.Tokenizer.Validate(); {
	case err != nil:
		return err
	case !isFullURL(&p.URL):
		return errors.New("missing provider URL")
	case !isFullURL(&p.ReturnURL):
		return errors.New("missing return URL")
	default:
		return nil
	}
}

func isFullURL(u *url.URL) bool {
	return u.Scheme != "" && u.Host != ""
}

type TokenizerConfig struct {
	// SealKey is the key we encrypt tokens to.
	SealKey string

	// Auth specifies the auth requires to use the sealed token.
	Auth tokenizer.AuthConfig

	// RequestValidators specifies validations that tokenizer should run on
	// requests before unsealing/adding token. Eg. limit what hosts the token
	// can be sent to.
	RequestValidators []tokenizer.RequestValidator
}

func (t *TokenizerConfig) SealedSecret(processor tokenizer.ProcessorConfig) (string, error) {
	secret := tokenizer.Secret{
		AuthConfig:        t.Auth,
		ProcessorConfig:   processor,
		RequestValidators: t.RequestValidators,
	}

	return secret.Seal(t.SealKey)
}

func (t *TokenizerConfig) Validate() error {
	switch {
	case t.SealKey == "":
		return errors.New("missing tokenizer seal key")
	case t.Auth == nil:
		return errors.New("missing tokenizer auth config")
	default:
		return nil
	}
}
