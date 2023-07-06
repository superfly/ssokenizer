package google

import (
	"net/http"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	// OAuth Client ID
	ClientID string

	// OAuth Client secret
	ClientSecret string

	// OAuth scopes to request
	Scopes []string

	// Where Google should return the user after consent-check
	// (https://ssokenizer/<name>/callback)
	RedirectURL string
}

var _ ssokenizer.ProviderConfig = Config{}

func (c Config) Register(sealKey, rpAuth string) (http.Handler, error) {
	return (&oauth2.Config{
		Config: xoauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  c.RedirectURL,
		},
	}).Register(sealKey, rpAuth)
}
