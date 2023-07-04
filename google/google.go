package google

import (
	"net/http"
	"regexp"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	"github.com/superfly/tokenizer"
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

	// Where tokenizer should request refreshes
	// (https://ssokenizer/<name>/refresh)
	RefreshURL string
}

var _ ssokenizer.ProviderConfig = Config{}

var googleApisDotComRegexp = regexp.MustCompile(`\.googleapis.com$`)

func (c Config) Register(sealKey, rpAuth string) (http.Handler, error) {
	return (&oauth2.Config{
		Config: xoauth2.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			Endpoint:     google.Endpoint,
			RedirectURL:  c.RedirectURL,
		},
		RefreshURL: c.RefreshURL,
		RequestValidators: []tokenizer.RequestValidator{
			tokenizer.AllowHostPattern(googleApisDotComRegexp),
		},
	}).Register(sealKey, rpAuth)
}
