package google

import (
	"regexp"

	"github.com/gorilla/mux"
	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	"github.com/superfly/tokenizer"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Config struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURL  string
	RefreshURL   string
}

var _ ssokenizer.ProviderConfig = Config{}

var googleApisDotComRegexp = regexp.MustCompile(`\.googleapis.com$`)

func (c Config) Register(r *mux.Router, sealKey, rpAuth string) error {
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
	}).Register(r, sealKey, rpAuth)
}
