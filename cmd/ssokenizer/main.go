package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/oauth2"
	"github.com/superfly/ssokenizer/vanta"
	"github.com/superfly/tokenizer"
	xoauth2 "golang.org/x/oauth2"
	"golang.org/x/oauth2/amazon"
	"golang.org/x/oauth2/bitbucket"
	"golang.org/x/oauth2/facebook"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/gitlab"
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/heroku"
	"golang.org/x/oauth2/microsoft"
	"golang.org/x/oauth2/slack"
	"gopkg.in/yaml.v3"
)

var (
	Version string
	Commit  string
)

func main() {
	if err := Run(context.Background(), os.Args[1:]); err == flag.ErrHelp {
		os.Exit(2)
	} else if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err)
		os.Exit(1)
	}
}

// Run is the main entry into the binary execution.
func Run(ctx context.Context, args []string) error {
	fmt.Println(VersionString())

	// Extract command name.
	var cmd string
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "serve":
		return NewServeCommand().Run(args)
	case "version":
		fmt.Println(VersionString())
		return nil

	default:
		if cmd == "" || cmd == "help" || strings.HasPrefix(cmd, "-") {
			printUsage()
			return flag.ErrHelp
		}
		return fmt.Errorf("ssokenizer %s: unknown command", cmd)
	}
}

type Config struct {
	// Tokenizer seal (public) key
	SealKey string `yaml:"seal_key"`

	// Where to return user after auth dance. If present, the string `:name` is
	// replaced with the provider name. Can also be specified per-provider.
	ReturnURL string `yaml:"return_url"`

	SecretAuth        SecretAuthConfig                  `yaml:"secret_auth"`
	Log               LogConfig                         `yaml:"log"`
	HTTP              HTTPConfig                        `yaml:"http"`
	IdentityProviders map[string]IdentityProviderConfig `yaml:"identity_providers"`
}

// Specifies what authentication clients should be required to present to
// tokenizer in order to use sealed secrets.
type SecretAuthConfig struct {
	// The plain string that clients must pass in the Proxy-Authorization
	// header.
	Bearer string `yaml:"bearer"`

	// Hex SHA256 digest of string that clients must pass in the
	// Proxy-Authorization header.
	BearerDigest string `yaml:"bearer_digest"`
}

func (c SecretAuthConfig) tokenizerAuthConfig() (tokenizer.AuthConfig, error) {
	switch {
	case c.Bearer != "" && c.BearerDigest != "":
		return nil, errors.New("bearer and bearer_digest are mutually exclusive")
	case c.Bearer != "":
		return tokenizer.NewBearerAuthConfig(c.Bearer), nil
	case c.BearerDigest != "":
		d, err := hex.DecodeString(c.BearerDigest)
		if err != nil {
			return nil, err
		}
		return &tokenizer.BearerAuthConfig{Digest: d}, nil
	default:
		return nil, nil
	}
}

// NewConfig returns a new instance of Config with defaults set.
func NewConfig() Config {
	var config Config
	return config
}

// Validate returns an error if the config is invalid.
func (c *Config) Validate() error {
	tac, err := c.SecretAuth.tokenizerAuthConfig()
	if err != nil {
		return err
	}

	if c.SealKey == "" {
		return errors.New("missing seal_key")
	}
	if c.HTTP.Address == "" {
		return errors.New("missing http.address")
	}
	for _, pc := range c.IdentityProviders {
		if err := pc.Validate(c.ReturnURL == "", tac == nil); err != nil {
			return err
		}
	}
	return nil
}

type LogConfig struct {
	Debug bool `yaml:"debug"`
}

type HTTPConfig struct {
	// address for http server to listen on
	Address string `yaml:"address"`
}

type IdentityProviderConfig struct {
	// idb profile name (e.g. google)
	Profile string `yaml:"profile"`

	// oauth client ID
	ClientID string `yaml:"client_id"`

	// oauth client secret
	ClientSecret string `yaml:"client_secret"`

	// oauth scopes to request. Can be specified as a space-separated list of strings.
	Scopes []string `yaml:"scopes"`

	// Where to return user after auth dance. Can also be specified globally.
	ReturnURL string `yaml:"return_url"`

	// oauth authorization endpoint URL. Only needed for "oauth" profile
	AuthURL string `yaml:"auth_url"`

	// oauth token endpoint URL. Only needed for "oauth" profile
	TokenURL string `yaml:"token_url"`

	SecretAuth SecretAuthConfig `yaml:"secret_auth"`
}

func (c IdentityProviderConfig) providerConfig(name, returnURL string) (ssokenizer.ProviderConfig, error) {
	switch c.Profile {
	case "vanta":
		return &vanta.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint: xoauth2.Endpoint{
					AuthURL:   "https://app.vanta.com/oauth/authorize",
					TokenURL:  "https://api.vanta.com/oauth/token",
					AuthStyle: xoauth2.AuthStyleInParams,
				},
			},
			ForwardParams: []string{"source_id"},
		}, nil
	case "oauth":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint: xoauth2.Endpoint{
					AuthURL:  c.AuthURL,
					TokenURL: c.TokenURL,
				},
			},
		}, nil
	case "amazon":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     amazon.Endpoint,
			},
		}, nil
	case "bitbucket":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     bitbucket.Endpoint,
			},
		}, nil
	case "facebook":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     facebook.Endpoint,
			},
		}, nil
	case "github":
		return &oauth2.Config{
			Path:               "/" + name,
			AllowedHostPattern: `api\.github\.com`,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     github.Endpoint,
			},
		}, nil
	case "gitlab":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     gitlab.Endpoint,
			},
		}, nil
	case "google":
		return &oauth2.Config{
			Path:               "/" + name,
			AllowedHostPattern: `.*\.googleapis\.com`,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     google.Endpoint,
			},
			ForwardParams: []string{"hd"},
		}, nil
	case "heroku":
		return &oauth2.Config{
			Path:               "/" + name,
			AllowedHostPattern: `api\.heroku\.com`,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     heroku.Endpoint,
			},
		}, nil
	case "microsoft":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     microsoft.LiveConnectEndpoint,
			},
		}, nil
	case "slack":
		return &oauth2.Config{
			Path: "/" + name,
			Config: xoauth2.Config{
				ClientID:     c.ClientID,
				ClientSecret: c.ClientSecret,
				Scopes:       c.Scopes,
				Endpoint:     slack.Endpoint,
			},
		}, nil
	default:
		return nil, fmt.Errorf("unknown identity provider profile: %s", c.Profile)
	}
}

func (c IdentityProviderConfig) Validate(needsReturnURL, needsProxyAuthorization bool) error {
	if c.Profile == "" {
		return errors.New("missing identity_providers.profile")
	}
	if c.ReturnURL == "" && needsReturnURL {
		return errors.New("missing return_url or identity_providers.return_url")
	}

	switch tac, err := c.SecretAuth.tokenizerAuthConfig(); {
	case err != nil:
		return err
	case tac == nil && needsProxyAuthorization:
		return errors.New("missing secret_auth or identity_providers.secret_auth")
	}

	return nil
}

// UnmarshalConfig unmarshals config from data. Expands variables as needed.
func UnmarshalConfig(config *Config, data []byte) error {
	// Expand environment variables.
	data = []byte(os.ExpandEnv(string(data)))

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true) // strict checking
	return dec.Decode(&config)
}

func VersionString() string {
	// Print version & commit information, if available.
	if Version != "" {
		return fmt.Sprintf("ssokenizer %s, commit=%s", Version, Commit)
	} else if Commit != "" {
		return fmt.Sprintf("ssokenizer commit=%s", Commit)
	}
	return "ssokenizer development build"
}

// printUsage prints the help screen to STDOUT.
func printUsage() {
	fmt.Println(`
ssokenizer is a SSO service.

Usage:

	ssokenizer <command> [arguments]

The commands are:

	serve        runs the server
	version      prints the version
`[1:])
}
