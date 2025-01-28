package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"regexp"
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
	// Full URL of the tokenizer service
	URL string `yaml:"url"`

	// Tokenizer seal (public) key
	SealKey string `yaml:"seal_key"`

	// Where to return user after auth dance. If present, the string `:name` is
	// replaced with the provider name. Can also be specified per-provider.
	ReturnURL string `yaml:"return_url"`

	SecretAuth        SecretAuthConfig                  `yaml:"secret_auth"`
	Log               LogConfig                         `yaml:"log"`
	HTTP              HTTPConfig                        `yaml:"http"`
	IdentityProviders map[string]IdentityProviderConfig `yaml:"identity_providers"`

	// fields populated during validation
	ssokenizerURL   *url.URL
	globalTAC       tokenizer.AuthConfig
	globalReturnURL *url.URL
	providers       ssokenizer.StaticProviderRegistry
}

func (c *Config) validate() error {
	var err error

	if c.HTTP.Address == "" {
		return errors.New("missing http.address")
	}

	c.ssokenizerURL, err = url.Parse(c.URL)
	switch {
	case c.URL == "":
		return errors.New("missing url")
	case err != nil:
		return fmt.Errorf("invalid URL (%q): %w", c.URL, err)
	case c.ssokenizerURL.Scheme == "" || c.ssokenizerURL.Host == "":
		return fmt.Errorf("malformed URL: %q", c.URL)
	}

	if c.SealKey == "" {
		return errors.New("missing seal_key")
	}

	c.globalTAC, err = c.SecretAuth.tokenizerAuthConfig()
	if err != nil {
		return err
	}

	if c.ReturnURL != "" {
		switch c.globalReturnURL, err = url.Parse(c.ReturnURL); {
		case err != nil:
			return err
		case c.globalReturnURL.Scheme == "" || c.globalReturnURL.Host == "":
			return fmt.Errorf("malformed return_url: %q", c.ReturnURL)
		}
	}

	c.providers = make(ssokenizer.StaticProviderRegistry)
	for name, pc := range c.IdentityProviders {
		if _, dup := c.providers[name]; dup {
			return fmt.Errorf("duplicate identity provider %q", name)
		}

		provider, err := pc.provider(name, c)
		if err != nil {
			return fmt.Errorf("invalid identity provider %q: %w", name, err)
		}

		c.providers[name] = provider
	}

	return nil
}

// tokenizerHostValidator returns validators that tokenizer can run to only
// allow tokens to be forwarded to specific hosts. In addition to whatever
// hostname pattern we want to allow for a given provider, we also include our
// own hostname so tokenizer can send us requests for refresh tokens.
func (c *Config) tokenizerHostValidator(pattern string) []tokenizer.RequestValidator {
	re := regexp.MustCompile(fmt.Sprintf("^(%s|%s)$", regexp.QuoteMeta(c.ssokenizerURL.Hostname()), pattern))
	return []tokenizer.RequestValidator{tokenizer.AllowHostPattern(re)}
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

func (ic *IdentityProviderConfig) provider(name string, c *Config) (ssokenizer.Provider, error) {
	switch {
	case ic.ClientID == "":
		return nil, errors.New("missing client_id")
	case ic.ClientSecret == "":
		return nil, errors.New("missing client_secret")
	}

	op := oauth2.Provider{
		ProviderConfig: ssokenizer.ProviderConfig{
			Tokenizer: ssokenizer.TokenizerConfig{
				SealKey: c.SealKey,
			},
			URL: *c.ssokenizerURL.JoinPath("/" + name),
		},
		OAuthConfig: xoauth2.Config{
			ClientID:     ic.ClientID,
			ClientSecret: ic.ClientSecret,
			Scopes:       ic.Scopes,
		},
	}

	switch tac, err := ic.SecretAuth.tokenizerAuthConfig(); {
	case err != nil:
		return nil, err
	case tac == nil && c.globalTAC == nil:
		return nil, errors.New("missing secret_auth")
	case tac == nil:
		op.ProviderConfig.Tokenizer.Auth = c.globalTAC
	default:
		op.ProviderConfig.Tokenizer.Auth = tac
	}

	switch {
	case ic.ReturnURL == "" && c.globalReturnURL == nil:
		return nil, errors.New("missing return_url")
	case ic.ReturnURL == "":
		op.ProviderConfig.ReturnURL = *c.globalReturnURL
	default:
		switch u, err := url.Parse(ic.ReturnURL); {
		case err != nil:
			return nil, fmt.Errorf("invalid return_url: %w", err)
		case u.Scheme == "" || u.Host == "":
			return nil, fmt.Errorf("malformed return_url: %q", ic.ReturnURL)
		default:
			op.ProviderConfig.ReturnURL = *u
		}
	}

	switch ic.Profile {
	case "vanta":
		op.OAuthConfig.Endpoint = xoauth2.Endpoint{
			AuthURL:   "https://app.vanta.com/oauth/authorize",
			TokenURL:  "https://api.vanta.com/oauth/token",
			AuthStyle: xoauth2.AuthStyleInParams,
		}

		op.ForwardParams = []string{"source_id"}

		return &vanta.Provider{Provider: op}, nil
	case "oauth":
		switch {
		case ic.AuthURL == "":
			return nil, errors.New("missing auth_url")
		case ic.TokenURL == "":
			return nil, errors.New("missing token_url")
		}

		op.OAuthConfig.Endpoint = xoauth2.Endpoint{
			AuthURL:  ic.AuthURL,
			TokenURL: ic.TokenURL,
		}

		return &op, nil
	case "amazon":
		op.OAuthConfig.Endpoint = amazon.Endpoint
		return &op, nil
	case "bitbucket":
		op.OAuthConfig.Endpoint = bitbucket.Endpoint
		return &op, nil
	case "facebook":
		op.OAuthConfig.Endpoint = facebook.Endpoint
		return &op, nil
	case "github":
		op.OAuthConfig.Endpoint = github.Endpoint
		op.Tokenizer.RequestValidators = c.tokenizerHostValidator(`api\.github\.com`)
		return &op, nil
	case "gitlab":
		op.OAuthConfig.Endpoint = gitlab.Endpoint
		return &op, nil
	case "google":
		op.OAuthConfig.Endpoint = google.Endpoint
		op.Tokenizer.RequestValidators = c.tokenizerHostValidator(`.*\.googleapis\.com`)
		op.ForwardParams = []string{"hd"}
		return &op, nil
	case "heroku":
		op.OAuthConfig.Endpoint = heroku.Endpoint
		op.Tokenizer.RequestValidators = c.tokenizerHostValidator(`api\.heroku\.com`)
		return &op, nil
	case "microsoft":
		op.OAuthConfig.Endpoint = microsoft.LiveConnectEndpoint
		return &op, nil
	case "slack":
		op.OAuthConfig.Endpoint = slack.Endpoint
		return &op, nil
	default:
		return nil, errors.New("unknown identity provider profile")
	}
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
