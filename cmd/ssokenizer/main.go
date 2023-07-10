package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/superfly/ssokenizer"
	"github.com/superfly/ssokenizer/amazon"
	"github.com/superfly/ssokenizer/bitbucket"
	"github.com/superfly/ssokenizer/facebook"
	"github.com/superfly/ssokenizer/github"
	"github.com/superfly/ssokenizer/google"
	"github.com/superfly/ssokenizer/heroku"
	"github.com/superfly/ssokenizer/microsoft"
	"github.com/superfly/ssokenizer/slack"
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

	// Auth key to put on tokenizer secrets
	RelyingPartyAuth string `yaml:"relying_party_auth"`

	// Where to return user after auth dance. If present, the string `:name` is
	// replaced with the provider name. Can also be specified per-provider.
	ReturnURL string `yaml:"return_url"`

	Log               LogConfig                         `yaml:"log"`
	HTTP              HTTPConfig                        `yaml:"http"`
	IdentityProviders map[string]IdentityProviderConfig `yaml:"identity_providers"`
}

// NewConfig returns a new instance of Config with defaults set.
func NewConfig() Config {
	var config Config
	return config
}

// Validate returns an error if the config is invalid.
func (c *Config) Validate() error {
	if c.RelyingPartyAuth == "" {
		return errors.New("missing relying_party_auth")
	}
	if c.SealKey == "" {
		return errors.New("missing seal_key")
	}
	if c.HTTP.Address == "" {
		return errors.New("missing http.address")
	}
	if c.HTTP.URL == "" {
		return errors.New("missing http.url")
	}
	for _, pc := range c.IdentityProviders {
		if err := pc.Validate(c.ReturnURL == ""); err != nil {
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

	// url that ssokenizer can be reached at
	URL string `yaml:"url"`
}

type IdentityProviderConfig struct {
	// idb profile name (e.g. google)
	Profile string `yaml:"profile"`

	// oauth client ID
	ClientID string `yaml:"client_id"`

	// oauth client secret
	ClientSecret string `yaml:"client_secret"`

	// oauth scopes to request
	Scopes []string `yaml:"scopes"`

	// Where to return user after auth dance. Can also be specified globally.
	ReturnURL string `yaml:"return_url"`
}

func (c IdentityProviderConfig) providerConfig(baseURL, returnURL string) (ssokenizer.ProviderConfig, error) {
	switch c.Profile {
	case "amazon":
		return amazon.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "bitbucket":
		return bitbucket.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "facebook":
		return facebook.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "github":
		return github.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "gitlab":
		return github.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "google":
		return google.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "heroku":
		return heroku.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "microsoft":
		return microsoft.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	case "slack":
		return slack.Config{
			ClientID:     c.ClientID,
			ClientSecret: c.ClientSecret,
			Scopes:       c.Scopes,
			RedirectURL:  baseURL + "/callback",
		}, nil
	default:
		return nil, fmt.Errorf("unknown identity provider profile: %s", c.Profile)
	}
}

func (c IdentityProviderConfig) Validate(needsReturnURL bool) error {
	if c.Profile == "" {
		return errors.New("missing identity_providers.profile")
	}
	if c.ReturnURL == "" && needsReturnURL {
		return errors.New("missing return_url or identity_providers.return_url")
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
