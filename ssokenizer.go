package ssokenizer

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/superfly/tokenizer"
)

type Server struct {
	Address string
	Done    chan struct{}
	Err     error

	sealKey string

	providers map[string]*provider
	http      *http.Server
}

// Returns a new Server. When a user successfully completes SSO, the sealKey is
// used to encrypt the resulting token for use with tokenizer. The rpAuth is
// set as the authentication token for the tokenizer sealed token and must be
// provided to tokenizer by the relying party in order to use the sealed token.
func NewServer(sealKey string) *Server {
	s := &Server{
		sealKey: sealKey,
		providers: map[string](*provider){
			"health": &provider{handler: handleHealth},
		},
	}

	s.http = &http.Server{Handler: s}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"method": r.Method, "uri": r.URL.Path, "host": r.Host}).Info()

	providerName, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	provider, ok := s.providers[providerName]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	r = withProvider(r, provider)

	t := &Transaction{
		ReturnState: r.URL.Query().Get("state"),
		Nonce:       randHex(16),
		Expiry:      time.Now().Add(transactionTTL),
	}

	if tc, err := r.Cookie(transactionCookieName); err != http.ErrNoCookie && tc.Value != "" {
		if err := unmarshalTransaction(t, tc.Value); err != nil {
			logrus.WithError(err).Warn("bad transaction cookie")
			t.ReturnError(w, r, "bad request")
			return
		}

		if time.Now().After(t.Expiry) {
			logrus.Warn("expired transaction")
			t.ReturnError(w, r, "expired")
			return
		}
	}

	ts, err := t.marshal()
	if err != nil {
		logrus.WithError(err).Warn("marshal transaction cookie")
		t.ReturnError(w, r, "unexpected error")
		return
	}

	t.setCookie(w, r, ts)
	r = withTransaction(r, t)
	r.URL.Path = "/" + rest

	provider.handler.ServeHTTP(w, r)
}

// Configure the server with an SSO provider. The name dictates the path that
// the provider's routes are served under. The returnURL is where the user is
// returned after an SSO transaction completes.
func (s *Server) AddProvider(name string, pc ProviderConfig, returnURL string, auth tokenizer.AuthConfig) error {
	if _, dup := s.providers[name]; dup {
		return fmt.Errorf("duplicate provider: %s", name)
	}

	p, err := pc.Register(s.sealKey, auth)
	if err != nil {
		return err
	}

	ru, err := url.Parse(returnURL)
	if err != nil {
		return err
	}

	s.providers[name] = &provider{
		name:      name,
		handler:   p,
		returnURL: ru,
	}

	return nil
}

// Start the server in a goroutine, listening at the specified address
// (host:port).
func (s *Server) Start(address string) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	s.Address = l.Addr().String()

	s.Done = make(chan struct{})
	go func() {
		defer close(s.Done)
		if err := s.http.Serve(l); err != http.ErrServerClosed {
			s.Err = err
		}
	}()

	return nil
}

// Gracefully shut down the server. If the context is cancelled before the
// shutdown completes, the server will be shutdown immediately.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

var handleHealth http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }
