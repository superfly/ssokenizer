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
)

type Server struct {
	Address string
	Done    chan struct{}
	Err     error

	sealKey string
	rpAuth  string

	providers map[string]*provider
	http      *http.Server
}

func NewServer(sealKey string, rpAuth string) *Server {
	s := &Server{
		sealKey: sealKey,
		rpAuth:  rpAuth,
		providers: map[string](*provider){
			"health": &provider{handler: handleHealth},
		},
	}

	s.http = &http.Server{Handler: s}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	logrus.WithFields(logrus.Fields{"method": r.Method, "uri": r.URL.Path}).Info()

	providerName, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	provider, ok := s.providers[providerName]
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	t := &Transaction{
		ReturnState: r.URL.Query().Get("state"),
		Nonce:       randHex(16),
		Expiry:      time.Now().Add(transactionTTL),

		returnURL:  provider.returnURL,
		cookiePath: "/" + providerName,
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
	r = r.WithContext(withTransaction(r.Context(), t))
	r.URL.Path = "/" + rest

	provider.handler.ServeHTTP(w, r)
}

func (s *Server) AddProvider(name string, pc ProviderConfig, returnURL string) error {
	if _, dup := s.providers[name]; dup {
		return fmt.Errorf("duplicate provider: %s", name)
	}

	p, err := pc.Register(s.sealKey, s.rpAuth)
	if err != nil {
		return err
	}

	ru, err := url.Parse(returnURL)
	if err != nil {
		return err
	}

	s.providers[name] = &provider{handler: p, returnURL: ru}

	return nil
}

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

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

var handleHealth http.HandlerFunc = func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) }
