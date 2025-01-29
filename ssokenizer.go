package ssokenizer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"
)

type Server struct {
	// Address is populated with the listening address after [Start] is called.
	Address string

	// Done is closed when the server has stopped. It is not populated until
	// [Start] is called.
	Done chan struct{}

	// Err is populated with any error returned by the HTTP server. It should
	// not be read until Done is closed.
	Err error

	providers ProviderRegistry
	http      *http.Server
}

// Returns a new Server.
func NewServer(providers ProviderRegistry) *Server {
	s := &Server{providers: providers}
	s.http = &http.Server{Handler: s}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if parts[0] == "health" {
		fmt.Fprintln(w, "ok")
		return
	}

	providerName := strings.Join(parts[0:len(parts)-1], "/")

	providerName, rest, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if providerName == "health" {
		fmt.Fprintln(w, "ok")
		return
	}

	r = WithFields(r, logrus.Fields{"method": r.Method, "uri": r.URL.Path, "host": r.Host})

	provider, err := s.providers.Get(r.Context(), providerName)
	switch {
	case errors.Is(err, ErrProviderNotFound):
		GetLog(r).WithField("status", http.StatusNotFound).Info()
		w.WriteHeader(http.StatusNotFound)
		return
	case err != nil:
		GetLog(r).WithError(err).WithField("status", http.StatusInternalServerError).Info()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	if err = provider.Validate(); err != nil {
		GetLog(r).WithError(err).WithField("status", http.StatusInternalServerError).Warn()
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	r = WithProvider(r, provider)
	r.URL.Path = "/" + rest
	provider.ServeHTTP(w, r)
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
