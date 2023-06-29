package ssokenizer

import (
	"context"
	"net"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

type Server struct {
	Address string
	Done    chan struct{}
	Err     error

	sealKey string
	rpAuth  string
	http    *http.Server
	router  *mux.Router
}

func NewServer(tls bool, sealKey string, rpAuth string, returnTo []string) (*Server, error) {
	router := mux.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.WithFields(logrus.Fields{
				"method": r.Method,
				"uri":    r.URL.String(),
			}).Info()

			w.Header().Set("Referrer-Policy", "origin-when-cross-origin")

			next.ServeHTTP(w, r)
		})
	})
	router.Use(transactionMiddleware(tls, returnTo))

	return &Server{
		sealKey: sealKey,
		rpAuth:  rpAuth,
		http:    &http.Server{Handler: router},
		router:  router,
	}, nil
}

func (s *Server) AddProvider(name string, pc ProviderConfig) error {
	return pc.Register(s.router.PathPrefix("/"+name).Subrouter(), s.sealKey, s.rpAuth)
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
