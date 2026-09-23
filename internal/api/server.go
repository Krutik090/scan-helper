// Package api exposes the scan modules over HTTP.
//
// Scans are asynchronous: POST accepts the request and returns a job id,
// and GET /api/v1/jobs/{id} reports progress and (in api_response mode)
// the finished result. A multi-minute scan must never depend on one HTTP
// connection staying open.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/Krutik090/scan-helper/internal/config"
	"github.com/Krutik090/scan-helper/internal/jobs"
	"github.com/Krutik090/scan-helper/internal/modules"
	"github.com/Krutik090/scan-helper/internal/storage"
	"github.com/go-chi/chi/v5"
)

type Deps struct {
	Config   config.Config
	Registry *modules.Registry
	Jobs     *jobs.Store
	Sink     storage.Sink
	Logger   *slog.Logger
}

type Server struct {
	deps    Deps
	handler http.Handler
}

func NewServer(deps Deps) *Server {
	s := &Server{deps: deps}

	r := chi.NewRouter()
	r.Use(recoverPanic(deps.Logger))
	r.Use(requestLogger(deps.Logger))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.handleHealth)

		r.Group(func(r chi.Router) {
			r.Use(requireAPIKey(deps.Config.Server.APIKey))
			r.Post("/scans/{module}", s.handleScan)
			r.Get("/jobs/{id}", s.handleJob)
			r.Get("/jobs", s.handleJobs)
		})
	})

	s.handler = r
	return s
}

func (s *Server) Handler() http.Handler { return s.handler }

// ListenAndServe serves until ctx is cancelled, then shuts down
// gracefully so an in-flight request finishes rather than being cut off.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", s.deps.Config.Server.Port),
		Handler:           s.handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		s.deps.Logger.Info("listening", "port", s.deps.Config.Server.Port, "mode", string(s.deps.Config.Mode))
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
