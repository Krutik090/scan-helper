package api

import (
	"crypto/subtle"
	"log/slog"
	"net/http"
	"time"
)

// requireAPIKey rejects anything without the configured X-API-Key. The
// config layer refuses to start with an empty key, so this can never
// degrade into "no auth".
//
// The comparison is constant-time. Go's == on strings returns as soon as
// two bytes differ, so how long a rejection takes leaks how much of the
// key the caller got right — enough, over many requests, to recover it a
// byte at a time. This is an auth primitive and the correct comparison
// costs nothing.
func requireAPIKey(key string) func(http.Handler) http.Handler {
	expected := []byte(key)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-API-Key")), expected) != 1 {
				writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "invalid or missing X-API-Key"})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r)
			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"duration", time.Since(start).String(),
			)
		})
	}
}

// recoverPanic keeps one bad request from taking down a server that is
// mid-scan for other jobs.
func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					logger.Error("panic serving request", "path", r.URL.Path, "panic", rec)
					writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "internal error"})
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
