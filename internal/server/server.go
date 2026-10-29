// Package server exposes the lookup service over HTTP: the web page, a JSON
// API and a plain-text answer for command-line clients.
package server

import (
	"context"
	"encoding/json"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/lookup"
	"github.com/zzusec/ip-lookup/internal/model"
)

// Server routes requests to the lookup service.
type Server struct {
	Lookup     *lookup.Service
	Web        fs.FS // contains index.html and static/
	TrustProxy bool  // read X-Real-IP / X-Forwarded-* from loopback peers
	Log        *slog.Logger
	limit      *rateLimiter
	index      []byte
}

func (s *Server) Handler() (http.Handler, error) {
	idx, err := fs.ReadFile(s.Web, "index.html")
	if err != nil {
		return nil, err
	}
	s.index = idx
	s.limit = newRateLimiter(20, time.Minute) // full lookups of arbitrary addresses per client
	static, err := fs.Sub(s.Web, "static")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", cacheFor(http.FileServerFS(static), 24*time.Hour)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /api/ip", s.apiIP)
	mux.HandleFunc("GET /api/lookup", s.apiLookup)
	mux.HandleFunc("GET /api/sources", s.apiSources)
	mux.HandleFunc("GET /json", s.jsonLookup)
	mux.HandleFunc("GET /json/{ip}", s.jsonLookup)
	mux.HandleFunc("GET /{$}", s.page)
	mux.HandleFunc("GET /{ip}", s.page)
	return s.wrap(mux), nil
}

// wrap adds security headers, the http->https redirect and access logging.
func (s *Server) wrap(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		hd := w.Header()
		hd.Set("X-Content-Type-Options", "nosniff")
		hd.Set("Referrer-Policy", "no-referrer")
		hd.Set("X-Frame-Options", "DENY")
		if s.forwardedProto(r) == "http" && isBrowser(r) && r.URL.Path != "/healthz" {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		if s.forwardedProto(r) == "https" {
			hd.Set("Strict-Transport-Security", "max-age=31536000")
		}
		sw := &statusWriter{ResponseWriter: w, code: 200}
		h.ServeHTTP(sw, r)
		if r.URL.Path != "/healthz" && !strings.HasPrefix(r.URL.Path, "/static/") {
			s.Log.Info("http", "method", r.Method, "path", r.URL.Path, "status", sw.code,
				"ms", time.Since(start).Milliseconds())
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(c int) { w.code = c; w.ResponseWriter.WriteHeader(c) }

func cacheFor(h http.Handler, d time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(d.Seconds())))
		h.ServeHTTP(w, r)
	})
}

// clientIP returns the visitor's address. Forwarding headers are only trusted
// from loopback peers, i.e. the local reverse proxy.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, _ := netip.ParseAddr(host)
	peer = peer.Unmap()
	if s.TrustProxy && peer.IsLoopback() {
		if a, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get("X-Real-IP"))); err == nil {
			return a.Unmap()
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.Unmap()
			}
		}
	}
	return peer
}

func (s *Server) forwardedProto(r *http.Request) string {
	if !s.TrustProxy {
		return ""
	}
	return strings.ToLower(r.Header.Get("X-Forwarded-Proto"))
}

// isBrowser tells pages apart from command-line clients.
func isBrowser(r *http.Request) bool {
	ua := strings.ToLower(r.Header.Get("User-Agent"))
	for _, cli := range []string{"curl/", "wget/", "httpie/", "powershell", "fetch/", "go-http-client", "python-requests", "aria2"} {
		if strings.Contains(ua, cli) {
			return false
		}
	}
	return strings.Contains(r.Header.Get("Accept"), "text/html") || strings.HasPrefix(ua, "mozilla/")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
}

func apiError(w http.ResponseWriter, code int, msg string, retry int) {
	if retry > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
	}
	writeJSON(w, code, model.APIError{Error: msg, RetryAfter: retry})
}

func ctxTimeout(r *http.Request, d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), d)
}
