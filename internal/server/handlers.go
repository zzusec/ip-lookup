package server

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

// target resolves the address a request asks about: the explicit one in the
// path or ?ip=, else the visitor. self reports whether it is the visitor.
func (s *Server) target(r *http.Request) (a netip.Addr, self bool, errMsg string) {
	raw := strings.TrimSpace(r.PathValue("ip"))
	if raw == "" {
		raw = strings.TrimSpace(r.URL.Query().Get("ip"))
	}
	if raw == "" {
		a := s.clientIP(r)
		if !a.IsValid() {
			return a, true, "无法识别访客 IP"
		}
		return a, true, ""
	}
	a, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return a, false, "不是有效的 IPv4/IPv6 地址"
	}
	a = a.Unmap().WithZone("")
	return a, a == s.clientIP(r), ""
}

// run performs the lookup, applying the rate limit to full lookups of
// addresses other than the visitor's own.
func (s *Server) run(w http.ResponseWriter, r *http.Request, full bool) (*model.Result, bool) {
	a, self, msg := s.target(r)
	if msg != "" {
		apiError(w, http.StatusBadRequest, msg, 0)
		return nil, false
	}
	if full && !self {
		if ok, retry := s.limit.allow(s.clientIP(r)); !ok {
			apiError(w, http.StatusTooManyRequests, "查询太频繁，请稍后再试", retry)
			return nil, false
		}
	}
	ctx, cancel := ctxTimeout(r, s.Lookup.Timeout+2*time.Second)
	defer cancel()
	return s.Lookup.Lookup(ctx, a, full), true
}

func (s *Server) apiLookup(w http.ResponseWriter, r *http.Request) {
	full := r.URL.Query().Get("mode") != "fast"
	if res, ok := s.run(w, r, full); ok {
		writeJSON(w, http.StatusOK, res)
	}
}

// jsonLookup serves /json and /json/{ip}: always a full lookup.
func (s *Server) jsonLookup(w http.ResponseWriter, r *http.Request) {
	if res, ok := s.run(w, r, true); ok {
		writeJSON(w, http.StatusOK, res)
	}
}

func (s *Server) apiIP(w http.ResponseWriter, r *http.Request) {
	a := s.clientIP(r)
	v := 4
	if a.Is6() {
		v = 6
	}
	writeJSON(w, http.StatusOK, model.ClientIP{IP: a.String(), Version: v})
}

func (s *Server) apiSources(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, model.SourcesReport{Datasets: s.Lookup.Data.Report(), Online: s.Lookup.Online.Report()})
}

// page serves the HTML app to browsers and a text report to command-line tools.
func (s *Server) page(w http.ResponseWriter, r *http.Request) {
	if raw := r.PathValue("ip"); raw != "" {
		if _, err := netip.ParseAddr(strings.Trim(raw, "[]")); err != nil {
			http.NotFound(w, r)
			return
		}
	}
	if isBrowser(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; connect-src *; img-src 'self' data: https:; "+
			"style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Write(s.index)
		return
	}
	full := r.URL.Query().Get("mode") != "fast"
	res, ok := s.run(w, r, full)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(Text(res, r.Host)))
}
