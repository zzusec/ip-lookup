package server

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

const adminCookie = "__Secure-ip_lookup_admin"
const adminLifetime = 8 * time.Hour

type AdminPanel struct {
	usage       *SiteUsage
	password    [sha256.Size]byte
	loginLimit  *rateLimiter
	globalLimit *rateLimiter
	mu          sync.Mutex
	sessions    map[[sha256.Size]byte]time.Time
}

func NewAdminPanel(passwordFile, dataDir string) (*AdminPanel, error) {
	if passwordFile == "" {
		return nil, nil
	}
	meta, err := os.Lstat(passwordFile)
	if err != nil {
		return nil, err
	}
	validFile := func(info fs.FileInfo) bool {
		return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && info.Size() >= 32 && info.Size() <= 258
	}
	if !validFile(meta) {
		return nil, errors.New("admin password must be a private regular file containing a strong random password")
	}
	file, err := os.Open(passwordFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !validFile(opened) || !os.SameFile(meta, opened) {
		return nil, errors.New("admin password file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, 259))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	password := bytes.TrimSuffix(bytes.TrimSuffix(data, []byte("\n")), []byte("\r"))
	var seen [128]bool
	var distinct int
	for _, char := range password {
		if char < 33 || char > 126 {
			return nil, errors.New("admin password must be a single line of printable ASCII without spaces")
		}
		if !seen[char] {
			seen[char] = true
			distinct++
		}
	}
	if len(password) < 32 || len(password) > 256 || distinct < 8 {
		return nil, errors.New("generate a strong random admin password of 32 to 256 characters")
	}
	usage, err := openSiteUsage(dataDir)
	if err != nil {
		return nil, err
	}
	return &AdminPanel{usage: usage, password: sha256.Sum256(password), loginLimit: newRateLimiter(8, 5*time.Minute),
		globalLimit: newRateLimiter(240, 5*time.Minute), sessions: make(map[[sha256.Size]byte]time.Time)}, nil
}

func adminTransport(srv *Server, r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || !net.ParseIP(peer).IsLoopback() {
		return ""
	}
	if proto := r.Header.Values("X-Forwarded-Proto"); srv.TrustProxy && len(proto) != 0 {
		if len(proto) == 1 && proto[0] == "https" {
			return "https"
		}
		if len(proto) != 1 || proto[0] != "http" {
			return ""
		}
	}
	host := (&url.URL{Host: r.Host}).Hostname()
	if strings.EqualFold(host, "localhost") || net.ParseIP(host).IsLoopback() {
		return "http"
	}
	return ""
}

func adminJSON(w http.ResponseWriter, r *http.Request, scheme string, target any) bool {
	origins := r.Header.Values("Origin")
	defaultPort := ":443"
	if scheme == "http" {
		defaultPort = ":80"
	}
	if len(origins) != 1 || !strings.EqualFold(strings.TrimSuffix(origins[0], defaultPort), scheme+"://"+strings.TrimSuffix(r.Host, defaultPort)) ||
		(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") {
		apiError(w, http.StatusForbidden, "仅接受同源请求", 0)
		return false
	}
	if kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || kind != "application/json" {
		apiError(w, http.StatusUnsupportedMediaType, "需要 JSON 请求", 0)
		return false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 2048))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			apiError(w, http.StatusRequestEntityTooLarge, "请求内容过大", 0)
		} else {
			apiError(w, http.StatusBadRequest, "无法读取请求", 0)
		}
		return false
	}
	defer clear(body)
	trimmed := bytes.TrimSpace(body)
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	if len(trimmed) == 0 || trimmed[0] != '{' || decoder.Decode(target) != nil || decoder.Decode(new(any)) != io.EOF {
		apiError(w, http.StatusBadRequest, "无效的 JSON 对象", 0)
		return false
	}
	return true
}

func adminSessionKey(r *http.Request) ([sha256.Size]byte, bool) {
	cookies := r.CookiesNamed(adminCookie)
	if len(cookies) == 1 && len(cookies[0].Value) == base64.RawURLEncoding.EncodedLen(32) {
		return sha256.Sum256([]byte(cookies[0].Value)), true
	}
	return [sha256.Size]byte{}, false
}

func (panel *AdminPanel) session(r *http.Request, revoke bool) bool {
	key, ok := adminSessionKey(r)
	if !ok {
		return false
	}
	panel.mu.Lock()
	defer panel.mu.Unlock()
	deadline, exists := panel.sessions[key]
	valid := exists && time.Now().Before(deadline)
	if !valid || revoke {
		delete(panel.sessions, key)
	}
	return valid
}

func (panel *AdminPanel) issue(w http.ResponseWriter) {
	var entropy [32]byte
	rand.Read(entropy[:])
	token := base64.RawURLEncoding.EncodeToString(entropy[:])
	now := time.Now()
	expires := now.Add(adminLifetime)
	panel.mu.Lock()
	for key, deadline := range panel.sessions {
		if !now.Before(deadline) {
			delete(panel.sessions, key)
		}
	}
	panel.sessions[sha256.Sum256([]byte(token))] = expires
	panel.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: adminCookie, Value: token, Path: "/admin", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, Expires: expires, MaxAge: int(adminLifetime.Seconds())})
}

func (panel *AdminPanel) register(mux *http.ServeMux, srv *Server) error {
	private := http.NewServeMux()
	if panel != nil {
		page, err := fs.ReadFile(srv.Web, "admin.html")
		if err != nil {
			return err
		}
		static, err := fs.Sub(srv.Web, "static")
		if err != nil {
			return err
		}
		page, err = versioned(page, static, "style.css", "admin.css", "admin.js", "favicon.svg")
		if err != nil {
			return err
		}
		shell := func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
			w.Write(page)
		}
		private.HandleFunc("GET /admin", shell)
		private.HandleFunc("GET /admin/{$}", shell)
		private.HandleFunc("POST /admin/api/login", func(w http.ResponseWriter, r *http.Request) {
			var login struct {
				Password string `json:"password"`
			}
			if !adminJSON(w, r, adminTransport(srv, r), &login) {
				return
			}
			if ok, retry := panel.globalLimit.allow(netip.Addr{}); !ok {
				apiError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试", retry)
				return
			}
			if ok, retry := panel.loginLimit.allow(srv.clientIP(r)); !ok {
				apiError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试", retry)
				return
			}
			candidate := sha256.Sum256([]byte(login.Password))
			if subtle.ConstantTimeCompare(candidate[:], panel.password[:]) != 1 {
				apiError(w, http.StatusUnauthorized, "口令不正确", 0)
				return
			}
			panel.session(r, true)
			panel.issue(w)
			w.WriteHeader(http.StatusNoContent)
		})
		private.HandleFunc("POST /admin/api/logout", func(w http.ResponseWriter, r *http.Request) {
			if !adminJSON(w, r, adminTransport(srv, r), new(struct{})) {
				return
			}
			panel.session(r, true)
			http.SetCookie(w, &http.Cookie{Name: adminCookie, Path: "/admin", MaxAge: -1, Expires: time.Unix(1, 0),
				Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
			w.WriteHeader(http.StatusNoContent)
		})
		private.HandleFunc("GET /admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
			if !panel.session(r, false) {
				apiError(w, http.StatusUnauthorized, "请先登录", 0)
				return
			}
			if srv.Lookup == nil || srv.Lookup.Data == nil || srv.Lookup.Online == nil {
				apiError(w, http.StatusServiceUnavailable, "数据源状态不可用", 0)
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Usage   usageReport         `json:"usage"`
				Sources model.SourcesReport `json:"sources"`
			}{panel.usage.snapshot(), model.SourcesReport{Datasets: srv.Lookup.Data.Report(), Online: srv.Lookup.Online.Report()}})
		})
	}
	guard := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Robots-Tag", "noindex, nofollow")
		if panel == nil {
			http.NotFound(w, r)
			return
		}
		if adminTransport(srv, r) == "" {
			apiError(w, http.StatusForbidden, "管理后台需要安全连接", 0)
			return
		}
		private.ServeHTTP(w, r)
	}
	mux.HandleFunc("/admin", guard)
	mux.HandleFunc("/admin/", guard)
	return nil
}
