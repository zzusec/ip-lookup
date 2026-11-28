package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
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
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zzusec/ip-lookup/internal/model"
)

const (
	adminCookieHTTPS = "__Secure-ip_lookup_admin"
	adminCookieHTTP  = "ip_lookup_admin"
	gateCookieHTTPS  = "__Secure-ip_lookup_gate"
	gateCookieHTTP   = "ip_lookup_gate"
	adminLifetime    = 12 * time.Hour
	gateLifetime     = 30 * 24 * time.Hour
)

var gateKeyFormat = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

type adminAuthDisk struct {
	Schema       int       `json:"schema"`
	SeedDigest   string    `json:"seedDigest"`
	Username     string    `json:"username"`
	PasswordSalt string    `json:"passwordSalt"`
	PasswordHash string    `json:"passwordHash"`
	GateKey      string    `json:"gateKey,omitempty"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type AdminPanel struct {
	dataDir     string
	authPath    string
	seedDigest  string
	usage       *SiteUsage
	live        *liveTelemetry
	loginLimit  *rateLimiter
	globalLimit *rateLimiter
	gateSecret  [32]byte

	mu       sync.Mutex
	username string
	pwSalt   [16]byte
	pwHash   [sha256.Size]byte
	gateKey  string
	sessions map[[sha256.Size]byte]time.Time
}

func hashAdminPassword(salt [16]byte, password []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("ip-lookup-admin-v2:"))
	h.Write(salt[:])
	h.Write([]byte{':'})
	h.Write(password)
	var out [sha256.Size]byte
	h.Sum(out[:0])
	return out
}

func validPrintableToken(b []byte, minLen, maxLen int) bool {
	if len(b) < minLen || len(b) > maxLen {
		return false
	}
	for _, c := range b {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}

func parseAdminSeed(raw []byte) (username, gateKey string, password []byte, keyedMode bool, err error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return "", "", nil, false, errors.New("empty admin credential file")
	}

	// Detect structured key:value format (gate_key / username / password)
	lines := bytes.Split(bytes.ReplaceAll(trimmed, []byte("\r\n"), []byte("\n")), []byte("\n"))
	hasKV := false
	for _, ln := range lines {
		s := strings.TrimSpace(string(ln))
		if strings.HasPrefix(s, "#") || s == "" {
			continue
		}
		low := strings.ToLower(s)
		if strings.HasPrefix(low, "gate_key:") || strings.HasPrefix(low, "token:") ||
			strings.HasPrefix(low, "username:") || strings.HasPrefix(low, "user:") ||
			strings.HasPrefix(low, "password:") || strings.HasPrefix(low, "pass:") {
			hasKV = true
			break
		}
	}

	if hasKV {
		kv := map[string]string{}
		for _, ln := range lines {
			s := strings.TrimSpace(string(ln))
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			idx := strings.IndexByte(s, ':')
			if idx <= 0 {
				return "", "", nil, false, errors.New("invalid line in admin credential file")
			}
			k := strings.ToLower(strings.TrimSpace(s[:idx]))
			v := strings.TrimSpace(s[idx+1:])
			kv[k] = v
		}
		username = firstNonEmptyStr(kv["username"], kv["user"], "admin")
		gateKey = firstNonEmptyStr(kv["gate_key"], kv["token"])
		pwStr := firstNonEmptyStr(kv["password"], kv["pass"])
		if !validPrintableToken([]byte(username), 1, 64) {
			return "", "", nil, false, errors.New("admin username must be 1 to 64 printable ASCII characters")
		}
		if gateKey != "" && !gateKeyFormat.MatchString(gateKey) {
			return "", "", nil, false, errors.New("admin gate_key must be 8 to 64 URL-safe characters")
		}
		minPW := 32
		if gateKey != "" {
			minPW = 6
		}
		if !validPrintableToken([]byte(pwStr), minPW, 256) {
			return "", "", nil, false, errors.New("admin password does not meet length or character policy")
		}
		return username, gateKey, []byte(pwStr), true, nil
	}

	// Legacy single-line strong random password file (32..256 chars, >=8 distinct ASCII chars)
	pw := bytes.TrimSuffix(bytes.TrimSuffix(raw, []byte("\n")), []byte("\r"))
	var seen [128]bool
	var distinct int
	for _, char := range pw {
		if char < 33 || char > 126 {
			return "", "", nil, false, errors.New("admin password must be a single line of printable ASCII without spaces")
		}
		if !seen[char] {
			seen[char] = true
			distinct++
		}
	}
	if len(pw) < 32 || len(pw) > 256 || distinct < 8 {
		return "", "", nil, false, errors.New("generate a strong random admin password of 32 to 256 characters")
	}
	return "admin", "", slices.Clone(pw), false, nil
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
		return info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 && info.Size() >= 20 && info.Size() <= 1024
	}
	if !validFile(meta) {
		return nil, errors.New("admin password must be a private regular file containing valid credentials")
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
	data, err := io.ReadAll(io.LimitReader(file, 1025))
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if len(data) > 1024 {
		return nil, errors.New("admin credential file is too large")
	}

	username, gateKey, password, _, err := parseAdminSeed(data)
	if err != nil {
		return nil, err
	}
	defer clear(password)

	seedSum := sha256.Sum256(bytes.TrimSpace(data))
	seedDigest := hex.EncodeToString(seedSum[:])

	usage, err := openSiteUsage(dataDir)
	if err != nil {
		return nil, err
	}

	var pwSalt [16]byte
	rand.Read(pwSalt[:])
	pwHash := hashAdminPassword(pwSalt, password)

	panel := &AdminPanel{
		dataDir:     dataDir,
		authPath:    filepath.Join(dataDir, "admin-auth.json"),
		seedDigest:  seedDigest,
		usage:       usage,
		live:        newLiveTelemetry(),
		loginLimit:  newRateLimiter(8, 5*time.Minute),
		globalLimit: newRateLimiter(240, 5*time.Minute),
		username:    username,
		pwSalt:      pwSalt,
		pwHash:      pwHash,
		gateKey:     gateKey,
		sessions:    make(map[[sha256.Size]byte]time.Time),
	}
	rand.Read(panel.gateSecret[:])
	panel.loadRuntimeAuthOverride()
	return panel, nil
}

func (panel *AdminPanel) loadRuntimeAuthOverride() {
	raw, err := readUsageFile(panel.authPath)
	if err != nil {
		return
	}
	var disk adminAuthDisk
	if json.Unmarshal(raw, &disk) != nil || disk.Schema != 1 || disk.SeedDigest != panel.seedDigest {
		return
	}
	saltBytes, err1 := hex.DecodeString(disk.PasswordSalt)
	hashBytes, err2 := hex.DecodeString(disk.PasswordHash)
	if err1 != nil || err2 != nil || len(saltBytes) != 16 || len(hashBytes) != sha256.Size {
		return
	}
	if !validPrintableToken([]byte(disk.Username), 1, 64) {
		return
	}
	if disk.GateKey != "" && !gateKeyFormat.MatchString(disk.GateKey) {
		return
	}
	copy(panel.pwSalt[:], saltBytes)
	copy(panel.pwHash[:], hashBytes)
	panel.username = disk.Username
	panel.gateKey = disk.GateKey
}

func (panel *AdminPanel) saveRuntimeAuthLocked() error {
	disk := adminAuthDisk{
		Schema:       1,
		SeedDigest:   panel.seedDigest,
		Username:     panel.username,
		PasswordSalt: hex.EncodeToString(panel.pwSalt[:]),
		PasswordHash: hex.EncodeToString(panel.pwHash[:]),
		GateKey:      panel.gateKey,
		UpdatedAt:    time.Now().UTC().Truncate(time.Second),
	}
	file, err := os.CreateTemp(panel.dataDir, ".admin-auth-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if err = json.NewEncoder(file).Encode(disk); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(file.Name(), panel.authPath)
}

func (panel *AdminPanel) verifyPasswordLocked(candidate string) bool {
	got := hashAdminPassword(panel.pwSalt, []byte(candidate))
	return subtle.ConstantTimeCompare(got[:], panel.pwHash[:]) == 1
}

func (panel *AdminPanel) gateCookieValLocked() string {
	if panel.gateKey == "" {
		return ""
	}
	mac := hmac.New(sha256.New, panel.gateSecret[:])
	mac.Write([]byte("gate:"))
	mac.Write([]byte(panel.gateKey))
	return hex.EncodeToString(mac.Sum(nil))
}

func adminCookieNames(scheme string) (sessName, gateName string, secure bool) {
	if scheme == "https" {
		return adminCookieHTTPS, gateCookieHTTPS, true
	}
	return adminCookieHTTP, gateCookieHTTP, false
}

func (panel *AdminPanel) issueGateCookie(w http.ResponseWriter, scheme, expected string) {
	if expected == "" {
		return
	}
	_, gateName, secure := adminCookieNames(scheme)
	expires := time.Now().Add(gateLifetime)
	http.SetCookie(w, &http.Cookie{
		Name:     gateName,
		Value:    expected,
		Path:     "/admin",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
		MaxAge:   int(gateLifetime.Seconds()),
	})
}

func (panel *AdminPanel) checkGate(w http.ResponseWriter, r *http.Request, scheme string, allowQuerySet bool) bool {
	panel.mu.Lock()
	gk := panel.gateKey
	expectedCookie := panel.gateCookieValLocked()
	panel.mu.Unlock()

	if gk == "" {
		return true
	}
	if panel.session(r, scheme, false) {
		return true
	}
	if qk := strings.TrimSpace(r.URL.Query().Get("k")); qk != "" {
		if subtle.ConstantTimeCompare([]byte(qk), []byte(gk)) == 1 {
			if allowQuerySet && w != nil {
				panel.issueGateCookie(w, scheme, expectedCookie)
			}
			return true
		}
		return false
	}
	if hk := strings.TrimSpace(r.Header.Get("X-Admin-Key")); hk != "" {
		return subtle.ConstantTimeCompare([]byte(hk), []byte(gk)) == 1
	}
	_, gateName, _ := adminCookieNames(scheme)
	for _, c := range r.CookiesNamed(gateName) {
		if subtle.ConstantTimeCompare([]byte(c.Value), []byte(expectedCookie)) == 1 {
			return true
		}
	}
	return false
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

func adminSessionKey(r *http.Request, scheme string) ([sha256.Size]byte, bool) {
	sessName, _, _ := adminCookieNames(scheme)
	cookies := r.CookiesNamed(sessName)
	if len(cookies) == 1 && len(cookies[0].Value) == base64.RawURLEncoding.EncodedLen(32) {
		return sha256.Sum256([]byte(cookies[0].Value)), true
	}
	return [sha256.Size]byte{}, false
}

func (panel *AdminPanel) session(r *http.Request, scheme string, revoke bool) bool {
	key, ok := adminSessionKey(r, scheme)
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

func (panel *AdminPanel) issue(w http.ResponseWriter, scheme string) {
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
	sessName, _, secure := adminCookieNames(scheme)
	http.SetCookie(w, &http.Cookie{
		Name:     sessName,
		Value:    token,
		Path:     "/admin",
		Secure:   secure,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
		MaxAge:   int(adminLifetime.Seconds()),
	})
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
		page, err = versioned(page, static, "admin.css", "admin.js", "favicon.svg")
		if err != nil {
			return err
		}
		shell := func(w http.ResponseWriter, r *http.Request) {
			scheme := adminTransport(srv, r)
			if !panel.checkGate(w, r, scheme, true) {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
			w.Write(page)
		}
		private.HandleFunc("GET /admin", shell)
		private.HandleFunc("GET /admin/{$}", shell)

		private.HandleFunc("POST /admin/api/login", func(w http.ResponseWriter, r *http.Request) {
			scheme := adminTransport(srv, r)
			if !panel.checkGate(nil, r, scheme, false) {
				http.NotFound(w, r)
				return
			}
			var login struct {
				Username string `json:"username"`
				Password string `json:"password"`
			}
			if !adminJSON(w, r, scheme, &login) {
				return
			}
			clientAddr := srv.clientIP(r)
			clientIP := ""
			if clientAddr.IsValid() {
				clientIP = clientAddr.String()
			}
			now := time.Now()
			if blocked, retry, msg := panel.live.checkIPBlock(clientIP, now); blocked {
				apiError(w, http.StatusTooManyRequests, msg, retry)
				return
			}
			if ok, retry := panel.globalLimit.allow(netip.Addr{}); !ok {
				apiError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试", retry)
				return
			}
			if ok, retry := panel.loginLimit.allow(clientAddr); !ok {
				apiError(w, http.StatusTooManyRequests, "登录尝试过多，请稍后再试", retry)
				return
			}

			panel.mu.Lock()
			expectUser := panel.username
			gated := panel.gateKey != ""
			pwOK := panel.verifyPasswordLocked(login.Password)
			panel.mu.Unlock()

			inputUser := strings.TrimSpace(login.Username)
			userOK := false
			if !gated && inputUser == "" {
				userOK = true
			} else if inputUser != "" {
				userOK = subtle.ConstantTimeCompare([]byte(inputUser), []byte(expectUser)) == 1
			}

			cSum := srv.offlineIPSummary(clientAddr)
			failLimit := 8
			if gated {
				failLimit = 3
			}
			if !userOK || !pwOK {
				panel.live.recordLoginAttempt(now, clientIP, cSum.Location, firstNonEmptyStr(inputUser, "-"), false, "账号或密码错误", failLimit)
				apiError(w, http.StatusUnauthorized, "账号或口令不正确", 0)
				return
			}
			panel.live.recordLoginAttempt(now, clientIP, cSum.Location, firstNonEmptyStr(inputUser, expectUser), true, "登录成功", failLimit)
			panel.session(r, scheme, true)
			panel.issue(w, scheme)
			w.WriteHeader(http.StatusNoContent)
		})

		private.HandleFunc("POST /admin/api/logout", func(w http.ResponseWriter, r *http.Request) {
			scheme := adminTransport(srv, r)
			if !panel.checkGate(nil, r, scheme, false) {
				http.NotFound(w, r)
				return
			}
			if !adminJSON(w, r, scheme, new(struct{})) {
				return
			}
			panel.session(r, scheme, true)
			sessName, _, secure := adminCookieNames(scheme)
			http.SetCookie(w, &http.Cookie{
				Name:     sessName,
				Path:     "/admin",
				MaxAge:   -1,
				Expires:  time.Unix(1, 0),
				Secure:   secure,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			w.WriteHeader(http.StatusNoContent)
		})

		requireSession := func(w http.ResponseWriter, r *http.Request) (string, bool) {
			scheme := adminTransport(srv, r)
			if panel.session(r, scheme, false) {
				return scheme, true
			}
			if !panel.checkGate(nil, r, scheme, false) {
				http.NotFound(w, r)
				return "", false
			}
			apiError(w, http.StatusUnauthorized, "请先登录", 0)
			return "", false
		}

		private.HandleFunc("GET /admin/api/overview", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := requireSession(w, r); !ok {
				return
			}
			if srv.Lookup == nil || srv.Lookup.Data == nil || srv.Lookup.Online == nil {
				apiError(w, http.StatusServiceUnavailable, "数据源状态不可用", 0)
				return
			}
			now := time.Now()
			usage := panel.usage.snapshot()
			live := panel.live.overview(usage, now)
			panel.mu.Lock()
			uname := panel.username
			gk := panel.gateKey
			panel.mu.Unlock()

			writeJSON(w, http.StatusOK, struct {
				Usage   usageReport         `json:"usage"`
				Sources model.SourcesReport `json:"sources"`
				Live    liveOverview        `json:"live"`
				Auth    struct {
					Username string `json:"username"`
					GateKey  string `json:"gateKey"`
					Gated    bool   `json:"gated"`
				} `json:"auth"`
			}{
				Usage:   usage,
				Sources: model.SourcesReport{Datasets: srv.Lookup.Data.Report(), Online: srv.Lookup.Online.Report()},
				Live:    live,
				Auth: struct {
					Username string `json:"username"`
					GateKey  string `json:"gateKey"`
					Gated    bool   `json:"gated"`
				}{Username: uname, GateKey: gk, Gated: gk != ""},
			})
		})

		private.HandleFunc("GET /admin/api/visits", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := requireSession(w, r); !ok {
				return
			}
			qs := r.URL.Query()
			page, _ := strconv.Atoi(qs.Get("page"))
			size, _ := strconv.Atoi(qs.Get("size"))
			if size <= 0 {
				size = 20
			}
			day := strings.TrimSpace(qs.Get("day"))
			from := strings.TrimSpace(qs.Get("from"))
			to := strings.TrimSpace(qs.Get("to"))
			if day != "" {
				from = day
				to = day
			}
			rows, total := panel.live.queryVisits(visitQuery{
				Page:  max(1, page),
				Size:  size,
				Q:     qs.Get("q"),
				Kind:  qs.Get("kind"),
				From:  from,
				To:    to,
				Today: qs.Get("today") == "1",
				Err:   qs.Get("err") == "1",
				Sort:  qs.Get("sort"),
				Order: qs.Get("order"),
			}, time.Now())
			writeJSON(w, http.StatusOK, struct {
				Total int           `json:"total"`
				Page  int           `json:"page"`
				Size  int           `json:"size"`
				Items []visitRecord `json:"items"`
			}{Total: total, Page: max(1, page), Size: size, Items: rows})
		})

		private.HandleFunc("GET /admin/api/visitor", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := requireSession(w, r); !ok {
				return
			}
			ipStr := strings.TrimSpace(r.URL.Query().Get("ip"))
			addr, err := netip.ParseAddr(strings.Trim(ipStr, "[]"))
			if err != nil {
				apiError(w, http.StatusBadRequest, "无效的 IP 地址", 0)
				return
			}
			addr = addr.Unmap().WithZone("")
			canon := addr.String()
			writeJSON(w, http.StatusOK, struct {
				IP      string        `json:"ip"`
				Summary ipSummary     `json:"summary"`
				History []visitRecord `json:"history"`
			}{
				IP:      canon,
				Summary: srv.offlineIPSummary(addr),
				History: panel.live.visitorHistory(canon),
			})
		})

		private.HandleFunc("POST /admin/api/change-password", func(w http.ResponseWriter, r *http.Request) {
			scheme, ok := requireSession(w, r)
			if !ok {
				return
			}
			var req struct {
				Username    string `json:"username"`
				OldPassword string `json:"old_password"`
				NewPassword string `json:"new_password"`
			}
			if !adminJSON(w, r, scheme, &req) {
				return
			}
			panel.mu.Lock()
			defer panel.mu.Unlock()
			if !panel.verifyPasswordLocked(req.OldPassword) {
				apiError(w, http.StatusUnauthorized, "当前密码不正确", 0)
				return
			}
			minPW := 6
			if panel.gateKey == "" {
				minPW = 12
			}
			if !validPrintableToken([]byte(req.NewPassword), minPW, 256) {
				apiError(w, http.StatusBadRequest, "新密码需为 "+strconv.Itoa(minPW)+"–256 位非空白可见字符", 0)
				return
			}
			newUser := strings.TrimSpace(req.Username)
			if newUser == "" {
				newUser = panel.username
			} else if !validPrintableToken([]byte(newUser), 1, 64) {
				apiError(w, http.StatusBadRequest, "账号格式无效", 0)
				return
			}
			var newSalt [16]byte
			rand.Read(newSalt[:])
			newHash := hashAdminPassword(newSalt, []byte(req.NewPassword))
			oldSalt, oldHash, oldUser := panel.pwSalt, panel.pwHash, panel.username
			panel.pwSalt, panel.pwHash, panel.username = newSalt, newHash, newUser
			if err := panel.saveRuntimeAuthLocked(); err != nil {
				panel.pwSalt, panel.pwHash, panel.username = oldSalt, oldHash, oldUser
				apiError(w, http.StatusInternalServerError, "保存新密码失败", 0)
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Username string `json:"username"`
			}{Username: panel.username})
		})

		private.HandleFunc("POST /admin/api/rotate-url-token", func(w http.ResponseWriter, r *http.Request) {
			scheme, ok := requireSession(w, r)
			if !ok {
				return
			}
			var req struct {
				Password string `json:"password"`
			}
			if !adminJSON(w, r, scheme, &req) {
				return
			}
			panel.mu.Lock()
			if !panel.verifyPasswordLocked(req.Password) {
				panel.mu.Unlock()
				apiError(w, http.StatusUnauthorized, "当前密码不正确", 0)
				return
			}
			var raw [8]byte
			rand.Read(raw[:])
			newGate := hex.EncodeToString(raw[:])
			oldGate := panel.gateKey
			panel.gateKey = newGate
			if err := panel.saveRuntimeAuthLocked(); err != nil {
				panel.gateKey = oldGate
				panel.mu.Unlock()
				apiError(w, http.StatusInternalServerError, "重置访问令牌失败", 0)
				return
			}
			expectedCookie := panel.gateCookieValLocked()
			panel.mu.Unlock()

			panel.issueGateCookie(w, scheme, expectedCookie)
			writeJSON(w, http.StatusOK, struct {
				URLToken string `json:"url_token"`
			}{URLToken: newGate})
		})

		private.HandleFunc("GET /admin/api/ip-blocks", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := requireSession(w, r); !ok {
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Items []ipBlockEntry `json:"items"`
			}{Items: panel.live.listIPBlocks()})
		})

		private.HandleFunc("POST /admin/api/ip-blocks/unblock", func(w http.ResponseWriter, r *http.Request) {
			scheme, ok := requireSession(w, r)
			if !ok {
				return
			}
			var req struct {
				IP string `json:"ip"`
			}
			if !adminJSON(w, r, scheme, &req) {
				return
			}
			panel.live.unblockIP(strings.TrimSpace(req.IP))
			w.WriteHeader(http.StatusNoContent)
		})

		private.HandleFunc("GET /admin/api/login-logs", func(w http.ResponseWriter, r *http.Request) {
			if _, ok := requireSession(w, r); !ok {
				return
			}
			writeJSON(w, http.StatusOK, struct {
				Items []loginLogEntry `json:"items"`
			}{Items: panel.live.listLoginLogs()})
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
