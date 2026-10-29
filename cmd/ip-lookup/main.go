// Command ip-lookup serves the IP lookup website.
//
// Configuration comes from environment variables, see deploy/ip-lookup.env.example.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/zzusec/ip-lookup/internal/datasets"
	"github.com/zzusec/ip-lookup/internal/dnsq"
	"github.com/zzusec/ip-lookup/internal/lookup"
	"github.com/zzusec/ip-lookup/internal/server"
	"github.com/zzusec/ip-lookup/internal/sources"
	"github.com/zzusec/ip-lookup/web"
)

var version = "dev"

func env(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func main() {
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	listen := env("LISTEN", "127.0.0.1:8990")
	dataDir := env("DATA_DIR", "/var/lib/ip-lookup")
	contact := env("CONTACT", "https://github.com/zzusec/ip-lookup")
	ua := "ip-lookup/" + version + " (+" + contact + ")"
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	data := datasets.NewManager(dataDir, ua, log)
	data.LoadCached()
	httpc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second, MaxIdleConns: 50, MaxIdleConnsPerHost: 4,
		IdleConnTimeout: 90 * time.Second, ForceAttemptHTTP2: true,
	}}
	keys := sources.Keys{IPInfo: os.Getenv("IPINFO_TOKEN"), IPAPIIs: os.Getenv("IPAPIIS_KEY"),
		ProxyCheck: os.Getenv("PROXYCHECK_KEY"), IP2Location: os.Getenv("IP2LOCATION_KEY"),
		GreyNoise: os.Getenv("GREYNOISE_KEY")}
	svc := &lookup.Service{
		Data:    data,
		Online:  sources.NewSet(&sources.Client{HTTP: httpc, UA: ua}, sources.All(keys)),
		DNS:     dnsq.New(strings.Split(env("DNS_SERVERS", "1.1.1.1:53,8.8.8.8:53"), ",")),
		Timeout: 9 * time.Second,
	}
	srv := &server.Server{Lookup: svc, Web: web.FS, TrustProxy: env("TRUST_PROXY", "1") == "1", Log: log}
	h, err := srv.Handler()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if env("UPDATE", "1") == "1" {
		go data.Run(ctx)
	}
	hs := &http.Server{Addr: listen, Handler: h, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	log.Info("listening", "addr", listen, "data", dataDir, "version", version)
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := hs.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
