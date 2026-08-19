package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

// zoneFlag collects repeatable -zone arguments of the form "origin=path" or "path".
type zoneFlag []string

func (z *zoneFlag) String() string { return strings.Join(*z, ",") }

func (z *zoneFlag) Set(v string) error {
	*z = append(*z, v)
	return nil
}

func main() {
	var zones zoneFlag
	listen := flag.String("listen", "127.0.0.1:53", "address to listen on, used for both UDP and TCP")
	flag.Var(&zones, "zone", "zone master file to serve; repeatable. Form \"origin=path\" or \"path\" (origin from the file's $ORIGIN, else the file name without extension)")
	upstream := flag.String("upstream", "", "recursive resolver to forward non-local queries to, e.g. 1.1.1.1:53")
	cacheSize := flag.Int("cache-size", 4096, "maximum number of cached recursive responses")
	timeout := flag.Duration("upstream-timeout", 5*time.Second, "timeout for upstream queries")
	logLevel := flag.String("log-level", "info", "log level: debug, info, warn or error")
	flag.Parse()

	var level slog.Level
	switch *logLevel {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		fmt.Fprintf(os.Stderr, "dnsd: invalid -log-level %q\n", *logLevel)
		os.Exit(2)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	zs, err := loadZones(zones)
	if err != nil {
		logger.Error("loading zones", "error", err)
		os.Exit(1)
	}
	if len(zs) == 0 {
		logger.Warn("no zones loaded; answering REFUSED unless -upstream is set")
	}

	srv := New(Config{
		Addr:      *listen,
		Zones:     zs,
		Upstream:  *upstream,
		Timeout:   *timeout,
		CacheSize: *cacheSize,
		Logger:    logger,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := srv.ListenAndServe(ctx); err != nil {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

// loadZones parses the -zone arguments; "origin=path" overrides the origin.
func loadZones(specs []string) ([]*Zone, error) {
	var out []*Zone
	for _, spec := range specs {
		origin, path := "", spec
		if i := strings.Index(spec, "="); i >= 0 {
			origin, path = spec[:i], spec[i+1:]
		}
		z, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		if origin != "" {
			z.Origin = CanonicalName(origin)
		}
		out = append(out, z)
	}
	return out, nil
}
