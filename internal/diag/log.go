// Package diag sets up logging.
package diag

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/rpajarola/gobootd/internal/config"
)

// Logs hands out loggers, one per service, each with its own level.
type Logs struct {
	w        io.Writer
	closer   io.Closer
	format   string
	level    slog.Level
	services map[string]slog.Level
}

// Open opens the log destination described by cfg.
func Open(cfg *config.Log) (*Logs, error) {
	l := &Logs{format: cfg.Format, services: map[string]slog.Level{}}
	switch cfg.File {
	case "stderr":
		l.w = os.Stderr
	case "stdout":
		l.w = os.Stdout
	default:
		f, err := os.OpenFile(cfg.File, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
		if err != nil {
			return nil, err
		}
		l.w, l.closer = f, f
	}
	var err error
	if l.level, err = parseLevel(cfg.Level); err != nil {
		return nil, err
	}
	for svc, s := range cfg.Services {
		if l.services[svc], err = parseLevel(s); err != nil {
			return nil, err
		}
	}
	return l, nil
}

// Logger returns the daemon's general logger.
func (l *Logs) Logger() *slog.Logger { return slog.New(l.handler(l.level)) }

// For returns the logger for a service.
func (l *Logs) For(svc string) *slog.Logger {
	lvl, ok := l.services[svc]
	if !ok {
		lvl = l.level
	}
	return slog.New(l.handler(lvl)).With("service", svc)
}

// Close closes the log file, if any.
func (l *Logs) Close() error {
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

func (l *Logs) handler(lvl slog.Level) slog.Handler {
	opts := &slog.HandlerOptions{Level: lvl}
	if l.format == "json" {
		return slog.NewJSONHandler(l.w, opts)
	}
	return slog.NewTextHandler(l.w, opts)
}

func parseLevel(s string) (slog.Level, error) {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(s)); err != nil {
		return 0, fmt.Errorf("invalid log level %q", s)
	}
	return lvl, nil
}
