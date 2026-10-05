// Package daemon loads the configuration and runs the boot services.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/hcl/v2"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/diag"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/resolve"
	"github.com/rpajarola/gobootd/internal/service"
)

// Env is what a running service gets from the daemon.
type Env struct {
	// Inventory returns the current inventory. It changes when the
	// configuration is reloaded; fetch it once per request.
	Inventory func() *inventory.Inventory
	Log       *slog.Logger
	// Config is the service's block from the configuration. Changes to
	// it take effect on restart.
	Config *config.Service
}

// Service is a boot protocol implementation.
type Service interface {
	// Run serves requests until ctx is cancelled. An error means the
	// service could not start or failed permanently.
	Run(ctx context.Context, env *Env) error
}

var (
	mu       sync.Mutex
	registry = map[string]func() Service{}
)

// Register makes an implementation available for a known service name.
func Register(name string, factory func() Service) {
	mu.Lock()
	defer mu.Unlock()
	if !service.Known(name) {
		panic("daemon: registering unknown service " + name)
	}
	registry[name] = factory
}

func lookup(name string) (func() Service, bool) {
	mu.Lock()
	defer mu.Unlock()
	f, ok := registry[name]
	return f, ok
}

// Loaded is the result of loading a configuration file.
type Loaded struct {
	Config    *config.Config
	Inventory *inventory.Inventory
	// Files holds the parsed sources, for printing diagnostics.
	Files map[string]*hcl.File
	Diags hcl.Diagnostics
}

// WriteDiags prints the diagnostics with source context.
func (l *Loaded) WriteDiags(w io.Writer) error {
	return hcl.NewDiagnosticTextWriter(w, l.Files, 0, false).WriteDiagnostics(l.Diags)
}

// Load parses the configuration at path and builds the inventory. Inventory
// is nil if the configuration has errors.
func Load(path string) *Loaded {
	cfg, p, diags := config.Load(path)
	l := &Loaded{Config: cfg, Files: p.Files(), Diags: diags}
	if diags.HasErrors() {
		return l
	}
	r, err := resolve.NewSystem(*cfg.Resolve.Ethers, *cfg.Resolve.DNS)
	if err != nil {
		l.Diags = append(l.Diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "Cannot read ethers file", Detail: err.Error()})
		return l
	}
	inv, d := inventory.Build(cfg, r)
	l.Diags = append(l.Diags, d...)
	if !l.Diags.HasErrors() {
		l.Inventory = inv
	}
	return l
}

// Run starts every enabled service and serves until ctx is cancelled or a
// service fails. Each value received on reload rebuilds the inventory from
// path; a configuration with errors is logged and ignored.
func Run(ctx context.Context, path string, reload <-chan struct{}, stderr io.Writer) error {
	l := Load(path)
	if l.Inventory == nil {
		l.WriteDiags(stderr)
		return errors.New("configuration has errors")
	}
	logs, err := diag.Open(l.Config.Log)
	if err != nil {
		return err
	}
	defer logs.Close()
	log := logs.Logger()
	logDiags(log, l.Diags)

	var inv atomic.Pointer[inventory.Inventory]
	inv.Store(l.Inventory)

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	for _, name := range l.Inventory.ServiceNames() {
		factory, ok := lookup(name)
		if !ok {
			log.Warn("service not implemented yet", "service", name)
			continue
		}
		env := &Env{Inventory: inv.Load, Log: logs.For(name), Config: l.Inventory.Services[name]}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := factory().Run(ctx, env); err != nil && ctx.Err() == nil {
				cancel(fmt.Errorf("service %s: %w", name, err))
			}
		}()
	}
	log.Info("bootd started", "config", path, "hosts", len(l.Inventory.Hosts), "services", l.Inventory.ServiceNames())

	for {
		select {
		case <-reload:
			n := Load(path)
			logDiags(log, n.Diags)
			if n.Inventory == nil {
				log.Error("configuration has errors, keeping the previous one", "config", path)
				continue
			}
			inv.Store(n.Inventory)
			log.Info("configuration reloaded; service and log settings take effect on restart", "hosts", len(n.Inventory.Hosts))
		case <-ctx.Done():
			wg.Wait()
			if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
				return err
			}
			log.Info("bootd stopped")
			return nil
		}
	}
}

func logDiags(log *slog.Logger, diags hcl.Diagnostics) {
	for _, d := range diags {
		lvl := slog.LevelWarn
		if d.Severity == hcl.DiagError {
			lvl = slog.LevelError
		}
		attrs := []any{"detail", d.Detail}
		if d.Subject != nil {
			attrs = append(attrs, "at", d.Subject.String())
		}
		log.Log(context.Background(), lvl, d.Summary, attrs...)
	}
}
