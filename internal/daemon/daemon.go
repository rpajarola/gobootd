// Package daemon loads the configuration and runs the boot services.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/diag"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/netif"
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
	// Networks the service is offered on.
	Networks []*netif.Network
}

// Subscribe returns a port on each of the service's networks that receives
// the frames match accepts.
func (e *Env) Subscribe(match func(link.Frame) bool) ([]link.Port, error) {
	if len(e.Networks) == 0 {
		return nil, errors.New("no network")
	}
	var ports []link.Port
	for _, n := range e.Networks {
		ports = append(ports, n.Subscribe(match))
	}
	return ports, nil
}

// Service is a boot protocol implementation.
type Service interface {
	// Run serves requests until ctx is cancelled. An error means the
	// service could not start or failed permanently.
	Run(ctx context.Context, env *Env) error
}

// Configurable is implemented by services that take options in their
// service block. Options returns a pointer to a struct with hcl tags; it
// is decoded before Run.
type Configurable interface {
	Options() any
}

// OpenNetwork opens a configured network; tests replace it.
var OpenNetwork = netif.Open

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
	for _, s := range cfg.Services {
		if factory, ok := lookup(s.Name); ok {
			l.Diags = append(l.Diags, DecodeOptions(factory(), s)...)
		}
	}
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
	defer wg.Wait()
	nets := map[string]*netif.Network{}
	for _, c := range l.Config.Networks {
		n, err := OpenNetwork(c)
		if err != nil {
			cancel(nil)
			return err
		}
		nets[c.Name] = n
		n.SetHosts(l.Inventory)
		n.RPC.SetLogger(log.With("network", c.Name))
		log.Info("network up", "network", c.Name, "address", n.Addr().String(), "mac", n.Interface().MAC.String(), "transport", n.Transport().Interface().Name)
		wg.Go(func() {
			if err := n.Run(ctx); err != nil && ctx.Err() == nil {
				cancel(fmt.Errorf("network %s: %w", c.Name, err))
			}
		})
	}
	for _, name := range l.Inventory.ServiceNames() {
		factory, ok := lookup(name)
		if !ok {
			log.Warn("service not implemented yet", "service", name)
			continue
		}
		env := &Env{Inventory: inv.Load, Log: logs.For(name), Config: l.Inventory.Services[name]}
		env.Networks = serviceNetworks(l.Config, env.Config, nets)
		svc := factory()
		DecodeOptions(svc, env.Config) // already checked by Load
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := svc.Run(ctx, env); err != nil && ctx.Err() == nil {
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
			for _, net := range nets {
				net.SetHosts(n.Inventory)
			}
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

// serviceNetworks returns the networks a service is offered on: those it
// names, or all.
func serviceNetworks(cfg *config.Config, s *config.Service, nets map[string]*netif.Network) []*netif.Network {
	var out []*netif.Network
	for _, c := range cfg.Networks {
		if len(s.Networks) == 0 || slices.Contains(s.Networks, c.Name) {
			out = append(out, nets[c.Name])
		}
	}
	return out
}

// DecodeOptions decodes the options in the service block into svc. A
// service without options rejects any.
func DecodeOptions(svc Service, s *config.Service) hcl.Diagnostics {
	var opts any = &struct{}{}
	if c, ok := svc.(Configurable); ok {
		opts = c.Options()
	}
	return gohcl.DecodeBody(s.Options, nil, opts)
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
