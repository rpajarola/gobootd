// Package prototest runs protocol services against a test configuration on
// an in-memory Ethernet segment.
package prototest

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/netif"
)

// Env is a parsed test configuration with its networks attached to a
// segment.
type Env struct {
	Config    *config.Config
	Inventory *inventory.Inventory
	Networks  map[string]*netif.Network
	Segment   *linktest.Segment
}

// Setup parses configuration source, builds the inventory and runs every
// network block on a new segment until the test ends. Relative paths
// resolve against dir. Resolution of missing addresses is disabled.
func Setup(t testing.TB, dir, src string) *Env {
	t.Helper()
	cfg, _, diags := config.Parse([]byte(src), filepath.Join(dir, "bootd.hcl"))
	if diags.HasErrors() {
		t.Fatalf("config: %v", diags)
	}
	inv, diags := inventory.Build(cfg, nil)
	if diags.HasErrors() {
		t.Fatalf("inventory: %v", diags)
	}
	e := &Env{Config: cfg, Inventory: inv, Networks: map[string]*netif.Network{}, Segment: linktest.NewSegment()}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})
	for _, c := range cfg.Networks {
		addr := netip.MustParsePrefix(c.Address)
		mac := link.DefaultMAC(c.Name, addr)
		if c.MAC != "" {
			mac, _ = net.ParseMAC(c.MAC)
		}
		n, err := netif.New(c, e.Segment.Station(mac.String()), mac)
		if err != nil {
			t.Fatal(err)
		}
		n.SetHosts(inv)
		e.Networks[c.Name] = n
		wg.Go(func() { n.Run(ctx) })
	}
	return e
}

// Client attaches an IP stack with the given addresses to the segment, as
// a test client.
func (e *Env) Client(t testing.TB, mac, addr string) *ipstack.Stack {
	t.Helper()
	hw, err := net.ParseMAC(mac)
	if err != nil {
		t.Fatal(err)
	}
	st, err := ipstack.New(e.Segment.Station(mac), hw, netip.MustParsePrefix(addr))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { st.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return st
}

// Log collects log output for assertions.
type Log struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if os.Getenv("PROTOTEST_VERBOSE") != "" {
		os.Stderr.Write(p)
	}
	return l.buf.Write(p)
}

// String returns everything logged so far.
func (l *Log) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Contains reports whether s was logged, waiting up to a second for it.
func (l *Log) Contains(s string) bool {
	for range 100 {
		if bytes.Contains([]byte(l.String()), []byte(s)) {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return false
}

// ServiceEnv returns the environment for svc with the named service block,
// with svc's options decoded, without running it. Its log goes to log.
func (e *Env) ServiceEnv(t testing.TB, svc daemon.Service, name string, log *Log) *daemon.Env {
	t.Helper()
	var cfg *config.Service
	for _, s := range e.Config.Services {
		if s.Name == name {
			cfg = s
		}
	}
	if cfg == nil {
		t.Fatalf("no service %q in configuration", name)
	}
	if d := daemon.DecodeOptions(svc, cfg); d.HasErrors() {
		t.Fatalf("options: %v", d)
	}
	env := &daemon.Env{
		Inventory: func() *inventory.Inventory { return e.Inventory },
		Log:       slog.New(slog.NewTextHandler(log, &slog.HandlerOptions{Level: slog.LevelDebug})).With("service", name),
		Config:    cfg,
	}
	for _, c := range e.Config.Networks {
		if len(cfg.Networks) == 0 || slices.Contains(cfg.Networks, c.Name) {
			env.Networks = append(env.Networks, e.Networks[c.Name])
		}
	}
	return env
}

// Start runs svc with the named service block until the test ends.
func (e *Env) Start(t testing.TB, svc daemon.Service, name string) *Log {
	t.Helper()
	log := &Log{}
	env := e.ServiceEnv(t, svc, name, log)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- svc.Run(ctx, env) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if t.Failed() {
			t.Logf("log:\n%s", log)
		}
	})
	// Let the service subscribe before the test sends.
	time.Sleep(20 * time.Millisecond)
	return log
}
