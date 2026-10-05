// Package prototest runs protocol services against a test configuration.
package prototest

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
)

// Inventory builds an inventory from configuration source. Relative paths
// resolve against dir. Resolution of missing addresses is disabled.
func Inventory(t testing.TB, dir, src string) *inventory.Inventory {
	t.Helper()
	cfg, _, diags := config.Parse([]byte(src), filepath.Join(dir, "bootd.hcl"))
	if diags.HasErrors() {
		t.Fatalf("config: %v", diags)
	}
	inv, diags := inventory.Build(cfg, nil)
	if diags.HasErrors() {
		t.Fatalf("inventory: %v", diags)
	}
	return inv
}

// Log collects log output for assertions.
type Log struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
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

// Start runs svc with the named service block of inv until the test ends.
func Start(t testing.TB, svc daemon.Service, name string, inv *inventory.Inventory, opener link.Opener) *Log {
	t.Helper()
	log := &Log{}
	cfg := inv.Services[name]
	if cfg == nil {
		t.Fatalf("no service %q in configuration", name)
	}
	if d := daemon.DecodeOptions(svc, cfg); d.HasErrors() {
		t.Fatalf("options: %v", d)
	}
	env := &daemon.Env{
		Inventory: func() *inventory.Inventory { return inv },
		Log:       slog.New(slog.NewTextHandler(teeWriter{log}, &slog.HandlerOptions{Level: slog.LevelDebug})).With("service", name),
		Config:    cfg,
		Link:      opener,
	}
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
	return log
}

type teeWriter struct{ l *Log }

func (w teeWriter) Write(p []byte) (int, error) {
	if os.Getenv("PROTOTEST_VERBOSE") != "" {
		os.Stderr.Write(p)
	}
	return w.l.Write(p)
}

// FilterMatches reports whether a pcap filter accepts frame. It writes the
// frame to a capture file and lets tcpdump apply the filter, which needs no
// privileges. (gopacket's offline filter compiler crashes on macOS.) The
// test is skipped if tcpdump is not installed.
func FilterMatches(t testing.TB, filter string, frame []byte) bool {
	t.Helper()
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump not installed")
	}
	path := filepath.Join(t.TempDir(), "frame.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	frame = link.Pad(frame)
	if err := w.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Now(), CaptureLength: len(frame), Length: len(frame)}, frame); err != nil {
		t.Fatal(err)
	}
	f.Close()
	out, err := exec.Command(tcpdump, "-n", "-r", path, filter).CombinedOutput()
	if err != nil {
		t.Fatalf("tcpdump %q: %v\n%s", filter, err, out)
	}
	// tcpdump prints one line per matching packet, after a "reading
	// from file" line on stderr.
	for _, l := range strings.Split(string(out), "\n") {
		if l != "" && !strings.HasPrefix(l, "reading from file") {
			return true
		}
	}
	return false
}
