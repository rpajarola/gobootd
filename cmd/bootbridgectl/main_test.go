package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/control"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

var testSun = net.HardwareAddr{0x08, 0, 0x20, 0, 0, 1}

type harness struct {
	socket string
	peer   *link.UDP
	out    *bytes.Buffer
}

// newHarness runs a bridge with a control socket and one learned peer.
func newHarness(t *testing.T) *harness {
	t.Helper()
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	sun := seg.Station("08:00:20:00:00:01")
	udp := listenUDP(t, netip.MustParseAddrPort("127.0.0.1:5099"))
	b := &bridge.Bridge{LAN: lanPort, UDP: udp, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go b.Run(ctx)

	peer := listenUDP(t, udp.Addr())
	peer.WriteFrame(link.Build(link.Broadcast, testSun, link.TypeIPv4, []byte("hi")))
	sun.WriteFrame(link.Build(link.Broadcast, testSun, link.TypeIPv4, []byte("hello")))
	time.Sleep(100 * time.Millisecond)

	path := filepath.Join(t.TempDir(), "ctl.sock")
	s := control.New(b, control.Info{Version: "test", PID: 1234, Interface: "station", Config: "/etc/bootbridge.hcl"})
	s.Log = slog.New(slog.DiscardHandler)
	if err := s.Listen(path); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	t.Cleanup(func() { _ = s.Close() })
	return &harness{socket: path, peer: peer, out: &bytes.Buffer{}}
}

func listenUDP(t *testing.T, peers ...netip.AddrPort) *link.UDP {
	t.Helper()
	u, err := link.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), peers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

func (h *harness) run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var errb bytes.Buffer
	// The socket follows the command name, where every flag goes.
	full := append([]string{args[0], "-socket", h.socket}, args[1:]...)
	code := mainCmd(full, h.out, &errb)
	return code, errb.String()
}

func TestUsage(t *testing.T) {
	var out, errb bytes.Buffer
	if code := mainCmd(nil, &out, &errb); code != 2 {
		t.Errorf("code %d, want 2", code)
	}
	if !strings.Contains(out.String(), "usage: bootbridgectl") {
		t.Errorf("no usage: %q", out.String())
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := mainCmd([]string{"bogus"}, &out, &errb); code != 2 {
		t.Errorf("code %d, want 2", code)
	}
	if !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("stderr %q", errb.String())
	}
}

func TestStatus(t *testing.T) {
	h := newHarness(t)
	code, errs := h.run(t, "status")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	got := h.out.String()
	for _, want := range []string{"test", "1234", "station", h.socket, "printing"} {
		if !strings.Contains(got, want) {
			t.Errorf("status output missing %q:\n%s", want, got)
		}
	}
}

func TestPeers(t *testing.T) {
	h := newHarness(t)
	code, errs := h.run(t, "peers")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	got := h.out.String()
	for _, want := range []string{"configured", "127.0.0.1:5099", h.peer.Addr().String(), "learned", testSun.String()} {
		if !strings.Contains(got, want) {
			t.Errorf("peers output missing %q:\n%s", want, got)
		}
	}
}

func TestStats(t *testing.T) {
	h := newHarness(t)
	code, errs := h.run(t, "stats")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	if !strings.Contains(h.out.String(), "RX PKTS") {
		t.Errorf("stats output:\n%s", h.out.String())
	}
}

func TestTail(t *testing.T) {
	h := newHarness(t)
	code, errs := h.run(t, "tail", "-n", "1")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	if !strings.Contains(h.out.String(), "IP") {
		t.Errorf("tail output:\n%s", h.out.String())
	}
}

func TestSetAndJSON(t *testing.T) {
	h := newHarness(t)
	code, errs := h.run(t, "set", "-json", "-print", "on", "-dump", "on", "-iface", "lan")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	var v map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(h.out.Bytes()), &v); err != nil {
		t.Fatalf("output is not one JSON object: %q: %v", h.out.String(), err)
	}
	if v["print"] != true || v["dump"] != true || v["print_interface"] != "lan" {
		t.Errorf("set response %v", v)
	}
}

func TestNotRunning(t *testing.T) {
	var out, errb bytes.Buffer
	code := mainCmd([]string{"status", "-socket", filepath.Join(t.TempDir(), "missing.sock")}, &out, &errb)
	if code != 1 {
		t.Fatalf("code %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "is bootbridge running") {
		t.Errorf("stderr %q", errb.String())
	}
}
