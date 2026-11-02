package control

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

var sunMAC = net.HardwareAddr{0x08, 0, 0x20, 0, 0, 1}

// testServer runs a control server over a bridge with one UDP transport
// that has a configured peer nobody ever sends to.
func testServer(t *testing.T) (*Server, *bridge.Bridge, *link.UDP) {
	t.Helper()
	seg := linktest.NewSegment()
	lanPort := seg.Station("02:00:00:00:00:fe")
	udp := mustListen(t, netip.MustParseAddrPort("127.0.0.1:5099"))
	b := &bridge.Bridge{LAN: lanPort, UDP: udp, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go b.Run(ctx)

	path := filepath.Join(t.TempDir(), "ctl.sock")
	s := New(b, Info{Version: "test", PID: 1234, Interface: "station"})
	s.Log = slog.New(slog.DiscardHandler)
	if err := s.Listen(path); err != nil {
		t.Fatal(err)
	}
	go s.Run(ctx)
	t.Cleanup(func() { s.Close() })
	// Wait for the socket.
	for range 100 {
		if c, err := net.Dial("unix", path); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return s, b, udp
}

func mustListen(t *testing.T, peers ...netip.AddrPort) *link.UDP {
	t.Helper()
	u, err := link.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), peers)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { u.Close() })
	return u
}

func request(t *testing.T, s *Server, method string, a Args) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	b, err := json.Marshal(Request{Method: method, Args: &a})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
	return c
}

func readLine(t *testing.T, c net.Conn) map[string]json.RawMessage {
	t.Helper()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatalf("bad JSON %q: %v", line, err)
	}
	if e, ok := v["error"]; ok {
		var s string
		json.Unmarshal(e, &s)
		t.Fatalf("server error: %s", s)
	}
	return v
}

func TestDefaultPath(t *testing.T) {
	if got := DefaultPath(0); got != "/run/bootbridge/bootbridge.sock" {
		t.Errorf("root: %s", got)
	}
	t.Setenv("XDG_RUNTIME_DIR", "/run/user/1000")
	if got := DefaultPath(1000); got != "/run/user/1000/bootbridge/bootbridge.sock" {
		t.Errorf("user: %s", got)
	}
}

func TestStatus(t *testing.T) {
	s, b, _ := testServer(t)
	b.SetPrintInterface("udp")
	v := readLine(t, request(t, s, "status", Args{}))
	var st struct {
		Version    string `json:"version"`
		PID        int    `json:"pid"`
		Socket     string `json:"socket"`
		Interface  string `json:"interface"`
		PrintIface string `json:"print_interface"`
	}
	decode(t, v, &st)
	if st.Version != "test" || st.Socket != s.Addr() || st.PID != 1234 || st.Interface != "station" {
		t.Errorf("status %+v", st)
	}
	if st.PrintIface != "udp" {
		t.Errorf("print_interface %q", st.PrintIface)
	}
}

func TestPeers(t *testing.T) {
	s, _, udp := testServer(t)
	peer := mustListen(t, udp.Addr())
	// Let the bridge hear the peer.
	if err := peer.WriteFrame(link.Build(link.Broadcast, sunMAC, 0x9000, []byte("hi"))); err != nil {
		t.Fatal(err)
	}
	for range 100 {
		if len(udp.PeersSnapshot()) > 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	v := readLine(t, request(t, s, "peers", Args{}))
	var out struct {
		Transports []struct {
			Name          string `json:"name"`
			Encapsulation string `json:"encapsulation"`
			Peers         []struct {
				Addr   string `json:"addr"`
				Static bool   `json:"static"`
			} `json:"peers"`
			MACs []struct {
				MAC string `json:"mac"`
			} `json:"macs"`
		} `json:"transports"`
	}
	decode(t, v, &out)
	if len(out.Transports) != 1 || out.Transports[0].Encapsulation != "raw" {
		t.Fatalf("transports %+v", out.Transports)
	}
	tr := out.Transports[0]
	if len(tr.Peers) < 2 {
		t.Fatalf("peers %+v, want the configured one and the learned one", tr.Peers)
	}
	learned := false
	for _, p := range tr.Peers {
		if p.Addr == peer.Addr().String() && !p.Static {
			learned = true
		}
	}
	if !learned {
		t.Errorf("learned peer %s missing: %+v", peer.Addr(), tr.Peers)
	}
	if len(tr.MACs) == 0 {
		t.Errorf("no learned MACs")
	}

	// The LAN filter leaves the UDP transports out.
	v = readLine(t, request(t, s, "peers", Args{Iface: "lan"}))
	decode(t, v, &out)
	if len(out.Transports) != 0 {
		t.Errorf("transports with -i lan: %+v", out.Transports)
	}
}

func TestSet(t *testing.T) {
	s, b, _ := testServer(t)
	on, want := true, "lan"
	v := readLine(t, request(t, s, "set", Args{Print: &on, Dump: &on, Iface: want}))
	var st struct {
		Print      bool   `json:"print"`
		Dump       bool   `json:"dump"`
		PrintIface string `json:"print_interface"`
	}
	decode(t, v, &st)
	if !st.Print || !st.Dump || st.PrintIface != want {
		t.Errorf("after set: %+v", st)
	}
	if !b.IsDumpPackets() {
		t.Error("bridge not in dump mode")
	}
}

func TestStats(t *testing.T) {
	s, _, udp := testServer(t)
	peer := mustListen(t, udp.Addr())
	peer.WriteFrame(link.Build(link.Broadcast, sunMAC, link.TypeIPv4, []byte("data")))
	for range 100 {
		if s.Bridge.UDPStats().RxPackets > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	v := readLine(t, request(t, s, "stats", Args{}))
	var st struct {
		UDP struct {
			Name      string `json:"name"`
			RxPackets uint64 `json:"rx_packets"`
		} `json:"udp"`
	}
	decode(t, v, &st)
	if st.UDP.Name == "" || st.UDP.RxPackets == 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestTailAndLog(t *testing.T) {
	s, b, udp := testServer(t)
	peer := mustListen(t, udp.Addr())
	w := b.Watch(0)
	defer w.Stop()
	for range 3 {
		peer.WriteFrame(link.Build(link.Broadcast, sunMAC, link.TypeIPv4, []byte("x")))
		<-w.Events
	}

	// tail answers with the remembered frames and closes.
	v := readLine(t, request(t, s, "tail", Args{N: 2}))
	var e Entry
	decode(t, v, &e)
	frame, err := hex.DecodeString(e.Frame)
	if err != nil {
		t.Fatalf("frame not hex: %q", e.Frame)
	}
	if len(frame) < link.HeaderLen || e.Action == "" {
		t.Errorf("entry %+v", e)
	}
	c := request(t, s, "tail", Args{})
	lines := 0
	sc := bufio.NewScanner(c)
	for sc.Scan() {
		lines++
	}
	if lines < 3 {
		t.Errorf("tail sent %d lines, want the whole ring (at least 3)", lines)
	}

	// log streams live frames after replaying history.
	c = request(t, s, "log", Args{Tail: 1})
	defer c.Close()
	sc = bufio.NewScanner(c)
	if !sc.Scan() {
		t.Fatal("no replayed frame")
	}
	peer.WriteFrame(link.Build(link.Broadcast, sunMAC, link.TypeIPv4, []byte("live")))
	if !sc.Scan() {
		t.Fatal("no live frame")
	}
	decode(t, mustLine(t, sc), &e)
}

func TestUnknownMethod(t *testing.T) {
	s, _, _ := testServer(t)
	c := request(t, s, "bogus", Args{})
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	json.Unmarshal([]byte(line), &v)
	if v["error"] == nil {
		t.Errorf("no error for unknown method: %s", line)
	}
}

func TestSocketPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	b := &bridge.Bridge{Log: slog.New(slog.DiscardHandler)}
	s := New(b, Info{})
	if err := s.Listen(path); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o660 {
		t.Errorf("mode %v, want 0660", st.Mode().Perm())
	}
}

func TestListenInUse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ctl.sock")
	b := &bridge.Bridge{Log: slog.New(slog.DiscardHandler)}
	s := New(b, Info{})
	if err := s.Listen(path); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	if err := New(b, Info{}).Listen(path); err == nil {
		t.Error("second listener accepted while the socket is in use")
	}
}

func decode(t *testing.T, v map[string]json.RawMessage, ptr any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, ptr); err != nil {
		t.Fatal(err)
	}
}

func mustLine(t *testing.T, sc *bufio.Scanner) map[string]json.RawMessage {
	t.Helper()
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	var v map[string]json.RawMessage
	if err := json.Unmarshal(sc.Bytes(), &v); err != nil {
		t.Fatalf("bad JSON %q: %v", sc.Text(), err)
	}
	return v
}
