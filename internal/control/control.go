// Package control serves the bootbridge debug interface: a Unix socket
// that answers JSON lines from bootbridgectl, reporting peers, statistics
// and the frames that pass through the bridge.
package control

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/link"
)

// DefaultPath returns the socket path a bootbridge of this user listens on
// and the one bootbridgectl looks for when none is given:
// /run/bootbridge/bootbridge.sock for root (or /var/run where there is no
// /run, as on macOS), and a per-user socket under $XDG_RUNTIME_DIR or
// /tmp for anyone else. Several bridges on one machine need explicit -ctl
// and -socket paths; bootbridge always logs the path it uses.
func DefaultPath(uid int) string {
	if uid == 0 {
		return filepath.Join(runtimeDir(), "bootbridge", "bootbridge.sock")
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		return filepath.Join(dir, "bootbridge", "bootbridge.sock")
	}
	return filepath.Join(os.TempDir(), "bootbridge-"+strconv.Itoa(uid), "bootbridge.sock")
}

// runtimeDir is where daemons keep their run-time files: /run on Linux,
// and /var/run on systems without /run, where root may not create one.
func runtimeDir() string {
	if fi, err := os.Stat("/run"); err == nil && fi.IsDir() {
		return "/run"
	}
	return "/var/run"
}

// Request is one command line from the client.
type Request struct {
	Method string `json:"method"`
	Args   *Args  `json:"args,omitempty"`
}

// Args are the method arguments; each method uses only the fields it
// needs.
type Args struct {
	// N is how many remembered frames tail sends (0 for all).
	N int `json:"n,omitempty"`
	// Tail is how many remembered frames log and dump replay before
	// streaming live.
	Tail int `json:"tail,omitempty"`
	// Iface limits the output to one interface ("lan", "udp", or a name).
	Iface string `json:"iface,omitempty"`
	// Print, Dump and Iface are set by the set command.
	Print *bool `json:"print,omitempty"`
	Dump  *bool `json:"dump,omitempty"`
	// Watch makes stats keep streaming.
	Watch bool `json:"watch,omitempty"`
}

// Entry is one frame on the wire; Frame is the hex-encoded bytes.
type Entry struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Interface string    `json:"interface"`
	Action    string    `json:"action"`
	Peer      string    `json:"peer,omitempty"`
	Frame     string    `json:"frame"`
}

// Info describes the running bridge to the status command; the daemon
// fills it in.
type Info struct {
	Version   string
	PID       int
	Socket    string
	Config    string
	Interface string
	MAC       string
}

// Server answers control requests about one bridge.
type Server struct {
	Bridge *bridge.Bridge
	Info   Info
	// Mode is the socket's permissions; New defaults it to 0660.
	Mode os.FileMode
	Log  *slog.Logger

	l     net.Listener
	mu    sync.Mutex
	path  string
	start time.Time
}

// New returns a server for b.
func New(b *bridge.Bridge, info Info) *Server {
	return &Server{Bridge: b, Info: info, Mode: 0o660, start: time.Now()}
}

// Listen opens the control socket at path, creating its parent directory.
// An empty path means DefaultPath for the running user.
func (s *Server) Listen(path string) error {
	if path == "" {
		path = DefaultPath(os.Geteuid())
	}
	s.Info.Socket = path
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// A socket file left by a killed bootbridge would make Listen fail;
	// nobody is connected to it if the address is not in use.
	if a, err := net.DialTimeout("unix", path, 100*time.Millisecond); err == nil {
		a.Close()
		return fmt.Errorf("%s is in use by another bootbridge", path)
	}
	os.Remove(path)
	u, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return err
	}
	if s.Mode != 0 {
		if err := os.Chmod(path, s.Mode); err != nil {
			u.Close()
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.l != nil {
		u.Close()
		return errors.New("already listening")
	}
	s.l, s.path = u, path
	return nil
}

// Addr returns the socket path.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.path
}

// Run serves control requests until ctx is done, then removes the socket.
func (s *Server) Run(ctx context.Context) error {
	s.mu.Lock()
	l := s.l
	s.mu.Unlock()
	if l == nil {
		return errors.New("control: not listening")
	}
	if uc, ok := l.(*net.UnixListener); ok {
		uc.SetUnlinkOnClose(false) // Close removes the file
	}
	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serve(ctx, c)
	}
}

// Close stops listening and removes the socket file.
func (s *Server) Close() error {
	s.mu.Lock()
	l, path := s.l, s.path
	s.l = nil
	s.mu.Unlock()
	if l == nil {
		return nil
	}
	err := l.Close()
	os.Remove(path)
	return err
}

func (s *Server) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Server) serve(ctx context.Context, c net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			s.log().Error("control request panicked", "err", r)
		}
		c.Close()
	}()
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		return
	}
	var r Request
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		writeError(c, "bad request: "+err.Error())
		return
	}
	if err := s.handle(ctx, c, &r); err != nil && !errors.Is(err, context.Canceled) && !isClosed(err) {
		s.log().Debug("control request failed", "method", r.Method, "err", err)
	}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}

func (s *Server) handle(ctx context.Context, c net.Conn, r *Request) error {
	a := Args{}
	if r.Args != nil {
		a = *r.Args
	}
	switch r.Method {
	case "status":
		return s.status(c)
	case "peers":
		return s.peers(c, a.Iface)
	case "stats":
		return s.stats(c, a.Watch)
	case "set":
		return s.set(c, a)
	case "tail":
		return s.tail(c, a)
	case "log", "dump":
		return s.frames(ctx, c, a)
	default:
		return writeError(c, "unknown method "+r.Method)
	}
}

func writeJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

func writeError(w io.Writer, msg string) error {
	return writeJSON(w, map[string]string{"error": msg})
}

func (s *Server) status(w io.Writer) error {
	b := s.Bridge
	return writeJSON(w, map[string]any{
		"version":         s.Info.Version,
		"pid":             s.Info.PID,
		"socket":          s.Info.Socket,
		"config":          s.Info.Config,
		"interface":       s.Info.Interface,
		"mac":             s.Info.MAC,
		"uptime":          time.Since(s.start).Round(time.Second).String(),
		"print":           b.IsPrintPackets(),
		"dump":            b.IsDumpPackets(),
		"print_interface": b.GetPrintInterface(),
	})
}

type transportJSON struct {
	Name          string     `json:"name"`
	Encapsulation string     `json:"encapsulation"`
	Peers         []peerJSON `json:"peers"`
	MACs          []macJSON  `json:"macs"`
}

type peerJSON struct {
	Addr     string `json:"addr"`
	Static   bool   `json:"static"`
	LastSeen string `json:"last_seen,omitempty"`
}

type macJSON struct {
	MAC      string `json:"mac"`
	Addr     string `json:"addr"`
	LastSeen string `json:"last_seen,omitempty"`
}

type hostJSON struct {
	MAC string `json:"mac"`
	IP  string `json:"ip,omitempty"`
}

// matchIface reports whether name passes the filter, in the style of
// bootbridge's -print-iface: lan and udp name the sides, anything else
// must be part of the interface's name.
func matchIface(filter, name string, isLAN func(string) bool) bool {
	switch strings.ToLower(filter) {
	case "", "all":
		return true
	case "lan":
		return isLAN(name)
	case "udp", "l2tp":
		return !isLAN(name)
	}
	return strings.EqualFold(name, filter) || strings.Contains(name, filter)
}

func (s *Server) peers(w io.Writer, iface string) error {
	b := s.Bridge
	isLAN := func(name string) bool { return name == b.LANName() }
	var ts []transportJSON
	for _, t := range b.UDPPeers() {
		if matchIface(iface, t.Name, isLAN) {
			ts = append(ts, convertTransport(t))
		}
	}
	out := map[string]any{"transports": ts}
	if matchIface(iface, b.LANName(), isLAN) {
		out["lan_hosts"] = convertHosts(b.LANHosts())
	}
	if matchIface(iface, b.UDPName(), isLAN) {
		out["udp_hosts"] = convertHosts(b.UDPHosts())
	}
	return writeJSON(w, out)
}

func convertTransport(t link.TransportState) transportJSON {
	out := transportJSON{Name: t.Name, Encapsulation: t.Encapsulation}
	for _, p := range t.Peers {
		out.Peers = append(out.Peers, peerJSON{Addr: p.Addr.String(), Static: p.Static, LastSeen: timeStr(p.LastSeen)})
	}
	for _, m := range t.MACs {
		out.MACs = append(out.MACs, macJSON{MAC: m.MAC.String(), Addr: m.Addr.String(), LastSeen: timeStr(m.LastSeen)})
	}
	return out
}

func convertHosts(hs []bridge.HostEntry) []hostJSON {
	out := make([]hostJSON, 0, len(hs))
	for _, h := range hs {
		out = append(out, hostJSON{MAC: h.MAC.String(), IP: h.IP.String()})
	}
	return out
}

func timeStr(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

type statsJSON struct {
	Name      string `json:"name"`
	Hosts     int    `json:"hosts"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	Errors    uint64 `json:"errors"`
}

func statsOf(s bridge.InterfaceStats) statsJSON {
	return statsJSON{s.Name, s.Hosts, s.RxPackets, s.TxPackets, s.RxBytes, s.TxBytes, s.Errors}
}

func (s *Server) stats(w io.Writer, watch bool) error {
	if !watch {
		return writeJSON(w, s.statsSnapshot())
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		if err := writeJSON(w, s.statsSnapshot()); err != nil {
			return err
		}
		<-t.C
	}
}

func (s *Server) statsSnapshot() map[string]any {
	b := s.Bridge
	return map[string]any{"time": time.Now().Format(time.RFC3339), "lan": statsOf(b.LANStats()), "udp": statsOf(b.UDPStats())}
}

func (s *Server) set(w io.Writer, a Args) error {
	b := s.Bridge
	if a.Print != nil {
		b.SetPrintPackets(*a.Print)
	}
	if a.Dump != nil {
		b.SetDumpPackets(*a.Dump)
	}
	if a.Iface != "" {
		b.SetPrintInterface(a.Iface)
	}
	return s.status(w)
}

// tail sends the n last remembered frames, all of them for n <= 0.
func (s *Server) tail(w io.Writer, a Args) error {
	n := a.N
	if n <= 0 {
		n = -1 // the whole ring
	}
	watcher := s.Bridge.Watch(n)
	defer watcher.Stop()
	for _, e := range watcher.History() {
		if err := writeJSON(w, entryOf(e)); err != nil {
			return err
		}
	}
	return nil
}

// frames streams the frames that pass through the bridge, replaying the
// last tail remembered ones first. It stops when the bridge stops or the
// client disconnects.
func (s *Server) frames(ctx context.Context, w io.Writer, a Args) error {
	b := s.Bridge
	isLAN := func(name string) bool { return name == b.LANName() }
	watcher := b.Watch(max(a.Tail, 0))
	defer watcher.Stop()
	for _, e := range watcher.History() {
		if matchIface(a.Iface, e.Interface, isLAN) {
			if err := writeJSON(w, entryOf(e)); err != nil {
				return err
			}
		}
	}
	notice := func() {
		if d := watcher.Dropped(); d > 0 {
			writeJSON(w, map[string]any{"notice": "the watcher fell behind; frames were dropped", "count": d})
		}
	}
	for {
		select {
		case <-ctx.Done():
			notice()
			return context.Canceled
		case e, ok := <-watcher.Events:
			if !ok {
				notice()
				return nil
			}
			if !matchIface(a.Iface, e.Interface, isLAN) {
				continue
			}
			if err := writeJSON(w, entryOf(e)); err != nil {
				return err
			}
		}
	}
}

func entryOf(e bridge.FrameEvent) Entry {
	en := Entry{Seq: e.Seq, Time: e.Time, Interface: e.Interface, Action: e.Action, Frame: fmt.Sprintf("%x", e.Frame)}
	if e.Peer.IsValid() {
		en.Peer = e.Peer.String()
	}
	return en
}
