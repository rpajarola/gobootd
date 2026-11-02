// Command bootbridgectl inspects and steers a running bootbridge through
// its control socket: it lists the known peers of every interface, shows
// statistics, prints the frames that pass through the bridge, and changes
// the packet printing settings while it runs.
package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/control"
	"github.com/rpajarola/gobootd/internal/version"
)

func main() { os.Exit(mainCmd(os.Args[1:], os.Stdout, os.Stderr)) }

func mainCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage(stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	if args[0] == "-version" || args[0] == "--version" {
		fmt.Fprintf(stdout, "bootbridgectl %s\n", version.String())
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		fmt.Fprintln(stderr, "bootbridgectl: flags come after the command, like `bootbridgectl status -socket path`")
		usage(stderr)
		return 2
	}
	name := args[0]
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	socket := fs.String("socket", "", "control socket path (default: $BOOTBRIDGE_CTL_SOCKET or the socket of the running bootbridge)")
	asJSON := fs.Bool("json", false, "print the server's JSON lines unchanged")
	var o opts
	switch name {
	case "status":
	case "peers":
		fs.StringVar(&o.iface, "i", "", "only this interface (lan, udp, all, or a name)")
	case "log", "dump":
		fs.StringVar(&o.iface, "i", "", "only this interface (lan, udp, all, or a name)")
		fs.IntVar(&o.n, "n", 0, "stop after this many frames")
		fs.IntVar(&o.tail, "t", 0, "replay this many remembered frames first")
	case "tail":
		fs.StringVar(&o.iface, "i", "", "only this interface (lan, udp, all, or a name)")
		fs.IntVar(&o.n, "n", 20, "print this many remembered frames (0 for all)")
		fs.BoolVar(&o.follow, "f", false, "keep printing live frames")
		fs.IntVar(&o.tail, "t", 50, "with -f: replay this many remembered frames first")
	case "stats":
		fs.BoolVar(&o.watch, "w", false, "keep printing once per second")
	case "set":
		fs.StringVar(&o.print, "print", "", "on or off")
		fs.StringVar(&o.dump, "dump", "", "on or off")
		fs.StringVar(&o.iface, "iface", "", "lan, udp, all, or an interface name")
	default:
		fmt.Fprintf(stderr, "bootbridgectl: unknown command %q\n", name)
		usage(stderr)
		return 2
	}
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "bootbridgectl: %s takes no arguments\n", name)
		return 2
	}
	if name == "dump" {
		o.hexdump = true
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	c := &client{socket: *socket, json: *asJSON, w: stdout}
	if err := c.run(ctx, name, o); err != nil {
		if ctx.Err() != nil {
			return 0
		}
		fmt.Fprintf(stderr, "bootbridgectl: %v\n", err)
		return 1
	}
	return 0
}

type opts struct {
	iface         string
	n, tail       int
	follow, watch bool
	print, dump   string
	hexdump       bool
}

func usage(w io.Writer) {
	fmt.Fprint(w, `usage: bootbridgectl command [flags]

commands:
  status                 the running bridge and its settings
  peers [-i iface]       UDP peers and learned addresses per interface
  stats [-w]             packet and byte counters (-w once per second)
  tail [-n count]        the last frames the bridge forwarded
  tail -f [flags]        tail, then keep printing live frames
  log [flags]            print frames live, like bootbridge -print
  dump [flags]           print frames live with a hex dump, like bootbridge -X
    -i iface             only lan, only udp, or one named interface
    -t count             with tail -f: replay this many remembered frames first
    -n count             stop after this many frames
  set [-print on|off] [-dump on|off] [-iface name]
                         change the packet printing settings

Every command takes -socket path and -json to print the server's JSON
lines unchanged. The control socket is bootbridge's -ctl path: its
default is /run/bootbridge/bootbridge.sock when bootbridge runs as root
(/var/run where there is no /run), and a per-user socket in
$XDG_RUNTIME_DIR or /tmp otherwise. Several bridges on one machine need
explicit -ctl and -socket paths; bootbridge logs the path it listens on.
$BOOTBRIDGE_CTL_SOCKET overrides where bootbridgectl looks.
`)
}

type client struct {
	socket string
	json   bool
	w      io.Writer
}

func (c *client) dial() (net.Conn, error) {
	path := c.socket
	if path == "" {
		path = os.Getenv("BOOTBRIDGE_CTL_SOCKET")
	}
	if path == "" {
		path = control.DefaultPath(os.Getuid())
	}
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w (is bootbridge running with -ctl?)", path, err)
	}
	return conn, nil
}

// run sends one request and prints the responses; with streaming methods
// it stops at ctx cancellation, after n responses, or when the server
// closes.
func (c *client) run(ctx context.Context, method string, o opts) error {
	a := control.Args{Iface: o.iface, Watch: o.watch, Tail: o.tail}
	switch method {
	case "tail":
		a.N = o.n
		if o.follow {
			method = "log"
		} else {
			a.Tail = 0
		}
	case "log", "dump":
		method = "log"
	case "set":
		p, err := parseOnOff(o.print)
		if err != nil {
			return err
		}
		d, err := parseOnOff(o.dump)
		if err != nil {
			return err
		}
		a.Print, a.Dump = p, d
	}
	conn, err := c.dial()
	if err != nil {
		return err
	}
	defer conn.Close()
	req := control.Request{Method: method, Args: &a}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(b, '\n')); err != nil {
		return err
	}
	// The server learns of our cancellation when a write to a dead
	// stream fails; for tail and status there is no write to fail, so
	// closing on ctx.Done is enough.
	done := make(chan error)
	go func() {
		sc := bufio.NewScanner(conn)
		sc.Buffer(make([]byte, 1<<20), 1<<21)
		var n int
		for sc.Scan() {
			v, err := decodeLine(sc.Bytes())
			if err != nil {
				done <- err
				return
			}
			if v == nil { // notice line
				continue
			}
			if err := c.print(v, o); err != nil {
				done <- err
				return
			}
			n++
			if o.n > 0 && n >= o.n {
				done <- nil
				return
			}
		}
		done <- sc.Err()
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		conn.Close()
		<-done
		return ctx.Err()
	}
}

func decodeLine(b []byte) (map[string]json.RawMessage, error) {
	var v map[string]json.RawMessage
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	if e, ok := v["error"]; ok {
		var s string
		json.Unmarshal(e, &s)
		return nil, fmt.Errorf("%s", s)
	}
	if _, ok := v["notice"]; ok {
		var s string
		var cnt int
		json.Unmarshal(v["notice"], &s)
		json.Unmarshal(v["count"], &cnt)
		fmt.Fprintf(os.Stderr, "bootbridgectl: %s (%d frames)\n", s, cnt)
		return nil, nil
	}
	return v, nil
}

func (c *client) print(v map[string]json.RawMessage, o opts) error {
	if c.json {
		b, _ := json.Marshal(v)
		_, err := fmt.Fprintln(c.w, string(b))
		return err
	}
	full, _ := json.Marshal(v)
	switch {
	case v["seq"] != nil:
		var e control.Entry
		if err := json.Unmarshal(full, &e); err != nil {
			return err
		}
		frame, err := hex.DecodeString(e.Frame)
		if err != nil {
			return fmt.Errorf("bad frame: %w", err)
		}
		fmt.Fprintln(c.w, bridge.FormatPacket(e.Time, e.Action, frame))
		if o.hexdump {
			fmt.Fprint(c.w, hex.Dump(frame))
		}
	case v["uptime"] != nil:
		return printStatus(c.w, full)
	case v["transports"] != nil:
		return printPeers(c.w, full)
	case v["lan"] != nil:
		return printStats(c.w, full)
	}
	fmt.Fprintln(c.w, string(full))
	return nil
}

func printStatus(w io.Writer, b []byte) error {
	var s struct {
		Version    string `json:"version"`
		PID        int    `json:"pid"`
		Socket     string `json:"socket"`
		Config     string `json:"config"`
		Interface  string `json:"interface"`
		MAC        string `json:"mac"`
		Uptime     string `json:"uptime"`
		Print      bool   `json:"print"`
		Dump       bool   `json:"dump"`
		PrintIface string `json:"print_interface"`
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "version\t%s\n", s.Version)
	fmt.Fprintf(tw, "pid\t%d\n", s.PID)
	fmt.Fprintf(tw, "uptime\t%s\n", s.Uptime)
	fmt.Fprintf(tw, "interface\t%s (%s)\n", s.Interface, s.MAC)
	fmt.Fprintf(tw, "config\t%s\n", s.Config)
	fmt.Fprintf(tw, "socket\t%s\n", s.Socket)
	fmt.Fprintf(tw, "printing\t%s\n", printState(s.Print, s.Dump, s.PrintIface))
	return tw.Flush()
}

func printState(print, dump bool, iface string) string {
	if !print {
		return "off"
	}
	if dump {
		return "on, hex dump, " + iface
	}
	return "on, summary, " + iface
}

type peersView struct {
	Transports []struct {
		Name          string `json:"name"`
		Encapsulation string `json:"encapsulation"`
		Peers         []struct {
			Addr     string `json:"addr"`
			Static   bool   `json:"static"`
			LastSeen string `json:"last_seen"`
		} `json:"peers"`
		MACs []struct {
			MAC      string `json:"mac"`
			Addr     string `json:"addr"`
			LastSeen string `json:"last_seen"`
		} `json:"macs"`
	} `json:"transports"`
	LANHosts []host `json:"lan_hosts"`
	UDPHosts []host `json:"udp_hosts"`
}

type host struct {
	MAC string `json:"mac"`
	IP  string `json:"ip"`
}

func printPeers(w io.Writer, b []byte) error {
	var p peersView
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if len(p.Transports) == 0 && len(p.LANHosts) == 0 && len(p.UDPHosts) == 0 {
		fmt.Fprintln(w, "no peers or hosts known")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, t := range p.Transports {
		fmt.Fprintf(tw, "\ntransport %s (%s)\t\t\t\n", t.Name, t.Encapsulation)
		fmt.Fprintf(tw, "PEER\tTYPE\tLAST SEEN\t\t\n")
		for _, e := range t.Peers {
			typ := "learned"
			if e.Static {
				typ = "configured"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t\t\n", e.Addr, typ, ago(e.LastSeen))
		}
		if len(t.MACs) > 0 {
			fmt.Fprintf(tw, "\nMAC\tAT PEER\tLAST SEEN\t\t\n")
			for _, m := range t.MACs {
				fmt.Fprintf(tw, "%s\t%s\t%s\t\t\n", m.MAC, m.Addr, ago(m.LastSeen))
			}
		}
	}
	if len(p.LANHosts) > 0 {
		fmt.Fprintf(tw, "\nhosts on the LAN\t\t\t\n")
		writeHosts(tw, p.LANHosts)
	}
	if len(p.UDPHosts) > 0 {
		fmt.Fprintf(tw, "\nhosts on the UDP side\t\t\t\n")
		writeHosts(tw, p.UDPHosts)
	}
	return tw.Flush()
}

func writeHosts(tw io.Writer, hs []host) {
	fmt.Fprintf(tw, "MAC\tIP\t\t\n")
	for _, h := range hs {
		ip := h.IP
		if ip == "" {
			ip = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t\t\n", h.MAC, ip)
	}
}

// ago renders an RFC3339 timestamp as an age, for last-seen columns.
func ago(s string) string {
	if s == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	d := time.Since(t).Round(time.Second)
	if h := int(d.Hours()); h >= 24 {
		return fmt.Sprintf("%dd%dh", h/24, h%24)
	}
	if d >= time.Minute {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return d.String()
}

func printStats(w io.Writer, b []byte) error {
	var st struct {
		Time string   `json:"time"`
		LAN  statsRow `json:"lan"`
		UDP  statsRow `json:"udp"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return err
	}
	t := st.Time
	if len(t) > 19 {
		t = t[11:19]
	}
	fmt.Fprintf(w, "== %s\n", t)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "INTERFACE\tHOSTS\tRX PKTS\tRX BYTES\tTX PKTS\tTX BYTES\tERRORS\n")
	for _, s := range []statsRow{st.LAN, st.UDP} {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\t%d\n", s.Name, s.Hosts, s.RxPackets, s.RxBytes, s.TxPackets, s.TxBytes, s.Errors)
	}
	return tw.Flush()
}

type statsRow struct {
	Name      string `json:"name"`
	Hosts     int    `json:"hosts"`
	RxPackets uint64 `json:"rx_packets"`
	TxPackets uint64 `json:"tx_packets"`
	RxBytes   uint64 `json:"rx_bytes"`
	TxBytes   uint64 `json:"tx_bytes"`
	Errors    uint64 `json:"errors"`
}

func parseOnOff(s string) (*bool, error) {
	switch strings.ToLower(s) {
	case "":
		return nil, nil
	case "on", "true", "1":
		t := true
		return &t, nil
	case "off", "false", "0":
		f := false
		return &f, nil
	}
	return nil, fmt.Errorf("%q is not on or off", s)
}
