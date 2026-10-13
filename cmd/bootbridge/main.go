// Command bootbridge connects a network interface to bootd, simh or QEMU
// over UDP, one Ethernet frame per datagram: raw (the HECnet bridge
// format), or with static L2TPv3, whose cookie keeps out peers that do not
// know it.
//
// It is the only part that needs capture privileges; bootd itself runs
// unprivileged. Peers that send to bootbridge are learned; peers given with
// -peer or -l2tp-peer always receive frames.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/link"
)

type crlfWriter struct {
	w io.Writer
}

func (c *crlfWriter) Write(p []byte) (n int, err error) {
	s := strings.ReplaceAll(string(p), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	_, err = c.w.Write([]byte(s))
	return len(p), err
}

type peerList []netip.AddrPort

func (p *peerList) String() string {
	var s []string
	for _, a := range *p {
		s = append(s, a.String())
	}
	return strings.Join(s, ",")
}

func (p *peerList) Set(v string) error {
	a, err := netip.ParseAddrPort(v)
	if err != nil {
		return err
	}
	*p = append(*p, a)
	return nil
}

func main() {
	os.Exit(mainCmd(os.Args[1:], os.Stderr))
}

func mainCmd(args []string, stderr io.Writer) int {
	return mainCmdWithIO(args, os.Stdin, os.Stdout, stderr)
}

func mainCmdWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if stderr == nil {
		stderr = os.Stderr
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if f, ok := stdin.(*os.File); ok && term.IsTerminal(int(f.Fd())) && !isBackground(f) {
		oldState, err := term.MakeRaw(int(f.Fd()))
		if err == nil {
			defer func() { _ = term.Restore(int(f.Fd()), oldState) }()
			stdout = &crlfWriter{w: stdout}
			stderr = &crlfWriter{w: stderr}
		}
	}
	fs := flag.NewFlagSet("bootbridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o options
	fs.StringVar(&o.iface, "i", "", "network interface to bridge (required)")
	fs.StringVar(&o.listen, "listen", "127.0.0.1:4711", "UDP address to exchange raw frames on (\"\" for none)")
	fs.Var(&o.peers, "peer", "raw UDP peer that always receives frames (repeatable)")
	fs.StringVar(&o.l2tp, "l2tp", "", "UDP address to exchange L2TPv3 frames on")
	fs.Var(&o.l2tpPeers, "l2tp-peer", "L2TPv3 peer that always receives frames (repeatable)")
	session := fs.Uint("session", 1, "L2TPv3 session ID")
	cookie := fs.String("cookie", "", "L2TPv3 cookie, 8 or 16 hex digits")
	counter := fs.Bool("counter", true, "L2TPv3 L2-specific sublayer with a sequence number")
	stats := fs.Duration("stats", 30*time.Second, "interval to log interface statistics (0 to disable)")
	verbose := fs.Bool("v", false, "log every forwarding error")
	fs.BoolVar(&o.printPkts, "print", false, "print packets as they pass through the bridge")
	fs.BoolVar(&o.printPkts, "p", false, "alias for -print")
	fs.BoolVar(&o.dumpPkts, "X", false, "dump very verbose packet info (hex/ASCII, like tcpdump -X)")
	fs.BoolVar(&o.dumpPkts, "dump", false, "alias for -X")
	fs.StringVar(&o.printIface, "print-iface", "all", "interface to print packets for (udp, lan, all, or interface name)")
	fs.StringVar(&o.printIface, "print-interface", "all", "alias for -print-iface")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: bootbridge -i interface [-listen addr:port] [-peer addr:port]... [-l2tp addr:port [-l2tp-peer addr:port]... [-session id] [-cookie hex] [-counter=false]] [-stats duration] [-v] [-print] [-X] [-print-iface name]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if o.iface == "" || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if o.l2tp != "" {
		if *session == 0 || *session > 0xffffffff {
			fmt.Fprintf(stderr, "bootbridge: -session must be 1 to 4294967295\n")
			return 2
		}
		o.l2tpCfg = &link.L2TPv3{Session: uint32(*session), Counter: *counter}
		if *cookie != "" {
			c, err := link.ParseCookie(*cookie)
			if err != nil {
				fmt.Fprintf(stderr, "bootbridge: -cookie: %v\n", err)
				return 2
			}
			o.l2tpCfg.Cookie = c
		}
	} else if *cookie != "" || len(o.l2tpPeers) > 0 {
		fmt.Fprintf(stderr, "bootbridge: -cookie and -l2tp-peer need -l2tp\n")
		return 2
	}
	if o.listen == "" && o.l2tp == "" {
		fmt.Fprintf(stderr, "bootbridge: need -listen or -l2tp\n")
		return 2
	}
	if o.dumpPkts {
		o.printPkts = true
	}
	if o.printIface != "" && o.printIface != "all" {
		o.printPkts = true
	}
	o.stats = *stats
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	if err := run(o, stdin, stdout, log); err != nil {
		fmt.Fprintf(stderr, "bootbridge: %v\n", err)
		return 1
	}
	return 0
}

type options struct {
	iface            string
	listen, l2tp     string
	peers, l2tpPeers peerList
	l2tpCfg          *link.L2TPv3
	stats            time.Duration
	printPkts        bool
	dumpPkts         bool
	printIface       string
}

func run(o options, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	var raw, l2tp netip.AddrPort
	var err error
	if o.listen != "" {
		if raw, err = netip.ParseAddrPort(o.listen); err != nil {
			return fmt.Errorf("-listen: %w", err)
		}
	}
	if o.l2tp != "" {
		if l2tp, err = netip.ParseAddrPort(o.l2tp); err != nil {
			return fmt.Errorf("-l2tp: %w", err)
		}
	}
	lan, err := link.OpenPcap(o.iface, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", o.iface, err)
	}
	defer lan.Close()
	mac := lan.Interface().MAC
	var members []*link.UDP
	defer func() {
		for _, u := range members {
			u.Close()
		}
	}()
	if raw.IsValid() {
		u, err := link.ListenUDPConfig(raw, link.UDPConfig{Peers: o.peers, KeepaliveMAC: mac, Log: log})
		if err != nil {
			return err
		}
		members = append(members, u)
		if !raw.Addr().IsLoopback() {
			log.Warn("raw UDP on a non-loopback address: anyone who can send UDP to it can put frames on the LAN; consider -l2tp with -cookie", "listen", raw.String())
		}
		log.Info("raw UDP", "listen", u.Addr().String(), "peers", o.peers)
	}
	if l2tp.IsValid() {
		u, err := link.ListenUDPConfig(l2tp, link.UDPConfig{Peers: o.l2tpPeers, L2TP: o.l2tpCfg, KeepaliveMAC: mac, Log: log})
		if err != nil {
			return err
		}
		members = append(members, u)
		if len(o.l2tpCfg.Cookie) == 0 && !l2tp.Addr().IsLoopback() {
			log.Warn("L2TPv3 without a cookie on a non-loopback address: anyone who can send UDP to it can put frames on the LAN", "l2tp", l2tp.String())
		}
		log.Info("L2TPv3", "listen", u.Addr().String(), "peers", o.l2tpPeers, "session", o.l2tpCfg.Session, "cookie", len(o.l2tpCfg.Cookie) > 0, "counter", o.l2tpCfg.Counter)
	}
	var udp bridge.Peers = members[0]
	if len(members) > 1 {
		udp = link.NewGroup(members...)
	}
	log.Info("bridging", "interface", o.iface, "mac", mac.String())
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	statsInterval := o.stats
	if statsInterval <= 0 {
		statsInterval = -1
	}
	b := &bridge.Bridge{
		LAN:            lan,
		UDP:            udp,
		Log:            log,
		StatsInterval:  statsInterval,
		PrintPackets:   o.printPkts,
		DumpPackets:    o.dumpPkts,
		PrintInterface: o.printIface,
		PacketWriter:   stdout,
	}
	if stdin != nil {
		go handleKeyboard(ctx, stop, stdin, stdout, b, log)
	}
	return b.Run(ctx)
}

func handleKeyboard(ctx context.Context, cancel context.CancelFunc, stdin io.Reader, out io.Writer, b *bridge.Bridge, log *slog.Logger) {
	if f, ok := stdin.(*os.File); ok {
		if !term.IsTerminal(int(f.Fd())) || isBackground(f) {
			return
		}
		fmt.Fprint(out, "[bootbridge] keyboard commands: p = toggle printing, x = toggle hex dump, i = cycle interface (all/udp/lan), u = udp only, l = lan only, a = all, s = show stats, q = quit, h = help\r\n")
	}

	buf := make([]byte, 1)
	for {
		n, err := stdin.Read(buf)
		if err != nil || n == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		c := buf[0]
		switch c {
		case 'p', 'P':
			if b.TogglePrintPackets() {
				if b.IsDumpPackets() {
					fmt.Fprint(out, "[bootbridge] packet printing enabled (extra verbose dump mode)\r\n")
				} else {
					fmt.Fprint(out, "[bootbridge] packet printing enabled (summary mode)\r\n")
				}
			} else {
				fmt.Fprint(out, "[bootbridge] packet printing disabled\r\n")
			}
		case 'x', 'X', 'v', 'V', 'd', 'D':
			if b.ToggleDumpPackets() {
				fmt.Fprint(out, "[bootbridge] extra verbose dump mode enabled (tcpdump -X mode)\r\n")
			} else {
				if b.IsPrintPackets() {
					fmt.Fprint(out, "[bootbridge] extra verbose dump mode disabled (summary mode)\r\n")
				} else {
					fmt.Fprint(out, "[bootbridge] extra verbose dump mode disabled\r\n")
				}
			}
		case 'i', 'I':
			next := b.CyclePrintInterface()
			b.SetPrintPackets(true)
			switch next {
			case "udp":
				fmt.Fprint(out, "[bootbridge] packet printing limited to udp\r\n")
			case "lan":
				fmt.Fprintf(out, "[bootbridge] packet printing limited to lan (%s)\r\n", b.LANName())
			default:
				fmt.Fprint(out, "[bootbridge] packet printing for all interfaces\r\n")
			}
		case 'u', 'U':
			b.SetPrintInterface("udp")
			b.SetPrintPackets(true)
			fmt.Fprint(out, "[bootbridge] packet printing limited to udp\r\n")
		case 'l', 'L':
			b.SetPrintInterface("lan")
			b.SetPrintPackets(true)
			fmt.Fprintf(out, "[bootbridge] packet printing limited to lan (%s)\r\n", b.LANName())
		case 'a', 'A':
			b.SetPrintInterface("all")
			fmt.Fprint(out, "[bootbridge] packet printing for all interfaces\r\n")
		case 's', 'S':
			b.LogStats()
		case 'h', 'H', '?':
			fmt.Fprint(out, "[bootbridge] keyboard commands: p = toggle printing, x = toggle hex dump, i = cycle interface (all/udp/lan), u = udp only, l = lan only, a = all, s = show stats, q = quit, h = help\r\n")
		case 'q', 'Q', 0x03, 0x04: // 'q', 'Q', Ctrl-C, Ctrl-D
			fmt.Fprint(out, "[bootbridge] quitting...\r\n")
			if cancel != nil {
				cancel()
			}
			return
		case '\r', '\n', ' ':
			if b.TogglePrintPackets() {
				if b.IsDumpPackets() {
					fmt.Fprint(out, "[bootbridge] packet printing enabled (extra verbose dump mode)\r\n")
				} else {
					fmt.Fprint(out, "[bootbridge] packet printing enabled (summary mode)\r\n")
				}
			} else {
				fmt.Fprint(out, "[bootbridge] packet printing disabled\r\n")
			}
		default:
			// Ignore other characters
		}
	}
}

func isBackground(f *os.File) bool {
	pgrp, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
	if err != nil {
		return false
	}
	return pgrp != syscall.Getpgrp()
}
