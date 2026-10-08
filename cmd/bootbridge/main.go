// Command bootbridge connects a network interface to bootd, simh or QEMU
// over UDP, one Ethernet frame per datagram (the HECnet bridge format).
//
// It is the only part that needs capture privileges; bootd itself runs
// unprivileged. Peers that send to bootbridge are learned; peers given with
// -peer always receive frames.
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
	iface := fs.String("i", "", "network interface to bridge (required)")
	listen := fs.String("listen", "127.0.0.1:4711", "UDP address to exchange frames on")
	stats := fs.Duration("stats", 30*time.Second, "interval to log interface statistics (0 to disable)")
	verbose := fs.Bool("v", false, "log every forwarding error")
	printPkts := fs.Bool("print", false, "print packets as they pass through the bridge")
	fs.BoolVar(printPkts, "p", false, "alias for -print")
	dumpPkts := fs.Bool("X", false, "dump very verbose packet info (hex/ASCII, like tcpdump -X)")
	fs.BoolVar(dumpPkts, "dump", false, "alias for -X")
	var peers peerList
	fs.Var(&peers, "peer", "UDP peer that always receives frames (repeatable)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: bootbridge -i interface [-listen addr:port] [-peer addr:port]... [-stats duration] [-v] [-print] [-X]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *iface == "" || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	if *dumpPkts {
		*printPkts = true
	}
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	if err := run(*iface, *listen, peers, *stats, *printPkts, *dumpPkts, stdin, stdout, log); err != nil {
		fmt.Fprintf(stderr, "bootbridge: %v\n", err)
		return 1
	}
	return 0
}

func run(iface, listen string, peers []netip.AddrPort, statsInterval time.Duration, printPkts, dumpPkts bool, stdin io.Reader, stdout io.Writer, log *slog.Logger) error {
	addr, err := netip.ParseAddrPort(listen)
	if err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	lan, err := link.OpenPcap(iface, nil)
	if err != nil {
		return fmt.Errorf("%s: %w", iface, err)
	}
	udp, err := link.ListenUDP(addr, peers)
	if err != nil {
		lan.Close()
		return err
	}
	defer lan.Close()
	defer udp.Close()
	if !addr.Addr().IsLoopback() {
		log.Warn("listening on a non-loopback address: anyone who can send UDP to it can put frames on the LAN", "listen", addr.String())
	}
	log.Info("bridging", "interface", iface, "mac", lan.Interface().MAC.String(), "listen", udp.Addr().String(), "peers", peers)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if statsInterval <= 0 {
		statsInterval = -1
	}
	b := &bridge.Bridge{
		LAN:           lan,
		UDP:           udp,
		Log:           log,
		StatsInterval: statsInterval,
		PrintPackets:  printPkts,
		DumpPackets:   dumpPkts,
		PacketWriter:  stdout,
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
		fmt.Fprint(out, "[bootbridge] keyboard commands: p = toggle printing, x = toggle hex dump, s = show stats, q = quit, h = help\r\n")
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
		case 's', 'S':
			b.LogStats()
		case 'h', 'H', '?':
			fmt.Fprint(out, "[bootbridge] keyboard commands: p = toggle printing, x = toggle hex dump, s = show stats, q = quit, h = help\r\n")
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
