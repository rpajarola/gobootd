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

	"github.com/rpajarola/gobootd/internal/bridge"
	"github.com/rpajarola/gobootd/internal/link"
)

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
	fs := flag.NewFlagSet("bootbridge", flag.ContinueOnError)
	fs.SetOutput(stderr)
	iface := fs.String("i", "", "network interface to bridge (required)")
	listen := fs.String("listen", "127.0.0.1:4711", "UDP address to exchange frames on")
	stats := fs.Duration("stats", 30*time.Second, "interval to log interface statistics (0 to disable)")
	verbose := fs.Bool("v", false, "log every forwarding error")
	var peers peerList
	fs.Var(&peers, "peer", "UDP peer that always receives frames (repeatable)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: bootbridge -i interface [-listen addr:port] [-peer addr:port]... [-stats duration] [-v]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *iface == "" || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: lvl}))
	if err := run(*iface, *listen, peers, *stats, log); err != nil {
		fmt.Fprintf(stderr, "bootbridge: %v\n", err)
		return 1
	}
	return 0
}

func run(iface, listen string, peers []netip.AddrPort, statsInterval time.Duration, log *slog.Logger) error {
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
	return (&bridge.Bridge{LAN: lan, UDP: udp, Log: log, StatsInterval: statsInterval}).Run(ctx)
}
