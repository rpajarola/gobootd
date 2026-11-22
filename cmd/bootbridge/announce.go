package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/mdns"
	"github.com/rpajarola/gobootd/internal/version"
)

// ServiceType is what bootbridge announces itself as over DNS-SD.
const ServiceType = "_bootbridge._udp"

// parseAnnounce parses -announce: auto for every interface a listener
// is reachable on, off for none, or a comma-separated list of interface
// names. It returns whether to announce and on which interfaces (nil
// for all).
func parseAnnounce(s string) (bool, []string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto", "on", "true", "yes":
		return true, nil, nil
	case "off", "none", "false", "no", "-":
		return false, nil, nil
	}
	var names []string
	for _, n := range strings.Split(s, ",") {
		if n = strings.TrimSpace(n); n == "" {
			return false, nil, fmt.Errorf("-announce %q: empty interface name", s)
		}
		names = append(names, n)
	}
	return true, names, nil
}

// checkAnnounceInterfaces warns about the interfaces -announce names that
// do not exist (yet).
func checkAnnounceInterfaces(names []string) []string {
	var bad []string
	for _, n := range names {
		if _, err := net.InterfaceByName(n); err != nil {
			bad = append(bad, n)
		}
	}
	return bad
}

// services are the DNS-SD instances for the listeners that other
// machines can reach: not those on loopback, and over IPv4 only. The TXT
// record says how to connect, but not the cookie, only its length.
func services(host, lan string, members []*link.UDP, l2tp *link.L2TPv3) []mdns.Service {
	var out []mdns.Service
	for _, u := range members {
		a := u.Addr()
		addr := a.Addr().Unmap()
		if addr.IsLoopback() || (addr.Is6() && !addr.IsUnspecified()) {
			continue
		}
		if addr.Is6() {
			addr = netip.IPv4Unspecified() // [::] takes IPv4 too
		}
		kind, txt := "raw", []string{"encap=raw"}
		if u.Encapsulation() == "l2tpv3" {
			kind = "L2TPv3"
			txt = []string{"encap=l2tpv3", "session=" + strconv.FormatUint(uint64(l2tp.Session), 10),
				"cookie=" + strconv.Itoa(8*len(l2tp.Cookie)), "counter=" + boolBit(l2tp.Counter)}
		}
		txt = append(txt, "lan="+lan, "version="+version.String())
		out = append(out, mdns.Service{
			Instance: instanceName(host, lan, kind),
			Type:     ServiceType,
			Port:     a.Port(),
			Addr:     addr,
			TXT:      txt,
		})
	}
	return out
}

// instanceName is "bootbridge on HOST (LAN, KIND)", which fits in a DNS
// label: no dots, at most 63 bytes.
func instanceName(host, lan, kind string) string {
	lan = strings.ReplaceAll(lan, ".", "-")
	tail := fmt.Sprintf(" (%s, %s)", lan, kind)
	if max := 63 - len("bootbridge on ") - len(tail); len(host) > max {
		host = host[:max]
	}
	return "bootbridge on " + host + tail
}

func boolBit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// startAnnounce announces the listeners that other machines can reach,
// until the returned function is called, which says goodbye.
func startAnnounce(ctx context.Context, o options, members []*link.UDP, log *slog.Logger) func() {
	svcs := services(mdns.DefaultHost(), o.iface, members, o.l2tpCfg)
	if len(svcs) == 0 {
		if o.announceIfaces != nil {
			log.Warn("-announce: every listener is on loopback, nothing to announce")
		}
		return func() {}
	}
	if bad := checkAnnounceInterfaces(o.announceIfaces); len(bad) > 0 {
		log.Warn("-announce: no such interface (yet)", "interfaces", bad)
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	r := &mdns.Responder{Services: svcs, Interfaces: o.announceIfaces, Log: log}
	go func() {
		defer close(done)
		if err := r.Run(ctx); err != nil && ctx.Err() == nil {
			log.Warn("no DNS-SD announcement", "err", err)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}
