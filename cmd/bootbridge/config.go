package main

import (
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/rpajarola/gobootd/internal/link"
)

// fileConfig is the configuration file. Only the listeners it declares
// are opened.
type fileConfig struct {
	Interface      string     `hcl:"interface,optional"`
	Stats          string     `hcl:"stats,optional"`
	Verbose        bool       `hcl:"verbose,optional"`
	Print          bool       `hcl:"print,optional"`
	Dump           bool       `hcl:"dump,optional"`
	PrintInterface string     `hcl:"print_interface,optional"`
	Raw            *rawBlock  `hcl:"raw,block"`
	L2TP           *l2tpBlock `hcl:"l2tp,block"`

	StatsRange hcl.Range `hcl:"stats,attr_range"`
}

// rawBlock is the raw (HECnet bridge format) listener.
type rawBlock struct {
	Listen string   `hcl:"listen,optional"`
	Peers  []string `hcl:"peers,optional"`

	ListenRange hcl.Range `hcl:"listen,attr_range"`
	PeersRange  hcl.Range `hcl:"peers,attr_range"`
}

// l2tpBlock is the L2TPv3 listener.
type l2tpBlock struct {
	Listen  string   `hcl:"listen"`
	Peers   []string `hcl:"peers,optional"`
	Session *uint32  `hcl:"session,optional"`
	Cookie  string   `hcl:"cookie,optional"`
	Counter *bool    `hcl:"counter,optional"`

	ListenRange  hcl.Range `hcl:"listen,attr_range"`
	PeersRange   hcl.Range `hcl:"peers,attr_range"`
	SessionRange hcl.Range `hcl:"session,attr_range"`
	CookieRange  hcl.Range `hcl:"cookie,attr_range"`
}

// settings are the values of the configuration file and flags, before
// they are checked.
type settings struct {
	iface            string
	listen, l2tp     string
	peers, l2tpPeers []string
	session          uint64
	cookie           string
	counter          bool
	stats            time.Duration
	verbose          bool
	print, dump      bool
	printIface       string
}

// defaults are the settings without a configuration file.
func defaults() settings {
	return settings{listen: "127.0.0.1:4711", session: 1, counter: true, stats: 30 * time.Second, printIface: "all"}
}

// loadConfig reads a configuration file. The diagnostics need the parser's
// files to be printed with source context.
func loadConfig(path string) (settings, *hclparse.Parser, hcl.Diagnostics) {
	s := defaults()
	s.listen = ""
	p := hclparse.NewParser()
	f, diags := p.ParseHCLFile(path)
	if diags.HasErrors() {
		return s, p, diags
	}
	var c fileConfig
	if diags = append(diags, gohcl.DecodeBody(f.Body, nil, &c)...); diags.HasErrors() {
		return s, p, diags
	}
	errorf := func(r hcl.Range, summary, format string, args ...any) {
		diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: fmt.Sprintf(format, args...), Subject: r.Ptr()})
	}
	checkAddr := func(r hcl.Range, a string) {
		if _, err := netip.ParseAddrPort(a); err != nil {
			errorf(r, "Invalid address", "%q is not an IP address and port, like \"127.0.0.1:4711\".", a)
		}
	}

	s.iface, s.verbose, s.print, s.dump = c.Interface, c.Verbose, c.Print, c.Dump
	if c.PrintInterface != "" {
		s.printIface = c.PrintInterface
	}
	if c.Stats != "" {
		d, err := time.ParseDuration(c.Stats)
		if err != nil {
			errorf(c.StatsRange, "Invalid duration", "%q is not a duration, like \"30s\" (\"0\" to disable).", c.Stats)
		}
		s.stats = d
	}
	if r := c.Raw; r != nil {
		s.listen = "127.0.0.1:4711"
		if r.Listen != "" {
			s.listen = r.Listen
			checkAddr(r.ListenRange, r.Listen)
		}
		for _, p := range r.Peers {
			checkAddr(r.PeersRange, p)
		}
		s.peers = r.Peers
	}
	if l := c.L2TP; l != nil {
		s.l2tp = l.Listen
		checkAddr(l.ListenRange, l.Listen)
		for _, p := range l.Peers {
			checkAddr(l.PeersRange, p)
		}
		s.l2tpPeers = l.Peers
		if l.Session != nil {
			s.session = uint64(*l.Session)
			if s.session == 0 {
				errorf(l.SessionRange, "Invalid L2TP session", "Session 0 is reserved for control messages.")
			}
		}
		if l.Counter != nil {
			s.counter = *l.Counter
		}
		if s.cookie = l.Cookie; s.cookie != "" {
			if _, err := link.ParseCookie(s.cookie); err != nil {
				errorf(l.CookieRange, "Invalid L2TP cookie", "%v.", err)
			}
			if st, err := os.Stat(path); err == nil && st.Mode().Perm()&0o004 != 0 {
				diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagWarning, Summary: "Cookie readable by everyone",
					Detail: fmt.Sprintf("%s holds the L2TPv3 cookie but anyone can read it; chmod o-r %s.", path, path), Subject: l.CookieRange.Ptr()})
			}
		}
	}
	if c.Raw == nil && c.L2TP == nil {
		diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: "No listener",
			Detail: "The configuration needs a raw or an l2tp block.", Subject: f.Body.MissingItemRange().Ptr()})
	}
	return s, p, diags
}

// check turns settings into options. Errors are usage errors.
func (s settings) check() (options, error) {
	o := options{iface: s.iface, listen: s.listen, l2tp: s.l2tp, stats: s.stats, printPkts: s.print, dumpPkts: s.dump, printIface: s.printIface}
	if s.iface == "" {
		return o, fmt.Errorf("no interface: use -i or interface in the configuration file")
	}
	for _, p := range s.peers {
		a, err := netip.ParseAddrPort(p)
		if err != nil {
			return o, fmt.Errorf("peer %q: %w", p, err)
		}
		o.peers = append(o.peers, a)
	}
	for _, p := range s.l2tpPeers {
		a, err := netip.ParseAddrPort(p)
		if err != nil {
			return o, fmt.Errorf("l2tp peer %q: %w", p, err)
		}
		o.l2tpPeers = append(o.l2tpPeers, a)
	}
	if s.l2tp != "" {
		if s.session == 0 || s.session > 0xffffffff {
			return o, fmt.Errorf("-session must be 1 to 4294967295")
		}
		o.l2tpCfg = &link.L2TPv3{Session: uint32(s.session), Counter: s.counter}
		if s.cookie != "" {
			c, err := link.ParseCookie(s.cookie)
			if err != nil {
				return o, fmt.Errorf("-cookie: %w", err)
			}
			o.l2tpCfg.Cookie = c
		}
	} else if s.cookie != "" || len(s.l2tpPeers) > 0 {
		return o, fmt.Errorf("-cookie and -l2tp-peer need -l2tp")
	}
	if s.listen == "" && len(s.peers) > 0 {
		return o, fmt.Errorf("raw peers need a raw listener (-listen)")
	}
	if s.listen == "" && s.l2tp == "" {
		return o, fmt.Errorf("need -listen or -l2tp")
	}
	if o.dumpPkts {
		o.printPkts = true
	}
	if o.printIface != "" && o.printIface != "all" {
		o.printPkts = true
	}
	return o, nil
}
