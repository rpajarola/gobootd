// Package mdns announces services with DNS-SD over multicast DNS (RFC
// 6762, RFC 6763), and finds them.
//
// The Responder answers for its own services only, next to whatever
// system responder (Avahi, mDNSResponder) shares port 5353 with it. It
// speaks IPv4 only, and does not probe for name conflicts: instance names
// carry the host name, which the system responder already defends.
package mdns

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Port is the mDNS port.
const Port = 5353

var group = netip.AddrPortFrom(netip.MustParseAddr("224.0.0.251"), Port)

// Record lifetimes, as RFC 6762 10 recommends: short for records that
// name a host, long for the others.
const (
	hostTTL  = 120
	otherTTL = 4500
	// cacheFlush marks a record as the whole set of its name and type.
	cacheFlush = 1 << 15
	// unicastResponse is the QU bit of a question's class.
	unicastResponse = 1 << 15
)

// Service is one service instance to announce.
type Service struct {
	// Instance is the user-visible name, such as "bootbridge on host
	// (en0, L2TPv3)". Dots are not allowed.
	Instance string
	// Type is the service type, such as "_bootbridge._udp".
	Type string
	// Port is the port the service listens on.
	Port uint16
	// Addr is the address it listens on: unspecified for every
	// interface, or the one address it is reachable at.
	Addr netip.Addr
	// TXT holds key=value pairs.
	TXT []string
}

// Interface is a network interface the responder can announce on.
type Interface struct {
	Index int
	Name  string
	Addrs []netip.Prefix // IPv4 only
}

// Interfaces returns the interfaces that are up, can multicast, are not
// loopback and have an IPv4 address.
func Interfaces() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Interface
	for _, ifi := range ifs {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagMulticast == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		var ps []netip.Prefix
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if p, ok := netip.AddrFromSlice(n.IP); ok && p.Unmap().Is4() {
					ones, _ := n.Mask.Size()
					ps = append(ps, netip.PrefixFrom(p.Unmap(), ones))
				}
			}
		}
		if len(ps) > 0 {
			out = append(out, Interface{Index: ifi.Index, Name: ifi.Name, Addrs: ps})
		}
	}
	return out, nil
}

// Responder announces Services and answers queries for them.
type Responder struct {
	Services []Service
	// Interfaces limits the responder to these interface names; nil
	// means all of them.
	Interfaces []string
	// Host is the host name without .local; the default is the system's
	// up to the first dot.
	Host string
	Log  *slog.Logger

	// listInterfaces is Interfaces, replaced by tests.
	listInterfaces func() ([]Interface, error)

	mu      sync.Mutex
	current map[int]ifaceRecords // by interface index
}

type ifaceRecords struct {
	ifi     Interface
	records []dnsmessage.Resource
}

// DefaultHost is the system's host name up to the first dot, which is
// also the name its own mDNS responder uses.
func DefaultHost() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	if h == "" {
		h = "localhost"
	}
	return h
}

func (r *Responder) host() string {
	if r.Host != "" {
		return r.Host
	}
	return DefaultHost()
}

// Run announces the services, answers queries until ctx is done, and
// then says goodbye. It checks every 30 seconds for interfaces and
// addresses that come and go.
func (r *Responder) Run(ctx context.Context) error {
	if r.Log == nil {
		r.Log = slog.New(slog.DiscardHandler)
	}
	if r.listInterfaces == nil {
		r.listInterfaces = Interfaces
	}
	lc := net.ListenConfig{Control: reuse}
	c, err := lc.ListenPacket(ctx, "udp4", fmt.Sprintf("0.0.0.0:%d", Port))
	if err != nil {
		return err
	}
	defer c.Close()
	pc := ipv4.NewPacketConn(c)
	pc.SetMulticastTTL(255)
	pc.SetMulticastLoopback(true)
	s := &sender{pc: pc, conn: c}

	joined := map[int]bool{}
	refresh := func() {
		ifs, err := r.listInterfaces()
		if err != nil {
			r.Log.Warn("mDNS: interfaces", "err", err)
			return
		}
		next := map[int]ifaceRecords{}
		for _, ifi := range ifs {
			if r.Interfaces != nil && !slices.Contains(r.Interfaces, ifi.Name) {
				continue
			}
			recs := r.records(ifi)
			if len(recs) == 0 {
				continue
			}
			if !joined[ifi.Index] {
				if err := pc.JoinGroup(&net.Interface{Index: ifi.Index, Name: ifi.Name}, &net.UDPAddr{IP: group.Addr().AsSlice()}); err != nil {
					r.Log.Warn("mDNS: cannot join the group", "interface", ifi.Name, "err", err)
					continue
				}
				joined[ifi.Index] = true
			}
			next[ifi.Index] = ifaceRecords{ifi, recs}
		}
		r.mu.Lock()
		prev := r.current
		r.current = next
		r.mu.Unlock()
		for idx, n := range next {
			p, ok := prev[idx]
			if ok && sameRecords(p.records, n.records) {
				continue
			}
			if ok {
				if gone := missing(p.records, n.records); len(gone) > 0 {
					s.multicast(n.ifi, response(0, nil, goodbye(gone), nil))
				}
			}
			var names []string
			for _, sv := range r.servicesOn(n.ifi) {
				names = append(names, sv.Instance)
			}
			r.Log.Info("mDNS: announcing", "interface", n.ifi.Name, "services", names)
			go announce(ctx, s, n.ifi, n.records)
		}
		for idx, p := range prev {
			if _, ok := next[idx]; !ok {
				r.Log.Info("mDNS: no longer announcing", "interface", p.ifi.Name)
				s.multicast(p.ifi, response(0, nil, goodbye(p.records), nil))
			}
		}
	}
	refresh()

	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 9000)
		for {
			n, _, src, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				continue
			}
			from := ua.AddrPort()
			from = netip.AddrPortFrom(from.Addr().Unmap(), from.Port())
			ifr, ok := r.ifaceFor(from.Addr())
			if !ok {
				continue
			}
			if out, unicast := answer(buf[:n], from, ifr.records); out != nil {
				if unicast {
					s.unicast(from, out)
				} else {
					s.multicast(ifr.ifi, out)
				}
			}
		}
	}()

	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			r.mu.Lock()
			cur := r.current
			r.mu.Unlock()
			for _, ir := range cur {
				s.multicast(ir.ifi, response(0, nil, goodbye(ir.records), nil))
			}
			c.Close()
			<-done
			return nil
		case <-t.C:
			refresh()
		case <-done:
			return errors.New("mDNS socket closed")
		}
	}
}

// reuse lets the socket share port 5353 with the system's responder.
func reuse(network, address string, c syscall.RawConn) error {
	var err error
	c.Control(func(fd uintptr) {
		if err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
			return
		}
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	return err
}

// ifaceFor finds the interface a query came in on by the network its
// source address is on.
func (r *Responder) ifaceFor(a netip.Addr) (ifaceRecords, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ir := range r.current {
		for _, p := range ir.ifi.Addrs {
			if p.Contains(a) {
				return ir, true
			}
		}
	}
	return ifaceRecords{}, false
}

// servicesOn are the services reachable on ifi.
func (r *Responder) servicesOn(ifi Interface) []Service {
	var out []Service
	for _, s := range r.Services {
		if s.Addr.IsUnspecified() || !s.Addr.IsValid() || slices.ContainsFunc(ifi.Addrs, func(p netip.Prefix) bool { return p.Addr() == s.Addr }) {
			out = append(out, s)
		}
	}
	return out
}

// records are what the responder answers for on ifi: the service
// enumeration, each service's PTR, SRV and TXT, and the host's addresses
// on ifi. The addresses are not marked cache-flush: the system responder
// owns them, and may know more.
func (r *Responder) records(ifi Interface) []dnsmessage.Resource {
	svcs := r.servicesOn(ifi)
	if len(svcs) == 0 {
		return nil
	}
	host := mustName(r.host() + ".local.")
	var recs []dnsmessage.Resource
	types := map[string]bool{}
	for _, s := range svcs {
		typ := mustName(s.Type + ".local.")
		if !types[s.Type] {
			types[s.Type] = true
			recs = append(recs, dnsmessage.Resource{
				Header: hdr(mustName("_services._dns-sd._udp.local."), otherTTL, false),
				Body:   &dnsmessage.PTRResource{PTR: typ},
			})
		}
		inst := mustName(s.Instance + "." + s.Type + ".local.")
		txt := s.TXT
		if len(txt) == 0 {
			txt = []string{""}
		}
		recs = append(recs,
			dnsmessage.Resource{Header: hdr(typ, otherTTL, false), Body: &dnsmessage.PTRResource{PTR: inst}},
			dnsmessage.Resource{Header: hdr(inst, hostTTL, true), Body: &dnsmessage.SRVResource{Target: host, Port: s.Port}},
			dnsmessage.Resource{Header: hdr(inst, otherTTL, true), Body: &dnsmessage.TXTResource{TXT: txt}},
		)
	}
	for _, p := range ifi.Addrs {
		recs = append(recs, dnsmessage.Resource{Header: hdr(host, hostTTL, false), Body: &dnsmessage.AResource{A: p.Addr().As4()}})
	}
	return recs
}

func hdr(name dnsmessage.Name, ttl uint32, unique bool) dnsmessage.ResourceHeader {
	class := dnsmessage.ClassINET
	if unique {
		class |= cacheFlush
	}
	return dnsmessage.ResourceHeader{Name: name, Class: class, TTL: ttl}
}

func mustName(s string) dnsmessage.Name {
	n, err := dnsmessage.NewName(s)
	if err != nil {
		panic(fmt.Sprintf("mdns: name %q: %v", s, err))
	}
	return n
}

// ValidName reports whether s can be an instance or host label.
func ValidName(s string) error {
	switch {
	case s == "":
		return errors.New("empty")
	case strings.Contains(s, "."):
		return errors.New("contains a dot")
	case len(s) > 63:
		return errors.New("longer than 63 bytes")
	}
	return nil
}

// announce sends the records unsolicited, three times a second or two
// apart, as RFC 6762 8.3 asks.
func announce(ctx context.Context, s *sender, ifi Interface, recs []dnsmessage.Resource) {
	msg := response(0, nil, recs, nil)
	for i := range 3 {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(i) * time.Second):
			}
		}
		s.multicast(ifi, msg)
	}
}

func goodbye(recs []dnsmessage.Resource) []dnsmessage.Resource {
	out := slices.Clone(recs)
	for i := range out {
		out[i].Header.TTL = 0
	}
	return out
}

func key(r dnsmessage.Resource) string {
	return strings.ToLower(r.Header.Name.String()) + " " + r.Body.GoString()
}

func sameRecords(a, b []dnsmessage.Resource) bool {
	return len(missing(a, b)) == 0 && len(missing(b, a)) == 0
}

// missing returns the records of a that b does not have.
func missing(a, b []dnsmessage.Resource) []dnsmessage.Resource {
	have := map[string]bool{}
	for _, r := range b {
		have[key(r)] = true
	}
	var out []dnsmessage.Resource
	for _, r := range a {
		if !have[key(r)] {
			out = append(out, r)
		}
	}
	return out
}

// answer builds the response to a query from ifi's records, or nil. It
// is to go back to the sender alone (unicast) when the sender is not a
// full mDNS responder (a "legacy" query from a port other than 5353,
// RFC 6762 6.7) or asked for a unicast reply.
func answer(query []byte, from netip.AddrPort, recs []dnsmessage.Resource) ([]byte, bool) {
	var m dnsmessage.Message
	if err := m.Unpack(query); err != nil || m.Header.Response || m.Header.OpCode != 0 {
		return nil, false
	}
	legacy := from.Port() != Port
	unicast := legacy
	var ans []dnsmessage.Resource
	seen := map[string]bool{}
	add := func(list *[]dnsmessage.Resource, r dnsmessage.Resource) {
		if k := key(r); !seen[k] {
			seen[k] = true
			*list = append(*list, r)
		}
	}
	for _, q := range m.Questions {
		if q.Class&unicastResponse != 0 {
			unicast = true
		}
		if c := q.Class &^ unicastResponse; c != dnsmessage.ClassINET && c != dnsmessage.ClassANY {
			continue
		}
		for _, r := range recs {
			if strings.EqualFold(r.Header.Name.String(), q.Name.String()) && (q.Type == dnsmessage.TypeALL || q.Type == typeOf(r.Body)) {
				add(&ans, r)
			}
		}
	}
	if len(ans) == 0 {
		return nil, false
	}
	// What a client would ask for next: a PTR's SRV and TXT, an SRV's
	// addresses.
	var extra []dnsmessage.Resource
	for i := 0; i < len(ans)+len(extra); i++ {
		var r dnsmessage.Resource
		if i < len(ans) {
			r = ans[i]
		} else {
			r = extra[i-len(ans)]
		}
		var target string
		switch b := r.Body.(type) {
		case *dnsmessage.PTRResource:
			target = b.PTR.String()
		case *dnsmessage.SRVResource:
			target = b.Target.String()
		default:
			continue
		}
		for _, o := range recs {
			if strings.EqualFold(o.Header.Name.String(), target) {
				add(&extra, o)
			}
		}
	}
	var qs []dnsmessage.Question
	var id uint16
	if legacy {
		// RFC 6762 6.7: echo the ID and the questions, keep the TTLs
		// short and leave out cache-flush.
		id, qs = m.Header.ID, m.Questions
		ans, extra = legacyRecords(ans), legacyRecords(extra)
	}
	return response(id, qs, ans, extra), unicast
}

func legacyRecords(rs []dnsmessage.Resource) []dnsmessage.Resource {
	out := slices.Clone(rs)
	for i := range out {
		out[i].Header.Class &^= cacheFlush
		out[i].Header.TTL = min(out[i].Header.TTL, 10)
	}
	return out
}

func response(id uint16, qs []dnsmessage.Question, ans, extra []dnsmessage.Resource) []byte {
	m := dnsmessage.Message{
		Header:      dnsmessage.Header{ID: id, Response: true, Authoritative: true},
		Questions:   qs,
		Answers:     ans,
		Additionals: extra,
	}
	b, err := m.Pack()
	if err != nil {
		panic(fmt.Sprintf("mdns: %v", err))
	}
	return b
}

// sender serializes writes, since choosing the multicast interface and
// sending are two calls.
type sender struct {
	mu   sync.Mutex
	pc   *ipv4.PacketConn
	conn net.PacketConn
}

func (s *sender) multicast(ifi Interface, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pc.SetMulticastInterface(&net.Interface{Index: ifi.Index, Name: ifi.Name}) != nil {
		return
	}
	s.pc.WriteTo(b, nil, net.UDPAddrFromAddrPort(group))
}

func (s *sender) unicast(to netip.AddrPort, b []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conn.WriteTo(b, net.UDPAddrFromAddrPort(to))
}

func typeOf(b dnsmessage.ResourceBody) dnsmessage.Type {
	switch b.(type) {
	case *dnsmessage.PTRResource:
		return dnsmessage.TypePTR
	case *dnsmessage.SRVResource:
		return dnsmessage.TypeSRV
	case *dnsmessage.TXTResource:
		return dnsmessage.TypeTXT
	case *dnsmessage.AResource:
		return dnsmessage.TypeA
	}
	return 0
}
