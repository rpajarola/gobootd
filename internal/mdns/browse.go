package mdns

import (
	"context"
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/ipv4"
)

// Found is a service instance a Browse found.
type Found struct {
	// Instance is the instance name without the service type.
	Instance string
	// Host is the target host name, with .local.
	Host  string
	Port  uint16
	Addrs []netip.Addr
	// TXT is the TXT record as key=value pairs.
	TXT map[string]string
	// Interface is where the answer came in.
	Interface string
}

// Browse asks every interface for instances of service, such as
// "_bootbridge._udp", and collects the answers for wait. It queries as a
// one-shot client (RFC 6762 5.1) from a port of its own, so it works
// next to the system's responder, which answers too.
func Browse(ctx context.Context, service string, wait time.Duration) ([]Found, error) {
	ifs, err := Interfaces()
	if err != nil {
		return nil, err
	}
	c, err := net.ListenPacket("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}
	defer c.Close()
	pc := ipv4.NewPacketConn(c)
	pc.SetMulticastTTL(255)
	pc.SetMulticastLoopback(true)

	typ := strings.ToLower(service + ".local.")
	send := func(qs []dnsmessage.Question) {
		m := dnsmessage.Message{Header: dnsmessage.Header{ID: uint16(rand.IntN(0xffff) + 1)}, Questions: qs}
		b, err := m.Pack()
		if err != nil {
			return
		}
		for _, ifi := range ifs {
			if pc.SetMulticastInterface(&net.Interface{Index: ifi.Index, Name: ifi.Name}) == nil {
				pc.WriteTo(b, nil, net.UDPAddrFromAddrPort(group))
			}
		}
	}
	send([]dnsmessage.Question{{Name: mustName(typ), Type: dnsmessage.TypePTR, Class: dnsmessage.ClassINET}})

	col := newCollector(typ)
	deadline := time.Now().Add(wait)
	followUp := time.Now().Add(wait / 2)
	followed := false
	buf := make([]byte, 9000)
	for {
		if ctx.Err() != nil {
			return col.results(), ctx.Err()
		}
		next := deadline
		if !followed && followUp.Before(next) {
			next = followUp
		}
		c.SetReadDeadline(next)
		n, src, err := c.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if !followed && time.Now().After(followUp) {
					followed = true
					// Ask for what the first answers left out.
					if qs := col.missing(); len(qs) > 0 {
						send(qs)
					}
					continue
				}
				return col.results(), nil
			}
			return col.results(), err
		}
		var m dnsmessage.Message
		if m.Unpack(buf[:n]) != nil || !m.Header.Response {
			continue
		}
		iface := ""
		if ua, ok := src.(*net.UDPAddr); ok {
			a := ua.AddrPort().Addr().Unmap()
			for _, ifi := range ifs {
				if slices.ContainsFunc(ifi.Addrs, func(p netip.Prefix) bool { return p.Contains(a) }) {
					iface = ifi.Name
				}
			}
		}
		col.add(append(m.Answers, m.Additionals...), iface)
	}
}

// collector puts together the records of a browse.
type collector struct {
	typ   string // lower case, with .local.
	insts map[string]*Found
	order []string
	addrs map[string][]netip.Addr // by lower-case host name
}

func newCollector(typ string) *collector {
	return &collector{typ: typ, insts: map[string]*Found{}, addrs: map[string][]netip.Addr{}}
}

func (c *collector) inst(full, iface string) *Found {
	k := strings.ToLower(full)
	f := c.insts[k]
	if f == nil {
		name := full[:len(full)-len(c.typ)]
		f = &Found{Instance: strings.TrimSuffix(name, "."), Interface: iface}
		c.insts[k] = f
		if !slices.Contains(c.order, k) {
			c.order = append(c.order, k)
		}
	}
	if f.Interface == "" {
		f.Interface = iface
	}
	return f
}

func (c *collector) ours(name string) bool {
	n := strings.ToLower(name)
	return strings.HasSuffix(n, "."+c.typ) && len(n) > len(c.typ)+1
}

func (c *collector) add(rs []dnsmessage.Resource, iface string) {
	for _, r := range rs {
		name := r.Header.Name.String()
		if _, ptr := r.Body.(*dnsmessage.PTRResource); r.Header.TTL == 0 && !ptr {
			continue // a goodbye; the PTR's removes the instance
		}
		switch b := r.Body.(type) {
		case *dnsmessage.PTRResource:
			if strings.EqualFold(name, c.typ) && c.ours(b.PTR.String()) {
				if r.Header.TTL == 0 { // goodbye
					delete(c.insts, strings.ToLower(b.PTR.String()))
				} else {
					c.inst(b.PTR.String(), iface)
				}
			}
		case *dnsmessage.SRVResource:
			if c.ours(name) {
				f := c.inst(name, iface)
				f.Host, f.Port = b.Target.String(), b.Port
			}
		case *dnsmessage.TXTResource:
			if c.ours(name) {
				f := c.inst(name, iface)
				f.TXT = map[string]string{}
				for _, kv := range b.TXT {
					if k, v, _ := strings.Cut(kv, "="); k != "" {
						f.TXT[strings.ToLower(k)] = v
					}
				}
			}
		case *dnsmessage.AResource:
			h := strings.ToLower(name)
			a := netip.AddrFrom4(b.A)
			if !slices.Contains(c.addrs[h], a) {
				c.addrs[h] = append(c.addrs[h], a)
			}
		}
	}
}

// missing are the questions for SRV and TXT records and addresses that
// have not come yet.
func (c *collector) missing() []dnsmessage.Question {
	var qs []dnsmessage.Question
	for _, k := range c.order {
		f := c.insts[k]
		if f == nil {
			continue
		}
		n, err := dnsmessage.NewName(f.Instance + "." + c.typ)
		if err != nil {
			continue
		}
		if f.Host == "" || f.TXT == nil {
			qs = append(qs, dnsmessage.Question{Name: n, Type: dnsmessage.TypeALL, Class: dnsmessage.ClassINET})
		} else if len(c.addrs[strings.ToLower(f.Host)]) == 0 {
			if h, err := dnsmessage.NewName(f.Host); err == nil {
				qs = append(qs, dnsmessage.Question{Name: h, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
			}
		}
	}
	return qs
}

func (c *collector) results() []Found {
	var out []Found
	for _, k := range c.order {
		f := c.insts[k]
		if f == nil {
			continue
		}
		r := *f
		r.Addrs = c.addrs[strings.ToLower(f.Host)]
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b Found) int { return strings.Compare(a.Instance, b.Instance) })
	return out
}
