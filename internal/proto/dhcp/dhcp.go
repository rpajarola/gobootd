// Package dhcp implements a BOOTP (RFC 951) and DHCP (RFC 2131) server
// that hands configured hosts their fixed address, boot file and root
// path.
//
// Clients are identified by their Ethernet address. There is no address
// pool: unknown clients get no answer, so another DHCP server on the
// network can serve them. Replies are sent as Ethernet frames, directly to
// the client's Ethernet address, so clients that cannot receive unicast
// before they are configured are reached too.
package dhcp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path"
	"sync/atomic"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.DHCP, func() daemon.Service { return &Server{} }) }

// Options are the settings in the dhcp service block.
type Options struct {
	// Routers are announced to clients on their subnet. Default none.
	Routers []string `hcl:"routers,optional"`
	// DNS are the name servers announced.
	DNS []string `hcl:"dns,optional"`
	// Domain is the DNS domain announced.
	Domain string `hcl:"domain,optional"`
	// LeaseTime is the DHCP lease time in seconds. Default one day.
	LeaseTime int `hcl:"lease_time,optional"`
}

// Server answers BOOTP and DHCP requests for hosts that may use dhcp.
type Server struct {
	opts    Options
	routers []netip.Addr
	dns     []netip.Addr
	id      atomic.Uint32
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

func (s *Server) setup() error {
	var err error
	if s.routers, err = parseAddrs("routers", s.opts.Routers); err != nil {
		return err
	}
	if s.dns, err = parseAddrs("dns", s.opts.DNS); err != nil {
		return err
	}
	if s.opts.LeaseTime < 0 {
		return fmt.Errorf("lease_time %d is negative", s.opts.LeaseTime)
	}
	if s.opts.LeaseTime == 0 {
		s.opts.LeaseTime = 86400
	}
	if len(s.opts.Domain) > 255 {
		return fmt.Errorf("domain %q is longer than 255 bytes", s.opts.Domain)
	}
	return nil
}

func parseAddrs(name string, ss []string) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, s := range ss {
		a, err := netip.ParseAddr(s)
		if err != nil || !a.Is4() {
			return nil, fmt.Errorf("%s: %q is not an IPv4 address", name, s)
		}
		out = append(out, a)
	}
	return out, nil
}

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if err := s.setup(); err != nil {
		return err
	}
	ports, err := env.Subscribe(Match)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "network", p.Interface().Name)
	}
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(env, p, frame) })
}

// request is one request being answered.
type request struct {
	env   *daemon.Env
	port  link.Port
	log   *slog.Logger
	d     Datagram
	p     *Packet
	typ   byte
	kind  string // "bootp request", "dhcp discover", ...
	who   string // the host name once known, the MAC address before
	inv   *inventory.Inventory
	host  *inventory.Host
	local netip.Prefix // bootd's address on the client's subnet
}

func (s *Server) handle(env *daemon.Env, port link.Port, frame []byte) {
	f, ok := link.Parse(frame)
	if !ok {
		return
	}
	d, ok := parseUDP(f)
	if !ok || d.Dst.Port() != ServerPort {
		return
	}
	p, err := Parse(d.Payload)
	if err != nil || p.Op != OpRequest {
		return
	}
	iface := port.Interface()
	mac := p.MAC()
	if mac == nil {
		env.Log.Debug("ignoring request for hardware type", "network", iface.Name, "htype", p.HType, "hlen", p.HLen)
		return
	}
	r := &request{env: env, port: port, d: d, p: p, typ: p.Type(), who: mac.String(), inv: env.Inventory()}
	r.kind = "bootp request"
	if r.typ != 0 {
		r.kind = "dhcp " + typeName(r.typ)
	}
	r.log = env.Log.With("network", iface.Name, "client", mac.String())
	r.log.Debug("received", "from", d.Src.String(), "packet", p)

	if p.GIAddr.IsValid() && !p.GIAddr.IsUnspecified() {
		r.log.Info(fmt.Sprintf("%s from %s via relay %s not answered (relay agents are not supported)", r.kind, r.who, p.GIAddr))
		return
	}
	switch r.typ {
	case 0, Discover, Request, Inform:
	case Release, Decline:
	default:
		r.log.Debug("ignoring message", "type", r.typ)
		return
	}

	h, err := r.inv.ByMAC(mac)
	if err != nil {
		if r.typ == Release || r.typ == Decline {
			r.log.Debug("ignoring message from unknown client", "type", r.kind)
		} else {
			r.denied(err)
		}
		return
	}
	r.host, r.who = h, h.Name
	r.log = r.log.With("host", h.Name)
	switch r.typ {
	case Release:
		r.log.Info(fmt.Sprintf("dhcp release from %s: %s", h.Name, p.CIAddr))
		return
	case Decline:
		r.log.Warn(fmt.Sprintf("dhcp decline from %s: %s is used by another station", h.Name, p.Addr(OptRequestedIP)))
		return
	}
	if err := h.Allows(service.DHCP); err != nil {
		r.denied(err)
		return
	}
	if !h.IP.IsValid() {
		r.denied(fmt.Errorf("host has no IP address"))
		return
	}
	local, ok := localPrefix(iface, h.IP)
	if !ok {
		r.log.Warn(fmt.Sprintf("%s from %s not answered (interface %s has no IPv4 address)", r.kind, h.Name, iface.Name))
		return
	}
	r.local = local
	if !iface.OnLink(h.IP) {
		r.log.Warn("client address is not on a subnet of this interface; it may not be able to reach this server",
			"ip", h.IP, "interface_addrs", iface.Addrs)
	}

	if r.typ == Request {
		// A client that chose another server's offer tells us by
		// naming that server.
		if sid := p.Addr(OptServerID); sid.IsValid() && sid != local.Addr() {
			r.log.Debug(fmt.Sprintf("dhcp request from %s is for server %s", h.Name, sid))
			return
		}
		want := p.Addr(OptRequestedIP)
		if !want.IsValid() {
			want = p.CIAddr
		}
		if want != h.IP {
			r.log.Info(fmt.Sprintf("dhcp request from %s for %s refused (its address is %s)", h.Name, want, h.IP))
			s.send(r, s.nak(r))
			return
		}
	}
	reply, file, err := s.reply(r)
	if err != nil {
		r.denied(err)
		return
	}
	if !s.send(r, reply) {
		return
	}
	attrs := []any{slog.String("server", local.Addr().String())}
	if file != nil {
		attrs = append(attrs, slog.String("file", reply.File), slog.String("path", file.Path))
	}
	switch r.typ {
	case 0:
		r.log.Info(fmt.Sprintf("bootp reply to %s: %s", h.Name, h.IP), attrs...)
	case Discover:
		r.log.Info(fmt.Sprintf("dhcp offer to %s: %s", h.Name, h.IP), attrs...)
	case Request:
		r.log.Info(fmt.Sprintf("dhcp ack to %s: %s", h.Name, h.IP), attrs...)
	case Inform:
		r.log.Info(fmt.Sprintf("dhcp ack to %s (inform)", h.Name), attrs...)
	}
}

func (r *request) denied(err error) {
	r.log.Info(fmt.Sprintf("%s from %s denied (%v)", r.kind, r.who, err))
}

// localPrefix returns bootd's address on the interface for ip, with its
// prefix.
func localPrefix(iface *link.Interface, ip netip.Addr) (netip.Prefix, bool) {
	for _, p := range iface.Addrs {
		if p.Contains(ip) {
			return p, true
		}
	}
	if len(iface.Addrs) > 0 {
		return iface.Addrs[0], true
	}
	return netip.Prefix{}, false
}

// reply builds the answer to a BOOTP request or a DHCP discover, request
// or inform, and returns the boot file in it, if any.
func (s *Server) reply(r *request) (*Packet, *inventory.File, error) {
	h, p := r.host, r.p
	rep := &Packet{
		Op: OpReply, HType: p.HType, HLen: p.HLen, XID: p.XID, Flags: p.Flags,
		CIAddr: p.CIAddr, YIAddr: h.IP, SIAddr: r.local.Addr(), CHAddr: p.CHAddr,
	}
	if r.typ == Inform {
		rep.YIAddr = netip.IPv4Unspecified()
	}
	f, _, err := h.FileIgnoringDir(service.DHCP, p.File)
	switch {
	case err == nil:
		rep.File = bootName(f, p.File)
		if len(rep.File) > 127 {
			return nil, nil, fmt.Errorf("boot file name %q is longer than 127 bytes", rep.File)
		}
	case p.File == "":
		// No boot file: the client only learns its address.
		f = nil
	default:
		return nil, nil, err
	}

	// Without the magic cookie, a BOOTP client gets options only if its
	// vendor area is empty; other formats are not understood.
	if r.typ == 0 && !p.Cookie && !zero(p.Vendor) {
		return rep, f, nil
	}
	rep.Cookie = true
	var required []Option
	space := 64 - len(magic) // a BOOTP vendor area
	if r.typ != 0 {
		t := byte(Offer)
		if r.typ != Discover {
			t = Ack
		}
		required = append(required, Option{OptMessageType, []byte{t}}, Option{OptServerID, ip4(r.local.Addr())})
		if r.typ != Inform {
			required = append(required, Option{OptLeaseTime, u32(uint32(s.opts.LeaseTime))})
		}
		space = p.MaxSize() - 20 - 8 - headerLen - len(magic)
	}
	opts, dropped := options(required, s.params(r, f), p.Get(OptParamRequest), space)
	if len(dropped) > 0 {
		r.log.Debug("options left out, they do not fit", "options", dropped)
	}
	rep.Options = opts
	return rep, f, nil
}

// params returns the options describing the host's network and boot.
func (s *Server) params(r *request, f *inventory.File) []Option {
	h, local := r.host, r.local
	mask := net.CIDRMask(local.Bits(), 32)
	opts := []Option{{OptSubnetMask, mask}}
	var routers []byte
	for _, a := range s.routers {
		if local.Contains(a) {
			routers = append(routers, ip4(a)...)
		}
	}
	if routers != nil {
		opts = append(opts, Option{OptRouter, routers})
	}
	if len(s.dns) > 0 {
		var b []byte
		for _, a := range s.dns {
			b = append(b, ip4(a)...)
		}
		opts = append(opts, Option{OptDNS, b})
	}
	opts = append(opts, Option{OptHostName, []byte(truncate(h.Name))})
	if s.opts.Domain != "" {
		opts = append(opts, Option{OptDomainName, []byte(s.opts.Domain)})
	}
	if root := rootPath(r.inv, h, local.Addr()); root != "" {
		opts = append(opts, Option{OptRootPath, []byte(truncate(root))})
	}
	bcast := local.Masked().Addr().As4()
	for i := range bcast {
		bcast[i] |= ^mask[i]
	}
	opts = append(opts, Option{OptBroadcast, bcast[:]})
	if d := nisDomain(r.inv); d != "" && h.Allows(service.NIS) == nil {
		opts = append(opts, Option{OptNISDomain, []byte(truncate(d))}, Option{OptNISServers, ip4(local.Addr())})
	}
	if f != nil {
		if st, err := os.Stat(f.Path); err == nil {
			blocks := min((st.Size()+511)/512, 0xffff)
			opts = append(opts, Option{OptBootSize, binary.BigEndian.AppendUint16(nil, uint16(blocks))})
		}
	}
	return opts
}

// nak builds the refusal of a DHCP request.
func (s *Server) nak(r *request) *Packet {
	p := r.p
	return &Packet{
		Op: OpReply, HType: p.HType, HLen: p.HLen, XID: p.XID, Flags: p.Flags, CHAddr: p.CHAddr,
		Cookie:  true,
		Options: []Option{{OptMessageType, []byte{Nak}}, {OptServerID, ip4(r.local.Addr())}},
	}
}

// send addresses the reply as RFC 2131 4.1 says and sends it. It reports
// whether it was sent.
func (s *Server) send(r *request, rep *Packet) bool {
	iface := r.port.Interface()
	dstMAC, dst := net.HardwareAddr(rep.CHAddr[:6]), rep.YIAddr
	switch {
	case rep.Type() == Nak:
		dstMAC, dst = link.Broadcast, broadcast
	case r.p.CIAddr.IsValid() && !r.p.CIAddr.IsUnspecified():
		// The client has an address and answers ARP: send to where the
		// request came from.
		dstMAC, dst = r.d.SrcMAC, r.p.CIAddr
	case r.p.Flags&flagBroadcast != 0:
		dstMAC, dst = link.Broadcast, broadcast
	}
	src := netip.AddrPortFrom(r.local.Addr(), ServerPort)
	frame := buildUDP(dstMAC, iface.MAC, src, netip.AddrPortFrom(dst, ClientPort), uint16(s.id.Add(1)), rep.Marshal())
	if err := r.port.WriteFrame(frame); err != nil {
		r.log.Warn("sending reply failed", "err", err)
		return false
	}
	r.log.Debug("sent", "to", dst.String(), "mac", dstMAC.String(), "packet", rep)
	return true
}

// bootName is the name the client is told to load f by. It loads it over
// TFTP, which looks the name up the same way.
func bootName(f *inventory.File, requested string) string {
	switch {
	case requested != "":
		return requested
	case f.Name != "*":
		return f.Name
	}
	return path.Base(f.Label)
}

// rootPath returns the host's root export as server:path, or "".
func rootPath(inv *inventory.Inventory, h *inventory.Host, local netip.Addr) string {
	x, err := h.Export("root")
	if err != nil {
		return ""
	}
	server := local.String()
	if x.Server != "" {
		server = x.Server
		if a, err := netip.ParseAddr(x.Server); err == nil {
			server = a.String()
		} else if sh, err := inv.ByName(x.Server); err == nil && sh.IP.IsValid() {
			server = sh.IP.String()
		}
	}
	return server + ":" + x.ExportPath
}

// nisDomain returns the domain of the nis service, or "".
func nisDomain(inv *inventory.Inventory) string {
	svc := inv.Services[service.NIS]
	if svc == nil {
		return ""
	}
	var opts struct {
		Domain string   `hcl:"domain,optional"`
		Rest   hcl.Body `hcl:",remain"`
	}
	gohcl.DecodeBody(svc.Options, nil, &opts)
	return opts.Domain
}

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

func ip4(a netip.Addr) []byte {
	b := a.As4()
	return b[:]
}

func u32(v uint32) []byte { return binary.BigEndian.AppendUint32(nil, v) }

// truncate cuts an option value to the 255 bytes an option holds.
func truncate(s string) string { return s[:min(len(s), 255)] }

func zero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
