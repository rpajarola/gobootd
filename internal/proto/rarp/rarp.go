// Package rarp implements the Reverse Address Resolution Protocol
// (RFC 903), which clients use to learn their IP address from their
// Ethernet address.
package rarp

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.RARP, func() daemon.Service { return &Server{} }) }

// Operations.
const (
	OpRequest = 3
	OpReply   = 4
)

const (
	hwEther = 1
	// Len is the length of an Ethernet/IPv4 RARP packet.
	Len = 28
)

// Packet is an Ethernet/IPv4 RARP packet.
type Packet struct {
	Op       uint16
	SenderHW net.HardwareAddr
	SenderIP netip.Addr
	TargetHW net.HardwareAddr
	TargetIP netip.Addr
}

// Parse parses a RARP payload. ok is false if it is not an Ethernet/IPv4
// RARP packet.
func Parse(b []byte) (p Packet, ok bool) {
	if len(b) < Len ||
		binary.BigEndian.Uint16(b[0:2]) != hwEther ||
		binary.BigEndian.Uint16(b[2:4]) != link.TypeIPv4 ||
		b[4] != 6 || b[5] != 4 {
		return p, false
	}
	return Packet{
		Op:       binary.BigEndian.Uint16(b[6:8]),
		SenderHW: net.HardwareAddr(b[8:14]),
		SenderIP: netip.AddrFrom4([4]byte(b[14:18])),
		TargetHW: net.HardwareAddr(b[18:24]),
		TargetIP: netip.AddrFrom4([4]byte(b[24:28])),
	}, true
}

// Marshal encodes p.
func (p Packet) Marshal() []byte {
	b := make([]byte, Len)
	binary.BigEndian.PutUint16(b[0:2], hwEther)
	binary.BigEndian.PutUint16(b[2:4], link.TypeIPv4)
	b[4], b[5] = 6, 4
	binary.BigEndian.PutUint16(b[6:8], p.Op)
	copy(b[8:14], p.SenderHW)
	put4(b[14:18], p.SenderIP)
	copy(b[18:24], p.TargetHW)
	put4(b[24:28], p.TargetIP)
	return b
}

func put4(b []byte, ip netip.Addr) {
	if ip.Is4() {
		a := ip.As4()
		copy(b, a[:])
	}
}

func (p Packet) String() string {
	op := fmt.Sprintf("op %d", p.Op)
	switch p.Op {
	case OpRequest:
		op = "request"
	case OpReply:
		op = "reply"
	}
	return fmt.Sprintf("%s sender %s %s target %s %s", op, p.SenderHW, ipString(p.SenderIP), p.TargetHW, ipString(p.TargetIP))
}

func ipString(ip netip.Addr) string {
	if !ip.IsValid() {
		return "-"
	}
	return ip.String()
}

// Server answers RARP requests for hosts that may use rarp.
type Server struct{}

// Match selects RARP frames.
var Match = link.MatchType(link.TypeRARP)

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	ports, err := env.Subscribe(Match)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "network", p.Interface().Name)
	}
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(env, p, frame) })
}

func (s *Server) handle(env *daemon.Env, port link.Port, frame []byte) {
	f, ok := link.Parse(frame)
	if !ok || f.Type != link.TypeRARP {
		return
	}
	req, ok := Parse(f.Payload)
	if !ok || req.Op != OpRequest {
		return
	}
	iface := port.Interface()
	if string(f.Src) == string(iface.MAC) {
		return
	}
	log := env.Log.With("network", iface.Name, "client", req.TargetHW.String())
	log.Debug("received", "from", f.Src.String(), "packet", req)

	// The target hardware address is the client asking; it is usually
	// also the sender, but a host may ask on behalf of another.
	h, err := env.Inventory().ByMAC(req.TargetHW)
	if err != nil {
		log.Info(fmt.Sprintf("rarp request from %s denied (%v)", req.TargetHW, err))
		return
	}
	log = log.With("host", h.Name)
	if err := h.Allows(service.RARP); err != nil {
		log.Info(fmt.Sprintf("rarp request from %s denied (%v)", h.Name, err))
		return
	}
	if !h.IP.IsValid() {
		log.Info(fmt.Sprintf("rarp request from %s denied (host has no IP address)", h.Name))
		return
	}
	serverIP, ok := iface.AddrFor(h.IP)
	if !ok {
		log.Warn(fmt.Sprintf("rarp request from %s not answered (interface %s has no IPv4 address)", h.Name, iface.Name))
		return
	}
	if !iface.OnLink(h.IP) {
		log.Warn("client address is not on a subnet of this interface; it may not be able to reach this server",
			"ip", h.IP, "interface_addrs", iface.Addrs)
	}
	repl := Packet{
		Op:       OpReply,
		SenderHW: iface.MAC,
		SenderIP: serverIP,
		TargetHW: req.TargetHW,
		TargetIP: h.IP,
	}
	if err := port.WriteFrame(link.Build(f.Src, iface.MAC, link.TypeRARP, repl.Marshal())); err != nil {
		log.Warn("sending reply failed", "err", err)
		return
	}
	log.Info(fmt.Sprintf("rarp reply to %s: %s", h.Name, h.IP), slog.String("server", serverIP.String()))
	log.Debug("sent", "packet", repl)
}
