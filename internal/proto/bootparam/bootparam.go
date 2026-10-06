// Package bootparam implements Sun's bootparam RPC protocol (program
// 100026), which diskless clients use after RARP to learn their host name
// and where their root and swap are.
//
// Clients usually find the server by broadcasting WHOAMI through the
// portmapper's CALLIT, then ask GETFILE for "root", "swap" and so on. The
// answers come from the host's export blocks, the same ones the NFS server
// serves, so the two cannot disagree. Unknown clients and unknown keys get
// no answer, so another server can answer instead.
package bootparam

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.Bootparam, func() daemon.Service { return &Server{} }) }

// Program numbers.
const (
	Prog        = 100026
	Vers        = 1
	ProcWhoami  = 1
	ProcGetfile = 2

	ipAddrType = 1
	maxName    = 255
	maxPath    = 1024
	maxFileID  = 32
)

// Options are the settings in the bootparam service block.
type Options struct {
	// ServerName is the name announced for exports without a server.
	// Defaults to the host name up to the first dot.
	ServerName string `hcl:"server_name,optional"`
	// Domain is the NIS domain announced to clients. Default empty.
	Domain string `hcl:"domain,optional"`
	// Router is the default router announced to clients. Defaults to
	// bootd's address on the network, like FreeBSD's bootparamd.
	Router string `hcl:"router,optional"`
}

// Server answers bootparam calls.
type Server struct {
	opts   Options
	router netip.Addr
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

func (s *Server) setup() error {
	if s.opts.ServerName == "" {
		h, _ := os.Hostname()
		s.opts.ServerName, _, _ = strings.Cut(h, ".")
	}
	if s.opts.Router != "" {
		r, err := netip.ParseAddr(s.opts.Router)
		if err != nil || !r.Is4() {
			return fmt.Errorf("router %q is not an IPv4 address", s.opts.Router)
		}
		s.router = r
	}
	return nil
}

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if err := s.setup(); err != nil {
		return err
	}
	if len(env.Networks) == 0 {
		return fmt.Errorf("no network")
	}
	for _, n := range env.Networks {
		unregister := n.RPC.Register(s.program(env, n))
		defer unregister()
		env.Log.Info("listening", "network", n.Name(), "server_name", s.opts.ServerName)
	}
	<-ctx.Done()
	return nil
}

func (s *Server) program(env *daemon.Env, n *netif.Network) *oncrpc.Program {
	return &oncrpc.Program{Prog: Prog, Vers: Vers, Procs: map[uint32]oncrpc.Proc{
		ProcWhoami:  func(c *oncrpc.Call) ([]byte, error) { return s.whoami(env, n, c) },
		ProcGetfile: func(c *oncrpc.Call) ([]byte, error) { return s.getfile(env, n, c) },
	}}
}

func decodeAddr(d *oncrpc.Decoder) netip.Addr {
	if d.Uint32() != ipAddrType {
		return netip.Addr{}
	}
	// XDR encodes each char of the address as an int.
	var a [4]byte
	for i := range a {
		a[i] = byte(d.Uint32())
	}
	return netip.AddrFrom4(a)
}

func encodeAddr(e *oncrpc.Encoder, a netip.Addr) {
	e.Uint32(ipAddrType)
	b := [4]byte{}
	if a.Is4() {
		b = a.As4()
	}
	for _, c := range b {
		e.Uint32(uint32(c))
	}
}

func (s *Server) whoami(env *daemon.Env, n *netif.Network, c *oncrpc.Call) ([]byte, error) {
	ip := decodeAddr(c.Args)
	if c.Args.Err() != nil || !ip.IsValid() {
		return nil, oncrpc.ErrGarbageArgs
	}
	log := env.Log.With("network", n.Name(), "client", ip.String(), "from", c.From.String())
	log.Debug("whoami", "broadcast", c.Broadcast, "indirect", c.Indirect)
	h, err := env.Inventory().ByIP(ip)
	if err != nil {
		log.Info(fmt.Sprintf("bootparam whoami from %s denied (%v)", ip, err))
		return nil, oncrpc.ErrDrop
	}
	if err := h.Allows(service.Bootparam); err != nil {
		log.Info(fmt.Sprintf("bootparam whoami from %s denied (%v)", h.Name, err))
		return nil, oncrpc.ErrDrop
	}
	router := s.router
	if !router.IsValid() {
		router = n.Addr().Addr()
	}
	e := &oncrpc.Encoder{}
	e.String(h.Name).String(s.opts.Domain)
	encodeAddr(e, router)
	log.Info(fmt.Sprintf("bootparam whoami from %s: %s", ip, h.Name), "domain", s.opts.Domain, "router", router.String())
	return e.Bytes(), nil
}

func (s *Server) getfile(env *daemon.Env, n *netif.Network, c *oncrpc.Call) ([]byte, error) {
	name, key := c.Args.String(maxName), c.Args.String(maxFileID)
	if c.Args.Err() != nil {
		return nil, oncrpc.ErrGarbageArgs
	}
	log := env.Log.With("network", n.Name(), "client", name, "from", c.From.String())
	inv := env.Inventory()
	h, err := inv.ByName(name)
	if err != nil {
		log.Info(fmt.Sprintf("bootparam getfile %s from %s denied (%v)", key, name, err))
		return nil, oncrpc.ErrDrop
	}
	if err := h.Allows(service.Bootparam); err != nil {
		log.Info(fmt.Sprintf("bootparam getfile %s from %s denied (%v)", key, h.Name, err))
		return nil, oncrpc.ErrDrop
	}
	e := &oncrpc.Encoder{}
	x, err := h.Export(key)
	if err != nil {
		if key == "dump" {
			// SunOS asks for a dump device; an empty answer means none.
			e.String("")
			encodeAddr(e, netip.Addr{})
			e.String("")
			log.Info(fmt.Sprintf("bootparam getfile dump from %s: none", h.Name))
			return e.Bytes(), nil
		}
		log.Info(fmt.Sprintf("bootparam getfile %s from %s denied (%v)", key, h.Name, err))
		return nil, oncrpc.ErrDrop
	}
	server, addr := s.opts.ServerName, n.Addr().Addr()
	if x.Server != "" {
		server = x.Server
		if addr, err = lookup(inv, x.Server); err != nil {
			log.Warn(fmt.Sprintf("bootparam getfile %s from %s failed (server %s: %v)", key, h.Name, x.Server, err))
			return nil, oncrpc.ErrDrop
		}
	}
	e.String(server)
	encodeAddr(e, addr)
	e.String(x.ExportPath)
	log.Info(fmt.Sprintf("bootparam getfile %s from %s: %s:%s", key, h.Name, server, x.ExportPath), "server_address", addr.String())
	return e.Bytes(), nil
}

// lookup finds the address of another NFS server: a configured host, or
// the system resolver.
func lookup(inv *inventory.Inventory, name string) (netip.Addr, error) {
	if h, err := inv.ByName(name); err == nil && h.IP.IsValid() {
		return h.IP, nil
	}
	if a, err := netip.ParseAddr(name); err == nil && a.Is4() {
		return a, nil
	}
	addrs, err := net.LookupHost(name)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, s := range addrs {
		if a, err := netip.ParseAddr(s); err == nil && a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return netip.Addr{}, fmt.Errorf("no IPv4 address")
}
