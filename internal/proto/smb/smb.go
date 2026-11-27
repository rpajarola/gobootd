// Package smb serves shares to DOS and early Windows clients over SMB1, in
// the dialects before NT LM 0.12: the core protocol of the PC Network
// Program and MS-NET, and LAN Manager 1.0 to 2.1. That covers the DOS
// redirectors of MS Network Client and LAN Manager, Windows for Workgroups
// and Windows 95.
//
// Sessions run over NetBIOS: on TCP/IP (port 139, with the name service on
// UDP 137) and on NetBEUI. Security is share-level and passwords are not
// checked: like every other service, a client is known by its address,
// and gets the shares of its host. Shares are read-only unless they are
// writable.
package smb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/llc"
	"github.com/rpajarola/gobootd/internal/netbios"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.SMB, func() daemon.Service { return &Server{} }) }

// Transports.
const (
	TCP     = "tcp"
	NetBEUI = "netbeui"
)

// Options are the settings in the smb service block.
type Options struct {
	// NetBIOSName is the server's name, which clients use in
	// \\NAME\SHARE. The default is the host name up to the first dot,
	// cut to 15 characters.
	NetBIOSName string `hcl:"netbios_name,optional"`
	// Workgroup is the workgroup the server says it is in.
	Workgroup string `hcl:"workgroup,optional"`
	// Transports are "tcp" (NetBIOS over TCP/IP) and "netbeui". The
	// default is both.
	Transports []string `hcl:"transports,optional"`
}

// Server is the SMB service.
type Server struct {
	opts  Options
	names []netbios.Name
	env   *daemon.Env
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

func (s *Server) setup() error {
	if s.opts.NetBIOSName == "" {
		h, _ := os.Hostname()
		s.opts.NetBIOSName, _, _ = strings.Cut(h, ".")
	}
	s.opts.NetBIOSName = strings.ToUpper(s.opts.NetBIOSName)
	if len(s.opts.NetBIOSName) > 15 {
		s.opts.NetBIOSName = s.opts.NetBIOSName[:15]
	}
	if s.opts.NetBIOSName == "" {
		return errors.New("no NetBIOS name")
	}
	if s.opts.Workgroup == "" {
		s.opts.Workgroup = "WORKGROUP"
	}
	s.opts.Workgroup = strings.ToUpper(s.opts.Workgroup)
	if s.opts.Transports == nil {
		s.opts.Transports = []string{TCP, NetBEUI}
	}
	for _, t := range s.opts.Transports {
		if t != TCP && t != NetBEUI {
			return fmt.Errorf("unknown transport %q: use %q or %q", t, TCP, NetBEUI)
		}
	}
	s.names = []netbios.Name{
		netbios.MakeName(s.opts.NetBIOSName, netbios.Server),
		netbios.MakeName(s.opts.NetBIOSName, netbios.Workstation),
	}
	return nil
}

// ours reports whether n is one of the server's names.
func (s *Server) ours(n netbios.Name) bool {
	return slices.ContainsFunc(s.names, n.Equal) || n.Equal(netbios.MakeName(s.opts.NetBIOSName, netbios.Messenger))
}

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if err := s.setup(); err != nil {
		return err
	}
	s.env = env
	if len(env.Networks) == 0 {
		return errors.New("no network")
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	defer wg.Wait()
	fail := func(err error) {
		if ctx.Err() == nil {
			cancel(err)
		}
	}
	if slices.Contains(s.opts.Transports, TCP) {
		for _, n := range env.Networks {
			if err := s.startNBT(ctx, &wg, n, fail); err != nil {
				cancel(nil)
				return fmt.Errorf("network %s: %w", n.Name(), err)
			}
		}
	}
	if slices.Contains(s.opts.Transports, NetBEUI) {
		var st []*llc.Station
		ports, err := env.Subscribe(func(f link.Frame) bool {
			return f.Type == 0 && len(f.Payload) >= 3 && (f.Payload[0]&^1 == netbios.SAP || f.Payload[0] == 0xff)
		})
		if err != nil {
			cancel(nil)
			return err
		}
		stations := map[link.Port]*llc.Station{}
		for _, p := range ports {
			station := &llc.Station{SAP: netbios.SAP, Port: p, Log: env.Log}
			nbf := &netbios.NBF{Station: station, Names: s.names, Log: env.Log,
				Check: func(mac net.HardwareAddr, called, calling netbios.Name) bool {
					_, err := s.client(env.Log, "netbeui", mac.String(), calling, func(inv *inventory.Inventory) (*inventory.Host, error) { return inv.ByMAC(mac) })
					return err == nil
				},
				Accept: func(c *netbios.NBFSession) { s.serveNBF(ctx, c) },
			}
			nbf.Init()
			stations[p] = station
			st = append(st, station)
			env.Log.Info("listening", "network", p.Interface().Name, "transport", NetBEUI, "name", s.opts.NetBIOSName)
		}
		for _, station := range st {
			wg.Go(func() { station.Run(ctx) })
		}
		wg.Go(func() {
			if err := link.Serve(ctx, ports, func(p link.Port, frame []byte) { stations[p].Handle(frame) }); err != nil {
				fail(err)
			}
		})
	}
	<-ctx.Done()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// client finds the host of a client and checks that it may use SMB,
// logging a refusal.
func (s *Server) client(log *slog.Logger, transport, addr string, calling netbios.Name, find func(*inventory.Inventory) (*inventory.Host, error)) (*inventory.Host, error) {
	h, err := find(s.env.Inventory())
	if err == nil {
		err = h.Allows(service.SMB)
	}
	if err != nil {
		who := addr
		if h != nil {
			who = h.Name
		}
		log.Info(fmt.Sprintf("smb session from %s (%s over %s) denied (%v)", who, calling.Base(), transport, err))
		return nil, err
	}
	return h, nil
}

// startNBT starts the name service and session service on a network.
func (s *Server) startNBT(ctx context.Context, wg *sync.WaitGroup, n *netif.Network, fail func(error)) error {
	ns, err := n.IP.ListenUDP(netbios.NameServicePort)
	if err != nil {
		return err
	}
	l, err := n.IP.ListenTCP(netbios.SessionServicePort)
	if err != nil {
		ns.Close()
		return err
	}
	log := s.env.Log.With("network", n.Name())
	log.Info("listening", "transport", TCP, "name", s.opts.NetBIOSName, "addr", n.Addr().Addr().String())
	context.AfterFunc(ctx, func() { ns.Close(); l.Close() })
	wg.Go(func() {
		for {
			d, err := ns.Read(ctx)
			if err != nil {
				if ctx.Err() == nil {
					fail(fmt.Errorf("network %s: %w", n.Name(), err))
				}
				return
			}
			if resp := s.nameQuery(log, n, d.Data, d.From.Addr()); resp != nil {
				ns.WriteTo(resp, d.From)
			}
		}
	})
	wg.Go(func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if ctx.Err() == nil {
					fail(fmt.Errorf("network %s: %w", n.Name(), err))
				}
				return
			}
			wg.Go(func() {
				defer c.Close()
				stop := context.AfterFunc(ctx, func() { c.Close() })
				defer stop()
				s.serveNBT(ctx, log, c)
			})
		}
	})
	return nil
}

// nameQuery answers name queries and node status requests for the
// server's names from clients that may use SMB.
func (s *Server) nameQuery(log *slog.Logger, n *netif.Network, b []byte, from netip.Addr) []byte {
	q, ok := netbios.ParseQuery(b)
	if !ok {
		return nil
	}
	if q.Status {
		if q.Name != netbios.Wildcard && !s.ours(q.Name) {
			return nil
		}
	} else if !s.ours(q.Name) {
		return nil
	}
	h, err := s.env.Inventory().ByIP(from)
	if err == nil {
		err = h.Allows(service.SMB)
	}
	if err != nil {
		if !q.Status {
			who := from.String()
			if h != nil {
				who = h.Name
			}
			log.Info(fmt.Sprintf("netbios name query from %s for %s denied (%v)", who, q.Name, err))
		}
		return nil
	}
	if q.Status {
		return q.StatusAnswer([]netbios.Entry{
			{Name: s.names[0]}, {Name: s.names[1]},
			{Name: netbios.MakeName(s.opts.Workgroup, netbios.Workstation), Group: true},
		}, n.Interface().MAC)
	}
	log.Debug("netbios name query", "host", h.Name, "name", q.Name.String())
	return q.Answer(n.Addr().Addr())
}

func (s *Server) serveNBT(ctx context.Context, log *slog.Logger, c net.Conn) {
	ip := addrOf(c.RemoteAddr())
	var h *inventory.Host
	nc, called, calling, err := netbios.AcceptNBT(c, func(called, calling netbios.Name) byte {
		var err error
		h, err = s.client(log, "tcp", ip.String(), calling, func(inv *inventory.Inventory) (*inventory.Host, error) { return inv.ByIP(ip) })
		if err != nil {
			return netbios.NotListeningForCaller
		}
		return 0
	})
	if err != nil {
		if h != nil {
			log.Debug("netbios session failed", "client", ip.String(), "err", err)
		}
		return
	}
	s.serve(ctx, log, nc, h, TCP, called, calling)
}

func (s *Server) serveNBF(ctx context.Context, c *netbios.NBFSession) {
	defer c.Close()
	h, err := s.client(s.env.Log, "netbeui", c.Remote().String(), c.Calling, func(inv *inventory.Inventory) (*inventory.Host, error) { return inv.ByMAC(c.Remote()) })
	if err != nil {
		return
	}
	s.serve(ctx, s.env.Log, c, h, NetBEUI, c.Called, c.Calling)
}

func addrOf(a net.Addr) netip.Addr {
	if t, ok := a.(*net.TCPAddr); ok {
		return t.AddrPort().Addr().Unmap()
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap.Addr()
}

// serve runs an SMB session until the client goes away.
func (s *Server) serve(ctx context.Context, log *slog.Logger, nc netbios.Conn, h *inventory.Host, transport string, called, calling netbios.Name) {
	c := &conn{
		s: s, nc: nc, host: h, transport: transport,
		log:      log.With("host", h.Name),
		trees:    map[uint16]*tree{},
		files:    map[uint16]*file{},
		searches: map[uint16]*search{},
		maxBuf:   defaultClientBuffer,
		key:      rand.Uint32(),
	}
	defer c.closeAll()
	c.log.Info(fmt.Sprintf("smb session from %s (%s over %s)", h.Name, calling.Base(), transport), "called", called.String())
	start := time.Now()
	for {
		msg, err := nc.ReadMessage(ctx)
		if err != nil {
			c.log.Info(fmt.Sprintf("smb session from %s ended", h.Name), "duration", time.Since(start).Round(time.Second).String())
			return
		}
		for _, out := range c.handle(msg) {
			if err := nc.WriteMessage(ctx, out); err != nil {
				c.log.Debug("smb write failed", "err", err)
				return
			}
		}
	}
}
