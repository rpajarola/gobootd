// Package nis implements an NIS (YP) server, version 2 of program 100004,
// enough for SunOS 4 and other old clients to bind and look up users,
// groups, hosts and the like.
//
// The client's ypbind finds the server by broadcasting DOMAIN_NONACK
// through the portmapper's CALLIT. Lookups (MATCH, FIRST, NEXT) come over
// UDP; ypcat uses ALL, which needs TCP.
//
// The maps are made from files in /etc format in the maps directory
// (passwd, group, hosts, ...), keyed as SunOS's /var/yp/Makefile keys them,
// plus the configured hosts in hosts.* and ethers.*. They are read at start
// and on reload. Maps cannot be transferred to other servers.
package nis

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.NIS, func() daemon.Service { return &Server{} }) }

// Program numbers.
const (
	Prog = 100004
	Vers = 2

	maxDomain = 64
	maxMap    = 64
)

// Procedures.
const (
	procDomain       = 1
	procDomainNonack = 2
	procMatch        = 3
	procFirst        = 4
	procNext         = 5
	procClear        = 7
	procAll          = 8
	procMaster       = 9
	procOrder        = 10
	procMaplist      = 11
)

// Status codes.
const (
	ypTrue    = 1
	ypNomore  = 2
	ypFalse   = 0
	ypNomap   = -1
	ypNodom   = -2
	ypNokey   = -3
	ypBadargs = -7
)

// Options are the settings in the nis service block.
type Options struct {
	// Domain is the NIS domain served.
	Domain string `hcl:"domain"`
	// Maps is the directory with the source files. Relative to root.
	Maps string `hcl:"maps,optional"`
	// ServerName is the master's name, and the name added to the hosts
	// maps with bootd's address. Defaults to the host name up to the
	// first dot.
	ServerName string `hcl:"server_name,optional"`
}

// Server answers NIS calls.
type Server struct {
	opts Options

	mu    sync.Mutex
	inv   *inventory.Inventory // the maps were built from
	base  *maps
	byNet map[*netif.Network]*maps
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.Domain == "" || len(s.opts.Domain) > maxDomain {
		return fmt.Errorf("domain %q must be 1 to %d characters", s.opts.Domain, maxDomain)
	}
	if s.opts.ServerName == "" {
		h, _ := os.Hostname()
		s.opts.ServerName, _, _ = strings.Cut(h, ".")
	}
	if len(env.Networks) == 0 {
		return errors.New("no network")
	}
	s.load(env)
	for _, n := range env.Networks {
		defer n.RPC.Register(s.program(env, n))()
		env.Log.Info("listening", "network", n.Name(), "domain", s.opts.Domain)
	}
	<-ctx.Done()
	return nil
}

// load returns the maps for the current inventory, building them again
// after a reload.
func (s *Server) load(env *daemon.Env) *maps {
	inv := env.Inventory()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inv == inv {
		return s.base
	}
	dir := s.opts.Maps
	if dir != "" && !filepath.IsAbs(dir) {
		dir = filepath.Join(inv.Root, dir)
	}
	if dir != "" {
		if _, err := os.Stat(dir); err != nil {
			env.Log.Warn("cannot read maps directory", "err", err)
		}
	}
	ms, warnings := build(dir, inv, uint32(time.Now().Unix()))
	for _, w := range warnings {
		env.Log.Warn("nis map: " + w)
	}
	s.inv, s.base, s.byNet = inv, ms, map[*netif.Network]*maps{}
	env.Log.Info("maps loaded", "domain", s.opts.Domain, "dir", dir, "maps", strings.Join(ms.names(), " "))
	return ms
}

func (s *Server) mapsFor(env *daemon.Env, n *netif.Network) *maps {
	base := s.load(env)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base != base {
		return base.withHost(s.opts.ServerName, n.Addr().Addr()) // reloaded meanwhile
	}
	ms := s.byNet[n]
	if ms == nil {
		ms = base.withHost(s.opts.ServerName, n.Addr().Addr())
		s.byNet[n] = ms
	}
	return ms
}

// request is a call from an allowed client.
type request struct {
	*oncrpc.Call
	host *inventory.Host
	log  *slog.Logger
	maps *maps
}

func (s *Server) program(env *daemon.Env, n *netif.Network) *oncrpc.Program {
	proc := func(name string, fn func(*request) ([]byte, error)) oncrpc.Proc {
		return func(c *oncrpc.Call) ([]byte, error) {
			ip := c.From.Addr()
			log := env.Log.With("network", n.Name(), "client", ip.String())
			h, err := env.Inventory().ByIP(ip)
			if err == nil {
				err = h.Allows(service.NIS)
			}
			if err != nil {
				who := ip.String()
				if h != nil {
					who = h.Name
				}
				log.Info(fmt.Sprintf("nis %s from %s denied (%v)", name, who, err))
				return nil, oncrpc.ErrDrop
			}
			return fn(&request{Call: c, host: h, log: log.With("host", h.Name), maps: s.mapsFor(env, n)})
		}
	}
	return &oncrpc.Program{Prog: Prog, Vers: Vers, TCP: true, Procs: map[uint32]oncrpc.Proc{
		procDomain:       proc("domain", func(r *request) ([]byte, error) { return s.domain(r, false) }),
		procDomainNonack: proc("domain", func(r *request) ([]byte, error) { return s.domain(r, true) }),
		procMatch:        proc("match", s.match),
		procFirst:        proc("first", s.first),
		procNext:         proc("next", s.next),
		procClear:        proc("clear", func(*request) ([]byte, error) { return nil, nil }),
		procAll:          proc("all", s.all),
		procMaster:       proc("master", s.master),
		procOrder:        proc("order", s.order),
		procMaplist:      proc("maplist", s.maplist),
	}}
}

// domain answers whether the domain is served. DOMAIN_NONACK, which
// ypbind broadcasts, gets no answer for other domains.
func (s *Server) domain(r *request, nonack bool) ([]byte, error) {
	d := r.Args.String(maxDomain)
	if r.Args.Err() != nil {
		return nil, oncrpc.ErrGarbageArgs
	}
	ok := d == s.opts.Domain
	switch {
	case !ok && nonack:
		r.log.Info(fmt.Sprintf("nis bind from %s denied (domain %q not served)", r.host.Name, d))
		return nil, oncrpc.ErrDrop
	case nonack:
		r.log.Info(fmt.Sprintf("nis bind from %s: domain %s", r.host.Name, d), "broadcast", r.Broadcast)
	default:
		r.log.Debug("nis domain", "domain", d, "served", ok)
	}
	return (&oncrpc.Encoder{}).Bool(ok).Bytes(), nil
}

// lookup decodes a domain and map name and finds the map.
func (s *Server) lookup(r *request) (*nisMap, string, int32, error) {
	d, name := r.Args.String(maxDomain), r.Args.String(maxMap)
	if r.Args.Err() != nil {
		return nil, name, 0, oncrpc.ErrGarbageArgs
	}
	if d != s.opts.Domain {
		r.log.Info(fmt.Sprintf("nis lookup in %s from %s denied (domain %q not served)", name, r.host.Name, d))
		return nil, name, ypNodom, nil
	}
	m := r.maps.m[name]
	if m == nil {
		r.log.Debug("nis no such map", "map", name)
		return nil, name, ypNomap, nil
	}
	return m, name, ypTrue, nil
}

func (s *Server) match(r *request) ([]byte, error) {
	m, name, stat, err := s.lookup(r)
	key := string(r.Args.Opaque(maxRecord))
	if err != nil || r.Args.Err() != nil {
		return nil, oncrpc.ErrGarbageArgs
	}
	e := &oncrpc.Encoder{}
	if stat != ypTrue {
		return e.Int32(stat).String("").Bytes(), nil
	}
	if key == "" {
		return e.Int32(ypBadargs).String("").Bytes(), nil
	}
	v, ok := m.lookup(key)
	r.log.Debug("nis match", "map", name, "key", key, "found", ok)
	if !ok {
		return e.Int32(ypNokey).String("").Bytes(), nil
	}
	return e.Int32(ypTrue).String(v).Bytes(), nil
}

// keyVal encodes a ypresp_key_val: the value comes before the key.
func keyVal(e *oncrpc.Encoder, stat int32, key, val string) *oncrpc.Encoder {
	return e.Int32(stat).String(val).String(key)
}

func (s *Server) first(r *request) ([]byte, error) {
	m, name, stat, err := s.lookup(r)
	if err != nil {
		return nil, err
	}
	e := &oncrpc.Encoder{}
	switch {
	case stat != ypTrue:
		return keyVal(e, stat, "", "").Bytes(), nil
	case len(m.keys) == 0:
		return keyVal(e, ypNomore, "", "").Bytes(), nil
	}
	r.log.Debug("nis first", "map", name)
	k := m.keys[0]
	return keyVal(e, ypTrue, k, m.vals[k]).Bytes(), nil
}

func (s *Server) next(r *request) ([]byte, error) {
	m, name, stat, err := s.lookup(r)
	prev := string(r.Args.Opaque(maxRecord))
	if err != nil || r.Args.Err() != nil {
		return nil, oncrpc.ErrGarbageArgs
	}
	e := &oncrpc.Encoder{}
	if stat != ypTrue {
		return keyVal(e, stat, "", "").Bytes(), nil
	}
	k, v, stat := m.next(prev)
	r.log.Debug("nis next", "map", name, "key", prev, "stat", stat)
	return keyVal(e, stat, k, v).Bytes(), nil
}

// all sends the whole map as a ypresp_all stream, ending like Sun's
// ypserv with YP_NOMORE and then no more entries.
func (s *Server) all(r *request) ([]byte, error) {
	m, name, stat, err := s.lookup(r)
	if err != nil {
		return nil, err
	}
	e := &oncrpc.Encoder{}
	if stat == ypTrue {
		for _, k := range m.keys {
			keyVal(e.Bool(true), ypTrue, k, m.vals[k])
		}
		stat = ypNomore
		r.log.Info(fmt.Sprintf("nis all %s from %s", name, r.host.Name), "entries", len(m.keys), "tcp", r.TCP)
	}
	return keyVal(e.Bool(true), stat, "", "").Bool(false).Bytes(), nil
}

func (s *Server) master(r *request) ([]byte, error) {
	_, _, stat, err := s.lookup(r)
	if err != nil {
		return nil, err
	}
	master := ""
	if stat == ypTrue {
		master = s.opts.ServerName
	}
	return (&oncrpc.Encoder{}).Int32(stat).String(master).Bytes(), nil
}

func (s *Server) order(r *request) ([]byte, error) {
	_, _, stat, err := s.lookup(r)
	if err != nil {
		return nil, err
	}
	return (&oncrpc.Encoder{}).Int32(stat).Uint32(r.maps.order).Bytes(), nil
}

func (s *Server) maplist(r *request) ([]byte, error) {
	d := r.Args.String(maxDomain)
	if r.Args.Err() != nil {
		return nil, oncrpc.ErrGarbageArgs
	}
	e := &oncrpc.Encoder{}
	if d != s.opts.Domain {
		return e.Int32(ypNodom).Bool(false).Bytes(), nil
	}
	e.Int32(ypTrue)
	for _, name := range r.maps.names() {
		e.Bool(true).String(name)
	}
	return e.Bool(false).Bytes(), nil
}
