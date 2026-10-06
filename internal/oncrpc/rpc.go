package oncrpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"sync"

	"github.com/rpajarola/gobootd/internal/ipstack"
)

// Message constants.
const (
	msgCall    = 0
	msgReply   = 1
	rpcVersion = 2

	replyAccepted = 0
	replyDenied   = 1
	rpcMismatch   = 0
)

// Authentication flavors.
const (
	AuthNone = 0
	AuthUnix = 1
)

// Accept status.
const (
	success      = 0
	progUnavail  = 1
	progMismatch = 2
	procUnavail  = 3
	garbageArgs  = 4
	systemErr    = 5
)

// Well known ports. Every program is served on both; the portmapper
// announces NFSPort for NFS, which many clients assume anyway, and
// PortmapPort for everything else.
const (
	PortmapPort = 111
	NFSPort     = 2049

	PortmapProg = 100000
	NFSProg     = 100003

	protoUDP = 17
)

// Errors a procedure returns instead of results.
var (
	// ErrDrop sends no reply, e.g. to a client that is not allowed.
	ErrDrop = errors.New("no reply")
	// ErrGarbageArgs reports arguments that could not be decoded.
	ErrGarbageArgs = errors.New("garbage arguments")
)

// UnixCred is an AUTH_UNIX credential.
type UnixCred struct {
	Stamp   uint32
	Machine string
	UID     uint32
	GID     uint32
	GIDs    []uint32
}

// Call is a received call.
type Call struct {
	XID              uint32
	Prog, Vers, Proc uint32
	// Cred is the caller's AUTH_UNIX credential, or nil.
	Cred *UnixCred
	Args *Decoder
	From netip.AddrPort
	// Broadcast is set if the call was sent to a broadcast address,
	// directly or through the portmapper's CALLIT. Callers expect no
	// reply to a broadcast call that fails.
	Broadcast bool
	// Indirect is set if the call came through CALLIT.
	Indirect bool
}

// Proc is a procedure. It returns the encoded results, or ErrDrop,
// ErrGarbageArgs or another error (a system error).
type Proc func(c *Call) ([]byte, error)

// Program is one version of an RPC program.
type Program struct {
	Prog, Vers uint32
	// Procs are the procedures; procedure 0 (NULL) is provided.
	Procs map[uint32]Proc
}

// Dispatcher serves the RPC programs registered on one IP stack.
type Dispatcher struct {
	st  *ipstack.Stack
	log *slog.Logger

	mu    sync.Mutex
	progs map[uint32]map[uint32]*Program
}

// NewDispatcher returns a dispatcher for st with the portmapper registered.
func NewDispatcher(st *ipstack.Stack) *Dispatcher {
	d := &Dispatcher{st: st, log: slog.New(slog.DiscardHandler), progs: map[uint32]map[uint32]*Program{}}
	d.Register(d.portmapper())
	return d
}

// SetLogger sets the logger for protocol errors.
func (d *Dispatcher) SetLogger(l *slog.Logger) { d.log = l }

// Register adds a program and returns a function that removes it.
func (d *Dispatcher) Register(p *Program) (unregister func()) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.progs[p.Prog] == nil {
		d.progs[p.Prog] = map[uint32]*Program{}
	}
	d.progs[p.Prog][p.Vers] = p
	return func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		delete(d.progs[p.Prog], p.Vers)
	}
}

// Port returns the port announced for prog.
func Port(prog uint32) uint16 {
	if prog == NFSProg {
		return NFSPort
	}
	return PortmapPort
}

// Run serves calls on the well known ports until ctx is done.
func (d *Dispatcher) Run(ctx context.Context) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	for _, port := range []uint16{PortmapPort, NFSPort} {
		l, err := d.st.ListenUDP(port)
		if err != nil {
			cancel(nil)
			return err
		}
		wg.Go(func() {
			defer l.Close()
			if err := d.serve(ctx, l, &wg); err != nil && ctx.Err() == nil {
				cancel(err)
			}
		})
	}
	<-ctx.Done()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (d *Dispatcher) serve(ctx context.Context, l *ipstack.UDPListener, wg *sync.WaitGroup) error {
	local := d.st.Addr().Addr()
	for {
		dg, err := l.Read(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		wg.Go(func() {
			if reply := d.handle(dg.Data, dg.From, dg.To != local); reply != nil {
				l.WriteTo(reply, dg.From)
			}
		})
	}
}

// handle decodes a call message and returns the reply, or nil.
func (d *Dispatcher) handle(msg []byte, from netip.AddrPort, broadcast bool) []byte {
	dec := NewDecoder(msg)
	xid, mtype := dec.Uint32(), dec.Uint32()
	if dec.Err() != nil || mtype != msgCall {
		return nil
	}
	c := &Call{XID: xid, From: from, Broadcast: broadcast}
	vers := dec.Uint32()
	c.Prog, c.Vers, c.Proc = dec.Uint32(), dec.Uint32(), dec.Uint32()
	credFlavor, cred := dec.Uint32(), dec.Opaque(400)
	dec.Uint32() // verifier
	dec.Opaque(400)
	if dec.Err() != nil {
		return nil
	}
	if vers != rpcVersion {
		if broadcast {
			return nil
		}
		e := header(xid)
		e.Uint32(replyDenied).Uint32(rpcMismatch).Uint32(rpcVersion).Uint32(rpcVersion)
		return e.Bytes()
	}
	if credFlavor == AuthUnix {
		cd := NewDecoder(cred)
		u := &UnixCred{Stamp: cd.Uint32(), Machine: cd.String(255), UID: cd.Uint32(), GID: cd.Uint32()}
		n := cd.Uint32()
		for i := uint32(0); i < n && i < 16; i++ {
			u.GIDs = append(u.GIDs, cd.Uint32())
		}
		if cd.Err() == nil {
			c.Cred = u
		}
	}
	c.Args = NewDecoder(dec.Rest())
	res, stat, low, high := d.call(c)
	if stat != success && broadcast {
		return nil
	}
	if res == nil && stat == success {
		return nil // dropped
	}
	e := accepted(xid, stat)
	switch stat {
	case success:
		e.Raw(res)
	case progMismatch:
		e.Uint32(low).Uint32(high)
	}
	return e.Bytes()
}

// call runs a call and returns the results and accept status. For
// progMismatch it also returns the supported versions. Nil results with
// success mean no reply.
func (d *Dispatcher) call(c *Call) (res []byte, stat, low, high uint32) {
	d.mu.Lock()
	versions := d.progs[c.Prog]
	p := versions[c.Vers]
	if p == nil && len(versions) > 0 {
		low, high = ^uint32(0), 0
		for v := range versions {
			low, high = min(low, v), max(high, v)
		}
	}
	d.mu.Unlock()
	switch {
	case p == nil && len(versions) == 0:
		return nil, progUnavail, 0, 0
	case p == nil:
		return nil, progMismatch, low, high
	case c.Proc == 0:
		return []byte{}, success, 0, 0
	}
	proc := p.Procs[c.Proc]
	if proc == nil {
		return nil, procUnavail, 0, 0
	}
	res, err := proc(c)
	switch {
	case err == nil:
		if res == nil {
			res = []byte{}
		}
		return res, success, 0, 0
	case errors.Is(err, ErrDrop):
		return nil, success, 0, 0
	case errors.Is(err, ErrGarbageArgs):
		return nil, garbageArgs, 0, 0
	default:
		d.log.Warn("rpc call failed", "prog", c.Prog, "vers", c.Vers, "proc", c.Proc, "client", c.From.String(), "err", err)
		return nil, systemErr, 0, 0
	}
}

func header(xid uint32) *Encoder {
	e := &Encoder{}
	return e.Uint32(xid).Uint32(msgReply)
}

func accepted(xid, stat uint32) *Encoder {
	return header(xid).Uint32(replyAccepted).Uint32(AuthNone).Uint32(0).Uint32(stat)
}

// portmapper is version 2 of the portmapper program.
func (d *Dispatcher) portmapper() *Program {
	no := func(c *Call) ([]byte, error) { return (&Encoder{}).Bool(false).Bytes(), nil }
	return &Program{Prog: PortmapProg, Vers: 2, Procs: map[uint32]Proc{
		1: no, // SET: programs cannot be registered from the network
		2: no, // UNSET
		3: d.getport,
		4: d.dump,
		5: d.callit,
	}}
}

func (d *Dispatcher) getport(c *Call) ([]byte, error) {
	prog, vers, prot := c.Args.Uint32(), c.Args.Uint32(), c.Args.Uint32()
	c.Args.Uint32() // port
	if c.Args.Err() != nil {
		return nil, ErrGarbageArgs
	}
	var port uint16
	d.mu.Lock()
	if d.progs[prog][vers] != nil && prot == protoUDP {
		port = Port(prog)
	}
	d.mu.Unlock()
	return (&Encoder{}).Uint32(uint32(port)).Bytes(), nil
}

func (d *Dispatcher) dump(c *Call) ([]byte, error) {
	type mapping struct{ prog, vers uint32 }
	var ms []mapping
	d.mu.Lock()
	for prog, vs := range d.progs {
		for vers := range vs {
			ms = append(ms, mapping{prog, vers})
		}
	}
	d.mu.Unlock()
	sort.Slice(ms, func(i, j int) bool {
		return ms[i].prog < ms[j].prog || ms[i].prog == ms[j].prog && ms[i].vers < ms[j].vers
	})
	e := &Encoder{}
	for _, m := range ms {
		e.Bool(true).Uint32(m.prog).Uint32(m.vers).Uint32(protoUDP).Uint32(uint32(Port(m.prog)))
	}
	return e.Bool(false).Bytes(), nil
}

// callit calls a procedure on behalf of the caller, as clients that
// broadcast to find a server do. Failures are not answered.
func (d *Dispatcher) callit(c *Call) ([]byte, error) {
	ic := &Call{XID: c.XID, Cred: c.Cred, From: c.From, Broadcast: c.Broadcast, Indirect: true}
	ic.Prog, ic.Vers, ic.Proc = c.Args.Uint32(), c.Args.Uint32(), c.Args.Uint32()
	args := c.Args.Opaque(65536)
	if c.Args.Err() != nil {
		return nil, ErrDrop
	}
	if ic.Prog == PortmapProg {
		return nil, ErrDrop // no recursion
	}
	ic.Args = NewDecoder(args)
	res, stat, _, _ := d.call(ic)
	if stat != success || res == nil {
		return nil, ErrDrop
	}
	return (&Encoder{}).Uint32(uint32(Port(ic.Prog))).Opaque(res).Bytes(), nil
}

// String describes a call for logging.
func (c *Call) String() string {
	return fmt.Sprintf("prog %d vers %d proc %d xid %#x from %s", c.Prog, c.Vers, c.Proc, c.XID, c.From)
}
