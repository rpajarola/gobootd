package oncrpc

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

func stack(t *testing.T, seg *linktest.Segment, mac, addr string) *ipstack.Stack {
	t.Helper()
	hw, _ := net.ParseMAC(mac)
	st, err := ipstack.New(seg.Station(mac), hw, netip.MustParsePrefix(addr))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { st.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return st
}

const (
	echoProg = 300000
	server   = "10.0.0.1"
)

// setup runs a dispatcher with an echo program (proc 1 echoes a string,
// proc 2 drops, proc 3 rejects its arguments) and returns a client.
func setup(t *testing.T) *Client {
	seg := linktest.NewSegment()
	srv := stack(t, seg, "02:00:00:00:00:01", server+"/24")
	d := NewDispatcher(srv)
	d.Register(&Program{Prog: echoProg, Vers: 2, Procs: map[uint32]Proc{
		1: func(c *Call) ([]byte, error) {
			s := c.Args.String(100)
			if c.Args.Err() != nil {
				return nil, ErrGarbageArgs
			}
			return (&Encoder{}).String(s).Bool(c.Broadcast).Bool(c.Indirect).Bytes(), nil
		},
		2: func(c *Call) ([]byte, error) { return nil, ErrDrop },
		3: func(c *Call) ([]byte, error) { return nil, errors.New("disk on fire") },
	}})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { d.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	cl := stack(t, seg, "02:00:00:00:00:02", "10.0.0.2/24")
	l, err := cl.ListenUDP(700)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	time.Sleep(20 * time.Millisecond)
	return &Client{L: l, Timeout: 200 * time.Millisecond, Tries: 2}
}

var ctx = context.Background()

func addr(port uint16) netip.AddrPort { return netip.AddrPortFrom(netip.MustParseAddr(server), port) }

func TestCall(t *testing.T) {
	c := setup(t)
	for _, port := range []uint16{PortmapPort, NFSPort} {
		res, _, err := c.Call(ctx, addr(port), echoProg, 2, 1, (&Encoder{}).String("hello").Bytes())
		if err != nil {
			t.Fatalf("port %d: %v", port, err)
		}
		if s, b, i := res.String(100), res.Bool(), res.Bool(); s != "hello" || b || i {
			t.Errorf("port %d: echo %q broadcast %v indirect %v", port, s, b, i)
		}
	}
	// NULL works for every program.
	if _, _, err := c.Call(ctx, addr(PortmapPort), echoProg, 2, 0, nil); err != nil {
		t.Errorf("NULL: %v", err)
	}
}

func TestErrors(t *testing.T) {
	c := setup(t)
	for _, tc := range []struct {
		name             string
		prog, vers, proc uint32
		args             []byte
		want             uint32
	}{
		{"unknown program", 399999, 1, 1, nil, progUnavail},
		{"unknown version", echoProg, 3, 1, nil, progMismatch},
		{"unknown procedure", echoProg, 2, 9, nil, procUnavail},
		{"garbage", echoProg, 2, 1, []byte{0, 0}, garbageArgs},
		{"failure", echoProg, 2, 3, nil, systemErr},
	} {
		_, _, err := c.Call(ctx, addr(PortmapPort), tc.prog, tc.vers, tc.proc, tc.args)
		var re *ReplyError
		if !errors.As(err, &re) || re.Stat != tc.want {
			t.Errorf("%s: %v, want status %d", tc.name, err, tc.want)
		}
	}
	if _, _, err := c.Call(ctx, addr(PortmapPort), echoProg, 2, 2, nil); err == nil || err.Error() != "rpc: no reply" {
		t.Errorf("dropped call: %v", err)
	}
}

func TestPortmapper(t *testing.T) {
	c := setup(t)
	getport := func(prog, vers, prot uint32) uint32 {
		res, _, err := c.Call(ctx, addr(PortmapPort), PortmapProg, 2, 3, (&Encoder{}).Uint32(prog).Uint32(vers).Uint32(prot).Uint32(0).Bytes())
		if err != nil {
			t.Fatal(err)
		}
		return res.Uint32()
	}
	if p := getport(echoProg, 2, protoUDP); p != PortmapPort {
		t.Errorf("GETPORT echo = %d", p)
	}
	if p := getport(echoProg, 1, protoUDP); p != PortmapPort {
		t.Errorf("GETPORT for another version = %d, want the program's port", p)
	}
	if p := getport(399999, 1, protoUDP); p != 0 {
		t.Errorf("GETPORT for an unknown program = %d", p)
	}
	if p := getport(echoProg, 2, 6); p != 0 {
		t.Errorf("GETPORT over TCP = %d", p)
	}

	res, _, err := c.Call(ctx, addr(PortmapPort), PortmapProg, 2, 4, nil)
	if err != nil {
		t.Fatal(err)
	}
	var progs []uint32
	for res.Bool() {
		progs = append(progs, res.Uint32())
		res.Uint32()
		res.Uint32()
		res.Uint32()
	}
	if len(progs) != 2 || progs[0] != PortmapProg || progs[1] != echoProg {
		t.Errorf("DUMP lists %v", progs)
	}
}

func TestCallitBroadcast(t *testing.T) {
	c := setup(t)
	bcast := netip.AddrPortFrom(netip.MustParseAddr("255.255.255.255"), PortmapPort)
	callit := func(prog, vers, proc uint32, args []byte) (*Decoder, error) {
		a := (&Encoder{}).Uint32(prog).Uint32(vers).Uint32(proc).Opaque(args).Bytes()
		res, from, err := c.Call(ctx, bcast, PortmapProg, 2, 5, a)
		if err == nil && from != addr(PortmapPort) {
			t.Errorf("reply from %v", from)
		}
		return res, err
	}
	res, err := callit(echoProg, 2, 1, (&Encoder{}).String("anyone?").Bytes())
	if err != nil {
		t.Fatal(err)
	}
	port, inner := res.Uint32(), NewDecoder(res.Opaque(1000))
	if s, b, i := inner.String(100), inner.Bool(), inner.Bool(); port != PortmapPort || s != "anyone?" || !b || !i {
		t.Errorf("port %d echo %q broadcast %v indirect %v", port, s, b, i)
	}
	// Failures of broadcast calls are not answered.
	for _, tc := range []struct{ prog, vers, proc uint32 }{{399999, 1, 1}, {echoProg, 2, 2}, {echoProg, 2, 9}} {
		if _, err := callit(tc.prog, tc.vers, tc.proc, nil); err == nil {
			t.Errorf("%v: got a reply", tc)
		}
	}
}

func TestXDR(t *testing.T) {
	e := (&Encoder{}).Uint32(7).String("abcde").Opaque([]byte{1}).Bool(true).Uint64(1 << 40)
	if len(e.Bytes())%4 != 0 {
		t.Fatalf("encoded length %d is not a multiple of 4", len(e.Bytes()))
	}
	d := NewDecoder(e.Bytes())
	if d.Uint32() != 7 || d.String(10) != "abcde" || string(d.Opaque(10)) != "\x01" || !d.Bool() || d.Uint64() != 1<<40 || d.Err() != nil {
		t.Error("round trip failed")
	}
	d = NewDecoder((&Encoder{}).String("toolong").Bytes())
	if d.String(3); d.Err() == nil {
		t.Error("accepted a string over its limit")
	}
	if d := NewDecoder([]byte{0, 0, 0, 9, 1}); d.Opaque(100) != nil || d.Err() == nil {
		t.Error("accepted a truncated opaque")
	}
}
