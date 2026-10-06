package oncrpc

import (
	"net/netip"
	"testing"
)

// FuzzHandle feeds arbitrary datagrams to the dispatcher. Replies must be
// well formed and answer the call's xid; broadcasts only get successes.
func FuzzHandle(f *testing.F) {
	echo := (&Encoder{}).String("x").Bytes()
	f.Add(EncodeCall(1, echoProg, 2, 1, nil, echo), false)
	f.Add(EncodeCall(2, PortmapProg, 2, 5, nil, (&Encoder{}).Uint32(echoProg).Uint32(2).Uint32(1).Opaque(echo).Bytes()), true)
	f.Add(EncodeCall(3, PortmapProg, 2, 4, nil, nil), false)
	f.Add(EncodeCall(4, PortmapProg, 2, 3, nil, (&Encoder{}).Uint32(echoProg).Uint32(2).Uint32(17).Uint32(0).Bytes()), false)

	d := NewDispatcher(nil)
	d.Register(&Program{Prog: echoProg, Vers: 2, Procs: map[uint32]Proc{
		1: func(c *Call) ([]byte, error) {
			s := c.Args.String(100)
			if c.Args.Err() != nil {
				return nil, ErrGarbageArgs
			}
			return (&Encoder{}).String(s).Bytes(), nil
		},
	}})
	from := netip.MustParseAddrPort("10.0.0.2:700")
	f.Fuzz(func(t *testing.T, msg []byte, broadcast bool) {
		reply := d.handle(msg, from, broadcast)
		if reply == nil {
			return
		}
		xid, _, err := DecodeReply(reply)
		if want := NewDecoder(msg).Uint32(); xid != want {
			t.Fatalf("reply xid %#x, call xid %#x", xid, want)
		}
		if broadcast && err != nil {
			t.Fatalf("answered a failed broadcast call: %v", err)
		}
	})
}
