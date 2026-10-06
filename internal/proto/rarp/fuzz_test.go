package rarp

import (
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
	"github.com/rpajarola/gobootd/internal/resolve"
)

// FuzzHandle feeds arbitrary frames to the RARP handler: it must not
// panic, and may only answer known hosts.
func FuzzHandle(f *testing.F) {
	hw, _ := resolve.ParseMAC("8:0:20:1:2:3")
	req := Packet{Op: OpRequest, SenderHW: hw, TargetHW: hw}
	f.Add(link.Build(link.Broadcast, hw, link.TypeRARP, req.Marshal()))
	f.Add(link.Build(link.Broadcast, hw, link.TypeRARP, []byte{0, 1, 8, 0, 6, 4, 0, 3}))

	e := prototest.Setup(f, f.TempDir(), conf)
	s := &Server{}
	env := e.ServiceEnv(f, s, "rarp", &prototest.Log{})
	port := &linktest.Recorder{Info: e.Networks["lan"].Interface()}
	f.Fuzz(func(t *testing.T, frame []byte) {
		s.handle(env, port, frame)
		for _, out := range port.Frames() {
			f, _ := link.Parse(out)
			p, ok := Parse(f.Payload)
			if !ok || p.Op != OpReply {
				t.Fatalf("sent %x", out)
			}
			if h, err := e.Inventory.ByMAC(p.TargetHW); err != nil || h.IP != p.TargetIP {
				t.Fatalf("answered %v", p)
			}
		}
	})
}
