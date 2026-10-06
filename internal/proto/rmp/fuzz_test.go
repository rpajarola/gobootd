package rmp

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// FuzzHandle feeds arbitrary payloads to the RMP handler from the client
// in the trace. Server state (sessions) carries over between inputs.
func FuzzHandle(f *testing.F) {
	for _, step := range trace {
		f.Add(unhexF(step.req))
	}
	f.Add(clientPacket(Packet{Type: ReadReq, Seq: 0xfffffff0, Session: 1, Size: 0xffff}))
	f.Add(clientPacket(Packet{Type: BootDone, Session: 1}))

	dir := f.TempDir()
	os.WriteFile(filepath.Join(dir, "SYSNESTA"), make([]byte, 3000), 0o644)
	e := prototest.Setup(f, dir, lan+nesta)
	s := &Server{}
	env := e.ServiceEnv(f, s, "rmp", &prototest.Log{})
	s.setup()
	f.Cleanup(s.closeAll)
	port := &linktest.Recorder{Info: e.Networks["lan"].Interface()}
	client := mustMAC("08:00:09:21:5b:62")
	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > link.MaxLength {
			return
		}
		s.handle(env, port, link.Build8023(Multicast, client, payload))
		for _, out := range port.Frames() {
			if len(out) > link.MaxFrame {
				t.Fatalf("sent a %d byte frame", len(out))
			}
			if f, ok := link.Parse(out); !ok || f.Type != 0 || string(f.Dst) != string(client) {
				t.Fatalf("sent %x", out)
			}
		}
	})
}

func FuzzParse(f *testing.F) {
	for _, step := range trace {
		f.Add(unhexF(step.req))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p, ok := Parse(b)
		if ok && len(p.Filename) > len(b) {
			t.Fatalf("file name longer than the packet")
		}
	})
}

// unhexF is unhex for fuzz seeds.
func unhexF(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return append([]byte{0xf8, 0xf8, 0x03}, b...)
}
