package rmp

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// The exchange between an HP 425t (NESTA) and FreeBSD's rbootd (AIAX), from
// doc/rmp/rmp-trace.txt in the C bootd. The trace omits the first three LLC
// bytes (f8 f8 03), which are added here. Requests carry stale bytes from
// the client's buffer after the fields that matter.
var trace = []struct{ name, req, repl string }{
	{"server id",
		"000000060806090100000000 00ffff0002 4850533330302020202020202020202020202020 00 00eeee1111",
		"000000060906088100000000 0000000002 04 61696178"},
	{"file name 1",
		"000000060806090100000000 01ffff0002 4850533330302020202020202020202020202020 00 00eeee1111",
		"000000060906088100000000 0100000002 08 5359534e45535441"},
	{"file name 2",
		"000000060806090100000000 02ffff0002 4850533330302020202020202020202020202020 00 00eeee1111",
		"000000060906088112000000 0200000002 00"},
	{"boot request",
		"0000000608060901 00bf73f76e 0000 0002 4850533330302020202020202020202020202020 08 5359534e45535441",
		"0000000609060881 00bf73f76e 0001 0002 08 5359534e45535441"},
	{"read request",
		"0000000608060902 0000000000 0001 0100 4850533330302020202020202020202020202020 08 5359534e45",
		"0000000609060882 0000000000 0001 " + strings.Repeat("ab", 256)},
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return append([]byte{0xf8, 0xf8, 0x03}, b...)
}

type client struct {
	t  *testing.T
	st *linktest.Port
}

func (c client) send(dst string, payload []byte) {
	hw := c.st.Interface().MAC
	dstHW := Multicast
	if dst != "" {
		dstHW = mustMAC(dst)
	}
	c.st.WriteFrame(link.Build8023(dstHW, hw, payload))
}

func (c client) recv() (link.Frame, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for {
		b, err := c.st.ReadFrame(ctx)
		if err != nil {
			return link.Frame{}, false
		}
		if f, ok := link.Parse(b); ok && f.Type == 0 {
			return f, true
		}
	}
}

func mustMAC(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, ":", ""))
	if err != nil {
		panic(err)
	}
	return b
}

func setup(t *testing.T, conf string) (client, *prototest.Log, string) {
	dir := t.TempDir()
	// The boot file is 0xab repeated, so the read reply is predictable.
	if err := os.WriteFile(filepath.Join(dir, "SYSNESTA"), bytes.Repeat([]byte{0xab}, 1000), 0o644); err != nil {
		t.Fatal(err)
	}
	e := prototest.Setup(t, dir, lan+conf)
	log := e.Start(t, &Server{}, "rmp")
	st := e.Segment.Station("08:00:09:21:5b:62")
	return client{t, st}, log, dir
}

const lan = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:a0:c9:00:00:01"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
`

const nesta = `
service "rmp" {
  server_name = "aiax"
}
host "nesta" {
  mac = "08:00:09:21:5b:62"
  file "SYSNESTA" {}
}
`

func TestTrace(t *testing.T) {
	c, log, _ := setup(t, nesta)
	for _, step := range trace {
		c.send("", unhex(t, step.req))
		f, ok := c.recv()
		if !ok {
			t.Fatalf("%s: no reply", step.name)
		}
		if want := unhex(t, step.repl); !bytes.Equal(f.Payload, want) {
			t.Errorf("%s: reply\n%x\nwant\n%x", step.name, f.Payload, want)
		}
		if f.Dst.String() != "08:00:09:21:5b:62" || f.Src.String() != "00:a0:c9:00:00:01" {
			t.Errorf("%s: reply %s -> %s", step.name, f.Src, f.Dst)
		}
	}
	if !log.Contains("rmp boot request from nesta: sending") {
		t.Error("boot not logged")
	}
}

func TestTransfer(t *testing.T) {
	c, log, _ := setup(t, nesta)
	c.send("", unhex(t, trace[3].req))
	f, ok := c.recv()
	if !ok {
		t.Fatal("no boot reply")
	}
	repl, _ := parseReply(f.Payload)
	var got []byte
	for {
		req := Packet{Type: ReadReq, Seq: uint32(len(got)), Session: repl.Session, Size: 1400}
		c.send("00:a0:c9:00:00:01", clientPacket(req))
		f, ok := c.recv()
		if !ok {
			t.Fatal("no read reply")
		}
		r, _ := parseReply(f.Payload)
		if r.RetCode == EOF {
			break
		}
		if r.RetCode != OK || r.Seq != req.Seq {
			t.Fatalf("read reply %v", r)
		}
		got = append(got, r.Data...)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xab}, 1000)) {
		t.Errorf("got %d bytes", len(got))
	}
	c.send("00:a0:c9:00:00:01", clientPacket(Packet{Type: BootDone, Session: repl.Session}))
	if !log.Contains("rmp boot of nesta complete") {
		t.Error("boot done not logged")
	}
	// The session is gone.
	c.send("00:a0:c9:00:00:01", clientPacket(Packet{Type: ReadReq, Session: repl.Session, Size: 10}))
	if f, ok := c.recv(); !ok {
		t.Error("no reply after boot done")
	} else if r, _ := parseReply(f.Payload); r.RetCode != Abort {
		t.Errorf("read after boot done: %v, want abort", r)
	}
}

func TestClassMatch(t *testing.T) {
	c, log, _ := setup(t, `
service "rmp" { server_name = "aiax" }
class "hp300" {
  match = { rmp_machtype = "HPS300" }
  file "SYSNESTA" {}
}
`)
	c.send("", unhex(t, trace[1].req))
	f, ok := c.recv()
	if !ok {
		t.Fatal("no reply")
	}
	if want := unhex(t, trace[1].repl); !bytes.Equal(f.Payload, want) {
		t.Errorf("reply %x, want %x", f.Payload, want)
	}
	if !log.Contains("class=hp300") {
		t.Error("class host not logged")
	}
}

func TestDenied(t *testing.T) {
	c, log, _ := setup(t, `
service "rmp" {}
host "other" {
  mac = "08:00:09:00:00:01"
}
`)
	c.send("", unhex(t, trace[0].req))
	if _, ok := c.recv(); ok {
		t.Error("unknown client got a reply")
	}
	if !log.Contains(`rmp request from 08:00:09:21:5b:62 denied (client unknown, and no class matches rmp_machtype = HPS300)`) {
		t.Error("denial not logged")
	}
	// Frames for another server are ignored.
	c.send("00:00:00:00:00:99", unhex(t, trace[0].req))
	if _, ok := c.recv(); ok {
		t.Error("answered a frame for another server")
	}
}

// clientPacket encodes a request as a client would.
func clientPacket(p Packet) []byte {
	b := p.Marshal()
	b[6], b[7], b[8], b[9] = 0x06, 0x08, 0x06, 0x09
	switch p.Type {
	case ReadReq:
		b = append(b, byte(p.Size>>8), byte(p.Size))
	case BootReq:
		b = b[:hdrLen]
		b = append(b, byte(p.Version>>8), byte(p.Version))
		b = append(b, fmt.Sprintf("%-20s", p.MachType)...)
		b = append(b, byte(len(p.Filename)))
		b = append(b, p.Filename...)
	}
	return b
}

// parseReply parses a reply from the server.
func parseReply(b []byte) (Packet, bool) {
	c := bytes.Clone(b)
	c[6], c[7], c[8], c[9] = 0x06, 0x08, 0x06, 0x09
	p, ok := Parse(c)
	switch p.Type {
	case BootRepl:
		p.Version = uint16(c[18])<<8 | uint16(c[19])
		p.Filename = string(c[21 : 21+int(c[20])])
	case ReadRepl:
		p.Data = c[hdrLen:]
	}
	return p, ok
}

func TestMatch(t *testing.T) {
	src := mustMAC("08:00:09:21:5b:62")
	if !Match(parse(link.Build8023(Multicast, src, unhex(t, trace[0].req)))) {
		t.Error("filter rejects an RMP boot request")
	}
	if Match(parse(link.Build(Multicast, src, link.TypeIPv4, unhex(t, trace[0].req)))) {
		t.Error("filter accepts an Ethernet II frame")
	}
}

func parse(b []byte) link.Frame {
	f, _ := link.Parse(link.Pad(b))
	return f
}
