package mop

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const lan = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:a0:c9:00:00:01"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
`

const vax = `
service "mop" {
  server_name = "aiax"
}
host "vax" {
  mac      = "08:00:2b:11:22:33"
  services = ["mop"]
  file "boot.mop" { name = "NETBSD" }
  file "other.mop" { name = "OTHER" }
}
`

var (
	server = mustMAC("00:a0:c9:00:00:01")
	vaxMAC = mustMAC("08:00:2b:11:22:33")
)

func mustMAC(s string) net.HardwareAddr {
	m, err := net.ParseMAC(s)
	if err != nil {
		panic(err)
	}
	return m
}

// program is the boot image: a VAX MOP image of 3000 bytes loaded at
// 0x200000.
func program() (file, body []byte) {
	le := binary.LittleEndian
	h := make([]byte, 512)
	le.PutUint16(h[ihdSize:], 0x30)
	le.PutUint16(h[ihdActivOff:], 0x60)
	h[ihdHdrBlkCnt] = 1
	le.PutUint16(h[ihdAlias:], 0xffff)
	le.PutUint32(h[0x30+isdVPN:], 0x1000)
	le.PutUint32(h[0x60+ihaTfrAdr1:], 0x200010)
	body = make([]byte, 3000)
	for i := range body {
		body[i] = byte(i * 7)
	}
	return append(h, body...), body
}

type client struct {
	t  *testing.T
	st *linktest.Port
	fr framing
}

func setup(t *testing.T, conf string, fr framing) (client, *prototest.Log) {
	dir := t.TempDir()
	file, _ := program()
	if err := os.WriteFile(filepath.Join(dir, "boot.mop"), file, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "other.mop"), []byte("not an image"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := prototest.Setup(t, dir, lan+conf)
	log := e.Start(t, &Server{}, "mop")
	return client{t, e.Segment.Station(vaxMAC.String()), fr}, log
}

func (c client) send(dst net.HardwareAddr, msg []byte) {
	c.st.WriteFrame(wrap(c.fr, dst, c.st.Interface().MAC, msg))
}

func (c client) recv() ([]byte, bool) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	for {
		b, err := c.st.ReadFrame(ctx)
		if err != nil {
			return nil, false
		}
		f, ok := link.Parse(b)
		if !ok {
			continue
		}
		msg, fr, ok := unwrap(f)
		if !ok {
			continue
		}
		if fr != c.fr {
			c.t.Errorf("reply in %v framing, want %v", fr, c.fr)
		}
		if f.Src.String() != server.String() || f.Dst.String() != vaxMAC.String() {
			c.t.Errorf("reply %s -> %s", f.Src, f.Dst)
		}
		return msg, true
	}
}

// rpr builds a program request for name with buffer size bsz.
func rpr(name string, bsz int) []byte {
	m := []byte{codeRPR, 25, 4, 2, byte(len(name))}
	m = append(m, name...)
	m = append(m, 0)
	if bsz > 0 {
		m = append(m, 0x91, 0x01, 2, byte(bsz), byte(bsz>>8))
	}
	return m
}

// load runs a load to the end and returns the image and the transfer
// address.
func (c client) load(name string, bsz int, lose bool) (map[uint32]byte, uint32) {
	c.t.Helper()
	c.send(server, rpr(name, bsz))
	mem := map[uint32]byte{}
	want := byte(0)
	for {
		msg, ok := c.recv()
		if !ok {
			c.t.Fatalf("no reply for load %d", want)
		}
		if msg[1] != want {
			c.t.Fatalf("load number %d, want %d", msg[1], want)
		}
		if lose && want == 1 {
			// Pretend the reply was lost: ask for it again.
			lose = false
			c.send(server, []byte{codeRML, want, 0})
			continue
		}
		switch msg[0] {
		case codeMLD:
			addr := binary.LittleEndian.Uint32(msg[2:])
			if bsz > 0 && len(msg)-6 > bsz {
				c.t.Errorf("load of %d bytes, buffer %d", len(msg)-6, bsz)
			}
			for i, b := range msg[6:] {
				mem[addr+uint32(i)] = b
			}
		case codePLT:
			p := msg[2:]
			for p[0] != pltEnd {
				switch p[0] {
				case pltHSN:
					if string(p[2:2+p[1]]) != "aiax" {
						c.t.Errorf("server name %q", p[2:2+p[1]])
					}
				case pltHSA:
					if !bytes.Equal(p[2:8], server) {
						c.t.Errorf("server address %x", p[2:8])
					}
				}
				p = p[2+p[1]:]
			}
			c.send(server, []byte{codeRML, want + 1, 0})
			return mem, binary.LittleEndian.Uint32(p[1:])
		default:
			c.t.Fatalf("unexpected message %x", msg)
		}
		want++
		c.send(server, []byte{codeRML, want, 0})
	}
}

func checkMem(t *testing.T, mem map[uint32]byte, xfer uint32) {
	t.Helper()
	_, body := program()
	if len(mem) != len(body) {
		t.Errorf("loaded %d bytes, want %d", len(mem), len(body))
	}
	for i, b := range body {
		if mem[0x200000+uint32(i)] != b {
			t.Fatalf("byte %#x differs", 0x200000+i)
		}
	}
	if xfer != 0x200010 {
		t.Errorf("transfer address %#x", xfer)
	}
}

func TestLoad(t *testing.T) {
	for _, fr := range []framing{ether, ieee8023} {
		t.Run(fr.String(), func(t *testing.T) {
			c, log := setup(t, vax, fr)
			// Multicast first: bootd volunteers.
			c.send(Multicast, rpr("NETBSD", 0))
			if msg, ok := c.recv(); !ok || !bytes.Equal(msg, []byte{codeASV}) {
				t.Fatalf("volunteer %x, %v", msg, ok)
			}
			mem, xfer := c.load("NETBSD", 0, false)
			checkMem(t, mem, xfer)
			if !log.Contains("mop load of") || !log.Contains("complete") {
				t.Error("completion not logged")
			}
		})
	}
}

func TestLoadSmallBuffer(t *testing.T) {
	c, _ := setup(t, vax, ether)
	mem, xfer := c.load("", 262, true)
	checkMem(t, mem, xfer)
}

func TestNames(t *testing.T) {
	c, log := setup(t, `
service "mop" {}
host "vax" {
  mac  = "08:00:2b:11:22:33"
  file "boot.mop" { name = "netbsd.sys" }
}
`, ether)
	c.send(Multicast, rpr("NETBSD", 0))
	if _, ok := c.recv(); !ok {
		t.Fatal("NETBSD did not find netbsd.sys")
	}
	c.send(Multicast, rpr("OPENBSD", 0))
	if _, ok := c.recv(); ok {
		t.Error("volunteered for an unknown file")
	}
	if !log.Contains(`file \"OPENBSD\" not configured`) {
		t.Errorf("refusal not logged:\n%s", log)
	}
}

func TestDenied(t *testing.T) {
	c, log := setup(t, vax, ether)
	// Not an image.
	c.send(Multicast, rpr("OTHER", 0))
	if _, ok := c.recv(); ok {
		t.Error("volunteered for a file that is not an image")
	}
	if !log.Contains("not an ELF, a.out or MOP image") {
		t.Errorf("bad image not logged:\n%s", log)
	}
}

func TestUnknownClient(t *testing.T) {
	dir := t.TempDir()
	file, _ := program()
	os.WriteFile(filepath.Join(dir, "boot.mop"), file, 0o644)
	os.WriteFile(filepath.Join(dir, "other.mop"), file, 0o644)
	e := prototest.Setup(t, dir, lan+vax)
	log := e.Start(t, &Server{}, "mop")
	c := client{t, e.Segment.Station("08:00:2b:99:99:99"), ether}
	c.send(Multicast, rpr("NETBSD", 0))
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := c.st.ReadFrame(ctx); err == nil {
		t.Error("answered an unknown client")
	}
	if !log.Contains("mop request from 08:00:2b:99:99:99 denied") {
		t.Errorf("refusal not logged:\n%s", log)
	}
}
