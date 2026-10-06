package rmp

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// exchange sends req until a reply of type typ with the same sequence
// number arrives, like a boot ROM on a bad network.
func (c client) exchange(dst string, req Packet, typ uint8) (Packet, error) {
	for try := 0; try < 50; try++ {
		c.send(dst, clientPacket(req))
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		for {
			b, err := c.st.ReadFrame(ctx)
			if err != nil {
				break
			}
			f, ok := link.Parse(b)
			if !ok || f.Type != 0 {
				continue
			}
			if r, ok := parseReply(f.Payload); ok && r.Type == typ && r.Seq == req.Seq {
				cancel()
				return r, nil
			}
		}
		cancel()
	}
	return Packet{}, fmt.Errorf("no reply to %v", req)
}

func TestLossy(t *testing.T) {
	file := content(50 * 1024)
	for seed := range uint64(3) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "SYSNESTA"), file, 0o644)
			e := prototest.Setup(t, dir, lan+nesta)
			e.Segment.Impair(linktest.Impairment{Drop: 0.05, Duplicate: 0.05, Reorder: 0.05, Seed: seed})
			log := e.Start(t, &Server{}, "rmp")
			c := client{t, e.Segment.Station("08:00:09:21:5b:62")}
			const server = "00:a0:c9:00:00:01"

			boot := Packet{Type: BootReq, Seq: 0xbf73f76e, Version: version, MachType: "HPS300", Filename: "SYSNESTA"}
			r, err := c.exchange("", boot, BootRepl)
			if err != nil || r.RetCode != OK {
				t.Fatalf("boot reply %v, %v", r, err)
			}
			var got []byte
			for {
				r, err := c.exchange(server, Packet{Type: ReadReq, Seq: uint32(len(got)), Session: r.Session, Size: 1024}, ReadRepl)
				if err != nil {
					t.Fatal(err)
				}
				if r.RetCode == EOF {
					break
				}
				if r.RetCode != OK {
					t.Fatalf("read at %d: %v", len(got), r)
				}
				got = append(got, r.Data...)
			}
			if !bytes.Equal(got, file) {
				t.Fatalf("got %d bytes, want %d", len(got), len(file))
			}
			// Boot done is not acknowledged; a lost one leaves a session
			// that times out. Send it until the server saw it.
			for range 5 {
				c.send(server, clientPacket(Packet{Type: BootDone, Session: r.Session}))
			}
			if !log.Contains("rmp boot of nesta complete") {
				t.Error("boot done not seen")
			}
			t.Logf("%+v", e.Segment.Stats())
		})
	}
}

func content(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

// TestRepeatedBootRequest: a client that did not get the boot reply sends
// the request again. Both replies must name the same session, so whichever
// one arrives, the reads work.
func TestRepeatedBootRequest(t *testing.T) {
	c, _, _ := setup(t, nesta)
	boot := clientPacket(Packet{Type: BootReq, Seq: 0x1234, Version: version, MachType: "HPS300", Filename: "SYSNESTA"})
	var sessions []uint16
	for range 2 {
		c.send("", boot)
		f, ok := c.recv()
		if !ok {
			t.Fatal("no boot reply")
		}
		r, _ := parseReply(f.Payload)
		sessions = append(sessions, r.Session)
	}
	if sessions[0] != sessions[1] {
		t.Errorf("sessions %v, want the same session twice", sessions)
	}
	c.send("00:a0:c9:00:00:01", clientPacket(Packet{Type: ReadReq, Session: sessions[0], Size: 10}))
	if f, ok := c.recv(); !ok {
		t.Fatal("no read reply")
	} else if r, _ := parseReply(f.Payload); r.RetCode != OK {
		t.Errorf("read with the first session: %v", r)
	}
	// A new boot request (another sequence number) starts over.
	c.send("", clientPacket(Packet{Type: BootReq, Seq: 0x5678, Version: version, MachType: "HPS300", Filename: "SYSNESTA"}))
	if f, ok := c.recv(); !ok {
		t.Fatal("no boot reply")
	} else if r, _ := parseReply(f.Payload); r.Session == sessions[0] {
		t.Error("a new boot request kept the old session")
	}
}
