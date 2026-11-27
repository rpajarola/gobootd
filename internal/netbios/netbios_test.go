package netbios

import (
	"bytes"
	"context"
	"encoding/hex"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/llc"
)

func TestNameEncoding(t *testing.T) {
	n := MakeName("bootd", Server)
	if n.String() != "BOOTD<20>" {
		t.Errorf("name %s", n)
	}
	enc := n.encode()
	// RFC 1001 14.1: "FRED" encodes to EGFCEFEECACACACACACACACACACACACA.
	if got := string(MakeName("FRED", ' ').encode()[1:33]); got != "EGFCEFEECACACACACACACACACACACACA" {
		t.Errorf("FRED encodes to %s", got)
	}
	d, l, err := decodeName(enc)
	if err != nil || d != n || l != 34 {
		t.Errorf("decoded %v, %d, %v", d, l, err)
	}
	if _, _, err := decodeName(enc[:20]); err == nil {
		t.Error("short name decoded")
	}
}

func TestQuery(t *testing.T) {
	q, ok := ParseQuery(EncodeQuery(0x1234, MakeName("BOOTD", Server), false, true))
	if !ok || q.ID != 0x1234 || q.Name != MakeName("BOOTD", Server) || q.Status || !q.Broadcast {
		t.Fatalf("query %+v, %v", q, ok)
	}
	ans := q.Answer(netip.MustParseAddr("192.168.1.1"))
	want := "12348500000000010000000020" + hex.EncodeToString(q.qname[1:]) + "0020000100" + "00012c0006" + "0000c0a80101"
	if got := hex.EncodeToString(ans); got != want {
		t.Errorf("answer\n%s\nwant\n%s", got, want)
	}
	q, ok = ParseQuery(EncodeQuery(1, Wildcard, true, false))
	if !ok || !q.Status || q.Name != Wildcard {
		t.Fatalf("status query %+v, %v", q, ok)
	}
	st := q.StatusAnswer([]Entry{{MakeName("BOOTD", Server), false}, {MakeName("WORKGROUP", Workstation), true}}, net.HardwareAddr{2, 0, 0, 0, 0, 1})
	// header, name, type, class, TTL, length, count, 2 names, stats
	if len(st) != 12+34+2+2+4+2+1+2*18+46 || st[len(st)-46-1-36] != 2 {
		t.Errorf("status answer %x", st)
	}
	// Responses and registrations are not queries.
	resp := EncodeQuery(1, Wildcard, false, false)
	resp[2] |= 0x80
	if _, ok := ParseQuery(resp); ok {
		t.Error("response parsed as a query")
	}
}

func TestNBTSession(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	server := MakeName("BOOTD", Server)
	done := make(chan error, 1)
	go func() {
		c, called, calling, err := AcceptNBT(b, func(called, calling Name) byte {
			if !called.Equal(server) {
				return CalledNotPresent
			}
			return 0
		})
		if err == nil && (called != server || calling.Base() != "PC") {
			t.Errorf("names %s %s", called, calling)
		}
		if err == nil {
			msg, err := c.ReadMessage(context.Background())
			if err == nil {
				err = c.WriteMessage(context.Background(), append([]byte("re: "), msg...))
			}
		}
		done <- err
	}()
	c, err := DialNBT(a, server, MakeName("pc", Workstation))
	if err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("x"), 70000) // needs the 17th length bit
	if err := c.WriteMessage(context.Background(), big); err != nil {
		t.Fatal(err)
	}
	got, err := c.ReadMessage(context.Background())
	if err != nil || !bytes.Equal(got, append([]byte("re: "), big...)) {
		t.Errorf("reply %d bytes, %v", len(got), err)
	}
	if err := <-done; err != nil {
		t.Error(err)
	}
}

func TestNBTRefused(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go AcceptNBT(b, func(called, calling Name) byte { return NotListeningForCaller })
	if _, err := DialNBT(a, MakeName("X", Server), MakeName("PC", 0)); err == nil {
		t.Error("session accepted")
	}
}

func station(t *testing.T, seg *linktest.Segment, mac string) *llc.Station {
	t.Helper()
	p := seg.Station(mac)
	s := &llc.Station{SAP: SAP, Port: p, T1: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			f, err := p.ReadFrame(ctx)
			if err != nil {
				return
			}
			s.Handle(f)
		}
	})
	wg.Go(func() { s.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	return s
}

func nbfPair(t *testing.T, seg *linktest.Segment, check func(net.HardwareAddr, Name, Name) bool) (*NBF, *NBF, chan *NBFSession) {
	accepted := make(chan *NBFSession, 4)
	srv := &NBF{Station: station(t, seg, "02:00:00:00:00:01"), Names: []Name{MakeName("BOOTD", Server)},
		Check: check, Accept: func(s *NBFSession) { accepted <- s }}
	srv.Init()
	cli := &NBF{Station: station(t, seg, "02:00:00:00:00:02")}
	cli.Init()
	return srv, cli, accepted
}

func testNBF(t *testing.T, seg *linktest.Segment) {
	_, cli, accepted := nbfPair(t, seg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c, err := cli.Dial(ctx, MakeName("bootd", Server), MakeName("PC", Workstation))
	if err != nil {
		t.Fatal(err)
	}
	var s *NBFSession
	select {
	case s = <-accepted:
	case <-ctx.Done():
		t.Fatal("no session")
	}
	if s.Calling.Base() != "PC" || s.Remote().String() != "02:00:00:00:00:02" {
		t.Errorf("session from %s at %s", s.Calling, s.Remote())
	}
	for _, size := range []int{0, 10, maxData, maxData + 1, 20000} {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		if err := c.WriteMessage(ctx, msg); err != nil {
			t.Fatal(err)
		}
		got, err := s.ReadMessage(ctx)
		if err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%d bytes: got %d, %v", size, len(got), err)
		}
		if err := s.WriteMessage(ctx, msg); err != nil {
			t.Fatal(err)
		}
		if got, err = c.ReadMessage(ctx); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("%d bytes back: got %d, %v", size, len(got), err)
		}
	}
	c.Close()
	if _, err := s.ReadMessage(ctx); err == nil {
		t.Error("session still open after SESSION_END")
	}
}

func TestNBF(t *testing.T) { testNBF(t, linktest.NewSegment()) }

func TestNBFLossy(t *testing.T) {
	seg := linktest.NewSegment()
	seg.Impair(linktest.Impairment{Drop: 0.05, Reorder: 0.05, Duplicate: 0.02, Seed: 3})
	testNBF(t, seg)
}

func TestNBFRefused(t *testing.T) {
	_, cli, _ := nbfPair(t, linktest.NewSegment(), func(net.HardwareAddr, Name, Name) bool { return false })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cli.Dial(ctx, MakeName("BOOTD", Server), MakeName("PC", 0)); err == nil {
		t.Error("refused client got a session")
	}
	if _, err := cli.Dial(ctx, MakeName("OTHER", Server), MakeName("PC", 0)); err == nil {
		t.Error("session with a name nobody has")
	}
}
