package llc

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

// recorder is a handler that keeps what it receives, and echoes it if
// echo is set.
type recorder struct {
	mu     sync.Mutex
	got    [][]byte
	closed chan struct{}
	echo   bool
}

func newRecorder(echo bool) *recorder { return &recorder{closed: make(chan struct{}), echo: echo} }

func (r *recorder) Receive(l *Link, info []byte) {
	r.mu.Lock()
	r.got = append(r.got, info)
	r.mu.Unlock()
	if r.echo {
		l.Send(info)
	}
}

func (r *recorder) Closed(*Link) { close(r.closed) }

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

func station(t *testing.T, seg *linktest.Segment, mac string, accept func(*Link) Handler) *Station {
	t.Helper()
	p := seg.Station(mac)
	s := &Station{SAP: 0xf0, Port: p, Accept: accept, T1: 50 * time.Millisecond, Log: slog.New(slog.DiscardHandler)}
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

func mac(s string) net.HardwareAddr {
	m, _ := net.ParseMAC(s)
	return m
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for range 500 {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func transfer(t *testing.T, seg *linktest.Segment, n int, lossy bool) {
	t.Helper()
	server := newRecorder(true)
	station(t, seg, "02:00:00:00:00:01", func(*Link) Handler { return server })
	client := newRecorder(false)
	cs := station(t, seg, "02:00:00:00:00:02", nil)
	l, err := cs.Connect(context.Background(), mac("02:00:00:00:00:01"), client)
	if err != nil {
		t.Fatal(err)
	}
	for i := range n {
		if err := l.Send(fmt.Appendf(nil, "frame %d", i)); err != nil {
			t.Fatal(err)
		}
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "the echoes", func() bool { return client.count() == n })
	for i, b := range client.got {
		if want := fmt.Sprintf("frame %d", i); string(b) != want {
			t.Fatalf("frame %d is %q", i, b)
		}
	}
	if server.count() != n {
		t.Errorf("server got %d frames, want %d", server.count(), n)
	}
	l.Disconnect()
	if lossy {
		return // the DISC may be lost
	}
	select {
	case <-server.closed:
	case <-time.After(5 * time.Second):
		t.Error("server link not closed by DISC")
	}
}

func TestTransfer(t *testing.T) {
	// More than the sequence space, to wrap around.
	transfer(t, linktest.NewSegment(), 300, false)
}

func TestLossyTransfer(t *testing.T) {
	seg := linktest.NewSegment()
	seg.Impair(linktest.Impairment{Drop: 0.1, Duplicate: 0.05, Reorder: 0.05, Seed: 1})
	transfer(t, seg, 300, true)
	t.Logf("%+v", seg.Stats())
}

func TestRefused(t *testing.T) {
	seg := linktest.NewSegment()
	station(t, seg, "02:00:00:00:00:01", func(*Link) Handler { return nil })
	p := seg.Station("02:00:00:00:00:02")
	p.WriteFrame(link.Build8023(mac("02:00:00:00:00:01"), mac("02:00:00:00:00:02"), []byte{0xf0, 0xf0, ctlSABME | pfU}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	f, err := p.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lf, _ := link.Parse(f); !bytes.Equal(lf.Payload, []byte{0xf0, 0xf1, ctlDM | pfU}) {
		t.Errorf("answer % x, want DM", lf.Payload)
	}
}

func TestXIDAndTest(t *testing.T) {
	seg := linktest.NewSegment()
	station(t, seg, "02:00:00:00:00:01", nil)
	p := seg.Station("02:00:00:00:00:02")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	for _, tc := range []struct{ req, want []byte }{
		{[]byte{0xf0, 0xf0, ctlXID | pfU, 0x81, 0x01, 0x00}, []byte{0xf0, 0xf1, ctlXID | pfU, 0x81, 0x03, window << 1}},
		{[]byte{0xf0, 0xf0, ctlTEST | pfU, 'h', 'i'}, []byte{0xf0, 0xf1, ctlTEST | pfU, 'h', 'i'}},
		{[]byte{0xf0, 0xf0, 0x00, 0x00}, []byte{0xf0, 0xf1, ctlDM | pfU}}, // I frame without a link, no poll: nothing
	} {
		if tc.req[2] == 0 {
			// With the poll bit, a frame without a link gets DM.
			tc.req[3] = 1
		}
		p.WriteFrame(link.Build8023(mac("02:00:00:00:00:01"), mac("02:00:00:00:00:02"), tc.req))
		f, err := p.ReadFrame(ctx)
		if err != nil {
			t.Fatal(err)
		}
		lf, _ := link.Parse(f)
		if !bytes.Equal(lf.Payload, tc.want) {
			t.Errorf("answer to % x: % x, want % x", tc.req, lf.Payload, tc.want)
		}
	}
}

// TestLinkLost: a link whose frames are never acknowledged is given up
// after maxRetries polls.
func TestLinkLost(t *testing.T) {
	seg := linktest.NewSegment()
	server := newRecorder(false)
	links := make(chan *Link, 1)
	station(t, seg, "02:00:00:00:00:01", func(l *Link) Handler { links <- l; return server })
	p := seg.Station("02:00:00:00:00:02")
	p.WriteFrame(link.Build8023(mac("02:00:00:00:00:01"), mac("02:00:00:00:00:02"), []byte{0xf0, 0xf0, ctlSABME | pfU}))
	l := <-links
	start := time.Now()
	l.Send([]byte("hello"))
	select {
	case <-server.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("link not given up")
	}
	if d := time.Since(start); d < maxRetries*50*time.Millisecond {
		t.Errorf("given up after %v", d)
	}
	if err := l.Send([]byte("again")); err != ErrClosed {
		t.Errorf("send on a lost link: %v", err)
	}
}
