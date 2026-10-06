package tftp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// lossyGet reads name like a boot PROM on a bad network: it resends its
// last packet when nothing arrives, re-acknowledges old blocks, and
// rejects packets from a second transfer with "unknown transfer ID".
func lossyGet(t *testing.T, l *ipstack.UDPListener, name string) ([]byte, error) {
	rrq := append([]byte{0, opRRQ}, name+"\x00octet\x00"...)
	last, lastTo := rrq, server
	l.WriteTo(rrq, server)
	var data []byte
	var peer netip.AddrPort
	want := uint16(1)
	for timeouts := 0; timeouts < 50; {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		d, err := l.Read(ctx)
		cancel()
		if err != nil {
			timeouts++
			l.WriteTo(last, lastTo)
			continue
		}
		if peer.IsValid() && d.From != peer {
			l.WriteTo(errorPacket(errUnknownID, "unknown transfer ID"), d.From)
			continue
		}
		if len(d.Data) < 4 {
			continue
		}
		switch binary.BigEndian.Uint16(d.Data) {
		case opERROR:
			return nil, fmt.Errorf("error %d: %s", binary.BigEndian.Uint16(d.Data[2:]), d.Data[4:])
		case opDATA:
			peer = d.From
			block := binary.BigEndian.Uint16(d.Data[2:])
			ack := binary.BigEndian.AppendUint16([]byte{0, opACK}, block)
			if block != want {
				// A duplicate or late block: acknowledge it again.
				if block == want-1 {
					l.WriteTo(ack, peer)
				}
				continue
			}
			data = append(data, d.Data[4:]...)
			last, lastTo = ack, peer
			l.WriteTo(ack, peer)
			want++
			if len(d.Data)-4 < defaultBlockSize {
				return data, nil
			}
		}
	}
	return nil, fmt.Errorf("gave up after %d bytes", len(data))
}

func TestLossy(t *testing.T) {
	file := content(100 * 1024)
	for seed := range uint64(3) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "sun4c"), file, 0o644)
			e := prototest.Setup(t, dir, conf)
			e.Segment.Impair(linktest.Impairment{Drop: 0.05, Duplicate: 0.05, Reorder: 0.05, Seed: seed})
			log := e.Start(t, &Server{retransmit: 50 * time.Millisecond}, "tftp")
			st := e.Client(t, "08:00:20:01:02:03", "192.168.1.5/24")
			l, err := st.ListenUDP(1234)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Close()
			got, err := lossyGet(t, l, "C0A80105.SUN4C")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, file) {
				t.Fatalf("got %d bytes, want %d", len(got), len(file))
			}
			if !log.Contains("to kali complete") {
				t.Error("server did not see the transfer complete")
			}
			t.Logf("%+v", e.Segment.Stats())
		})
	}
}
