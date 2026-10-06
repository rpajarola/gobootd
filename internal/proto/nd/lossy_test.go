package nd

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

// lossyRead reads like a Sun-2 PROM on a bad network: it takes packets in
// order only, and asks again from where it is when a window ends with a
// gap or nothing arrives.
func lossyRead(t *testing.T, st *linktest.Port, block, count int32) []byte {
	t.Helper()
	zero := netip.IPv4Unspecified()
	var got []byte
	for tries := 0; tries < 200; tries++ {
		send(st, zero, zero, Packet{Op: OpRead, Minor: MinorPublic, Seq: 7, Block: block, Count: count, Offset: int32(len(got))})
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		for {
			b, err := st.ReadFrame(ctx)
			if err != nil {
				break
			}
			f, _ := link.Parse(b)
			ip, ok := parseIPv4(f.Payload)
			if !ok || ip.proto != IPProto {
				continue
			}
			p, ok := parsePacket(ip.payload)
			if !ok || p.Seq != 7 || p.Block != block || p.Offset != int32(len(got)) {
				continue // duplicate, reordered, or from an earlier request
			}
			got = append(got, p.Data...)
			if p.Op&FlagDone != 0 {
				cancel()
				return got
			}
			if p.Op&FlagWait != 0 {
				break
			}
		}
		cancel()
	}
	t.Fatalf("gave up after %d of %d bytes", len(got), count)
	return nil
}

func TestLossy(t *testing.T) {
	for seed := range uint64(3) {
		t.Run(fmt.Sprint("seed", seed), func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "bootyy"), boot1, 0o644)
			os.WriteFile(filepath.Join(dir, "netboot"), boot2, 0o644)
			e := prototest.Setup(t, dir, conf)
			e.Segment.Impair(linktest.Impairment{Drop: 0.1, Duplicate: 0.1, Reorder: 0.1, Seed: seed})
			e.Start(t, &Server{}, "nd")
			st := e.Segment.Station("8:0:20:0:0:1")
			if got := lossyRead(t, st, 0, int32(len(disk))); !bytes.Equal(got, disk) {
				t.Errorf("got %d bytes that differ from the disk", len(got))
			}
			// A large read of the second stage: 60 packets.
			want := make([]byte, 60*1024)
			copy(want, boot2)
			if got := lossyRead(t, st, 16, int32(len(want))); !bytes.Equal(got, want) {
				t.Errorf("got %d bytes that differ from the second stage", len(got))
			}
			t.Logf("%+v", e.Segment.Stats())
		})
	}
}
