package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/link"
)

// freePort returns a UDP port on localhost that is free right now.
func freePort(t *testing.T) netip.AddrPort {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).AddrPort()
}

// TestEndToEnd runs the daemon on a UDP network, attaches a client the way
// an emulator would (simh "attach xq udp:...", QEMU "-netdev dgram"), and
// boots it with RARP and TFTP.
func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	boot := bytes.Repeat([]byte("sparc"), 2000)
	if err := os.WriteFile(filepath.Join(dir, "boot"), boot, 0o644); err != nil {
		t.Fatal(err)
	}
	bootd := freePort(t)
	conf := fmt.Sprintf(`
resolve {
  ethers = ""
  dns    = false
}
log { file = "bootd.log" }
network "lab" {
  address = "192.168.7.1/24"
  udp     = "%s"
}
service "rarp" {}
service "tftp" {}
host "kali" {
  mac = "8:0:20:1:2:3"
  ip  = "192.168.7.5"
  file "boot" { name = "*" }
}
`, bootd)
	path := filepath.Join(dir, "bootd.hcl")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	var stderr bytes.Buffer
	go func() { done <- daemon.Run(ctx, path, nil, &stderr) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("daemon: %v\n%s", err, stderr.String())
		}
		if t.Failed() {
			log, _ := os.ReadFile(filepath.Join(dir, "bootd.log"))
			t.Logf("log:\n%s", log)
		}
	}()

	// The client: a UDP transport pointed at bootd.
	tr, err := link.ListenUDP(netip.MustParseAddrPort("127.0.0.1:0"), []netip.AddrPort{bootd})
	if err != nil {
		t.Fatal(err)
	}
	mac, _ := net.ParseMAC("08:00:20:01:02:03")

	// RARP, read directly from the transport before the IP stack runs.
	rarp := make([]byte, 28)
	binary.BigEndian.PutUint16(rarp[0:], 1)
	binary.BigEndian.PutUint16(rarp[2:], link.TypeIPv4)
	rarp[4], rarp[5] = 6, 4
	binary.BigEndian.PutUint16(rarp[6:], 3)
	copy(rarp[8:], mac)
	copy(rarp[18:], mac)
	var reply link.Frame
	for try := 0; try < 50 && reply.Payload == nil; try++ {
		tr.WriteFrame(link.Build(link.Broadcast, mac, link.TypeRARP, rarp))
		rctx, rcancel := context.WithTimeout(ctx, 100*time.Millisecond)
		for {
			b, err := tr.ReadFrame(rctx)
			if err != nil {
				break
			}
			if f, ok := link.Parse(b); ok && f.Type == link.TypeRARP && binary.BigEndian.Uint16(f.Payload[6:]) == 4 {
				f.Payload = bytes.Clone(f.Payload)
				reply = f
				break
			}
		}
		rcancel()
	}
	if reply.Payload == nil {
		t.Fatal("no RARP reply")
	}
	ip := netip.AddrFrom4([4]byte(reply.Payload[24:28]))
	server := netip.AddrFrom4([4]byte(reply.Payload[14:18]))
	if ip.String() != "192.168.7.5" || server.String() != "192.168.7.1" {
		t.Fatalf("RARP: client %s, server %s", ip, server)
	}

	// TFTP over a client IP stack on the same transport.
	st, err := ipstack.New(tr, mac, netip.PrefixFrom(ip, 24))
	if err != nil {
		t.Fatal(err)
	}
	sctx, scancel := context.WithCancel(ctx)
	defer scancel()
	go st.Run(sctx)
	l, err := st.ListenUDP(1024)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.WriteTo(append([]byte{0, 1}, "C0A80705.SUN4C\x00octet\x00"...), netip.AddrPortFrom(server, 69))
	var got []byte
	for block := uint16(1); ; block++ {
		rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
		d, err := l.Read(rctx)
		rcancel()
		if err != nil {
			t.Fatalf("block %d: %v", block, err)
		}
		if binary.BigEndian.Uint16(d.Data) != 3 || binary.BigEndian.Uint16(d.Data[2:]) != block {
			t.Fatalf("block %d: got %x", block, d.Data[:min(len(d.Data), 20)])
		}
		got = append(got, d.Data[4:]...)
		l.WriteTo([]byte{0, 4, byte(block >> 8), byte(block)}, d.From)
		if len(d.Data)-4 < 512 {
			break
		}
	}
	if !bytes.Equal(got, boot) {
		t.Errorf("got %d bytes, want %d", len(got), len(boot))
	}
}
