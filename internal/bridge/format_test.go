package bridge

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/nd"
	"github.com/rpajarola/gobootd/internal/proto/rarp"
	"github.com/rpajarola/gobootd/internal/proto/rmp"
)

func buildIPv4UDP(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, payload []byte) []byte {
	udpLen := 8 + len(payload)
	totalLen := 20 + udpLen
	b := make([]byte, totalLen)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	b[8] = 64
	b[9] = 17 // UDP
	s4, d4 := srcIP.As4(), dstIP.As4()
	copy(b[12:16], s4[:])
	copy(b[16:20], d4[:])
	binary.BigEndian.PutUint16(b[20:22], srcPort)
	binary.BigEndian.PutUint16(b[22:24], dstPort)
	binary.BigEndian.PutUint16(b[24:26], uint16(udpLen))
	copy(b[28:], payload)
	return b
}

func buildRPCCall(xid, prog, vers, proc uint32, args []byte) []byte {
	e := &oncrpc.Encoder{}
	e.Uint32(xid).Uint32(0).Uint32(2)
	e.Uint32(prog).Uint32(vers).Uint32(proc)
	e.Uint32(0).Opaque(nil) // AUTH_NONE cred
	e.Uint32(0).Opaque(nil) // AUTH_NONE verf
	e.Raw(args)
	return e.Bytes()
}

func TestFormatPacket(t *testing.T) {
	ts := time.Date(2026, 10, 20, 1, 27, 41, 540_000_000, time.UTC)
	srcMAC := mac("08:00:2b:45:2b:2f")
	dstMAC := mac("02:00:00:00:00:01")
	srcIP := netip.MustParseAddr("10.3.0.1")
	dstIP := netip.MustParseAddr("10.3.0.99")

	t.Run("ARP Request", func(t *testing.T) {
		arp := (&rarp.Packet{
			Op:       1,
			SenderHW: srcMAC,
			SenderIP: srcIP,
			TargetHW: mac("00:00:00:00:00:00"),
			TargetIP: dstIP,
		}).Marshal()
		frame := link.Build(link.Broadcast, srcMAC, link.TypeARP, arp)
		got := FormatPacket(ts, "en0 -> udp", frame)
		want := "01:27:41.54 [en0 -> udp] 08:00:2b:45:2b:2f > ff:ff:ff:ff:ff:ff ARP Request who-has 10.3.0.99 tell 10.3.0.1"
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})

	t.Run("ARP Reply", func(t *testing.T) {
		arp := (&rarp.Packet{
			Op:       2,
			SenderHW: dstMAC,
			SenderIP: dstIP,
			TargetHW: srcMAC,
			TargetIP: srcIP,
		}).Marshal()
		frame := link.Build(srcMAC, dstMAC, link.TypeARP, arp)
		got := FormatPacket(ts, "", frame)
		want := "01:27:41.54 02:00:00:00:00:01 > 08:00:2b:45:2b:2f ARP Reply 10.3.0.99 is-at 02:00:00:00:00:01"
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})

	t.Run("RARP Request and Reply", func(t *testing.T) {
		req := (&rarp.Packet{
			Op:       rarp.OpRequest,
			SenderHW: srcMAC,
			TargetHW: srcMAC,
		}).Marshal()
		gotReq := FormatPacket(ts, "en0 -> udp", link.Build(link.Broadcast, srcMAC, link.TypeRARP, req))
		wantReq := "01:27:41.54 [en0 -> udp] 08:00:2b:45:2b:2f > ff:ff:ff:ff:ff:ff RARP Request who-is 08:00:2b:45:2b:2f tell 08:00:2b:45:2b:2f"
		if gotReq != wantReq {
			t.Errorf("got  %q\nwant %q", gotReq, wantReq)
		}

		repl := (&rarp.Packet{
			Op:       rarp.OpReply,
			SenderHW: dstMAC,
			SenderIP: srcIP,
			TargetHW: srcMAC,
			TargetIP: dstIP,
		}).Marshal()
		gotRepl := FormatPacket(ts, "udp -> en0", link.Build(srcMAC, dstMAC, link.TypeRARP, repl))
		wantRepl := "01:27:41.54 [udp -> en0] 02:00:00:00:00:01 > 08:00:2b:45:2b:2f RARP Reply 08:00:2b:45:2b:2f at 10.3.0.99"
		if gotRepl != wantRepl {
			t.Errorf("got  %q\nwant %q", gotRepl, wantRepl)
		}
	})

	t.Run("RMP", func(t *testing.T) {
		repl := rmp.Packet{
			Type:     rmp.BootRepl,
			RetCode:  rmp.OK,
			Seq:      0x123,
			Session:  1,
			Version:  2,
			Filename: "SYS_UBOOT",
		}.Marshal()
		frame := link.Build8023(srcMAC, dstMAC, repl)
		got := FormatPacket(ts, "udp -> en0", frame)
		if !strings.Contains(got, "RMP boot reply ok seq 0x123 session 1 version 2 name \"SYS_UBOOT\"") {
			t.Errorf("unexpected RMP output: %q", got)
		}
	})

	t.Run("ND", func(t *testing.T) {
		ndPkt := make([]byte, 28)
		ndPkt[0] = nd.OpRead | nd.FlagWait | nd.FlagDone
		ndPkt[1] = 0x40
		binary.BigEndian.PutUint32(ndPkt[4:8], 1)     // seq
		binary.BigEndian.PutUint32(ndPkt[8:12], 16)   // block
		binary.BigEndian.PutUint32(ndPkt[12:16], 512) // count
		binary.BigEndian.PutUint32(ndPkt[24:28], 512) // pktCount

		ip := make([]byte, 20+len(ndPkt))
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
		ip[9] = nd.IPProto
		s4, d4 := srcIP.As4(), dstIP.As4()
		copy(ip[12:16], s4[:])
		copy(ip[16:20], d4[:])
		copy(ip[20:], ndPkt)

		got := FormatPacket(ts, "en0 -> udp", link.Build(dstMAC, srcMAC, link.TypeIPv4, ip))
		want := "01:27:41.54 [en0 -> udp] 08:00:2b:45:2b:2f > 02:00:00:00:00:01 IP 10.3.0.1 > 10.3.0.99: ND Read[wait,done] minor 0x40 seq 1 block 16 offset 0 count 512 len 512"
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})

	t.Run("TFTP", func(t *testing.T) {
		rrq := []byte("\x00\x01C0A80101.SUN4C\x00octet\x00blksize\x001468\x00")
		ip := buildIPv4UDP(dstIP, srcIP, 4000, 69, rrq)
		got := FormatPacket(ts, "en0 -> udp", link.Build(dstMAC, srcMAC, link.TypeIPv4, ip))
		want := `01:27:41.54 [en0 -> udp] 08:00:2b:45:2b:2f > 02:00:00:00:00:01 IP 10.3.0.99.4000 > 10.3.0.1.69: TFTP Read "C0A80101.SUN4C" (octet, blksize=1468)`
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}

		dataPkt := []byte{0, 3, 0, 1, 'a', 'b', 'c', 'd'}
		ipData := buildIPv4UDP(srcIP, dstIP, 50000, 4000, dataPkt)
		gotData := FormatPacket(ts, "udp -> en0", link.Build(srcMAC, dstMAC, link.TypeIPv4, ipData))
		wantData := "01:27:41.54 [udp -> en0] 02:00:00:00:00:01 > 08:00:2b:45:2b:2f IP 10.3.0.1.50000 > 10.3.0.99.4000: TFTP Data block 1 (4 bytes)"
		if gotData != wantData {
			t.Errorf("got  %q\nwant %q", gotData, wantData)
		}
	})

	t.Run("ONC RPC Portmap CALLIT Bootparam WHOAMI", func(t *testing.T) {
		bpArgs := (&oncrpc.Encoder{}).Uint32(1).Uint32(10).Uint32(3).Uint32(0).Uint32(99).Bytes()
		callitArgs := (&oncrpc.Encoder{}).Uint32(100026).Uint32(1).Uint32(1).Opaque(bpArgs).Bytes()
		rpc := buildRPCCall(0xdeadbeef, oncrpc.PortmapProg, 2, 5, callitArgs)
		ip := buildIPv4UDP(dstIP, netip.MustParseAddr("255.255.255.255"), 1023, 111, rpc)
		got := FormatPacket(ts, "en0 -> udp", link.Build(link.Broadcast, srcMAC, link.TypeIPv4, ip))
		want := "01:27:41.54 [en0 -> udp] 08:00:2b:45:2b:2f > ff:ff:ff:ff:ff:ff IP 10.3.0.99.1023 > 255.255.255.255.111: RPC Call xid 0xdeadbeef portmap CALLIT bootparam WHOAMI 10.3.0.99"
		if got != want {
			t.Errorf("got  %q\nwant %q", got, want)
		}
	})

	t.Run("ONC RPC Mount and NFS and NIS", func(t *testing.T) {
		mntArgs := (&oncrpc.Encoder{}).String("/export/root/sun3").Bytes()
		mntCall := buildRPCCall(0x11, 100005, 1, 1, mntArgs)
		gotMnt := FormatPacket(ts, "en0 -> udp", link.Build(dstMAC, srcMAC, link.TypeIPv4, buildIPv4UDP(dstIP, srcIP, 800, 111, mntCall)))
		if !strings.Contains(gotMnt, `RPC Call xid 0x11 mount v1 MNT "/export/root/sun3"`) {
			t.Errorf("unexpected mount output: %q", gotMnt)
		}

		fh := make([]byte, 32)
		nfsArgs := (&oncrpc.Encoder{}).Fixed(fh).String("vmunix").Bytes()
		nfsCall := buildRPCCall(0x22, oncrpc.NFSProg, 2, 4, nfsArgs)
		gotNFS := FormatPacket(ts, "en0 -> udp", link.Build(dstMAC, srcMAC, link.TypeIPv4, buildIPv4UDP(dstIP, srcIP, 800, 2049, nfsCall)))
		if !strings.Contains(gotNFS, `RPC Call xid 0x22 nfs LOOKUP "vmunix"`) {
			t.Errorf("unexpected nfs output: %q", gotNFS)
		}

		nisArgs := (&oncrpc.Encoder{}).String("test.dom").String("hosts.byname").Opaque([]byte("sun3")).Bytes()
		nisCall := buildRPCCall(0x33, 100004, 2, 3, nisArgs)
		gotNIS := FormatPacket(ts, "en0 -> udp", link.Build(dstMAC, srcMAC, link.TypeIPv4, buildIPv4UDP(dstIP, srcIP, 800, 111, nisCall)))
		if !strings.Contains(gotNIS, `RPC Call xid 0x33 nis MATCH test.dom hosts.byname "sun3"`) {
			t.Errorf("unexpected nis output: %q", gotNIS)
		}
	})
}
