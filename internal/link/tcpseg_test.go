package link

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// tcpTestFrame returns an Ethernet frame with a TCP segment over IPv4 or
// IPv6, its TCP checksum left as GRO leaves it (not valid for the packet).
func tcpTestFrame(v6 bool, seq uint32, flags byte, opts, payload []byte) []byte {
	th := make([]byte, 20, 20+len(opts))
	binary.BigEndian.PutUint16(th[0:2], 1021)
	binary.BigEndian.PutUint16(th[2:4], 512)
	binary.BigEndian.PutUint32(th[4:8], seq)
	binary.BigEndian.PutUint32(th[8:12], 777)
	th[12] = byte((20+len(opts))/4) << 4
	th[13] = flags
	binary.BigEndian.PutUint16(th[14:16], 4096)
	th[16], th[17] = 0xde, 0xad
	th = append(th, opts...)

	var ip []byte
	typ := uint16(TypeIPv4)
	if v6 {
		typ = TypeIPv6
		ip = make([]byte, 40)
		ip[0] = 0x60
		binary.BigEndian.PutUint16(ip[4:6], uint16(len(th)+len(payload)))
		ip[6], ip[7] = 6, 64
		copy(ip[8:24], netip.MustParseAddr("fd00::5").AsSlice())
		copy(ip[24:40], netip.MustParseAddr("fd00::63").AsSlice())
	} else {
		ip = make([]byte, 20)
		ip[0] = 0x45
		binary.BigEndian.PutUint16(ip[2:4], uint16(20+len(th)+len(payload)))
		binary.BigEndian.PutUint16(ip[4:6], 0xfffe)
		ip[6] = 0x40 // don't fragment
		ip[8], ip[9] = 64, 6
		copy(ip[12:16], []byte{10, 3, 0, 5})
		copy(ip[16:20], []byte{10, 3, 0, 99})
	}
	pkt := append(append(ip, th...), payload...)
	return Build(Broadcast[:6], Broadcast[:6], typ, pkt)
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestSegmentTCP(t *testing.T) {
	timestamps := []byte{1, 1, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2}
	for _, v6 := range []bool{false, true} {
		payload := pattern(5000)
		frame := tcpTestFrame(v6, 0xfffffc00, tcpCWR|tcpPSH|tcpFIN|0x10, timestamps, payload)
		segs, ok := SegmentTCP(frame, 1024)
		if !ok {
			t.Fatalf("v6=%v: not split", v6)
		}
		// 1024 less the 12 bytes of options.
		if len(segs) != 5 {
			t.Fatalf("v6=%v: %d segments, want 5", v6, len(segs))
		}
		var got []byte
		for i, seg := range segs {
			tf, ok := parseTCP(seg)
			if !ok {
				t.Fatalf("v6=%v segment %d: does not parse", v6, i)
			}
			if tf.end != len(seg) {
				t.Errorf("v6=%v segment %d: IP length %d, frame %d", v6, i, tf.end, len(seg))
			}
			data := seg[tf.data:]
			if i < 4 && len(data) != 1012 {
				t.Errorf("v6=%v segment %d: %d bytes, want 1012", v6, i, len(data))
			}
			if s := binary.BigEndian.Uint32(seg[tf.tcp+4:]); s != 0xfffffc00+uint32(len(got)) {
				t.Errorf("v6=%v segment %d: seq %#x", v6, i, s)
			}
			flags := seg[tf.tcp+13]
			if want := i == 0; (flags&tcpCWR != 0) != want {
				t.Errorf("v6=%v segment %d: CWR %#x", v6, i, flags)
			}
			if want := i == 4; (flags&tcpPSH != 0) != want || (flags&tcpFIN != 0) != want {
				t.Errorf("v6=%v segment %d: PSH/FIN %#x", v6, i, flags)
			}
			if !bytes.Equal(seg[tf.tcp+20:tf.data], timestamps) {
				t.Errorf("v6=%v segment %d: options lost", v6, i)
			}
			if c := sum(pseudoSum(seg, tf), seg[tf.tcp:]); c != 0xffff {
				t.Errorf("v6=%v segment %d: bad TCP checksum", v6, i)
			}
			if !v6 {
				if c := sum(0, seg[tf.ip:tf.tcp]); c != 0xffff {
					t.Errorf("segment %d: bad IP checksum", i)
				}
				if id := binary.BigEndian.Uint16(seg[tf.ip+4:]); id != 0xfffe+uint16(i) {
					t.Errorf("segment %d: IP ID %#x", i, id)
				}
			}
			got = append(got, data...)
		}
		if !bytes.Equal(got, payload) {
			t.Errorf("v6=%v: payload differs after splitting", v6)
		}
	}
}

func TestSegmentTCPFitsFrame(t *testing.T) {
	frame := tcpTestFrame(false, 1, 0x10, nil, pattern(4000))
	segs, ok := SegmentTCP(frame, 9000)
	if !ok {
		t.Fatal("not split")
	}
	for i, seg := range segs {
		if len(seg) > MaxFrame {
			t.Errorf("segment %d: %d bytes", i, len(seg))
		}
	}
	if len(segs) != 3 {
		t.Errorf("%d segments, want 3", len(segs))
	}
}

func TestSegmentTCPRejects(t *testing.T) {
	udp := tcpTestFrame(false, 1, 0x10, nil, pattern(3000))
	udp[HeaderLen+9] = 17
	fragment := tcpTestFrame(false, 1, 0x10, nil, pattern(3000))
	fragment[HeaderLen+6] |= 0x20 // more fragments
	truncated := tcpTestFrame(false, 1, 0x10, nil, pattern(3000))[:2000]
	for name, f := range map[string][]byte{"udp": udp, "fragment": fragment, "truncated": truncated, "arp": Build(Broadcast, Broadcast, TypeARP, pattern(2000))} {
		if _, ok := SegmentTCP(f, 1460); ok {
			t.Errorf("%s: split", name)
		}
	}
}

func TestSYNMSS(t *testing.T) {
	syn := tcpTestFrame(false, 1, tcpSYN, []byte{1, 1, 4, 2, 2, 4, 0x04, 0x00}, nil)
	flow, mss, ok := SYNMSS(syn)
	if !ok || mss != 1024 {
		t.Fatalf("SYNMSS = %d, %v; want 1024", mss, ok)
	}
	want := TCPFlow{Src: netip.MustParseAddrPort("10.3.0.5:1021"), Dst: netip.MustParseAddrPort("10.3.0.99:512")}
	if flow != want {
		t.Errorf("flow %v, want %v", flow, want)
	}
	if _, mss, _ := SYNMSS(tcpTestFrame(true, 1, tcpSYN, nil, nil)); mss != DefaultMSS {
		t.Errorf("no option: MSS %d, want %d", mss, DefaultMSS)
	}
	if _, mss, _ := SYNMSS(tcpTestFrame(false, 1, tcpSYN, []byte{8, 0, 0, 0}, nil)); mss != DefaultMSS {
		t.Errorf("bad option: MSS %d, want %d", mss, DefaultMSS)
	}
	if _, _, ok := SYNMSS(tcpTestFrame(false, 1, 0x10, nil, nil)); ok {
		t.Error("not a SYN, but found an MSS")
	}
}
