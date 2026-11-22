package dhcp

import (
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  mac     = "00:11:22:33:44:55"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "dhcp" {
  routers = ["192.168.1.254", "10.0.0.1"]
  dns     = ["192.168.1.53"]
  domain  = "lab"
}
service "tftp" {}
service "nfs" {}
service "nis" { domain = "yp" }
host "kali" {
  mac = "8:0:20:1:2:3"
  ip  = "192.168.1.5"
  file "boot.net" { aliases = ["vmunix"] }
  export "root" {
    path        = "root"
    export_path = "/kali/root"
  }
}
host "wild" {
  mac      = "8:0:20:1:2:6"
  ip       = "192.168.1.8"
  services = ["dhcp", "tftp"]
  file "pxe/boot.bin" { name = "*" }
}
host "nofile" {
  mac      = "8:0:20:1:2:5"
  ip       = "192.168.1.7"
  services = ["dhcp"]
}
host "notallowed" {
  mac      = "8:0:20:1:2:4"
  ip       = "192.168.1.6"
  services = ["tftp"]
}
`

var (
	clientMAC = net.HardwareAddr{8, 0, 0x20, 1, 2, 3}
	serverMAC = "00:11:22:33:44:55"
	kaliIP    = netip.MustParseAddr("192.168.1.5")
	serverIP  = netip.MustParseAddr("192.168.1.1")
)

func setup(t *testing.T) (*prototest.Env, *prototest.Log, *linktest.Port) {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "boot.net"), make([]byte, 1000), 0o644)
	os.MkdirAll(filepath.Join(dir, "pxe"), 0o755)
	os.WriteFile(filepath.Join(dir, "pxe", "boot.bin"), nil, 0o644)
	os.Mkdir(filepath.Join(dir, "root"), 0o755)
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "dhcp")
	return e, log, e.Segment.Station("8:0:20:1:2:3")
}

func newRequest(mac net.HardwareAddr, typ byte, opts ...Option) *Packet {
	p := &Packet{Op: OpRequest, HType: hwEther, HLen: 6, XID: 0x1234}
	copy(p.CHAddr[:], mac)
	if typ != 0 {
		p.Cookie = true
		p.Options = append([]Option{{OptMessageType, []byte{typ}}}, opts...)
	}
	return p
}

func send(st *linktest.Port, p *Packet) {
	src := netip.AddrPortFrom(netip.IPv4Unspecified(), ClientPort)
	if p.CIAddr.IsValid() {
		src = netip.AddrPortFrom(p.CIAddr, ClientPort)
	}
	mac := net.HardwareAddr(p.CHAddr[:6])
	st.WriteFrame(buildUDP(link.Broadcast, mac, src, netip.AddrPortFrom(broadcast, ServerPort), 1, p.Marshal()))
}

type reply struct {
	frame link.Frame
	d     Datagram
	p     *Packet
	size  int
}

func receive(t *testing.T, st *linktest.Port) (reply, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	for {
		b, err := st.ReadFrame(ctx)
		if err != nil {
			return reply{}, false
		}
		f, _ := link.Parse(b)
		d, ok := parseUDP(f)
		if !ok || d.Dst.Port() != ClientPort {
			continue
		}
		p, err := Parse(d.Payload)
		if err != nil {
			t.Fatalf("bad reply: %v", err)
		}
		if p.Op == OpReply {
			return reply{f, d, p, len(d.Payload)}, true
		}
	}
}

func TestDHCP(t *testing.T) {
	_, log, st := setup(t)

	send(st, newRequest(clientMAC, Discover, Option{OptParamRequest, []byte{OptRootPath, OptSubnetMask}}))
	r, ok := receive(t, st)
	if !ok {
		t.Fatal("no offer")
	}
	if r.p.Type() != Offer || r.p.YIAddr != kaliIP || r.p.SIAddr != serverIP || r.p.File != "boot.net" {
		t.Errorf("offer %v", r.p)
	}
	// Sent straight to the client, which has no address yet.
	if r.frame.Dst.String() != "08:00:20:01:02:03" || r.frame.Src.String() != serverMAC ||
		r.d.Dst.Addr() != kaliIP || r.d.Src != netip.MustParseAddrPort("192.168.1.1:67") {
		t.Errorf("offer sent %s %s -> %s %s", r.frame.Src, r.d.Src, r.frame.Dst, r.d.Dst)
	}
	for code, want := range map[byte]string{
		OptServerID:   "\xc0\xa8\x01\x01",
		OptSubnetMask: "\xff\xff\xff\x00",
		OptRouter:     "\xc0\xa8\x01\xfe", // 10.0.0.1 is not on the subnet
		OptDNS:        "\xc0\xa8\x01\x35",
		OptHostName:   "kali",
		OptDomainName: "lab",
		OptRootPath:   "192.168.1.1:/kali/root",
		OptBroadcast:  "\xc0\xa8\x01\xff",
		OptLeaseTime:  "\x00\x01\x51\x80",
		OptNISDomain:  "yp",
		OptNISServers: "\xc0\xa8\x01\x01",
		OptBootSize:   "\x00\x02",
	} {
		if got := string(r.p.Get(code)); got != want {
			t.Errorf("option %d = %q, want %q", code, got, want)
		}
	}
	// Mandatory options first, then the ones asked for in order.
	if len(r.p.Options) < 5 || r.p.Options[3].Code != OptRootPath || r.p.Options[4].Code != OptSubnetMask {
		t.Errorf("option order %v", r.p.Options)
	}
	if !log.Contains("dhcp offer to kali: 192.168.1.5") {
		t.Error("offer not logged")
	}

	send(st, newRequest(clientMAC, Request, Option{OptServerID, ip4(serverIP)}, Option{OptRequestedIP, ip4(kaliIP)}))
	r, ok = receive(t, st)
	if !ok || r.p.Type() != Ack || r.p.YIAddr != kaliIP || r.p.File != "boot.net" {
		t.Fatalf("ack %v %v", ok, r.p)
	}
	if !log.Contains("dhcp ack to kali: 192.168.1.5") {
		t.Error("ack not logged")
	}

	// Renewing: the client has its address and sends from it.
	req := newRequest(clientMAC, Request)
	req.CIAddr = kaliIP
	send(st, req)
	if r, ok = receive(t, st); !ok || r.p.Type() != Ack || r.d.Dst.Addr() != kaliIP {
		t.Errorf("renew %v %v", ok, r.p)
	}

	// Inform gets the parameters but no address or lease.
	req = newRequest(clientMAC, Inform)
	req.CIAddr = kaliIP
	send(st, req)
	if r, ok = receive(t, st); !ok || r.p.Type() != Ack || !r.p.YIAddr.IsUnspecified() || r.p.Get(OptLeaseTime) != nil {
		t.Errorf("inform %v %v", ok, r.p)
	}
}

func TestRequestRefused(t *testing.T) {
	_, log, st := setup(t)

	// A client that chose another server's offer.
	send(st, newRequest(clientMAC, Request, Option{OptServerID, []byte{192, 168, 1, 2}}, Option{OptRequestedIP, []byte{192, 168, 1, 99}}))
	if r, ok := receive(t, st); ok {
		t.Errorf("answered a request for another server: %v", r.p)
	}

	// A client asking for an address it does not have.
	send(st, newRequest(clientMAC, Request, Option{OptRequestedIP, []byte{192, 168, 1, 99}}))
	r, ok := receive(t, st)
	if !ok || r.p.Type() != Nak || !r.p.YIAddr.IsUnspecified() {
		t.Fatalf("nak %v %v", ok, r.p)
	}
	if !bytes.Equal(r.frame.Dst, link.Broadcast) || r.d.Dst.Addr() != broadcast {
		t.Errorf("nak sent to %s %s", r.frame.Dst, r.d.Dst)
	}
	if !log.Contains("dhcp request from kali for 192.168.1.99 refused (its address is 192.168.1.5)") {
		t.Error("nak not logged")
	}
}

func TestBroadcastFlag(t *testing.T) {
	_, _, st := setup(t)
	req := newRequest(clientMAC, Discover)
	req.Flags = flagBroadcast
	send(st, req)
	r, ok := receive(t, st)
	if !ok || !bytes.Equal(r.frame.Dst, link.Broadcast) || r.d.Dst.Addr() != broadcast {
		t.Fatalf("reply %v to %s %s", ok, r.frame.Dst, r.d.Dst)
	}
}

func TestBOOTP(t *testing.T) {
	_, log, st := setup(t)

	// An empty vendor area gets RFC 1048 options, within 64 bytes.
	req := newRequest(clientMAC, 0)
	req.File = "vmunix"
	send(st, req)
	r, ok := receive(t, st)
	if !ok {
		t.Fatal("no reply")
	}
	if r.p.Type() != 0 || r.p.YIAddr != kaliIP || r.p.SIAddr != serverIP || r.p.File != "vmunix" {
		t.Errorf("reply %v", r.p)
	}
	if r.size != minLen || !r.p.Cookie || string(r.p.Get(OptSubnetMask)) != "\xff\xff\xff\x00" {
		t.Errorf("reply is %d bytes, options %v", r.size, r.p.Options)
	}
	if !log.Contains("bootp reply to kali: 192.168.1.5") {
		t.Error("reply not logged")
	}

	// Other vendor formats are left alone.
	req = newRequest(clientMAC, 0)
	req.Vendor = []byte("CMU\x00")
	send(st, req)
	if r, ok = receive(t, st); !ok || r.p.Cookie || r.p.YIAddr != kaliIP {
		t.Errorf("CMU reply %v %v", ok, r.p)
	}

	// A file the host does not have.
	req = newRequest(clientMAC, 0)
	req.File = "other"
	send(st, req)
	if _, ok := receive(t, st); ok {
		t.Error("answered a request for an unknown file")
	}
	if !log.Contains(`bootp request from kali denied (file \"other\" not configured for this host)`) {
		t.Error("refusal not logged")
	}
}

func TestBootName(t *testing.T) {
	_, _, st := setup(t)
	for _, tc := range []struct {
		mac  net.HardwareAddr
		file string
	}{
		{net.HardwareAddr{8, 0, 0x20, 1, 2, 6}, "boot.bin"}, // wildcard: the file's base name
		{net.HardwareAddr{8, 0, 0x20, 1, 2, 5}, ""},         // no file: only an address
	} {
		send(st, newRequest(tc.mac, Discover))
		r, ok := receive(t, st)
		if !ok || r.p.File != tc.file || r.p.Get(OptRootPath) != nil {
			t.Errorf("%s: %v %v", tc.mac, ok, r.p)
		}
	}
}

func TestDenied(t *testing.T) {
	_, log, st := setup(t)
	for _, tc := range []struct {
		mac  net.HardwareAddr
		want string
	}{
		{net.HardwareAddr{8, 0, 0x20, 9, 9, 9}, "dhcp discover from 08:00:20:09:09:09 denied (client unknown)"},
		{net.HardwareAddr{8, 0, 0x20, 1, 2, 4}, "dhcp discover from notallowed denied (dhcp not allowed for this host)"},
	} {
		send(st, newRequest(tc.mac, Discover))
		if r, ok := receive(t, st); ok {
			t.Errorf("%s: answered %v", tc.mac, r.p)
		}
		if !log.Contains(tc.want) {
			t.Errorf("log does not contain %q", tc.want)
		}
	}
	req := newRequest(clientMAC, Discover)
	req.GIAddr = netip.MustParseAddr("10.1.1.1")
	send(st, req)
	if _, ok := receive(t, st); ok {
		t.Error("answered a relayed request")
	}
	if !log.Contains("via relay 10.1.1.1 not answered") {
		t.Error("relayed request not logged")
	}
}

func TestPacketRoundTrip(t *testing.T) {
	p := newRequest(clientMAC, Discover, Option{OptHostName, []byte("kali")})
	p.CIAddr, p.YIAddr, p.SIAddr, p.GIAddr = kaliIP, kaliIP, serverIP, serverIP
	p.File, p.SName, p.Secs, p.Flags = "boot.net", "server", 3, flagBroadcast
	q, err := Parse(p.Marshal())
	if err != nil || q.String() != p.String() || q.SName != "server" {
		t.Errorf("round trip: %v %v, want %v", q, err, p)
	}
	if _, err := Parse(append(p.Marshal()[:240], OptHostName, 10, 'k')); err == nil {
		t.Error("truncated option accepted")
	}
}

func TestOverload(t *testing.T) {
	b := newRequest(clientMAC, Discover, Option{OptOverload, []byte{1}}).Marshal()
	copy(b[108:], []byte{OptHostName, 2, 'h', 'i', OptEnd})
	p, err := Parse(b)
	if err != nil || p.File != "" || string(p.Get(OptHostName)) != "hi" {
		t.Errorf("overload: %v %v", p, err)
	}
}

func TestUDP(t *testing.T) {
	src, dst := netip.MustParseAddrPort("192.168.1.1:67"), netip.MustParseAddrPort("192.168.1.5:68")
	frame := link.Pad(buildUDP(clientMAC, clientMAC, src, dst, 7, []byte("hello")))
	f, _ := link.Parse(frame)
	d, ok := parseUDP(f)
	if !ok || d.Src != src || d.Dst != dst || string(d.Payload) != "hello" {
		t.Fatalf("parse: %v %+v", ok, d)
	}
	if Match(f) {
		t.Error("match accepts a datagram to the client port")
	}
}

func TestChecksum(t *testing.T) {
	src, dst := netip.MustParseAddrPort("0.0.0.0:68"), netip.MustParseAddrPort("255.255.255.255:67")
	frame := buildUDP(link.Broadcast, clientMAC, src, dst, 1, []byte("payload"))
	f, _ := link.Parse(frame)
	if !Match(f) {
		t.Fatal("match rejects a datagram to the server port")
	}
	frame[len(frame)-1] ^= 1
	f, _ = link.Parse(frame)
	if _, ok := parseUDP(f); ok {
		t.Error("bad checksum accepted")
	}
}

func TestOptionsFit(t *testing.T) {
	req := []Option{{OptMessageType, []byte{Offer}}}
	rest := []Option{{OptHostName, make([]byte, 20)}, {OptRootPath, make([]byte, 40)}, {OptSubnetMask, make([]byte, 4)}}
	out, dropped := options(req, rest, []byte{OptSubnetMask}, 40)
	if len(out) != 3 || out[1].Code != OptSubnetMask || out[2].Code != OptHostName || len(dropped) != 1 || dropped[0] != OptRootPath {
		t.Errorf("options %v, dropped %v", out, dropped)
	}
}
