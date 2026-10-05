package tftp

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const lan = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
`

const conf = lan + `
service "tftp" {
  timeout = 1
}
service "rarp" {}
host "kali" {
  ip       = "192.168.1.5"
  mac      = "8:0:20:1:2:3"
  services = ["tftp"]
  file "sun4c" { name = "*" }
  file "boot/netbsd" { aliases = ["bsd"] }
  file "text" {}
}
`

var server = netip.MustParseAddrPort("192.168.1.1:69")

type testEnv struct {
	*prototest.Env
	log   *prototest.Log
	st    *ipstack.Stack
	ports uint16
}

func start(t *testing.T, conf string, files map[string][]byte) *testEnv {
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "tftp")
	st := e.Client(t, "08:00:20:01:02:03", "192.168.1.5/24")
	return &testEnv{Env: e, log: log, st: st, ports: 2000}
}

type client struct {
	t    *testing.T
	l    *ipstack.UDPListener
	srv  netip.AddrPort
	peer netip.AddrPort // transfer address
}

// dial returns a client on a new port, sending requests to server.
func (e *testEnv) dial(t *testing.T, srv netip.AddrPort) *client {
	e.ports++
	l, err := e.st.ListenUDP(e.ports)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &client{t: t, l: l, srv: srv}
}

func (c *client) request(op uint16, name, mode string, opts ...string) {
	b := binary.BigEndian.AppendUint16(nil, op)
	for _, s := range append([]string{name, mode}, opts...) {
		b = append(append(b, s...), 0)
	}
	if err := c.l.WriteTo(b, c.srv); err != nil {
		c.t.Fatal(err)
	}
}

func (c *client) recv() []byte {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	d, err := c.l.Read(ctx)
	if err != nil {
		return nil
	}
	if d.From.Port() == 69 {
		c.t.Errorf("reply from the listening port %v, want a new transfer port", d.From)
	}
	c.peer = d.From
	return d.Data
}

func (c *client) ack(block uint16) {
	b := binary.BigEndian.AppendUint16(nil, opACK)
	c.l.WriteTo(binary.BigEndian.AppendUint16(b, block), c.peer)
}

// get reads a whole file, returning the data and the OACK options.
func (c *client) get(name, mode string, opts ...string) ([]byte, map[string]string, error) {
	c.request(opRRQ, name, mode, opts...)
	var data []byte
	var oack map[string]string
	blksize := 512
	for want := uint16(1); ; want++ {
		p := c.recv()
		if p == nil {
			return nil, nil, io.ErrUnexpectedEOF
		}
		switch binary.BigEndian.Uint16(p) {
		case opERROR:
			return nil, nil, &tftpError{binary.BigEndian.Uint16(p[2:]), strings.TrimRight(string(p[4:]), "\x00")}
		case opOACK:
			oack = map[string]string{}
			f := strings.Split(string(p[2:]), "\x00")
			for i := 0; i+1 < len(f); i += 2 {
				oack[f[i]] = f[i+1]
			}
			if s, ok := oack["blksize"]; ok {
				blksize = atoi(s)
			}
			c.ack(0)
			want--
			continue
		case opDATA:
			if got := binary.BigEndian.Uint16(p[2:]); got != want {
				c.t.Fatalf("block %d, want %d", got, want)
			}
			data = append(data, p[4:]...)
			c.ack(want)
			if len(p)-4 < blksize {
				return data, oack, nil
			}
		}
	}
}

type tftpError struct {
	code uint16
	msg  string
}

func (e *tftpError) Error() string { return e.msg }

func atoi(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func content(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i * 7)
	}
	return b
}

func TestRead(t *testing.T) {
	files := map[string][]byte{"sun4c": content(1024), "boot/netbsd": content(3000), "text": []byte("a\nb\rc")}
	e := start(t, conf, files)
	log := e.log

	for _, tc := range []struct {
		name, mode string
		opts       []string
		want       []byte
		oack       map[string]string
	}{
		// Exactly two blocks: the transfer ends with an empty block.
		{name: "C0A80105.SUN4C", mode: "octet", want: files["sun4c"]},
		{name: "netbsd", mode: "OCTET", want: files["boot/netbsd"]},
		{name: "/tftpboot/bsd", mode: "octet", want: files["boot/netbsd"]},
		{name: "netbsd", mode: "octet", opts: []string{"blksize", "1400", "tsize", "0"}, want: files["boot/netbsd"],
			oack: map[string]string{"blksize": "1400", "tsize": "3000"}},
		{name: "netbsd", mode: "octet", opts: []string{"blksize", "9000", "foo", "bar"}, want: files["boot/netbsd"],
			oack: map[string]string{"blksize": "1468"}},
		{name: "text", mode: "netascii", opts: []string{"tsize", "0"}, want: []byte("a\r\nb\r\x00c")},
	} {
		got, oack, err := e.dial(t, server).get(tc.name, tc.mode, tc.opts...)
		if err != nil {
			t.Errorf("%s %v: %v", tc.name, tc.opts, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%s %v: got %d bytes, want %d", tc.name, tc.opts, len(got), len(tc.want))
		}
		if len(oack) != len(tc.oack) {
			t.Errorf("%s %v: oack %v, want %v", tc.name, tc.opts, oack, tc.oack)
		}
		for k, v := range tc.oack {
			if oack[k] != v {
				t.Errorf("%s %v: oack %v, want %v", tc.name, tc.opts, oack, tc.oack)
			}
		}
	}
	if !log.Contains(`tftp transfer of `) || !log.Contains(`to kali complete`) {
		t.Error("transfer not logged")
	}
}

func TestDenied(t *testing.T) {
	e := start(t, lan+`
service "tftp" {}
host "kali" {
  ip = "192.168.1.5"
  file "netbsd" {}
}
`, map[string][]byte{"netbsd": content(10)})
	log := e.log

	for _, tc := range []struct {
		op         uint16
		name, mode string
		code       uint16
		log        string
	}{
		{opRRQ, "vmunix", "octet", errNotFound, `tftp request from kali for \"vmunix\" denied (file \"vmunix\" not configured for this host)`},
		{opWRQ, "netbsd", "octet", errAccess, `denied (writing is not supported)`},
		{opRRQ, "netbsd", "mail", errIllegal, `denied (mode \"mail\" not supported)`},
	} {
		c := e.dial(t, server)
		c.request(tc.op, tc.name, tc.mode)
		p := c.recv()
		if p == nil || binary.BigEndian.Uint16(p) != opERROR || binary.BigEndian.Uint16(p[2:]) != tc.code {
			t.Errorf("%s: got %q, want error %d", tc.name, p, tc.code)
		}
		if !log.Contains(tc.log) {
			t.Errorf("log does not contain %s", tc.log)
		}
	}
}

func TestRetransmit(t *testing.T) {
	e := start(t, conf, map[string][]byte{"sun4c": content(100)})
	log := e.log
	c := e.dial(t, server)
	c.request(opRRQ, "x", "octet")
	first := c.recv()
	// Don't acknowledge: the server must send the block again.
	again := c.recv()
	if again == nil || !bytes.Equal(first, again) {
		t.Fatalf("retransmission %x, want %x", again, first)
	}
	c.ack(1)
	if !log.Contains("to kali complete") {
		t.Error("transfer not completed")
	}
}

func TestParseRequest(t *testing.T) {
	for _, tc := range []struct {
		in   string
		ok   bool
		opts int
	}{
		{"\x00\x01file\x00octet\x00", true, 0},
		{"\x00\x01file\x00octet\x00blksize\x001024\x00", true, 1},
		{"\x00\x01file\x00octet\x00\x00\x00", true, 0}, // NUL padding
		{"\x00\x01file\x00octet", false, 0},
		{"\x00\x03file\x00octet\x00", false, 0},
	} {
		r, err := parseRequest([]byte(tc.in))
		if (err == nil) != tc.ok {
			t.Errorf("%q: err %v", tc.in, err)
			continue
		}
		if err == nil && len(r.options) != tc.opts {
			t.Errorf("%q: options %v", tc.in, r.options)
		}
	}
}

func TestBroadcast(t *testing.T) {
	e := start(t, conf, map[string][]byte{"sun4c": content(600)})
	// Sun PROMs broadcast their request and take the first answer.
	got, _, err := e.dial(t, netip.MustParseAddrPort("255.255.255.255:69")).get("C0A80105.SUN4C", "octet")
	if err != nil || len(got) != 600 {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	if !e.log.Contains("broadcast=true") {
		t.Error("broadcast not logged")
	}
	// Refusals of broadcast requests are not sent, so other servers can
	// answer.
	c := e.dial(t, netip.MustParseAddrPort("192.168.1.255:69"))
	c.request(opWRQ, "x", "octet")
	if p := c.recv(); p != nil {
		t.Errorf("got %x for a refused broadcast request", p)
	}
	if !e.log.Contains("denied (writing is not supported)") {
		t.Error("refusal not logged")
	}
}
