package tftp

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
service "tftp" {
  listen  = ["127.0.0.1:0"]
  timeout = 1
}
service "rarp" {}
host "kali" {
  ip       = "127.0.0.1"
  services = ["tftp"]
  file "sun4c" { name = "*" }
  file "boot/netbsd" { aliases = ["bsd"] }
  file "text" {}
}
`

func start(t *testing.T, conf string, files map[string][]byte) (*net.UDPAddr, *prototest.Log) {
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	addr := make(chan net.Addr, 1)
	s := &Server{listening: func(a net.Addr) { addr <- a }}
	log := prototest.Start(t, s, "tftp", prototest.Inventory(t, dir, conf), nil)
	select {
	case a := <-addr:
		return a.(*net.UDPAddr), log
	case <-time.After(time.Second):
		t.Fatal("server did not start")
	}
	return nil, nil
}

type client struct {
	t    *testing.T
	conn *net.UDPConn
	srv  *net.UDPAddr
	peer *net.UDPAddr // transfer address
}

func dial(t *testing.T, srv *net.UDPAddr) *client {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return &client{t: t, conn: c, srv: srv}
}

func (c *client) request(op uint16, name, mode string, opts ...string) {
	b := binary.BigEndian.AppendUint16(nil, op)
	for _, s := range append([]string{name, mode}, opts...) {
		b = append(append(b, s...), 0)
	}
	c.conn.WriteToUDP(b, c.srv)
}

func (c *client) recv() []byte {
	buf := make([]byte, 70000)
	c.conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, from, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return nil
	}
	if from.Port == c.srv.Port {
		c.t.Errorf("reply from the listening port %v, want a new transfer port", from)
	}
	c.peer = from
	return buf[:n]
}

func (c *client) ack(block uint16) {
	b := binary.BigEndian.AppendUint16(nil, opACK)
	c.conn.WriteToUDP(binary.BigEndian.AppendUint16(b, block), c.peer)
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
	srv, log := start(t, conf, files)

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
		got, oack, err := dial(t, srv).get(tc.name, tc.mode, tc.opts...)
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
	srv, log := start(t, `
service "tftp" { listen = ["127.0.0.1:0"] }
host "kali" {
  ip = "127.0.0.1"
  file "netbsd" {}
}
`, map[string][]byte{"netbsd": content(10)})

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
		c := dial(t, srv)
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
	srv, log := start(t, conf, map[string][]byte{"sun4c": content(100)})
	c := dial(t, srv)
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
