package ftpd

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0"
}
service "ftp" {}
service "tftp" {}
host "kali" {
  ip       = "192.168.1.5"
  mac      = "8:0:20:1:2:3"
  services = ["ftp"]
  file "boot/bsd.rd" {}
  export "sets" {
    path        = "netbsd"
    export_path = "/pub/netbsd"
  }
}
host "other" {
  ip       = "192.168.1.6"
  mac      = "8:0:20:1:2:4"
  services = ["tftp"]
}
`

var server = netip.MustParseAddrPort("192.168.1.1:21")

func start(t *testing.T) (*prototest.Env, *prototest.Log) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"boot/bsd.rd":          "kernel",
		"netbsd/sets/base.tgz": "0123456789",
		"netbsd/README":        "one\ntwo\n",
	} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	e := prototest.Setup(t, dir, conf)
	return e, e.Start(t, &Server{}, "ftp")
}

type client struct {
	t  *testing.T
	st *ipstack.Stack
	c  *textproto.Conn
}

func dial(t *testing.T, e *prototest.Env, mac, addr string) *client {
	st := e.Client(t, mac, addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nc, err := st.DialTCP(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { nc.Close() })
	nc.SetDeadline(time.Now().Add(10 * time.Second))
	return &client{t: t, st: st, c: textproto.NewConn(nc)}
}

// cmd sends a command and checks the reply code.
func (c *client) cmd(code int, format string, args ...any) string {
	c.t.Helper()
	if format != "" {
		if err := c.c.PrintfLine(format, args...); err != nil {
			c.t.Fatal(err)
		}
	}
	got, msg, err := c.c.ReadResponse(code)
	if err != nil {
		c.t.Fatalf("%s: %d %s: %v", fmt.Sprintf(format, args...), got, msg, err)
	}
	return msg
}

func (c *client) login() {
	c.t.Helper()
	c.cmd(220, "")
	c.cmd(331, "USER anonymous")
	c.cmd(230, "PASS me@example.com")
}

var epsvRE = regexp.MustCompile(`\(\|\|\|(\d+)\|\)`)

// passive runs a command over an EPSV data connection and returns the
// data.
func (c *client) passive(cmd string) string {
	c.t.Helper()
	m := epsvRE.FindStringSubmatch(c.cmd(229, "EPSV"))
	if m == nil {
		c.t.Fatal("no EPSV port")
	}
	port, _ := strconv.Atoi(m[1])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dc, err := c.st.DialTCP(ctx, netip.AddrPortFrom(server.Addr(), uint16(port)))
	if err != nil {
		c.t.Fatal(err)
	}
	c.cmd(150, "%s", cmd)
	b, _ := io.ReadAll(dc)
	dc.Close()
	c.cmd(226, "")
	return string(b)
}

func TestFTP(t *testing.T) {
	e, log := start(t)
	c := dial(t, e, "08:00:20:01:02:03", "192.168.1.5/24")
	c.cmd(220, "")
	c.cmd(530, "LIST")
	c.cmd(530, "USER root")
	c.cmd(331, "USER ftp")
	c.cmd(230, "PASS x")
	if !log.Contains("ftp login from kali") {
		t.Error("login not logged")
	}
	c.cmd(215, "SYST")
	if feat := c.cmd(211, "FEAT"); !strings.Contains(feat, "EPSV") || !strings.Contains(feat, "REST STREAM") {
		t.Errorf("FEAT: %q", feat)
	}
	c.cmd(200, "TYPE I")
	if got := c.passive("RETR /bsd.rd"); got != "kernel" {
		t.Errorf("RETR bsd.rd = %q", got)
	}
	if !log.Contains("ftp request from kali for /bsd.rd: sending ") {
		t.Error("transfer not logged")
	}
	c.cmd(250, "CWD pub/netbsd/sets")
	if pwd := c.cmd(257, "PWD"); !strings.HasPrefix(pwd, `"/pub/netbsd/sets"`) {
		t.Errorf("PWD: %q", pwd)
	}
	c.cmd(213, "SIZE base.tgz")
	if mdtm := c.cmd(213, "MDTM base.tgz"); len(mdtm) != 14 {
		t.Errorf("MDTM: %q", mdtm)
	}
	c.cmd(350, "REST 4")
	if got := c.passive("RETR base.tgz"); got != "456789" {
		t.Errorf("RETR after REST = %q", got)
	}
	c.cmd(250, "CDUP")
	if got := c.passive("NLST"); got != "README\r\nsets\r\n" {
		t.Errorf("NLST = %q", got)
	}
	if got := c.passive("LIST -la"); !regexp.MustCompile(`(?m)^-rw-r--r--   1 ftp      ftp                 8 .* README\r$`).MatchString(got) ||
		!regexp.MustCompile(`(?m)^drwx.* sets\r$`).MatchString(got) {
		t.Errorf("LIST =\n%s", got)
	}
	c.cmd(200, "TYPE A")
	if got := c.passive("RETR README"); got != "one\r\ntwo\r\n" {
		t.Errorf("ASCII RETR = %q", got)
	}
	c.cmd(550, "RETR ../../etc/passwd")
	c.cmd(550, "STOR x")
	c.cmd(550, "CWD /nowhere")
	c.cmd(504, "PORT 10,0,0,1,4,0")
	c.cmd(221, "QUIT")
}

// Active mode: the server connects back to the client.
func TestFTPActive(t *testing.T) {
	e, _ := start(t)
	c := dial(t, e, "08:00:20:01:02:03", "192.168.1.5/24")
	c.login()
	l, err := c.st.ListenTCP(5000)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan string, 1)
	go func() {
		dc, err := l.Accept()
		if err != nil {
			got <- err.Error()
			return
		}
		b, _ := io.ReadAll(dc)
		dc.Close()
		got <- string(b)
	}()
	c.cmd(200, "TYPE I")
	c.cmd(200, "PORT 192,168,1,5,19,136")
	c.cmd(150, "RETR bsd.rd")
	if s := <-got; s != "kernel" {
		t.Errorf("active RETR = %q", s)
	}
	c.cmd(226, "")
	c.cmd(200, "EPRT |1|192.168.1.5|5000|")
	c.cmd(150, "NLST /")
	if s := <-func() chan string {
		ch := make(chan string, 1)
		go func() {
			dc, err := l.Accept()
			if err != nil {
				ch <- err.Error()
				return
			}
			b, _ := io.ReadAll(dc)
			dc.Close()
			ch <- string(b)
		}()
		return ch
	}(); s != "bsd.rd\r\npub\r\n" {
		t.Errorf("active NLST = %q", s)
	}
	c.cmd(226, "")
}

func TestFTPDenied(t *testing.T) {
	e, log := start(t)
	c := dial(t, e, "08:00:20:01:02:04", "192.168.1.6/24")
	c.cmd(421, "")
	if !log.Contains("ftp connection from other denied (ftp not allowed for this host)") {
		t.Error("denial not logged")
	}
}
