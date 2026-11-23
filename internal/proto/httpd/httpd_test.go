package httpd

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0"
}
service "http" {}
service "tftp" {}
host "kali" {
  ip       = "192.168.1.5"
  mac      = "8:0:20:1:2:3"
  services = ["http"]
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

func start(t *testing.T) (*prototest.Env, *prototest.Log) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"boot/bsd.rd":           "kernel",
		"netbsd/sets/base.tgz":  "0123456789",
		"netbsd/sets/<odd>.tgz": "x",
	} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte(data), 0o644)
	}
	e := prototest.Setup(t, dir, conf)
	return e, e.Start(t, &Server{}, "http")
}

func client(t *testing.T, e *prototest.Env, mac, addr string) *http.Client {
	st := e.Client(t, mac, addr)
	return &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, a string) (net.Conn, error) {
			return st.DialTCP(ctx, netip.MustParseAddrPort(a))
		}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func get(t *testing.T, c *http.Client, method, path string, hdr ...string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, "http://192.168.1.1"+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestHTTP(t *testing.T) {
	e, log := start(t)
	c := client(t, e, "08:00:20:01:02:03", "192.168.1.5/24")

	if resp, body := get(t, c, "GET", "/pub/netbsd/sets/base.tgz"); resp.StatusCode != 200 || body != "0123456789" {
		t.Errorf("GET base.tgz: %d %q", resp.StatusCode, body)
	}
	if !log.Contains(`http request from kali for /pub/netbsd/sets/base.tgz: sending `) {
		t.Error("transfer not logged")
	}
	if resp, body := get(t, c, "GET", "/pub/netbsd/sets/base.tgz", "Range", "bytes=4-"); resp.StatusCode != 206 || body != "456789" {
		t.Errorf("GET range: %d %q", resp.StatusCode, body)
	}
	if resp, body := get(t, c, "HEAD", "/bsd.rd"); resp.StatusCode != 200 || resp.ContentLength != 6 || body != "" {
		t.Errorf("HEAD bsd.rd: %d %d %q", resp.StatusCode, resp.ContentLength, body)
	}
	if resp, _ := get(t, c, "GET", "/pub"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/pub/" {
		t.Errorf("GET /pub: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp, body := get(t, c, "GET", "/")
	if resp.StatusCode != 200 || !strings.Contains(body, `<a href="bsd.rd">bsd.rd</a>`) || !strings.Contains(body, `<a href="pub/">pub/</a>`) {
		t.Errorf("GET /: %d\n%s", resp.StatusCode, body)
	}
	if _, body := get(t, c, "GET", "/pub/netbsd/sets/"); !strings.Contains(body, `<a href="%3Codd%3E.tgz">&lt;odd&gt;.tgz</a>`) {
		t.Errorf("listing does not escape names:\n%s", body)
	}
	if resp, _ := get(t, c, "GET", "/pub/netbsd/../../netbsd/sets/base.tgz"); resp.StatusCode != 404 {
		t.Errorf("GET outside: %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, "PUT", "/bsd.rd"); resp.StatusCode != 405 {
		t.Errorf("PUT: %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, "GET", "/nothing"); resp.StatusCode != 404 || !log.Contains("http request from kali for /nothing denied (not found)") {
		t.Errorf("GET /nothing: %d", resp.StatusCode)
	}
}

func TestHTTPDenied(t *testing.T) {
	e, log := start(t)
	for _, c := range []struct{ mac, addr, logged string }{
		{"08:00:20:01:02:04", "192.168.1.6/24", "http request from other for /bsd.rd denied (http not allowed for this host)"},
		{"08:00:20:01:02:05", "192.168.1.7/24", "http request from 192.168.1.7 for /bsd.rd denied (client unknown)"},
	} {
		if resp, _ := get(t, client(t, e, c.mac, c.addr), "GET", "/bsd.rd"); resp.StatusCode != 403 {
			t.Errorf("%s: %d", c.addr, resp.StatusCode)
		}
		if !log.Contains(c.logged) {
			t.Errorf("not logged: %s", c.logged)
		}
	}
}
