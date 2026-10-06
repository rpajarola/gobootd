package bootparam

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "bootparam" {
  server_name = "aiax"
}
service "nfs" {}
host "kali" {
  ip  = "192.168.1.5"
  mac = "8:0:20:1:2:3"
  export "root" { path = "root" }
  export "swap" {
    path   = "/export/swap/kali"
    server = "nfshost"
  }
}
host "nfshost" {
  ip       = "192.168.1.9"
  services = ["nfs"]
}
host "other" {
  ip       = "192.168.1.6"
  services = ["nfs"]
  export "root" { path = "root" }
}
`

var (
	ctx    = context.Background()
	server = netip.MustParseAddrPort("192.168.1.1:111")
	bcast  = netip.MustParseAddrPort("255.255.255.255:111")
)

func setup(t *testing.T) (*oncrpc.Client, *prototest.Log, string) {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "root"), 0o755)
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "bootparam")
	st := e.Client(t, "08:00:20:01:02:03", "192.168.1.5/24")
	l, err := st.ListenUDP(1023)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &oncrpc.Client{L: l, Timeout: 200 * time.Millisecond, Tries: 2}, log, dir
}

func whoamiArgs(ip string) []byte {
	e := &oncrpc.Encoder{}
	encodeAddr(e, netip.MustParseAddr(ip))
	return e.Bytes()
}

// TestWhoamiBroadcast finds the server the way NetBSD and SunOS do: a
// WHOAMI broadcast through the portmapper.
func TestWhoamiBroadcast(t *testing.T) {
	c, log, _ := setup(t)
	args := (&oncrpc.Encoder{}).Uint32(Prog).Uint32(Vers).Uint32(ProcWhoami).Opaque(whoamiArgs("192.168.1.5")).Bytes()
	res, from, err := c.Call(ctx, bcast, oncrpc.PortmapProg, 2, 5, args)
	if err != nil {
		t.Fatal(err)
	}
	port, r := res.Uint32(), oncrpc.NewDecoder(res.Opaque(1000))
	name, domain, router := r.String(255), r.String(255), decodeAddr(r)
	if from != server || port != 111 || name != "kali" || domain != "" || router.String() != "192.168.1.1" || r.Err() != nil {
		t.Errorf("from %v port %d: name %q domain %q router %v", from, port, name, domain, router)
	}
	if !log.Contains("bootparam whoami from 192.168.1.5: kali") {
		t.Error("not logged")
	}

	// Unknown clients and clients without bootparam get no answer.
	for _, ip := range []string{"192.168.1.77", "192.168.1.6"} {
		args := (&oncrpc.Encoder{}).Uint32(Prog).Uint32(Vers).Uint32(ProcWhoami).Opaque(whoamiArgs(ip)).Bytes()
		if _, _, err := c.Call(ctx, bcast, oncrpc.PortmapProg, 2, 5, args); err == nil {
			t.Errorf("%s: got an answer", ip)
		}
	}
	if !log.Contains("bootparam whoami from 192.168.1.77 denied (client unknown)") ||
		!log.Contains("bootparam whoami from other denied (bootparam not allowed for this host)") {
		t.Error("denials not logged")
	}
}

func TestGetfile(t *testing.T) {
	c, log, dir := setup(t)
	getfile := func(name, key string) (string, netip.Addr, string, error) {
		res, _, err := c.Call(ctx, server, Prog, Vers, ProcGetfile, (&oncrpc.Encoder{}).String(name).String(key).Bytes())
		if err != nil {
			return "", netip.Addr{}, "", err
		}
		return res.String(255), decodeAddr(res), res.String(1024), res.Err()
	}
	for _, tc := range []struct {
		key, server, addr, path string
	}{
		{"root", "aiax", "192.168.1.1", filepath.Join(dir, "root")},
		{"swap", "nfshost", "192.168.1.9", "/export/swap/kali"},
		{"dump", "", "0.0.0.0", ""},
		{"gateway", "192.168.1.1", "192.168.1.1", "255.255.255.0"},
	} {
		server, addr, path, err := getfile("kali", tc.key)
		if err != nil || server != tc.server || addr.String() != tc.addr || path != tc.path {
			t.Errorf("%s: %q %v %q, %v", tc.key, server, addr, path, err)
		}
	}
	if _, _, _, err := getfile("kali", "home"); err == nil {
		t.Error("answered for a missing key")
	}
	if _, _, _, err := getfile("nobody", "root"); err == nil {
		t.Error("answered for an unknown client")
	}
	if !log.Contains(`bootparam getfile home from kali denied (export \"home\" not configured for this host)`) {
		t.Error("missing key not logged")
	}
	// The portmapper knows where bootparam is.
	res, _, err := c.Call(ctx, server, oncrpc.PortmapProg, 2, 3, (&oncrpc.Encoder{}).Uint32(Prog).Uint32(Vers).Uint32(17).Uint32(0).Bytes())
	if err != nil || res.Uint32() != 111 {
		t.Errorf("GETPORT: %v", err)
	}
}
