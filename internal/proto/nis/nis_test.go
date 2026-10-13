package nis

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
service "nis" {
  domain      = "lab"
  maps        = "yp"
  server_name = "aiax"
}
host "kali" {
  ip       = "192.168.1.5"
  mac      = "08:00:20:01:02:03"
  services = ["nis"]
}
host "other" {
  ip       = "192.168.1.6"
  mac      = "08:00:20:0a:0b:0c"
  services = ["nis"]
}
host "nonis" {
  ip       = "192.168.1.7"
  services = ["tftp"]
  file "x" {}
}
`

var files = map[string]string{
	"passwd": `root:*:0:1:Operator:/:/bin/csh
+::0:0:::
rico:xyzzy:100:10:Rico #1:/home/rico:/bin/csh
`,
	"group": "wheel:*:0:root\nstaff:*:10:\n",
	"hosts": `# comment
192.168.1.20  printer lp   # the printer
192.168.1.5   kali-from-file
`,
	"ethers":   "8:0:20:a:b:c other\n",
	"services": "ftp\t21/tcp\ntelnet\t23/tcp\n",
	"aliases":  "postmaster: root\nstaff: rico,\n\troot\n",
	"netgroup": "trusted (kali,,) \\\n  (other,,)\n",
}

var ctx = context.Background()

var (
	server = netip.MustParseAddrPort("192.168.1.1:111")
	bcast  = netip.MustParseAddrPort("255.255.255.255:111")
)

type client struct {
	t *testing.T
	*oncrpc.Client
	log *prototest.Log
	e   *prototest.Env
}

func setup(t *testing.T, ip string) *client {
	dir := t.TempDir()
	os.Mkdir(filepath.Join(dir, "yp"), 0o755)
	os.WriteFile(filepath.Join(dir, "x"), nil, 0o644)
	for name, s := range files {
		os.WriteFile(filepath.Join(dir, "yp", name), []byte(s), 0o644)
	}
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "nis")
	return &client{t: t, Client: dial(t, e, ip), log: log, e: e}
}

func dial(t *testing.T, e *prototest.Env, ip string) *oncrpc.Client {
	st := e.Client(t, "08:00:20:01:02:99", ip+"/24")
	l, err := st.ListenUDP(1023)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &oncrpc.Client{L: l, Timeout: 200 * time.Millisecond, Tries: 2}
}

func (c *client) call(proc uint32, args []byte) *oncrpc.Decoder {
	c.t.Helper()
	res, _, err := c.Call(ctx, server, Prog, Vers, proc, args)
	if err != nil {
		c.t.Fatalf("proc %d: %v", proc, err)
	}
	return res
}

func nokey(domain, m string) []byte { return (&oncrpc.Encoder{}).String(domain).String(m).Bytes() }

func key(domain, m, k string) []byte {
	return (&oncrpc.Encoder{}).String(domain).String(m).String(k).Bytes()
}

func (c *client) match(m, k string) (int32, string) {
	c.t.Helper()
	res := c.call(procMatch, key("lab", m, k))
	return res.Int32(), res.String(maxRecord)
}

// TestBind finds the server as ypbind does: DOMAIN_NONACK broadcast
// through the portmapper. Other domains get no answer.
func TestBind(t *testing.T) {
	c := setup(t, "192.168.1.5")
	callit := func(domain string) (*oncrpc.Decoder, error) {
		args := (&oncrpc.Encoder{}).Uint32(Prog).Uint32(Vers).Uint32(procDomainNonack).Opaque((&oncrpc.Encoder{}).String(domain).Bytes()).Bytes()
		res, _, err := c.Call(ctx, bcast, oncrpc.PortmapProg, 2, 5, args)
		return res, err
	}
	res, err := callit("lab")
	if err != nil {
		t.Fatal(err)
	}
	port, r := res.Uint32(), oncrpc.NewDecoder(res.Opaque(100))
	if port != oncrpc.PortmapPort || !r.Bool() {
		t.Errorf("port %d", port)
	}
	if !c.log.Contains("nis bind from kali: domain lab") {
		t.Error("bind not logged")
	}
	if _, err := callit("other"); err == nil {
		t.Error("answered for another domain")
	}
	if c.call(procDomain, (&oncrpc.Encoder{}).String("other").Bytes()).Bool() {
		t.Error("DOMAIN other = true")
	}
}

func TestMatch(t *testing.T) {
	c := setup(t, "192.168.1.5")
	for _, tc := range []struct {
		m, k string
		stat int32
		val  string
	}{
		{"passwd.byname", "rico", ypTrue, "rico:xyzzy:100:10:Rico #1:/home/rico:/bin/csh"},
		{"passwd.byuid", "0", ypTrue, "root:*:0:1:Operator:/:/bin/csh"},
		{"passwd.byname", "+", ypNokey, ""},
		{"passwd.byname", "nobody", ypNokey, ""},
		{"group.bygid", "10", ypTrue, "staff:*:10:"},
		{"hosts.byname", "LP", ypTrue, "192.168.1.20  printer lp"},
		{"hosts.byaddr", "192.168.1.5", ypTrue, "192.168.1.5   kali-from-file"},
		{"hosts.byname", "kali", ypTrue, "192.168.1.5\tkali"},
		{"hosts.byname", "other", ypTrue, "192.168.1.6\tother"},
		{"hosts.byname", "aiax", ypTrue, "192.168.1.1\taiax"},
		{"ethers.byaddr", "8:0:20:1:2:3", ypTrue, "8:0:20:1:2:3\tkali"},
		{"ethers.byaddr", "8:0:20:a:b:c", ypTrue, "8:0:20:a:b:c other"},
		{"services.byname", "23/tcp", ypTrue, "telnet\t23/tcp"},
		{"mail.aliases", "Staff", ypTrue, "rico, root"},
		{"mail.aliases", "@", ypTrue, "@"},
		{"netgroup", "trusted", ypTrue, "(kali,,) (other,,)"},
		{"ypservers", "aiax", ypTrue, "aiax"},
		{"rpc.bynumber", "100000", ypNomap, ""},
	} {
		if stat, val := c.match(tc.m, tc.k); stat != tc.stat || val != tc.val {
			t.Errorf("match %s %s = %d %q, want %d %q", tc.m, tc.k, stat, val, tc.stat, tc.val)
		}
	}
	if stat := c.call(procMatch, key("other", "passwd.byname", "rico")).Int32(); stat != ypNodom {
		t.Errorf("match in another domain = %d", stat)
	}
}

// TestFirstNext walks a map as getpwent does.
func TestFirstNext(t *testing.T) {
	c := setup(t, "192.168.1.5")
	var keys []string
	res := c.call(procFirst, nokey("lab", "passwd.byname"))
	for {
		stat, val, k := res.Int32(), res.String(maxRecord), res.String(maxRecord)
		if stat == ypNomore {
			break
		}
		if stat != ypTrue || !strings.HasPrefix(val, k+":") {
			t.Fatalf("stat %d key %q value %q", stat, k, val)
		}
		keys = append(keys, k)
		res = c.call(procNext, key("lab", "passwd.byname", k))
	}
	if !slices.Equal(keys, []string{"rico", "root"}) {
		t.Errorf("keys %q", keys)
	}
	if stat := c.call(procNext, key("lab", "passwd.byname", "nobody")).Int32(); stat != ypNokey {
		t.Errorf("next after an unknown key = %d", stat)
	}
}

func TestMasterOrderMaplist(t *testing.T) {
	c := setup(t, "192.168.1.5")
	if res := c.call(procMaster, nokey("lab", "passwd.byname")); res.Int32() != ypTrue || res.String(64) != "aiax" {
		t.Error("master")
	}
	if res := c.call(procOrder, nokey("lab", "passwd.byname")); res.Int32() != ypTrue || res.Uint32() == 0 {
		t.Error("order")
	}
	res := c.call(procMaplist, (&oncrpc.Encoder{}).String("lab").Bytes())
	if res.Int32() != ypTrue {
		t.Fatal("maplist failed")
	}
	var names []string
	for res.Bool() {
		names = append(names, res.String(maxMap))
	}
	for _, want := range []string{"ethers.byaddr", "hosts.byname", "mail.aliases", "passwd.byuid", "ypservers"} {
		if !slices.Contains(names, want) {
			t.Errorf("maplist %q lacks %s", names, want)
		}
	}
	if slices.Contains(names, "rpc.bynumber") {
		t.Error("maplist lists a map without a source")
	}
}

// TestAll reads a map as ypcat does: GETPORT for TCP, then ALL over TCP.
func TestAll(t *testing.T) {
	c := setup(t, "192.168.1.5")
	pm, _, err := c.Call(ctx, server, oncrpc.PortmapProg, 2, 3, (&oncrpc.Encoder{}).Uint32(Prog).Uint32(Vers).Uint32(6).Uint32(0).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if port := pm.Uint32(); port != oncrpc.PortmapPort {
		t.Fatalf("GETPORT TCP = %d", port)
	}
	st := c.e.Client(t, "08:00:20:01:02:98", "192.168.1.6/24")
	conn, err := st.DialTCP(ctx, server)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tc := &oncrpc.TCPClient{Conn: conn}
	all, err := tc.Call(Prog, Vers, procAll, nokey("lab", "group.byname"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for all.Bool() {
		stat, val, k := all.Int32(), all.String(maxRecord), all.String(maxRecord)
		if stat != ypTrue {
			if stat != ypNomore {
				t.Errorf("stat %d", stat)
			}
			continue
		}
		got = append(got, k+"="+val)
	}
	if all.Err() != nil || !slices.Equal(got, []string{"staff=staff:*:10:", "wheel=wheel:*:0:root"}) {
		t.Errorf("all: %q (%v)", got, all.Err())
	}
}

// TestDenied: hosts that may not use NIS get no answer.
func TestDenied(t *testing.T) {
	for _, ip := range []string{"192.168.1.7", "192.168.1.99"} {
		t.Run(ip, func(t *testing.T) {
			c := setup(t, ip)
			_, _, err := c.Call(ctx, server, Prog, Vers, procMatch, key("lab", "passwd.byname", "root"))
			if err == nil || err.Error() != "rpc: no reply" {
				t.Errorf("got %v", err)
			}
			if !c.log.Contains("nis match from") || !c.log.Contains("denied") {
				t.Error("denial not logged")
			}
		})
	}
}
