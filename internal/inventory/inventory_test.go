package inventory

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/resolve"
)

type fakeResolver struct {
	macs map[string]string
	ips  map[string]string
}

func (r fakeResolver) LookupMAC(name string) (net.HardwareAddr, string, error) {
	if s, ok := r.macs[name]; ok {
		mac, err := resolve.ParseMAC(s)
		return mac, "ethers", err
	}
	return nil, "", resolve.ErrNotFound
}

func (r fakeResolver) LookupIP(name string) (netip.Addr, string, error) {
	if s, ok := r.ips[name]; ok {
		return netip.MustParseAddr(s), "dns", nil
	}
	return netip.Addr{}, "", resolve.ErrNotFound
}

// build parses src with root set to a temporary directory containing files.
func build(t *testing.T, src string, files ...string) (*Inventory, hcl.Diagnostics) {
	t.Helper()
	dir := t.TempDir()
	for _, f := range files {
		p := filepath.Join(dir, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg, _, diags := config.Parse([]byte(src), filepath.Join(dir, "bootd.hcl"))
	if diags.HasErrors() {
		t.Fatalf("parse: %v", diags)
	}
	r := fakeResolver{
		macs: map[string]string{"kali": "8:0:20:1:2:3"},
		ips:  map[string]string{"kali": "192.0.2.5"},
	}
	return Build(cfg, r)
}

func mustBuild(t *testing.T, src string, files ...string) *Inventory {
	t.Helper()
	inv, diags := build(t, src, files...)
	if len(diags) > 0 {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	return inv
}

// wantDiag checks that diags contain one with the given severity whose text
// contains want.
func wantDiag(t *testing.T, diags hcl.Diagnostics, sev hcl.DiagnosticSeverity, want string) {
	t.Helper()
	for _, d := range diags {
		if d.Severity == sev && strings.Contains(d.Summary+": "+d.Detail, want) {
			return
		}
	}
	t.Errorf("no diagnostic containing %q in %v", want, diags)
}

func TestLookup(t *testing.T) {
	inv := mustBuild(t, `
service "rarp" {}
host "kali" {}
host "nesta" {
  mac = "08:00:09:aa:bb:cc"
  ip  = "192.0.2.7"
}
`)
	kali, err := inv.ByName("KALI")
	if err != nil {
		t.Fatal(err)
	}
	if kali.MAC.String() != "08:00:20:01:02:03" || kali.MACSource != "ethers" {
		t.Errorf("kali MAC = %s from %s", kali.MAC, kali.MACSource)
	}
	if kali.IP.String() != "192.0.2.5" || kali.IPSource != "dns" {
		t.Errorf("kali IP = %s from %s", kali.IP, kali.IPSource)
	}
	if h, err := inv.ByMAC(net.HardwareAddr{8, 0, 9, 0xaa, 0xbb, 0xcc}); err != nil || h.Name != "nesta" {
		t.Errorf("ByMAC = %v, %v", h, err)
	}
	if h, err := inv.ByIP(netip.MustParseAddr("::ffff:192.0.2.7")); err != nil || h.Name != "nesta" {
		t.Errorf("ByIP = %v, %v", h, err)
	}
	_, err = inv.ByName("tiamat")
	var denied *DeniedError
	if !errors.As(err, &denied) || err.Error() != "client unknown" {
		t.Errorf("ByName(unknown) error = %v", err)
	}
}

func TestServices(t *testing.T) {
	inv, diags := build(t, `
service "rarp" {}
service "tftp" {}
host "all" {
  mac = "0:0:0:0:0:1"
  ip  = "192.0.2.1"
}
host "some" {
  mac      = "0:0:0:0:0:2"
  ip       = "192.0.2.2"
  services = ["tftp", "rmp"]
}
`)
	wantDiag(t, diags, hcl.DiagWarning, `there is no service "rmp" block`)
	all, _ := inv.ByName("all")
	if got := strings.Join(all.Services, " "); got != "rarp tftp" {
		t.Errorf("default services = %q, want all enabled", got)
	}
	some, _ := inv.ByName("some")
	if some.Allows("tftp") != nil || some.Allows("rarp") == nil {
		t.Errorf("some services = %v", some.Services)
	}
	if err := some.Allows("rarp"); err.Error() != "rarp not allowed for this host" {
		t.Errorf("Allows error = %q", err)
	}
}

func TestFileLookup(t *testing.T) {
	inv := mustBuild(t, `
service "tftp" {}
service "rmp" {}
host "kali" {
  file "sparc/solaris" { name = "*" }
  file "sparc/openbsd-2.8" {}
  file "hp300/netbsd-uboot" {
    name     = "netbsd"
    aliases  = ["netbsd-uboot"]
    services = ["rmp"]
  }
}
`, "sparc/solaris", "sparc/openbsd-2.8", "hp300/netbsd-uboot")
	h, _ := inv.ByName("kali")
	for _, tc := range []struct {
		svc, name, want string
		kind            MatchKind
	}{
		{"tftp", "openbsd-2.8", "sparc/openbsd-2.8", MatchName},
		{"tftp", "sparc/openbsd-2.8", "sparc/openbsd-2.8", MatchPath},
		{"tftp", "C0000205.SUN4C", "sparc/solaris", MatchWildcard},
		{"tftp", "netbsd", "sparc/solaris", MatchWildcard}, // rmp only
		{"tftp", "", "sparc/solaris", MatchAny},
		{"rmp", "netbsd-uboot", "hp300/netbsd-uboot", MatchAlias},
		{"rmp", "netbsd", "hp300/netbsd-uboot", MatchName},
	} {
		f, kind, err := h.File(tc.svc, tc.name)
		if err != nil {
			t.Errorf("File(%s, %q): %v", tc.svc, tc.name, err)
			continue
		}
		if f.Label != tc.want || kind != tc.kind {
			t.Errorf("File(%s, %q) = %s by %s, want %s by %s", tc.svc, tc.name, f.Label, kind, tc.want, tc.kind)
		}
	}
	if fs := h.FilesFor("rmp"); len(fs) != 3 {
		t.Errorf("FilesFor(rmp) = %d files, want 3", len(fs))
	}
}

func TestFileNotFound(t *testing.T) {
	inv := mustBuild(t, `
service "tftp" {}
host "kali" {
  file "a" {}
}
`, "a")
	h, _ := inv.ByName("kali")
	if _, _, err := h.File("tftp", "b"); err == nil || err.Error() != `file "b" not configured for this host` {
		t.Errorf("File(b) error = %v", err)
	}
}

func TestClass(t *testing.T) {
	inv := mustBuild(t, `
service "rmp" {}
service "nfs" {}
class "hp300" {
  match    = { rmp_machtype = "HP9000/425" }
  services = ["rmp", "nfs"]
  file "netbsd" {}
  export "root" { path = "class-root" }
}
host "nesta" {
  class = "hp300"
  mac   = "0:0:0:0:0:1"
  ip    = "192.0.2.1"
  file "netbsd-test" { name = "netbsd" }
  export "root" { path = "nesta-root" }
}
host "other" {
  class    = "hp300"
  mac      = "0:0:0:0:0:2"
  ip       = "192.0.2.2"
  services = ["nfs"]
}
`, "netbsd", "netbsd-test", "class-root", "nesta-root")
	if c := inv.MatchClass("rmp_machtype", "HP9000/425"); c == nil || c.Name != "hp300" {
		t.Errorf("MatchClass = %v", c)
	}
	if c := inv.MatchClass("rmp_machtype", "HP9000/320"); c != nil {
		t.Errorf("MatchClass(320) = %v", c)
	}
	nesta, _ := inv.ByName("nesta")
	if strings.Join(nesta.Services, " ") != "rmp nfs" {
		t.Errorf("nesta services = %v, want class services", nesta.Services)
	}
	if f, _, _ := nesta.File("rmp", "netbsd"); f.Label != "netbsd-test" || len(nesta.Files) != 1 {
		t.Errorf("host file does not take precedence: got %s", f.Label)
	}
	if e, _ := nesta.Export("root"); filepath.Base(e.Path) != "nesta-root" || len(nesta.Exports) != 1 {
		t.Errorf("host export does not replace class export: %v", nesta.Exports)
	}
	other, _ := inv.ByName("other")
	if strings.Join(other.Services, " ") != "nfs" {
		t.Errorf("other services = %v, want host services", other.Services)
	}
	if e, _ := other.Export("root"); filepath.Base(e.Path) != "class-root" {
		t.Errorf("other export = %v, want class export", e)
	}
}

func TestErrors(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"duplicate host", `
host "kali" {}
host "Kali" {}`, `Host "Kali" is already defined`},
		{"duplicate mac", `
host "a" { mac = "0:0:0:0:0:1" }
host "b" { mac = "00:00:00:00:00:01" }`, "MAC address 00:00:00:00:00:01, which host \"a\""},
		{"duplicate ip", `
host "a" { ip = "192.0.2.1" }
host "b" { ip = "192.0.2.1" }`, "IP address 192.0.2.1, which host \"a\""},
		{"bad mac", `host "a" { mac = "0:0:0:0:1" }`, "invalid MAC address"},
		{"ipv6", `host "a" { ip = "2001:db8::1" }`, "not an IPv4 address"},
		{"unknown class", `host "a" { class = "sun3" }`, `class "sun3", which is not defined`},
		{"duplicate class", `
class "a" {}
class "a" {}`, `Class "a" is already defined`},
		{"duplicate disk unit", `
host "a" {
  disk "x" { path = "x" }
  disk "y" { path = "y" }
}`, "both on unit 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := build(t, tc.src)
			wantDiag(t, diags, hcl.DiagError, tc.want)
		})
	}
}

func TestWarnings(t *testing.T) {
	for _, tc := range []struct{ name, src, want string }{
		{"missing file", `
service "tftp" {}
host "kali" {
  file "nonexistent" {}
}`, "nonexistent does not exist"},
		{"no mac", `
service "rarp" {}
host "a" { ip = "192.0.2.1" }`, "rarp will not recognize it"},
		{"no ip", `
service "tftp" {}
host "a" { mac = "0:0:0:0:0:1" }`, "tftp will not work for it"},
		{"shadowed name", `
service "tftp" {}
host "kali" {
  file "f1" { name = "*" }
  file "f2" { name = "*" }
}`, `tftp name "*" already refers to f1`},
		{"file never served", `
service "tftp" {}
host "kali" {
  services = ["tftp"]
  file "f1" { services = ["rmp"] }
}`, "File f1 is limited to rmp"},
		{"unused service", `
service "tftp" {}
service "rarp" {}
host "kali" { services = ["tftp"] }`, `Service "rarp" is enabled, but no host may use it`},
		{"unused export", `
service "tftp" {}
host "kali" {
  export "root" { path = "/" }
}`, "has export entries, but may not use nfs or bootparam"},
		{"no exports", `
service "bootparam" {}
host "kali" {}`, "may use bootparam, but has no export entries"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, diags := build(t, tc.src, "f1", "f2")
			if diags.HasErrors() {
				t.Fatalf("unexpected errors: %v", diags)
			}
			wantDiag(t, diags, hcl.DiagWarning, tc.want)
		})
	}
}
