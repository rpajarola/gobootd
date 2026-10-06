package nfs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

func TestParseSpec(t *testing.T) {
	// The full path form bsdtar writes.
	full := `#mtree
. gname=wheel uname=root mode=755 gid=0 uid=0 type=dir
./bin gname=wheel uname=root mode=755 gid=0 uid=0 type=dir
./bin/su mode=4555 uid=0 gid=0 type=file
./dev/console gname=wheel uname=root mode=600 gid=0 uid=0 type=char device=native,0,0
./dev/ttya uname=uucp mode=600 gid=0 uid=66 type=char device=native,12,0
./dev/apm mode=700 type=link link=tctrl0
./my\040file type=file mode=644 uid=0
`
	// The hierarchical form of "mtree -c", with /set defaults.
	hier := `/set type=file uname=root gname=wheel mode=0444
.               type=dir mode=0755
bin             type=dir mode=0755
    su          mode=04555
..
dev             type=dir mode=0755
    console     type=char mode=0600 device=0,0
    ttya        type=char mode=0600 uid=66 device=netbsd,12,0
    apm         type=link mode=0700 link=tctrl0
..
my\sfile        mode=0644
`
	for name, src := range map[string]string{"full": full, "hierarchical": hier} {
		s, err := parseSpec(strings.NewReader(src))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		check := func(p, typ string, mode uint32, uid uint32) {
			e := s[p]
			if e == nil || e.typ != typ || e.mode != mode || !e.hasUID || e.uid != uid {
				t.Errorf("%s: %s = %+v, want type %s mode %o uid %d", name, p, e, typ, mode, uid)
			}
		}
		check(".", "dir", 0o755, 0)
		check("bin/su", "file", 0o4555, 0)
		check("dev/console", "char", 0o600, 0)
		check("dev/ttya", "char", 0o600, 66)
		check("my file", "file", 0o644, 0)
		if e := s["dev/ttya"]; e.major != 12 || e.minor != 0 {
			t.Errorf("%s: ttya device %d,%d", name, e.major, e.minor)
		}
		if e := s["dev/apm"]; e.link != "tctrl0" {
			t.Errorf("%s: apm link %q", name, e.link)
		}
	}
	if rdev(12, 0) != 12<<8 || rdev(3, 2) != 3<<8|2 || rdev(1, 0x1234) != 1<<8|0x34|0x01200000 {
		t.Error("rdev encoding")
	}
}

// TestSpecExport serves a root file system extracted without privileges:
// the spec supplies owners, setuid bits and the device nodes tar could not
// create.
func TestSpecExport(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "root/bin"), 0o755)
	os.MkdirAll(filepath.Join(dir, "root/dev"), 0o755)
	os.WriteFile(filepath.Join(dir, "root/bin/su"), []byte("su"), 0o755)
	os.WriteFile(filepath.Join(dir, "root.mtree"), []byte(`#mtree
. mode=755 uid=0 gid=0 type=dir
./bin mode=755 uid=0 gid=0 type=dir
./bin/su mode=4555 uid=0 gid=0 type=file
./dev mode=755 uid=0 gid=0 type=dir
./dev/console mode=600 uid=0 gid=0 type=char device=native,0,0
./dev/sd0a mode=640 uid=0 gid=5 type=block device=native,7,0
./dev/stdin mode=755 uid=0 gid=0 type=link link=fd/0
`), 0o644)
	e := prototest.Setup(t, dir, `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0"
}
service "nfs" {}
host "kali" {
  ip  = "192.168.1.5"
  mac = "8:0:20:1:2:3"
  export "root" {
    path = "root"
    spec = "root.mtree"
  }
}
`)
	env := &env{Env: e, dir: dir, log: e.Start(t, &Server{}, "nfs")}
	c := env.client(t, "08:00:20:01:02:03", "192.168.1.5")
	root, st := c.mount(filepath.Join(dir, "root"))
	if st != nfsOK {
		t.Fatalf("mount: status %d", st)
	}
	_, a := c.path(root, "bin", "su")
	if a.uid != 0 || a.mode&0o7777 != 0o4555 || a.typ != typeReg {
		t.Errorf("su: %+v, want root-owned setuid", a)
	}
	devfh, _ := c.path(root, "dev")
	fh, a := c.path(root, "dev", "console")
	if a.typ != typeChr || a.rdev != 0 || a.mode&0o777 != 0o600 {
		t.Errorf("console: %+v", a)
	}
	if _, a = c.path(root, "dev", "sd0a"); a.typ != typeBlk || a.rdev != 7<<8 || a.gid != 5 {
		t.Errorf("sd0a: %+v", a)
	}
	lfh, a := c.path(root, "dev", "stdin")
	res := c.call(NFSProg, NFSVers, procReadlink, (&oncrpc.Encoder{}).Fixed(lfh))
	if st, target := res.Uint32(), res.String(maxPath); a.typ != typeLnk || st != nfsOK || target != "fd/0" {
		t.Errorf("stdin: type %d status %d target %q", a.typ, st, target)
	}
	if names := c.readdir(devfh, 8192); !slices.Equal(names, []string{".", "..", "console", "sd0a", "stdin"}) {
		t.Errorf("readdir /dev: %v", names)
	}
	// Device nodes have no data here.
	res = c.call(NFSProg, NFSVers, procRead, (&oncrpc.Encoder{}).Fixed(fh).Uint32(0).Uint32(100).Uint32(0))
	if st := res.Uint32(); st != errNxio {
		t.Errorf("read of a device: status %d", st)
	}
	// Virtual handles survive a restart.
	s := &Server{files: newFiles()}
	defer s.files.close()
	x, err := s.files.open(filepath.Join(dir, "root"), filepath.Join(dir, "root.mtree"))
	if err != nil {
		t.Fatal(err)
	}
	h, _ := decodeHandle(fh)
	if p, _, err := s.files.resolve(x, h); err != nil || p != "dev/console" {
		t.Errorf("resolve virtual handle: %q, %v", p, err)
	}
}
