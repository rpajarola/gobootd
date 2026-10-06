package nfs

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "nfs" {}
host "kali" {
  ip  = "192.168.1.5"
  mac = "8:0:20:1:2:3"
  export "root" { path = "kali" }
  export "swap" { path = "swap/kali" }
}
host "other" {
  ip  = "192.168.1.6"
  mac = "8:0:20:1:2:4"
  export "root" { path = "other" }
}
`

var (
	ctx    = context.Background()
	server = netip.MustParseAddrPort("192.168.1.1:2049")
)

// big is larger than one NFS read, so reads are fragmented and chunked.
var big = func() []byte {
	b := make([]byte, 20000)
	for i := range b {
		b[i] = byte(i * 13)
	}
	return b
}()

type env struct {
	*prototest.Env
	dir string
	log *prototest.Log
}

func setup(t *testing.T) *env {
	dir := t.TempDir()
	for _, d := range []string{"kali/etc", "kali/bin", "other", "swap"} {
		os.MkdirAll(filepath.Join(dir, d), 0o755)
	}
	os.WriteFile(filepath.Join(dir, "kali/etc/motd"), []byte("hello from bootd\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "kali/bin/sh"), big, 0o755)
	os.Symlink("../etc/motd", filepath.Join(dir, "kali/bin/motd"))
	os.Symlink("/etc/passwd", filepath.Join(dir, "kali/passwd"))
	os.WriteFile(filepath.Join(dir, "other/secret"), []byte("no"), 0o600)
	os.WriteFile(filepath.Join(dir, "swap/kali"), make([]byte, 64*1024), 0o600)
	e := prototest.Setup(t, dir, conf)
	return &env{Env: e, dir: dir, log: e.Start(t, &Server{}, "nfs")}
}

type client struct {
	t *testing.T
	c *oncrpc.Client
}

func (e *env) client(t *testing.T, mac, ip string) *client {
	st := e.Client(t, mac, ip+"/24")
	l, err := st.ListenUDP(800)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return &client{t, &oncrpc.Client{L: l, Timeout: 300 * time.Millisecond, Tries: 3}}
}

func (c *client) call(prog, vers, proc uint32, args *oncrpc.Encoder) *oncrpc.Decoder {
	c.t.Helper()
	res, _, err := c.c.Call(ctx, server, prog, vers, proc, args.Bytes())
	if err != nil {
		c.t.Fatalf("call %d.%d: %v", prog, proc, err)
	}
	return res
}

func (c *client) mount(path string) ([]byte, uint32) {
	res := c.call(MountProg, MountVers, mountMnt, (&oncrpc.Encoder{}).String(path))
	if st := res.Uint32(); st != nfsOK {
		return nil, st
	}
	return res.Fixed(fhSize), nfsOK
}

type attr struct {
	typ, mode, nlink, uid, gid, size, bsize, rdev, blocks, fsid, fileid uint32
}

func decodeAttr(d *oncrpc.Decoder) attr {
	a := attr{d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32(), d.Uint32()}
	for range 6 {
		d.Uint32() // times
	}
	return a
}

func (c *client) lookup(dir []byte, name string) ([]byte, attr, uint32) {
	res := c.call(NFSProg, NFSVers, procLookup, (&oncrpc.Encoder{}).Fixed(dir).String(name))
	if st := res.Uint32(); st != nfsOK {
		return nil, attr{}, st
	}
	return res.Fixed(fhSize), decodeAttr(res), nfsOK
}

func (c *client) path(root []byte, names ...string) ([]byte, attr) {
	c.t.Helper()
	fh, a := root, attr{}
	for _, n := range names {
		var st uint32
		if fh, a, st = c.lookup(fh, n); st != nfsOK {
			c.t.Fatalf("lookup %s: status %d", n, st)
		}
	}
	return fh, a
}

func (c *client) readAll(fh []byte) []byte {
	c.t.Helper()
	var data []byte
	for {
		res := c.call(NFSProg, NFSVers, procRead, (&oncrpc.Encoder{}).Fixed(fh).Uint32(uint32(len(data))).Uint32(maxData).Uint32(0))
		if st := res.Uint32(); st != nfsOK {
			c.t.Fatalf("read: status %d", st)
		}
		decodeAttr(res)
		chunk := res.Opaque(maxData)
		if len(chunk) == 0 {
			return data
		}
		data = append(data, chunk...)
	}
}

func (c *client) readdir(fh []byte, count uint32) []string {
	c.t.Helper()
	var names []string
	cookie := uint32(0)
	for {
		res := c.call(NFSProg, NFSVers, procReaddir, (&oncrpc.Encoder{}).Fixed(fh).Uint32(cookie).Uint32(count))
		if st := res.Uint32(); st != nfsOK {
			c.t.Fatalf("readdir: status %d", st)
		}
		for res.Bool() {
			res.Uint32()
			names = append(names, res.String(maxName))
			cookie = res.Uint32()
		}
		if res.Bool() {
			return names
		}
	}
}

func TestMountAndRead(t *testing.T) {
	e := setup(t)
	c := e.client(t, "08:00:20:01:02:03", "192.168.1.5")
	root, st := c.mount(filepath.Join(e.dir, "kali"))
	if st != nfsOK {
		t.Fatalf("mount: status %d", st)
	}
	fh, a := c.path(root, "etc", "motd")
	if a.typ != typeReg || a.size != 17 || a.mode&0o777 != 0o644 {
		t.Errorf("motd attributes %+v", a)
	}
	if got := c.readAll(fh); string(got) != "hello from bootd\n" {
		t.Errorf("motd = %q", got)
	}
	// 8 KB replies are fragmented by the IP stack.
	fh, _ = c.path(root, "bin", "sh")
	if got := c.readAll(fh); !bytes.Equal(got, big) {
		t.Errorf("read %d bytes, want %d", len(got), len(big))
	}
	// Symlinks are returned, not followed: the client resolves them.
	fh, a = c.path(root, "bin", "motd")
	res := c.call(NFSProg, NFSVers, procReadlink, (&oncrpc.Encoder{}).Fixed(fh))
	if st, target := res.Uint32(), res.String(maxPath); a.typ != typeLnk || st != nfsOK || target != "../etc/motd" {
		t.Errorf("readlink: type %d status %d target %q", a.typ, st, target)
	}
	fh, _ = c.path(root, "passwd")
	if res := c.call(NFSProg, NFSVers, procReadlink, (&oncrpc.Encoder{}).Fixed(fh)); res.Uint32() != nfsOK || res.String(maxPath) != "/etc/passwd" {
		t.Error("readlink of an absolute link")
	}
	// ".." does not leave the export.
	up, a := c.path(root, "..")
	if !bytes.Equal(up, root) || a.typ != typeDir {
		t.Error(`".." of the export is not the export`)
	}
	if _, _, st := c.lookup(root, "../other"); st == nfsOK {
		t.Error("looked up a name with a slash")
	}
	// Small reply buffers make readdir take several calls.
	for _, count := range []uint32{8192, 64} {
		if names := c.readdir(root, count); !slices.Equal(names, []string{".", "..", "bin", "etc", "passwd"}) {
			t.Errorf("readdir with count %d: %v", count, names)
		}
	}
	res = c.call(NFSProg, NFSVers, procStatfs, (&oncrpc.Encoder{}).Fixed(root))
	if st, tsize := res.Uint32(), res.Uint32(); st != nfsOK || tsize != maxData {
		t.Errorf("statfs: status %d tsize %d", st, tsize)
	}
	// Writing is refused.
	res = c.call(NFSProg, NFSVers, procCreate, (&oncrpc.Encoder{}).Fixed(root).String("x"))
	if st := res.Uint32(); st != errRofs {
		t.Errorf("create: status %d, want read-only file system", st)
	}
	if !e.log.Contains("mount " + filepath.Join(e.dir, "kali") + " from kali") {
		t.Error("mount not logged")
	}
}

func TestFileExport(t *testing.T) {
	e := setup(t)
	c := e.client(t, "08:00:20:01:02:03", "192.168.1.5")
	fh, st := c.mount(filepath.Join(e.dir, "swap/kali"))
	if st != nfsOK {
		t.Fatalf("mount swap: status %d", st)
	}
	res := c.call(NFSProg, NFSVers, procGetattr, (&oncrpc.Encoder{}).Fixed(fh))
	if st, a := res.Uint32(), decodeAttr(res); st != nfsOK || a.typ != typeReg || a.size != 64*1024 {
		t.Errorf("swap attributes: status %d %+v", st, a)
	}
	if _, _, st := c.lookup(fh, "x"); st != errNotdir {
		t.Errorf("lookup in a file export: status %d", st)
	}
}

func TestAccess(t *testing.T) {
	e := setup(t)
	kali := e.client(t, "08:00:20:01:02:03", "192.168.1.5")
	other := e.client(t, "08:00:20:01:02:04", "192.168.1.6")
	// Only your own exports can be mounted.
	if _, st := kali.mount(filepath.Join(e.dir, "other")); st != errAcces {
		t.Errorf("kali mounted other's root: status %d", st)
	}
	if _, st := kali.mount(e.dir); st != errAcces {
		t.Errorf("kali mounted the parent of its export: status %d", st)
	}
	// A handle from someone else's export is useless.
	root, _ := kali.mount(filepath.Join(e.dir, "kali"))
	if _, _, st := other.lookup(root, "etc"); st != errStaleCode {
		t.Errorf("other used kali's handle: status %d", st)
	}
	if !e.log.Contains("not exported to this host") || !e.log.Contains("file handle not in its exports") {
		t.Error("denials not logged")
	}
	// Unknown clients get no answer.
	stranger := e.client(t, "08:00:20:01:02:09", "192.168.1.9")
	if _, _, err := stranger.c.Call(ctx, server, MountProg, MountVers, mountMnt, (&oncrpc.Encoder{}).String(e.dir).Bytes()); err == nil {
		t.Error("an unknown client got an answer")
	}
}

// TestRestart: handles stay valid when the handle table is lost.
func TestRestart(t *testing.T) {
	e := setup(t)
	c := e.client(t, "08:00:20:01:02:03", "192.168.1.5")
	root, _ := c.mount(filepath.Join(e.dir, "kali"))
	fh, _ := c.path(root, "etc", "motd")

	s := &Server{files: newFiles()} // a fresh server knows no handles
	defer s.files.close()
	h, _ := decodeHandle(fh)
	x, err := s.files.open(filepath.Join(e.dir, "kali"), "")
	if err != nil {
		t.Fatal(err)
	}
	p, _, err := s.files.resolve(x, h)
	if err != nil || p != "etc/motd" {
		t.Errorf("resolve after restart = %q, %v", p, err)
	}
	os.Remove(filepath.Join(e.dir, "kali/etc/motd"))
	s2 := &Server{files: newFiles()}
	defer s2.files.close()
	x, _ = s2.files.open(filepath.Join(e.dir, "kali"), "")
	if _, _, err := s2.files.resolve(x, h); !errors.Is(err, errStale) {
		t.Errorf("resolve of a removed file = %v, want stale", err)
	}
}

// TestLossy reads through a link that loses fragments: the client's RPC
// retries recover.
func TestLossy(t *testing.T) {
	e := setup(t)
	e.Segment.Impair(linktest.Impairment{Drop: 0.03, Duplicate: 0.03, Reorder: 0.03, Seed: 1})
	c := e.client(t, "08:00:20:01:02:03", "192.168.1.5")
	c.c.Tries = 20
	root, st := c.mount(filepath.Join(e.dir, "kali"))
	if st != nfsOK {
		t.Fatalf("mount: status %d", st)
	}
	fh, _ := c.path(root, "bin", "sh")
	if got := c.readAll(fh); !bytes.Equal(got, big) {
		t.Errorf("read %d bytes, want %d", len(got), len(big))
	}
	t.Logf("%+v", e.Segment.Stats())
}
