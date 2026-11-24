package nfs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const writableConf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0"
}
service "nfs" {}
host "kali" {
  ip  = "192.168.1.5"
  mac = "8:0:20:1:2:3"
  export "root" {
    path     = "kali"
    writable = true
  }
  export "swap" {
    path     = "swap/kali"
    writable = true
  }
}
`

func sattrArgs(e *oncrpc.Encoder, mode, uid, gid, size uint32) *oncrpc.Encoder {
	return e.Uint32(mode).Uint32(uid).Uint32(gid).Uint32(size).Uint32(unset).Uint32(unset).Uint32(unset).Uint32(unset)
}

type wenv struct {
	*prototest.Env
	dir string
	log *prototest.Log
	c   *client
	// root is the handle of kali's root export.
	root []byte
}

func setupWritable(t *testing.T) *wenv {
	privileged = false
	saveDelay = 10 * time.Millisecond
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "kali/etc"), 0o755)
	os.MkdirAll(filepath.Join(dir, "kali/bin"), 0o555) // as tar extracts it
	os.MkdirAll(filepath.Join(dir, "swap"), 0o755)
	os.WriteFile(filepath.Join(dir, "kali/etc/motd"), []byte("hello\n"), 0o444)
	os.WriteFile(filepath.Join(dir, "swap/kali"), make([]byte, 64*1024), 0o600)
	t.Cleanup(func() { os.Chmod(filepath.Join(dir, "kali/bin"), 0o755) })
	e := prototest.Setup(t, dir, writableConf)
	w := &wenv{Env: e, dir: dir, log: e.Start(t, &Server{}, "nfs")}
	w.c = w.client(t)
	var st uint32
	if w.root, st = w.c.mount(filepath.Join(dir, "kali")); st != nfsOK {
		t.Fatalf("mount: status %d", st)
	}
	return w
}

func (w *wenv) client(t *testing.T) *client {
	e := &env{Env: w.Env, dir: w.dir, log: w.log}
	return e.client(t, "08:00:20:01:02:03", "192.168.1.5")
}

// do calls an NFS procedure and returns its status and the rest.
func (c *client) do(proc uint32, args *oncrpc.Encoder) (uint32, *oncrpc.Decoder) {
	c.t.Helper()
	res := c.call(NFSProg, NFSVers, proc, args)
	return res.Uint32(), res
}

func (c *client) create(dir []byte, name string, mode, size uint32) ([]byte, attr, uint32) {
	c.t.Helper()
	st, res := c.do(procCreate, sattrArgs((&oncrpc.Encoder{}).Fixed(dir).String(name), mode, unset, unset, size))
	if st != nfsOK {
		return nil, attr{}, st
	}
	return res.Fixed(fhSize), decodeAttr(res), st
}

func (c *client) getattr(fh []byte) (attr, uint32) {
	c.t.Helper()
	st, res := c.do(procGetattr, (&oncrpc.Encoder{}).Fixed(fh))
	if st != nfsOK {
		return attr{}, st
	}
	return decodeAttr(res), st
}

func (c *client) setattr(fh []byte, mode, uid, gid, size uint32) (attr, uint32) {
	c.t.Helper()
	st, res := c.do(procSetattr, sattrArgs((&oncrpc.Encoder{}).Fixed(fh), mode, uid, gid, size))
	if st != nfsOK {
		return attr{}, st
	}
	return decodeAttr(res), st
}

func (c *client) write(fh []byte, off uint32, data []byte) uint32 {
	c.t.Helper()
	st, _ := c.do(procWrite, (&oncrpc.Encoder{}).Fixed(fh).Uint32(0).Uint32(off).Uint32(0).Opaque(data))
	return st
}

func (c *client) dirop(proc uint32, dir []byte, name string) uint32 {
	c.t.Helper()
	st, _ := c.do(proc, (&oncrpc.Encoder{}).Fixed(dir).String(name))
	return st
}

// spec waits for the saved spec to contain all of want.
func (w *wenv) spec(t *testing.T, want ...string) string {
	t.Helper()
	var s string
	for range 100 {
		b, _ := os.ReadFile(filepath.Join(w.dir, "kali.mtree"))
		s = string(b)
		if !slices.ContainsFunc(want, func(x string) bool { return !strings.Contains(s, x) }) {
			return s
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("spec lacks %q:\n%s", want, s)
	return s
}

// specWithout waits for the saved spec to lack gone.
func (w *wenv) specWithout(t *testing.T, gone string) {
	t.Helper()
	var s string
	for range 100 {
		b, _ := os.ReadFile(filepath.Join(w.dir, "kali.mtree"))
		if s = string(b); !strings.Contains(s, gone) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("spec still has %q:\n%s", gone, s)
}

func TestCreateWrite(t *testing.T) {
	w := setupWritable(t)
	c := w.c
	etc, _ := c.path(w.root, "etc")
	fh, a, st := c.create(etc, "passwd", sIFREG|0o600, unset)
	if st != nfsOK || a.typ != typeReg || a.mode&0o7777 != 0o600 || a.uid != 0 || a.gid != 0 {
		t.Fatalf("create: status %d %+v", st, a)
	}
	// 8 KB writes are fragmented.
	for off := 0; off < len(big); off += maxData {
		if st := c.write(fh, uint32(off), big[off:min(off+maxData, len(big))]); st != nfsOK {
			t.Fatalf("write at %d: status %d", off, st)
		}
	}
	if got, _ := os.ReadFile(filepath.Join(w.dir, "kali/etc/passwd")); !bytes.Equal(got, big) {
		t.Errorf("on disk: %d bytes", len(got))
	}
	if got := c.readAll(fh); !bytes.Equal(got, big) {
		t.Errorf("read back %d bytes", len(got))
	}
	if a, st := c.setattr(fh, unset, unset, unset, 10); st != nfsOK || a.size != 10 {
		t.Errorf("truncate: status %d size %d", st, a.size)
	}
	// Owned by root for the client, by bootd on disk.
	w.spec(t, "./etc/passwd type=file uid=0 gid=0")
	if fi, _ := os.Stat(filepath.Join(w.dir, "kali/etc/passwd")); statOf(fi).uid != uint32(os.Getuid()) {
		t.Error("the file is not bootd's on disk")
	}
	// A mode that would lock bootd out is kept in the spec.
	if a, st := c.setattr(fh, 0o4555, 3, 4, unset); st != nfsOK || a.mode&0o7777 != 0o4555 || a.uid != 3 || a.gid != 4 {
		t.Errorf("setattr: status %d %+v", st, a)
	}
	if st := c.write(fh, 0, []byte("x")); st != nfsOK {
		t.Errorf("write to a 0555 file: status %d", st)
	}
	w.spec(t, "./etc/passwd type=file mode=4555 uid=3 gid=4")

	// Files from the start: bootd gives itself the right to write
	// them, and keeps their mode.
	motd, _ := c.path(w.root, "etc", "motd")
	if st := c.write(motd, 0, []byte("H")); st != nfsOK {
		t.Errorf("write to a 0444 file: status %d", st)
	}
	if a, _ := c.getattr(motd); a.mode&0o777 != 0o444 {
		t.Errorf("motd mode %o", a.mode&0o777)
	}
	bin, _ := c.path(w.root, "bin")
	if _, _, st := c.create(bin, "sh", 0o755, unset); st != nfsOK {
		t.Errorf("create in a 0555 directory: status %d", st)
	}
	if a, _ := c.getattr(bin); a.mode&0o777 != 0o555 {
		t.Errorf("bin mode %o", a.mode&0o777)
	}
	// Creating an existing file truncates it.
	if _, a, st := c.create(etc, "passwd", 0o600, 0); st != nfsOK || a.size != 0 {
		t.Errorf("create existing: status %d size %d", st, a.size)
	}
}

func TestDirectories(t *testing.T) {
	w := setupWritable(t)
	c := w.c
	st, res := c.do(procMkdir, sattrArgs((&oncrpc.Encoder{}).Fixed(w.root).String("usr"), 0o755, unset, unset, unset))
	if st != nfsOK {
		t.Fatalf("mkdir: status %d", st)
	}
	usr := res.Fixed(fhSize)
	if st, _ := c.do(procMkdir, sattrArgs((&oncrpc.Encoder{}).Fixed(w.root).String("usr"), 0o755, unset, unset, unset)); st != errExist {
		t.Errorf("mkdir again: status %d", st)
	}
	if _, _, st := c.create(usr, "file", 0o644, unset); st != nfsOK {
		t.Fatal(st)
	}
	// symlink
	st, _ = c.do(procSymlink, sattrArgs((&oncrpc.Encoder{}).Fixed(usr).String("lnk").String("/etc/motd"), 0o777, unset, unset, unset))
	if st != nfsOK {
		t.Fatalf("symlink: status %d", st)
	}
	lnk, a := c.path(w.root, "usr", "lnk")
	res = c.call(NFSProg, NFSVers, procReadlink, (&oncrpc.Encoder{}).Fixed(lnk))
	if st, target := res.Uint32(), res.String(maxPath); st != nfsOK || target != "/etc/motd" || a.typ != typeLnk {
		t.Errorf("readlink: %d %q", st, target)
	}
	// link
	file, _ := c.path(w.root, "usr", "file")
	if st, _ := c.do(procLink, (&oncrpc.Encoder{}).Fixed(file).Fixed(usr).String("hard")); st != nfsOK {
		t.Errorf("link: status %d", st)
	}
	if a, _ := c.getattr(file); a.nlink != 2 {
		t.Errorf("nlink %d", a.nlink)
	}
	// A directory with files is not removed.
	if st := c.dirop(procRmdir, w.root, "usr"); st != errNotempty {
		t.Errorf("rmdir of a full directory: status %d", st)
	}
	// Renaming a directory moves the spec entries under it, and its
	// handles stay valid.
	if st, _ := c.do(procRename, (&oncrpc.Encoder{}).Fixed(w.root).String("usr").Fixed(w.root).String("opt")); st != nfsOK {
		t.Fatalf("rename: status %d", st)
	}
	if a, st := c.getattr(file); st != nfsOK || a.uid != 0 {
		t.Errorf("handle after rename: status %d %+v", st, a)
	}
	w.spec(t, "./opt/file type=file", "./opt type=dir")
	w.specWithout(t, "./usr")
	for _, n := range []string{"file", "hard", "lnk"} {
		if st := c.dirop(procRemove, usr, n); st != nfsOK {
			t.Errorf("remove %s: status %d", n, st)
		}
	}
	if st := c.dirop(procRemove, w.root, "opt"); st != errIsdir {
		t.Errorf("remove of a directory: status %d", st)
	}
	if st := c.dirop(procRmdir, w.root, "opt"); st != nfsOK {
		t.Errorf("rmdir: status %d", st)
	}
	if names := c.readdir(w.root, 8192); !slices.Equal(names, []string{".", "..", "bin", "etc"}) {
		t.Errorf("readdir: %v", names)
	}
	w.specWithout(t, "./opt")
}

func TestDevices(t *testing.T) {
	w := setupWritable(t)
	c := w.c
	if st, _ := c.do(procMkdir, sattrArgs((&oncrpc.Encoder{}).Fixed(w.root).String("dev"), 0o755, unset, unset, unset)); st != nfsOK {
		t.Fatal(st)
	}
	dev, _ := c.path(w.root, "dev")
	// MAKEDEV: mknod sd0a b 7 0, then a fifo.
	fh, a, st := c.create(dev, "sd0a", sIFBLK|0o640, rdev(7, 0))
	if st != nfsOK || a.typ != typeBlk || a.rdev != rdev(7, 0) || a.mode&0o7777 != 0o640 {
		t.Fatalf("mknod: status %d %+v", st, a)
	}
	if _, a, st := c.create(dev, "fifo", sIFCHR|0o600, unset); st != nfsOK || a.typ != typeChr || a.mode&sIFMT != sIFIFO {
		t.Errorf("mkfifo: status %d %+v", st, a)
	}
	if _, _, st := c.create(dev, "sd0a", sIFBLK|0o640, rdev(7, 0)); st != errExist {
		t.Errorf("mknod again: status %d", st)
	}
	if names := c.readdir(dev, 8192); !slices.Equal(names, []string{".", "..", "fifo", "sd0a"}) {
		t.Errorf("readdir: %v", names)
	}
	w.spec(t, "./dev/sd0a type=block mode=640 uid=0 gid=0 device=native,7,0")
	// The handle survives a rename and a chown.
	if st, _ := c.do(procRename, (&oncrpc.Encoder{}).Fixed(dev).String("sd0a").Fixed(dev).String("disk")); st != nfsOK {
		t.Fatalf("rename: status %d", st)
	}
	if a, st := c.setattr(fh, unset, 5, unset, unset); st != nfsOK || a.uid != 5 || a.typ != typeBlk {
		t.Errorf("setattr after rename: status %d %+v", st, a)
	}
	w.spec(t, "./dev/disk type=block mode=640 uid=5 gid=0 device=native,7,0")
	if st := c.dirop(procRmdir, w.root, "dev"); st != errNotempty {
		t.Errorf("rmdir with devices: status %d", st)
	}
	if st := c.dirop(procRemove, dev, "disk"); st != nfsOK {
		t.Errorf("remove: status %d", st)
	}
	if _, st := c.getattr(fh); st != errStaleCode {
		t.Errorf("getattr of a removed device: status %d", st)
	}

	// A new server finds the devices in the saved spec.
	w.spec(t, "./dev/fifo type=fifo")
	s := &Server{files: newFiles()}
	defer s.files.close()
	x, err := s.files.open(filepath.Join(w.dir, "kali"), filepath.Join(w.dir, "kali.mtree"))
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := x.lstat("dev/fifo"); err != nil || typeOf(fi) != "fifo" || statOf(fi).uid != 0 {
		t.Errorf("after restart: %v", err)
	}
}

func TestSwapWrite(t *testing.T) {
	w := setupWritable(t)
	fh, st := w.c.mount(filepath.Join(w.dir, "swap/kali"))
	if st != nfsOK {
		t.Fatal(st)
	}
	if st := w.c.write(fh, 4096, []byte("page")); st != nfsOK {
		t.Fatalf("write: status %d", st)
	}
	b, _ := os.ReadFile(filepath.Join(w.dir, "swap/kali"))
	if string(b[4096:4100]) != "page" || len(b) != 64*1024 {
		t.Error("swap not written")
	}
	if st := w.c.dirop(procRemove, fh, "x"); st != errNotdir {
		t.Errorf("remove in a file export: status %d", st)
	}
}

// TestRetransmit: a REMOVE that is sent again gets the first answer, not
// "no such file".
func TestRetransmit(t *testing.T) {
	w := setupWritable(t)
	etc, _ := w.c.path(w.root, "etc")
	args := (&oncrpc.Encoder{}).Fixed(etc).String("motd").Bytes()
	call := oncrpc.EncodeCall(4242, NFSProg, NFSVers, procRemove, nil, args)
	l := w.c.c.L
	for i := range 2 {
		if err := l.WriteTo(call, server); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		d, err := l.Read(ctx)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		_, res, err := oncrpc.DecodeReply(d.Data)
		if err != nil {
			t.Fatal(err)
		}
		if st := res.Uint32(); st != nfsOK {
			t.Errorf("try %d: status %d", i, st)
		}
	}
	if _, err := os.Stat(filepath.Join(w.dir, "kali/etc/motd")); !os.IsNotExist(err) {
		t.Error("not removed")
	}
}
