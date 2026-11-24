package nfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rpajarola/gobootd/internal/oncrpc"
)

// Writable exports.
//
// Files are created and written on disk. What the disk cannot hold because
// bootd runs without privileges, such as files owned by root, device
// nodes and modes that would lock bootd out, is kept in the export's spec,
// which is saved shortly after it changes. With privileges, owners and
// device nodes are set on disk instead.

// More NFS status codes.
const (
	errExist    = 17
	errFbig     = 27
	errNospc    = 28
	errNotempty = 66
	errDquot    = 69
)

// unset marks a sattr field the client does not set.
const unset = 0xffffffff

// File type bits of a mode.
const (
	sIFMT  = 0o170000
	sIFIFO = 0o010000
	sIFCHR = 0o020000
	sIFDIR = 0o040000
	sIFBLK = 0o060000
	sIFREG = 0o100000
)

// privileged is whether bootd can set owners and make device nodes on
// disk; tests clear it.
var privileged = os.Geteuid() == 0

// saveDelay batches the spec changes of many calls, such as MAKEDEV's,
// into one save.
var saveDelay = time.Second

// sattr is the attributes a client sets.
type sattr struct {
	mode, uid, gid, size uint32
	atime, mtime         time.Time
	setAtime, setMtime   bool
}

func decodeSattr(d *oncrpc.Decoder) sattr {
	a := sattr{mode: d.Uint32(), uid: d.Uint32(), gid: d.Uint32(), size: d.Uint32()}
	a.atime, a.setAtime = decodeTime(d)
	a.mtime, a.setMtime = decodeTime(d)
	return a
}

func decodeTime(d *oncrpc.Decoder) (time.Time, bool) {
	sec, usec := d.Uint32(), d.Uint32()
	switch {
	case sec == unset:
		return time.Time{}, false
	case usec == 1000000: // the server's time, as Solaris asks for it
		return time.Now(), true
	}
	return time.Unix(int64(sec), int64(usec%1000000)*1000), true
}

// owner is the owner of a new file: the one the client sets, or the
// caller's.
func owner(r *request, a sattr) (uid, gid uint32) {
	uid, gid = 65534, 65534
	if r.Cred != nil {
		uid, gid = r.Cred.UID, r.Cred.GID
	}
	if a.uid != unset {
		uid = a.uid
	}
	if a.gid != unset {
		gid = a.gid
	}
	return uid, gid
}

// unixPerm converts the permission bits of an fs.FileMode to Unix ones.
func unixPerm(m fs.FileMode) uint32 {
	p := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		p |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		p |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		p |= 0o1000
	}
	return p
}

// diskPerm is the mode a file gets on disk for the mode a client wants:
// without privileges, bootd keeps the right to read and write it.
func diskPerm(want uint32, dir bool) uint32 {
	switch {
	case privileged:
		return want
	case dir:
		return want | 0o700
	}
	return want | 0o600
}

func typeOf(fi fs.FileInfo) string {
	m := fi.Mode()
	switch {
	case m.IsDir():
		return "dir"
	case m&fs.ModeSymlink != 0:
		return "link"
	case m&fs.ModeNamedPipe != 0:
		return "fifo"
	case m&fs.ModeCharDevice != 0:
		return "char"
	case m&fs.ModeDevice != 0:
		return "block"
	}
	return "file"
}

func isVirtual(fi fs.FileInfo) bool {
	i, ok := fi.(*info)
	return ok && i.virtual
}

// entry returns the spec entry of p, adding one. x.mu must be held.
func (x *export) entry(p, typ string) *specEntry {
	e := x.spec[p]
	if e == nil {
		e = &specEntry{typ: typ}
		x.spec[p] = e
	}
	return e
}

// tidy removes the entry of p if it says nothing. x.mu must be held.
func (x *export) tidy(p string) {
	if e := x.spec[p]; e != nil && e.empty() {
		delete(x.spec, p)
	}
}

// under reports whether k is p or inside it.
func under(k, p string) bool {
	return k == p || p == "." || strings.HasPrefix(k, p+"/")
}

// dropSpec forgets p and everything under it. x.mu must be held.
func (x *export) dropSpec(p string) {
	for k := range x.spec {
		if under(k, p) {
			delete(x.spec, k)
		}
	}
	for k := range x.vinos {
		if under(k, p) {
			delete(x.vinos, k)
		}
	}
	for d := range x.virtual {
		if under(d, p) {
			delete(x.virtual, d)
		}
	}
	x.unlistVirtual(p)
}

func (x *export) listVirtual(p string) {
	dir := path.Dir(p)
	x.virtual[dir] = append(x.virtual[dir], path.Base(p))
}

func (x *export) unlistVirtual(p string) {
	dir, name := path.Dir(p), path.Base(p)
	names := x.virtual[dir]
	for i, n := range names {
		if n == name {
			x.virtual[dir] = append(names[:i:i], names[i+1:]...)
			break
		}
	}
	if len(x.virtual[dir]) == 0 {
		delete(x.virtual, dir)
	}
}

// moveSpec moves what the spec says about from and everything under it
// to to. Virtual files keep their inode numbers. x.mu must be held.
func (x *export) moveSpec(from, to string, virtual bool) {
	x.dropSpec(to)
	moved := func(k string) string { return to + k[len(from):] }
	for k, e := range x.spec {
		if under(k, from) {
			if e.isVirtual() {
				x.vinos[moved(k)] = x.inoOf(k)
			}
			x.spec[moved(k)] = e
			delete(x.spec, k)
		}
	}
	for k := range x.vinos {
		if under(k, from) {
			delete(x.vinos, k)
		}
	}
	for d, names := range x.virtual {
		if under(d, from) {
			x.virtual[moved(d)] = names
			delete(x.virtual, d)
		}
	}
	x.unlistVirtual(from)
	if virtual {
		x.listVirtual(to)
	}
}

// changed schedules saving the spec.
func (x *export) changed() {
	x.dirty = true
	x.saver.schedule(x)
}

// saver saves an export's spec a little after it changes.
type saver struct {
	mu     sync.Mutex
	timer  *time.Timer
	saving sync.Mutex
}

func (s *saver) schedule(x *export) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.timer == nil {
		s.timer = time.AfterFunc(saveDelay, func() { x.save() })
	}
}

// flush saves now what is not saved yet.
func (s *saver) flush(x *export) {
	s.mu.Lock()
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	s.mu.Unlock()
	x.save()
}

// save writes the spec, replacing the file at once.
func (x *export) save() {
	x.saver.saving.Lock()
	defer x.saver.saving.Unlock()
	x.saver.mu.Lock()
	x.saver.timer = nil
	x.saver.mu.Unlock()

	x.mu.Lock()
	if !x.dirty || x.specPath == "" {
		x.mu.Unlock()
		return
	}
	x.dirty = false
	var buf bytes.Buffer
	x.spec.write(&buf)
	x.mu.Unlock()

	tmp := x.specPath + ".tmp"
	err := os.WriteFile(tmp, buf.Bytes(), 0o644)
	if err == nil {
		err = os.Rename(tmp, x.specPath)
	}
	if err != nil {
		os.Remove(tmp)
		x.log.Error(fmt.Sprintf("cannot save the spec of %s; owners, modes and device nodes that clients set are lost on restart", x.path), "spec", x.specPath, "err", err)
		x.mu.Lock()
		x.dirty = true
		x.mu.Unlock()
		return
	}
	x.log.Debug("spec saved", "export", x.path, "spec", x.specPath)
}

// ownerAccess gives bootd the right to read and write p on disk, keeping
// the mode the client sees in the spec.
func (x *export) ownerAccess(p string) {
	rel := x.rel(p)
	fi, err := x.root.Lstat(rel)
	if err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		return
	}
	disk := unixPerm(fi.Mode())
	want := diskPerm(disk, fi.IsDir())
	if want == disk {
		return
	}
	x.mu.Lock()
	if e := x.entry(p, typeOf(fi)); !e.hasMode {
		e.mode, e.hasMode = disk, true
		x.changed()
	}
	x.mu.Unlock()
	x.root.Chmod(rel, goMode(want))
}

// withAccess runs fn, and once more after making the paths accessible to
// bootd if it was refused.
func (x *export) withAccess(fn func() error, paths ...string) error {
	err := fn()
	if err == nil || privileged || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	for _, p := range paths {
		x.ownerAccess(p)
	}
	return fn()
}

// setAttrs gives p a mode, owner and group (unset leaves them): on disk
// where it can, in the spec where it cannot.
func (x *export) setAttrs(p string, mode, uid, gid uint32) error {
	fi, err := x.lstat(p)
	if err != nil {
		return err
	}
	if isVirtual(fi) {
		x.mu.Lock()
		defer x.mu.Unlock()
		e := x.spec[p]
		if e == nil {
			return fs.ErrNotExist
		}
		if mode != unset {
			e.mode, e.hasMode = mode&0o7777, true
		}
		if uid != unset {
			e.uid, e.hasUID = uid, true
		}
		if gid != unset {
			e.gid, e.hasGID = gid, true
		}
		x.changed()
		return nil
	}
	rel := x.rel(p)
	typ := typeOf(fi)
	if uid != unset || gid != unset {
		cu, cg := -1, -1
		if uid != unset {
			cu = int(uid)
		}
		if gid != unset {
			cg = int(gid)
		}
		err := x.root.Lchown(rel, cu, cg)
		if err != nil && !errors.Is(err, fs.ErrPermission) {
			return err
		}
		x.mu.Lock()
		e := x.entry(p, typ)
		if uid != unset {
			e.uid, e.hasUID = uid, err != nil
		}
		if gid != unset {
			e.gid, e.hasGID = gid, err != nil
		}
		x.tidy(p)
		x.changed()
		x.mu.Unlock()
	}
	if mode != unset && typ != "link" {
		want := mode & 0o7777
		if err := x.root.Chmod(rel, goMode(diskPerm(want, typ == "dir"))); err != nil {
			return err
		}
		nfi, err := x.root.Lstat(rel)
		if err != nil {
			return err
		}
		x.mu.Lock()
		e := x.entry(p, typ)
		e.mode, e.hasMode = want, unixPerm(nfi.Mode()) != want
		x.tidy(p)
		x.changed()
		x.mu.Unlock()
	}
	return nil
}

// apply sets what a SETATTR or CREATE of an existing file asks for.
func (x *export) apply(p string, fi fs.FileInfo, a sattr) error {
	rel := x.rel(p)
	if a.size != unset && !isVirtual(fi) {
		if fi.IsDir() {
			return syscall.EISDIR
		}
		var f *os.File
		err := x.withAccess(func() (err error) {
			f, err = x.root.OpenFile(rel, os.O_WRONLY, 0)
			return err
		}, p)
		if err != nil {
			return err
		}
		err = f.Truncate(int64(a.size))
		f.Close()
		if err != nil {
			return err
		}
	}
	if err := x.setAttrs(p, a.mode, a.uid, a.gid); err != nil {
		return err
	}
	if !a.setAtime && !a.setMtime {
		return nil
	}
	if isVirtual(fi) {
		if a.setMtime {
			x.mu.Lock()
			if e := x.spec[p]; e != nil {
				e.mtime, e.hasTime = a.mtime, true
				x.changed()
			}
			x.mu.Unlock()
		}
		return nil
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil // Chtimes would follow it
	}
	at, mt := a.atime, a.mtime
	if !a.setAtime {
		at = statOf(fi).atime
	}
	if !a.setMtime {
		mt = fi.ModTime()
	}
	return x.withAccess(func() error { return x.root.Chtimes(rel, at, mt) }, p)
}

// attrstat is the reply of a call that returns a file's attributes.
func attrstat(x *export, p string) []byte {
	e := &oncrpc.Encoder{}
	fi, err := x.lstat(p)
	if err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	e.Uint32(nfsOK)
	fattr(e, x, fi)
	return e.Bytes()
}

// diropres is the reply of a call that returns a handle and attributes.
func (s *Server) diropres(x *export, p string) []byte {
	e := &oncrpc.Encoder{}
	h, fi, err := s.files.handleFor(x, p)
	if err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	e.Uint32(nfsOK).Fixed(h.encode())
	fattr(e, x, fi)
	return e.Bytes()
}

func statusOnly(err error) []byte {
	st := uint32(nfsOK)
	if err != nil {
		st = status(err)
	}
	return (&oncrpc.Encoder{}).Uint32(st).Bytes()
}

// dirop decodes a directory and a name in it, for a call that changes the
// directory.
func (s *Server) dirop(r *request) (*export, string, uint32) {
	x, dir, fi, st := s.file(r)
	name := r.Args.String(maxName)
	switch {
	case st != nfsOK:
		return nil, "", st
	case !r.writable:
		return nil, "", errRofs
	case !fi.IsDir() || x.file != "":
		return nil, "", errNotdir
	case name == "." || name == "..":
		return nil, "", errAcces
	}
	p, ok := join(dir, name)
	if !ok {
		return nil, "", errAcces
	}
	return x, p, nfsOK
}

func (s *Server) setattr(r *request) []byte {
	x, p, fi, st := s.file(r)
	a := decodeSattr(r.Args)
	switch {
	case st != nfsOK:
		return statusOnly(statusErr(st))
	case !r.writable:
		return statusOnly(statusErr(errRofs))
	}
	if err := x.apply(p, fi, a); err != nil {
		r.log.Debug("nfs setattr failed", "path", p, "err", err)
		return statusOnly(err)
	}
	return attrstat(x, p)
}

func (s *Server) write(r *request) []byte {
	x, p, fi, st := s.file(r)
	r.Args.Uint32() // beginoffset, unused
	offset := r.Args.Uint32()
	r.Args.Uint32() // totalcount, unused
	data := r.Args.Opaque(maxData)
	switch {
	case st != nfsOK:
		return statusOnly(statusErr(st))
	case !r.writable:
		return statusOnly(statusErr(errRofs))
	case fi.IsDir():
		return statusOnly(statusErr(errIsdir))
	case !fi.Mode().IsRegular():
		return statusOnly(statusErr(errNxio))
	}
	var f *os.File
	err := x.withAccess(func() (err error) {
		f, err = x.root.OpenFile(x.rel(p), os.O_WRONLY, 0)
		return err
	}, p)
	if err == nil {
		_, err = f.WriteAt(data, int64(offset))
		if err == nil && s.opts.Sync {
			err = f.Sync()
		}
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		r.log.Debug("nfs write failed", "path", p, "err", err)
		return statusOnly(err)
	}
	return attrstat(x, p)
}

func (s *Server) create(r *request) []byte {
	x, p, st := s.dirop(r)
	a := decodeSattr(r.Args)
	if st != nfsOK {
		return statusOnly(statusErr(st))
	}
	uid, gid := owner(r, a)
	perm := uint32(0o644)
	typ := uint32(sIFREG)
	if a.mode != unset {
		perm = a.mode & 0o7777
		if t := a.mode & sIFMT; t != 0 {
			typ = t
		}
	}
	var err error
	switch typ {
	case sIFCHR, sIFBLK, sIFIFO:
		// NFSv2 sends the device number in the size, and a fifo as a
		// character device numbered -1.
		kind := map[uint32]string{sIFCHR: "char", sIFBLK: "block", sIFIFO: "fifo"}[typ]
		if typ == sIFCHR && a.size == unset {
			kind = "fifo"
		}
		err = x.mknod(p, kind, perm, a.size, uid, gid)
	case sIFREG:
		err = x.createFile(p, a, perm, uid, gid)
	default:
		err = syscall.EINVAL
	}
	if err != nil {
		r.log.Debug("nfs create failed", "path", p, "err", err)
		return statusOnly(err)
	}
	r.log.Debug(fmt.Sprintf("nfs create %s by %s", p, r.host.Name))
	return s.diropres(x, p)
}

func (x *export) createFile(p string, a sattr, perm, uid, gid uint32) error {
	if fi, err := x.lstat(p); err == nil {
		// Creating an existing file truncates it, if asked to.
		if !fi.Mode().IsRegular() {
			return fs.ErrExist
		}
		return x.apply(p, fi, a)
	}
	rel := x.rel(p)
	err := x.withAccess(func() error {
		f, err := x.root.OpenFile(rel, os.O_WRONLY|os.O_CREATE|os.O_EXCL, goMode(diskPerm(perm, false)))
		if err == nil {
			f.Close()
		}
		return err
	}, path.Dir(p))
	if err != nil {
		return err
	}
	x.mu.Lock()
	x.dropSpec(p) // left over from a file that was removed outside
	x.mu.Unlock()
	a.size = unset
	a.mode, a.uid, a.gid = perm, uid, gid
	fi, err := x.lstat(p)
	if err != nil {
		return err
	}
	return x.apply(p, fi, a)
}

// mknod makes a device node or fifo: on disk if bootd may, in the spec
// otherwise.
func (x *export) mknod(p, kind string, perm, rdev, uid, gid uint32) error {
	if _, err := x.lstat(p); err == nil {
		return fs.ErrExist
	}
	major, minor := (rdev>>8)&0xfff, rdev&0xff|(rdev>>12)&0xfff00
	if kind == "fifo" || privileged {
		mode := map[string]uint32{"char": syscall.S_IFCHR, "block": syscall.S_IFBLK, "fifo": syscall.S_IFIFO}[kind]
		err := x.withAccess(func() error {
			d, err := x.root.Open(path.Dir(p))
			if err != nil {
				return err
			}
			defer d.Close()
			return mknodAt(d, path.Base(p), mode|diskPerm(perm, false), major, minor)
		}, path.Dir(p))
		switch {
		case err == nil:
			return x.setAttrs(p, perm, uid, gid)
		case !errors.Is(err, fs.ErrPermission) && !errors.Is(err, errors.ErrUnsupported):
			return err
		}
	}
	// The directory must exist on disk to hold a virtual file.
	if fi, err := x.root.Stat(path.Dir(p)); err != nil || !fi.IsDir() {
		return syscall.ENOTDIR
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.dropSpec(p)
	x.spec[p] = &specEntry{typ: kind, mode: perm, hasMode: true, uid: uid, hasUID: true, gid: gid, hasGID: true,
		major: major, minor: minor, mtime: time.Now(), hasTime: true}
	x.listVirtual(p)
	x.changed()
	return nil
}

func (s *Server) mkdir(r *request) []byte {
	x, p, st := s.dirop(r)
	a := decodeSattr(r.Args)
	if st != nfsOK {
		return statusOnly(statusErr(st))
	}
	uid, gid := owner(r, a)
	perm := uint32(0o755)
	if a.mode != unset {
		perm = a.mode & 0o7777
	}
	if _, err := x.lstat(p); err == nil {
		return statusOnly(fs.ErrExist)
	}
	err := x.withAccess(func() error { return x.root.Mkdir(p, goMode(diskPerm(perm, true))) }, path.Dir(p))
	if err == nil {
		x.mu.Lock()
		x.dropSpec(p)
		x.mu.Unlock()
		a.size, a.mode, a.uid, a.gid = unset, perm, uid, gid
		var fi fs.FileInfo
		if fi, err = x.lstat(p); err == nil {
			err = x.apply(p, fi, a)
		}
	}
	if err != nil {
		r.log.Debug("nfs mkdir failed", "path", p, "err", err)
		return statusOnly(err)
	}
	r.log.Debug(fmt.Sprintf("nfs mkdir %s by %s", p, r.host.Name))
	return s.diropres(x, p)
}

func (s *Server) symlink(r *request) []byte {
	x, p, st := s.dirop(r)
	target := r.Args.String(maxPath)
	a := decodeSattr(r.Args)
	if st != nfsOK {
		return statusOnly(statusErr(st))
	}
	if _, err := x.lstat(p); err == nil {
		return statusOnly(fs.ErrExist)
	}
	if strings.ContainsRune(target, 0) || target == "" {
		return statusOnly(statusErr(errAcces))
	}
	err := x.withAccess(func() error { return x.root.Symlink(target, p) }, path.Dir(p))
	if err == nil {
		x.mu.Lock()
		x.dropSpec(p)
		x.mu.Unlock()
		uid, gid := owner(r, a)
		err = x.setAttrs(p, unset, uid, gid)
	}
	if err != nil {
		r.log.Debug("nfs symlink failed", "path", p, "err", err)
	}
	return statusOnly(err)
}

func (s *Server) link(r *request) []byte {
	x, from, fi, st := s.file(r)
	writable := r.writable
	tx, p, tst := s.dirop(r)
	switch {
	case st != nfsOK:
		return statusOnly(statusErr(st))
	case tst != nfsOK:
		return statusOnly(statusErr(tst))
	case !writable:
		return statusOnly(statusErr(errRofs))
	case tx != x:
		return statusOnly(statusErr(errAcces))
	case fi.IsDir():
		return statusOnly(statusErr(errPerm))
	}
	if _, err := x.lstat(p); err == nil {
		return statusOnly(fs.ErrExist)
	}
	if !isVirtual(fi) {
		if err := x.withAccess(func() error { return x.root.Link(x.rel(from), p) }, path.Dir(p)); err != nil {
			r.log.Debug("nfs link failed", "from", from, "path", p, "err", err)
			return statusOnly(err)
		}
	}
	x.mu.Lock()
	x.dropSpec(p)
	if e := x.spec[from]; e != nil {
		c := *e
		x.spec[p] = &c
		if e.isVirtual() {
			x.listVirtual(p)
		}
		x.changed()
	}
	x.mu.Unlock()
	return statusOnly(nil)
}

func (s *Server) remove(r *request) []byte {
	x, p, st := s.dirop(r)
	if st != nfsOK {
		return statusOnly(statusErr(st))
	}
	fi, err := x.lstat(p)
	switch {
	case err != nil:
		return statusOnly(err)
	case fi.IsDir():
		return statusOnly(statusErr(errIsdir))
	case !isVirtual(fi):
		if err := x.withAccess(func() error { return x.root.Remove(p) }, path.Dir(p)); err != nil {
			r.log.Debug("nfs remove failed", "path", p, "err", err)
			return statusOnly(err)
		}
	}
	x.mu.Lock()
	if _, ok := x.spec[p]; ok {
		x.dropSpec(p)
		x.changed()
	}
	x.mu.Unlock()
	r.log.Debug(fmt.Sprintf("nfs remove %s by %s", p, r.host.Name))
	return statusOnly(nil)
}

func (s *Server) rmdir(r *request) []byte {
	x, p, st := s.dirop(r)
	if st != nfsOK {
		return statusOnly(statusErr(st))
	}
	fi, err := x.lstat(p)
	switch {
	case err != nil:
		return statusOnly(err)
	case !fi.IsDir():
		return statusOnly(statusErr(errNotdir))
	}
	x.mu.RLock()
	full := len(x.virtual[p]) > 0
	x.mu.RUnlock()
	if full {
		return statusOnly(statusErr(errNotempty))
	}
	if err := x.withAccess(func() error { return x.root.Remove(p) }, path.Dir(p)); err != nil {
		r.log.Debug("nfs rmdir failed", "path", p, "err", err)
		return statusOnly(err)
	}
	x.mu.Lock()
	x.dropSpec(p)
	x.changed()
	x.mu.Unlock()
	r.log.Debug(fmt.Sprintf("nfs rmdir %s by %s", p, r.host.Name))
	return statusOnly(nil)
}

func (s *Server) rename(r *request) []byte {
	x, from, st := s.dirop(r)
	tx, to, tst := s.dirop(r)
	switch {
	case st != nfsOK:
		return statusOnly(statusErr(st))
	case tst != nfsOK:
		return statusOnly(statusErr(tst))
	case tx != x:
		return statusOnly(statusErr(errAcces))
	}
	fi, err := x.lstat(from)
	if err != nil {
		return statusOnly(err)
	}
	if from == to {
		return statusOnly(nil)
	}
	if under(to, from) {
		return statusOnly(syscall.EINVAL) // into itself
	}
	tfi, terr := x.lstat(to)
	if terr == nil {
		switch {
		case fi.IsDir() && !tfi.IsDir():
			return statusOnly(statusErr(errNotdir))
		case !fi.IsDir() && tfi.IsDir():
			return statusOnly(statusErr(errIsdir))
		}
	}
	parents := []string{path.Dir(from), path.Dir(to)}
	if fi.IsDir() {
		parents = append(parents, from) // for its ".."
	}
	switch {
	case !isVirtual(fi):
		err = x.withAccess(func() error { return x.root.Rename(from, to) }, parents...)
	case terr == nil && !isVirtual(tfi):
		// A virtual file replaces one on disk.
		err = x.withAccess(func() error { return x.root.Remove(to) }, path.Dir(to))
	}
	if err != nil {
		r.log.Debug("nfs rename failed", "from", from, "to", to, "err", err)
		return statusOnly(err)
	}
	x.mu.Lock()
	x.moveSpec(from, to, isVirtual(fi))
	x.changed()
	x.mu.Unlock()
	s.files.moved(x, from, to)
	r.log.Debug(fmt.Sprintf("nfs rename %s to %s by %s", from, to, r.host.Name))
	return statusOnly(nil)
}

// moved updates the remembered paths of handles after a rename.
func (t *files) moved(x *export, from, to string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for h, p := range t.paths {
		if h.export == x.id && under(p, from) {
			t.paths[h] = to + p[len(from):]
		}
	}
}

// statusErr wraps an NFS status as an error, for statusOnly.
type statusErr uint32

func (e statusErr) Error() string { return fmt.Sprintf("nfs status %d", uint32(e)) }

// drc is a duplicate request cache: a call that is retransmitted after it
// changed something gets the first reply again instead of an error, such
// as "no such file" for a REMOVE that already happened.
type drc struct {
	mu    sync.Mutex
	calls map[drcKey]*drcEntry
	order []drcKey
}

type drcKey struct {
	from string
	xid  uint32
}

type drcEntry struct {
	done bool
	res  []byte
}

const drcSize = 1024

// do runs fn for a call it has not seen yet, and returns the earlier
// reply otherwise. A call still running is not answered twice.
func (d *drc) do(c *oncrpc.Call, fn func() ([]byte, error)) ([]byte, error) {
	k := drcKey{c.From.String(), c.XID}
	d.mu.Lock()
	if d.calls == nil {
		d.calls = map[drcKey]*drcEntry{}
	}
	if e, ok := d.calls[k]; ok {
		d.mu.Unlock()
		if !e.done {
			return nil, oncrpc.ErrDrop
		}
		return e.res, nil
	}
	e := &drcEntry{}
	d.calls[k] = e
	d.order = append(d.order, k)
	if len(d.order) > drcSize {
		delete(d.calls, d.order[0])
		d.order = d.order[1:]
	}
	d.mu.Unlock()

	res, err := fn()
	d.mu.Lock()
	if err != nil {
		delete(d.calls, k)
	} else {
		e.res, e.done = res, true
	}
	d.mu.Unlock()
	return res, err
}
