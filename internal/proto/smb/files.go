package smb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"
	"syscall"
	"time"
)

// file is an open file.
type file struct {
	fid   uint16
	tid   uint16
	pid   uint16
	f     *os.File
	rel   string
	write bool
	pos   int64
	t     *tree
}

// Access modes.
const (
	accessRead      = 0
	accessWrite     = 1
	accessReadWrite = 2
	accessExecute   = 3
	accessFCB       = 7
)

func (c *conn) file(r *request, fid uint16) (*file, error) {
	if r.chained && c.chainFID != 0 {
		fid = c.chainFID
	}
	f := c.files[fid]
	if f == nil || f.tid != r.tid {
		return nil, errBadFid
	}
	return f, nil
}

// openFlags maps an access mode to open flags, refusing writes to a
// read-only share. FCB opens get what the share allows.
func openFlags(t *tree, access uint16) (int, uint16, error) {
	switch access & 7 {
	case accessRead, accessExecute:
		return os.O_RDONLY, access & 7, nil
	case accessWrite:
		if !t.writable {
			return 0, 0, errNoAccess
		}
		return os.O_WRONLY, accessWrite, nil
	case accessReadWrite:
		if !t.writable {
			return 0, 0, errNoAccess
		}
		return os.O_RDWR, accessReadWrite, nil
	case accessFCB:
		if t.writable {
			return os.O_RDWR, accessReadWrite, nil
		}
		return os.O_RDONLY, accessRead, nil
	}
	return 0, 0, errBadAccess
}

// newFile opens rel and gives it a FID.
func (c *conn) newFile(r *request, t *tree, rel string, flags int) (*file, fs.FileInfo, error) {
	if len(c.files) >= maxFiles {
		return nil, nil, errNoFids
	}
	if fi, err := t.root.Stat(rel); err == nil && fi.IsDir() {
		return nil, nil, errNoAccess
	}
	fd, err := t.root.OpenFile(rel, flags, 0o666)
	if err != nil {
		return nil, nil, err
	}
	fi, err := fd.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		fd.Close()
		return nil, nil, errNoAccess
	}
	for {
		c.nextFID++
		if c.nextFID != 0 && c.nextFID != 0xffff && c.files[c.nextFID] == nil {
			break
		}
	}
	f := &file{fid: c.nextFID, tid: t.tid, pid: r.pid, f: fd, rel: rel, write: flags&(os.O_WRONLY|os.O_RDWR) != 0, t: t}
	c.files[f.fid] = f
	c.log.Debug("smb open", "share", t.name, "file", rel, "fid", f.fid, "write", f.write)
	return f, fi, nil
}

// pathArg returns the path of a core command: the first buffer string.
func pathArg(r *request) (string, []byte, error) {
	p, rest, ok := bufferString(r.data)
	if !ok {
		return "", nil, errBadData
	}
	return p, rest, nil
}

func (c *conn) open(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	flags, granted, err := openFlags(t, r.word(0))
	if err != nil {
		return err
	}
	rel, _, err := t.resolve(p, false, r.longNames())
	if err != nil {
		return err
	}
	f, fi, err := c.newFile(r, t, rel, flags)
	if err != nil {
		return err
	}
	rp.w16(f.fid)
	rp.w16(attributes(path.Base(rel), fi))
	rp.w32(utime(fi.ModTime()))
	rp.w32(uint32(min(fi.Size(), 1<<32-1)))
	rp.w16(granted)
	return nil
}

// create is CREATE, which truncates a file that exists, and CREATE_NEW,
// which fails then.
func (c *conn) create(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	rel, _, err := t.resolve(p, true, r.longNames())
	if err != nil {
		return err
	}
	flags := os.O_RDWR | os.O_CREATE | os.O_TRUNC
	if r.cmd == cmdCreateNew {
		flags = os.O_RDWR | os.O_CREATE | os.O_EXCL
	}
	f, _, err := c.newFile(r, t, rel, flags)
	if err != nil {
		return err
	}
	c.log.Debug("smb create", "share", t.name, "file", rel)
	rp.w16(f.fid)
	return nil
}

func (c *conn) createTemporary(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	dir, ok, err := t.resolve(p, false, r.longNames())
	if err == nil && !ok {
		err = errBadPath
	}
	if err != nil {
		return err
	}
	for range 100 {
		name := fmt.Sprintf("tmp%05x", uint32(time.Now().UnixNano())&0xfffff)
		f, _, err := c.newFile(r, t, path.Join(dir, name), os.O_RDWR|os.O_CREATE|os.O_EXCL)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		rp.w16(f.fid)
		rp.b8(0x04)
		rp.str(strings.ToUpper(name))
		return nil
	}
	return errNoAccess
}

// closeFile closes a file and sets its time if t is not zero.
func (c *conn) closeFile(f *file, mtime time.Time) error {
	delete(c.files, f.fid)
	err := f.f.Close()
	if !mtime.IsZero() && f.write {
		f.t.root.Chtimes(f.rel, time.Time{}, mtime)
	}
	c.log.Debug("smb close", "file", f.rel, "fid", f.fid)
	return err
}

func (c *conn) close(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	return c.closeFile(f, fromUtime(r.dword(1)))
}

// flush is a no-op: writes go to the file at once, and are not synced,
// as with NFS.
func (c *conn) flush(r *request, rp *reply) error {
	if fid := r.word(0); fid != 0xffff {
		if _, err := c.file(r, fid); err != nil {
			return err
		}
	}
	return nil
}

func (c *conn) delete(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	attrs := r.word(0)
	dirPart, pattern := splitPattern(p)
	if !wild(pattern) {
		rel, _, err := t.resolve(p, false, r.longNames())
		if err != nil {
			return err
		}
		fi, err := t.root.Lstat(rel)
		if err != nil {
			return err
		}
		if fi.IsDir() {
			return errNoAccess
		}
		if attributes(path.Base(rel), fi)&attrHidden != 0 && attrs&attrHidden == 0 {
			return errBadFile
		}
		c.log.Debug("smb delete", "share", t.name, "file", rel)
		return t.root.Remove(rel)
	}
	dir, ok, err := t.resolve(dirPart, false, r.longNames())
	if err == nil && !ok {
		err = errBadPath
	}
	if err != nil {
		return err
	}
	entries, err := t.list(dir)
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		if e.dir() || !e.matches(pattern, attrs, r.longNames()) {
			continue
		}
		if err := t.root.Remove(path.Join(dir, e.name)); err != nil {
			return err
		}
		n++
	}
	c.log.Debug("smb delete", "share", t.name, "dir", dir, "pattern", pattern, "files", n)
	if n == 0 {
		return errBadFile
	}
	return nil
}

// rename renames a file or directory. A wildcard rename takes each ? of
// the new name from the old one, as in DOS.
func (c *conn) rename(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	oldp, rest, err := pathArg(r)
	if err != nil {
		return err
	}
	newp, _, ok := bufferString(rest)
	if !ok {
		return errBadData
	}
	oldDir, oldPat := splitPattern(oldp)
	if !wild(oldPat) {
		from, _, err := t.resolve(oldp, false, r.longNames())
		if err != nil {
			return err
		}
		to, exists, err := t.resolve(newp, true, true)
		if err != nil {
			return err
		}
		if exists && !strings.EqualFold(to, from) {
			return errFileExists
		}
		if exists {
			// A change of case only.
			to = path.Join(path.Dir(to), path.Base(strings.ReplaceAll(newp, `\`, "/")))
		}
		c.log.Debug("smb rename", "share", t.name, "from", from, "to", to)
		return t.root.Rename(from, to)
	}
	dir, ok, err := t.resolve(oldDir, false, r.longNames())
	if err == nil && !ok {
		err = errBadPath
	}
	if err != nil {
		return err
	}
	_, tpl := splitPattern(newp)
	entries, err := t.list(dir)
	if err != nil {
		return err
	}
	n := 0
	for _, e := range entries {
		if e.dir() || !e.matches(oldPat, r.word(0), false) {
			continue
		}
		to := path.Join(dir, strings.ToLower(applyTemplate(tpl, e.dos)))
		if _, err := t.root.Lstat(to); err == nil {
			return errFileExists
		}
		if err := t.root.Rename(path.Join(dir, e.name), to); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return errBadFile
	}
	return nil
}

// applyTemplate makes a new 8.3 name from a rename template.
func applyTemplate(tpl, name string) string {
	t, n := fcb(tpl), fcb(name)
	for i := range t {
		if t[i] == '?' {
			t[i] = n[i]
		}
	}
	base := strings.TrimRight(string(t[:8]), " ")
	ext := strings.TrimRight(string(t[8:]), " ")
	if ext == "" {
		return base
	}
	return base + "." + ext
}

// stat returns the attributes of a path, the share root included.
func (t *tree) stat(p string, longNames bool) (string, fs.FileInfo, error) {
	rel, _, err := t.resolve(p, false, longNames)
	if err != nil {
		return "", nil, err
	}
	fi, err := t.root.Stat(rel)
	return rel, fi, err
}

func (c *conn) queryInformation(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	rel, fi, err := t.stat(p, r.longNames())
	if err != nil {
		return err
	}
	rp.w16(attributes(path.Base(rel), fi))
	rp.w32(utime(fi.ModTime()))
	size := uint32(0)
	if !fi.IsDir() {
		size = uint32(min(fi.Size(), 1<<32-1))
	}
	rp.w32(size)
	rp.zero(10)
	return nil
}

// setAttributes sets the time and the read-only attribute of a file.
func (t *tree) setAttributes(rel string, attrs uint16, mtime time.Time) error {
	fi, err := t.root.Stat(rel)
	if err != nil {
		return err
	}
	if !mtime.IsZero() {
		if err := t.root.Chtimes(rel, time.Time{}, mtime); err != nil {
			return err
		}
	}
	perm := fi.Mode().Perm()
	switch {
	case attrs&attrReadOnly != 0 && perm&0o222 != 0:
		perm &^= 0o222
	case attrs&attrReadOnly == 0 && perm&0o200 == 0:
		perm |= 0o200
	default:
		return nil
	}
	return t.root.Chmod(rel, perm)
}

func (c *conn) setInformation(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	rel, _, err := t.resolve(p, false, r.longNames())
	if err != nil {
		return err
	}
	return t.setAttributes(rel, r.word(0), fromUtime(r.dword(1)))
}

// readAt reads up to n bytes at off.
func readAt(f *file, off int64, n int) ([]byte, error) {
	buf := make([]byte, n)
	m, err := f.f.ReadAt(buf, off)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:m], nil
}

// maxRead is the most data a read reply to the client may carry, given
// the size of the rest of the reply.
func (c *conn) maxRead(overhead int) int {
	return max(c.maxBuf-overhead, 512)
}

func (c *conn) read(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	n := min(int(r.word(1)), c.maxRead(hdrLen+1+10+2+3))
	data, err := readAt(f, int64(r.dword(2)), n)
	if err != nil {
		return err
	}
	c.log.Log(context.Background(), slog.LevelDebug-1, "smb read", "file", f.rel, "offset", r.dword(2), "bytes", len(data))
	rp.w16(uint16(len(data)))
	rp.zero(8)
	rp.b8(0x01)
	rp.b16(uint16(len(data)))
	rp.data = append(rp.data, data...)
	return nil
}

// writeAt writes data at off; no data sets the file's size to off.
func (c *conn) writeAt(f *file, off int64, data []byte) (int, error) {
	if !f.write {
		return 0, errNoAccess
	}
	if len(data) == 0 {
		return 0, f.f.Truncate(off)
	}
	c.log.Log(context.Background(), slog.LevelDebug-1, "smb write", "file", f.rel, "offset", off, "bytes", len(data))
	return f.f.WriteAt(data, off)
}

func (c *conn) write(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	if len(r.data) < 3 || r.data[0] != 0x01 {
		return errBadData
	}
	data := r.data[3:]
	data = data[:min(len(data), int(le.Uint16(r.data[1:])), int(r.word(1)))]
	n, err := c.writeAt(f, int64(r.dword(2)), data)
	if err != nil {
		return err
	}
	rp.w16(uint16(n))
	return nil
}

func (c *conn) writeAndClose(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	if len(r.data) < 1 {
		return errBadData
	}
	data := r.data[1:]
	data = data[:min(len(data), int(r.word(1)))]
	n := 0
	if len(data) > 0 {
		if n, err = c.writeAt(f, int64(r.dword(2)), data); err != nil {
			return err
		}
	}
	if err := c.closeFile(f, fromUtime(r.dword(4))); err != nil {
		return err
	}
	rp.w16(uint16(n))
	return nil
}

// lock accepts byte range locks without keeping them: files are not
// shared between clients in the ways that need them.
func (c *conn) lock(r *request, rp *reply) error {
	_, err := c.file(r, r.word(0))
	return err
}

func (c *conn) seek(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	off := int64(int32(r.dword(2)))
	switch r.word(1) {
	case 0:
	case 1:
		off += f.pos
	case 2:
		fi, err := f.f.Stat()
		if err != nil {
			return err
		}
		off += fi.Size()
	default:
		return errBadFunc
	}
	f.pos = max(off, 0)
	rp.w32(uint32(f.pos))
	return nil
}

func (c *conn) checkDirectory(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	_, fi, err := t.stat(p, r.longNames())
	if err != nil || !fi.IsDir() {
		return errBadPath
	}
	return nil
}

func (c *conn) mkdir(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	rel, exists, err := t.resolve(p, true, r.longNames())
	if err != nil {
		return err
	}
	if exists {
		return errNoAccess
	}
	c.log.Debug("smb mkdir", "share", t.name, "dir", rel)
	return t.root.Mkdir(rel, 0o777)
}

func (c *conn) rmdir(r *request, rp *reply) error {
	t, err := c.writableTree(r)
	if err != nil {
		return err
	}
	p, _, err := pathArg(r)
	if err != nil {
		return err
	}
	rel, fi, err := t.stat(p, r.longNames())
	if err != nil {
		return errBadPath
	}
	if !fi.IsDir() || rel == "." {
		return errBadPath
	}
	c.log.Debug("smb rmdir", "share", t.name, "dir", rel)
	if err := t.root.Remove(rel); err != nil {
		if errors.Is(err, syscall.ENOTEMPTY) || errors.Is(err, syscall.EEXIST) {
			return errNoAccess
		}
		return err
	}
	return nil
}

// diskSpace returns the size and free space of the share's file system,
// capped at what 16-bit cluster counts can say: 2 GB.
func (t *tree) diskSpace() (total, free uint64) {
	var sfs syscall.Statfs_t
	if err := syscall.Statfs(t.share.Path, &sfs); err != nil {
		return 0, 0
	}
	total = uint64(sfs.Blocks) * uint64(sfs.Bsize)
	free = uint64(sfs.Bavail) * uint64(sfs.Bsize)
	const limit = 65535 * 64 * 512
	return min(total, limit), min(free, limit)
}

func (c *conn) queryDisk(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	total, free := t.diskSpace()
	const block = 512
	bpu := uint64(1)
	for total/(block*bpu) > 65535 {
		bpu *= 2
	}
	rp.w16(uint16(total / (block * bpu)))
	rp.w16(uint16(bpu))
	rp.w16(block)
	rp.w16(uint16(free / (block * bpu)))
	rp.w16(0)
	return nil
}

func (c *conn) queryInformation2(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	fi, err := f.f.Stat()
	if err != nil {
		return err
	}
	d, tm := dosDateTime(fi.ModTime())
	for range 3 {
		rp.w16(d)
		rp.w16(tm)
	}
	rp.w32(uint32(min(fi.Size(), 1<<32-1)))
	rp.w32(uint32(min((fi.Size()+4095)&^4095, 1<<32-1)))
	rp.w16(attributes(path.Base(f.rel), fi))
	return nil
}

func (c *conn) setInformation2(r *request, rp *reply) error {
	f, err := c.file(r, r.word(0))
	if err != nil {
		return err
	}
	if !f.t.writable {
		return errNoAccess
	}
	if t := fromDOS(r.word(5), r.word(6)); !t.IsZero() {
		return f.t.root.Chtimes(f.rel, time.Time{}, t)
	}
	return nil
}

// Open functions of OPEN_ANDX.
const (
	openExistFail     = 0
	openExistOpen     = 1
	openExistTruncate = 2
	openCreate        = 0x10
)

func (c *conn) openAndX(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	p, _ := cstring(r.data)
	fn := r.word(8)
	rel, exists, err := t.resolve(p, fn&openCreate != 0, r.longNames())
	if err != nil {
		return err
	}
	flags, granted, err := openFlags(t, r.word(3))
	if err != nil {
		return err
	}
	action := uint16(1)
	switch {
	case exists && fn&3 == openExistFail:
		return errFileExists
	case exists && fn&3 == openExistTruncate:
		if !t.writable {
			return errNoAccess
		}
		flags |= os.O_TRUNC
		action = 3
	case exists && fn&3 == openExistOpen:
	case exists:
		return errBadAccess
	default:
		if !t.writable {
			return errNoAccess
		}
		flags |= os.O_CREATE | os.O_EXCL
		action = 2
	}
	f, fi, err := c.newFile(r, t, rel, flags)
	if err != nil {
		return err
	}
	c.chainFID = f.fid
	rp.andx()
	rp.w16(f.fid)
	rp.w16(attributes(path.Base(rel), fi))
	rp.w32(utime(fi.ModTime()))
	rp.w32(uint32(min(fi.Size(), 1<<32-1)))
	rp.w16(granted)
	rp.w16(0) // disk file
	rp.w16(0)
	rp.w16(action)
	rp.w32(0)
	rp.w16(0)
	return nil
}

func (c *conn) readAndX(r *request, rp *reply) error {
	f, err := c.file(r, r.word(2))
	if err != nil {
		return err
	}
	off := int64(r.dword(3))
	n := min(int(r.word(5)), c.maxRead(rp.base+1+24+2))
	data, err := readAt(f, off, n)
	if err != nil {
		return err
	}
	c.log.Log(context.Background(), slog.LevelDebug-1, "smb read", "file", f.rel, "offset", off, "bytes", len(data))
	rp.andx()
	rp.w16(0xffff) // remaining: not a pipe
	rp.w16(0)
	rp.w16(0)
	rp.w16(uint16(len(data)))
	rp.w16(uint16(rp.dataOffset(12)))
	rp.zero(10)
	rp.data = data
	return nil
}

func (c *conn) writeAndX(r *request, rp *reply) error {
	f, err := c.file(r, r.word(2))
	if err != nil {
		return err
	}
	n, off := int(r.word(10)), int(r.word(11))
	if off+n > len(r.msg) || off < hdrLen {
		return errBadData
	}
	w, err := c.writeAt(f, int64(r.dword(3)), r.msg[off:off+n])
	if err != nil {
		return err
	}
	rp.andx()
	rp.w16(uint16(w))
	rp.w16(0xffff)
	rp.zero(4)
	return nil
}

func (c *conn) lockingAndX(r *request, rp *reply) error {
	if _, err := c.file(r, r.word(2)); err != nil {
		return err
	}
	// An oplock release without locks has no reply; no oplocks are
	// granted, so it does not come anyway.
	if r.word(3)&0x02 != 0 && r.word(6) == 0 && r.word(7) == 0 {
		rp.noReply = true
		return nil
	}
	rp.andx()
	return nil
}

// readRaw is not offered, but a client that sends it anyway gets the empty
// message that means it failed.
func (c *conn) readRaw(r *request, rp *reply) error {
	rp.raw = []byte{}
	return nil
}
