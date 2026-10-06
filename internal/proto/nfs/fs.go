package nfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// fhSize is the size of an NFSv2 file handle.
const fhSize = 32

// fhMagic marks bootd's file handles.
const fhMagic = 0x62746431 // "btd1"

// export is an exported directory or file, opened for serving.
type export struct {
	id   uint32
	path string // absolute path on the server
	// root is the exported directory, or the directory holding an
	// exported file.
	root *os.Root
	// file is the name of the exported file in root, or "" for a
	// directory export.
	file string
	// spec overrides attributes and adds device nodes, fifos and
	// symlinks that are not on disk.
	spec spec
	// virtual lists, by directory, the spec entries that are not on
	// disk.
	virtual map[string][]string
	mtime   time.Time
}

// rel converts a path relative to the export to one relative to root.
func (x *export) rel(p string) string {
	if x.file != "" {
		return x.file
	}
	return p
}

// exportID derives a stable export ID from its path.
func exportID(p string) uint32 {
	h := fnv.New32a()
	h.Write([]byte(p))
	return h.Sum32()
}

// handle is a decoded file handle.
type handle struct {
	export uint32
	ino    uint64
}

func (h handle) encode() []byte {
	b := make([]byte, fhSize)
	binary.BigEndian.PutUint32(b[0:], fhMagic)
	binary.BigEndian.PutUint32(b[4:], h.export)
	binary.BigEndian.PutUint64(b[8:], h.ino)
	return b
}

func decodeHandle(b []byte) (handle, bool) {
	if len(b) != fhSize || binary.BigEndian.Uint32(b) != fhMagic {
		return handle{}, false
	}
	return handle{export: binary.BigEndian.Uint32(b[4:]), ino: binary.BigEndian.Uint64(b[8:])}, true
}

// files maps file handles to paths. Handles stay valid across restarts:
// a handle that is not in the table is found again by walking its export.
type files struct {
	mu      sync.Mutex
	exports map[string]*export // by path
	paths   map[handle]string  // path relative to the export, "." for its top
}

func newFiles() *files {
	return &files{exports: map[string]*export{}, paths: map[handle]string{}}
}

// open returns the export for an absolute path, opening it on first use.
// specPath is an mtree specification for its files, or "".
func (t *files) open(p, specPath string) (*export, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := p + "\x00" + specPath
	if x, ok := t.exports[key]; ok {
		return x, nil
	}
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	x := &export{id: exportID(p), path: p, mtime: st.ModTime()}
	dir := p
	if !st.IsDir() {
		dir, x.file = filepath.Split(p)
	}
	if specPath != "" && x.file == "" {
		if err := x.loadSpec(specPath); err != nil {
			return nil, fmt.Errorf("spec %s: %w", specPath, err)
		}
	}
	if x.root, err = os.OpenRoot(dir); err != nil {
		return nil, err
	}
	t.exports[key] = x
	return x, nil
}

func (x *export) loadSpec(specPath string) error {
	f, err := os.Open(specPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if x.spec, err = parseSpec(f); err != nil {
		return err
	}
	x.virtual = map[string][]string{}
	for p, e := range x.spec {
		if !e.isVirtual() || p == "." {
			continue
		}
		if _, err := os.Lstat(filepath.Join(x.path, filepath.FromSlash(p))); err == nil {
			continue
		}
		dir := path.Dir(p)
		x.virtual[dir] = append(x.virtual[dir], path.Base(p))
	}
	return nil
}

// close closes all exports.
func (t *files) close() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, x := range t.exports {
		x.root.Close()
	}
	t.exports = map[string]*export{}
}

// lstat returns information about p in x, with the attributes of the spec
// applied. Spec entries that are not on disk are virtual files.
func (x *export) lstat(p string) (fs.FileInfo, error) {
	fi, err := x.root.Lstat(x.rel(p))
	e := x.spec[p]
	switch {
	case err == nil:
		return overlay(fi, e), nil
	case errors.Is(err, fs.ErrNotExist) && e != nil && e.isVirtual():
		return x.virtualInfo(p, e), nil
	}
	return nil, err
}

// readlink returns the target of the symlink p.
func (x *export) readlink(p string) (string, error) {
	fi, err := x.lstat(p)
	if err != nil {
		return "", err
	}
	if i, ok := fi.(*info); ok && i.virtual {
		return i.link, nil
	}
	return x.root.Readlink(x.rel(p))
}

// names lists directory dir, including virtual entries, sorted.
func (x *export) names(dir string) ([]string, error) {
	f, err := x.root.Open(dir)
	if err != nil {
		return nil, err
	}
	ents, err := f.ReadDir(-1)
	f.Close()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, de := range ents {
		names = append(names, de.Name())
	}
	names = append(names, x.virtual[dir]...)
	sort.Strings(names)
	return names, nil
}

// handleFor returns the handle for p in x and remembers it.
func (t *files) handleFor(x *export, p string) (handle, fs.FileInfo, error) {
	fi, err := x.lstat(p)
	if err != nil {
		return handle{}, nil, err
	}
	h := handle{export: x.id, ino: statOf(fi).ino}
	t.mu.Lock()
	t.paths[h] = p
	t.mu.Unlock()
	return h, fi, nil
}

var errStale = errors.New("stale file handle")

// resolve returns the path of h in x. If the handle is not known, the
// export is searched for its inode.
func (t *files) resolve(x *export, h handle) (string, fs.FileInfo, error) {
	t.mu.Lock()
	p, ok := t.paths[h]
	t.mu.Unlock()
	if ok {
		if fi, err := x.lstat(p); err == nil && statOf(fi).ino == h.ino {
			return p, fi, nil
		}
	}
	if x.file != "" {
		return "", nil, errStale
	}
	if h.ino&virtualIno != 0 {
		for dir, names := range x.virtual {
			for _, n := range names {
				if p := path.Join(dir, n); vino(p) == h.ino {
					fi, err := x.lstat(p)
					if err != nil {
						return "", nil, errStale
					}
					t.mu.Lock()
					t.paths[h] = p
					t.mu.Unlock()
					return p, fi, nil
				}
			}
		}
		return "", nil, errStale
	}
	var found string
	var foundFI fs.FileInfo
	walk := func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if statOf(fi).ino == h.ino {
			found, foundFI = p, fi
			return filepath.SkipAll
		}
		return nil
	}
	if err := fs.WalkDir(x.root.FS(), ".", walk); err != nil || found == "" {
		return "", nil, errStale
	}
	t.mu.Lock()
	t.paths[h] = found
	t.mu.Unlock()
	return found, foundFI, nil
}

// join returns the path of name in directory dir, or false if name is not
// a plain file name. ".." does not leave the export.
func join(dir, name string) (string, bool) {
	switch {
	case name == "" || strings.ContainsRune(name, '/') || strings.ContainsRune(name, 0):
		return "", false
	case name == ".":
		return dir, true
	case name == "..":
		if dir == "." {
			return ".", true
		}
		return path.Dir(dir), true
	}
	return path.Join(dir, name), true
}

// info is a file's attributes as served: from disk with the spec applied,
// or entirely from the spec.
type info struct {
	name    string
	size    int64
	mode    fs.FileMode
	mtime   time.Time
	st      stat
	virtual bool
	link    string // target of a virtual symlink
}

func (i *info) Name() string       { return i.name }
func (i *info) Size() int64        { return i.size }
func (i *info) Mode() fs.FileMode  { return i.mode }
func (i *info) ModTime() time.Time { return i.mtime }
func (i *info) IsDir() bool        { return i.mode.IsDir() }
func (i *info) Sys() any           { return nil }

const permBits = fs.ModePerm | fs.ModeSetuid | fs.ModeSetgid | fs.ModeSticky

// overlay applies a spec entry to a file on disk.
func overlay(fi fs.FileInfo, e *specEntry) *info {
	i := &info{name: fi.Name(), size: fi.Size(), mode: fi.Mode(), mtime: fi.ModTime(), st: statOf(fi)}
	if e == nil {
		return i
	}
	if e.hasMode {
		i.mode = i.mode&^permBits | goMode(e.mode)
	}
	if e.hasUID {
		i.st.uid = e.uid
	}
	if e.hasGID {
		i.st.gid = e.gid
	}
	return i
}

// isVirtual reports whether an entry can be served without a file on disk.
func (e *specEntry) isVirtual() bool {
	switch e.typ {
	case "char", "block", "fifo", "link":
		return true
	}
	return false
}

// virtualIno marks the inode numbers of virtual files.
const virtualIno = 1 << 63

func vino(p string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(p))
	return h.Sum64() | virtualIno
}

func (x *export) virtualInfo(p string, e *specEntry) *info {
	i := &info{
		name:    path.Base(p),
		mode:    goMode(e.mode),
		mtime:   x.mtime,
		virtual: true,
		st:      stat{ino: vino(p), nlink: 1, uid: e.uid, gid: e.gid, atime: x.mtime, ctime: x.mtime},
	}
	switch e.typ {
	case "char":
		i.mode |= fs.ModeDevice | fs.ModeCharDevice
		i.st.rdev = rdev(e.major, e.minor)
	case "block":
		i.mode |= fs.ModeDevice
		i.st.rdev = rdev(e.major, e.minor)
	case "fifo":
		i.mode |= fs.ModeNamedPipe
	case "link":
		i.mode |= fs.ModeSymlink
		i.link = e.link
		i.size = int64(len(e.link))
	}
	return i
}

// goMode converts Unix permission bits to an fs.FileMode.
func goMode(m uint32) fs.FileMode {
	fm := fs.FileMode(m & 0o777)
	if m&0o4000 != 0 {
		fm |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		fm |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		fm |= fs.ModeSticky
	}
	return fm
}
