// Package pubfs is the read-only file tree a host sees over HTTP and FTP.
//
// Like WebNFS, paths name files by the export paths NFS clients mount:
// an export with export_path "/netbsd" holds /netbsd/amd64/binary/sets,
// and directories above the export paths are listed so a client can find
// its way down to them. The host's files are at the top too, under their
// names and aliases, so /bsd.rd fetches the file TFTP would send as
// bsd.rd. Wildcard names are not used: they would answer every request.
//
// Files are read through os.Root, so a symbolic link may not lead out of
// its export. Exports served by another server and the attributes of
// mtree specifications are ignored.
package pubfs

import (
	"errors"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/rpajarola/gobootd/internal/inventory"
)

// Tree is what one host may read over one service.
type Tree struct {
	host *inventory.Host
	svc  string
}

// New returns the tree host h may read over svc.
func New(h *inventory.Host, svc string) *Tree { return &Tree{host: h, svc: svc} }

// Clean turns a requested path into the absolute, clean path the tree
// uses. ".." never leaves the top.
func Clean(p string) string { return path.Clean("/" + p) }

// File is an open regular file.
type File struct {
	*os.File
	Info fs.FileInfo
	// Source is the file's path on this server, for logging.
	Source string
}

// ErrIsDir is returned by Open for a directory.
var ErrIsDir = errors.New("is a directory")

// started is the time virtual directories claim to be modified at.
var started = time.Now()

// location is where a path leads: into an export, to a configured file,
// or to a directory that only exists above export paths.
type location struct {
	// dir and rel are an export's directory and the path relative to
	// it, for os.Root.
	dir, rel string
	file     *inventory.File
	virtual  bool
}

// exportFor finds the export with the longest export path that holds p.
func (t *Tree) exportFor(p string) (location, bool) {
	var best *inventory.Export
	var bestDir bool
	for _, x := range t.host.Exports {
		if x.Server != "" {
			continue
		}
		ep := x.ExportPath
		st, err := os.Stat(x.Path)
		if err != nil {
			continue
		}
		holds := p == ep || st.IsDir() && (ep == "/" || strings.HasPrefix(p, ep+"/"))
		if holds && (best == nil || len(ep) > len(best.ExportPath)) {
			best, bestDir = x, st.IsDir()
		}
	}
	switch {
	case best == nil:
		return location{}, false
	case !bestDir:
		return location{dir: filepath.Dir(best.Path), rel: filepath.Base(best.Path)}, true
	}
	rel := strings.TrimPrefix(strings.TrimPrefix(p, best.ExportPath), "/")
	if rel == "" {
		rel = "."
	}
	return location{dir: best.Path, rel: rel}, true
}

// fileFor finds a configured file by name, alias or path.
func (t *Tree) fileFor(p string) (*inventory.File, bool) {
	name := strings.TrimPrefix(p, "/")
	if name == "" {
		return nil, false
	}
	f, kind, err := t.host.File(t.svc, name)
	if err != nil || kind == inventory.MatchWildcard || kind == inventory.MatchAny {
		return nil, false
	}
	return f, true
}

// above reports whether p is a directory above one of the export paths.
func (t *Tree) above(p string) bool {
	if p == "/" {
		return true
	}
	for _, x := range t.host.Exports {
		if x.Server == "" && strings.HasPrefix(x.ExportPath, p+"/") {
			return true
		}
	}
	return false
}

// stat finds where p leads and what is there. Inside an export, a
// missing path falls through to the files and directories above exports,
// so an export at "/" does not hide them.
func (t *Tree) stat(p string) (location, fs.FileInfo, error) {
	err := error(fs.ErrNotExist)
	if l, ok := t.exportFor(p); ok {
		root, rerr := os.OpenRoot(l.dir)
		if rerr == nil {
			fi, serr := root.Stat(l.rel)
			root.Close()
			if serr == nil {
				return l, fi, nil
			}
			err = serr
		} else {
			err = rerr
		}
	}
	if f, ok := t.fileFor(p); ok {
		fi, serr := os.Stat(f.Path)
		if serr == nil {
			return location{file: f}, fi, nil
		}
		err = serr
	}
	if t.above(p) {
		return location{virtual: true}, virtualDir(path.Base(p)), nil
	}
	return location{}, nil, err
}

// Stat describes the file or directory at p.
func (t *Tree) Stat(p string) (fs.FileInfo, error) {
	_, fi, err := t.stat(Clean(p))
	return fi, err
}

// Open opens the regular file at p.
func (t *Tree) Open(p string) (*File, error) {
	l, fi, err := t.stat(Clean(p))
	switch {
	case err != nil:
		return nil, err
	case fi.IsDir():
		return nil, ErrIsDir
	case !fi.Mode().IsRegular():
		return nil, fs.ErrPermission
	}
	var f *os.File
	src := ""
	if l.file != nil {
		src = l.file.Path
		f, err = os.Open(src)
	} else {
		src = filepath.Join(l.dir, l.rel)
		var root *os.Root
		if root, err = os.OpenRoot(l.dir); err == nil {
			f, err = root.Open(l.rel)
			root.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	// The file may have changed between the stat and the open.
	if fi, err = f.Stat(); err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, fs.ErrPermission
	}
	return &File{File: f, Info: fi, Source: src}, nil
}

// ReadDir lists the directory at p, sorted by name. Only directories and
// regular files are listed.
func (t *Tree) ReadDir(p string) ([]fs.FileInfo, error) {
	p = Clean(p)
	l, fi, err := t.stat(p)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errNotDir
	}
	seen := map[string]bool{}
	var out []fs.FileInfo
	add := func(fi fs.FileInfo) {
		if fi == nil || seen[fi.Name()] || !fi.IsDir() && !fi.Mode().IsRegular() {
			return
		}
		seen[fi.Name()] = true
		out = append(out, fi)
	}
	if !l.virtual {
		root, err := os.OpenRoot(l.dir)
		if err != nil {
			return nil, err
		}
		defer root.Close()
		d, err := root.Open(l.rel)
		if err != nil {
			return nil, err
		}
		ents, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return nil, err
		}
		for _, e := range ents {
			// Follow symbolic links that stay inside the export.
			if fi, err := root.Stat(path.Join(l.rel, e.Name())); err == nil {
				add(named{fi, e.Name()})
			}
		}
	}
	// Directories and files above and between the export paths.
	prefix := strings.TrimSuffix(p, "/") + "/"
	for _, x := range t.host.Exports {
		if x.Server != "" || !strings.HasPrefix(x.ExportPath, prefix) {
			continue
		}
		name, _, _ := strings.Cut(x.ExportPath[len(prefix):], "/")
		if name != "" && !seen[name] {
			if _, fi, err := t.stat(prefix + name); err == nil {
				add(named{fi, name})
			}
		}
	}
	if p == "/" {
		for _, f := range t.host.FilesFor(t.svc) {
			for _, n := range append([]string{f.Name}, f.Aliases...) {
				if n == "*" || n == "" || strings.Contains(n, "/") || seen[n] {
					continue
				}
				// An earlier file may have the name already.
				if g, ok := t.fileFor("/" + n); ok && g == f {
					if fi, err := os.Stat(f.Path); err == nil {
						add(named{fi, n})
					}
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b fs.FileInfo) int { return strings.Compare(a.Name(), b.Name()) })
	return out, nil
}

var errNotDir = errors.New("not a directory")

// IsNotDir reports whether err says a path is not a directory.
func IsNotDir(err error) bool { return errors.Is(err, errNotDir) }

// named renames a FileInfo, for files listed under an alias or link name.
type named struct {
	fs.FileInfo
	name string
}

func (n named) Name() string { return n.name }

// virtualDir is a directory above export paths.
type virtualDir string

func (d virtualDir) Name() string     { return string(d) }
func (virtualDir) Size() int64        { return 0 }
func (virtualDir) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (virtualDir) ModTime() time.Time { return started }
func (virtualDir) IsDir() bool        { return true }
func (virtualDir) Sys() any           { return nil }
