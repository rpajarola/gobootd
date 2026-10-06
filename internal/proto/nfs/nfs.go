// Package nfs implements NFS version 2 (RFC 1094) with MOUNT version 1
// over UDP, the protocols diskless SunOS, NetBSD and early Solaris clients
// use for their root and swap. It serves the export blocks of the
// configuration: a client may only mount its own exports, and only see the
// files inside them.
//
// The server is read-only for now; anything that would change a file is
// answered with "read-only file system".
package nfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"path/filepath"
	"slices"
	"syscall"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.NFS, func() daemon.Service { return &Server{} }) }

// Program numbers.
const (
	MountProg = 100005
	MountVers = 1
	NFSProg   = oncrpc.NFSProg
	NFSVers   = 2

	maxPath = 1024
	maxName = 255
	maxData = 8192
)

// MOUNT procedures.
const (
	mountMnt     = 1
	mountDump    = 2
	mountUmnt    = 3
	mountUmntall = 4
	mountExport  = 5
)

// NFS procedures.
const (
	procGetattr    = 1
	procSetattr    = 2
	procRoot       = 3
	procLookup     = 4
	procReadlink   = 5
	procRead       = 6
	procWritecache = 7
	procWrite      = 8
	procCreate     = 9
	procRemove     = 10
	procRename     = 11
	procLink       = 12
	procSymlink    = 13
	procMkdir      = 14
	procRmdir      = 15
	procReaddir    = 16
	procStatfs     = 17
)

// NFS status codes.
const (
	nfsOK          = 0
	errPerm        = 1
	errNoent       = 2
	errIO          = 5
	errNxio        = 6
	errAcces       = 13
	errNotdir      = 20
	errIsdir       = 21
	errRofs        = 30
	errNametoolong = 63
	errStaleCode   = 70
)

// File types.
const (
	typeReg = 1
	typeDir = 2
	typeBlk = 3
	typeChr = 4
	typeLnk = 5
)

// Server serves exports over NFS.
type Server struct {
	files *files
}

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if len(env.Networks) == 0 {
		return errors.New("no network")
	}
	s.files = newFiles()
	defer s.files.close()
	for _, n := range env.Networks {
		defer n.RPC.Register(s.mountProgram(env, n))()
		defer n.RPC.Register(s.nfsProgram(env, n))()
		env.Log.Info("listening", "network", n.Name(), "port", oncrpc.NFSPort)
	}
	<-ctx.Done()
	return nil
}

// request is a call with the client identified.
type request struct {
	*oncrpc.Call
	host *inventory.Host
	log  *slog.Logger
}

// client finds the host making the call. Calls from unknown hosts, or
// hosts that may not use NFS, are not answered.
func (s *Server) client(env *daemon.Env, n *netif.Network, c *oncrpc.Call, what string) (*request, error) {
	ip := c.From.Addr()
	log := env.Log.With("network", n.Name(), "client", ip.String())
	h, err := env.Inventory().ByIP(ip)
	if err != nil {
		log.Info(fmt.Sprintf("%s from %s denied (%v)", what, ip, err))
		return nil, oncrpc.ErrDrop
	}
	if err := h.Allows(service.NFS); err != nil {
		log.Info(fmt.Sprintf("%s from %s denied (%v)", what, h.Name, err))
		return nil, oncrpc.ErrDrop
	}
	return &request{Call: c, host: h, log: log.With("host", h.Name)}, nil
}

func (s *Server) mountProgram(env *daemon.Env, n *netif.Network) *oncrpc.Program {
	return &oncrpc.Program{Prog: MountProg, Vers: MountVers, Procs: map[uint32]oncrpc.Proc{
		mountMnt: func(c *oncrpc.Call) ([]byte, error) {
			path := c.Args.String(maxPath)
			if c.Args.Err() != nil {
				return nil, oncrpc.ErrGarbageArgs
			}
			r, err := s.client(env, n, c, "mount "+path)
			if err != nil {
				return nil, err
			}
			return s.mnt(r, path), nil
		},
		mountDump:    func(*oncrpc.Call) ([]byte, error) { return (&oncrpc.Encoder{}).Bool(false).Bytes(), nil },
		mountUmnt:    func(*oncrpc.Call) ([]byte, error) { return nil, nil },
		mountUmntall: func(*oncrpc.Call) ([]byte, error) { return nil, nil },
		mountExport: func(c *oncrpc.Call) ([]byte, error) {
			r, err := s.client(env, n, c, "mount export list")
			if err != nil {
				return nil, err
			}
			e := &oncrpc.Encoder{}
			for _, x := range r.host.Exports {
				e.Bool(true).String(x.ExportPath).Bool(true).String(r.host.Name).Bool(false)
			}
			return e.Bool(false).Bytes(), nil
		},
	}}
}

// mnt returns the handle of one of the host's exports.
func (s *Server) mnt(r *request, path string) []byte {
	e := &oncrpc.Encoder{}
	clean := filepath.Clean(path)
	i := slices.IndexFunc(r.host.Exports, func(x *inventory.Export) bool { return x.ExportPath == clean })
	if i < 0 {
		r.log.Info(fmt.Sprintf("mount %s from %s denied (not exported to this host)", path, r.host.Name))
		return e.Uint32(errAcces).Bytes()
	}
	x, err := s.files.open(r.host.Exports[i].Path, r.host.Exports[i].Spec)
	if err != nil {
		r.log.Warn(fmt.Sprintf("mount %s from %s failed (%v)", path, r.host.Name, err))
		return e.Uint32(status(err)).Bytes()
	}
	h, _, err := s.files.handleFor(x, ".")
	if err != nil {
		r.log.Warn(fmt.Sprintf("mount %s from %s failed (%v)", path, r.host.Name, err))
		return e.Uint32(status(err)).Bytes()
	}
	r.log.Info(fmt.Sprintf("mount %s from %s", path, r.host.Name), "export", r.host.Exports[i].Name)
	return e.Uint32(nfsOK).Fixed(h.encode()).Bytes()
}

func (s *Server) nfsProgram(env *daemon.Env, n *netif.Network) *oncrpc.Program {
	proc := func(name string, fn func(*request) []byte) oncrpc.Proc {
		return func(c *oncrpc.Call) ([]byte, error) {
			r, err := s.client(env, n, c, "nfs "+name)
			if err != nil {
				return nil, err
			}
			res := fn(r)
			if c.Args.Err() != nil {
				return nil, oncrpc.ErrGarbageArgs
			}
			return res, nil
		}
	}
	rofs := func(r *request) []byte { return (&oncrpc.Encoder{}).Uint32(errRofs).Bytes() }
	void := func(*request) []byte { return nil }
	return &oncrpc.Program{Prog: NFSProg, Vers: NFSVers, Procs: map[uint32]oncrpc.Proc{
		procGetattr:    proc("getattr", s.getattr),
		procSetattr:    proc("setattr", rofs),
		procRoot:       proc("root", void),
		procLookup:     proc("lookup", s.lookup),
		procReadlink:   proc("readlink", s.readlink),
		procRead:       proc("read", s.read),
		procWritecache: proc("writecache", void),
		procWrite:      proc("write", rofs),
		procCreate:     proc("create", rofs),
		procRemove:     proc("remove", rofs),
		procRename:     proc("rename", rofs),
		procLink:       proc("link", rofs),
		procSymlink:    proc("symlink", rofs),
		procMkdir:      proc("mkdir", rofs),
		procRmdir:      proc("rmdir", rofs),
		procReaddir:    proc("readdir", s.readdir),
		procStatfs:     proc("statfs", s.statfs),
	}}
}

// file decodes a file handle argument and finds the file. It checks that
// the handle belongs to one of the host's exports.
func (s *Server) file(r *request) (*export, string, fs.FileInfo, uint32) {
	h, ok := decodeHandle(r.Args.Fixed(fhSize))
	if !ok {
		return nil, "", nil, errStaleCode
	}
	for _, e := range r.host.Exports {
		if exportID(e.Path) != h.export {
			continue
		}
		x, err := s.files.open(e.Path, e.Spec)
		if err != nil {
			return nil, "", nil, status(err)
		}
		p, fi, err := s.files.resolve(x, h)
		if err != nil {
			return nil, "", nil, status(err)
		}
		return x, p, fi, nfsOK
	}
	r.log.Info(fmt.Sprintf("nfs request from %s denied (file handle not in its exports)", r.host.Name))
	return nil, "", nil, errStaleCode
}

func (s *Server) getattr(r *request) []byte {
	x, _, fi, st := s.file(r)
	e := (&oncrpc.Encoder{}).Uint32(st)
	if st == nfsOK {
		fattr(e, x, fi)
	}
	return e.Bytes()
}

func (s *Server) lookup(r *request) []byte {
	x, dir, fi, st := s.file(r)
	name := r.Args.String(maxName)
	e := &oncrpc.Encoder{}
	switch {
	case st != nfsOK:
		return e.Uint32(st).Bytes()
	case !fi.IsDir() || x.file != "":
		return e.Uint32(errNotdir).Bytes()
	}
	p, ok := join(dir, name)
	if !ok {
		return e.Uint32(errNoent).Bytes()
	}
	h, cfi, err := s.files.handleFor(x, p)
	if err != nil {
		r.log.Debug("lookup", "dir", dir, "name", name, "err", err)
		return e.Uint32(status(err)).Bytes()
	}
	e.Uint32(nfsOK).Fixed(h.encode())
	fattr(e, x, cfi)
	return e.Bytes()
}

func (s *Server) readlink(r *request) []byte {
	x, p, fi, st := s.file(r)
	e := &oncrpc.Encoder{}
	if st != nfsOK {
		return e.Uint32(st).Bytes()
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return e.Uint32(errIO).Bytes() // not a link; NFSv2 has no EINVAL
	}
	target, err := x.readlink(p)
	if err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	return e.Uint32(nfsOK).String(target).Bytes()
}

func (s *Server) read(r *request) []byte {
	x, p, fi, st := s.file(r)
	offset, count := r.Args.Uint32(), r.Args.Uint32()
	r.Args.Uint32() // totalcount, unused
	e := &oncrpc.Encoder{}
	if st != nfsOK {
		return e.Uint32(st).Bytes()
	}
	if fi.IsDir() {
		return e.Uint32(errIsdir).Bytes()
	}
	if !fi.Mode().IsRegular() {
		return e.Uint32(errNxio).Bytes()
	}
	f, err := x.root.Open(x.rel(p))
	if err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	defer f.Close()
	buf := make([]byte, min(count, maxData))
	n, err := f.ReadAt(buf, int64(offset))
	if err != nil && err != io.EOF {
		return e.Uint32(status(err)).Bytes()
	}
	if offset == 0 {
		r.log.Debug(fmt.Sprintf("nfs read %s/%s by %s", x.path, p, r.host.Name))
	}
	e.Uint32(nfsOK)
	fattr(e, x, fi)
	return e.Opaque(buf[:n]).Bytes()
}

func (s *Server) readdir(r *request) []byte {
	x, dir, fi, st := s.file(r)
	cookie := r.Args.Uint32()
	count := r.Args.Uint32()
	e := &oncrpc.Encoder{}
	switch {
	case st != nfsOK:
		return e.Uint32(st).Bytes()
	case !fi.IsDir() || x.file != "":
		return e.Uint32(errNotdir).Bytes()
	}
	list, err := x.names(dir)
	if err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	names := append([]string{".", ".."}, list...)

	e.Uint32(nfsOK)
	// Leave room for the end of the list and the eof flag.
	size, limit := 4, int(min(count, maxData))-8
	i := int(cookie)
	for ; i < len(names); i++ {
		name := names[i]
		p, _ := join(dir, name)
		cfi, err := x.lstat(p)
		if err != nil {
			continue // removed meanwhile
		}
		entry := 4 + 4 + 4 + len(name) + (4-len(name)%4)%4 + 4
		if size+entry > limit {
			break
		}
		size += entry
		e.Bool(true).Uint32(fileid(statOf(cfi).ino)).String(name).Uint32(uint32(i + 1))
	}
	return e.Bool(false).Bool(i >= len(names)).Bytes()
}

func (s *Server) statfs(r *request) []byte {
	x, _, _, st := s.file(r)
	e := &oncrpc.Encoder{}
	if st != nfsOK {
		return e.Uint32(st).Bytes()
	}
	var sfs syscall.Statfs_t
	if err := syscall.Statfs(x.path, &sfs); err != nil {
		return e.Uint32(status(err)).Bytes()
	}
	const bsize = 4096
	scale := func(n uint64) uint32 { return uint32(min(n*uint64(sfs.Bsize)/bsize, 1<<31-1)) }
	return e.Uint32(nfsOK).Uint32(maxData).Uint32(bsize).
		Uint32(scale(uint64(sfs.Blocks))).Uint32(scale(uint64(sfs.Bfree))).Uint32(scale(uint64(sfs.Bavail))).Bytes()
}

// fileid folds an inode number into NFSv2's 32 bits.
func fileid(ino uint64) uint32 { return uint32(ino) ^ uint32(ino>>32) }

// fattr encodes the attributes of fi.
func fattr(e *oncrpc.Encoder, x *export, fi fs.FileInfo) {
	st := statOf(fi)
	m := fi.Mode()
	var typ, ifmt uint32
	switch {
	case m.IsDir():
		typ, ifmt = typeDir, syscall.S_IFDIR
	case m&fs.ModeSymlink != 0:
		typ, ifmt = typeLnk, syscall.S_IFLNK
	case m&fs.ModeCharDevice != 0:
		typ, ifmt = typeChr, syscall.S_IFCHR
	case m&fs.ModeDevice != 0:
		typ, ifmt = typeBlk, syscall.S_IFBLK
	case m&fs.ModeNamedPipe != 0:
		// NFSv2 has no fifo type; SunOS sends a character device type
		// with the fifo mode.
		typ, ifmt = typeChr, syscall.S_IFIFO
	default:
		typ, ifmt = typeReg, syscall.S_IFREG
	}
	mode := ifmt | uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		mode |= syscall.S_ISUID
	}
	if m&fs.ModeSetgid != 0 {
		mode |= syscall.S_ISGID
	}
	if m&fs.ModeSticky != 0 {
		mode |= syscall.S_ISVTX
	}
	const bsize = 4096
	e.Uint32(typ).Uint32(mode).Uint32(st.nlink).Uint32(st.uid).Uint32(st.gid)
	e.Uint32(uint32(min(fi.Size(), 1<<32-1))).Uint32(bsize).Uint32(st.rdev)
	e.Uint32(uint32((st.blocks*512 + bsize - 1) / bsize)).Uint32(x.id).Uint32(fileid(st.ino))
	for _, t := range []time.Time{st.atime, fi.ModTime(), st.ctime} {
		e.Uint32(uint32(t.Unix())).Uint32(uint32(t.Nanosecond() / 1000))
	}
}

// status converts an error to an NFS status.
func status(err error) uint32 {
	var errno syscall.Errno
	switch {
	case errors.Is(err, errStale):
		return errStaleCode
	case errors.Is(err, fs.ErrNotExist):
		return errNoent
	case errors.Is(err, fs.ErrPermission):
		return errAcces
	case errors.As(err, &errno):
		switch errno {
		case syscall.ENOTDIR:
			return errNotdir
		case syscall.EISDIR:
			return errIsdir
		case syscall.ENAMETOOLONG:
			return errNametoolong
		case syscall.EPERM:
			return errPerm
		}
	}
	// os.Root refuses paths that leave the root.
	return errAcces
}
