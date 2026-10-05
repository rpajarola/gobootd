// Package rmp implements HP's Remote Maintenance Protocol, which the boot
// ROMs of HP 9000/300 and /400 workstations use to load a boot program.
//
// The protocol is undocumented; this follows FreeBSD's rbootd and a packet
// trace of an HP 425t. A client first probes with boot requests on
// session 0xffff: sequence 0 asks for the server's name, sequence n for the
// name of the nth boot file. It then opens a file with a boot request, reads
// it with read requests that carry a file offset, and ends with boot done.
package rmp

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
	"sync"
	"syscall"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.RMP, func() daemon.Service { return &Server{} }) }

// Match selects 802.3 frames for the HP SAP.
func Match(f link.Frame) bool { return f.Type == 0 && len(f.Payload) > 0 && f.Payload[0] == sapHP }

// MatchKey is the class match key for the machine type clients send.
const MatchKey = "rmp_machtype"

// sessionTimeout drops sessions of clients that stopped reading.
const sessionTimeout = 10 * time.Minute

// Options are the settings in the rmp service block.
type Options struct {
	// ServerName is sent to clients that ask for the server's name.
	// Defaults to the host name up to the first dot.
	ServerName string `hcl:"server_name,optional"`
}

// Server serves boot files over RMP.
type Server struct {
	opts Options

	mu       sync.Mutex
	sessions map[string]*session // by client MAC
	lastSID  uint16
}

type session struct {
	id   uint16
	host *inventory.Host
	file *inventory.File
	f    *os.File
	sent int64
	seen time.Time
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.ServerName == "" {
		h, _ := os.Hostname()
		s.opts.ServerName, _, _ = strings.Cut(h, ".")
	}
	if len(s.opts.ServerName) > hostLen {
		s.opts.ServerName = s.opts.ServerName[:hostLen]
	}
	s.sessions = map[string]*session{}
	defer s.closeAll()

	ports, err := env.Subscribe(Match)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "network", p.Interface().Name, "server_name", s.opts.ServerName)
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				s.expire(env.Log, now)
			}
		}
	}()
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(env, p, frame) })
}

func (s *Server) handle(env *daemon.Env, port link.Port, frame []byte) {
	iface := port.Interface()
	f, ok := link.Parse(frame)
	if !ok || f.Type != 0 || string(f.Src) == string(iface.MAC) {
		return
	}
	if string(f.Dst) != string(Multicast) && string(f.Dst) != string(iface.MAC) {
		return // for another server
	}
	req, ok := Parse(f.Payload)
	if !ok {
		return
	}
	client := f.Src.String()
	log := env.Log.With("network", iface.Name, "client", client)
	lvl := slog.LevelInfo
	if req.Type == ReadReq && req.Seq != 0 {
		lvl = slog.LevelDebug - 1 // every block of a transfer
	}
	log.Log(context.Background(), lvl, "received", "packet", req)

	var repl *Packet
	switch req.Type {
	case BootReq:
		repl = s.boot(env, log, f, req)
	case ReadReq:
		repl = s.read(log, client, req)
	case BootDone:
		s.done(log, client, req)
	default:
		log.Warn("unexpected packet", "packet", req)
	}
	if repl == nil {
		return
	}
	if err := port.WriteFrame(link.Build8023(f.Src, iface.MAC, repl.Marshal())); err != nil {
		log.Warn("sending reply failed", "err", err)
		return
	}
	log.Log(context.Background(), lvl, "sent", "packet", *repl)
}

// boot answers probes and opens files.
func (s *Server) boot(env *daemon.Env, log *slog.Logger, f link.Frame, req Packet) *Packet {
	if req.Version != version {
		log.Info(fmt.Sprintf("rmp request from %s denied (version %d not supported)", f.Src, req.Version))
		return nil
	}
	inv := env.Inventory()
	h, err := inv.ByMAC(f.Src)
	if err != nil {
		cl := inv.MatchClass(MatchKey, req.MachType)
		if cl == nil {
			log.Info(fmt.Sprintf("rmp request from %s denied (client unknown, and no class matches %s = %s)", f.Src, MatchKey, req.MachType))
			return nil
		}
		h = inv.HostFromClass(cl, f.Src)
		log.Debug("unknown client matched class", "class", cl.Name, "machtype", req.MachType)
	}
	log = log.With("host", h.Name)
	if err := h.Allows(service.RMP); err != nil {
		log.Info(fmt.Sprintf("rmp request from %s denied (%v)", h.Name, err))
		return nil
	}
	repl := &Packet{Type: BootRepl, Seq: req.Seq, Version: version}

	if req.Session == probeSID {
		if req.Seq == 0 {
			repl.Filename = s.opts.ServerName
			return repl
		}
		files := h.FilesFor(service.RMP)
		if n := int(req.Seq) - 1; n < len(files) {
			repl.Filename = listName(files[n])
		} else {
			repl.RetCode = NoDefault
		}
		return repl
	}

	repl.Filename = req.Filename
	// HP-UX secondary loaders ask for paths like /hp-ux.
	file, how, err := h.FileIgnoringDir(service.RMP, req.Filename)
	if err != nil {
		log.Info(fmt.Sprintf("rmp boot request from %s denied (%v)", h.Name, err))
		repl.RetCode = NoFile
		return repl
	}
	fd, err := os.Open(file.Path)
	if err != nil {
		log.Warn(fmt.Sprintf("rmp boot request from %s failed (%v)", h.Name, err))
		switch {
		case errors.Is(err, fs.ErrNotExist):
			repl.RetCode = NoFile
		case errors.Is(err, syscall.EMFILE), errors.Is(err, syscall.ENFILE):
			repl.RetCode = Busy
		default:
			repl.RetCode = OpenFailed
		}
		return repl
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.sessions[f.Src.String()]; ok {
		log.Info("dropping previous session", "session", old.id)
		old.f.Close()
	}
	s.lastSID++
	if s.lastSID == 0 || s.lastSID == probeSID {
		s.lastSID = 1
	}
	s.sessions[f.Src.String()] = &session{id: s.lastSID, host: h, file: file, f: fd, seen: time.Now()}
	repl.Session = s.lastSID
	log.Info(fmt.Sprintf("rmp boot request from %s: sending %s", h.Name, file.Path),
		"requested", req.Filename, "match", how.String(), "session", s.lastSID)
	return repl
}

// listName is the name a file is announced under in probe replies.
func listName(f *inventory.File) string {
	if f.Name != "*" {
		return f.Name
	}
	for _, a := range f.Aliases {
		if a != "*" {
			return a
		}
	}
	return path.Base(f.Label)
}

func (s *Server) read(log *slog.Logger, client string, req Packet) *Packet {
	repl := &Packet{Type: ReadRepl, Seq: req.Seq, Session: req.Session}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[client]
	switch {
	case !ok:
		log.Info(fmt.Sprintf("rmp read request from %s aborted (no open session)", client))
		repl.RetCode = Abort
		return repl
	case sess.id != req.Session:
		log.Info(fmt.Sprintf("rmp read request from %s refused (session %d, expected %d)", sess.host.Name, req.Session, sess.id))
		repl.RetCode = BadSession
		return repl
	}
	sess.seen = time.Now()
	buf := make([]byte, min(int(req.Size), maxData))
	n, err := sess.f.ReadAt(buf, int64(req.Seq))
	repl.Data = buf[:n]
	sess.sent += int64(n)
	switch {
	case n == 0 && err == io.EOF:
		repl.RetCode = EOF
		log.Info(fmt.Sprintf("rmp transfer of %s to %s complete", sess.file.Path, sess.host.Name), "bytes", sess.sent)
	case err != nil && err != io.EOF:
		log.Warn(fmt.Sprintf("rmp read of %s for %s failed (%v)", sess.file.Path, sess.host.Name, err))
		repl.RetCode = Abort
	}
	return repl
}

func (s *Server) done(log *slog.Logger, client string, req Packet) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[client]
	if !ok || sess.id != req.Session {
		log.Info(fmt.Sprintf("rmp boot done from %s ignored (no such session)", client))
		return
	}
	sess.f.Close()
	delete(s.sessions, client)
	log.Info(fmt.Sprintf("rmp boot of %s complete", sess.host.Name), "file", sess.file.Path, "bytes", sess.sent)
}

func (s *Server) expire(log *slog.Logger, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, sess := range s.sessions {
		if now.Sub(sess.seen) > sessionTimeout {
			log.Info(fmt.Sprintf("rmp session of %s timed out", sess.host.Name), "client", c, "bytes", sess.sent)
			sess.f.Close()
			delete(s.sessions, c)
		}
	}
}

func (s *Server) closeAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, sess := range s.sessions {
		sess.f.Close()
		delete(s.sessions, c)
	}
}
