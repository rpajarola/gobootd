// Package mop implements the load part of DEC's Maintenance Operation
// Protocol (MOP Dump/Load), which the console firmware of VAXen, DECstations,
// Alphas and DEC terminal servers uses to load a boot program.
//
// It follows NetBSD's mopd. A client multicasts a program request to
// AB-00-00-01-00-00; servers that have the program volunteer, and the
// client repeats its request to one of them. The server then sends the
// image in memory load messages, each acknowledged by a request for the
// next, and ends with a parameter load that carries the transfer address.
// Messages travel in Ethernet II frames (type 6001) or 802.3 frames with
// a SNAP header, and replies use the client's framing.
package mop

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.MOP, func() daemon.Service { return &Server{} }) }

const (
	// maxData is the most image data in one memory load, which fills an
	// Ethernet frame.
	maxData = 1492
	// sessionTimeout drops loads of clients that stopped asking.
	sessionTimeout = 10 * time.Minute
	// nameLen is the longest server name sent: a DECnet node name.
	nameLen = 6
)

// Options are the settings in the mop service block.
type Options struct {
	// ServerName is sent to clients in the parameter load that ends a
	// load. Defaults to the host name up to the first dot.
	ServerName string `hcl:"server_name,optional"`
}

// Server loads boot images over MOP.
type Server struct {
	opts Options

	mu       sync.Mutex
	sessions map[string]*session // by client MAC
}

type session struct {
	host *inventory.Host
	file *inventory.File
	f    *os.File
	img  *image
	fr   framing
	bsz  int
	// count is the load number of the last message, which carries the
	// image from off up to next.
	count     byte
	off, next int64
	last      []byte
	done      bool // the last message was the parameter load
	seen      time.Time
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	s.setup()
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

func (s *Server) setup() {
	if s.opts.ServerName == "" {
		h, _ := os.Hostname()
		s.opts.ServerName, _, _ = strings.Cut(h, ".")
		s.opts.ServerName = strings.ToUpper(s.opts.ServerName)
	}
	if len(s.opts.ServerName) > nameLen {
		s.opts.ServerName = s.opts.ServerName[:nameLen]
	}
	s.sessions = map[string]*session{}
}

func (s *Server) handle(env *daemon.Env, port link.Port, frame []byte) {
	iface := port.Interface()
	f, ok := link.Parse(frame)
	if !ok || string(f.Src) == string(iface.MAC) {
		return
	}
	msg, fr, ok := unwrap(f)
	if !ok {
		return
	}
	mcast := string(f.Dst) == string(Multicast)
	if !mcast && string(f.Dst) != string(iface.MAC) {
		return // for another server
	}
	log := env.Log.With("network", iface.Name, "client", f.Src.String())
	switch msg[0] {
	case codeRPR:
		req, ok := parseRequest(msg[1:])
		if !ok {
			log.Debug("malformed program request", "msg", fmt.Sprintf("%x", msg))
			return
		}
		log.Info("received", "packet", req.LogValue(), "multicast", mcast, "framing", fr.String())
		s.request(env, log, port, f, fr, req, mcast)
	case codeRML:
		if mcast || len(msg) < 3 {
			return
		}
		s.next(log, port, f, msg[1], msg[2])
	default:
		log.Debug("ignoring message", "code", msg[0])
	}
}

// request answers a program request: a multicast one with a volunteer if
// the client may load the program, and a direct one by starting the load.
func (s *Server) request(env *daemon.Env, log *slog.Logger, port link.Port, f link.Frame, fr framing, req request, mcast bool) {
	h, err := env.Inventory().ByMAC(f.Src)
	if err != nil {
		log.Info(fmt.Sprintf("mop request from %s denied (%v)", f.Src, err))
		return
	}
	log = log.With("host", h.Name)
	file, how, err := FindFile(h, req.Software)
	if err != nil {
		log.Info(fmt.Sprintf("mop request from %s denied (%v)", h.Name, err))
		return
	}
	fd, err := os.Open(file.Path)
	if err != nil {
		log.Warn(fmt.Sprintf("mop request from %s failed (%v)", h.Name, err))
		return
	}
	st, err := fd.Stat()
	var img *image
	if err == nil {
		img, err = loadImage(fd, st.Size())
	}
	if err != nil {
		fd.Close()
		log.Warn(fmt.Sprintf("mop request from %s failed (%s: %v)", h.Name, file.Path, err))
		return
	}
	iface := port.Interface()
	if mcast {
		fd.Close()
		s.send(log, port, wrap(fr, f.Src, iface.MAC, []byte{codeASV}))
		log.Info(fmt.Sprintf("mop request from %s: volunteering to load %s", h.Name, file.Path), "requested", req.Software, "match", how.String())
		return
	}

	bsz := req.BufSize
	switch {
	case bsz == 1030: // VAXstation and MicroVAX 2000, as in mopd
		bsz = 1000
	case bsz < 16 || bsz > maxData:
		bsz = maxData
	}
	if fr == ieee8023 {
		bsz -= len(snapDL)
	}
	sess := &session{host: h, file: file, f: fd, img: img, fr: fr, bsz: bsz, seen: time.Now()}
	s.mu.Lock()
	if old, ok := s.sessions[f.Src.String()]; ok {
		old.f.Close()
	}
	s.sessions[f.Src.String()] = sess
	err = s.load(sess, iface.MAC)
	if err != nil {
		delete(s.sessions, f.Src.String())
		fd.Close()
	}
	s.mu.Unlock()
	if err != nil {
		log.Warn(fmt.Sprintf("mop load of %s for %s failed (%v)", file.Path, h.Name, err))
		return
	}
	log.Info(fmt.Sprintf("mop request from %s: sending %s", h.Name, file.Path),
		"requested", req.Software, "match", how.String(), "image", img.String(), "block", bsz)
	s.send(log, port, wrap(fr, f.Src, iface.MAC, sess.last))
}

// load builds the message with the image from sess.off: a memory load, or
// the parameter load after the end of the image. s.mu must be held.
func (s *Server) load(sess *session, mac []byte) error {
	if sess.off >= sess.img.size {
		sess.last = parameterLoad(sess.count, s.opts.ServerName, mac, time.Now(), sess.img.xfer)
		sess.next, sess.done = sess.off, true
		return nil
	}
	buf := make([]byte, min(int64(sess.bsz), sess.img.size-sess.off))
	n, err := sess.img.readAt(sess.f, buf, sess.off)
	if err != nil {
		return err
	}
	sess.last = memoryLoad(sess.count, sess.img.load+uint32(sess.off), buf[:n])
	sess.next = sess.off + int64(n)
	return nil
}

// next answers a request for the next memory load: load is the number of
// the message the client wants, which repeats the last one if it was
// lost.
func (s *Server) next(log *slog.Logger, port link.Port, f link.Frame, load, errcode byte) {
	iface := port.Interface()
	client := f.Src.String()
	s.mu.Lock()
	sess, ok := s.sessions[client]
	if !ok {
		s.mu.Unlock()
		log.Debug("memory load request without a load", "load", load)
		return
	}
	sess.seen = time.Now()
	log = log.With("host", sess.host.Name)
	switch load {
	case sess.count:
		log.Debug("repeating memory load", "load", load, "error", errcode)
	case sess.count + 1:
		if sess.done {
			sess.f.Close()
			delete(s.sessions, client)
			s.mu.Unlock()
			log.Info(fmt.Sprintf("mop load of %s for %s complete", sess.file.Path, sess.host.Name), "bytes", sess.img.size)
			return
		}
		sess.count, sess.off = load, sess.next
		if err := s.load(sess, iface.MAC); err != nil {
			sess.f.Close()
			delete(s.sessions, client)
			s.mu.Unlock()
			log.Warn(fmt.Sprintf("mop load of %s for %s failed (%v)", sess.file.Path, sess.host.Name, err))
			return
		}
	default:
		s.mu.Unlock()
		log.Debug("memory load request out of sequence", "load", load, "expected", sess.count+1)
		return
	}
	frame := wrap(sess.fr, f.Src, iface.MAC, sess.last)
	off := sess.off
	s.mu.Unlock()
	log.Log(context.Background(), slog.LevelDebug-1, "sent", "load", load, "offset", off)
	s.send(log, port, frame)
}

func (s *Server) send(log *slog.Logger, port link.Port, frame []byte) {
	if err := port.WriteFrame(frame); err != nil {
		log.Warn("sending reply failed", "err", err)
	}
}

// FindFile finds the file a client asks for. Clients ask by name without
// the .SYS that mopd needs on its files, and often in capitals, so these
// are tried too. An empty name selects the host's first MOP file.
func FindFile(h *inventory.Host, name string) (*inventory.File, inventory.MatchKind, error) {
	f, kind, err := h.File(service.MOP, name)
	if name == "" || (err == nil && kind < inventory.MatchWildcard) {
		return f, kind, err
	}
	lower := strings.ToLower(name)
	for _, alt := range []string{name + ".SYS", lower, lower + ".sys"} {
		if af, akind, aerr := h.File(service.MOP, alt); aerr == nil && (err != nil || akind < kind) {
			f, kind, err = af, akind, nil
		}
	}
	return f, kind, err
}

func (s *Server) expire(log *slog.Logger, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c, sess := range s.sessions {
		if now.Sub(sess.seen) > sessionTimeout {
			log.Info(fmt.Sprintf("mop load of %s for %s timed out", sess.file.Path, sess.host.Name), "client", c, "sent", sess.off)
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

// Describe says how the file at p would be loaded.
func Describe(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	img, err := loadImage(f, st.Size())
	if err != nil {
		return "", err
	}
	return img.String(), nil
}
