// Package ftpd serves the files and exports of a host read-only over
// anonymous FTP (RFC 959), for installers that fetch their sets that way,
// such as NetBSD's sysinst. Paths are the ones NFS clients mount, as with
// WebNFS; see package pubfs.
//
// Clients are identified by their IP address; the only users are
// "anonymous" and "ftp", with any password. Passive (PASV, EPSV) and active
// (PORT, EPRT, to the client's own address only) data connections work, as
// do SIZE, MDTM and REST (RFC 3659).
package ftpd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/netip"
	"path"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/netif"
	"github.com/rpajarola/gobootd/internal/proto/pubfs"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.FTP, func() daemon.Service { return &Server{} }) }

// Options are the settings in the ftp service block.
type Options struct {
	// Port is the control port to listen on. Default 21.
	Port int `hcl:"port,optional"`
}

const (
	idleTimeout = 5 * time.Minute
	dataTimeout = 30 * time.Second
	maxLine     = 4096
)

// Server serves files over FTP.
type Server struct {
	opts Options
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.Port <= 0 {
		s.opts.Port = 21
	}
	if len(env.Networks) == 0 {
		return errors.New("no network")
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, n := range env.Networks {
		l, err := n.IP.ListenTCP(uint16(s.opts.Port))
		if err != nil {
			cancel(nil)
			return fmt.Errorf("network %s: %w", n.Name(), err)
		}
		env.Log.Info("listening", "network", n.Name(), "addr", netip.AddrPortFrom(n.Addr().Addr(), uint16(s.opts.Port)).String())
		stop := context.AfterFunc(ctx, func() { l.Close() })
		defer stop()
		wg.Go(func() {
			for {
				c, err := l.Accept()
				if err != nil {
					if ctx.Err() == nil {
						cancel(fmt.Errorf("network %s: %w", n.Name(), err))
					}
					return
				}
				wg.Go(func() {
					defer c.Close()
					stop := context.AfterFunc(ctx, func() { c.Close() })
					defer stop()
					newSession(ctx, env, n, c).run()
				})
			}
		})
	}
	<-ctx.Done()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// session is one control connection.
type session struct {
	ctx  context.Context
	env  *daemon.Env
	n    *netif.Network
	c    net.Conn
	r    *bufio.Reader
	ip   netip.Addr
	log  *slog.Logger
	host *inventory.Host

	user     string // after USER
	loggedIn bool
	cwd      string
	ascii    bool
	rest     int64
	epsvAll  bool

	// pasv is the listener of a passive data connection, active the
	// client's address for an active one.
	pasv   net.Listener
	active netip.AddrPort
}

func newSession(ctx context.Context, env *daemon.Env, n *netif.Network, c net.Conn) *session {
	ip := addrOf(c.RemoteAddr()).Addr()
	return &session{
		ctx: ctx, env: env, n: n, c: c, r: bufio.NewReaderSize(c, maxLine), ip: ip, cwd: "/", ascii: true,
		log: env.Log.With("network", n.Name(), "client", ip.String()),
	}
}

func addrOf(a net.Addr) netip.AddrPort {
	if t, ok := a.(*net.TCPAddr); ok {
		ap := t.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// reply sends a reply; a text with several lines becomes a multi-line
// reply.
func (s *session) reply(code int, format string, args ...any) {
	lines := strings.Split(fmt.Sprintf(format, args...), "\n")
	var b strings.Builder
	for i, l := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		if i > 0 && i < len(lines)-1 {
			fmt.Fprintf(&b, " %s\r\n", l)
			continue
		}
		fmt.Fprintf(&b, "%d%s%s\r\n", code, sep, l)
	}
	s.c.SetWriteDeadline(time.Now().Add(dataTimeout))
	io.WriteString(s.c, b.String())
}

func (s *session) run() {
	defer s.closeData()
	h, err := s.env.Inventory().ByIP(s.ip)
	if err == nil {
		err = h.Allows(service.FTP)
	}
	if err != nil {
		who := s.ip.String()
		if h != nil {
			who = h.Name
		}
		s.log.Info(fmt.Sprintf("ftp connection from %s denied (%v)", who, err))
		s.reply(421, "Service not available for %s.", s.ip)
		return
	}
	s.host = h
	s.log = s.log.With("host", h.Name)
	s.reply(220, "bootd FTP server ready, anonymous only.")
	for {
		s.c.SetReadDeadline(time.Now().Add(idleTimeout))
		line, err := s.readLine()
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				s.reply(500, "Line too long.")
				continue
			}
			if s.ctx.Err() == nil && !errors.Is(err, io.EOF) {
				s.log.Debug("ftp connection closed", "err", err)
			}
			return
		}
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		if cmd == "PASS" {
			s.log.Debug("ftp command", "cmd", cmd)
		} else {
			s.log.Debug("ftp command", "cmd", cmd, "arg", arg)
		}
		if !s.command(cmd, arg) {
			return
		}
	}
}

var errLineTooLong = errors.New("line too long")

// readLine reads a command line, dropping Telnet commands.
func (s *session) readLine() (string, error) {
	line, err := s.r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = s.r.ReadSlice('\n')
		}
		if err != nil {
			return "", err
		}
		return "", errLineTooLong
	}
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		switch c := line[i]; {
		case c == 0xff && i+1 < len(line): // IAC
			i++
			if line[i] >= 0xfb && line[i] <= 0xfe { // WILL, WONT, DO, DONT
				i++
			}
		case c == '\r' || c == '\n':
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), nil
}

// command runs one command. It returns false to close the connection.
func (s *session) command(cmd, arg string) bool {
	switch cmd {
	case "USER":
		s.loggedIn = false
		switch strings.ToLower(arg) {
		case "anonymous", "ftp":
			s.user = arg
			s.reply(331, "Anonymous login ok, send your e-mail address as password.")
		default:
			s.user = ""
			s.reply(530, "Only anonymous login is allowed.")
		}
		return true
	case "PASS":
		if s.user == "" {
			s.reply(503, "Login with USER first.")
			return true
		}
		s.loggedIn = true
		s.log.Info(fmt.Sprintf("ftp login from %s", s.host.Name), "user", s.user)
		s.reply(230, "Login successful.")
		return true
	case "QUIT":
		s.reply(221, "Goodbye.")
		return false
	case "NOOP":
		s.reply(200, "NOOP ok.")
		return true
	case "SYST":
		s.reply(215, "UNIX Type: L8")
		return true
	case "FEAT":
		s.reply(211, "Features:\nEPRT\nEPSV\nMDTM\nPASV\nREST STREAM\nSIZE\nTVFS\nUTF8\nEnd")
		return true
	case "OPTS":
		if strings.EqualFold(strings.TrimSpace(arg), "UTF8 ON") {
			s.reply(200, "Always in UTF8 mode.")
		} else {
			s.reply(501, "Option not understood.")
		}
		return true
	case "HELP":
		s.reply(214, "The read-only commands of RFC 959 and SIZE, MDTM, REST, EPSV, EPRT are understood.")
		return true
	}
	if !s.loggedIn {
		s.reply(530, "Please login with USER and PASS.")
		return true
	}
	switch cmd {
	case "PWD", "XPWD":
		s.reply(257, "%q is the current directory.", s.cwd)
	case "CWD", "XCWD":
		s.cd(arg)
	case "CDUP", "XCUP":
		s.cd("..")
	case "TYPE":
		switch t := strings.ToUpper(strings.Join(strings.Fields(arg), " ")); t {
		case "A", "A N":
			s.ascii = true
			s.reply(200, "Type set to A.")
		case "I", "L 8":
			s.ascii = false
			s.reply(200, "Type set to I.")
		default:
			s.reply(504, "Type %s not supported.", arg)
		}
	case "MODE":
		s.onlyOne(arg, "S", "Mode")
	case "STRU":
		s.onlyOne(arg, "F", "Structure")
	case "ALLO", "ACCT":
		s.reply(202, "Not needed.")
	case "PASV":
		s.passive(false)
	case "EPSV":
		switch strings.ToUpper(strings.TrimSpace(arg)) {
		case "", "1":
			s.passive(true)
		case "ALL":
			s.epsvAll = true
			s.reply(200, "EPSV ALL ok.")
		default:
			s.reply(522, "Network protocol not supported, use (1)")
		}
	case "PORT", "EPRT":
		s.port(cmd, arg)
	case "REST":
		n, err := strconv.ParseInt(strings.TrimSpace(arg), 10, 64)
		if err != nil || n < 0 {
			s.reply(501, "Invalid restart position.")
			break
		}
		s.rest = n
		s.reply(350, "Restarting at %d. Send RETR to start the transfer.", n)
	case "SIZE":
		p := s.abs(arg)
		fi, err := s.tree().Stat(p)
		switch {
		case err != nil:
			s.fail(550, "size", p, err)
		case fi.IsDir():
			s.reply(550, "%s is a directory.", p)
		default:
			s.reply(213, "%d", fi.Size())
		}
	case "MDTM":
		p := s.abs(arg)
		if fi, err := s.tree().Stat(p); err != nil {
			s.fail(550, "mdtm", p, err)
		} else {
			s.reply(213, "%s", fi.ModTime().UTC().Format("20060102150405"))
		}
	case "RETR":
		s.retr(arg)
	case "LIST", "NLST":
		s.list(cmd == "LIST", arg)
	case "STAT":
		if arg != "" {
			s.reply(502, "STAT with a path is not supported; use LIST.")
			break
		}
		s.reply(211, "bootd FTP server status:\nLogged in anonymously from %s as host %s\nRead only\nEnd of status", s.ip, s.host.Name)
	case "ABOR":
		s.closeData()
		s.reply(226, "No transfer to abort.")
	case "STOR", "STOU", "APPE", "DELE", "RNFR", "RNTO", "MKD", "XMKD", "RMD", "XRMD", "SITE":
		s.reply(550, "Permission denied, the server is read only.")
	default:
		s.reply(502, "Command %s not implemented.", cmd)
	}
	return true
}

func (s *session) onlyOne(arg, want, what string) {
	if strings.EqualFold(strings.TrimSpace(arg), want) {
		s.reply(200, "%s set to %s.", what, want)
	} else {
		s.reply(504, "%s %s not supported.", what, arg)
	}
}

func (s *session) tree() *pubfs.Tree { return pubfs.New(s.host, service.FTP) }

// abs resolves a path against the current directory.
func (s *session) abs(p string) string {
	if !strings.HasPrefix(p, "/") {
		p = path.Join(s.cwd, p)
	}
	return pubfs.Clean(p)
}

// fail replies to a request for p that failed with err, and logs it.
func (s *session) fail(code int, what, p string, err error) {
	reason := err.Error()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		reason = "not found"
	case pubfs.IsNotDir(err):
		reason = "not a directory"
	case errors.Is(err, pubfs.ErrIsDir):
		reason = "is a directory"
	}
	s.log.Info(fmt.Sprintf("ftp %s from %s for %s denied (%s)", what, s.host.Name, p, reason))
	s.reply(code, "%s: %s.", p, reason)
}

func (s *session) cd(arg string) {
	p := s.abs(arg)
	fi, err := s.tree().Stat(p)
	switch {
	case err != nil:
		s.fail(550, "cwd", p, err)
	case !fi.IsDir():
		s.reply(550, "%s: not a directory.", p)
	default:
		s.cwd = p
		s.reply(250, "Directory changed to %s.", p)
	}
}

func (s *session) closeData() {
	if s.pasv != nil {
		s.pasv.Close()
		s.pasv = nil
	}
	s.active = netip.AddrPort{}
}

// passive opens a listener for the next data connection.
func (s *session) passive(extended bool) {
	if !extended && s.epsvAll {
		s.reply(503, "Only EPSV after EPSV ALL.")
		return
	}
	s.closeData()
	l, err := s.n.IP.ListenTCP(0)
	if err != nil {
		s.log.Warn("ftp passive listen failed", "err", err)
		s.reply(425, "Cannot open a passive connection.")
		return
	}
	s.pasv = l
	port := addrOf(l.Addr()).Port()
	if extended {
		s.reply(229, "Entering Extended Passive Mode (|||%d|)", port)
		return
	}
	a := s.n.Addr().Addr().As4()
	s.reply(227, "Entering Passive Mode (%d,%d,%d,%d,%d,%d).", a[0], a[1], a[2], a[3], port>>8, port&0xff)
}

// port sets the client's address for an active data connection. Only
// the client's own address is accepted, so the server cannot be used to
// connect elsewhere.
func (s *session) port(cmd, arg string) {
	if s.epsvAll {
		s.reply(503, "Only EPSV after EPSV ALL.")
		return
	}
	var ap netip.AddrPort
	var ok bool
	if cmd == "PORT" {
		ap, ok = parsePort(arg)
	} else {
		ap, ok = parseEPRT(arg)
		if !ok && strings.HasPrefix(arg, "|2|") {
			s.reply(522, "Network protocol not supported, use (1)")
			return
		}
	}
	switch {
	case !ok:
		s.reply(501, "Invalid %s argument.", cmd)
	case ap.Addr() != s.ip || ap.Port() < 1024:
		s.log.Info(fmt.Sprintf("ftp %s from %s denied (to %s, not the client)", strings.ToLower(cmd), s.host.Name, ap))
		s.reply(504, "Data connections go to %s only, on ports from 1024.", s.ip)
	default:
		s.closeData()
		s.active = ap
		s.reply(200, "%s command successful.", cmd)
	}
}

func parsePort(arg string) (netip.AddrPort, bool) {
	f := strings.Split(strings.TrimSpace(arg), ",")
	if len(f) != 6 {
		return netip.AddrPort{}, false
	}
	var b [6]byte
	for i, s := range f {
		n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 8)
		if err != nil {
			return netip.AddrPort{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[:4])), uint16(b[4])<<8|uint16(b[5])), true
}

func parseEPRT(arg string) (netip.AddrPort, bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 {
		return netip.AddrPort{}, false
	}
	f := strings.Split(arg[1:], arg[:1])
	if len(f) != 4 || f[0] != "1" || f[3] != "" {
		return netip.AddrPort{}, false
	}
	a, err := netip.ParseAddr(f[1])
	port, perr := strconv.ParseUint(f[2], 10, 16)
	if err != nil || !a.Is4() || perr != nil {
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(a, uint16(port)), true
}

// data opens the data connection set up by PASV, EPSV, PORT or EPRT,
// after replying 150. It replies itself and returns nil on failure.
func (s *session) data(what string) net.Conn {
	defer s.closeData()
	switch {
	case s.pasv != nil:
		s.reply(150, "Opening %s mode data connection for %s.", s.mode(), what)
		l := s.pasv
		stop := time.AfterFunc(dataTimeout, func() { l.Close() })
		defer stop.Stop()
		for {
			c, err := l.Accept()
			if err != nil {
				s.reply(425, "No data connection.")
				return nil
			}
			// Someone else may have found the port.
			if addrOf(c.RemoteAddr()).Addr() != s.ip {
				s.log.Info(fmt.Sprintf("ftp data connection from %s for %s refused", addrOf(c.RemoteAddr()).Addr(), s.host.Name))
				c.Close()
				continue
			}
			return c
		}
	case s.active.IsValid():
		s.reply(150, "Opening %s mode data connection for %s.", s.mode(), what)
		ctx, cancel := context.WithTimeout(s.ctx, dataTimeout)
		defer cancel()
		c, err := s.n.IP.DialTCP(ctx, s.active)
		if err != nil {
			s.reply(425, "Cannot open data connection to %s.", s.active)
			return nil
		}
		return c
	}
	s.reply(425, "Use PORT or PASV first.")
	return nil
}

func (s *session) mode() string {
	if s.ascii {
		return "ASCII"
	}
	return "BINARY"
}

// send copies r to a data connection and replies with the result.
func (s *session) send(c net.Conn, r io.Reader, ascii bool) (int64, bool) {
	defer c.Close()
	var w io.Writer = c
	if ascii {
		w = &crlfWriter{w: c}
	}
	stop := context.AfterFunc(s.ctx, func() { c.Close() })
	defer stop()
	n, err := io.Copy(&deadlineWriter{c: c, w: w}, r)
	if err != nil {
		s.reply(426, "Transfer aborted: %v.", err)
		return n, false
	}
	s.reply(226, "Transfer complete.")
	return n, true
}

func (s *session) retr(arg string) {
	p := s.abs(arg)
	// REST holds until the next transfer, whatever comes in between.
	rest := s.rest
	s.rest = 0
	f, err := s.tree().Open(p)
	if err != nil {
		s.fail(550, "request", p, err)
		return
	}
	defer f.Close()
	if rest > 0 {
		if _, err := f.Seek(rest, io.SeekStart); err != nil {
			s.reply(554, "Cannot restart at %d.", rest)
			return
		}
	}
	c := s.data(fmt.Sprintf("%s (%d bytes)", p, f.Info.Size()))
	if c == nil {
		return
	}
	attrs := []any{"bytes", f.Info.Size(), "mode", strings.ToLower(s.mode())}
	if rest > 0 {
		attrs = append(attrs, "offset", rest)
	}
	s.log.Info(fmt.Sprintf("ftp request from %s for %s: sending %s", s.host.Name, p, f.Source), attrs...)
	if n, ok := s.send(c, f, s.ascii); !ok {
		s.log.Info(fmt.Sprintf("ftp transfer of %s to %s aborted", p, s.host.Name), "sent", n)
	}
}

// list sends a directory listing: ls -l style for LIST, names for NLST.
func (s *session) list(long bool, arg string) {
	// Clients pass ls options, such as "-la".
	var args []string
	for _, a := range strings.Fields(arg) {
		if !strings.HasPrefix(a, "-") {
			args = append(args, a)
		}
	}
	s.rest = 0
	p := s.cwd
	if len(args) > 0 {
		p = s.abs(strings.Join(args, " "))
	}
	t := s.tree()
	fi, err := t.Stat(p)
	if err != nil {
		s.fail(550, "list", p, err)
		return
	}
	entries := []fs.FileInfo{fi}
	if fi.IsDir() {
		if entries, err = t.ReadDir(p); err != nil {
			s.fail(550, "list", p, err)
			return
		}
	}
	var b strings.Builder
	now := time.Now()
	for _, e := range entries {
		if !long {
			b.WriteString(e.Name() + "\r\n")
			continue
		}
		b.WriteString(lsLine(e, now) + "\r\n")
	}
	c := s.data("directory listing")
	if c == nil {
		return
	}
	s.log.Debug(fmt.Sprintf("ftp listing of %s for %s", p, s.host.Name))
	s.send(c, strings.NewReader(b.String()), false)
}

// lsLine formats an entry like ls -l does.
func lsLine(fi fs.FileInfo, now time.Time) string {
	kind, links := "-", 1
	if fi.IsDir() {
		kind, links = "d", 2
	}
	t := fi.ModTime()
	when := t.Format("Jan _2 15:04")
	if t.Before(now.AddDate(0, -6, 0)) || t.After(now.Add(time.Hour)) {
		when = t.Format("Jan _2  2006")
	}
	return fmt.Sprintf("%s%s %3d ftp      ftp      %12d %s %s", kind, fi.Mode().Perm().String()[1:], links, fi.Size(), when, fi.Name())
}

// crlfWriter turns line feeds into CR LF, for ASCII transfers.
type crlfWriter struct {
	w    io.Writer
	last byte
}

func (c *crlfWriter) Write(p []byte) (int, error) {
	out := make([]byte, 0, len(p)+len(p)/16)
	for _, b := range p {
		if b == '\n' && c.last != '\r' {
			out = append(out, '\r')
		}
		out = append(out, b)
		c.last = b
	}
	if _, err := c.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// deadlineWriter gives up when the client stops reading.
type deadlineWriter struct {
	c net.Conn
	w io.Writer
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	d.c.SetWriteDeadline(time.Now().Add(dataTimeout))
	return d.w.Write(p)
}
