package smb

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/netbios"
	"github.com/rpajarola/gobootd/internal/version"
)

const (
	// ourMaxBuffer is the largest message clients may send.
	ourMaxBuffer = 16644
	// defaultClientBuffer is what a client takes before it says.
	defaultClientBuffer = 4356
	maxMpx              = 10
	maxTrees            = 32
	maxFiles            = 256
	maxSearches         = 64
	ipcShare            = "IPC$"
)

// level is how much of LAN Manager a dialect has.
type level int

const (
	levelCore level = iota
	levelCorePlus
	levelLanman1
	levelLanman12
	levelLanman21
)

// dialects in order of preference.
var dialects = []struct {
	name  string
	level level
}{
	{"LANMAN2.1", levelLanman21},
	{"DOS LANMAN2.1", levelLanman21},
	{"LM1.2X002", levelLanman12},
	{"DOS LM1.2X002", levelLanman12},
	{"Windows for Workgroups 3.1a", levelLanman1},
	{"LANMAN1.0", levelLanman1},
	{"MICROSOFT NETWORKS 3.0", levelLanman1},
	{"MICROSOFT NETWORKS 1.03", levelCorePlus},
	{"PC NETWORK PROGRAM 1.0", levelCore},
	{"PCLAN1.0", levelCore},
}

// conn is an SMB session.
type conn struct {
	s         *Server
	nc        netbios.Conn
	host      *inventory.Host
	transport string
	log       *slog.Logger

	dialect string
	level   level
	maxBuf  int
	key     uint32
	user    string

	// The TID and UID of the command being handled, which a chained
	// tree connect or session setup changes for those after it.
	curTID, curUID uint16
	// chainFID is the file a chained open opened, which the commands
	// chained after it use.
	chainFID uint16

	trees    map[uint16]*tree
	files    map[uint16]*file
	searches map[uint16]*search // TRANS2 searches by SID, core ones by 0x8000|id
	nextTID  uint16
	nextFID  uint16
	nextSID  uint16
	nextCore byte
	trans    *partialTrans
}

// tree is a connected share.
type tree struct {
	tid      uint16
	name     string
	share    *inventory.Share // nil for IPC$
	root     *os.Root
	writable bool
}

type handler func(c *conn, r *request, rp *reply) error

var handlers map[byte]handler

func init() {
	handlers = map[byte]handler{
		cmdNegotiate:          (*conn).negotiate,
		cmdSessionSetupAndX:   (*conn).sessionSetup,
		cmdLogoffAndX:         (*conn).logoff,
		cmdTreeConnect:        (*conn).treeConnect,
		cmdTreeConnectAndX:    (*conn).treeConnectAndX,
		cmdTreeDisconnect:     (*conn).treeDisconnect,
		cmdProcessExit:        (*conn).processExit,
		cmdCreateDirectory:    (*conn).mkdir,
		cmdDeleteDirectory:    (*conn).rmdir,
		cmdOpen:               (*conn).open,
		cmdCreate:             (*conn).create,
		cmdCreateNew:          (*conn).create,
		cmdCreateTemporary:    (*conn).createTemporary,
		cmdClose:              (*conn).close,
		cmdFlush:              (*conn).flush,
		cmdDelete:             (*conn).delete,
		cmdRename:             (*conn).rename,
		cmdQueryInformation:   (*conn).queryInformation,
		cmdSetInformation:     (*conn).setInformation,
		cmdRead:               (*conn).read,
		cmdLockAndRead:        (*conn).read,
		cmdWrite:              (*conn).write,
		cmdWriteAndUnlock:     (*conn).write,
		cmdWriteAndClose:      (*conn).writeAndClose,
		cmdLockByteRange:      (*conn).lock,
		cmdUnlockByteRange:    (*conn).lock,
		cmdSeek:               (*conn).seek,
		cmdCheckDirectory:     (*conn).checkDirectory,
		cmdQueryInformationDk: (*conn).queryDisk,
		cmdSearch:             (*conn).search,
		cmdFind:               (*conn).search,
		cmdFindUnique:         (*conn).search,
		cmdFindClose:          (*conn).findClose,
		cmdQueryInformation2:  (*conn).queryInformation2,
		cmdSetInformation2:    (*conn).setInformation2,
		cmdOpenAndX:           (*conn).openAndX,
		cmdReadAndX:           (*conn).readAndX,
		cmdWriteAndX:          (*conn).writeAndX,
		cmdLockingAndX:        (*conn).lockingAndX,
		cmdFindClose2:         (*conn).findClose2,
		cmdTransaction:        (*conn).transaction,
		cmdTransaction2:       (*conn).transaction,
		cmdTransactionSec:     (*conn).transactionSecondary,
		cmdTransaction2Sec:    (*conn).transactionSecondary,
		cmdReadRaw:            (*conn).readRaw,
	}
}

// handle answers one message. Most messages get one reply; ECHO and large
// transactions get several, and some none.
func (c *conn) handle(msg []byte) [][]byte {
	if len(msg) < hdrLen+3 || string(msg[:4]) != "\xffSMB" {
		c.log.Debug("ignoring a message that is not SMB", "len", len(msg))
		return nil
	}
	cmd := msg[offCommand]
	if cmd == cmdEcho {
		return c.echo(msg)
	}
	out := make([]byte, hdrLen, 512)
	copy(out, msg[:hdrLen])
	out[offFlags] = flagReply | flagCaseless
	le.PutUint16(out[offFlags2:], le.Uint16(msg[offFlags2:])&flags2LongNames)
	clear(out[offClass : offError+2])
	c.curTID, c.curUID = le.Uint16(msg[offTID:]), le.Uint16(msg[offUID:])
	c.chainFID = 0

	off, prevAndX := hdrLen, -1
	var status error
	var trans *transResult
	for {
		rp := &reply{base: len(out)}
		r, err := parseBlock(msg, cmd, off)
		if err == nil {
			r.tid, r.uid = c.curTID, c.curUID
			r.chained = off != hdrLen
			err = c.dispatch(r, rp)
		}
		if err == nil && rp.raw != nil {
			return [][]byte{rp.raw}
		}
		if err == nil && rp.noReply {
			return nil
		}
		if prevAndX >= 0 {
			out[prevAndX] = cmd
			le.PutUint16(out[prevAndX+2:], uint16(len(out)))
		}
		if err != nil {
			status = err
			out = append(out, 0, 0, 0)
			break
		}
		if rp.trans != nil {
			trans = rp.trans
			break
		}
		out = append(out, byte(len(rp.words)/2))
		out = append(out, rp.words...)
		out = le.AppendUint16(out, uint16(len(rp.data)))
		out = append(out, rp.data...)
		if !andX(cmd) || len(r.words) < 4 || len(rp.words) < 4 {
			break
		}
		out[rp.base+1], out[rp.base+2] = cmdNone, 0
		le.PutUint16(out[rp.base+3:], 0)
		next, nextOff := r.words[0], int(le.Uint16(r.words[2:]))
		if next == cmdNone || nextOff <= off || nextOff >= len(msg) {
			break
		}
		prevAndX = rp.base + 1
		cmd, off = next, nextOff
	}
	le.PutUint16(out[offTID:], c.curTID)
	le.PutUint16(out[offUID:], c.curUID)
	if status != nil {
		e := toSMB(status)
		out[offClass] = e.class
		le.PutUint16(out[offError:], e.code)
		if e == errGeneral {
			c.log.Warn("smb command failed", "command", fmt.Sprintf("%#02x", cmd), "err", status)
		} else {
			c.log.Log(context.Background(), slog.LevelDebug-1, "smb error", "command", fmt.Sprintf("%#02x", cmd), "class", e.class, "code", e.code)
		}
	}
	if trans != nil {
		return c.transReplies(out, trans)
	}
	return [][]byte{out}
}

func (c *conn) dispatch(r *request, rp *reply) error {
	h, ok := handlers[r.cmd]
	if !ok {
		c.log.Debug("unsupported smb command", "command", fmt.Sprintf("%#02x", r.cmd))
		return errSMBCmd
	}
	c.log.Log(context.Background(), slog.LevelDebug-1, "smb request", "command", fmt.Sprintf("%#02x", r.cmd), "tid", r.tid, "pid", r.pid, "mid", r.mid)
	return h(c, r, rp)
}

// echo answers ECHO with as many replies as asked for.
func (c *conn) echo(msg []byte) [][]byte {
	r, err := parseBlock(msg, cmdEcho, hdrLen)
	if err != nil {
		return nil
	}
	var out [][]byte
	for i := range min(int(r.word(0)), 16) {
		b := make([]byte, hdrLen, hdrLen+5+len(r.data))
		copy(b, msg[:hdrLen])
		b[offFlags] = flagReply | flagCaseless
		clear(b[offClass : offError+2])
		b = append(b, 1)
		b = le.AppendUint16(b, uint16(i+1))
		b = le.AppendUint16(b, uint16(len(r.data)))
		out = append(out, append(b, r.data...))
	}
	return out
}

func (c *conn) closeAll() {
	for _, f := range c.files {
		f.f.Close()
	}
	for _, t := range c.trees {
		if t.root != nil {
			t.root.Close()
		}
	}
}

// negotiate picks the best dialect the client knows.
func (c *conn) negotiate(r *request, rp *reply) error {
	var offered []string
	for b := r.data; len(b) > 0; {
		var s string
		var ok bool
		if s, b, ok = bufferString(b); !ok {
			break
		}
		offered = append(offered, s)
	}
	idx := -1
	for _, d := range dialects {
		if i := slices.Index(offered, d.name); i >= 0 {
			idx, c.dialect, c.level = i, d.name, d.level
			break
		}
	}
	if idx < 0 {
		c.log.Info(fmt.Sprintf("smb session from %s: no dialect in common", c.host.Name), "offered", strings.Join(offered, ", "))
		rp.w16(0xffff)
		return nil
	}
	c.log.Debug("smb dialect", "dialect", c.dialect, "offered", strings.Join(offered, ", "))
	rp.w16(uint16(idx))
	if c.level < levelLanman1 {
		return nil
	}
	now := time.Now()
	date, tm := dosDateTime(now)
	_, offset := now.Zone()
	rp.w16(0) // security mode: share level, plain text passwords
	rp.w16(ourMaxBuffer)
	rp.w16(maxMpx)
	rp.w16(1) // virtual circuits
	rp.w16(0) // no raw mode
	rp.w32(c.key)
	rp.w16(tm)
	rp.w16(date)
	rp.w16(uint16(int16(-offset / 60))) // minutes west of UTC
	rp.w16(0)                           // no encryption key
	rp.w16(0)
	if c.level >= levelLanman12 {
		rp.str(c.s.opts.Workgroup)
	}
	return nil
}

// sessionSetup takes any user: shares are given by host, not by user.
func (c *conn) sessionSetup(r *request, rp *reply) error {
	if n := int(r.word(2)); n >= 512 {
		c.maxBuf = n
	}
	passLen := int(r.word(7))
	if passLen <= len(r.data) {
		c.user, _ = cstring(r.data[passLen:])
	}
	c.curUID = 100
	c.log.Debug("smb session setup", "user", c.user, "max_buffer", c.maxBuf)
	rp.andx()
	rp.w16(0)
	rp.str("Unix")
	rp.str("gobootd " + version.String())
	rp.str(c.s.opts.Workgroup)
	return nil
}

func (c *conn) logoff(r *request, rp *reply) error {
	rp.andx()
	return nil
}

// shareName returns the share of a \\SERVER\SHARE path.
func shareName(p string) string {
	p = strings.ReplaceAll(p, "/", `\`)
	if i := strings.LastIndexByte(p, '\\'); i >= 0 {
		p = p[i+1:]
	}
	return p
}

func (c *conn) connect(p, svc string) (*tree, error) {
	name := shareName(p)
	t := &tree{name: strings.ToUpper(name)}
	switch {
	case strings.EqualFold(name, ipcShare):
		if svc != "" && svc != "?????" && !strings.EqualFold(svc, "IPC") {
			return nil, errInvDevice
		}
	case svc != "" && svc != "?????" && !strings.EqualFold(svc, "A:"):
		c.log.Info(fmt.Sprintf("smb tree connect from %s to %s denied (service %q: only disks are shared)", c.host.Name, p, svc))
		return nil, errInvDevice
	default:
		sh, err := c.host.Share(name)
		if err != nil {
			c.log.Info(fmt.Sprintf("smb tree connect from %s to %s denied (%v)", c.host.Name, p, err))
			return nil, errInvNetName
		}
		root, err := os.OpenRoot(sh.Path)
		if err != nil {
			c.log.Warn(fmt.Sprintf("smb tree connect from %s to %s failed (%v)", c.host.Name, p, err))
			return nil, errInvNetName
		}
		t.share, t.root, t.writable = sh, root, sh.Writable
	}
	if len(c.trees) >= maxTrees {
		if t.root != nil {
			t.root.Close()
		}
		return nil, errSrvError
	}
	for {
		c.nextTID++
		if c.nextTID != 0 && c.nextTID != 0xffff && c.trees[c.nextTID] == nil {
			break
		}
	}
	t.tid = c.nextTID
	c.trees[t.tid] = t
	c.curTID = t.tid
	if t.share != nil {
		mode := "read-only"
		if t.writable {
			mode = "writable"
		}
		c.log.Info(fmt.Sprintf("smb tree connect from %s to %s: %s (%s)", c.host.Name, t.name, t.share.Path, mode), "tid", t.tid)
	}
	return t, nil
}

// treeConnect is the core protocol's tree connect.
func (c *conn) treeConnect(r *request, rp *reply) error {
	p, rest, _ := bufferString(r.data)
	_, rest, _ = bufferString(rest) // password
	svc, _, _ := bufferString(rest)
	t, err := c.connect(p, svc)
	if err != nil {
		return err
	}
	rp.w16(ourMaxBuffer)
	rp.w16(t.tid)
	return nil
}

func (c *conn) treeConnectAndX(r *request, rp *reply) error {
	if r.word(2)&1 != 0 {
		c.disconnect(r.tid)
	}
	passLen := int(r.word(3))
	if passLen > len(r.data) {
		return errBadData
	}
	p, rest := cstring(r.data[passLen:])
	svc, _ := cstring(rest)
	t, err := c.connect(p, svc)
	if err != nil {
		return err
	}
	rp.andx()
	if c.level >= levelLanman21 {
		rp.w16(1) // search bits supported
	}
	if t.share == nil {
		rp.str("IPC")
	} else {
		rp.str("A:")
	}
	if c.level >= levelLanman21 {
		rp.str("FAT")
	}
	return nil
}

func (c *conn) treeDisconnect(r *request, rp *reply) error {
	if c.trees[r.tid] == nil {
		return errInvTID
	}
	c.disconnect(r.tid)
	return nil
}

func (c *conn) disconnect(tid uint16) {
	t := c.trees[tid]
	if t == nil {
		return
	}
	for fid, f := range c.files {
		if f.tid == tid {
			f.f.Close()
			delete(c.files, fid)
		}
	}
	for id, s := range c.searches {
		if s.tid == tid {
			delete(c.searches, id)
		}
	}
	if t.root != nil {
		t.root.Close()
	}
	delete(c.trees, tid)
}

func (c *conn) processExit(r *request, rp *reply) error {
	for fid, f := range c.files {
		if f.pid == r.pid {
			f.f.Close()
			delete(c.files, fid)
		}
	}
	return nil
}

// tree returns the disk share of a request.
func (c *conn) tree(r *request) (*tree, error) {
	t := c.trees[r.tid]
	if t == nil {
		return nil, errInvTID
	}
	if t.root == nil {
		return nil, errNoAccess
	}
	return t, nil
}

// writableTree returns the share of a request that changes it.
func (c *conn) writableTree(r *request) (*tree, error) {
	t, err := c.tree(r)
	if err == nil && !t.writable {
		err = errNoAccess
	}
	return t, err
}

// splitPath splits a client's path into its components, resolving . and
// .. without leaving the share.
func splitPath(p string) ([]string, error) {
	var out []string
	for c := range strings.SplitSeq(strings.ReplaceAll(p, "/", `\`), `\`) {
		c = strings.TrimRight(c, " ")
		switch c {
		case "", ".":
		case "..":
			if len(out) == 0 {
				return nil, errBadPath
			}
			out = out[:len(out)-1]
		default:
			if strings.ContainsAny(c, "\x00:") {
				return nil, errBadPath
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// lookup finds the entry of dir that a client means by name: the name
// itself, the name in another case, or the 8.3 name of a long one.
func (t *tree) lookup(dir, name string) (string, bool) {
	if _, err := t.root.Lstat(path.Join(dir, name)); err == nil {
		return name, true
	}
	f, err := t.root.Open(dir)
	if err != nil {
		return "", false
	}
	defer f.Close()
	entries, err := f.ReadDir(-1)
	if err != nil {
		return "", false
	}
	mangled := ""
	up := strings.ToUpper(name)
	for _, e := range entries {
		if strings.EqualFold(e.Name(), name) {
			return e.Name(), true
		}
		if mangled == "" && dosName(e.Name()) == up {
			mangled = e.Name()
		}
	}
	return mangled, mangled != ""
}

// resolve turns a client's path into one relative to the share root. With
// create, the last component need not exist; it is then the name as the
// client gave it, in lower case if the client knows only 8.3 names.
func (t *tree) resolve(p string, create, longNames bool) (string, bool, error) {
	comps, err := splitPath(p)
	if err != nil {
		return "", false, err
	}
	rel := "."
	for i, comp := range comps {
		name, ok := t.lookup(rel, comp)
		if !ok {
			if i < len(comps)-1 {
				return "", false, errBadPath
			}
			if !create {
				return "", false, errBadFile
			}
			if !longNames {
				comp = strings.ToLower(comp)
			}
			return path.Join(rel, comp), false, nil
		}
		rel = path.Join(rel, name)
	}
	return rel, true, nil
}

// splitPattern splits a path into its directory and last component, for
// commands that take wildcards.
func splitPattern(p string) (string, string) {
	p = strings.ReplaceAll(p, "/", `\`)
	i := strings.LastIndexByte(p, '\\')
	return p[:i+1], p[i+1:]
}

// attributes returns the DOS attributes of a file.
func attributes(name string, fi fs.FileInfo) uint16 {
	var a uint16
	if fi.IsDir() {
		a |= attrDirectory
	} else {
		a |= attrArchive
	}
	if fi.Mode().Perm()&0o200 == 0 {
		a |= attrReadOnly
	}
	if strings.HasPrefix(name, ".") && name != "." && name != ".." {
		a |= attrHidden
	}
	return a
}

// Resolve finds what a client's path, SHARE or SHARE\DIR\FILE, leads to on
// this server, as a session of h would: names match in any case and by
// their 8.3 names.
func Resolve(h *inventory.Host, p string) (*inventory.Share, string, error) {
	p = strings.TrimLeft(strings.ReplaceAll(p, "/", `\`), `\`)
	name, rest, _ := strings.Cut(p, `\`)
	sh, err := h.Share(name)
	if err != nil {
		return nil, "", err
	}
	root, err := os.OpenRoot(sh.Path)
	if err != nil {
		return sh, "", err
	}
	defer root.Close()
	t := &tree{root: root}
	rel, _, err := t.resolve(rest, false, true)
	if err != nil {
		if errors.Is(err, errBadPath) {
			return sh, "", fmt.Errorf("path %q not found", rest)
		}
		return sh, "", fmt.Errorf("file %q not found", rest)
	}
	return sh, path.Join(sh.Path, rel), nil
}

// DOSName returns the 8.3 name DOS clients see for a file name.
func DOSName(name string) string { return dosName(name) }
