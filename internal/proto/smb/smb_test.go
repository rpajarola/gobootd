package smb

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/llc"
	"github.com/rpajarola/gobootd/internal/netbios"
	"github.com/rpajarola/gobootd/internal/proto/prototest"
)

const conf = `
network "lan" {
  address = "192.168.1.1/24"
  udp     = "127.0.0.1:0" # not used: tests run on an in-memory segment
}
service "smb" {
  netbios_name = "bootd"
}
host "pc" {
  ip       = "192.168.1.5"
  mac      = "02:00:00:00:00:05"
  services = ["smb"]
  share "dos" { path = "dos" }
  share "data" {
    path     = "data"
    writable = true
  }
}
host "other" {
  ip       = "192.168.1.6"
  mac      = "02:00:00:00:00:06"
  services = []
}
`

type testEnv struct {
	*prototest.Env
	log *prototest.Log
	dir string
}

func start(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	for name, data := range map[string]string{
		"dos/AUTOEXEC.BAT":          "@echo off\r\n",
		"dos/readme.txt":            "hello",
		"dos/A Long File Name.text": "long",
		"dos/.hidden":               "h",
		"dos/sub/inner.txt":         strings.Repeat("x", 10000),
		"data/keep.txt":             "keep",
	} {
		p := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	e := prototest.Setup(t, dir, conf)
	log := e.Start(t, &Server{}, "smb")
	return &testEnv{Env: e, log: log, dir: dir}
}

// client is an SMB client for tests.
type client struct {
	t      *testing.T
	nc     netbios.Conn
	tid    uint16
	uid    uint16
	mid    uint16
	flags2 uint16
}

type response struct {
	msg   []byte
	class byte
	code  uint16
	words []byte
	data  []byte
}

func (r *response) word(i int) uint16 { return le.Uint16(r.words[2*i:]) }
func (r *response) ok() bool          { return r.class == 0 && r.code == 0 }

// message builds a request.
func (c *client) message(cmd byte, words, data []byte) []byte {
	c.mid++
	b := make([]byte, hdrLen)
	copy(b, "\xffSMB")
	b[offCommand] = cmd
	b[offFlags] = flagCaseless
	le.PutUint16(b[offFlags2:], c.flags2)
	le.PutUint16(b[offTID:], c.tid)
	le.PutUint16(b[offPID:], 1)
	le.PutUint16(b[offUID:], c.uid)
	le.PutUint16(b[offMID:], c.mid)
	b = append(b, byte(len(words)/2))
	b = append(b, words...)
	b = le.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

func (c *client) send(msg []byte) *response {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := c.nc.WriteMessage(ctx, msg); err != nil {
		c.t.Fatal(err)
	}
	return c.recv(ctx)
}

func (c *client) recv(ctx context.Context) *response {
	c.t.Helper()
	m, err := c.nc.ReadMessage(ctx)
	if err != nil {
		c.t.Fatal(err)
	}
	if len(m) < hdrLen+3 || m[offFlags]&flagReply == 0 {
		c.t.Fatalf("bad reply % x", m)
	}
	r := &response{msg: m, class: m[offClass], code: le.Uint16(m[offError:])}
	wc := int(m[hdrLen])
	r.words = m[hdrLen+1 : hdrLen+1+2*wc]
	bc := int(le.Uint16(m[hdrLen+1+2*wc:]))
	r.data = m[hdrLen+3+2*wc : hdrLen+3+2*wc+bc]
	return r
}

func (c *client) call(cmd byte, words, data []byte) *response {
	c.t.Helper()
	return c.send(c.message(cmd, words, data))
}

func w(vs ...uint16) []byte {
	var b []byte
	for _, v := range vs {
		b = le.AppendUint16(b, v)
	}
	return b
}

func dw(v uint32) []uint16 { return []uint16{uint16(v), uint16(v >> 16)} }

func ascii(s string) []byte { return append([]byte{0x04}, append([]byte(s), 0)...) }

func cat(bs ...[]byte) []byte { return bytes.Join(bs, nil) }

func expectError(t *testing.T, what string, r *response, want smbError) {
	t.Helper()
	if r.class != want.class || r.code != want.code {
		t.Errorf("%s: error %d/%d, want %d/%d", what, r.class, r.code, want.class, want.code)
	}
}

func (e *testEnv) tcp(t *testing.T, mac, ip string) *client {
	t.Helper()
	st := e.Client(t, mac, ip+"/24")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tc, err := st.DialTCP(ctx, netip.MustParseAddrPort("192.168.1.1:139"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tc.Close() })
	nc, err := netbios.DialNBT(tc, netbios.MakeName("BOOTD", netbios.Server), netbios.MakeName("PC", 0))
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, nc: nc}
}

// netbeui connects as a NetBEUI client.
func (e *testEnv) netbeui(t *testing.T, mac string) *client {
	t.Helper()
	p := e.Segment.Station(mac)
	st := &llc.Station{SAP: netbios.SAP, Port: p, T1: 100 * time.Millisecond, Log: slog.New(slog.DiscardHandler)}
	nbf := &netbios.NBF{Station: st}
	nbf.Init()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			f, err := p.ReadFrame(ctx)
			if err != nil {
				return
			}
			st.Handle(f)
		}
	})
	wg.Go(func() { st.Run(ctx) })
	t.Cleanup(func() { cancel(); wg.Wait() })
	dctx, dcancel := context.WithTimeout(ctx, 5*time.Second)
	defer dcancel()
	s, err := nbf.Dial(dctx, netbios.MakeName("BOOTD", netbios.Server), netbios.MakeName("PC", 0))
	if err != nil {
		t.Fatal(err)
	}
	return &client{t: t, nc: s}
}

var dosDialects = []string{"PC NETWORK PROGRAM 1.0", "MICROSOFT NETWORKS 3.0", "DOS LM1.2X002", "DOS LANMAN2.1"}

func (c *client) negotiate(dialects ...string) *response {
	var d []byte
	for _, s := range dialects {
		d = append(append(append(d, 0x02), s...), 0)
	}
	return c.call(cmdNegotiate, nil, d)
}

// connect negotiates the core protocol and connects to a share with the
// core tree connect.
func (c *client) connect(share string) *response {
	c.t.Helper()
	if r := c.negotiate("PC NETWORK PROGRAM 1.0"); !r.ok() || r.word(0) != 0 {
		c.t.Fatalf("negotiate: %+v", r)
	}
	r := c.call(cmdTreeConnect, nil, cat(ascii(`\\BOOTD\`+share), ascii(""), ascii("A:")))
	if r.ok() {
		c.tid = r.word(1)
	}
	return r
}

func TestNegotiate(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	r := c.negotiate(dosDialects...)
	if !r.ok() || len(r.words) != 26 || r.word(0) != 3 || r.word(1) != 0 || r.word(2) != ourMaxBuffer || r.word(5) != 0 {
		t.Errorf("LANMAN2.1 negotiate: %+v", r)
	}
	if !bytes.Contains(r.data, []byte("WORKGROUP\x00")) {
		t.Errorf("no domain in %q", r.data)
	}
	if r := c.negotiate("PC NETWORK PROGRAM 1.0", "XENIX CORE"); !r.ok() || len(r.words) != 2 || r.word(0) != 0 {
		t.Errorf("core negotiate: %+v", r)
	}
	if r := c.negotiate("NT LM 0.12"); !r.ok() || r.word(0) != 0xffff {
		t.Errorf("NT negotiate: %+v", r)
	}
	if !e.log.Contains("smb session from pc (PC over tcp)") {
		t.Error("session not logged")
	}
}

func TestDenied(t *testing.T) {
	e := start(t)
	st := e.Client(t, "02:00:00:00:00:06", "192.168.1.6/24")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tc, err := st.DialTCP(ctx, netip.MustParseAddrPort("192.168.1.1:139"))
	if err != nil {
		t.Fatal(err)
	}
	defer tc.Close()
	if _, err := netbios.DialNBT(tc, netbios.MakeName("BOOTD", netbios.Server), netbios.MakeName("OTHER", 0)); err == nil {
		t.Error("session for a host without smb")
	}
	if !e.log.Contains("smb session from other (OTHER over tcp) denied (smb not allowed for this host)") {
		t.Error("refusal not logged")
	}
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	if r := c.connect("nothere"); r.ok() {
		t.Error("connected to a share that is not configured")
	} else {
		expectError(t, "unknown share", r, errInvNetName)
	}
	if !e.log.Contains(`smb tree connect from pc to \\\\BOOTD\\nothere denied (share \"nothere\" not configured for this host)`) {
		t.Error("tree connect refusal not logged")
	}
}

// coreSearch searches with the core protocol until no more files come, and
// returns the names.
func (c *client) coreSearch(pattern string, attrs uint16, max uint16) []string {
	c.t.Helper()
	var names []string
	key := []byte{0x05, 0, 0}
	for {
		r := c.call(cmdSearch, w(max, attrs), cat(ascii(pattern), key))
		if r.class == errNoFiles.class && r.code == errNoFiles.code {
			return names
		}
		if !r.ok() {
			c.t.Fatalf("search %s: %d/%d", pattern, r.class, r.code)
		}
		n := int(r.word(0))
		ents := r.data[3:]
		if len(ents) != n*dirEntryLen {
			c.t.Fatalf("search returned %d bytes for %d entries", len(ents), n)
		}
		for i := range n {
			e := ents[i*dirEntryLen:]
			name, _ := cstring(e[30:43])
			names = append(names, name)
		}
		last := ents[(n-1)*dirEntryLen:]
		key = cat([]byte{0x05}, w(resumeKeyLen), last[:resumeKeyLen])
		pattern = ""
	}
}

func TestCoreSearch(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	if r := c.connect("DOS"); !r.ok() {
		t.Fatalf("connect: %+v", r)
	}
	long := mangle("A Long File Name.text")
	all := c.coreSearch(`\????????.???`, attrDirectory, 2)
	want := []string{long, "AUTOEXEC.BAT", "README.TXT", "SUB"}
	slices.Sort(all)
	slices.Sort(want)
	if !slices.Equal(all, want) {
		t.Errorf("search found %v, want %v", all, want)
	}
	if got := c.coreSearch(`\*.*`, attrHidden, 10); len(got) != 4 || !slices.Contains(got, mangle(".hidden")) {
		t.Errorf("hidden search found %v", got)
	}
	if got := c.coreSearch(`\SUB\*.*`, attrDirectory, 10); !slices.Equal(got, []string{".", "..", "INNER.TXT"}) {
		t.Errorf("subdirectory search found %v", got)
	}
	if got := c.coreSearch(`\R*.TXT`, 0, 10); !slices.Equal(got, []string{"README.TXT"}) {
		t.Errorf("README search found %v", got)
	}
	if got := c.coreSearch(`\NOTHERE.*`, 0, 10); len(got) != 0 {
		t.Errorf("found %v", got)
	}
	// The volume label.
	r := c.call(cmdSearch, w(1, attrVolume), cat(ascii(`\????????.???`), []byte{0x05, 0, 0}))
	if !r.ok() || r.word(0) != 1 || r.data[3+21] != attrVolume {
		t.Errorf("volume label: %+v", r)
	}
	// The long file opens by its 8.3 name.
	r = c.call(cmdOpen, w(0, 0), ascii(`\`+long))
	if !r.ok() || le.Uint32(r.words[8:]) != 4 {
		t.Errorf("open %s: %+v", long, r)
	}
}

func TestCoreFiles(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	if r := c.connect("DOS"); !r.ok() {
		t.Fatal("connect")
	}
	// Read a file in two pieces.
	r := c.call(cmdOpen, w(0, 0x16), ascii(`\SUB\INNER.TXT`))
	if !r.ok() || le.Uint32(r.words[8:]) != 10000 {
		t.Fatalf("open: %+v", r)
	}
	fid := r.word(0)
	var got []byte
	for off := uint32(0); off < 10000; {
		r = c.call(cmdRead, cat(w(fid, 4096), w(dw(off)...), w(0)), nil)
		if !r.ok() {
			t.Fatalf("read at %d: %+v", off, r)
		}
		n := int(r.word(0))
		if n == 0 || r.data[0] != 1 || int(le.Uint16(r.data[1:])) != n {
			t.Fatalf("read at %d: %d bytes, data % x", off, n, r.data[:3])
		}
		got = append(got, r.data[3:3+n]...)
		off += uint32(n)
	}
	if string(got) != strings.Repeat("x", 10000) {
		t.Error("read the wrong data")
	}
	if r = c.call(cmdClose, w(fid, 0, 0), nil); !r.ok() {
		t.Errorf("close: %+v", r)
	}
	expectError(t, "read after close", c.call(cmdRead, w(fid, 10, 0, 0, 0), nil), errBadFid)
	// Read-only share.
	expectError(t, "create", c.call(cmdCreate, w(0, 0, 0), ascii(`\NEW.TXT`)), errNoAccess)
	expectError(t, "open for writing", c.call(cmdOpen, w(accessReadWrite, 0), ascii(`\README.TXT`)), errNoAccess)
	expectError(t, "missing file", c.call(cmdOpen, w(0, 0), ascii(`\NOTHERE.TXT`)), errBadFile)
	expectError(t, "missing directory", c.call(cmdOpen, w(0, 0), ascii(`\NOWHERE\X.TXT`)), errBadPath)
	expectError(t, "escape", c.call(cmdOpen, w(0, 0), ascii(`\..\data\keep.txt`)), errBadPath)
	r = c.call(cmdQueryInformation, nil, ascii(`\README.TXT`))
	if !r.ok() || r.word(0) != attrArchive || le.Uint32(r.words[6:]) != 5 {
		t.Errorf("query information: %+v", r)
	}
	if r = c.call(cmdCheckDirectory, nil, ascii(`\SUB`)); !r.ok() {
		t.Errorf("check directory: %+v", r)
	}
	expectError(t, "check a file", c.call(cmdCheckDirectory, nil, ascii(`\README.TXT`)), errBadPath)
	if r = c.call(cmdQueryInformationDk, nil, nil); !r.ok() || r.word(2) != 512 {
		t.Errorf("disk: %+v", r)
	}
}

func TestWrite(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	if r := c.connect("DATA"); !r.ok() {
		t.Fatal("connect")
	}
	r := c.call(cmdCreate, w(0, 0, 0), ascii(`\NEW.TXT`))
	if !r.ok() {
		t.Fatalf("create: %+v", r)
	}
	fid := r.word(0)
	payload := []byte("written by DOS")
	r = c.call(cmdWrite, cat(w(fid, uint16(len(payload))), w(dw(0)...), w(0)), cat([]byte{1}, w(uint16(len(payload))), payload))
	if !r.ok() || r.word(0) != uint16(len(payload)) {
		t.Fatalf("write: %+v", r)
	}
	mtime := time.Date(1994, 3, 1, 12, 0, 0, 0, time.Local)
	if r = c.call(cmdClose, cat(w(fid), w(dw(utime(mtime))...)), nil); !r.ok() {
		t.Fatalf("close: %+v", r)
	}
	p := filepath.Join(e.dir, "data", "new.txt")
	if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, payload) {
		t.Fatalf("new.txt: %q, %v", b, err)
	}
	if fi, _ := os.Stat(p); !fi.ModTime().Equal(mtime) {
		t.Errorf("mtime %v, want %v", fi.ModTime(), mtime)
	}
	expectError(t, "create new", c.call(cmdCreateNew, w(0, 0, 0), ascii(`\NEW.TXT`)), errFileExists)
	// Directories.
	if r = c.call(cmdCreateDirectory, nil, ascii(`\SUBDIR`)); !r.ok() {
		t.Fatalf("mkdir: %+v", r)
	}
	if r = c.call(cmdRename, w(0), cat(ascii(`\NEW.TXT`), ascii(`\SUBDIR\MOVED.TXT`))); !r.ok() {
		t.Fatalf("rename: %+v", r)
	}
	expectError(t, "rmdir of a full directory", c.call(cmdDeleteDirectory, nil, ascii(`\SUBDIR`)), errNoAccess)
	if r = c.call(cmdDelete, w(0), ascii(`\SUBDIR\*.TXT`)); !r.ok() {
		t.Fatalf("delete: %+v", r)
	}
	if r = c.call(cmdDeleteDirectory, nil, ascii(`\SUBDIR`)); !r.ok() {
		t.Fatalf("rmdir: %+v", r)
	}
	// Wildcard rename, DOS style.
	if r = c.call(cmdRename, w(0), cat(ascii(`\*.TXT`), ascii(`\*.BAK`))); !r.ok() {
		t.Fatalf("rename *.TXT: %+v", r)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "data", "keep.bak")); err != nil {
		t.Errorf("wildcard rename: %v", err)
	}
	// Truncation with a zero-length write.
	r = c.call(cmdOpen, w(accessReadWrite, 0), ascii(`\KEEP.BAK`))
	fid = r.word(0)
	if r = c.call(cmdWrite, w(fid, 0, 2, 0, 0), cat([]byte{1}, w(0))); !r.ok() {
		t.Fatalf("truncate: %+v", r)
	}
	c.call(cmdClose, w(fid, 0, 0), nil)
	if b, _ := os.ReadFile(filepath.Join(e.dir, "data", "keep.bak")); string(b) != "ke" {
		t.Errorf("truncated to %q", b)
	}
}

// lanman sets up a LANMAN2.1 session with a chained session setup and tree
// connect.
func (c *client) lanman(share string) *response {
	c.t.Helper()
	if r := c.negotiate(dosDialects...); !r.ok() {
		c.t.Fatal("negotiate")
	}
	setup := w(cmdTreeConnectAndX, 0, 4356, 1, 0, 0, 0, 1, 0, 0)
	setupData := cat([]byte{0}, []byte("USER\x00WORKGROUP\x00DOS\x00LAN Manager\x00"))
	msg := c.message(cmdSessionSetupAndX, setup, setupData)
	off := len(msg)
	le.PutUint16(msg[hdrLen+1+2:], uint16(off))
	tc := w(cmdNone, 0, 0, 1)
	msg = append(msg, byte(len(tc)/2))
	msg = append(msg, tc...)
	path := []byte(`\\BOOTD\` + share + "\x00?????\x00")
	msg = le.AppendUint16(msg, uint16(1+len(path)))
	msg = append(msg, 0)
	msg = append(msg, path...)
	r := c.send(msg)
	if r.ok() {
		c.tid, c.uid = le.Uint16(r.msg[offTID:]), le.Uint16(r.msg[offUID:])
	}
	return r
}

func TestAndX(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	r := c.lanman("dos")
	if !r.ok() || c.tid == 0 || r.words[0] != cmdTreeConnectAndX {
		t.Fatalf("session setup and tree connect: %+v", r)
	}
	tcOff := int(le.Uint16(r.words[2:]))
	if tcOff >= len(r.msg) || r.msg[tcOff] != 3 {
		t.Fatalf("tree connect reply at %d", tcOff)
	}
	if !bytes.Contains(r.msg[tcOff:], []byte("A:\x00FAT\x00")) {
		t.Errorf("tree connect reply % x", r.msg[tcOff:])
	}
	// OPEN_ANDX chained with READ_ANDX.
	open := w(cmdReadAndX, 0, 0, accessRead, 0x16, 0, 0, 0, openExistOpen, 0, 0, 0, 0, 0, 0)
	msg := c.message(cmdOpenAndX, open, []byte(`\README.TXT`+"\x00"))
	le.PutUint16(msg[hdrLen+1+2:], uint16(len(msg)))
	read := w(cmdNone, 0, 0xffff, 0, 0, 100, 0, 0, 0, 0) // the FID of the open
	msg = append(msg, byte(len(read)/2))
	msg = append(msg, read...)
	msg = le.AppendUint16(msg, 0)
	r = c.send(msg)
	if !r.ok() || r.words[0] != cmdReadAndX || r.word(9+2) != 1 {
		t.Fatalf("open and read: %+v", r)
	}
	rdOff := int(le.Uint16(r.words[2:]))
	rd := r.msg[rdOff+1:]
	n, dataOff := int(le.Uint16(rd[10:])), int(le.Uint16(rd[12:]))
	if n != 5 || string(r.msg[dataOff:dataOff+n]) != "hello" {
		t.Errorf("read_andx returned %d bytes at %d", n, dataOff)
	}
	// A chained command that fails ends the chain with its error.
	msg = c.message(cmdOpenAndX, open, []byte(`\NOTHERE.TXT`+"\x00"))
	r = c.send(msg)
	expectError(t, "open of a missing file", r, errBadFile)
}

func (c *client) trans2(fn uint16, params, data []byte) *response {
	c.t.Helper()
	const wc = 15
	base := hdrLen + 1 + 2*wc + 2
	po := base + 3 // after the name and pad
	do := po + len(params)
	words := w(uint16(len(params)), uint16(len(data)), 10, 8000, 0, 0, 0, 0, 0,
		uint16(len(params)), uint16(po), uint16(len(data)), uint16(do), 1, fn)
	return c.call(cmdTransaction2, words, cat([]byte{0, 0, 0}, params, data))
}

// transParams returns the parameters and data of a transaction reply.
func transParams(r *response) ([]byte, []byte) {
	pc, po := int(le.Uint16(r.words[6:])), int(le.Uint16(r.words[8:]))
	dc, do := int(le.Uint16(r.words[12:])), int(le.Uint16(r.words[14:]))
	return r.msg[po : po+pc], r.msg[do : do+dc]
}

// standardNames returns the names in SMB_INFO_STANDARD entries.
func standardNames(data []byte, resumeKeys bool) []string {
	var names []string
	for len(data) > 0 {
		if resumeKeys {
			data = data[4:]
		}
		n := int(data[22])
		names = append(names, string(data[23:23+n]))
		data = data[23+n+1:]
	}
	return names
}

func TestTrans2(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	c.flags2 = flags2LongNames
	if r := c.lanman("dos"); !r.ok() {
		t.Fatal("connect")
	}
	params := cat(w(attrDirectory, 2, findResumeKeys, infoStandard, 0, 0), []byte(`\*`+"\x00"))
	r := c.trans2(t2FindFirst, params, nil)
	if !r.ok() {
		t.Fatalf("find first: %+v", r)
	}
	p, d := transParams(r)
	sid, n, eos := le.Uint16(p), le.Uint16(p[2:]), le.Uint16(p[4:])
	names := standardNames(d, true)
	if n != 2 || eos != 0 || len(names) != 2 {
		t.Fatalf("find first: %d entries %v, end %d", n, names, eos)
	}
	for eos == 0 {
		r = c.trans2(t2FindNext, cat(w(sid, 10, infoStandard, 0, 0, findContinue), []byte{0}), nil)
		if !r.ok() {
			t.Fatalf("find next: %+v", r)
		}
		p, d = transParams(r)
		eos = le.Uint16(p[2:])
		names = append(names, standardNames(d, false)...)
	}
	want := []string{"A Long File Name.text", "AUTOEXEC.BAT", "readme.txt", "sub"}
	if !slices.Equal(names, want) {
		t.Errorf("found %v, want %v", names, want)
	}
	r = c.trans2(t2QueryPathInfo, cat(w(infoStandard, 0, 0), []byte(`\SUB\INNER.TXT`+"\x00")), nil)
	if _, d := transParams(r); !r.ok() || len(d) != 22 || le.Uint32(d[12:]) != 10000 {
		t.Errorf("query path info: %+v", r)
	}
	r = c.trans2(t2QueryFSInfo, w(fsInfoVolume), nil)
	if _, d := transParams(r); !r.ok() || string(d[5:8]) != "DOS" {
		t.Errorf("volume info: %+v", r)
	}
	expectError(t, "find nothing", c.trans2(t2FindFirst, cat(w(0, 10, 0, infoStandard, 0, 0), []byte(`\X*.Y`+"\x00")), nil), errBadFile)
}

func (c *client) rap(params []byte, maxData uint16) *response {
	c.t.Helper()
	const wc = 14
	name := []byte(`\PIPE\LANMAN` + "\x00")
	base := hdrLen + 1 + 2*wc + 2
	po := base + len(name)
	words := w(uint16(len(params)), 0, 100, maxData, 0, 0, 0, 0, 0, uint16(len(params)), uint16(po), 0, 0, 0)
	return c.call(cmdTransaction, words, cat(name, params))
}

func TestRAP(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	if r := c.lanman("IPC$"); !r.ok() {
		t.Fatal("connect to IPC$")
	}
	r := c.rap(cat(w(rapNetShareEnum), []byte("WrLeh\x00B13BWz\x00"), w(1, 4096)), 4096)
	if !r.ok() {
		t.Fatalf("NetShareEnum: %+v", r)
	}
	p, d := transParams(r)
	if le.Uint16(p) != 0 || le.Uint16(p[4:]) != 3 {
		t.Fatalf("NetShareEnum params % x", p)
	}
	var shares []string
	for i := range 3 {
		name, _ := cstring(d[i*20 : i*20+13])
		shares = append(shares, name)
	}
	if !slices.Equal(shares, []string{"DOS", "DATA", "IPC$"}) {
		t.Errorf("shares %v", shares)
	}
	if ptr := le.Uint32(d[2*20+16:]); ptr >= uint32(len(d)) || !strings.HasPrefix(string(d[ptr:]), "Remote IPC\x00") {
		t.Errorf("IPC$ remark at %d in %q", ptr, d)
	}
	// Too small a buffer gets what fits, and says there is more.
	r = c.rap(cat(w(rapNetShareEnum), []byte("WrLeh\x00B13BWz\x00"), w(1, 30)), 30)
	if p, _ := transParams(r); le.Uint16(p) != rapMoreData || le.Uint16(p[4:]) != 1 {
		t.Errorf("short NetShareEnum params % x", p)
	}
	r = c.rap(cat(w(rapNetServerGetInfo), []byte("WrLh\x00B16BBDz\x00"), w(1, 4096)), 4096)
	if p, d := transParams(r); !r.ok() || le.Uint16(p) != 0 || !bytes.HasPrefix(d, []byte("BOOTD\x00")) {
		t.Errorf("NetServerGetInfo: % x / %q", p, d)
	}
	r = c.rap(cat(w(9999), []byte("\x00\x00")), 100)
	if p, _ := transParams(r); le.Uint16(p) != rapNotSupported {
		t.Errorf("unknown call: % x", p)
	}
}

func TestEcho(t *testing.T) {
	e := start(t)
	c := e.tcp(t, "02:00:00:00:00:05", "192.168.1.5")
	c.negotiate(dosDialects...)
	r := c.call(cmdEcho, w(2), []byte("ping"))
	if !r.ok() || r.word(0) != 1 || string(r.data) != "ping" {
		t.Errorf("echo: %+v", r)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if r = c.recv(ctx); r.word(0) != 2 {
		t.Errorf("second echo: %+v", r)
	}
}

// answer reads the next name service response, skipping the client's own
// broadcasts.
func answer(t *testing.T, ctx context.Context, l *ipstack.UDPListener) ipstack.Datagram {
	t.Helper()
	for {
		d, err := l.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(d.Data) > 2 && d.Data[2]&0x80 != 0 {
			return d
		}
	}
}

func TestNameService(t *testing.T) {
	e := start(t)
	st := e.Client(t, "02:00:00:00:00:05", "192.168.1.5/24")
	l, err := st.ListenUDP(netbios.NameServicePort)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bcast := netip.MustParseAddrPort("192.168.1.255:137")
	if err := l.WriteTo(netbios.EncodeQuery(7, netbios.MakeName("BOOTD", netbios.Server), false, true), bcast); err != nil {
		t.Fatal(err)
	}
	d := answer(t, ctx, l)
	if len(d.Data) < 6 || !bytes.HasSuffix(d.Data, []byte{192, 168, 1, 1}) || le.Uint16(d.Data) != 0x0700 {
		t.Errorf("answer % x", d.Data)
	}
	l.WriteTo(netbios.EncodeQuery(8, netbios.Wildcard, true, false), netip.MustParseAddrPort("192.168.1.1:137"))
	if d = answer(t, ctx, l); !bytes.Contains(d.Data, []byte("BOOTD           ")) || !bytes.Contains(d.Data, []byte("WORKGROUP")) {
		t.Errorf("status answer %q", d.Data)
	}
}

func TestNetBEUI(t *testing.T) {
	e := start(t)
	c := e.netbeui(t, "02:00:00:00:00:05")
	if r := c.connect("DOS"); !r.ok() {
		t.Fatalf("connect: %+v", r)
	}
	r := c.call(cmdOpen, w(0, 0), ascii(`\SUB\INNER.TXT`))
	if !r.ok() {
		t.Fatalf("open: %+v", r)
	}
	// A read larger than a frame.
	r = c.call(cmdRead, w(r.word(0), 4000, 0, 0, 0), nil)
	if !r.ok() || r.word(0) != 4000 || string(r.data[3:]) != strings.Repeat("x", 4000) {
		t.Errorf("read: %d bytes", r.word(0))
	}
	if !e.log.Contains("smb session from pc (PC over netbeui)") {
		t.Error("session not logged")
	}
}

func TestNetBEUIDenied(t *testing.T) {
	e := start(t)
	p := e.Segment.Station("02:00:00:00:00:06")
	st := &llc.Station{SAP: netbios.SAP, Port: p, Log: slog.New(slog.DiscardHandler)}
	nbf := &netbios.NBF{Station: st}
	nbf.Init()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		for {
			f, err := p.ReadFrame(ctx)
			if err != nil {
				return
			}
			st.Handle(f)
		}
	}()
	if _, err := nbf.Dial(ctx, netbios.MakeName("BOOTD", netbios.Server), netbios.MakeName("OTHER", 0)); err == nil {
		t.Error("session for a host without smb")
	}
	if !e.log.Contains("denied (smb not allowed for this host)") {
		t.Error("refusal not logged")
	}
}
