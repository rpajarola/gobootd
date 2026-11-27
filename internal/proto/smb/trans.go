package smb

import (
	"io/fs"
	"path"
	"strings"
	"time"
)

// transResult is the answer to a transaction.
type transResult struct {
	cmd          byte
	setup        []uint16
	params, data []byte
}

// partialTrans is a transaction whose parameters or data come in
// secondary requests.
type partialTrans struct {
	cmd            byte
	mid            uint16
	name           string
	setup          []uint16
	params, data   []byte
	gotP, gotD     int
	maxP, maxD     int
	tid, pid, flag uint16
	longNames      bool
}

func (p *partialTrans) complete() bool { return p.gotP >= len(p.params) && p.gotD >= len(p.data) }

// transIn is a transaction request, complete.
type transIn struct {
	cmd          byte
	name         string
	setup        []uint16
	params, data []byte
	maxP, maxD   int
	tid, pid     uint16
	longNames    bool
}

// piece copies count bytes at off in msg to buf at disp.
func piece(msg, buf []byte, off, count, disp int) bool {
	if count == 0 {
		return true
	}
	if off < hdrLen || off+count > len(msg) || disp+count > len(buf) {
		return false
	}
	copy(buf[disp:], msg[off:off+count])
	return true
}

// transaction is TRANSACTION and TRANSACTION2.
func (c *conn) transaction(r *request, rp *reply) error {
	if len(r.words) < 28 {
		return errBadData
	}
	totalP, totalD := int(r.word(0)), int(r.word(1))
	pc, po, dc, do := int(r.word(9)), int(r.word(10)), int(r.word(11)), int(r.word(12))
	sc := int(r.word(13) & 0xff)
	if len(r.words) < 28+2*sc {
		return errBadData
	}
	p := &partialTrans{
		cmd: r.cmd, mid: r.mid, maxP: int(r.word(2)), maxD: int(r.word(3)),
		params: make([]byte, totalP), data: make([]byte, totalD),
		tid: r.tid, pid: r.pid, flag: r.word(5), longNames: r.longNames(),
	}
	for i := range sc {
		p.setup = append(p.setup, r.word(14+i))
	}
	if r.cmd == cmdTransaction {
		p.name, _ = cstring(r.data)
	}
	if !piece(r.msg, p.params, po, pc, 0) || !piece(r.msg, p.data, do, dc, 0) {
		return errBadData
	}
	p.gotP, p.gotD = pc, dc
	if !p.complete() {
		// An interim response asks for the rest.
		c.trans = p
		return nil
	}
	return c.runTrans(p, rp)
}

func (c *conn) transactionSecondary(r *request, rp *reply) error {
	p := c.trans
	if p == nil || p.mid != r.mid || (r.cmd == cmdTransactionSec) != (p.cmd == cmdTransaction) {
		return errSrvError
	}
	pc, po, pd := int(r.word(2)), int(r.word(3)), int(r.word(4))
	dc, do, dd := int(r.word(5)), int(r.word(6)), int(r.word(7))
	if !piece(r.msg, p.params, po, pc, pd) || !piece(r.msg, p.data, do, dc, dd) {
		c.trans = nil
		return errBadData
	}
	p.gotP += pc
	p.gotD += dc
	if !p.complete() {
		// Secondary requests have no response of their own.
		rp.noReply = true
		return nil
	}
	c.trans = nil
	return c.runTrans(p, rp)
}

func (c *conn) runTrans(p *partialTrans, rp *reply) error {
	in := &transIn{cmd: p.cmd, name: p.name, setup: p.setup, params: p.params, data: p.data,
		maxP: p.maxP, maxD: p.maxD, tid: p.tid, pid: p.pid, longNames: p.longNames}
	var res *transResult
	var err error
	if p.cmd == cmdTransaction {
		if p.flag&0x02 != 0 {
			// A one-way transaction, like a mailslot write.
			rp.noReply = true
			return nil
		}
		res, err = c.trans1(in)
	} else {
		res, err = c.trans2(in)
	}
	if err != nil {
		return err
	}
	res.cmd = p.cmd
	rp.trans = res
	return nil
}

// transReplies builds the responses of a transaction, as many as the
// client's buffer needs. hdr is the response header.
func (c *conn) transReplies(hdr []byte, res *transResult) [][]byte {
	wc := 10 + len(res.setup)
	base := hdrLen + 1 + 2*wc + 2
	room := max(c.maxBuf-base-8, 256)
	var out [][]byte
	pOff, dOff := 0, 0
	for first := true; first || pOff < len(res.params) || dOff < len(res.data); first = false {
		pn := min(len(res.params)-pOff, room)
		dn := min(len(res.data)-dOff, room-pn)
		padP := (4 - base%4) % 4
		paramOff := base + padP
		padD := (4 - (paramOff+pn)%4) % 4
		dataOff := paramOff + pn + padD
		if dn == 0 {
			padD, dataOff = 0, paramOff+pn
		}
		b := make([]byte, hdrLen, dataOff+dn)
		copy(b, hdr[:hdrLen])
		b[offCommand] = res.cmd
		b = append(b, byte(wc))
		for _, v := range []int{len(res.params), len(res.data), 0, pn, paramOff, pOff, dn, dataOff, dOff} {
			b = le.AppendUint16(b, uint16(v))
		}
		b = le.AppendUint16(b, uint16(len(res.setup)))
		for _, s := range res.setup {
			b = le.AppendUint16(b, s)
		}
		b = le.AppendUint16(b, uint16(dataOff+dn-base))
		b = append(b, make([]byte, padP)...)
		b = append(b, res.params[pOff:pOff+pn]...)
		b = append(b, make([]byte, padD)...)
		b = append(b, res.data[dOff:dOff+dn]...)
		out = append(out, b)
		pOff += pn
		dOff += dn
	}
	return out
}

// trans1 is TRANSACTION: the LAN Manager remote API on \PIPE\LANMAN.
func (c *conn) trans1(in *transIn) (*transResult, error) {
	if !strings.EqualFold(in.name, `\PIPE\LANMAN`) {
		c.log.Debug("unsupported transaction", "name", in.name)
		return nil, errNotSup
	}
	return c.rap(in), nil
}

// TRANSACTION2 subcommands.
const (
	t2FindFirst       = 0x01
	t2FindNext        = 0x02
	t2QueryFSInfo     = 0x03
	t2QueryPathInfo   = 0x05
	t2SetPathInfo     = 0x06
	t2QueryFileInfo   = 0x07
	t2SetFileInfo     = 0x08
	t2CreateDirectory = 0x0d
)

// Information levels.
const (
	infoStandard   = 1
	infoEASize     = 2
	infoEAsInList  = 3
	infoAllEAs     = 4
	infoNameValid  = 6
	fsInfoAlloc    = 1
	fsInfoVolume   = 2
	findCloseAfter = 0x01
	findCloseAtEOS = 0x02
	findResumeKeys = 0x04
	findContinue   = 0x08
)

func (c *conn) trans2(in *transIn) (*transResult, error) {
	if len(in.setup) < 1 {
		return nil, errBadData
	}
	r := &request{tid: in.tid, pid: in.pid}
	if in.longNames {
		r.flags2 = flags2LongNames
	}
	t, err := c.tree(r)
	if err != nil {
		return nil, err
	}
	p := in.params
	need := func(n int) error {
		if len(p) < n {
			return errBadData
		}
		return nil
	}
	switch in.setup[0] {
	case t2FindFirst:
		if err := need(12); err != nil {
			return nil, err
		}
		name, _ := cstring(p[12:])
		return c.findFirst2(t, in, le.Uint16(p), int(le.Uint16(p[2:])), le.Uint16(p[4:]), le.Uint16(p[6:]), name)
	case t2FindNext:
		if err := need(12); err != nil {
			return nil, err
		}
		name, _ := cstring(p[12:])
		return c.findNext2(in, le.Uint16(p), int(le.Uint16(p[2:])), le.Uint16(p[4:]), le.Uint32(p[6:]), le.Uint16(p[10:]), name)
	case t2QueryFSInfo:
		if err := need(2); err != nil {
			return nil, err
		}
		return c.queryFS(t, le.Uint16(p))
	case t2QueryPathInfo:
		if err := need(6); err != nil {
			return nil, err
		}
		name, _ := cstring(p[6:])
		level := le.Uint16(p)
		if level == infoNameValid {
			if _, err := splitPath(name); err != nil {
				return nil, errBadPath
			}
			return &transResult{params: []byte{0, 0}}, nil
		}
		rel, fi, err := t.stat(name, in.longNames)
		if err != nil {
			return nil, err
		}
		return fileInfo(path.Base(rel), fi, level)
	case t2QueryFileInfo:
		if err := need(4); err != nil {
			return nil, err
		}
		f, err := c.file(r, le.Uint16(p))
		if err != nil {
			return nil, err
		}
		fi, err := f.f.Stat()
		if err != nil {
			return nil, err
		}
		return fileInfo(path.Base(f.rel), fi, le.Uint16(p[2:]))
	case t2SetPathInfo:
		if err := need(6); err != nil {
			return nil, err
		}
		if !t.writable {
			return nil, errNoAccess
		}
		name, _ := cstring(p[6:])
		rel, _, err := t.resolve(name, false, in.longNames)
		if err != nil {
			return nil, err
		}
		return setInfo(t, rel, le.Uint16(p), in.data)
	case t2SetFileInfo:
		if err := need(4); err != nil {
			return nil, err
		}
		f, err := c.file(r, le.Uint16(p))
		if err != nil {
			return nil, err
		}
		if !t.writable {
			return nil, errNoAccess
		}
		return setInfo(t, f.rel, le.Uint16(p[2:]), in.data)
	case t2CreateDirectory:
		if err := need(4); err != nil {
			return nil, err
		}
		if !t.writable {
			return nil, errNoAccess
		}
		name, _ := cstring(p[4:])
		rel, exists, err := t.resolve(name, true, in.longNames)
		if err != nil {
			return nil, err
		}
		if exists {
			return nil, errNoAccess
		}
		if err := t.root.Mkdir(rel, 0o777); err != nil {
			return nil, err
		}
		return &transResult{params: []byte{0, 0}}, nil
	}
	c.log.Debug("unsupported transaction2", "function", in.setup[0])
	return nil, errNotSup
}

// standardInfo appends the SMB_INFO_STANDARD fields of a file: three
// dates and times, the size, the allocation and the attributes.
func standardInfo(b []byte, name string, fi fs.FileInfo) []byte {
	d, t := dosDateTime(fi.ModTime())
	for range 3 {
		b = le.AppendUint16(b, d)
		b = le.AppendUint16(b, t)
	}
	size := int64(0)
	if !fi.IsDir() {
		size = fi.Size()
	}
	b = le.AppendUint32(b, uint32(min(size, 1<<32-1)))
	b = le.AppendUint32(b, uint32(min((size+4095)&^4095, 1<<32-1)))
	return le.AppendUint16(b, attributes(name, fi))
}

func fileInfo(name string, fi fs.FileInfo, level uint16) (*transResult, error) {
	res := &transResult{params: []byte{0, 0}}
	switch level {
	case infoStandard:
		res.data = standardInfo(nil, name, fi)
	case infoEASize:
		res.data = le.AppendUint32(standardInfo(nil, name, fi), 0)
	case infoEAsInList, infoAllEAs:
		res.data = le.AppendUint32(nil, 4) // an empty list
	default:
		return nil, errBadLevel
	}
	return res, nil
}

func setInfo(t *tree, rel string, level uint16, data []byte) (*transResult, error) {
	res := &transResult{params: []byte{0, 0}}
	switch level {
	case infoStandard:
		if len(data) < 22 {
			return nil, errBadData
		}
		mtime := fromDOS(le.Uint16(data[8:]), le.Uint16(data[10:]))
		if err := t.setAttributes(rel, le.Uint16(data[20:]), mtime); err != nil {
			return nil, err
		}
	case infoEASize:
		// Extended attributes are not kept.
	default:
		return nil, errBadLevel
	}
	return res, nil
}

func (c *conn) queryFS(t *tree, level uint16) (*transResult, error) {
	res := &transResult{}
	switch level {
	case fsInfoAlloc:
		total, free := t.diskSpace()
		const sector, perUnit = 512, 8
		b := le.AppendUint32(nil, 0)
		b = le.AppendUint32(b, perUnit)
		b = le.AppendUint32(b, uint32(total/(sector*perUnit)))
		b = le.AppendUint32(b, uint32(free/(sector*perUnit)))
		res.data = le.AppendUint16(b, sector)
	case fsInfoVolume:
		label := t.name
		b := le.AppendUint32(nil, c.key)
		b = append(b, byte(len(label)))
		res.data = append(append(b, label...), 0)
	default:
		return nil, errBadLevel
	}
	return res, nil
}

// findEntries encodes search results in an information level, as many as
// fit in max bytes, and returns how many and where the last name is.
func findEntries(es []found, level, flags uint16, longNames bool, max int) ([]byte, int, int) {
	var b []byte
	n, last := 0, 0
	for _, e := range es {
		name := e.dos
		if longNames {
			name = e.name
		}
		var x []byte
		if flags&findResumeKeys != 0 {
			x = le.AppendUint32(x, uint32(e.resume))
		}
		x = standardInfo(x, e.name, e.fi)
		if level == infoEASize {
			x = le.AppendUint32(x, 0)
		}
		nameOff := len(b) + len(x) + 1
		x = append(x, byte(len(name)))
		x = append(append(x, name...), 0)
		if len(b)+len(x) > max {
			break
		}
		b = append(b, x...)
		n++
		last = nameOff
	}
	return b, n, last
}

func (c *conn) findFirst2(t *tree, in *transIn, attrs uint16, count int, flags, level uint16, name string) (*transResult, error) {
	if level != infoStandard && level != infoEASize {
		return nil, errBadLevel
	}
	s, err := c.startSearch(t, name, attrs, in.longNames)
	if err != nil {
		return nil, err
	}
	data, n, last, eos := c.findMore(s, in, count, flags, level)
	if n == 0 {
		return nil, errBadFile
	}
	var sid uint16
	for {
		c.nextSID = (c.nextSID + 1) &^ coreSearch
		if c.nextSID != 0 && c.searches[c.nextSID] == nil {
			break
		}
	}
	sid = c.nextSID
	if flags&findCloseAfter == 0 && !(eos && flags&findCloseAtEOS != 0) {
		c.keep(sid, s)
	}
	p := le.AppendUint16(nil, sid)
	p = le.AppendUint16(p, uint16(n))
	p = le.AppendUint16(p, boolWord(eos))
	p = le.AppendUint16(p, 0)
	p = le.AppendUint16(p, uint16(last))
	return &transResult{params: p, data: data}, nil
}

func (c *conn) findNext2(in *transIn, sid uint16, count int, level uint16, key uint32, flags uint16, name string) (*transResult, error) {
	s := c.searches[sid]
	if s == nil || sid&coreSearch != 0 || s.tid != in.tid {
		return nil, errBadFid
	}
	if level != infoStandard && level != infoEASize {
		return nil, errBadLevel
	}
	switch {
	case flags&findContinue != 0:
	case key != 0 && int(key) <= len(s.entries):
		s.pos = int(key)
	case name != "":
		for i, e := range s.entries {
			if e.name == name || e.dos == strings.ToUpper(name) {
				s.pos = i + 1
				break
			}
		}
	}
	data, n, last, eos := c.findMore(s, in, count, flags, level)
	if flags&findCloseAfter != 0 || eos && flags&findCloseAtEOS != 0 {
		delete(c.searches, sid)
	}
	p := le.AppendUint16(nil, uint16(n))
	p = le.AppendUint16(p, boolWord(eos))
	p = le.AppendUint16(p, 0)
	p = le.AppendUint16(p, uint16(last))
	return &transResult{params: p, data: data}, nil
}

// findMore returns the next entries of a search that fit the client's
// limits, and whether the search is at its end.
func (c *conn) findMore(s *search, in *transIn, count int, flags, level uint16) ([]byte, int, int, bool) {
	limit := in.maxD
	if limit <= 0 {
		limit = c.maxBuf
	}
	start := s.pos
	es := s.next(max(count, 1))
	data, n, last := findEntries(es, level, flags, in.longNames, limit)
	if n < len(es) {
		// Entries that did not fit come next time.
		s.pos = es[n].resume - 1
		if n == 0 {
			s.pos = start
		}
	}
	s.used = time.Now()
	return data, n, last, s.done()
}

func boolWord(b bool) uint16 {
	if b {
		return 1
	}
	return 0
}
