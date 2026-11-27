package smb

import (
	"strings"
)

// The LAN Manager remote administration protocol (RAP) over
// \PIPE\LANMAN, as far as clients use it to browse: the list of shares,
// and what the server and its workgroup are.

// RAP functions.
const (
	rapNetShareEnum     = 0
	rapNetShareGetInfo  = 1
	rapNetServerGetInfo = 13
	rapNetWkstaGetInfo  = 63
	rapNetServerEnum2   = 104
)

// RAP status codes.
const (
	rapOK           = 0
	rapNotSupported = 50
	rapBadLevel     = 124
	rapMoreData     = 234
	rapShareMissing = 2310
)

// Server types.
const (
	svWorkstation = 0x00000001
	svServer      = 0x00000002
	svDomainEnum  = 0x80000000
)

const serverComment = "gobootd"

// rapIn reads the arguments of a call after its descriptors.
type rapIn struct{ b []byte }

func (r *rapIn) word() uint16 {
	if len(r.b) < 2 {
		r.b = nil
		return 0
	}
	v := le.Uint16(r.b)
	r.b = r.b[2:]
	return v
}

func (r *rapIn) dword() uint32 {
	lo := r.word()
	return uint32(lo) | uint32(r.word())<<16
}

func (r *rapIn) str() string {
	s, rest := cstring(r.b)
	r.b = rest
	return s
}

// rapOut builds the data of a reply: fixed entries first, then the strings
// they point to.
type rapOut struct {
	fixed   []byte
	strs    []byte
	entries int
	// entrySize is the fixed size of an entry.
	entrySize int
	// pending are the string pointers to patch once the fixed part's
	// size is known: their offset in fixed and the string's in strs.
	pending [][2]int
}

func (o *rapOut) name(s string, n int) {
	b := make([]byte, n)
	copy(b, strings.ToUpper(s)[:min(len(s), n-1)])
	o.fixed = append(o.fixed, b...)
}

func (o *rapOut) b8(v byte)    { o.fixed = append(o.fixed, v) }
func (o *rapOut) w16(v uint16) { o.fixed = le.AppendUint16(o.fixed, v) }
func (o *rapOut) w32(v uint32) { o.fixed = le.AppendUint32(o.fixed, v) }

// ptr adds a pointer to a string.
func (o *rapOut) ptr(s string) {
	o.pending = append(o.pending, [2]int{len(o.fixed), len(o.strs)})
	o.fixed = append(o.fixed, 0, 0, 0, 0)
	o.strs = append(append(o.strs, s...), 0)
}

// bytes returns the data, cut to the entries that fit in max bytes, and
// how many those are.
func (o *rapOut) bytes(max int) ([]byte, int) {
	n := o.entries
	for n > 0 && n*o.entrySize+o.stringsFor(n) > max {
		n--
	}
	fixed := append([]byte(nil), o.fixed[:n*o.entrySize]...)
	var strs []byte
	for _, p := range o.pending {
		if p[0] >= len(fixed) {
			break
		}
		s, _ := cstring(o.strs[p[1]:])
		le.PutUint32(fixed[p[0]:], uint32(len(fixed)+len(strs)))
		strs = append(append(strs, s...), 0)
	}
	return append(fixed, strs...), n
}

// stringsFor is the size of the strings of the first n entries.
func (o *rapOut) stringsFor(n int) int {
	size := 0
	for _, p := range o.pending {
		if p[0] >= n*o.entrySize {
			break
		}
		s, _ := cstring(o.strs[p[1]:])
		size += len(s) + 1
	}
	return size
}

// rap answers a remote API call. Errors go back in the status word.
func (c *conn) rap(in *transIn) *transResult {
	a := &rapIn{b: in.params}
	fn := a.word()
	a.str() // parameter descriptor
	a.str() // data descriptor
	status := func(st uint16) *transResult {
		return &transResult{params: le.AppendUint16(le.AppendUint16(nil, st), 0)}
	}
	// enum ends a list reply: status, converter, count, available.
	enum := func(o *rapOut, bufSize int) *transResult {
		data, n := o.bytes(min(bufSize, max(in.maxD, 0)))
		st := uint16(rapOK)
		if n < o.entries {
			st = rapMoreData
		}
		p := le.AppendUint16(nil, st)
		p = le.AppendUint16(p, 0)
		p = le.AppendUint16(p, uint16(n))
		p = le.AppendUint16(p, uint16(o.entries))
		return &transResult{params: p, data: data}
	}
	// info ends a get-info reply: status, converter, size.
	info := func(o *rapOut, bufSize int) *transResult {
		data, n := o.bytes(min(bufSize, max(in.maxD, 0)))
		st := uint16(rapOK)
		if n == 0 {
			st = rapMoreData
		}
		p := le.AppendUint16(nil, st)
		p = le.AppendUint16(p, 0)
		p = le.AppendUint16(p, uint16(o.entrySize+o.stringsFor(1)))
		return &transResult{params: p, data: data}
	}
	c.log.Debug("rap call", "function", fn)
	switch fn {
	case rapNetShareEnum:
		level, bufSize := a.word(), int(a.word())
		o, ok := c.shares(level)
		if !ok {
			return status(rapBadLevel)
		}
		for _, sh := range c.host.Shares {
			o.share(level, sh.Name, 0)
		}
		o.share(level, ipcShare, 3)
		return enum(o, bufSize)
	case rapNetShareGetInfo:
		name := a.str()
		level, bufSize := a.word(), int(a.word())
		o, ok := c.shares(level)
		if !ok {
			return status(rapBadLevel)
		}
		switch {
		case strings.EqualFold(name, ipcShare):
			o.share(level, ipcShare, 3)
		default:
			sh, err := c.host.Share(name)
			if err != nil {
				return status(rapShareMissing)
			}
			o.share(level, sh.Name, 0)
		}
		return info(o, bufSize)
	case rapNetServerGetInfo:
		level, bufSize := a.word(), int(a.word())
		o := &rapOut{}
		if !c.server(o, level, c.s.opts.NetBIOSName, svWorkstation|svServer, serverComment) {
			return status(rapBadLevel)
		}
		return info(o, bufSize)
	case rapNetServerEnum2:
		level, bufSize := a.word(), int(a.word())
		types := a.dword()
		o := &rapOut{}
		if types == svDomainEnum {
			if !c.server(o, level, c.s.opts.Workgroup, svDomainEnum, c.s.opts.NetBIOSName) {
				return status(rapBadLevel)
			}
		} else if types&(svWorkstation|svServer) != 0 {
			if !c.server(o, level, c.s.opts.NetBIOSName, svWorkstation|svServer, serverComment) {
				return status(rapBadLevel)
			}
		}
		return enum(o, bufSize)
	case rapNetWkstaGetInfo:
		level, bufSize := a.word(), int(a.word())
		if level != 10 {
			return status(rapBadLevel)
		}
		o := &rapOut{entries: 1, entrySize: 22}
		o.ptr(c.s.opts.NetBIOSName)
		o.ptr(c.user)
		o.ptr(c.s.opts.Workgroup)
		o.b8(2)
		o.b8(1)
		o.ptr(c.s.opts.Workgroup)
		o.ptr("")
		return info(o, bufSize)
	}
	return status(rapNotSupported)
}

// shares starts a list of shares at a level: 0 is names, 1 adds the
// type and a remark.
func (c *conn) shares(level uint16) (*rapOut, bool) {
	switch level {
	case 0:
		return &rapOut{entrySize: 13}, true
	case 1:
		return &rapOut{entrySize: 20}, true
	}
	return nil, false
}

func (o *rapOut) share(level uint16, name string, typ uint16) {
	o.entries++
	o.name(name, 13)
	if level == 1 {
		o.b8(0)
		o.w16(typ)
		remark := ""
		if typ == 3 {
			remark = "Remote IPC"
		}
		o.ptr(remark)
	}
}

// server adds a server entry: 0 is the name, 1 adds the version, type and
// comment.
func (c *conn) server(o *rapOut, level uint16, name string, typ uint32, comment string) bool {
	switch level {
	case 0:
		o.entrySize = 16
	case 1:
		o.entrySize = 26
	default:
		return false
	}
	o.entries++
	o.name(name, 16)
	if level == 1 {
		o.b8(2) // LAN Manager 2.1
		o.b8(1)
		o.w32(typ)
		o.ptr(comment)
	}
	return true
}
