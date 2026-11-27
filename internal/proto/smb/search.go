package smb

import (
	"io/fs"
	"path"
	"slices"
	"strings"
	"time"
)

// entry is a directory entry as clients see it.
type entry struct {
	name string // on disk
	dos  string // the 8.3 name
	fi   fs.FileInfo
}

func (e entry) dir() bool { return e.fi.IsDir() }

func (e entry) attrs() uint16 { return attributes(e.name, e.fi) }

// matches reports whether a search for pattern with the given attributes
// finds e. Directories and hidden files are found only when asked for.
// Clients that know long names match them; others match 8.3 names.
func (e entry) matches(pattern string, attrs uint16, longNames bool) bool {
	a := e.attrs()
	if a&attrDirectory != 0 && attrs&attrDirectory == 0 || a&attrHidden != 0 && attrs&attrHidden == 0 {
		return false
	}
	if longNames {
		return matchGlob(pattern, e.name) || matchGlob(pattern, e.dos)
	}
	return matchFCB(pattern, e.dos)
}

// list returns the entries of a directory sorted by name, with . and ..
// in directories below the root.
func (t *tree) list(dir string) ([]entry, error) {
	f, err := t.root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	des, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	var out []entry
	if dir != "." {
		for _, n := range []string{".", ".."} {
			if fi, err := t.root.Stat(path.Join(dir, n)); err == nil {
				out = append(out, entry{name: n, dos: n, fi: fi})
			}
		}
	}
	var es []entry
	for _, de := range des {
		fi, err := t.root.Stat(path.Join(dir, de.Name()))
		if err != nil || !fi.Mode().IsRegular() && !fi.IsDir() {
			continue
		}
		es = append(es, entry{name: de.Name(), dos: dosName(de.Name()), fi: fi})
	}
	slices.SortFunc(es, func(a, b entry) int { return strings.Compare(a.name, b.name) })
	return append(out, es...), nil
}

// search is a directory search in progress.
type search struct {
	tid       uint16
	pattern   string
	attrs     uint16
	longNames bool
	entries   []entry
	pos       int // the next entry to look at
	used      time.Time
}

// found is a matching entry and the position just past it, where a
// search resumed from it goes on.
type found struct {
	entry
	resume int
}

// next returns up to n more matching entries.
func (s *search) next(n int) []found {
	var out []found
	for s.pos < len(s.entries) && len(out) < n {
		e := s.entries[s.pos]
		s.pos++
		if e.matches(s.pattern, s.attrs, s.longNames) {
			out = append(out, found{e, s.pos})
		}
	}
	s.used = time.Now()
	return out
}

func (s *search) done() bool {
	for _, e := range s.entries[s.pos:] {
		if e.matches(s.pattern, s.attrs, s.longNames) {
			return false
		}
	}
	return true
}

// startSearch lists the directory of a path with a pattern.
func (c *conn) startSearch(t *tree, p string, attrs uint16, longNames bool) (*search, error) {
	dirPart, pattern := splitPattern(p)
	if pattern == "" {
		pattern = "*"
	}
	dir, ok, err := t.resolve(dirPart, false, longNames)
	if err == nil && !ok {
		err = errBadPath
	}
	if err != nil {
		return nil, errBadPath
	}
	if fi, err := t.root.Stat(dir); err != nil || !fi.IsDir() {
		return nil, errBadPath
	}
	var entries []entry
	if !wild(pattern) {
		// One name: look it up, which also finds it by its 8.3 name.
		if name, ok := t.lookup(dir, pattern); ok {
			if fi, err := t.root.Stat(path.Join(dir, name)); err == nil {
				entries = []entry{{name: name, dos: dosName(name), fi: fi}}
				pattern = "*"
			}
		}
	} else if entries, err = t.list(dir); err != nil {
		return nil, err
	}
	return &search{tid: t.tid, pattern: pattern, attrs: attrs, longNames: longNames, entries: entries, used: time.Now()}, nil
}

// keep stores a search under id, dropping the least recently used one when
// there are too many.
func (c *conn) keep(id uint16, s *search) {
	if len(c.searches) >= maxSearches {
		var oldest uint16
		var t time.Time
		for k, v := range c.searches {
			if t.IsZero() || v.used.Before(t) {
				oldest, t = k, v.used
			}
		}
		delete(c.searches, oldest)
	}
	c.searches[id] = s
}

// Core searches are kept under coreSearch|id, where id is the byte the
// resume key carries.
const coreSearch = 0x8000

const (
	resumeKeyLen = 21
	dirEntryLen  = 43
)

// search is SEARCH, FIND and FIND_UNIQUE: the core protocol's directory
// search, with 8.3 names and a resume key per entry.
func (c *conn) search(r *request, rp *reply) error {
	t, err := c.tree(r)
	if err != nil {
		return err
	}
	maxCount, attrs := int(r.word(0)), r.word(1)
	p, rest, ok := bufferString(r.data)
	if !ok || len(rest) < 3 || rest[0] != 0x05 {
		return errBadData
	}
	keyLen := int(le.Uint16(rest[1:]))
	key := rest[3:]
	var s *search
	var id byte
	var client [4]byte
	switch {
	case keyLen == 0 && attrs == attrVolume:
		// The volume label, which DIR shows.
		label := t.name
		if len(label) > 11 {
			label = label[:11]
		}
		e := make([]byte, dirEntryLen)
		f := fcb(label)
		copy(e[1:12], f[:])
		e[21] = attrVolume
		copy(e[30:42], label)
		rp.w16(1)
		rp.b8(0x05)
		rp.b16(dirEntryLen)
		rp.data = append(rp.data, e...)
		return nil
	case keyLen == 0:
		if s, err = c.startSearch(t, p, attrs, false); err != nil {
			return err
		}
		c.nextCore++
		id = c.nextCore
		c.keep(coreSearch|uint16(id), s)
	case keyLen >= resumeKeyLen && len(key) >= resumeKeyLen:
		id = key[12]
		s = c.searches[coreSearch|uint16(id)]
		if s == nil || s.tid != t.tid {
			return errNoFiles
		}
		s.pos = int(le.Uint32(key[13:]))
		copy(client[:], key[17:21])
	default:
		return errBadData
	}
	maxCount = min(maxCount, (c.maxBuf-hdrLen-8)/dirEntryLen)
	if r.cmd == cmdFindUnique {
		defer delete(c.searches, coreSearch|uint16(id))
	}
	es := s.next(max(maxCount, 1))
	if len(es) == 0 {
		delete(c.searches, coreSearch|uint16(id))
		return errNoFiles
	}
	rp.w16(uint16(len(es)))
	rp.b8(0x05)
	rp.b16(uint16(len(es) * dirEntryLen))
	// Each resume key leads past its entry, so a client that resumes
	// from any of them gets the rest.
	for _, e := range es {
		b := make([]byte, dirEntryLen)
		f := fcb(e.dos)
		copy(b[1:12], f[:])
		b[12] = id
		le.PutUint32(b[13:], uint32(e.resume))
		copy(b[17:21], client[:])
		b[21] = byte(e.attrs())
		d, tm := dosDateTime(e.fi.ModTime())
		le.PutUint16(b[22:], tm)
		le.PutUint16(b[24:], d)
		if !e.dir() {
			le.PutUint32(b[26:], uint32(min(e.fi.Size(), 1<<32-1)))
		}
		copy(b[30:42], e.dos)
		rp.data = append(rp.data, b...)
	}
	return nil
}

func (c *conn) findClose(r *request, rp *reply) error {
	_, rest, ok := bufferString(r.data)
	if ok && len(rest) >= 3+resumeKeyLen && rest[0] == 0x05 {
		delete(c.searches, coreSearch|uint16(rest[3+12]))
	}
	rp.w16(0)
	rp.b8(0x05)
	rp.b16(0)
	return nil
}

func (c *conn) findClose2(r *request, rp *reply) error {
	sid := r.word(0)
	if c.searches[sid] == nil || sid&coreSearch != 0 {
		return errBadFid
	}
	delete(c.searches, sid)
	return nil
}
