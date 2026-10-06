package nfs

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
)

// specEntry is what an mtree specification says about one file.
type specEntry struct {
	typ      string // file, dir, link, char, block, fifo, socket
	mode     uint32 // permission bits including setuid, setgid and sticky
	hasMode  bool
	uid, gid uint32
	hasUID   bool
	hasGID   bool
	major    uint32
	minor    uint32
	link     string
}

// spec maps paths relative to an export ("." for its top) to entries.
type spec map[string]*specEntry

// parseSpec reads an mtree(5) specification, in the full path form bsdtar
// writes ("tar -cf x.mtree --format=mtree @root.tgz") or the hierarchical
// form of "mtree -c".
func parseSpec(r io.Reader) (spec, error) {
	s := spec{}
	set := map[string]string{}
	cwd := "."
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		// Continuation lines end in a backslash.
		for strings.HasSuffix(text, "\\") && sc.Scan() {
			line++
			text = strings.TrimSuffix(text, "\\") + " " + sc.Text()
		}
		fields := strings.Fields(text)
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "/set":
			for _, kv := range fields[1:] {
				if k, v, ok := strings.Cut(kv, "="); ok {
					set[k] = v
				}
			}
			continue
		case "/unset":
			for _, k := range fields[1:] {
				if k == "all" {
					set = map[string]string{}
				}
				delete(set, k)
			}
			continue
		case "..":
			if cwd != "." {
				cwd = path.Dir(cwd)
			}
			continue
		}
		name, err := unvis(fields[0])
		if err != nil {
			return nil, fmt.Errorf("line %d: %v", line, err)
		}
		kw := map[string]string{}
		for k, v := range set {
			kw[k] = v
		}
		for _, f := range fields[1:] {
			if k, v, ok := strings.Cut(f, "="); ok {
				kw[k] = v
			}
		}
		var p string
		if strings.Contains(name, "/") {
			p = path.Clean(name)
		} else {
			p = path.Join(cwd, name)
		}
		e, err := parseEntry(kw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %s: %v", line, name, err)
		}
		s[p] = e
		// In the hierarchical form a directory entry is entered.
		if !strings.Contains(name, "/") && e.typ == "dir" && name != "." {
			cwd = p
		}
	}
	return s, sc.Err()
}

func parseEntry(kw map[string]string) (*specEntry, error) {
	e := &specEntry{typ: kw["type"]}
	if e.typ == "" {
		e.typ = "file"
	}
	if v, ok := kw["mode"]; ok {
		m, err := strconv.ParseUint(v, 8, 32)
		if err != nil {
			return nil, fmt.Errorf("mode %q", v)
		}
		e.mode, e.hasMode = uint32(m)&0o7777, true
	}
	var err error
	if e.uid, e.hasUID, err = id(kw, "uid", "uname"); err != nil {
		return nil, err
	}
	if e.gid, e.hasGID, err = id(kw, "gid", "gname"); err != nil {
		return nil, err
	}
	if v, ok := kw["device"]; ok {
		if e.major, e.minor, err = device(v); err != nil {
			return nil, err
		}
	}
	if v, ok := kw["link"]; ok {
		if e.link, err = unvis(v); err != nil {
			return nil, err
		}
	}
	return e, nil
}

// id returns a numeric id, or the well known id of a name: root and wheel
// are 0 everywhere; other names need numeric ids.
func id(kw map[string]string, num, name string) (uint32, bool, error) {
	if v, ok := kw[num]; ok {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return 0, false, fmt.Errorf("%s %q", num, v)
		}
		return uint32(n), true, nil
	}
	switch kw[name] {
	case "root", "wheel":
		return 0, true, nil
	}
	return 0, false, nil
}

// device parses "format,major,minor" (any format) or "major,minor".
func device(v string) (uint32, uint32, error) {
	parts := strings.Split(v, ",")
	if len(parts) == 3 {
		parts = parts[1:]
	}
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("device %q", v)
	}
	maj, err1 := strconv.ParseUint(parts[0], 0, 32)
	min, err2 := strconv.ParseUint(parts[1], 0, 32)
	if err1 != nil || err2 != nil {
		return 0, 0, fmt.Errorf("device %q", v)
	}
	return uint32(maj), uint32(min), nil
}

// unvis decodes the octal and C style escapes of mtree names.
func unvis(s string) (string, error) {
	if !strings.Contains(s, "\\") {
		return s, nil
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			continue
		}
		if i+4 <= len(s) && isOctal(s[i+1:i+4]) {
			n, _ := strconv.ParseUint(s[i+1:i+4], 8, 8)
			b.WriteByte(byte(n))
			i += 3
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("bad escape in %q", s)
		}
		i++
		switch s[i] {
		case 's':
			b.WriteByte(' ')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), nil
}

func isOctal(s string) bool {
	if len(s) != 3 {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '7' {
			return false
		}
	}
	return true
}

// rdev encodes a device number for NFSv2 the way BSD and SunOS clients
// decode it: major in bits 8-19, minor in bits 0-7 and 20-31.
func rdev(major, minor uint32) uint32 {
	return (major<<8)&0x000fff00 | minor&0xff | (minor<<12)&0xfff00000
}
