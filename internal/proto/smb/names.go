package smb

import (
	"hash/fnv"
	"strings"
)

// DOS clients see names in 8.3 form. A name that is not one is mangled
// into a stable 8.3 name, which leads back to it: the first characters of
// the name, a tilde and a hash of the whole name, and the start of the
// extension, as in LONGFI~K3Z.TXT.

// dosChar reports whether c may appear in an 8.3 name.
func dosChar(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'()-@^_`{}~", c) >= 0
}

// valid83 returns name in upper case if it is a valid 8.3 name.
func valid83(name string) (string, bool) {
	if name == "." || name == ".." {
		return name, true
	}
	base, ext, dot := strings.Cut(name, ".")
	if len(base) < 1 || len(base) > 8 || len(ext) > 3 || dot && ext == "" || strings.Contains(ext, ".") {
		return "", false
	}
	for i := range len(name) {
		if name[i] != '.' && !dosChar(name[i]) {
			return "", false
		}
	}
	return strings.ToUpper(name), true
}

// clean83 returns up to n characters of s that may be in an 8.3 name, in
// upper case.
func clean83(s string, n int) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < n; i++ {
		if dosChar(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return strings.ToUpper(b.String())
}

// mangle returns the 8.3 name of a name that is not one.
func mangle(name string) string {
	h := fnv.New32a()
	h.Write([]byte(name))
	sum := h.Sum32() % (36 * 36 * 36)
	const digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	hash := []byte{digits[sum/1296], digits[sum/36%36], digits[sum%36]}
	trimmed := strings.TrimLeft(name, ".")
	base, ext := trimmed, ""
	if i := strings.LastIndexByte(trimmed, '.'); i > 0 {
		base, ext = trimmed[:i], trimmed[i+1:]
	}
	prefix := clean83(base, 4)
	if prefix == "" {
		prefix = "_"
	}
	out := prefix + "~" + string(hash)
	if e := clean83(ext, 3); e != "" {
		out += "." + e
	}
	return out
}

// dosName returns the 8.3 name a DOS client sees for name.
func dosName(name string) string {
	if n, ok := valid83(name); ok {
		return n
	}
	return mangle(name)
}

// fcb returns the 11-character form of an 8.3 name or pattern, as FCBs
// and search resume keys hold it: the base padded to 8 and the extension
// to 3, with a * turned into ? to the end of its part.
func fcb(s string) [11]byte {
	var out [11]byte
	for i := range out {
		out[i] = ' '
	}
	if s == "." || s == ".." {
		copy(out[:], s)
		return out
	}
	base, ext := s, ""
	if i := strings.LastIndexByte(s, '.'); i >= 0 {
		base, ext = s[:i], s[i+1:]
	}
	fill := func(dst []byte, part string) {
		for i := 0; i < len(dst) && i < len(part); i++ {
			if part[i] == '*' {
				for j := i; j < len(dst); j++ {
					dst[j] = '?'
				}
				return
			}
			dst[i] = upper(part[i])
		}
	}
	fill(out[:8], base)
	fill(out[8:], ext)
	return out
}

func upper(c byte) byte {
	if c >= 'a' && c <= 'z' {
		return c - 'a' + 'A'
	}
	return c
}

// matchFCB matches an 8.3 name against a pattern the DOS way, field by
// field.
func matchFCB(pattern, name string) bool {
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	p, n := fcb(pattern), fcb(name)
	for i := range p {
		if p[i] != '?' && p[i] != n[i] {
			return false
		}
	}
	return true
}

// matchGlob matches a name against a pattern with * and ?, ignoring case.
// As in DOS, *.* also matches names without an extension.
func matchGlob(pattern, name string) bool {
	pattern, name = strings.ToUpper(pattern), strings.ToUpper(name)
	if pattern == "*" || pattern == "*.*" {
		return true
	}
	if glob(pattern, name) {
		return true
	}
	if p, ok := strings.CutSuffix(pattern, ".*"); ok && !strings.Contains(name, ".") {
		return glob(p, name)
	}
	return false
}

func glob(p, s string) bool {
	for len(p) > 0 {
		switch p[0] {
		case '*':
			for i := len(s); i >= 0; i-- {
				if glob(p[1:], s[i:]) {
					return true
				}
			}
			return false
		case '?':
			if len(s) == 0 {
				// ? also matches nothing at the end, as in DOS.
				return glob(p[1:], s)
			}
		default:
			if len(s) == 0 || s[0] != p[0] {
				return false
			}
		}
		p, s = p[1:], s[1:]
	}
	return len(s) == 0
}

// wild reports whether a name has wildcards.
func wild(s string) bool { return strings.ContainsAny(s, "*?") }
