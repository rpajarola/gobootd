package nis

import (
	"bufio"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rpajarola/gobootd/internal/inventory"
)

// maxRecord is the longest key or value a client accepts (YPMAXRECORD).
const maxRecord = 1024

// nisMap is one map: keys in order, with their values.
type nisMap struct {
	keys  []string
	vals  map[string]string
	index map[string]int
	// lower is set for maps whose keys are matched without case.
	lower bool
}

func newMap(name string) *nisMap {
	return &nisMap{vals: map[string]string{}, lower: slices.Contains(lowerMaps, name)}
}

func (m *nisMap) key(k string) string {
	if m.lower {
		return strings.ToLower(k)
	}
	return k
}

// add adds an entry; the first entry for a key wins, as with makedbm.
func (m *nisMap) add(k, v string) {
	k = m.key(k)
	if _, ok := m.vals[k]; ok || k == "" {
		return
	}
	m.vals[k] = v
	m.keys = append(m.keys, k)
}

func (m *nisMap) finish() {
	slices.Sort(m.keys)
	m.index = make(map[string]int, len(m.keys))
	for i, k := range m.keys {
		m.index[k] = i
	}
}

func (m *nisMap) lookup(k string) (string, bool) {
	v, ok := m.vals[m.key(k)]
	return v, ok
}

// next returns the entry after k.
func (m *nisMap) next(k string) (key, val string, stat int32) {
	i, ok := m.index[m.key(k)]
	switch {
	case !ok:
		return "", "", ypNokey
	case i+1 >= len(m.keys):
		return "", "", ypNomore
	}
	key = m.keys[i+1]
	return key, m.vals[key], ypTrue
}

func (m *nisMap) clone() *nisMap {
	c := &nisMap{keys: slices.Clone(m.keys), vals: make(map[string]string, len(m.vals)), lower: m.lower}
	for k, v := range m.vals {
		c.vals[k] = v
	}
	return c
}

// maps are the maps of the domain.
type maps struct {
	m     map[string]*nisMap
	order uint32
}

func (ms *maps) get(name string) *nisMap {
	if ms.m[name] == nil {
		ms.m[name] = newMap(name)
	}
	return ms.m[name]
}

func (ms *maps) names() []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range ms.m {
			if !yield(k) {
				return
			}
		}
	})
}

// withHost returns a copy of ms with the server's own name and address in
// the hosts maps, unless they are there already, and the server in
// ypservers.
func (ms *maps) withHost(name string, ip netip.Addr) *maps {
	c := &maps{m: map[string]*nisMap{}, order: ms.order}
	for k, m := range ms.m {
		c.m[k] = m
	}
	byName, byAddr := c.get("hosts.byname").clone(), c.get("hosts.byaddr").clone()
	line := ip.String() + "\t" + name
	byName.add(name, line)
	byAddr.add(ip.String(), line)
	servers := newMap("ypservers")
	servers.add(name, name)
	for _, m := range []*nisMap{byName, byAddr, servers} {
		m.finish()
	}
	c.m["hosts.byname"], c.m["hosts.byaddr"], c.m["ypservers"] = byName, byAddr, servers
	return c
}

// Maps whose keys are matched without case, as SunOS's makedbm -l makes
// them.
var lowerMaps = []string{"hosts.byname", "networks.byname", "mail.aliases"}

// lineStyle says how a source file is split into entries.
type lineStyle int

const (
	// colon files (passwd, group) have no comments; lines starting with
	// + or - are NIS references, not entries.
	colon lineStyle = iota
	// words files have # comments and \ continuations.
	words
	// aliases files continue an entry on lines starting with blanks.
	aliases
)

type adder func(m, key, val string)

// source is a file in the maps directory and the maps made from it.
type source struct {
	file  string
	style lineStyle
	maps  []string
	parse func(line string, f []string, add adder)
}

// rest returns line after its first field.
func rest(line string, f []string) string {
	return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), f[0]))
}

// The maps made from each file, keyed as in SunOS 4's /var/yp/Makefile.
var sources = []source{
	{"passwd", colon, []string{"passwd.byname", "passwd.byuid"}, func(l string, _ []string, add adder) {
		if f := strings.Split(l, ":"); len(f) >= 7 {
			add("passwd.byname", f[0], l)
			add("passwd.byuid", f[2], l)
		}
	}},
	{"group", colon, []string{"group.byname", "group.bygid"}, func(l string, _ []string, add adder) {
		if f := strings.Split(l, ":"); len(f) >= 4 {
			add("group.byname", f[0], l)
			add("group.bygid", f[2], l)
		}
	}},
	{"hosts", words, []string{"hosts.byname", "hosts.byaddr"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("hosts.byaddr", f[0], l)
			for _, name := range f[1:] {
				add("hosts.byname", name, l)
			}
		}
	}},
	{"ethers", words, []string{"ethers.byaddr", "ethers.byname"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("ethers.byaddr", etherKey(f[0]), l)
			add("ethers.byname", f[1], l)
		}
	}},
	{"netgroup", words, []string{"netgroup"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("netgroup", f[0], rest(l, f))
		}
	}},
	{"services", words, []string{"services.byname"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("services.byname", f[1], l) // keyed port/protocol
		}
	}},
	{"protocols", words, []string{"protocols.byname", "protocols.bynumber"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("protocols.bynumber", f[1], l)
			add("protocols.byname", f[0], l)
			for _, a := range f[2:] {
				add("protocols.byname", a, l)
			}
		}
	}},
	{"rpc", words, []string{"rpc.bynumber"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("rpc.bynumber", f[1], l)
		}
	}},
	{"networks", words, []string{"networks.byname", "networks.byaddr"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("networks.byaddr", f[1], l)
			add("networks.byname", f[0], l)
			for _, a := range f[2:] {
				add("networks.byname", a, l)
			}
		}
	}},
	{"netmasks", words, []string{"netmasks.byaddr"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("netmasks.byaddr", f[0], f[1])
		}
	}},
	{"publickey", words, []string{"publickey.byname"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("publickey.byname", f[0], rest(l, f))
		}
	}},
	{"bootparams", words, []string{"bootparams"}, func(l string, f []string, add adder) {
		if len(f) >= 2 {
			add("bootparams", f[0], rest(l, f))
		}
	}},
	{"aliases", aliases, []string{"mail.aliases"}, func(l string, _ []string, add adder) {
		if name, val, ok := strings.Cut(l, ":"); ok {
			add("mail.aliases", strings.TrimSpace(name), strings.TrimSpace(val))
		}
	}},
}

// etherKey formats an Ethernet address the way ether_ntoa does
// (8:0:20:1:2:3), which is how clients look it up.
func etherKey(s string) string {
	mac, err := net.ParseMAC(s)
	if err != nil || len(mac) != 6 {
		// Accept SunOS's own format, which ParseMAC rejects.
		parts := strings.Split(s, ":")
		if len(parts) != 6 {
			return strings.ToLower(s)
		}
		mac = make(net.HardwareAddr, 6)
		for i, p := range parts {
			var b uint8
			if _, err := fmt.Sscanf(p, "%x", &b); err != nil || len(p) > 2 {
				return strings.ToLower(s)
			}
			mac[i] = b
		}
	}
	return fmt.Sprintf("%x:%x:%x:%x:%x:%x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// readEntries returns the entries of a source file.
func readEntries(path string, style lineStyle) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	var cont bool
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		l := strings.TrimRight(sc.Text(), " \t\r")
		switch style {
		case colon:
			if l == "" || strings.ContainsAny(l[:1], "#+-") {
				continue
			}
			out = append(out, l)
		case words:
			if i := strings.IndexByte(l, '#'); i >= 0 {
				l = strings.TrimRight(l[:i], " \t")
			}
			more := strings.HasSuffix(l, "\\")
			l = strings.TrimSuffix(l, "\\")
			if cont {
				out[len(out)-1] += " " + strings.TrimSpace(l)
			} else if strings.TrimSpace(l) != "" {
				out = append(out, strings.TrimSpace(l))
			} else {
				more = false
			}
			cont = more
		case aliases:
			if strings.HasPrefix(l, "#") || strings.TrimSpace(l) == "" {
				continue
			}
			if (l[0] == ' ' || l[0] == '\t') && len(out) > 0 {
				out[len(out)-1] += " " + strings.TrimSpace(l)
				continue
			}
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// build makes the maps from the source files in dir (if not empty) and
// the hosts in inv. It returns problems worth a warning.
func build(dir string, inv *inventory.Inventory, order uint32) (*maps, []string) {
	ms := &maps{m: map[string]*nisMap{}, order: order}
	var warnings []string
	for _, src := range sources {
		if dir == "" {
			break
		}
		path := filepath.Join(dir, src.file)
		entries, err := readEntries(path, src.style)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			warnings = append(warnings, err.Error())
			continue
		}
		for _, name := range src.maps {
			ms.get(name)
		}
		for _, l := range entries {
			src.parse(l, strings.Fields(l), func(m, k, v string) {
				if len(k) > maxRecord || len(v) > maxRecord {
					warnings = append(warnings, fmt.Sprintf("%s: entry %q in %s longer than %d bytes", path, k, m, maxRecord))
					return
				}
				ms.get(m).add(k, v)
			})
		}
	}
	// Configured hosts, unless the files list them.
	for _, h := range inv.Hosts {
		if h.IP.IsValid() {
			line := h.IP.String() + "\t" + h.Name
			ms.get("hosts.byname").add(h.Name, line)
			ms.get("hosts.byaddr").add(h.IP.String(), line)
		}
		if len(h.MAC) == 6 {
			key := etherKey(h.MAC.String())
			ms.get("ethers.byaddr").add(key, key+"\t"+h.Name)
			ms.get("ethers.byname").add(h.Name, key+"\t"+h.Name)
		}
	}
	if m := ms.m["mail.aliases"]; m != nil {
		m.add("@", "@") // sendmail checks for this to know the map is complete
	}
	for _, m := range ms.m {
		m.finish()
	}
	return ms, warnings
}
