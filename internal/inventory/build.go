package inventory

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/resolve"
	"github.com/rpajarola/gobootd/internal/service"
)

// Services that identify clients by MAC address, and services that need to
// know the client's IP address.
var (
	needsMAC = []string{service.RARP, service.RMP, service.MOP, service.ND, service.RPL, service.DHCP, service.RBCS}
	needsIP  = []string{service.RARP, service.ND, service.TFTP, service.Bootparam, service.NFS, service.SMB}
)

// Build creates an inventory from a parsed configuration, looking up missing
// addresses with r. Problems that make the configuration unusable are
// errors; problems that only affect some clients are warnings.
func Build(cfg *config.Config, r resolve.Resolver) (*Inventory, hcl.Diagnostics) {
	b := &builder{
		cfg: cfg,
		r:   r,
		inv: &Inventory{
			Root:     cfg.Root,
			Services: map[string]*config.Service{},
			byName:   map[string]*Host{},
			byMAC:    map[string]*Host{},
			byIP:     map[netip.Addr]*Host{},
		},
	}
	if st, err := os.Stat(cfg.Root); err != nil || !st.IsDir() {
		b.warn(nil, "Root directory missing", "Root directory %s does not exist; relative file paths will not be found.", cfg.Root)
		b.rootMissing = true
	}
	for _, s := range cfg.Services {
		b.inv.Services[s.Name] = s
	}
	classes := map[string]*Class{}
	for _, c := range cfg.Classes {
		if prev, ok := classes[c.Name]; ok {
			b.errorf(&c.DefRange, "Duplicate class", "Class %q is already defined at %s.", c.Name, prev.Origin)
			continue
		}
		cl := b.class(c)
		classes[c.Name] = cl
		b.inv.Classes = append(b.inv.Classes, cl)
	}
	for _, c := range cfg.Hosts {
		b.host(c, classes)
	}
	for _, svc := range b.inv.ServiceNames() {
		used := false
		for _, h := range b.inv.Hosts {
			used = used || slices.Contains(h.Services, svc)
		}
		// Classes with a match serve clients that have no host entry.
		for _, c := range b.inv.Classes {
			used = used || len(c.Match) > 0 && (c.Services == nil || slices.Contains(c.Services, "all") || slices.Contains(c.Services, svc))
		}
		if !used {
			s := b.inv.Services[svc]
			b.warn(&s.DefRange, "Service not used", "Service %q is enabled, but no host may use it.", svc)
		}
	}
	return b.inv, b.diags
}

type builder struct {
	cfg   *config.Config
	r     resolve.Resolver
	inv   *Inventory
	diags hcl.Diagnostics
	// rootMissing suppresses a warning per file when the root is missing.
	rootMissing bool
}

func (b *builder) class(c *config.Class) *Class {
	return &Class{
		Name:     c.Name,
		Match:    c.Match,
		Services: c.Services,
		Files:    b.files(c.Files),
		Disks:    b.disks(c.Disks),
		Exports:  b.exports(c.Exports),
		Shares:   b.shares(c.Shares),
		Origin:   c.DefRange,
	}
}

func (b *builder) host(c *config.Host, classes map[string]*Class) {
	key := strings.ToLower(c.Name)
	if prev, ok := b.inv.byName[key]; ok {
		b.errorf(&c.DefRange, "Duplicate host", "Host %q is already defined at %s.", c.Name, prev.Origin)
		return
	}
	h := &Host{
		Name:    c.Name,
		Files:   b.files(c.Files),
		Disks:   b.disks(c.Disks),
		Exports: b.exports(c.Exports),
		Shares:  b.shares(c.Shares),
		Origin:  c.DefRange,
	}
	services := c.Services
	if c.Class != "" {
		cl, ok := classes[c.Class]
		if !ok {
			b.errorf(&c.ClassRange, "Unknown class", "Host %q refers to class %q, which is not defined.", c.Name, c.Class)
		} else {
			h.Class = cl
			if services == nil {
				services = cl.Services
			}
			h.Files = mergeNamed(h.Files, cl.Files, func(f *File) string { return f.Name })
			h.Disks = mergeNamed(h.Disks, cl.Disks, func(d *Disk) string { return d.Name })
			h.Exports = mergeNamed(h.Exports, cl.Exports, func(e *Export) string { return e.Name })
			h.Shares = mergeNamed(h.Shares, cl.Shares, func(s *Share) string { return s.Name })
		}
	}
	h.Services = b.hostServices(h, services, &c.ServicesRange)
	b.addresses(h, c)
	b.checkHost(h)

	b.inv.Hosts = append(b.inv.Hosts, h)
	b.inv.byName[key] = h
	if h.MAC != nil {
		if prev, ok := b.inv.byMAC[h.MAC.String()]; ok {
			b.errorf(&c.DefRange, "Duplicate MAC address", "Host %q has MAC address %s, which host %q (%s) already has.", h.Name, h.MAC, prev.Name, prev.Origin)
		} else {
			b.inv.byMAC[h.MAC.String()] = h
		}
	}
	if h.IP.IsValid() {
		if prev, ok := b.inv.byIP[h.IP]; ok {
			b.errorf(&c.DefRange, "Duplicate IP address", "Host %q has IP address %s, which host %q (%s) already has.", h.Name, h.IP, prev.Name, prev.Origin)
		} else {
			b.inv.byIP[h.IP] = h
		}
	}
}

// hostServices expands "all" and defaults to every enabled service, and
// warns about services that are allowed but not enabled.
func (b *builder) hostServices(h *Host, names []string, rng *hcl.Range) []string {
	if names == nil || slices.Contains(names, "all") {
		return b.inv.ServiceNames()
	}
	var out []string
	for _, n := range service.All {
		if !slices.Contains(names, n) {
			continue
		}
		if _, ok := b.inv.Services[n]; !ok {
			b.warn(rng, "Service not enabled", "Host %q may use %s, but there is no service %q block, so %s requests will not be answered.", h.Name, n, n, n)
		}
		out = append(out, n)
	}
	return out
}

func (b *builder) addresses(h *Host, c *config.Host) {
	if c.MAC != "" {
		mac, err := resolve.ParseMAC(c.MAC)
		if err != nil {
			b.errorf(&c.MACRange, "Invalid MAC address", "%v.", err)
		} else {
			h.MAC, h.MACSource = mac, "config"
		}
	} else if b.r != nil {
		mac, src, err := b.r.LookupMAC(h.Name)
		switch {
		case err == nil:
			h.MAC, h.MACSource = mac, src
		case !errors.Is(err, resolve.ErrNotFound):
			b.warn(&c.DefRange, "MAC lookup failed", "Looking up the MAC address of %q: %v.", h.Name, err)
		}
	}
	if c.IP != "" {
		ip, err := netip.ParseAddr(c.IP)
		switch {
		case err != nil:
			b.errorf(&c.IPRange, "Invalid IP address", "%q is not an IP address.", c.IP)
		case !ip.Unmap().Is4():
			b.errorf(&c.IPRange, "Invalid IP address", "%s is not an IPv4 address.", c.IP)
		default:
			h.IP, h.IPSource = ip.Unmap(), "config"
		}
	} else if b.r != nil {
		ip, src, err := b.r.LookupIP(h.Name)
		switch {
		case err == nil:
			h.IP, h.IPSource = ip, src
		case !errors.Is(err, resolve.ErrNotFound):
			b.warn(&c.DefRange, "IP lookup failed", "Looking up the IP address of %q: %v.", h.Name, err)
		}
	}
	if h.MAC == nil {
		if svcs := intersect(h.Services, needsMAC); svcs != nil {
			b.warn(&c.DefRange, "No MAC address", "Host %q has no mac attribute and is not in the ethers file; %s will not recognize it.", h.Name, strings.Join(svcs, ", "))
		}
	}
	if !h.IP.IsValid() {
		if svcs := intersect(h.Services, needsIP); svcs != nil {
			b.warn(&c.DefRange, "No IP address", "Host %q has no ip attribute and its name does not resolve; %s will not work for it.", h.Name, strings.Join(svcs, ", "))
		}
	}
}

func (b *builder) checkHost(h *Host) {
	// Files that are never served, or shadowed by an earlier file.
	for _, f := range h.Files {
		if f.Services != nil && intersect(f.Services, h.Services) == nil {
			b.warn(&f.Origin, "File never served", "File %s is limited to %s, which host %q may not use.", f.Label, strings.Join(f.Services, ", "), h.Name)
		}
	}
	for _, svc := range h.Services {
		seen := map[string]*File{}
		for _, f := range h.FilesFor(svc) {
			for _, n := range append([]string{f.Name}, f.Aliases...) {
				if prev, ok := seen[n]; ok && prev != f {
					b.warn(&f.Origin, "File name shadowed", "For host %q, %s name %q already refers to %s (%s); this file is never served under that name.", h.Name, svc, n, prev.Label, prev.Origin)
				}
				if _, ok := seen[n]; !ok {
					seen[n] = f
				}
			}
		}
	}
	units := map[int]*Disk{}
	for _, d := range h.Disks {
		if prev, ok := units[d.Unit]; ok {
			b.errorf(&d.Origin, "Duplicate disk unit", "Host %q has disks %q and %q both on unit %d.", h.Name, prev.Name, d.Name, d.Unit)
		}
		units[d.Unit] = d
	}
	for _, d := range h.Disks {
		if d.Mode != config.DiskBootfile {
			continue
		}
		// Blocks 1-15 of a bootfile disk hold the first stage.
		if st, err := os.Stat(d.Path); err == nil && st.Size() > 15*512 {
			b.warn(&d.Origin, "Boot program too large", "%s is %d bytes, but the first-stage boot program of a bootfile disk must fit in 15 blocks (7680 bytes); use boot2 for the rest.", d.Path, st.Size())
		}
	}
	unused := func(n int, kind string, svcs ...string) {
		if n > 0 && intersect(h.Services, svcs) == nil {
			b.warn(&h.Origin, "Unused "+kind, "Host %q has %s entries, but may not use %s.", h.Name, kind, strings.Join(svcs, " or "))
		}
	}
	unused(len(h.Disks), "disk", service.ND)
	unused(len(h.Exports), "export", service.NFS, service.Bootparam)
	unused(len(h.Shares), "share", service.SMB)
	if len(h.Exports) == 0 {
		for _, svc := range intersect(h.Services, []string{service.Bootparam, service.NFS}) {
			b.warn(&h.Origin, "No exports", "Host %q may use %s, but has no export entries.", h.Name, svc)
		}
	}
}

func (b *builder) files(cs []*config.File) []*File {
	var out []*File
	for _, c := range cs {
		f := &File{
			Label:    c.Path,
			Path:     b.path(c.Path),
			Name:     c.Name,
			Aliases:  c.Aliases,
			Services: c.Services,
			Origin:   c.DefRange,
		}
		if f.Name == "" {
			f.Name = filepath.Base(c.Path)
		}
		b.exists(f.Path, &c.DefRange)
		out = append(out, f)
	}
	return out
}

func (b *builder) disks(cs []*config.Disk) []*Disk {
	var out []*Disk
	for _, c := range cs {
		d := &Disk{Name: c.Name, Path: b.path(c.Path), Mode: c.Mode, Unit: c.Unit, Writable: c.Writable, Origin: c.DefRange}
		b.exists(d.Path, &c.DefRange)
		if c.Boot2 != "" {
			d.Boot2 = b.path(c.Boot2)
			b.exists(d.Boot2, &c.Boot2Range)
		}
		out = append(out, d)
	}
	return out
}

func (b *builder) exports(cs []*config.Export) []*Export {
	var out []*Export
	for _, c := range cs {
		e := &Export{Name: c.Name, Path: b.path(c.Path), ExportPath: c.ExportPath, Server: c.Server, Writable: c.Writable, Origin: c.DefRange}
		if e.ExportPath == "" {
			e.ExportPath = e.Path
		}
		e.ExportPath = filepath.Clean(e.ExportPath)
		if len(e.ExportPath) > 86 {
			b.warn(&c.DefRange, "Long export path", "Export path %s is %d characters long; NetBSD clients keep \"server:path\" in 90 bytes. Set a shorter export_path.", e.ExportPath, len(e.ExportPath))
		}
		b.exists(e.Path, &c.DefRange)
		if c.Spec != "" {
			e.Spec = b.path(c.Spec)
			b.exists(e.Spec, &c.SpecRange)
		}
		out = append(out, e)
	}
	return out
}

func (b *builder) shares(cs []*config.Share) []*Share {
	var out []*Share
	for _, c := range cs {
		s := &Share{Name: c.Name, Path: b.path(c.Path), Writable: c.Writable, Origin: c.DefRange}
		b.exists(s.Path, &c.DefRange)
		out = append(out, s)
	}
	return out
}

func (b *builder) path(p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(b.inv.Root, p)
}

func (b *builder) exists(path string, rng *hcl.Range) {
	if b.rootMissing && strings.HasPrefix(path, b.inv.Root+string(filepath.Separator)) {
		return
	}
	if _, err := os.Stat(path); err != nil {
		b.warn(rng, "File not found", "%s does not exist.", path)
	}
}

func (b *builder) errorf(rng *hcl.Range, summary, format string, args ...any) {
	b.diags = append(b.diags, &hcl.Diagnostic{Severity: hcl.DiagError, Summary: summary, Detail: fmt.Sprintf(format, args...), Subject: rng})
}

func (b *builder) warn(rng *hcl.Range, summary, format string, args ...any) {
	b.diags = append(b.diags, &hcl.Diagnostic{Severity: hcl.DiagWarning, Summary: summary, Detail: fmt.Sprintf(format, args...), Subject: rng})
}

// mergeNamed appends the class entries the host does not override by name
// (for files: the name clients ask for).
func mergeNamed[T any](host, class []T, name func(T) string) []T {
	out := host
	for _, c := range class {
		if !slices.ContainsFunc(host, func(h T) bool { return name(h) == name(c) }) {
			out = append(out, c)
		}
	}
	return out
}

// intersect returns the elements of a that are in b, or nil if none are.
func intersect(a, b []string) []string {
	var out []string
	for _, s := range a {
		if slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}
