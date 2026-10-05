// Package config parses the bootd HCL configuration file.
//
// It only checks syntax and the shape of the configuration. Cross references
// and name resolution are done when the inventory is built from it.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"slices"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"

	"github.com/rpajarola/gobootd/internal/service"
)

// DefaultPath is where bootd looks for its configuration by default.
const DefaultPath = "/etc/bootd.hcl"

// Config is the top level of a configuration file.
type Config struct {
	// Root is the base directory for relative file paths. Relative roots
	// are relative to the directory containing the configuration file.
	Root     string     `hcl:"root,optional"`
	Log      *Log       `hcl:"log,block"`
	Resolve  *Resolve   `hcl:"resolve,block"`
	Networks []*Network `hcl:"network,block"`
	Services []*Service `hcl:"service,block"`
	Classes  []*Class   `hcl:"class,block"`
	Hosts    []*Host    `hcl:"host,block"`

	// Filename is the path the configuration was loaded from.
	Filename string
}

// Log configures logging.
type Log struct {
	Level  string `hcl:"level,optional"`  // debug, info, warn, error
	Format string `hcl:"format,optional"` // text, json
	File   string `hcl:"file,optional"`   // path, "stderr" or "stdout"
	// Services overrides the level per service, e.g. { tftp = "debug" }.
	Services map[string]string `hcl:"services,optional"`

	DefRange      hcl.Range `hcl:",def_range"`
	LevelRange    hcl.Range `hcl:"level,attr_range"`
	FormatRange   hcl.Range `hcl:"format,attr_range"`
	ServicesRange hcl.Range `hcl:"services,attr_range"`
}

// Resolve configures how missing host addresses are looked up.
type Resolve struct {
	// Ethers is the ethers(5) file used to find MAC addresses by host
	// name. An empty string disables it.
	Ethers *string `hcl:"ethers,optional"`
	// DNS enables looking up IP addresses with the system resolver
	// (which includes /etc/hosts).
	DNS *bool `hcl:"dns,optional"`
}

// Network is an Ethernet segment bootd is attached to, with its own
// Ethernet and IP address. bootd runs its own IP stack on it.
type Network struct {
	Name string `hcl:"name,label"`
	// Address is bootd's IPv4 address and prefix, e.g. "192.168.1.250/24".
	Address string `hcl:"address"`
	// MAC is bootd's Ethernet address on the network. Empty means a
	// locally administered address derived from the network name;
	// "interface" means the address of the pcap interface.
	MAC string `hcl:"mac,optional"`
	// UDP is the address to exchange Ethernet frames on, one frame per
	// datagram (the HECnet bridge format, as used by bootbridge, simh
	// and QEMU).
	UDP string `hcl:"udp,optional"`
	// Peers are UDP addresses frames are always sent to. Other peers
	// are learned when they send.
	Peers []string `hcl:"peers,optional"`
	// Pcap is a network interface to capture on directly. This needs
	// privileges.
	Pcap string `hcl:"pcap,optional"`

	DefRange     hcl.Range `hcl:",def_range"`
	AddressRange hcl.Range `hcl:"address,attr_range"`
	MACRange     hcl.Range `hcl:"mac,attr_range"`
	UDPRange     hcl.Range `hcl:"udp,attr_range"`
	PeersRange   hcl.Range `hcl:"peers,attr_range"`
}

// MACInterface is the MAC setting that uses the interface's own address.
const MACInterface = "interface"

// Service enables a boot protocol.
type Service struct {
	Name string `hcl:"name,label"`
	// Networks the service is offered on. Defaults to all networks.
	Networks []string `hcl:"networks,optional"`
	// Options holds protocol specific settings.
	Options hcl.Body `hcl:",remain"`

	DefRange      hcl.Range `hcl:",def_range"`
	NetworksRange hcl.Range `hcl:"networks,attr_range"`
}

// Class is a template for hosts. Hosts reference it with class = "name";
// protocols that identify the client model (e.g. RMP machine type) can also
// select it through Match.
type Class struct {
	Name     string            `hcl:"name,label"`
	Match    map[string]string `hcl:"match,optional"`
	Services []string          `hcl:"services,optional"`
	Files    []*File           `hcl:"file,block"`
	Disks    []*Disk           `hcl:"disk,block"`
	Exports  []*Export         `hcl:"export,block"`
	Shares   []*Share          `hcl:"share,block"`

	DefRange      hcl.Range `hcl:",def_range"`
	ServicesRange hcl.Range `hcl:"services,attr_range"`
}

// Host is a boot client.
type Host struct {
	Name     string    `hcl:"name,label"`
	MAC      string    `hcl:"mac,optional"`
	IP       string    `hcl:"ip,optional"`
	Class    string    `hcl:"class,optional"`
	Services []string  `hcl:"services,optional"`
	Files    []*File   `hcl:"file,block"`
	Disks    []*Disk   `hcl:"disk,block"`
	Exports  []*Export `hcl:"export,block"`
	Shares   []*Share  `hcl:"share,block"`

	DefRange      hcl.Range `hcl:",def_range"`
	MACRange      hcl.Range `hcl:"mac,attr_range"`
	IPRange       hcl.Range `hcl:"ip,attr_range"`
	ClassRange    hcl.Range `hcl:"class,attr_range"`
	ServicesRange hcl.Range `hcl:"services,attr_range"`
}

// File is a file served to a client under one or more names.
type File struct {
	Path string `hcl:"path,label"`
	// Name is what the client asks for; "*" matches any name. Defaults
	// to the base name of Path.
	Name    string   `hcl:"name,optional"`
	Aliases []string `hcl:"aliases,optional"`
	// Services limits which protocols may serve the file. Defaults to all
	// services of the host.
	Services []string `hcl:"services,optional"`

	DefRange      hcl.Range `hcl:",def_range"`
	ServicesRange hcl.Range `hcl:"services,attr_range"`
}

// Disk is a block device image served by block protocols such as ND.
type Disk struct {
	Name string `hcl:"name,label"`
	Path string `hcl:"path"`
	// Mode is "image" (a disk image) or "bootfile" (a boot program served
	// as the first blocks of a virtual disk).
	Mode string `hcl:"mode,optional"`
	// Boot2 is a second-stage boot program for bootfile disks, served
	// from block 16 on, after the first-stage program in Path.
	Boot2    string `hcl:"boot2,optional"`
	Unit     int    `hcl:"unit,optional"`
	Writable bool   `hcl:"writable,optional"`

	DefRange   hcl.Range `hcl:",def_range"`
	ModeRange  hcl.Range `hcl:"mode,attr_range"`
	Boot2Range hcl.Range `hcl:"boot2,attr_range"`
}

// Export is a directory or file served over NFS and announced by bootparam.
type Export struct {
	Name string `hcl:"name,label"`
	Path string `hcl:"path"`
	// Server is the server name bootparam announces. Defaults to this
	// server.
	Server   string `hcl:"server,optional"`
	Writable bool   `hcl:"writable,optional"`

	DefRange hcl.Range `hcl:",def_range"`
}

// Share is a directory served over SMB.
type Share struct {
	Name     string `hcl:"name,label"`
	Path     string `hcl:"path"`
	Writable bool   `hcl:"writable,optional"`

	DefRange hcl.Range `hcl:",def_range"`
}

// Disk modes.
const (
	DiskImage    = "image"
	DiskBootfile = "bootfile"
)

// Load parses the configuration file at path. The returned parser holds the
// source files for printing diagnostics. The config is nil only if the file
// could not be parsed at all.
func Load(path string) (*Config, *hclparse.Parser, hcl.Diagnostics) {
	p := hclparse.NewParser()
	f, diags := p.ParseHCLFile(path)
	if diags.HasErrors() {
		return nil, p, diags
	}
	cfg, d := decode(f.Body, path)
	return cfg, p, append(diags, d...)
}

// Parse parses configuration source. filename is used in diagnostics and to
// resolve a relative root.
func Parse(src []byte, filename string) (*Config, *hclparse.Parser, hcl.Diagnostics) {
	p := hclparse.NewParser()
	f, diags := p.ParseHCL(src, filename)
	if diags.HasErrors() {
		return nil, p, diags
	}
	cfg, d := decode(f.Body, filename)
	return cfg, p, append(diags, d...)
}

func decode(body hcl.Body, filename string) (*Config, hcl.Diagnostics) {
	cfg := &Config{Filename: filename}
	diags := gohcl.DecodeBody(body, nil, cfg)
	if diags.HasErrors() {
		return nil, diags
	}
	diags = append(diags, cfg.defaults()...)
	diags = append(diags, cfg.validate()...)
	return cfg, diags
}

func (c *Config) defaults() hcl.Diagnostics {
	base := filepath.Dir(c.Filename)
	if abs, err := filepath.Abs(base); err == nil {
		base = abs
	}
	switch {
	case c.Root == "":
		c.Root = base
	case !filepath.IsAbs(c.Root):
		c.Root = filepath.Join(base, c.Root)
	}
	if c.Log == nil {
		c.Log = &Log{}
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	switch {
	case c.Log.File == "":
		c.Log.File = "stderr"
	case c.Log.File != "stderr" && c.Log.File != "stdout" && !filepath.IsAbs(c.Log.File):
		c.Log.File = filepath.Join(base, c.Log.File)
	}
	if c.Resolve == nil {
		c.Resolve = &Resolve{}
	}
	if c.Resolve.Ethers == nil {
		s := "/etc/ethers"
		c.Resolve.Ethers = &s
	}
	if c.Resolve.DNS == nil {
		t := true
		c.Resolve.DNS = &t
	}
	for _, h := range c.Hosts {
		disksDefaults(h.Disks)
	}
	for _, cl := range c.Classes {
		disksDefaults(cl.Disks)
	}
	return nil
}

func disksDefaults(disks []*Disk) {
	for _, d := range disks {
		if d.Mode == "" {
			d.Mode = DiskImage
		}
	}
}

var logLevels = []string{"debug", "info", "warn", "error"}

func (c *Config) validate() hcl.Diagnostics {
	var diags hcl.Diagnostics
	if !slices.Contains(logLevels, c.Log.Level) {
		diags = append(diags, errorf(c.Log.LevelRange, "Invalid log level",
			"Log level %q is not one of %v.", c.Log.Level, logLevels))
	}
	for svc, lvl := range c.Log.Services {
		if !service.Known(svc) {
			diags = append(diags, unknownService(c.Log.ServicesRange, svc))
		}
		if !slices.Contains(logLevels, lvl) {
			diags = append(diags, errorf(c.Log.ServicesRange, "Invalid log level",
				"Log level %q for service %s is not one of %v.", lvl, svc, logLevels))
		}
	}
	if c.Log.Format != "text" && c.Log.Format != "json" {
		diags = append(diags, errorf(c.Log.FormatRange, "Invalid log format",
			"Log format %q is not \"text\" or \"json\".", c.Log.Format))
	}

	nets := map[string]*Network{}
	for _, n := range c.Networks {
		if prev, ok := nets[n.Name]; ok {
			diags = append(diags, errorf(n.DefRange, "Duplicate network",
				"Network %q is already defined at %s.", n.Name, prev.DefRange))
		}
		nets[n.Name] = n
		diags = append(diags, n.validate()...)
	}

	seen := map[string]*Service{}
	for _, s := range c.Services {
		for _, n := range s.Networks {
			if _, ok := nets[n]; !ok {
				diags = append(diags, errorf(s.NetworksRange, "Unknown network",
					"Service %q uses network %q, which is not defined.", s.Name, n))
			}
		}
		if !service.Known(s.Name) {
			diags = append(diags, unknownService(s.DefRange, s.Name))
		}
		if prev, ok := seen[s.Name]; ok {
			diags = append(diags, errorf(s.DefRange, "Duplicate service block",
				"Service %q is already configured at %s.", s.Name, prev.DefRange))
		}
		seen[s.Name] = s
	}

	if len(c.Services) > 0 && len(c.Networks) == 0 {
		diags = append(diags, &hcl.Diagnostic{Severity: hcl.DiagWarning, Summary: "No network",
			Detail:  "Services are enabled, but there is no network block to offer them on.",
			Subject: c.Services[0].DefRange.Ptr()})
	}
	for _, cl := range c.Classes {
		diags = append(diags, checkServices(cl.Services, cl.ServicesRange, true)...)
		diags = append(diags, checkFiles(cl.Files)...)
		diags = append(diags, checkDisks(cl.Disks)...)
	}
	for _, h := range c.Hosts {
		diags = append(diags, checkServices(h.Services, h.ServicesRange, true)...)
		diags = append(diags, checkFiles(h.Files)...)
		diags = append(diags, checkDisks(h.Disks)...)
	}
	return diags
}

func (n *Network) validate() hcl.Diagnostics {
	var diags hcl.Diagnostics
	if p, err := netip.ParsePrefix(n.Address); err != nil || !p.Addr().Is4() {
		diags = append(diags, errorf(n.AddressRange, "Invalid network address",
			"%q is not an IPv4 address with prefix length, like \"192.168.1.250/24\".", n.Address))
	}
	switch {
	case (n.UDP == "") == (n.Pcap == ""):
		diags = append(diags, errorf(n.DefRange, "Network needs one transport",
			"Network %q must have either udp or pcap.", n.Name))
	case n.UDP != "":
		if _, err := netip.ParseAddrPort(n.UDP); err != nil {
			diags = append(diags, errorf(n.UDPRange, "Invalid UDP address",
				"%q is not an IP address and port, like \"127.0.0.1:4711\".", n.UDP))
		}
	}
	if n.Pcap == "" && len(n.Peers) > 0 {
		for _, p := range n.Peers {
			if _, err := netip.ParseAddrPort(p); err != nil {
				diags = append(diags, errorf(n.PeersRange, "Invalid peer address",
					"%q is not an IP address and port.", p))
			}
		}
	} else if len(n.Peers) > 0 {
		diags = append(diags, errorf(n.PeersRange, "Peers need udp", "Only udp networks have peers."))
	}
	switch {
	case n.MAC == MACInterface:
		if n.Pcap == "" {
			diags = append(diags, errorf(n.MACRange, "No interface MAC",
				"mac = %q needs a pcap interface.", MACInterface))
		}
	case n.MAC != "":
		if mac, err := net.ParseMAC(n.MAC); err != nil || len(mac) != 6 {
			diags = append(diags, errorf(n.MACRange, "Invalid MAC address", "%q is not an Ethernet address.", n.MAC))
		} else if mac[0]&1 != 0 {
			diags = append(diags, errorf(n.MACRange, "Invalid MAC address", "%s is a multicast address.", n.MAC))
		}
	}
	return diags
}

func checkServices(names []string, rng hcl.Range, allowAll bool) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, n := range names {
		if allowAll && n == "all" {
			continue
		}
		if !service.Known(n) {
			diags = append(diags, unknownService(rng, n))
		}
	}
	return diags
}

func checkFiles(files []*File) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, f := range files {
		diags = append(diags, checkServices(f.Services, f.ServicesRange, false)...)
	}
	return diags
}

func checkDisks(disks []*Disk) hcl.Diagnostics {
	var diags hcl.Diagnostics
	for _, d := range disks {
		if d.Mode != DiskImage && d.Mode != DiskBootfile {
			diags = append(diags, errorf(d.ModeRange, "Invalid disk mode",
				"Disk mode %q is not %q or %q.", d.Mode, DiskImage, DiskBootfile))
		}
		if d.Boot2 != "" && d.Mode != DiskBootfile {
			diags = append(diags, errorf(d.Boot2Range, "boot2 needs bootfile mode",
				"Only disks with mode = %q have a second-stage boot program.", DiskBootfile))
		}
		if d.Writable && d.Mode == DiskBootfile {
			diags = append(diags, errorf(d.DefRange, "Bootfile disk is read only",
				"Disks with mode = %q cannot be writable.", DiskBootfile))
		}
	}
	return diags
}

func unknownService(rng hcl.Range, name string) *hcl.Diagnostic {
	return errorf(rng, "Unknown service", "%q is not a known service. Known services are: %v.", name, service.All)
}

func errorf(rng hcl.Range, summary, format string, args ...any) *hcl.Diagnostic {
	return &hcl.Diagnostic{
		Severity: hcl.DiagError,
		Summary:  summary,
		Detail:   fmt.Sprintf(format, args...),
		Subject:  rng.Ptr(),
	}
}
