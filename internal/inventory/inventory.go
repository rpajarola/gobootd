// Package inventory holds the boot clients bootd serves and answers the
// questions every protocol asks: who is this client, may it use this
// service, and which file does this name refer to.
//
// An Inventory is immutable once built; a configuration reload builds a new
// one.
package inventory

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/service"
)

// Inventory is the set of configured hosts and classes.
type Inventory struct {
	// Root is the base directory for relative file paths.
	Root string
	// Services are the enabled services, by name.
	Services map[string]*config.Service
	Hosts    []*Host
	Classes  []*Class

	byName map[string]*Host // lower case
	byMAC  map[string]*Host // net.HardwareAddr.String()
	byIP   map[netip.Addr]*Host
}

// Class is a host template.
type Class struct {
	Name     string
	Match    map[string]string
	Services []string
	Files    []*File
	Disks    []*Disk
	Exports  []*Export
	Shares   []*Share
	Origin   hcl.Range
}

// Host is a boot client with all class settings applied.
type Host struct {
	Name  string
	MAC   net.HardwareAddr
	IP    netip.Addr
	Class *Class
	// Services the host may use, sorted.
	Services []string
	// Files in lookup order: host files first, then class files.
	Files   []*File
	Disks   []*Disk
	Exports []*Export
	Shares  []*Share

	// MACSource and IPSource say where the addresses came from:
	// "config", an ethers file, "dns", or empty if unknown.
	MACSource string
	IPSource  string
	Origin    hcl.Range
}

// File is a file a host may load.
type File struct {
	// Label is the path as written in the configuration.
	Label string
	// Path is the absolute path on this server.
	Path    string
	Name    string
	Aliases []string
	// Services that may serve this file. Nil means all services of the
	// host.
	Services []string
	Origin   hcl.Range
}

// Disk is a block device image.
type Disk struct {
	Name     string
	Path     string
	Mode     string
	Unit     int
	Writable bool
	Origin   hcl.Range
}

// Export is a file system path served over NFS.
type Export struct {
	Name     string
	Path     string
	Server   string
	Writable bool
	Origin   hcl.Range
}

// Share is a directory served over SMB.
type Share struct {
	Name     string
	Path     string
	Writable bool
	Origin   hcl.Range
}

// DeniedError explains why a request is refused. Its message is meant to be
// logged as is, e.g. "rarp request from 8:0:20:1:2:3 denied (client unknown)".
type DeniedError struct{ Reason string }

func (e *DeniedError) Error() string { return e.Reason }

func denied(format string, args ...any) error {
	return &DeniedError{Reason: fmt.Sprintf(format, args...)}
}

// ByName finds a host by name, ignoring case.
func (inv *Inventory) ByName(name string) (*Host, error) {
	if h, ok := inv.byName[strings.ToLower(name)]; ok {
		return h, nil
	}
	return nil, denied("client unknown")
}

// ByMAC finds a host by Ethernet address.
func (inv *Inventory) ByMAC(mac net.HardwareAddr) (*Host, error) {
	if h, ok := inv.byMAC[mac.String()]; ok {
		return h, nil
	}
	return nil, denied("client unknown")
}

// ByIP finds a host by IP address.
func (inv *Inventory) ByIP(ip netip.Addr) (*Host, error) {
	if h, ok := inv.byIP[ip.Unmap()]; ok {
		return h, nil
	}
	return nil, denied("client unknown")
}

// MatchClass returns the first class whose match map has key set to value,
// for protocols that identify the client model (e.g. RMP machine type).
func (inv *Inventory) MatchClass(key, value string) *Class {
	for _, c := range inv.Classes {
		if v, ok := c.Match[key]; ok && v == value {
			return c
		}
	}
	return nil
}

// Allows checks whether the host may use svc.
func (h *Host) Allows(svc string) error {
	if slices.Contains(h.Services, svc) {
		return nil
	}
	return denied("%s not allowed for this host", svc)
}

// MatchKind says how a requested name matched a file.
type MatchKind int

// Match kinds, best first.
const (
	MatchNone     MatchKind = iota
	MatchAny                // no name was requested
	MatchPath               // the full path
	MatchName               // the file's name
	MatchAlias              // one of the file's aliases
	MatchWildcard           // a "*" name or alias
)

func (k MatchKind) String() string {
	switch k {
	case MatchAny:
		return "default file"
	case MatchPath:
		return "path"
	case MatchName:
		return "name"
	case MatchAlias:
		return "alias"
	case MatchWildcard:
		return "wildcard"
	}
	return "no match"
}

// ServedBy reports whether svc may serve the file for host h.
func (f *File) ServedBy(h *Host, svc string) bool {
	if f.Services == nil {
		return slices.Contains(h.Services, svc)
	}
	return slices.Contains(f.Services, svc)
}

func (f *File) match(name string) MatchKind {
	switch {
	case name == "":
		return MatchAny
	case name == f.Path || name == f.Label:
		return MatchPath
	case name == f.Name:
		return MatchName
	case slices.Contains(f.Aliases, name):
		return MatchAlias
	case f.Name == "*" || slices.Contains(f.Aliases, "*"):
		return MatchWildcard
	}
	return MatchNone
}

// File finds the file a client asks for by name over svc. Exact matches win
// over aliases, aliases over wildcards; within a kind, the first configured
// file wins. An empty name selects the first file svc may serve.
func (h *Host) File(svc, name string) (*File, MatchKind, error) {
	if err := h.Allows(svc); err != nil {
		return nil, MatchNone, err
	}
	var best *File
	bestKind := MatchNone
	for _, f := range h.Files {
		if !f.ServedBy(h, svc) {
			continue
		}
		k := f.match(name)
		if k != MatchNone && (best == nil || k < bestKind) {
			best, bestKind = f, k
		}
	}
	if best == nil {
		if name == "" {
			return nil, MatchNone, denied("no %s file configured for this host", svc)
		}
		return nil, MatchNone, denied("file %q not configured for this host", name)
	}
	return best, bestKind, nil
}

// FilesFor lists the files svc may serve to the host, in lookup order.
func (h *Host) FilesFor(svc string) []*File {
	var fs []*File
	for _, f := range h.Files {
		if f.ServedBy(h, svc) {
			fs = append(fs, f)
		}
	}
	return fs
}

// Export finds an export by name.
func (h *Host) Export(name string) (*Export, error) {
	for _, e := range h.Exports {
		if e.Name == name {
			return e, nil
		}
	}
	return nil, denied("export %q not configured for this host", name)
}

// Disk finds a disk by unit number.
func (h *Host) Disk(unit int) (*Disk, error) {
	for _, d := range h.Disks {
		if d.Unit == unit {
			return d, nil
		}
	}
	return nil, denied("disk unit %d not configured for this host", unit)
}

// Share finds a share by name, ignoring case like SMB clients do.
func (h *Host) Share(name string) (*Share, error) {
	for _, s := range h.Shares {
		if strings.EqualFold(s.Name, name) {
			return s, nil
		}
	}
	return nil, denied("share %q not configured for this host", name)
}

// ServiceNames returns the enabled services in the standard order.
func (inv *Inventory) ServiceNames() []string {
	var names []string
	for _, n := range service.All {
		if _, ok := inv.Services[n]; ok {
			names = append(names, n)
		}
	}
	return names
}
