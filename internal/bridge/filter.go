package bridge

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/rpajarola/gobootd/internal/link"
)

// Filter selects what a command shows: the frames of log, tail, dump
// and the bridge's own printing, or the transports and hosts of peers.
// ParseFilter makes one from what the user typed after -i.
type Filter struct {
	// Spec is what was parsed, for display.
	Spec string
	// Auto shows everything but LAN noise (see FrameEvent.Noise).
	Auto bool
	// LAN and UDP select the sides. Both are set for "all".
	LAN, UDP bool
	// Transports, for peers, are the selected UDP transports by name;
	// nil means all of them when UDP is set.
	Transports []string
}

// Purposes of a filter: frames are selected by side, peers also by
// transport.
const (
	ForFrames = false
	ForPeers  = true
)

// ParseFilter parses spec, which is one of
//
//	all, auto      everything, or everything but LAN noise
//	lan            the LAN side, also by its interface name
//	udp            the UDP side, also by its name
//	TRANSPORT      for peers: a transport by name, any unique part of
//	               one, or l2tp or raw for the transports of that kind
//
// and may start with - or ! to select everything else. An empty spec is
// auto for frames and all for peers. Case does not matter.
func (b *Bridge) ParseFilter(spec string, peers bool) (Filter, error) {
	s := strings.ToLower(strings.TrimSpace(spec))
	f := Filter{Spec: spec}
	if s == "" {
		if peers {
			s = "all"
		} else {
			s = "auto"
		}
		f.Spec = s
	}
	not := false
	if r := strings.TrimLeft(s, "-!"); r != s {
		not, s = true, r
	}
	transports := b.UDPPeers()
	var names []string
	for _, t := range transports {
		names = append(names, t.Name)
	}
	switch {
	case s == "all" || s == "auto":
		if not {
			return Filter{}, fmt.Errorf("%q: %s cannot be excluded", spec, s)
		}
		f.LAN, f.UDP, f.Auto = true, true, s == "auto"
		return f, nil
	case s == "lan" || s == strings.ToLower(b.lanName()):
		f.LAN = true
	case s == "udp" || s == strings.ToLower(b.udpName()):
		f.UDP = true
	default:
		sel, err := matchTransports(s, transports)
		if errors.Is(err, errNoSuchInterface) {
			return Filter{}, fmt.Errorf("%q: %w; %s", spec, err, b.filterHelp(peers, names))
		} else if err != nil {
			return Filter{}, fmt.Errorf("%q: %w", spec, err)
		}
		switch {
		case len(sel) == len(names):
			f.UDP = true // every transport: the UDP side
		case !peers:
			return Filter{}, fmt.Errorf("%q: frames are shown by side, not by transport: use udp, or %s with peers", spec, spec)
		default:
			f.UDP, f.Transports = true, sel
		}
	}
	if not {
		f.LAN = !f.LAN
		switch {
		case f.Transports != nil:
			var rest []string
			for _, n := range names {
				if !slices.Contains(f.Transports, n) {
					rest = append(rest, n)
				}
			}
			f.UDP, f.Transports = true, rest
		default:
			f.UDP = !f.UDP
		}
	}
	return f, nil
}

var errNoSuchInterface = errors.New("no such interface")

// matchTransports finds the transports s names: by kind, by name, or by
// a part of the name that only one of them has.
func matchTransports(s string, ts []link.TransportState) ([]string, error) {
	var sel []string
	switch s {
	case "l2tp", "l2tpv3", "raw":
		kind := "l2tpv3"
		if s == "raw" {
			kind = "raw"
		}
		for _, t := range ts {
			if t.Encapsulation == kind {
				sel = append(sel, t.Name)
			}
		}
		if sel == nil {
			return nil, fmt.Errorf("there is no %s transport", s)
		}
		return sel, nil
	}
	for _, t := range ts {
		if strings.ToLower(t.Name) == s {
			return []string{t.Name}, nil
		}
	}
	for _, t := range ts {
		if strings.Contains(strings.ToLower(t.Name), s) {
			sel = append(sel, t.Name)
		}
	}
	switch len(sel) {
	case 0:
		return nil, errNoSuchInterface
	case 1:
		return sel, nil
	}
	return nil, fmt.Errorf("%q is part of %s; say which", s, strings.Join(sel, " and "))
}

func (b *Bridge) filterHelp(peers bool, transports []string) string {
	h := fmt.Sprintf("use all, auto, lan (%s) or udp (%s)", b.lanName(), b.udpName())
	if peers && len(transports) > 1 {
		h += ", a transport (" + strings.Join(transports, ", ") + ")"
	}
	return h + ", or - before one to exclude it"
}

// Frame reports whether the filter shows e.
func (f Filter) Frame(e FrameEvent, lanName string) bool {
	if e.Interface == lanName {
		return f.LAN && !(f.Auto && e.Noise)
	}
	return f.UDP
}

// Transport reports whether the filter shows a UDP transport, for peers.
func (f Filter) Transport(name string) bool {
	return f.UDP && (f.Transports == nil || slices.Contains(f.Transports, name))
}

// AllTransports reports whether the filter shows the whole UDP side.
func (f Filter) AllTransports() bool { return f.UDP && f.Transports == nil }

// bootPorts are the UDP ports boot clients broadcast to: BOOTP and DHCP,
// TFTP, portmap (for CALLIT, which bootparam and NIS clients broadcast
// through) and PXE. A broadcast to any other port is noise.
var bootPorts = []uint16{67, 68, 69, 111, 4011}

// noiseTypes are EtherTypes of modern link management that no boot
// client speaks.
var noiseTypes = []uint16{
	0x86dd, // IPv6
	0x88cc, // LLDP
	0x88e1, // HomePlug AV
	0x8912, // HomePlug (Mediaxtream)
	0x893a, // IEEE 1905.1
	0x8899, // Realtek RRCP
}

// lanNoise reports whether a frame from the LAN has nothing to do with
// the UDP side: IPv6, link-layer control (spanning tree, LLDP, CDP,
// powerline), anything to an IPv4 multicast address (IGMP, mDNS, SSDP and
// the like: boot clients do not multicast), UDP broadcasts to ports that
// are not in bootPorts (the discovery of Syncthing, Plex, Ubiquiti,
// NetBIOS...), and ARP that is not about a host on the UDP side. Frames to
// a host on the UDP side are never noise, and neither is anything else,
// such as RARP, MOP, DECnet, AppleTalk or IPX: a request nobody answers is
// the one to see.
func (b *Bridge) lanNoise(frame []byte) bool {
	if len(frame) < 14 {
		return false
	}
	dst := [6]byte(frame[0:6])
	b.mu.Lock()
	toUDP := dst[0]&1 == 0 && b.isUDPLocked(dst)
	b.mu.Unlock()
	if toUDP {
		return false
	}
	typ := binary.BigEndian.Uint16(frame[12:14])
	switch {
	case dst[0] == 0x01 && dst[1] == 0x80 && dst[2] == 0xc2 && dst[3] == 0 && dst[4] == 0 && dst[5] < 0x10:
		return true // IEEE 802.1 link-local: STP, LLDP, LACP, 802.1X
	case dst == [6]byte{0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc}:
		return true // CDP, VTP
	case slices.Contains(noiseTypes, typ):
		return true
	case typ == 0x0806:
		return !b.arpAboutUDP(frame[14:])
	case typ == 0x0800:
		return ipv4Noise(frame[14:], dst[0]&1 != 0)
	}
	return false
}

// ipv4Noise reports whether an IPv4 packet sent to a group Ethernet
// address (broadcast or multicast) or not is noise.
func ipv4Noise(p []byte, group bool) bool {
	if len(p) < 20 || p[0]>>4 != 4 {
		return false
	}
	if netip.AddrFrom4([4]byte(p[16:20])).IsMulticast() {
		return true
	}
	hl := int(p[0]&0xf) * 4
	if !group || p[9] != 17 || len(p) < hl+4 || binary.BigEndian.Uint16(p[6:8])&0x1fff != 0 {
		return false
	}
	return !slices.Contains(bootPorts, binary.BigEndian.Uint16(p[hl+2:hl+4]))
}

// arpAboutUDP reports whether an ARP packet's sender or target is a host
// on the UDP side.
func (b *Bridge) arpAboutUDP(p []byte) bool {
	if len(p) < 28 || p[4] != 6 || p[5] != 4 {
		return true // not Ethernet/IPv4: show it
	}
	sender, target := netip.AddrFrom4([4]byte(p[14:18])), netip.AddrFrom4([4]byte(p[24:28]))
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, h := range b.udpStats.hosts {
		if h.ip == sender || h.ip == target {
			return true
		}
	}
	return false
}
