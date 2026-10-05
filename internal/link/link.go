// Package link sends and receives raw Ethernet frames, for the boot
// protocols that do not run over IP or that must answer clients before they
// have an IP address.
package link

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
)

// Ethernet constants.
const (
	HeaderLen = 14
	// MinFrame is the minimum frame length without the frame check
	// sequence; shorter frames are padded.
	MinFrame = 60
	MaxFrame = 1514
	// MaxLength is the largest value of the type/length field that is a
	// length (IEEE 802.3) rather than an ethertype.
	MaxLength = 1500
)

// Ethertypes.
const (
	TypeIPv4 = 0x0800
	TypeARP  = 0x0806
	TypeRARP = 0x8035
)

// Interface describes a network interface a Port is attached to.
type Interface struct {
	Name string
	MAC  net.HardwareAddr
	// Addrs are the interface's IPv4 addresses.
	Addrs []netip.Prefix
}

// AddrFor returns the interface address on the same subnet as ip, or the
// first IPv4 address if none is, and false if the interface has none.
func (i *Interface) AddrFor(ip netip.Addr) (netip.Addr, bool) {
	for _, p := range i.Addrs {
		if p.Contains(ip) {
			return p.Addr(), true
		}
	}
	if len(i.Addrs) > 0 {
		return i.Addrs[0].Addr(), true
	}
	return netip.Addr{}, false
}

// OnLink reports whether ip is on one of the interface's subnets.
func (i *Interface) OnLink(ip netip.Addr) bool {
	return slices.ContainsFunc(i.Addrs, func(p netip.Prefix) bool { return p.Contains(ip) })
}

// Port receives and sends frames on one interface.
type Port interface {
	Interface() *Interface
	// ReadFrame returns the next received frame. It returns ctx.Err()
	// once ctx is done. The frame is only valid until the next call.
	ReadFrame(ctx context.Context) ([]byte, error)
	// WriteFrame sends a complete Ethernet frame, padding it to MinFrame.
	WriteFrame(frame []byte) error
	Close() error
}

// Opener opens ports. filter is a pcap filter expression that selects the
// frames a protocol wants; implementations may deliver other frames too, so
// protocols must check what they receive.
type Opener interface {
	Open(iface, filter string) (Port, error)
	// Interfaces lists the interfaces "all" stands for.
	Interfaces() ([]string, error)
}

// OpenAll opens a port on each named interface. "all" (or no names at all)
// stands for every suitable interface.
func OpenAll(o Opener, names []string, filter string) ([]Port, error) {
	if len(names) == 0 || slices.Contains(names, "all") {
		all, err := o.Interfaces()
		if err != nil {
			return nil, err
		}
		if len(all) == 0 {
			return nil, errors.New("no usable Ethernet interfaces")
		}
		names = all
	}
	var ports []Port
	for _, n := range names {
		p, err := o.Open(n, filter)
		if err != nil {
			for _, p := range ports {
				p.Close()
			}
			return nil, fmt.Errorf("interface %s: %w", n, err)
		}
		ports = append(ports, p)
	}
	return ports, nil
}

// Serve reads frames from every port and calls handle for each, one frame at
// a time per port, until ctx is done or a port fails. It closes the ports
// before returning.
func Serve(ctx context.Context, ports []Port, handle func(p Port, frame []byte)) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	for _, p := range ports {
		wg.Go(func() {
			defer p.Close()
			for {
				f, err := p.ReadFrame(ctx)
				if err != nil {
					if ctx.Err() == nil {
						cancel(fmt.Errorf("interface %s: %w", p.Interface().Name, err))
					}
					return
				}
				handle(p, f)
			}
		})
	}
	wg.Wait()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// Frame is a parsed Ethernet header.
type Frame struct {
	Dst, Src net.HardwareAddr
	// Type is the ethertype, or 0 for an IEEE 802.3 frame.
	Type uint16
	// Payload follows the header. For 802.3 frames it is cut to the
	// length field, which removes padding.
	Payload []byte
}

// Parse parses the Ethernet header of b. The result shares memory with b.
func Parse(b []byte) (Frame, bool) {
	if len(b) < HeaderLen {
		return Frame{}, false
	}
	f := Frame{Dst: net.HardwareAddr(b[0:6]), Src: net.HardwareAddr(b[6:12]), Payload: b[HeaderLen:]}
	tl := binary.BigEndian.Uint16(b[12:14])
	if tl > MaxLength {
		f.Type = tl
		return f, true
	}
	if int(tl) > len(f.Payload) {
		return Frame{}, false
	}
	f.Payload = f.Payload[:tl]
	return f, true
}

// Build returns a frame with an Ethernet II header and payload.
func Build(dst, src net.HardwareAddr, typ uint16, payload []byte) []byte {
	b := make([]byte, HeaderLen, HeaderLen+len(payload))
	copy(b[0:6], dst)
	copy(b[6:12], src)
	binary.BigEndian.PutUint16(b[12:14], typ)
	return append(b, payload...)
}

// Build8023 returns an IEEE 802.3 frame, whose header holds the payload
// length instead of a type.
func Build8023(dst, src net.HardwareAddr, payload []byte) []byte {
	return Build(dst, src, uint16(len(payload)), payload)
}

// Pad pads a frame to MinFrame bytes.
func Pad(frame []byte) []byte {
	if len(frame) >= MinFrame {
		return frame
	}
	return append(frame, make([]byte, MinFrame-len(frame))...)
}

// Broadcast is the Ethernet broadcast address.
var Broadcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
