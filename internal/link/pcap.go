package link

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// Pcap opens ports with libpcap. It needs privileges to capture.
type Pcap struct{}

// readTimeout bounds how long ReadFrame waits before checking for
// cancellation.
const readTimeout = 250 * time.Millisecond

// Open opens a capture on iface. Frames are captured in promiscuous mode,
// because several protocols use multicast addresses the interface would
// otherwise filter out (RMP 09:00:09:00:00:04, RPL 03:00:02:00:00:00).
func (Pcap) Open(iface, filter string) (Port, error) {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	info := &Interface{Name: iface, MAC: ni.HardwareAddr, Addrs: ipv4Prefixes(ni)}
	if len(info.MAC) != 6 {
		return nil, errors.New("not an Ethernet interface")
	}

	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	for _, set := range []func() error{
		func() error { return in.SetSnapLen(65535) },
		func() error { return in.SetPromisc(true) },
		func() error { return in.SetTimeout(readTimeout) },
		// Deliver frames as they arrive instead of batching them.
		func() error { return in.SetImmediateMode(true) },
	} {
		if err := set(); err != nil {
			return nil, err
		}
	}
	h, err := in.Activate()
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "permission") {
			err = fmt.Errorf("%w (capturing needs root, CAP_NET_RAW on Linux, or access to /dev/bpf* on BSD and macOS)", err)
		}
		return nil, err
	}
	if h.LinkType() != 1 { // DLT_EN10MB
		h.Close()
		return nil, fmt.Errorf("link type %s is not Ethernet", h.LinkType())
	}
	if err := h.SetBPFFilter(filter); err != nil {
		h.Close()
		return nil, fmt.Errorf("filter %q: %w", filter, err)
	}
	// Ignore our own transmissions. Not every platform supports this,
	// so protocols also skip frames from the port's own address.
	_ = h.SetDirection(pcap.DirectionIn)
	return &pcapPort{h: h, info: info}, nil
}

// Interfaces lists the interfaces that are up, not loopback, have an
// Ethernet address and an IPv4 address.
func (Pcap) Interfaces() ([]string, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, i := range ifs {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagBroadcast == 0 ||
			len(i.HardwareAddr) != 6 || len(ipv4Prefixes(&i)) == 0 {
			continue
		}
		names = append(names, i.Name)
	}
	return names, nil
}

func ipv4Prefixes(ni *net.Interface) []netip.Prefix {
	addrs, err := ni.Addrs()
	if err != nil {
		return nil
	}
	var ps []netip.Prefix
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(n.IP)
		if !ok || !ip.Unmap().Is4() {
			continue
		}
		ones, _ := n.Mask.Size()
		if len(n.Mask) == net.IPv6len {
			ones -= 96
		}
		ps = append(ps, netip.PrefixFrom(ip.Unmap(), ones))
	}
	return ps
}

type pcapPort struct {
	h    *pcap.Handle
	info *Interface
	// wmu serializes writes; pcap handles are not safe for concurrent
	// sends.
	wmu  sync.Mutex
	once sync.Once
}

func (p *pcapPort) Interface() *Interface { return p.info }

func (p *pcapPort) ReadFrame(ctx context.Context) ([]byte, error) {
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, _, err := p.h.ZeroCopyReadPacketData()
		switch {
		case err == nil:
			return data, nil
		case errors.Is(err, pcap.NextErrorTimeoutExpired):
			continue
		default:
			return nil, err
		}
	}
}

func (p *pcapPort) WriteFrame(frame []byte) error {
	p.wmu.Lock()
	defer p.wmu.Unlock()
	return p.h.WritePacketData(Pad(frame))
}

func (p *pcapPort) Close() error {
	p.once.Do(p.h.Close)
	return nil
}
