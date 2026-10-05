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

// readTimeout bounds how long ReadFrame waits before checking for
// cancellation.
const readTimeout = 250 * time.Millisecond

// OpenPcap captures on iface with libpcap, which needs privileges. It
// receives frames for mac and multicast frames. If mac is not the
// interface's own address, the interface is put in promiscuous mode. A nil
// mac receives every frame, as a bridge needs.
func OpenPcap(iface string, mac net.HardwareAddr) (Port, error) {
	ni, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, err
	}
	info := &Interface{Name: iface, MAC: ni.HardwareAddr, Addrs: ipv4Prefixes(ni)}
	if len(info.MAC) != 6 {
		return nil, errors.New("not an Ethernet interface")
	}
	promisc := string(mac) != string(info.MAC)

	in, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		return nil, err
	}
	defer in.CleanUp()
	for _, set := range []func() error{
		func() error { return in.SetSnapLen(65535) },
		func() error { return in.SetPromisc(promisc) },
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
	if mac != nil {
		filter := fmt.Sprintf("ether dst %s or ether multicast", mac)
		if err := h.SetBPFFilter(filter); err != nil {
			h.Close()
			return nil, fmt.Errorf("filter %q: %w", filter, err)
		}
	}
	// Ignore our own transmissions. Not every platform supports this;
	// Network also drops frames from its own address.
	_ = h.SetDirection(pcap.DirectionIn)
	return &pcapPort{h: h, info: info}, nil
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
