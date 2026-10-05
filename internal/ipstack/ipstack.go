// Package ipstack runs a userspace IPv4 stack (gVisor's netstack) on a
// link port, so IP based protocols work the same over any transport and
// need no privileges or host addresses.
package ipstack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/link/ethernet"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/rpajarola/gobootd/internal/link"
)

const nicID = 1

// Stack is an IPv4 stack with one address on one link.
type Stack struct {
	s    *stack.Stack
	ep   *channel.Endpoint
	port link.Port
	addr netip.Prefix

	mu        sync.Mutex
	neighbors map[netip.Addr]net.HardwareAddr
}

// New creates a stack that sends and receives on port with the given
// Ethernet and IP address. Call Run to start it.
func New(port link.Port, mac net.HardwareAddr, addr netip.Prefix) (*Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol, tcp.NewProtocol, icmp.NewProtocol4},
		HandleLocal:        true,
	})
	ep := channel.New(512, link.MaxFrame, tcpip.LinkAddress(mac))
	if err := s.CreateNIC(nicID, ethernet.New(ep)); err != nil {
		return nil, fmt.Errorf("create NIC: %s", err)
	}
	pa := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4(addr.Addr().As4()),
			PrefixLen: addr.Bits(),
		},
	}
	if err := s.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
		return nil, fmt.Errorf("add address: %s", err)
	}
	// Every destination is on the link: boot clients are on the same
	// segment, even when their address is not in our subnet.
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nicID}})
	return &Stack{s: s, ep: ep, port: port, addr: addr, neighbors: map[netip.Addr]net.HardwareAddr{}}, nil
}

// Addr returns the stack's address.
func (st *Stack) Addr() netip.Prefix { return st.addr }

// Run moves frames between the port and the stack until ctx is done.
func (st *Stack) Run(ctx context.Context) error {
	defer st.s.Close()
	defer st.ep.Close()
	go func() {
		for {
			pkt := st.ep.ReadContext(ctx)
			if pkt == nil {
				return
			}
			frame := pkt.ToView().AsSlice()
			pkt.DecRef()
			st.port.WriteFrame(frame)
		}
	}()
	for {
		frame, err := st.port.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
		st.ep.InjectInbound(0, pkt)
		pkt.DecRef()
	}
}

// SetNeighbors replaces the static ARP entries. Boot clients often do not
// answer ARP before their operating system runs, so known hosts are
// entered statically.
func (st *Stack) SetNeighbors(n map[netip.Addr]net.HardwareAddr) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for ip := range st.neighbors {
		if _, ok := n[ip]; !ok {
			st.s.RemoveNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFrom4(ip.As4()))
			delete(st.neighbors, ip)
		}
	}
	for ip, mac := range n {
		if !ip.Is4() || len(mac) != 6 {
			continue
		}
		st.s.AddStaticNeighbor(nicID, ipv4.ProtocolNumber, tcpip.AddrFrom4(ip.As4()), tcpip.LinkAddress(mac))
		st.neighbors[ip] = mac
	}
}

func fullAddr(ap netip.AddrPort) tcpip.FullAddress {
	fa := tcpip.FullAddress{NIC: nicID, Port: ap.Port()}
	if ap.Addr().IsValid() && !ap.Addr().IsUnspecified() {
		fa.Addr = tcpip.AddrFrom4(ap.Addr().As4())
	}
	return fa
}

func toAddrPort(fa tcpip.FullAddress) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4(fa.Addr.As4()), fa.Port)
}

// DialUDP returns a UDP socket bound to local and connected to remote.
// A zero local port picks a free one.
func (st *Stack) DialUDP(local, remote netip.AddrPort) (net.Conn, error) {
	l, r := fullAddr(local), fullAddr(remote)
	return gonet.DialUDP(st.s, &l, &r, ipv4.ProtocolNumber)
}

// ListenTCP returns a TCP listener on port.
func (st *Stack) ListenTCP(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(st.s, tcpip.FullAddress{NIC: nicID, Port: port}, ipv4.ProtocolNumber)
}

// UDPListener receives datagrams on a port, sent to the stack's address or
// to a broadcast address.
type UDPListener struct {
	ep tcpip.Endpoint
	wq *waiter.Queue
}

// ListenUDP listens on port.
func (st *Stack) ListenUDP(port uint16) (*UDPListener, error) {
	var wq waiter.Queue
	ep, err := st.s.NewEndpoint(udp.ProtocolNumber, ipv4.ProtocolNumber, &wq)
	if err != nil {
		return nil, errors.New(err.String())
	}
	ep.SocketOptions().SetReceivePacketInfo(true)
	ep.SocketOptions().SetBroadcast(true)
	if err := ep.Bind(tcpip.FullAddress{NIC: nicID, Port: port}); err != nil {
		ep.Close()
		return nil, fmt.Errorf("bind port %d: %s", port, err)
	}
	return &UDPListener{ep: ep, wq: &wq}, nil
}

// Datagram is a received datagram.
type Datagram struct {
	Data []byte
	From netip.AddrPort
	// To is the destination address in the IP header.
	To netip.Addr
}

// ErrClosed is returned by Read after Close.
var ErrClosed = errors.New("closed")

// Read waits for the next datagram, until ctx is done.
func (l *UDPListener) Read(ctx context.Context) (Datagram, error) {
	buf := make([]byte, 65536)
	entry, notify := waiter.NewChannelEntry(waiter.ReadableEvents)
	l.wq.EventRegister(&entry)
	defer l.wq.EventUnregister(&entry)
	for {
		w := tcpip.SliceWriter(buf)
		res, err := l.ep.Read(&w, tcpip.ReadOptions{NeedRemoteAddr: true})
		switch err.(type) {
		case nil:
			d := Datagram{Data: buf[:res.Count], From: toAddrPort(res.RemoteAddr)}
			if cm := res.ControlMessages; cm.HasIPPacketInfo {
				d.To = netip.AddrFrom4(cm.PacketInfo.DestinationAddr.As4())
			}
			return d, nil
		case *tcpip.ErrWouldBlock:
			select {
			case <-notify:
			case <-ctx.Done():
				return Datagram{}, ctx.Err()
			}
		case *tcpip.ErrClosedForReceive, *tcpip.ErrInvalidEndpointState:
			return Datagram{}, ErrClosed
		default:
			return Datagram{}, errors.New(err.String())
		}
	}
}

// Close closes the listener.
func (l *UDPListener) Close() error {
	l.ep.Close()
	return nil
}

// WriteTo sends a datagram from the listener's port.
func (l *UDPListener) WriteTo(b []byte, to netip.AddrPort) error {
	fa := fullAddr(to)
	var r bytes.Reader
	r.Reset(b)
	if _, err := l.ep.Write(&r, tcpip.WriteOptions{To: &fa}); err != nil {
		return errors.New(err.String())
	}
	return nil
}
