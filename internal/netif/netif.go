// Package netif sets up the networks bootd is attached to: the transport
// that carries Ethernet frames, bootd's addresses, and the IP stack.
package netif

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/ipstack"
	"github.com/rpajarola/gobootd/internal/link"
)

// Network is one configured network.
type Network struct {
	*link.Network
	Config *config.Network
	// IP is bootd's IP stack on the network. It receives the frames no
	// protocol subscribed to.
	IP *ipstack.Stack
}

// Open opens the transport described by cfg and returns the network. Call
// Run to start it.
func Open(cfg *config.Network) (*Network, error) {
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return nil, err
	}
	var mac net.HardwareAddr
	switch cfg.MAC {
	case "", config.MACInterface:
	default:
		if mac, err = net.ParseMAC(cfg.MAC); err != nil {
			return nil, err
		}
	}
	if cfg.MAC == "" {
		mac = link.DefaultMAC(cfg.Name, addr)
	}
	var t link.Port
	if cfg.Pcap != "" {
		if mac == nil {
			ni, err := net.InterfaceByName(cfg.Pcap)
			if err != nil {
				return nil, fmt.Errorf("network %s: %w", cfg.Name, err)
			}
			mac = ni.HardwareAddr
		}
		if t, err = link.OpenPcap(cfg.Pcap, mac); err != nil {
			return nil, fmt.Errorf("network %s: %w", cfg.Name, err)
		}
	} else {
		local, err := netip.ParseAddrPort(cfg.UDP)
		if err != nil {
			return nil, err
		}
		var peers []netip.AddrPort
		for _, p := range cfg.Peers {
			ap, err := netip.ParseAddrPort(p)
			if err != nil {
				return nil, err
			}
			peers = append(peers, ap)
		}
		if t, err = link.ListenUDP(local, peers); err != nil {
			return nil, fmt.Errorf("network %s: %w", cfg.Name, err)
		}
	}
	return New(cfg, t, mac)
}

// New creates a network on an open transport. mac is bootd's Ethernet
// address.
func New(cfg *config.Network, t link.Port, mac net.HardwareAddr) (*Network, error) {
	addr, err := netip.ParsePrefix(cfg.Address)
	if err != nil {
		return nil, err
	}
	ln := link.NewNetwork(cfg.Name, t, mac, addr)
	ip, err := ipstack.New(ln.SetDefault(), mac, addr)
	if err != nil {
		t.Close()
		return nil, err
	}
	return &Network{Network: ln, Config: cfg, IP: ip}, nil
}

// Run serves the network until ctx is done.
func (n *Network) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 1)
	go func() { errc <- n.IP.Run(ctx) }()
	err := n.Network.Run(ctx)
	cancel()
	if ipErr := <-errc; err == nil {
		err = ipErr
	}
	return err
}

// SetHosts enters the hosts with both addresses as static ARP entries, so
// clients that do not answer ARP yet can still be reached.
func (n *Network) SetHosts(inv *inventory.Inventory) {
	m := map[netip.Addr]net.HardwareAddr{}
	for _, h := range inv.Hosts {
		if h.MAC != nil && h.IP.IsValid() {
			m[h.IP] = h.MAC
		}
	}
	n.IP.SetNeighbors(m)
}

// Addr returns bootd's IP address on the network.
func (n *Network) Addr() netip.Prefix { return n.Interface().Addrs[0] }
