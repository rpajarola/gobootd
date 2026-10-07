// Package bridge connects an Ethernet segment to UDP peers that exchange
// frames in the HECnet bridge format, so that bootd, simh and QEMU can
// reach real machines without privileges of their own.
package bridge

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
)

// lanTimeout is how long a MAC address seen on the LAN is remembered.
const lanTimeout = 5 * time.Minute

type ifStats struct {
	hosts     map[[6]byte]netip.Addr
	rxPackets uint64
	txPackets uint64
	rxBytes   uint64
	txBytes   uint64
	errors    uint64
}

// InterfaceStats holds counters for an interface connected to the bridge.
type InterfaceStats struct {
	Name      string
	Hosts     int
	RxPackets uint64
	TxPackets uint64
	RxBytes   uint64
	TxBytes   uint64
	Errors    uint64
}

// Bridge forwards frames between a LAN port and a UDP transport. Like a
// learning switch, it only forwards unicast frames to the side the
// destination was last seen on, so the UDP peers do not receive all of the
// LAN's traffic.
type Bridge struct {
	LAN link.Port
	UDP *link.UDP
	Log *slog.Logger

	// StatsInterval is how often interface statistics are logged.
	// If zero, it defaults to 30 seconds. If negative, periodic logging is disabled.
	StatsInterval time.Duration

	mu       sync.Mutex
	lanMAC   [6]byte
	lan      map[[6]byte]time.Time
	udp      map[[6]byte]time.Time
	lanStats ifStats
	udpStats ifStats
}

// isLAN reports whether mac is currently known on the LAN.
func (b *Bridge) isLAN(mac [6]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.isLANLocked(mac)
}

func (b *Bridge) isLANLocked(mac [6]byte) bool {
	if b.lanMAC != [6]byte{} && mac == b.lanMAC {
		return true
	}
	t, ok := b.lan[mac]
	if !ok || time.Since(t) >= lanTimeout {
		return false
	}
	if ut, uok := b.udp[mac]; uok && ut.After(t) {
		return false
	}
	return true
}

// isUDP reports whether mac is currently known on the UDP transport.
func (b *Bridge) isUDP(mac [6]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.isUDPLocked(mac)
}

func (b *Bridge) isUDPLocked(mac [6]byte) bool {
	t, ok := b.udp[mac]
	if ok && time.Since(t) < lanTimeout {
		if lt, lok := b.lan[mac]; lok && lt.After(t) {
			return false
		}
		return true
	}
	if b.UDP != nil && b.UDP.Knows(mac[:]) {
		if lt, lok := b.lan[mac]; lok && time.Since(lt) < lanTimeout {
			return false
		}
		return true
	}
	return false
}

func (b *Bridge) pruneLocked(now time.Time) {
	for m, t := range b.lan {
		if now.Sub(t) >= lanTimeout {
			delete(b.lan, m)
		}
	}
	for m, t := range b.udp {
		if now.Sub(t) >= lanTimeout {
			delete(b.udp, m)
		}
	}
}

// LANStats returns a snapshot of the LAN interface statistics.
func (b *Bridge) LANStats() InterfaceStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return InterfaceStats{
		Name:      b.lanName(),
		Hosts:     len(b.lanStats.hosts),
		RxPackets: b.lanStats.rxPackets,
		TxPackets: b.lanStats.txPackets,
		RxBytes:   b.lanStats.rxBytes,
		TxBytes:   b.lanStats.txBytes,
		Errors:    b.lanStats.errors,
	}
}

// UDPStats returns a snapshot of the UDP interface statistics.
func (b *Bridge) UDPStats() InterfaceStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	return InterfaceStats{
		Name:      b.udpName(),
		Hosts:     len(b.udpStats.hosts),
		RxPackets: b.udpStats.rxPackets,
		TxPackets: b.udpStats.txPackets,
		RxBytes:   b.udpStats.rxBytes,
		TxBytes:   b.udpStats.txBytes,
		Errors:    b.udpStats.errors,
	}
}

// LogStats logs the current statistics for each interface.
func (b *Bridge) LogStats() {
	b.mu.Lock()
	b.pruneLocked(time.Now())
	b.mu.Unlock()
	b.logInterface(b.LANStats())
	b.logInterface(b.UDPStats())
}

func (b *Bridge) logInterface(s InterfaceStats) {
	b.logger().Info("interface stats",
		"interface", s.Name,
		"hosts", s.Hosts,
		"rx_packets", s.RxPackets,
		"tx_packets", s.TxPackets,
		"rx_bytes", s.RxBytes,
		"tx_bytes", s.TxBytes,
		"errors", s.Errors,
	)
}

func (b *Bridge) lanName() string {
	if b.LAN != nil && b.LAN.Interface() != nil && b.LAN.Interface().Name != "" {
		return b.LAN.Interface().Name
	}
	return "lan"
}

func (b *Bridge) udpName() string {
	if b.UDP != nil && b.UDP.Interface() != nil && b.UDP.Interface().Name != "" {
		return b.UDP.Interface().Name
	}
	return "udp"
}

func (b *Bridge) logger() *slog.Logger {
	if b.Log != nil {
		return b.Log
	}
	return slog.Default()
}

func (b *Bridge) recordUDPTx(bytes, pkts int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.udpStats.errors++
	}
	if pkts > 0 {
		b.udpStats.txPackets += uint64(pkts)
		b.udpStats.txBytes += uint64(bytes)
	}
}

func (b *Bridge) recordLANTx(bytes, pkts int, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err != nil {
		b.lanStats.errors++
	}
	if pkts > 0 {
		b.lanStats.txPackets += uint64(pkts)
		b.lanStats.txBytes += uint64(bytes)
	}
}

// Run forwards frames until ctx is done or a port fails.
func (b *Bridge) Run(ctx context.Context) error {
	b.mu.Lock()
	b.lan = map[[6]byte]time.Time{}
	b.udp = map[[6]byte]time.Time{}
	b.lanStats = ifStats{hosts: make(map[[6]byte]netip.Addr)}
	b.udpStats = ifStats{hosts: make(map[[6]byte]netip.Addr)}
	if b.LAN != nil && b.LAN.Interface() != nil && len(b.LAN.Interface().MAC) == 6 {
		copy(b.lanMAC[:], b.LAN.Interface().MAC)
	}
	b.mu.Unlock()

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	wg.Go(func() {
		if err := b.fromLAN(ctx); err != nil && ctx.Err() == nil {
			cancel(err)
		}
	})
	wg.Go(func() {
		if err := b.fromUDP(ctx); err != nil && ctx.Err() == nil {
			cancel(err)
		}
	})
	interval := b.StatsInterval
	if interval == 0 {
		interval = 30 * time.Second
	}
	if interval > 0 {
		wg.Go(func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					b.LogStats()
				case <-ctx.Done():
					return
				}
			}
		})
	}
	wg.Wait()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (b *Bridge) logNewHost(iface string, mac net.HardwareAddr, ip, peer netip.Addr) {
	attrs := []any{"interface", iface, "mac", mac.String()}
	if ip.IsValid() {
		attrs = append(attrs, "ip", ip.String())
	}
	if peer.IsValid() {
		attrs = append(attrs, "peer", peer.String())
	}
	b.logger().Info("new host", attrs...)
}

func (b *Bridge) logHostIP(iface string, mac net.HardwareAddr, ip, peer netip.Addr) {
	attrs := []any{"interface", iface, "mac", mac.String(), "ip", ip.String()}
	if peer.IsValid() {
		attrs = append(attrs, "peer", peer.String())
	}
	b.logger().Info("host ip", attrs...)
}

func findSourceIP(frame []byte) netip.Addr {
	if len(frame) < link.HeaderLen {
		return netip.Addr{}
	}
	ethertype := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[link.HeaderLen:]

	if ethertype <= link.MaxLength {
		// IEEE 802.3 LLC/SNAP frame
		if len(payload) >= 8 && payload[0] == 0xaa && payload[1] == 0xaa && payload[2] == 0x03 {
			ethertype = binary.BigEndian.Uint16(payload[6:8])
			payload = payload[8:]
		} else {
			return netip.Addr{}
		}
	}

	switch ethertype {
	case link.TypeIPv4:
		if len(payload) >= 20 {
			version := payload[0] >> 4
			ihl := payload[0] & 0x0f
			if version == 4 && ihl >= 5 && len(payload) >= int(ihl)*4 {
				ip := netip.AddrFrom4([4]byte(payload[12:16]))
				if ip.IsValid() && !ip.IsUnspecified() {
					return ip
				}
			}
		}
	case link.TypeARP, link.TypeRARP:
		if len(payload) >= 28 {
			hwType := binary.BigEndian.Uint16(payload[0:2])
			protoType := binary.BigEndian.Uint16(payload[2:4])
			hwLen := payload[4]
			protoLen := payload[5]
			if hwType == 1 && protoType == link.TypeIPv4 && hwLen == 6 && protoLen == 4 {
				ip := netip.AddrFrom4([4]byte(payload[14:18]))
				if ip.IsValid() && !ip.IsUnspecified() {
					return ip
				}
			}
		}
	case 0x86dd: // IPv6
		if len(payload) >= 40 {
			version := payload[0] >> 4
			if version == 6 {
				ip := netip.AddrFrom16([16]byte(payload[8:24]))
				if ip.IsValid() && !ip.IsUnspecified() {
					return ip
				}
			}
		}
	}
	return netip.Addr{}
}

func (b *Bridge) fromLAN(ctx context.Context) error {
	for {
		frame, err := b.LAN.ReadFrame(ctx)
		if err != nil {
			if ctx.Err() == nil {
				b.mu.Lock()
				b.lanStats.errors++
				b.mu.Unlock()
			}
			return err
		}
		if len(frame) < link.HeaderLen {
			b.mu.Lock()
			b.lanStats.errors++
			b.mu.Unlock()
			continue
		}
		var dstMAC, srcMAC [6]byte
		copy(dstMAC[:], frame[0:6])
		copy(srcMAC[:], frame[6:12])

		// Drop invalid frames: multicast source, all-zero source, or loopback (src == dst).
		if srcMAC[0]&1 != 0 || srcMAC == [6]byte{} || srcMAC == dstMAC {
			b.mu.Lock()
			b.lanStats.errors++
			b.mu.Unlock()
			continue
		}

		// Suppress BPF loopback: if the source MAC is known on the UDP side,
		// this frame was transmitted onto the LAN by this bridge (or looped
		// back by the physical segment).
		if b.isUDP(srcMAC) {
			continue
		}

		ip := findSourceIP(frame)

		var newHost, newIP bool
		b.mu.Lock()
		b.lanStats.rxPackets++
		b.lanStats.rxBytes += uint64(len(frame))
		if prevIP, ok := b.lanStats.hosts[srcMAC]; !ok {
			b.lanStats.hosts[srcMAC] = ip
			newHost = true
		} else if !prevIP.IsValid() && ip.IsValid() {
			b.lanStats.hosts[srcMAC] = ip
			newIP = true
		}
		now := time.Now()
		b.lan[srcMAC] = now
		delete(b.udp, srcMAC)

		multicast := dstMAC[0]&1 != 0
		dstOnLAN := b.isLANLocked(dstMAC)
		b.mu.Unlock()

		if newHost {
			b.logNewHost(b.lanName(), frame[6:12], ip, netip.Addr{})
		} else if newIP {
			b.logHostIP(b.lanName(), frame[6:12], ip, netip.Addr{})
		}

		// Standard Ethernet switch filtering:
		// If destination is unicast and known on the same port (LAN), filter (drop).
		if !multicast && dstOnLAN {
			continue
		}

		if err := b.UDP.WriteFrame(frame); err != nil {
			b.recordUDPTx(len(frame), 1, err)
			b.logger().Debug("sending to peers failed", "err", err)
		} else {
			b.recordUDPTx(len(frame), 1, nil)
		}
	}
}

func (b *Bridge) fromUDP(ctx context.Context) error {
	peers := map[netip.Addr]bool{}
	for {
		frame, from, err := b.UDP.ReadFrameFrom(ctx)
		if err != nil {
			if ctx.Err() == nil {
				b.mu.Lock()
				b.udpStats.errors++
				b.mu.Unlock()
			}
			return err
		}
		if len(frame) < link.HeaderLen {
			b.mu.Lock()
			b.udpStats.errors++
			b.mu.Unlock()
			continue
		}
		var dstMAC, srcMAC [6]byte
		copy(dstMAC[:], frame[0:6])
		copy(srcMAC[:], frame[6:12])

		// Drop invalid frames: multicast source, all-zero source, or loopback (src == dst).
		if srcMAC[0]&1 != 0 || srcMAC == [6]byte{} || srcMAC == dstMAC {
			b.mu.Lock()
			b.udpStats.errors++
			b.mu.Unlock()
			continue
		}

		peerIP := from.Addr()
		if !peers[peerIP] {
			peers[peerIP] = true
			b.logger().Info("new peer", "peer", peerIP.String(), "mac", net.HardwareAddr(frame[6:12]).String())
		}

		ip := findSourceIP(frame)

		var newHost, newIP bool
		b.mu.Lock()
		b.udpStats.rxPackets++
		b.udpStats.rxBytes += uint64(len(frame))
		if prevIP, ok := b.udpStats.hosts[srcMAC]; !ok {
			b.udpStats.hosts[srcMAC] = ip
			newHost = true
		} else if !prevIP.IsValid() && ip.IsValid() {
			b.udpStats.hosts[srcMAC] = ip
			newIP = true
		}
		now := time.Now()
		b.udp[srcMAC] = now
		delete(b.lan, srcMAC)

		multicast := dstMAC[0]&1 != 0
		dstOnLAN := b.isLANLocked(dstMAC)
		dstOnUDP := b.isUDPLocked(dstMAC)
		b.mu.Unlock()

		if newHost {
			b.logNewHost(b.udpName(), frame[6:12], ip, peerIP)
		} else if newIP {
			b.logHostIP(b.udpName(), frame[6:12], ip, peerIP)
		}

		// Standard Ethernet switch filtering:
		// - Multicast/broadcast: flood to both other UDP peers and LAN.
		// - Unicast known on LAN: forward ONLY to LAN.
		// - Unicast known on UDP: relay ONLY to other UDP peers.
		// - Unicast unknown: flood to BOTH.
		relayPeers := multicast || !dstOnLAN
		sendLAN := multicast || !dstOnUDP

		if relayPeers {
			if n, err := b.UDP.WriteFrameExcept(frame, from); err != nil {
				b.recordUDPTx(len(frame)*n, n, err)
				b.logger().Debug("relaying to peers failed", "err", err)
			} else {
				b.recordUDPTx(len(frame)*n, n, nil)
			}
		}
		if sendLAN {
			if err := b.LAN.WriteFrame(frame); err != nil {
				b.recordLANTx(len(frame), 1, err)
				b.logger().Warn("sending on the LAN failed", "err", err)
			} else {
				b.recordLANTx(len(frame), 1, nil)
			}
		}
	}
}
