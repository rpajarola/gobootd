// Package bridge connects an Ethernet segment to UDP peers that exchange
// frames in the HECnet bridge format, so that bootd, simh and QEMU can
// reach real machines without privileges of their own.
package bridge

import (
	"context"
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

// Bridge forwards frames between a LAN port and a UDP transport. Like a
// learning switch, it only forwards unicast frames to the side the
// destination was last seen on, so the UDP peers do not receive all of the
// LAN's traffic.
type Bridge struct {
	LAN link.Port
	UDP *link.UDP
	Log *slog.Logger

	mu  sync.Mutex
	lan map[[6]byte]time.Time
}

// Run forwards frames until ctx is done or a port fails.
func (b *Bridge) Run(ctx context.Context) error {
	b.lan = map[[6]byte]time.Time{}
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
	wg.Wait()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (b *Bridge) fromLAN(ctx context.Context) error {
	for {
		frame, err := b.LAN.ReadFrame(ctx)
		if err != nil {
			return err
		}
		if len(frame) < link.HeaderLen {
			continue
		}
		dst, src := net.HardwareAddr(frame[0:6]), net.HardwareAddr(frame[6:12])
		// Our own transmissions, captured again on platforms that cannot
		// capture only incoming frames.
		if b.UDP.Knows(src) {
			continue
		}
		b.mu.Lock()
		b.lan[[6]byte(src)] = time.Now()
		local := dst[0]&1 == 0 && time.Since(b.lan[[6]byte(dst)]) < lanTimeout
		b.mu.Unlock()
		if local {
			continue // between two machines on the LAN
		}
		if err := b.UDP.WriteFrame(frame); err != nil {
			b.Log.Debug("sending to peers failed", "err", err)
		}
	}
}

func (b *Bridge) fromUDP(ctx context.Context) error {
	peers := map[netip.AddrPort]bool{}
	for {
		frame, from, err := b.UDP.ReadFrameFrom(ctx)
		if err != nil {
			return err
		}
		if !peers[from] {
			peers[from] = true
			b.Log.Info("new peer", "peer", from.String(), "mac", net.HardwareAddr(frame[6:12]).String())
		}
		dst := net.HardwareAddr(frame[0:6])
		multicast := dst[0]&1 != 0
		if multicast || b.UDP.Knows(dst) {
			// Relay between peers.
			if err := b.UDP.WriteFrameExcept(frame, from); err != nil {
				b.Log.Debug("relaying to peers failed", "err", err)
			}
		}
		if multicast || !b.UDP.Knows(dst) {
			if err := b.LAN.WriteFrame(frame); err != nil {
				b.Log.Warn("sending on the LAN failed", "err", err)
			}
		}
	}
}
