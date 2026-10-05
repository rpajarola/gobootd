// Package nd implements Sun's Network Disk protocol, which Sun-2 boot PROMs
// use to read a boot program from a disk on the network.
//
// ND runs directly over IP (protocol 77). A Sun-2 PROM does not use RARP:
// it sends its first request to IP address 0 and learns its address from
// the reply. Frames are therefore sent and received on the link layer, and
// clients are identified by their Ethernet address.
//
// Disks in "bootfile" mode work like NetBSD's ndbootd: block 0 is an empty
// disk label, blocks 1-15 hold the first-stage boot program (the PROM
// loads blocks 0-15) and a second-stage program, if any, starts at block
// 16. Disks in "image" mode serve a disk image. Writes are not supported
// yet.
package nd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.ND, func() daemon.Service { return &Server{} }) }

// Filter selects ND packets.
const Filter = "ip proto 77"

// Bootfile disk layout.
const (
	boot1Block = 1
	boot2Block = 16
)

// Options are the settings in the nd service block.
type Options struct {
	// Window is the number of 1 KB packets sent before waiting for the
	// client to ask for more. Default 6.
	Window int `hcl:"window,optional"`
	// SendDelay is the pause before each packet in milliseconds, for
	// clients that cannot keep up. Default 10.
	SendDelay *int `hcl:"send_delay,optional"`
}

// Server serves disks over ND.
type Server struct {
	opts Options
	ipID atomic.Uint32
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.Window <= 0 {
		s.opts.Window = 6
	}
	if s.opts.SendDelay == nil {
		d := 10
		s.opts.SendDelay = &d
	}
	ports, err := link.OpenAll(env.Link, env.Config.Interfaces, Filter)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "interface", p.Interface().Name, "mac", p.Interface().MAC.String())
	}
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(ctx, env, p, frame) })
}

func (s *Server) handle(ctx context.Context, env *daemon.Env, port link.Port, frame []byte) {
	iface := port.Interface()
	f, ok := link.Parse(frame)
	if !ok || f.Type != link.TypeIPv4 || string(f.Src) == string(iface.MAC) {
		return
	}
	ip, ok := parseIPv4(f.Payload)
	if !ok || ip.proto != IPProto {
		return
	}
	req, ok := parsePacket(ip.payload)
	if !ok {
		return
	}
	log := env.Log.With("interface", iface.Name, "client", f.Src.String())
	log.Debug("received", "src", ip.src, "dst", ip.dst, "packet", req)

	h, err := env.Inventory().ByMAC(f.Src)
	if err != nil {
		log.Info(fmt.Sprintf("nd request from %s denied (%v)", f.Src, err))
		return
	}
	log = log.With("host", h.Name)
	if err := h.Allows(service.ND); err != nil {
		log.Info(fmt.Sprintf("nd request from %s denied (%v)", h.Name, err))
		return
	}
	if !h.IP.IsValid() {
		log.Info(fmt.Sprintf("nd request from %s denied (host has no IP address)", h.Name))
		return
	}
	server, ok := iface.AddrFor(h.IP)
	if !ok {
		log.Warn(fmt.Sprintf("nd request from %s not answered (interface %s has no IPv4 address)", h.Name, iface.Name))
		return
	}
	// A PROM that does not know its address yet sends to 0.0.0.0.
	if ip.dst != netip.IPv4Unspecified() {
		if ip.dst != server {
			return // for another server
		}
		if ip.src != h.IP {
			log.Info(fmt.Sprintf("nd request from %s denied (sent from %s, but its address is %s)", h.Name, ip.src, h.IP))
			return
		}
	}

	disk, err := findDisk(h, req.Minor)
	if err != nil {
		log.Info(fmt.Sprintf("nd request from %s denied (%v)", h.Name, err))
		return
	}
	if reason := check(&req); reason != "" {
		log.Info(fmt.Sprintf("nd request from %s ignored (%s)", h.Name, reason), "packet", req)
		return
	}
	data, err := read(disk, req.Block, req.Offset, req.PacketCount)
	if err != nil {
		log.Warn(fmt.Sprintf("nd read from %s for %s failed (%v)", disk.Path, h.Name, err))
		return
	}
	lvl := slog.LevelDebug
	if req.Block == 0 && req.Offset == 0 {
		lvl = slog.LevelInfo
	}
	log.Log(ctx, lvl, fmt.Sprintf("nd read by %s from disk %s", h.Name, disk.Name),
		"block", req.Block, "offset", req.Offset, "bytes", req.PacketCount, "ip", h.IP)
	s.reply(ctx, log, port, f.Src, server, h.IP, req, data)
}

// findDisk finds the disk for an ND minor device number. The minor is
// matched against the disk's unit; ndp0 (the PROM's boot device) also
// selects the first bootfile disk.
func findDisk(h *inventory.Host, minor uint8) (*inventory.Disk, error) {
	d, err := h.Disk(int(minor))
	if err == nil {
		return d, nil
	}
	if minor == MinorPublic {
		for _, d := range h.Disks {
			if d.Mode == config.DiskBootfile {
				return d, nil
			}
		}
	}
	return nil, err
}

// check validates a read request like ndbootd does, and fills in a zero
// packet count. It returns why the request is invalid, or "".
func check(req *Packet) string {
	switch {
	case req.Op&opMask == OpWrite:
		return "writing is not supported"
	case req.Op&opMask != OpRead:
		return fmt.Sprintf("bad op %#x", req.Op)
	case req.DiskVersion != 0:
		return fmt.Sprintf("disk version %d", req.DiskVersion)
	case req.Block < 0:
		return "negative block number"
	case req.Count <= 0 || req.Count > maxCount:
		return fmt.Sprintf("bad byte count %d", req.Count)
	case req.Offset < 0 || req.Offset >= req.Count:
		return fmt.Sprintf("bad offset %d", req.Offset)
	case req.PacketCount < 0 || req.PacketCount > req.Count-req.Offset:
		return fmt.Sprintf("bad count %d", req.PacketCount)
	}
	if req.PacketCount == 0 {
		req.PacketCount = req.Count - req.Offset
	}
	return ""
}

// read returns n bytes starting at offset bytes into block. Parts of the
// disk that hold no data read as zeros.
func read(d *inventory.Disk, block, offset, n int32) ([]byte, error) {
	buf := make([]byte, n)
	start := int64(block)*BlockSize + int64(offset)
	if d.Mode != config.DiskBootfile {
		return buf, readAt(d.Path, buf, start, -1)
	}
	// Bootfile disk: the label block stays zero.
	b1 := int64(boot1Block * BlockSize)
	b2 := int64(boot2Block * BlockSize)
	if err := readRegion(d.Path, buf, start, b1, b2); err != nil {
		return nil, err
	}
	if d.Boot2 != "" {
		if err := readRegion(d.Boot2, buf, start, b2, -1); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// readRegion copies the part of file that lies in the disk region
// [from, to) and overlaps the buffer at disk offset start. to < 0 means
// no end.
func readRegion(path string, buf []byte, start, from, to int64) error {
	end := start + int64(len(buf))
	lo, hi := max(start, from), end
	if to >= 0 {
		hi = min(end, to)
	}
	if lo >= hi {
		return nil
	}
	return readAt(path, buf[lo-start:hi-start], lo-from, to-from)
}

// readAt reads buf at off from path, leaving bytes past the end of the file
// zero. If limit >= 0, a file longer than limit bytes is an error.
func readAt(path string, buf []byte, off, limit int64) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if limit >= 0 {
		if st, err := f.Stat(); err == nil && st.Size() > limit {
			return fmt.Errorf("%s is %d bytes, but only %d fit before block %d", path, st.Size(), limit, boot2Block)
		}
	}
	if _, err := f.ReadAt(buf, off); err != nil && err != io.EOF {
		return err
	}
	return nil
}

// reply sends data in packets of up to 1 KB. The client acknowledges a
// window of packets by asking for the rest.
func (s *Server) reply(ctx context.Context, log *slog.Logger, port link.Port, mac []byte, server, client netip.Addr, req Packet, data []byte) {
	iface := port.Interface()
	p := req
	for sent := 0; ; sent++ {
		n := min(int32(len(data)), maxData)
		p.PacketCount = n
		p.Data = data[:n]
		p.Op = OpRead
		switch {
		case p.Offset+n == req.Count:
			p.Op |= FlagDone | FlagWait
		case sent+1 == s.opts.Window:
			p.Op |= FlagWait
		}
		pkt := buildIPv4(uint16(s.ipID.Add(1)), server, client, IPProto, p.marshal())
		if d := *s.opts.SendDelay; d > 0 {
			select {
			case <-time.After(time.Duration(d) * time.Millisecond):
			case <-ctx.Done():
				return
			}
		}
		if err := port.WriteFrame(link.Build(mac, iface.MAC, link.TypeIPv4, pkt)); err != nil {
			log.Warn("sending reply failed", "err", err)
			return
		}
		log.Debug("sent", "packet", p)
		if p.Op != OpRead || int(n) == len(data) {
			return
		}
		data = data[n:]
		p.Offset += n
	}
}
