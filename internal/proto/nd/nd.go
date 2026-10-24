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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rpajarola/gobootd/internal/config"
	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.ND, func() daemon.Service { return &Server{} }) }

// Match selects ND packets.
func Match(f link.Frame) bool {
	return f.Type == link.TypeIPv4 && len(f.Payload) >= 20 && f.Payload[9] == IPProto
}

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

	mu     sync.Mutex
	writes map[writeKey]*pendingWrite
}

// writeKey identifies a client's write request.
type writeKey struct {
	client string // MAC address
	seq    int32
}

// pendingWrite collects the data of a write request until it is complete.
type pendingWrite struct {
	disk  *inventory.Disk
	block int32
	buf   []byte
	have  int32 // bytes received, in order
	done  bool  // written to disk
	err   error
	seen  time.Time
}

// writeTimeout drops write requests the client stopped sending, and
// forgets completed ones.
const writeTimeout = 30 * time.Second

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	s.setup()
	ports, err := env.Subscribe(Match)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "network", p.Interface().Name)
	}
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(ctx, env, p, frame) })
}

// setup applies option defaults.
func (s *Server) setup() {
	s.writes = map[writeKey]*pendingWrite{}
	if s.opts.Window <= 0 {
		s.opts.Window = 6
	}
	if s.opts.SendDelay == nil {
		d := 10
		s.opts.SendDelay = &d
	}
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
	log := env.Log.With("network", iface.Name, "client", f.Src.String())
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
	// Until its address is configured, a Sun sends from a temporary
	// address on network 0 (made of its MAC address or serial number),
	// and its first request goes to 0.0.0.0.
	if ip.dst != netip.IPv4Unspecified() {
		if ip.dst != server {
			return // for another server
		}
		if ip.src != h.IP && !temporary.Contains(ip.src) {
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
	// Replies go to the host's address, as from Sun's server: a client
	// still on its temporary address takes any destination, and learns
	// its address and the server's from the first reply.
	to := destination{port: port, mac: f.Src, server: server, client: h.IP}
	if req.Op&opMask == OpRead && req.Block == sizeBlock && req.Count == 4 {
		s.size(ctx, log, to, h, disk, req)
		return
	}
	if req.Op&opMask == OpWrite {
		s.write(ctx, log, to, h, disk, req)
		return
	}
	data, err := read(disk, req.Block, req.Offset, req.PacketCount)
	if err != nil {
		log.Warn(fmt.Sprintf("nd read of %s by %s failed (%v)", disk.MinorName(), h.Name, err), "block", req.Block)
		s.sendError(ctx, log, to, req, err)
		return
	}
	lvl := slog.LevelDebug
	if req.Block == 0 && req.Offset == 0 {
		lvl = slog.LevelInfo
	}
	log.Log(ctx, lvl, fmt.Sprintf("nd read by %s from disk %s", h.Name, disk.Name),
		"block", req.Block, "offset", req.Offset, "bytes", req.PacketCount, "ip", h.IP)
	s.reply(ctx, log, to, req, data)
}

// temporary is the network of the addresses Sun ROMs and kernels use until
// they know theirs.
var temporary = netip.MustParsePrefix("0.0.0.0/8")

// sizeBlock is the block number the SunOS kernel reads 4 bytes from to
// learn the size of a unit, e.g. for swap.
const sizeBlock = 0x10000000

// size answers a size query with the unit's size in blocks.
func (s *Server) size(ctx context.Context, log *slog.Logger, to destination, h *inventory.Host, d *inventory.Disk, req Packet) {
	size, err := diskSize(d)
	if err != nil {
		log.Warn(fmt.Sprintf("nd size of %s for %s failed (%v)", d.MinorName(), h.Name, err))
		s.sendError(ctx, log, to, req, err)
		return
	}
	log.Info(fmt.Sprintf("nd size of %s for %s: %d blocks", d.MinorName(), h.Name, size/BlockSize))
	p := req
	p.Op = OpRead | FlagDone | FlagWait
	p.PacketCount = 4
	p.Data = binary.BigEndian.AppendUint32(nil, uint32(size/BlockSize))
	s.send(ctx, log, to, p)
}

// diskSize returns the size of a disk in bytes.
func diskSize(d *inventory.Disk) (int64, error) {
	if d.Size > 0 {
		return d.Size, nil
	}
	st, err := os.Stat(d.Path)
	if err != nil {
		return 0, err
	}
	return st.Size() - d.Offset, nil
}

// destination is where replies to a request go.
type destination struct {
	port           link.Port
	mac            net.HardwareAddr
	server, client netip.Addr
}

// send sends one ND packet after the configured delay.
func (s *Server) send(ctx context.Context, log *slog.Logger, to destination, p Packet) bool {
	pkt := buildIPv4(uint16(s.ipID.Add(1)), to.server, to.client, IPProto, p.marshal())
	if d := *s.opts.SendDelay; d > 0 {
		select {
		case <-time.After(time.Duration(d) * time.Millisecond):
		case <-ctx.Done():
			return false
		}
	}
	if err := to.port.WriteFrame(link.Build(to.mac, to.port.Interface().MAC, link.TypeIPv4, pkt)); err != nil {
		log.Warn("sending reply failed", "err", err)
		return false
	}
	log.Debug("sent", "packet", p)
	return true
}

// sendError answers a request with an I/O error. Unlike other replies, an
// error has no DONE flag: SunOS takes a DONE packet for data.
func (s *Server) sendError(ctx context.Context, log *slog.Logger, to destination, req Packet, err error) {
	p := req
	p.Op = OpError
	p.Error = errEIO
	if errors.Is(err, errRange) {
		p.Error = errENXIO
	}
	p.PacketCount, p.Data = 0, nil
	s.send(ctx, log, to, p)
}

// Errors as the client's errno.
const (
	errEIO   = 5
	errENXIO = 6
	errEROFS = 30
)

var errRange = errors.New("beyond the end of the disk")

// write collects the packets of a write request. The client sends a window
// of packets and waits; we answer with the offset of the data we need next,
// or with the count once the data is on disk.
func (s *Server) write(ctx context.Context, log *slog.Logger, to destination, h *inventory.Host, d *inventory.Disk, req Packet) {
	if !d.Writable {
		log.Info(fmt.Sprintf("nd write by %s to %s refused (read only)", h.Name, d.MinorName()), "block", req.Block)
		p := req
		p.Op, p.Error, p.PacketCount, p.Data = OpError, errEROFS, 0, nil
		s.send(ctx, log, to, p)
		return
	}
	now := time.Now()
	key := writeKey{to.mac.String(), req.Seq}
	s.mu.Lock()
	for k, w := range s.writes {
		if now.Sub(w.seen) > writeTimeout {
			delete(s.writes, k)
		}
	}
	w := s.writes[key]
	if w == nil || w.block != req.Block || int32(len(w.buf)) != req.Count || w.disk != d {
		w = &pendingWrite{disk: d, block: req.Block, buf: make([]byte, req.Count)}
		s.writes[key] = w
	}
	w.seen = now
	if !w.done && req.Offset == w.have {
		n := min(int32(len(req.Data)), req.PacketCount, req.Count-w.have)
		copy(w.buf[w.have:], req.Data[:n])
		w.have += n
	}
	completed := false
	if !w.done && w.have == int32(len(w.buf)) {
		w.done, completed = true, true
		w.err = writeDisk(d, w.block, w.buf)
		lvl := slog.LevelDebug
		if w.err != nil {
			lvl = slog.LevelWarn
		}
		log.Log(ctx, lvl, fmt.Sprintf("nd write by %s to %s", h.Name, d.MinorName()), "block", w.block, "bytes", len(w.buf), "err", w.err)
	}
	done, have, werr := w.done, w.have, w.err
	s.mu.Unlock()

	p := req
	p.PacketCount, p.Data = 0, nil
	waiting := req.Op&FlagWait != 0
	switch {
	case done && !completed && !waiting:
		// More packets of a request we already finished.
	case done && werr != nil:
		s.sendError(ctx, log, to, req, werr)
	case done:
		p.Op = OpWrite | FlagDone | FlagWait
		p.Offset = req.Count
		s.send(ctx, log, to, p)
	case waiting:
		// The client sent a window and waits: ask for what is missing.
		p.Op = OpWrite | FlagDone | FlagWait
		p.Offset = have
		p.PacketCount = min(req.Count-have, int32(s.opts.Window)*maxData)
		s.send(ctx, log, to, p)
	}
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
	case req.Op&opMask != OpRead && req.Op&opMask != OpWrite:
		return fmt.Sprintf("bad op %#x", req.Op)
	case req.DiskVersion != 0:
		return fmt.Sprintf("disk version %d", req.DiskVersion)
	case req.Block < 0:
		return "negative block number"
	case req.Count <= 0 || req.Count > maxCount:
		return fmt.Sprintf("bad byte count %d", req.Count)
	case req.Offset < 0 || req.Offset > req.Count || req.Offset == req.Count && req.Op&opMask == OpRead:
		// A write status request may point past the data it sent.
		return fmt.Sprintf("bad offset %d", req.Offset)
	case req.PacketCount < 0 || req.PacketCount > req.Count-req.Offset:
		return fmt.Sprintf("bad count %d", req.PacketCount)
	}
	if req.Op&opMask == OpWrite {
		if int(req.PacketCount) > len(req.Data) {
			return fmt.Sprintf("write packet with %d of %d bytes", len(req.Data), req.PacketCount)
		}
		return ""
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
		if d.Size > 0 && start+int64(n) > d.Size {
			return nil, errRange
		}
		if err := readAt(d.Path, buf, d.Offset+start, -1); err != nil {
			return nil, err
		}
		if d.Boot != "" {
			// Blocks 1-15 are the boot program, the PROM loads it.
			clear(overlap(buf, start, boot1Block*BlockSize, boot2Block*BlockSize))
			if err := readRegion(d.Boot, buf, start, boot1Block*BlockSize, boot2Block*BlockSize); err != nil {
				return nil, err
			}
		}
		return buf, nil
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
func (s *Server) reply(ctx context.Context, log *slog.Logger, to destination, req Packet, data []byte) {
	p := req
	for sent := 0; ; sent++ {
		n := min(int32(len(data)), maxData)
		p.PacketCount = n
		p.Data = data[:n]
		p.Op = OpRead | FlagDone
		if p.Offset+n == req.Count || sent+1 == s.opts.Window {
			p.Op |= FlagWait
		}
		if !s.send(ctx, log, to, p) {
			return
		}
		if p.Op&FlagWait != 0 || int(n) == len(data) {
			return
		}
		data = data[n:]
		p.Offset += n
	}
}

// overlap returns the part of buf, which starts at disk offset start, that
// lies in [from, to).
func overlap(buf []byte, start, from, to int64) []byte {
	lo, hi := max(start, from), min(start+int64(len(buf)), to)
	if lo >= hi {
		return nil
	}
	return buf[lo-start : hi-start]
}

// writeDisk writes data at block of an image disk.
func writeDisk(d *inventory.Disk, block int32, data []byte) error {
	start := int64(block) * BlockSize
	if d.Size > 0 && start+int64(len(data)) > d.Size {
		return errRange
	}
	f, err := os.OpenFile(d.Path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	if _, err := f.WriteAt(data, d.Offset+start); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
