// Package tftp implements a read-only TFTP server (RFC 1350) with the
// blksize, tsize and timeout options (RFC 2347, 2348, 2349).
//
// Clients are identified by their IP address and may only read the files
// configured for them. Requests sent to a broadcast address, as some boot
// PROMs do, are answered from this server's address on the client's
// subnet, and refused silently so other servers can answer.
package tftp

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
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.TFTP, func() daemon.Service { return &Server{} }) }

// Options are the settings in the tftp service block.
type Options struct {
	// Timeout is the retransmission timeout in seconds, unless the client
	// asks for another one. Default 2.
	Timeout int `hcl:"timeout,optional"`
	// Retries is how often a packet is sent before giving up. Default 5.
	Retries int `hcl:"retries,optional"`
	// MaxBlockSize caps the blksize option. The default 1468 keeps
	// packets within one Ethernet frame.
	MaxBlockSize int `hcl:"max_blksize,optional"`
}

const (
	defaultBlockSize = 512
	minBlockSize     = 8
	maxBlockSize     = 65464
)

// Server serves files over TFTP.
type Server struct {
	opts Options
	// listening is called with each listening address; for tests.
	listening func(net.Addr)
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	if s.opts.Timeout <= 0 {
		s.opts.Timeout = 2
	}
	if s.opts.Retries <= 0 {
		s.opts.Retries = 5
	}
	if s.opts.MaxBlockSize <= 0 {
		s.opts.MaxBlockSize = 1468
	}
	s.opts.MaxBlockSize = max(minBlockSize, min(s.opts.MaxBlockSize, maxBlockSize))

	addrs := env.Config.Listen
	if len(addrs) == 0 {
		addrs = []string{":69"}
	}
	var conns []*ipv4.PacketConn
	defer func() {
		for _, c := range conns {
			c.Close()
		}
	}()
	for _, a := range addrs {
		c, err := net.ListenPacket("udp4", a)
		if err != nil {
			return err
		}
		pc := ipv4.NewPacketConn(c)
		if err := pc.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true); err != nil {
			c.Close()
			return fmt.Errorf("%s: %w", a, err)
		}
		conns = append(conns, pc)
		env.Log.Info("listening", "addr", c.LocalAddr().String())
		if s.listening != nil {
			s.listening(c.LocalAddr())
		}
	}

	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var wg sync.WaitGroup
	for _, pc := range conns {
		wg.Go(func() {
			if err := s.serve(ctx, env, pc, &wg); err != nil && ctx.Err() == nil {
				cancel(err)
			}
		})
	}
	<-ctx.Done()
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	if err := context.Cause(ctx); !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func (s *Server) serve(ctx context.Context, env *daemon.Env, pc *ipv4.PacketConn, wg *sync.WaitGroup) error {
	buf := make([]byte, 65536)
	for {
		n, cm, src, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ua, ok := src.(*net.UDPAddr)
		if !ok {
			continue
		}
		client := ua.AddrPort()
		client = netip.AddrPortFrom(client.Addr().Unmap(), client.Port())
		req, err := parseRequest(buf[:n])
		log := env.Log.With("client", client.Addr().String())
		if err != nil {
			log.Debug("ignoring packet", "err", err)
			continue
		}
		local, broadcast := localAddr(cm, client.Addr())
		t := &transfer{
			s: s, env: env, log: log, req: req,
			client: client, local: local, broadcast: broadcast,
		}
		wg.Go(func() { t.run(ctx) })
	}
}

// localAddr returns the address to answer from, and whether the request
// was sent to a broadcast address rather than to this server.
func localAddr(cm *ipv4.ControlMessage, client netip.Addr) (netip.Addr, bool) {
	if cm == nil {
		return netip.Addr{}, false
	}
	dst, _ := netip.AddrFromSlice(cm.Dst)
	dst = dst.Unmap()
	if isLocal(dst) {
		return dst, false
	}
	ifi, err := net.InterfaceByIndex(cm.IfIndex)
	if err != nil {
		return netip.Addr{}, true
	}
	addrs, _ := ifi.Addrs()
	var first netip.Addr
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		p, ok := netip.AddrFromSlice(n.IP)
		if !ok || !p.Unmap().Is4() {
			continue
		}
		ones, _ := n.Mask.Size()
		if len(n.Mask) == net.IPv6len {
			ones -= 96
		}
		if netip.PrefixFrom(p.Unmap(), ones).Contains(client) {
			return p.Unmap(), true
		}
		if !first.IsValid() {
			first = p.Unmap()
		}
	}
	return first, true
}

func isLocal(ip netip.Addr) bool {
	if !ip.IsValid() || ip == netip.IPv4Unspecified() {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			if p, ok := netip.AddrFromSlice(n.IP); ok && p.Unmap() == ip {
				return true
			}
		}
	}
	return false
}

type transfer struct {
	s         *Server
	env       *daemon.Env
	log       *slog.Logger
	req       *request
	client    netip.AddrPort
	local     netip.Addr
	broadcast bool

	ctx     context.Context
	conn    *net.UDPConn
	timeout time.Duration
}

// deny logs why a request is refused and tells the client, unless the
// request was broadcast.
func (t *transfer) deny(code uint16, reason string) {
	t.log.Info(fmt.Sprintf("tftp request from %s for %q denied (%s)", t.who(), t.req.filename, reason))
	if t.broadcast {
		return
	}
	if err := t.open(); err == nil {
		t.conn.Write(errorPacket(code, reason))
		t.conn.Close()
	}
}

func (t *transfer) who() string {
	if h, err := t.env.Inventory().ByIP(t.client.Addr()); err == nil {
		return h.Name
	}
	return t.client.Addr().String()
}

// open creates the socket for the transfer, with a new port.
func (t *transfer) open() error {
	var laddr *net.UDPAddr
	if t.local.IsValid() {
		laddr = net.UDPAddrFromAddrPort(netip.AddrPortFrom(t.local, 0))
	}
	c, err := net.DialUDP("udp4", laddr, net.UDPAddrFromAddrPort(t.client))
	if err != nil {
		t.log.Warn("cannot open transfer socket", "err", err)
		return err
	}
	t.conn = c
	return nil
}

func (t *transfer) run(ctx context.Context) {
	t.ctx = ctx
	if t.req.op == opWRQ {
		t.deny(errAccess, "writing is not supported")
		return
	}
	h, err := t.env.Inventory().ByIP(t.client.Addr())
	if err != nil {
		t.deny(errAccess, err.Error())
		return
	}
	t.log = t.log.With("host", h.Name)
	if err := h.Allows(service.TFTP); err != nil {
		t.deny(errAccess, err.Error())
		return
	}
	if t.req.mode != "octet" && t.req.mode != "netascii" {
		t.deny(errIllegal, fmt.Sprintf("mode %q not supported", t.req.mode))
		return
	}
	file, how, err := h.FileIgnoringDir(service.TFTP, t.req.filename)
	if err != nil {
		t.deny(errNotFound, err.Error())
		return
	}
	f, err := os.Open(file.Path)
	if err != nil {
		t.log.Warn(fmt.Sprintf("tftp request from %s for %q failed (%v)", h.Name, t.req.filename, err))
		t.deny(errNotFound, "cannot open file")
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() {
		t.deny(errNotFound, "not a regular file")
		return
	}
	if err := t.open(); err != nil {
		return
	}
	defer t.conn.Close()
	stop := context.AfterFunc(ctx, func() { t.conn.SetDeadline(time.Now()) })
	defer stop()

	blksize, oack := t.negotiate(st.Size())
	t.log.Info(fmt.Sprintf("tftp request from %s for %q: sending %s", h.Name, t.req.filename, file.Path),
		"match", how.String(), "bytes", st.Size(), "blksize", blksize, "mode", t.req.mode, "broadcast", t.broadcast)

	var r io.Reader = f
	if t.req.mode == "netascii" {
		r = newNetascii(f)
	}
	start := time.Now()
	sent, err := t.send(r, blksize, oack)
	if err != nil {
		t.log.Warn(fmt.Sprintf("tftp transfer of %s to %s failed (%v)", file.Path, h.Name, err), "bytes", sent)
		return
	}
	t.log.Info(fmt.Sprintf("tftp transfer of %s to %s complete", file.Path, h.Name), "bytes", sent, "duration", time.Since(start).Round(time.Millisecond).String())
}

// negotiate applies the client's options and returns the block size and
// the OACK to send, or nil if no option was accepted.
func (t *transfer) negotiate(size int64) (int, []byte) {
	blksize := defaultBlockSize
	t.timeout = time.Duration(t.s.opts.Timeout) * time.Second
	var acked []option
	for _, o := range t.req.options {
		switch o.name {
		case "blksize":
			n, err := strconv.Atoi(o.value)
			if err != nil || n < minBlockSize {
				continue
			}
			blksize = min(n, t.s.opts.MaxBlockSize)
			acked = append(acked, option{o.name, strconv.Itoa(blksize)})
		case "tsize":
			if t.req.mode == "octet" {
				acked = append(acked, option{o.name, strconv.FormatInt(size, 10)})
			}
		case "timeout":
			n, err := strconv.Atoi(o.value)
			if err != nil || n < 1 || n > 255 {
				continue
			}
			t.timeout = time.Duration(n) * time.Second
			acked = append(acked, option{o.name, o.value})
		}
	}
	if acked == nil {
		return blksize, nil
	}
	return blksize, oackPacket(acked)
}

// send transfers r, starting with the OACK if there is one. It returns the
// number of data bytes sent.
func (t *transfer) send(r io.Reader, blksize int, oack []byte) (int64, error) {
	if oack != nil {
		if err := t.exchange(oack, 0); err != nil {
			return 0, err
		}
	}
	buf := make([]byte, blksize)
	var sent int64
	for block := uint16(1); ; block++ {
		n, err := io.ReadFull(r, buf)
		last := false
		switch {
		case err == io.EOF || err == io.ErrUnexpectedEOF:
			last = true
		case err != nil:
			t.conn.Write(errorPacket(errUndefined, "read error"))
			return sent, err
		}
		if err := t.exchange(dataPacket(block, buf[:n]), block); err != nil {
			return sent, err
		}
		sent += int64(n)
		if last {
			return sent, nil
		}
	}
}

// exchange sends pkt until the client acknowledges block.
func (t *transfer) exchange(pkt []byte, block uint16) error {
	ack := make([]byte, 1024)
	for try := 0; try < t.s.opts.Retries; try++ {
		if _, err := t.conn.Write(pkt); err != nil {
			return err
		}
		deadline := time.Now().Add(t.timeout)
		for {
			if err := t.ctx.Err(); err != nil {
				return err
			}
			t.conn.SetReadDeadline(deadline)
			n, err := t.conn.Read(ack)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && time.Now().After(deadline.Add(-time.Millisecond)) {
					break // retransmit
				}
				return err
			}
			if n < 4 {
				continue
			}
			switch binary.BigEndian.Uint16(ack) {
			case opACK:
				if binary.BigEndian.Uint16(ack[2:]) == block {
					return nil
				}
				// A duplicate ACK for an earlier block: ignore it
				// rather than resend (Sorcerer's Apprentice).
			case opERROR:
				msg := strings.TrimRight(string(ack[4:n]), "\x00")
				return fmt.Errorf("client sent error %d: %s", binary.BigEndian.Uint16(ack[2:]), msg)
			}
		}
		t.log.Debug("timeout, retransmitting", "block", block, "try", try+1)
	}
	return fmt.Errorf("no acknowledgement for block %d after %d tries", block, t.s.opts.Retries)
}
