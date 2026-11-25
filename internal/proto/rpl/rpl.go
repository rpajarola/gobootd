// Package rpl implements IBM's Remote Program Load (RIPL), which the boot
// ROMs of PC network cards (IBM, 3Com, Intel, Realtek and others) use to
// load a boot image over 802.2 LLC.
//
// The protocol follows Linux's rpld. A client multicasts FIND to
// 03-00-02-00-00-00; servers that know it answer FOUND, and the client
// sends SEND.FILE.REQUEST to one of them. The server then streams the image
// in numbered FILE.DATA.RESPONSE frames, each with its load address, the
// last one with the flag to start the program. A client that misses a
// frame asks again from the block it is missing.
//
// A host's RPL files are loaded at their load addresses. A floppy image is
// loaded with a small loader (ramdisk.S) that makes it drive A: and boots
// it, so DOS starts without NetBEUI or a file server.
package rpl

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/rpajarola/gobootd/internal/daemon"
	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/service"
)

func init() { daemon.Register(service.RPL, func() daemon.Service { return &Server{} }) }

const (
	// blockSize is the most data in a block, a multiple of 8 as some
	// boot ROMs want.
	blockSize = 1440
	// overhead is what a block's frame needs besides its data, as rpld
	// reckons it.
	overhead = 0x30
	// maxFrame is the largest frame clients get.
	maxFrame = 1500
)

// Options are the settings in the rpl service block.
type Options struct {
	// SendDelay is the pause before each block in milliseconds: RPL
	// sends the whole image without waiting for the client.
	SendDelay *int `hcl:"send_delay,optional"`
}

// Server loads boot images over RPL.
type Server struct {
	opts Options
	ctx  context.Context

	mu      sync.Mutex
	streams map[string]*stream // by client MAC
}

// stream is a transfer in progress.
type stream struct {
	cancel context.CancelFunc
}

// Options implements daemon.Configurable.
func (s *Server) Options() any { return &s.opts }

// Run implements daemon.Service.
func (s *Server) Run(ctx context.Context, env *daemon.Env) error {
	s.setup(ctx)
	ports, err := env.Subscribe(Match)
	if err != nil {
		return err
	}
	for _, p := range ports {
		env.Log.Info("listening", "network", p.Interface().Name, "send_delay", *s.opts.SendDelay)
	}
	return link.Serve(ctx, ports, func(p link.Port, frame []byte) { s.handle(env, p, frame) })
}

func (s *Server) setup(ctx context.Context) {
	if s.opts.SendDelay == nil {
		d := 10
		s.opts.SendDelay = &d
	}
	s.ctx = ctx
	s.streams = map[string]*stream{}
}

func (s *Server) handle(env *daemon.Env, port link.Port, frame []byte) {
	iface := port.Interface()
	f, ok := link.Parse(frame)
	if !ok || !Match(f) || string(f.Src) == string(iface.MAC) {
		return
	}
	mcast := string(f.Dst) == string(Multicast)
	if !mcast && string(f.Dst) != string(iface.MAC) {
		return // for another server
	}
	p, ok := parse(f.Payload)
	if !ok {
		return
	}
	log := env.Log.With("network", iface.Name, "client", f.Src.String())
	switch p.Cmd {
	case cmdFind:
		log.Info("received", "packet", p.LogValue())
		s.find(env, log, port, f.Src, p)
	case cmdSendFile:
		if mcast {
			return
		}
		lvl := slog.LevelInfo
		if p.Sequence != 0 {
			lvl = slog.LevelDebug
		}
		log.Log(context.Background(), lvl, "received", "packet", p.LogValue())
		s.sendFile(env, log, port, f.Src, p)
	default:
		log.Debug("ignoring frame", "packet", p.LogValue())
	}
}

// find answers clients that may load an image.
func (s *Server) find(env *daemon.Env, log *slog.Logger, port link.Port, client net.HardwareAddr, p packet) {
	h, err := env.Inventory().ByMAC(client)
	if err != nil {
		log.Info(fmt.Sprintf("rpl request from %s denied (%v)", client, err))
		return
	}
	log = log.With("host", h.Name)
	if err := h.Allows(service.RPL); err != nil {
		log.Info(fmt.Sprintf("rpl request from %s denied (%v)", h.Name, err))
		return
	}
	plan, err := MakePlan(h)
	if err != nil {
		log.Warn(fmt.Sprintf("rpl request from %s failed (%v)", h.Name, err))
		return
	}
	fl := maxFrame
	if p.FrameLen > 0 {
		fl = min(fl, p.FrameLen)
	}
	s.send(log, port, client, found(p.Correlator, client, port.Interface().MAC, fl))
	log.Info(fmt.Sprintf("rpl request from %s: offering %s", h.Name, plan))
}

// sendFile starts sending the image from the requested block, stopping a
// transfer to the client that is still running.
func (s *Server) sendFile(env *daemon.Env, log *slog.Logger, port link.Port, client net.HardwareAddr, p packet) {
	h, err := env.Inventory().ByMAC(client)
	if err != nil {
		log.Info(fmt.Sprintf("rpl request from %s denied (%v)", client, err))
		return
	}
	log = log.With("host", h.Name)
	if err := h.Allows(service.RPL); err != nil {
		log.Info(fmt.Sprintf("rpl request from %s denied (%v)", h.Name, err))
		return
	}
	plan, err := MakePlan(h)
	if err != nil {
		log.Warn(fmt.Sprintf("rpl request from %s failed (%v)", h.Name, err))
		return
	}
	bs := blockSize
	if p.FrameLen > 0 && bs+overhead > p.FrameLen {
		bs = max(64, (p.FrameLen-overhead)&^7)
	}
	total := plan.total(bs)
	if p.Sequence >= total {
		log.Info(fmt.Sprintf("rpl request from %s for block %d ignored (the image has %d)", h.Name, p.Sequence, total))
		return
	}
	im, err := plan.open()
	if err != nil {
		log.Warn(fmt.Sprintf("rpl request from %s failed (%v)", h.Name, err))
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	st := &stream{cancel: cancel}
	key := client.String()
	s.mu.Lock()
	if old, ok := s.streams[key]; ok {
		old.cancel()
	}
	s.streams[key] = st
	s.mu.Unlock()
	if p.Sequence == 0 {
		log.Info(fmt.Sprintf("rpl request from %s: sending %s", h.Name, plan), "blocks", total, "block_size", bs)
	} else {
		log.Debug("resending", "from", p.Sequence)
	}
	go func() {
		defer im.Close()
		defer func() {
			s.mu.Lock()
			if s.streams[key] == st {
				delete(s.streams, key)
			}
			s.mu.Unlock()
			cancel()
		}()
		delay := time.Duration(*s.opts.SendDelay) * time.Millisecond
		for n := p.Sequence; n < total; n++ {
			load, data, err := im.block(n, bs)
			if err != nil {
				log.Warn(fmt.Sprintf("rpl transfer to %s failed (%v)", h.Name, err))
				return
			}
			flags := byte(flagMore)
			if n == total-1 {
				flags = flagLast
			}
			if delay > 0 {
				select {
				case <-time.After(delay):
				case <-ctx.Done():
					return
				}
			} else if ctx.Err() != nil {
				return
			}
			s.send(log, port, client, fileData(n, load, plan.exec, flags, data))
			log.Log(ctx, slog.LevelDebug-1, "sent", "block", n, "load", fmt.Sprintf("%#x", load))
		}
		log.Info(fmt.Sprintf("rpl transfer to %s sent", h.Name), "blocks", total-p.Sequence, "start", fmt.Sprintf("%#x", plan.exec))
	}()
}

func (s *Server) send(log *slog.Logger, port link.Port, dst net.HardwareAddr, payload []byte) {
	if err := port.WriteFrame(link.Pad(link.Build8023(dst, port.Interface().MAC, payload))); err != nil {
		log.Warn("sending reply failed", "err", err)
	}
}
