package oncrpc

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/rpajarola/gobootd/internal/ipstack"
)

// EncodeCall builds a call message with AUTH_UNIX credentials for uid 0 if
// cred is nil, as boot clients send.
func EncodeCall(xid, prog, vers, proc uint32, cred *UnixCred, args []byte) []byte {
	if cred == nil {
		cred = &UnixCred{Machine: "client"}
	}
	ce := &Encoder{}
	ce.Uint32(cred.Stamp).String(cred.Machine).Uint32(cred.UID).Uint32(cred.GID).Uint32(uint32(len(cred.GIDs)))
	for _, g := range cred.GIDs {
		ce.Uint32(g)
	}
	e := &Encoder{}
	e.Uint32(xid).Uint32(msgCall).Uint32(rpcVersion).Uint32(prog).Uint32(vers).Uint32(proc)
	e.Uint32(AuthUnix).Opaque(ce.Bytes())
	e.Uint32(AuthNone).Opaque(nil)
	return e.Raw(args).Bytes()
}

// ReplyError is a reply that is not a success.
type ReplyError struct {
	Denied bool
	Stat   uint32
}

func (e *ReplyError) Error() string {
	if e.Denied {
		return fmt.Sprintf("rpc: call denied (%d)", e.Stat)
	}
	names := map[uint32]string{progUnavail: "program unavailable", progMismatch: "program version mismatch",
		procUnavail: "procedure unavailable", garbageArgs: "garbage arguments", systemErr: "system error"}
	return "rpc: " + names[e.Stat]
}

// DecodeReply decodes a reply message and returns its xid and results.
func DecodeReply(msg []byte) (xid uint32, res *Decoder, err error) {
	d := NewDecoder(msg)
	xid = d.Uint32()
	if d.Uint32() != msgReply {
		return xid, nil, errors.New("rpc: not a reply")
	}
	if d.Uint32() == replyDenied {
		return xid, nil, &ReplyError{Denied: true, Stat: d.Uint32()}
	}
	d.Uint32() // verifier
	d.Opaque(400)
	if stat := d.Uint32(); stat != success {
		return xid, nil, &ReplyError{Stat: stat}
	}
	if d.Err() != nil {
		return xid, nil, d.Err()
	}
	return xid, NewDecoder(d.Rest()), nil
}

// Client makes calls from a UDP listener, retrying until a reply with the
// call's xid arrives.
type Client struct {
	L       *ipstack.UDPListener
	Timeout time.Duration
	Tries   int
	xid     uint32
}

// Call calls proc at to and returns the results and the address the reply
// came from.
func (c *Client) Call(ctx context.Context, to netip.AddrPort, prog, vers, proc uint32, args []byte) (*Decoder, netip.AddrPort, error) {
	c.xid++
	msg := EncodeCall(c.xid, prog, vers, proc, nil, args)
	timeout, tries := c.Timeout, c.Tries
	if timeout == 0 {
		timeout = time.Second
	}
	if tries == 0 {
		tries = 3
	}
	for range tries {
		if err := c.L.WriteTo(msg, to); err != nil {
			return nil, netip.AddrPort{}, err
		}
		rctx, cancel := context.WithTimeout(ctx, timeout)
		for {
			dg, err := c.L.Read(rctx)
			if err != nil {
				break
			}
			xid, res, err := DecodeReply(dg.Data)
			if xid != c.xid {
				continue
			}
			cancel()
			return res, dg.From, err
		}
		cancel()
		if ctx.Err() != nil {
			return nil, netip.AddrPort{}, ctx.Err()
		}
	}
	return nil, netip.AddrPort{}, errors.New("rpc: no reply")
}
