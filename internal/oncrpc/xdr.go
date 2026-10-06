// Package oncrpc implements ONC RPC (RFC 5531) over bootd's IP stack, with
// the XDR encoding (RFC 4506) and a built-in portmapper (RFC 1833,
// version 2). It is the base for bootparam, MOUNT and NFS.
package oncrpc

import (
	"encoding/binary"
	"errors"
)

// ErrShort is returned when a message ends early or a length is too big.
var ErrShort = errors.New("xdr: short or malformed data")

// Decoder reads XDR data. The first error sticks; check Err after
// decoding.
type Decoder struct {
	b   []byte
	err error
}

// NewDecoder returns a decoder for b.
func NewDecoder(b []byte) *Decoder { return &Decoder{b: b} }

// Err returns the first decoding error.
func (d *Decoder) Err() error { return d.err }

// Rest returns the undecoded bytes.
func (d *Decoder) Rest() []byte { return d.b }

func (d *Decoder) take(n int) []byte {
	if d.err != nil {
		return nil
	}
	if n < 0 || n > len(d.b) {
		d.err = ErrShort
		d.b = nil
		return nil
	}
	b := d.b[:n]
	d.b = d.b[n:]
	return b
}

// Uint32 decodes an unsigned int.
func (d *Decoder) Uint32() uint32 {
	b := d.take(4)
	if b == nil {
		return 0
	}
	return binary.BigEndian.Uint32(b)
}

// Int32 decodes an int.
func (d *Decoder) Int32() int32 { return int32(d.Uint32()) }

// Uint64 decodes an unsigned hyper.
func (d *Decoder) Uint64() uint64 { return uint64(d.Uint32())<<32 | uint64(d.Uint32()) }

// Bool decodes a bool.
func (d *Decoder) Bool() bool { return d.Uint32() != 0 }

// Fixed decodes fixed-length opaque data of n bytes.
func (d *Decoder) Fixed(n int) []byte {
	b := d.take(n)
	d.take(pad(n))
	return b
}

// Opaque decodes variable-length opaque data of at most max bytes.
func (d *Decoder) Opaque(max int) []byte {
	n := d.Uint32()
	if d.err == nil && n > uint32(max) {
		d.err = ErrShort
		return nil
	}
	return d.Fixed(int(n))
}

// String decodes a string of at most max bytes.
func (d *Decoder) String(max int) string { return string(d.Opaque(max)) }

func pad(n int) int { return (4 - n%4) % 4 }

// Encoder builds XDR data.
type Encoder struct{ b []byte }

// Bytes returns the encoded data.
func (e *Encoder) Bytes() []byte { return e.b }

// Uint32 encodes an unsigned int.
func (e *Encoder) Uint32(v uint32) *Encoder {
	e.b = binary.BigEndian.AppendUint32(e.b, v)
	return e
}

// Int32 encodes an int.
func (e *Encoder) Int32(v int32) *Encoder { return e.Uint32(uint32(v)) }

// Uint64 encodes an unsigned hyper.
func (e *Encoder) Uint64(v uint64) *Encoder { return e.Uint32(uint32(v >> 32)).Uint32(uint32(v)) }

// Bool encodes a bool.
func (e *Encoder) Bool(v bool) *Encoder {
	if v {
		return e.Uint32(1)
	}
	return e.Uint32(0)
}

// Fixed encodes fixed-length opaque data.
func (e *Encoder) Fixed(b []byte) *Encoder {
	e.b = append(e.b, b...)
	e.b = append(e.b, make([]byte, pad(len(b)))...)
	return e
}

// Opaque encodes variable-length opaque data.
func (e *Encoder) Opaque(b []byte) *Encoder { return e.Uint32(uint32(len(b))).Fixed(b) }

// String encodes a string.
func (e *Encoder) String(s string) *Encoder { return e.Opaque([]byte(s)) }

// Raw appends already encoded data.
func (e *Encoder) Raw(b []byte) *Encoder {
	e.b = append(e.b, b...)
	return e
}
