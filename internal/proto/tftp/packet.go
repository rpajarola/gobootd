package tftp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
)

// Opcodes.
const (
	opRRQ   = 1
	opWRQ   = 2
	opDATA  = 3
	opACK   = 4
	opERROR = 5
	opOACK  = 6
)

// Error codes.
const (
	errUndefined      = 0
	errNotFound       = 1
	errAccess         = 2
	errIllegal        = 4
	errUnknownID      = 5
	errOptionsRefused = 8
)

// request is a read or write request.
type request struct {
	op       uint16
	filename string
	mode     string
	// options in the order the client sent them, names in lower case.
	options []option
}

type option struct{ name, value string }

func parseRequest(b []byte) (*request, error) {
	if len(b) < 2 {
		return nil, errors.New("short packet")
	}
	r := &request{op: binary.BigEndian.Uint16(b)}
	if r.op != opRRQ && r.op != opWRQ {
		return nil, errors.New("not a request")
	}
	fields := bytes.Split(b[2:], []byte{0})
	// A well formed request ends in NUL, leaving an empty last field.
	if len(fields) < 3 || len(fields[len(fields)-1]) != 0 {
		return nil, errors.New("malformed request")
	}
	fields = fields[:len(fields)-1]
	r.filename = string(fields[0])
	r.mode = strings.ToLower(string(fields[1]))
	opts := fields[2:]
	// Some clients pad requests with NULs; ignore a trailing odd field.
	for i := 0; i+1 < len(opts); i += 2 {
		if len(opts[i]) == 0 {
			break
		}
		r.options = append(r.options, option{strings.ToLower(string(opts[i])), string(opts[i+1])})
	}
	return r, nil
}

func dataPacket(block uint16, data []byte) []byte {
	b := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint16(b, opDATA)
	binary.BigEndian.PutUint16(b[2:], block)
	return append(b, data...)
}

func errorPacket(code uint16, msg string) []byte {
	b := make([]byte, 4, 5+len(msg))
	binary.BigEndian.PutUint16(b, opERROR)
	binary.BigEndian.PutUint16(b[2:], code)
	b = append(b, msg...)
	return append(b, 0)
}

func oackPacket(opts []option) []byte {
	b := binary.BigEndian.AppendUint16(nil, opOACK)
	for _, o := range opts {
		b = append(b, o.name...)
		b = append(b, 0)
		b = append(b, o.value...)
		b = append(b, 0)
	}
	return b
}
