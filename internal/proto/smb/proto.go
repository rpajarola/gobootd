package smb

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"syscall"
	"time"
)

// Commands.
const (
	cmdCreateDirectory    = 0x00
	cmdDeleteDirectory    = 0x01
	cmdOpen               = 0x02
	cmdCreate             = 0x03
	cmdClose              = 0x04
	cmdFlush              = 0x05
	cmdDelete             = 0x06
	cmdRename             = 0x07
	cmdQueryInformation   = 0x08
	cmdSetInformation     = 0x09
	cmdRead               = 0x0a
	cmdWrite              = 0x0b
	cmdLockByteRange      = 0x0c
	cmdUnlockByteRange    = 0x0d
	cmdCreateTemporary    = 0x0e
	cmdCreateNew          = 0x0f
	cmdCheckDirectory     = 0x10
	cmdProcessExit        = 0x11
	cmdSeek               = 0x12
	cmdLockAndRead        = 0x13
	cmdWriteAndUnlock     = 0x14
	cmdReadRaw            = 0x1a
	cmdWriteRaw           = 0x1d
	cmdSetInformation2    = 0x22
	cmdQueryInformation2  = 0x23
	cmdLockingAndX        = 0x24
	cmdTransaction        = 0x25
	cmdTransactionSec     = 0x26
	cmdEcho               = 0x2b
	cmdWriteAndClose      = 0x2c
	cmdOpenAndX           = 0x2d
	cmdReadAndX           = 0x2e
	cmdWriteAndX          = 0x2f
	cmdTransaction2       = 0x32
	cmdTransaction2Sec    = 0x33
	cmdFindClose2         = 0x34
	cmdTreeConnect        = 0x70
	cmdTreeDisconnect     = 0x71
	cmdNegotiate          = 0x72
	cmdSessionSetupAndX   = 0x73
	cmdLogoffAndX         = 0x74
	cmdTreeConnectAndX    = 0x75
	cmdQueryInformationDk = 0x80
	cmdSearch             = 0x81
	cmdFind               = 0x82
	cmdFindUnique         = 0x83
	cmdFindClose          = 0x84
	cmdNone               = 0xff
)

// andX reports whether a command's words start with an AndX header.
func andX(cmd byte) bool {
	switch cmd {
	case cmdLockingAndX, cmdOpenAndX, cmdReadAndX, cmdWriteAndX, cmdSessionSetupAndX, cmdLogoffAndX, cmdTreeConnectAndX:
		return true
	}
	return false
}

// Header layout.
const (
	hdrLen       = 32
	offCommand   = 4
	offClass     = 5
	offError     = 7
	offFlags     = 9
	offFlags2    = 10
	offTID       = 24
	offPID       = 26
	offUID       = 28
	offMID       = 30
	flagReply    = 0x80
	flagCaseless = 0x08
	// flags2LongNames is set by clients that understand names that
	// are not 8.3.
	flags2LongNames = 0x0001
)

// File attributes.
const (
	attrReadOnly  = 0x01
	attrHidden    = 0x02
	attrSystem    = 0x04
	attrVolume    = 0x08
	attrDirectory = 0x10
	attrArchive   = 0x20
)

// smbError is an error in DOS error classes, which every dialect here
// uses.
type smbError struct {
	class byte
	code  uint16
}

func (e smbError) Error() string { return fmt.Sprintf("SMB error %d/%d", e.class, e.code) }

const (
	errDOS = 1
	errSRV = 2
	errHRD = 3
)

var (
	errBadFunc     = smbError{errDOS, 1}
	errBadFile     = smbError{errDOS, 2}
	errBadPath     = smbError{errDOS, 3}
	errNoFids      = smbError{errDOS, 4}
	errNoAccess    = smbError{errDOS, 5}
	errBadFid      = smbError{errDOS, 6}
	errBadAccess   = smbError{errDOS, 12}
	errRemoveCD    = smbError{errDOS, 16}
	errDiffDevice  = smbError{errDOS, 17}
	errNoFiles     = smbError{errDOS, 18}
	errNotSup      = smbError{errDOS, 50}
	errFileExists  = smbError{errDOS, 80}
	errBadLevel    = smbError{errDOS, 124}
	errSrvError    = smbError{errSRV, 1}
	errInvTID      = smbError{errSRV, 5}
	errInvNetName  = smbError{errSRV, 6}
	errInvDevice   = smbError{errSRV, 7}
	errSMBCmd      = smbError{errSRV, 64}
	errSrvNoSup    = smbError{errSRV, 0xffff}
	errBadData     = smbError{errDOS, 13}
	errDiskFull    = smbError{errHRD, 39}
	errWriteProt   = smbError{errHRD, 19}
	errGeneral     = smbError{errHRD, 31}
	errDirNotEmpty = smbError{errDOS, 145}
)

// toSMB maps a file system error to a DOS error.
func toSMB(err error) smbError {
	var e smbError
	switch {
	case errors.As(err, &e):
		return e
	case errors.Is(err, fs.ErrNotExist):
		return errBadFile
	case errors.Is(err, fs.ErrExist):
		return errFileExists
	case errors.Is(err, fs.ErrPermission), errors.Is(err, syscall.EROFS):
		return errNoAccess
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return errDiskFull
	case errors.Is(err, syscall.ENOTEMPTY), errors.Is(err, syscall.EEXIST):
		return errNoAccess
	case errors.Is(err, syscall.ENOTDIR):
		return errBadPath
	case errors.Is(err, syscall.EXDEV):
		return errDiffDevice
	case errors.Is(err, os.ErrClosed):
		return errBadFid
	}
	return errGeneral
}

var le = binary.LittleEndian

// request is one command of a message: the words and bytes of the block
// at off.
type request struct {
	msg    []byte
	cmd    byte
	off    int // offset of the block's word count
	words  []byte
	data   []byte
	tid    uint16
	pid    uint16
	uid    uint16
	mid    uint16
	flags2 uint16
	// chained is set for the commands after the first of a message.
	chained bool
}

// parseBlock parses the block of cmd at off in msg.
func parseBlock(msg []byte, cmd byte, off int) (*request, error) {
	if off >= len(msg) {
		return nil, errBadData
	}
	wc := int(msg[off])
	if off+1+2*wc+2 > len(msg) {
		return nil, errBadData
	}
	words := msg[off+1 : off+1+2*wc]
	bc := int(le.Uint16(msg[off+1+2*wc:]))
	start := off + 1 + 2*wc + 2
	end := min(start+bc, len(msg))
	return &request{
		msg: msg, cmd: cmd, off: off, words: words, data: msg[start:end],
		tid: le.Uint16(msg[offTID:]), pid: le.Uint16(msg[offPID:]), uid: le.Uint16(msg[offUID:]),
		mid: le.Uint16(msg[offMID:]), flags2: le.Uint16(msg[offFlags2:]),
	}, nil
}

// word returns word i, or 0 past the end.
func (r *request) word(i int) uint16 {
	if 2*i+2 > len(r.words) {
		return 0
	}
	return le.Uint16(r.words[2*i:])
}

// dword returns the 32-bit value at word i.
func (r *request) dword(i int) uint32 {
	return uint32(r.word(i)) | uint32(r.word(i+1))<<16
}

func (r *request) longNames() bool { return r.flags2&flags2LongNames != 0 }

// reply is the response block to a command.
type reply struct {
	base  int // offset of the block's word count in the message
	words []byte
	data  []byte
	// noReply suppresses the response, for commands that have none.
	noReply bool
	// raw is sent as is instead of an SMB, for READ_RAW.
	raw []byte
	// trans is the result of a transaction, which may take several
	// responses.
	trans *transResult
}

func (rp *reply) w16(v uint16) { rp.words = le.AppendUint16(rp.words, v) }
func (rp *reply) w32(v uint32) { rp.words = le.AppendUint32(rp.words, v) }
func (rp *reply) zero(n int)   { rp.words = append(rp.words, make([]byte, n)...) }

// andx reserves the AndX header, which the dispatcher fills in.
func (rp *reply) andx() { rp.zero(4) }

func (rp *reply) b8(v byte)    { rp.data = append(rp.data, v) }
func (rp *reply) b16(v uint16) { rp.data = le.AppendUint16(rp.data, v) }
func (rp *reply) b32(v uint32) { rp.data = le.AppendUint32(rp.data, v) }

// str appends a null-terminated string.
func (rp *reply) str(s string) { rp.data = append(append(rp.data, s...), 0) }

// dataOffset is the offset in the message of the reply's data, given the
// words it will have.
func (rp *reply) dataOffset(words int) int { return rp.base + 1 + 2*words + 2 }

// cstring reads a null-terminated string from b and returns the rest.
func cstring(b []byte) (string, []byte) {
	for i, c := range b {
		if c == 0 {
			return string(b[:i]), b[i+1:]
		}
	}
	return string(b), nil
}

// bufferString reads a string with a buffer format byte, as core commands
// send them: 0x04 for an ASCII string (0x02 for dialects, 0x03 for
// pathnames in some clients).
func bufferString(b []byte) (string, []byte, bool) {
	if len(b) == 0 || (b[0] != 0x04 && b[0] != 0x03 && b[0] != 0x02) {
		return "", b, false
	}
	s, rest := cstring(b[1:])
	return s, rest, true
}

// DOS dates and times are local, with two-second resolution.

func dosDateTime(t time.Time) (date, tm uint16) {
	t = t.Local()
	if t.Year() < 1980 {
		return 1<<5 | 1, 0
	}
	if t.Year() > 2107 {
		t = time.Date(2107, 12, 31, 23, 59, 58, 0, time.Local)
	}
	date = uint16(t.Year()-1980)<<9 | uint16(t.Month())<<5 | uint16(t.Day())
	tm = uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2)
	return date, tm
}

func fromDOS(date, tm uint16) time.Time {
	if date == 0 && tm == 0 {
		return time.Time{}
	}
	return time.Date(int(date>>9)+1980, time.Month(date>>5&0x0f), int(date&0x1f),
		int(tm>>11), int(tm>>5&0x3f), int(tm&0x1f)*2, 0, time.Local)
}

// utime is the 32-bit time of core commands: seconds since 1970 in local
// time.
func utime(t time.Time) uint32 {
	if t.IsZero() {
		return 0
	}
	_, off := t.Zone()
	return uint32(max(t.Unix()+int64(off), 0))
}

func fromUtime(u uint32) time.Time {
	if u == 0 || u == 0xffffffff {
		return time.Time{}
	}
	t := time.Unix(int64(u), 0)
	_, off := t.Zone()
	return time.Unix(int64(u)-int64(off), 0)
}
