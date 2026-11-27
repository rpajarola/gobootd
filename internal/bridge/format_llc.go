package bridge

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// LLC frames: the control field, and NetBEUI's NetBIOS frames on SAP F0.

var llcU = map[byte]string{
	0x03: "UI", 0x6f: "SABME", 0x63: "UA", 0x43: "DISC", 0x0f: "DM", 0x87: "FRMR", 0xaf: "XID", 0xe3: "TEST",
}

var llcS = map[byte]string{0x01: "RR", 0x05: "RNR", 0x09: "REJ"}

var nbfCommands = map[byte]string{
	0x00: "ADD_GROUP_NAME_QUERY", 0x01: "ADD_NAME_QUERY", 0x02: "NAME_IN_CONFLICT", 0x03: "STATUS_QUERY",
	0x08: "DATAGRAM", 0x09: "DATAGRAM_BROADCAST", 0x0a: "NAME_QUERY", 0x0d: "ADD_NAME_RESPONSE",
	0x0e: "NAME_RECOGNIZED", 0x0f: "STATUS_RESPONSE", 0x14: "DATA_ACK", 0x15: "DATA_FIRST_MIDDLE",
	0x16: "DATA_ONLY_LAST", 0x17: "SESSION_CONFIRM", 0x18: "SESSION_END", 0x19: "SESSION_INITIALIZE",
	0x1a: "NO_RECEIVE", 0x1b: "RECEIVE_OUTSTANDING", 0x1c: "RECEIVE_CONTINUE", 0x1f: "SESSION_ALIVE",
}

// formatLLC formats an 802.2 frame: its control field and, for NetBEUI,
// the NetBIOS frame in it.
func formatLLC(b []byte) (string, bool) {
	if len(b) < 3 {
		return "", false
	}
	dsap, ssap, c0 := b[0], b[1], b[2]
	cr := "cmd"
	if ssap&1 != 0 {
		cr = "resp"
	}
	var ctl string
	var info []byte
	switch {
	case c0&3 == 3:
		name, ok := llcU[c0&^0x10]
		if !ok {
			name = fmt.Sprintf("U %#02x", c0)
		}
		ctl = name
		if c0&0x10 != 0 {
			ctl += " P/F"
		}
		info = b[3:]
	case len(b) < 4:
		return "", false
	case c0&1 == 0:
		ctl = fmt.Sprintf("I ns %d nr %d", c0>>1, b[3]>>1)
		if b[3]&1 != 0 {
			ctl += " P/F"
		}
		info = b[4:]
	default:
		name, ok := llcS[c0]
		if !ok {
			name = fmt.Sprintf("S %#02x", c0)
		}
		ctl = fmt.Sprintf("%s nr %d", name, b[3]>>1)
		if b[3]&1 != 0 {
			ctl += " P/F"
		}
	}
	if dsap&^1 == 0xf0 && ssap&^1 == 0xf0 {
		s := "NetBEUI " + ctl + " " + cr
		if nb := formatNBF(info); nb != "" {
			s += ", " + nb
		}
		return s, true
	}
	s := fmt.Sprintf("802.2 dsap %#02x ssap %#02x %s %s", dsap, ssap&^1, ctl, cr)
	if len(info) > 0 {
		s += fmt.Sprintf(" (%d bytes)", len(info))
	}
	return s, true
}

// nbName formats a 16-byte NetBIOS name.
func nbName(b []byte) string {
	name := strings.TrimRight(string(b[:15]), " \x00")
	if strings.ContainsFunc(name, func(r rune) bool { return r < ' ' || r > '~' }) {
		name = fmt.Sprintf("%q", name)
	}
	return fmt.Sprintf("%s<%02x>", name, b[15])
}

func formatNBF(b []byte) string {
	if len(b) < 14 || binary.LittleEndian.Uint16(b[2:]) != 0xefff {
		return ""
	}
	n := int(binary.LittleEndian.Uint16(b))
	cmd, ok := nbfCommands[b[4]]
	if !ok {
		cmd = fmt.Sprintf("command %#02x", b[4])
	}
	data2 := binary.LittleEndian.Uint16(b[6:])
	switch {
	case n == 44 && len(b) >= 44:
		s := fmt.Sprintf("%s %s from %s", cmd, nbName(b[12:28]), nbName(b[28:44]))
		if (b[4] == 0x0a || b[4] == 0x0e) && byte(data2) != 0 {
			s += fmt.Sprintf(" session %d", byte(data2))
		}
		if extra := len(b) - 44; extra > 0 {
			s += fmt.Sprintf(" (%d bytes)", extra)
		}
		return s
	case n == 14:
		s := fmt.Sprintf("%s %d>%d", cmd, b[13], b[12])
		if extra := len(b) - 14; extra > 0 {
			s += fmt.Sprintf(" (%d bytes)", extra)
		}
		return s
	}
	return cmd
}
