package bridge

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/oncrpc"
	"github.com/rpajarola/gobootd/internal/proto/nd"
	"github.com/rpajarola/gobootd/internal/proto/rmp"
)

// FormatPacket formats an Ethernet frame as a single-line tcpdump-style summary.
func FormatPacket(now time.Time, prefix string, frame []byte) string {
	ts := now.Format("15:04:05.00")
	pfx := " "
	if prefix != "" {
		pfx = fmt.Sprintf(" [%s] ", prefix)
	}
	if len(frame) < link.HeaderLen {
		return fmt.Sprintf("%s%srunt (%d bytes)", ts, pfx, len(frame))
	}
	dst := net.HardwareAddr(frame[0:6])
	src := net.HardwareAddr(frame[6:12])
	ethertype := binary.BigEndian.Uint16(frame[12:14])
	payload := frame[link.HeaderLen:]

	if ethertype <= link.MaxLength {
		if int(ethertype) <= len(payload) {
			payload = payload[:ethertype]
		}
		if len(payload) >= 8 && payload[0] == 0xaa && payload[1] == 0xaa && payload[2] == 0x03 {
			ethertype = binary.BigEndian.Uint16(payload[6:8])
			payload = payload[8:]
		} else {
			return fmt.Sprintf("%s%s%s > %s %s", ts, pfx, src, dst, format8023(payload))
		}
	}

	return fmt.Sprintf("%s%s%s > %s %s", ts, pfx, src, dst, formatEtherType(ethertype, payload))
}

func format8023(payload []byte) string {
	if s, ok := formatRMP(payload); ok {
		return s
	}
	if len(payload) >= 3 {
		return fmt.Sprintf("802.3 dsap %#02x ssap %#02x (%d bytes)", payload[0], payload[1], len(payload))
	}
	return fmt.Sprintf("802.3 (%d bytes)", len(payload))
}

func formatRMP(b []byte) (string, bool) {
	const (
		sapHP    = 0xf8
		cntlHP   = 0x0300
		dxsapHP  = 0x0608
		sxsapHP  = 0x0609
		hdrLen   = 18
		machLen  = 20
		probeSID = 0xffff
	)
	if len(b) < hdrLen || b[0] != sapHP || binary.BigEndian.Uint16(b[2:4]) != cntlHP {
		return "", false
	}
	dxsap := binary.BigEndian.Uint16(b[6:8])
	if dxsap != dxsapHP && dxsap != sxsapHP {
		return "", false
	}
	p := rmp.Packet{
		Type:    b[10],
		RetCode: b[11],
		Seq:     binary.BigEndian.Uint32(b[12:16]),
		Session: binary.BigEndian.Uint16(b[16:18]),
	}
	d := b[hdrLen:]
	switch p.Type {
	case rmp.BootReq:
		if len(d) < 2+machLen+1 {
			return "", false
		}
		p.Version = binary.BigEndian.Uint16(d[0:2])
		mt := d[2 : 2+machLen]
		if i := bytes.IndexAny(mt, " \x00"); i >= 0 {
			mt = mt[:i]
		}
		p.MachType = string(mt)
		n := int(d[2+machLen])
		name := d[2+machLen+1:]
		if n > len(name) {
			return "", false
		}
		p.Filename = string(name[:n])
	case rmp.BootRepl:
		if len(d) < 3 {
			return "", false
		}
		p.Version = binary.BigEndian.Uint16(d[0:2])
		n := int(d[2])
		name := d[3:]
		if n > len(name) {
			return "", false
		}
		p.Filename = string(name[:n])
	case rmp.ReadReq:
		if len(d) < 2 {
			return "", false
		}
		p.Size = binary.BigEndian.Uint16(d[0:2])
	case rmp.ReadRepl:
		p.Data = d
	case rmp.BootDone:
	}
	return "RMP " + p.String(), true
}

func formatEtherType(ethertype uint16, payload []byte) string {
	switch ethertype {
	case link.TypeARP:
		return formatARP("ARP", payload)
	case link.TypeRARP:
		return formatARP("RARP", payload)
	case link.TypeIPv4:
		return formatIPv4(payload)
	case 0x86dd:
		return formatIPv6(payload)
	default:
		return fmt.Sprintf("ethertype %#04x (%d bytes)", ethertype, len(payload))
	}
}

func formatARP(proto string, b []byte) string {
	if len(b) < 28 ||
		binary.BigEndian.Uint16(b[0:2]) != 1 ||
		binary.BigEndian.Uint16(b[2:4]) != link.TypeIPv4 ||
		b[4] != 6 || b[5] != 4 {
		return fmt.Sprintf("%s (%d bytes)", proto, len(b))
	}
	op := binary.BigEndian.Uint16(b[6:8])
	senderHW := net.HardwareAddr(b[8:14])
	senderIP := netip.AddrFrom4([4]byte(b[14:18]))
	targetHW := net.HardwareAddr(b[18:24])
	targetIP := netip.AddrFrom4([4]byte(b[24:28]))
	switch op {
	case 1:
		return fmt.Sprintf("ARP Request who-has %s tell %s", targetIP, senderIP)
	case 2:
		return fmt.Sprintf("ARP Reply %s is-at %s", senderIP, senderHW)
	case 3:
		return fmt.Sprintf("RARP Request who-is %s tell %s", targetHW, senderHW)
	case 4:
		return fmt.Sprintf("RARP Reply %s at %s", targetHW, targetIP)
	default:
		return fmt.Sprintf("%s op %d", proto, op)
	}
}

func formatIPv4(b []byte) string {
	if len(b) < 20 || b[0]>>4 != 4 {
		return fmt.Sprintf("IP (%d bytes)", len(b))
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < 20 || len(b) < ihl {
		return fmt.Sprintf("IP (%d bytes)", len(b))
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	payload := b[ihl:]
	if total >= ihl && total <= len(b) {
		payload = b[ihl:total]
	}
	src := netip.AddrFrom4([4]byte(b[12:16]))
	dst := netip.AddrFrom4([4]byte(b[16:20]))
	proto := b[9]
	frag := binary.BigEndian.Uint16(b[6:8])
	if frag&0x1fff != 0 {
		return fmt.Sprintf("IP %s > %s: proto %d frag offset %d (%d bytes)", src, dst, proto, (frag&0x1fff)*8, len(payload))
	}

	switch proto {
	case 1:
		return fmt.Sprintf("IP %s > %s: %s", src, dst, formatICMP(payload))
	case nd.IPProto:
		return fmt.Sprintf("IP %s > %s: %s", src, dst, formatND(payload))
	case 17:
		if len(payload) < 8 {
			return fmt.Sprintf("IP %s > %s: UDP (%d bytes)", src, dst, len(payload))
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		udpLen := int(binary.BigEndian.Uint16(payload[4:6]))
		udpData := payload[8:]
		if udpLen >= 8 && udpLen <= len(payload) {
			udpData = payload[8:udpLen]
		}
		return fmt.Sprintf("IP %s.%d > %s.%d: %s", src, srcPort, dst, dstPort, formatUDP(srcPort, dstPort, udpData))
	case 6:
		if len(payload) < 20 {
			return fmt.Sprintf("IP %s > %s: TCP (%d bytes)", src, dst, len(payload))
		}
		srcPort := binary.BigEndian.Uint16(payload[0:2])
		dstPort := binary.BigEndian.Uint16(payload[2:4])
		return fmt.Sprintf("IP %s.%d > %s.%d: %s", src, srcPort, dst, dstPort, formatTCP(srcPort, dstPort, payload))
	default:
		return fmt.Sprintf("IP %s > %s: proto %d (%d bytes)", src, dst, proto, len(payload))
	}
}

func formatIPv6(b []byte) string {
	if len(b) < 40 || b[0]>>4 != 6 {
		return fmt.Sprintf("IP6 (%d bytes)", len(b))
	}
	src := netip.AddrFrom16([16]byte(b[8:24]))
	dst := netip.AddrFrom16([16]byte(b[24:40]))
	return fmt.Sprintf("IP6 %s > %s: next-header %d (%d bytes)", src, dst, b[6], len(b)-40)
}

func formatICMP(b []byte) string {
	if len(b) < 4 {
		return fmt.Sprintf("ICMP (%d bytes)", len(b))
	}
	typ, code := b[0], b[1]
	switch {
	case typ == 8 && code == 0 && len(b) >= 8:
		id := binary.BigEndian.Uint16(b[4:6])
		seq := binary.BigEndian.Uint16(b[6:8])
		return fmt.Sprintf("ICMP echo request, id %d, seq %d, length %d", id, seq, len(b))
	case typ == 0 && code == 0 && len(b) >= 8:
		id := binary.BigEndian.Uint16(b[4:6])
		seq := binary.BigEndian.Uint16(b[6:8])
		return fmt.Sprintf("ICMP echo reply, id %d, seq %d, length %d", id, seq, len(b))
	case typ == 3:
		return fmt.Sprintf("ICMP destination unreachable (code %d)", code)
	case typ == 11:
		return "ICMP time exceeded"
	default:
		return fmt.Sprintf("ICMP type %d code %d", typ, code)
	}
}

func formatND(b []byte) string {
	if len(b) < 28 {
		return fmt.Sprintf("ND (%d bytes)", len(b))
	}
	i32 := func(o int) int32 { return int32(binary.BigEndian.Uint32(b[o:])) }
	op := b[0]
	minor := b[1]
	errCode := int8(b[2])
	seq := i32(4)
	block := i32(8)
	count := i32(12)
	offset := i32(20)
	pktCount := i32(24)

	var opName string
	switch op & 7 {
	case nd.OpRead:
		opName = "Read"
	case nd.OpWrite:
		opName = "Write"
	case nd.OpError:
		opName = "Error"
	default:
		opName = fmt.Sprintf("op %#x", op&7)
	}
	var flags []string
	if op&nd.FlagWait != 0 {
		flags = append(flags, "wait")
	}
	if op&nd.FlagDone != 0 {
		flags = append(flags, "done")
	}
	if len(flags) > 0 {
		opName += "[" + strings.Join(flags, ",") + "]"
	}
	s := fmt.Sprintf("ND %s minor %#x seq %d block %d offset %d count %d len %d",
		opName, minor, seq, block, offset, count, pktCount)
	if errCode != 0 {
		s += fmt.Sprintf(" err %d", errCode)
	}
	return s
}

func formatUDP(srcPort, dstPort uint16, b []byte) string {
	if s, ok := formatONCRPC(srcPort, dstPort, b); ok {
		return s
	}
	if s, ok := formatTFTP(srcPort, dstPort, b); ok {
		return s
	}
	if (srcPort == 67 || dstPort == 67 || srcPort == 68 || dstPort == 68) && len(b) >= 236 {
		if s, ok := formatBOOTP(b); ok {
			return s
		}
	}
	return fmt.Sprintf("UDP, length %d", len(b))
}

func formatTCP(srcPort, dstPort uint16, b []byte) string {
	seq := binary.BigEndian.Uint32(b[4:8])
	ack := binary.BigEndian.Uint32(b[8:12])
	dataOff := int(b[12]>>4) * 4
	flags := b[13]

	var fs strings.Builder
	if flags&0x02 != 0 {
		fs.WriteByte('S')
	}
	if flags&0x01 != 0 {
		fs.WriteByte('F')
	}
	if flags&0x04 != 0 {
		fs.WriteByte('R')
	}
	if flags&0x08 != 0 {
		fs.WriteByte('P')
	}
	if flags&0x10 != 0 {
		fs.WriteByte('.')
	}
	if fs.Len() == 0 {
		fs.WriteString("none")
	}

	var payload []byte
	if dataOff >= 20 && dataOff <= len(b) {
		payload = b[dataOff:]
	}
	summary := fmt.Sprintf("TCP Flags [%s], seq %d, ack %d, length %d", fs.String(), seq, ack, len(payload))
	if len(payload) >= 4 {
		recHdr := binary.BigEndian.Uint32(payload[0:4])
		recLen := int(recHdr & 0x7fffffff)
		if recLen > 0 && 4+recLen <= len(payload) {
			if rpc, ok := formatONCRPC(srcPort, dstPort, payload[4:4+recLen]); ok {
				summary += ": " + rpc
			}
		}
	}
	return summary
}

func formatTFTP(srcPort, dstPort uint16, b []byte) (string, bool) {
	if len(b) < 4 {
		return "", false
	}
	op := binary.BigEndian.Uint16(b[0:2])
	switch op {
	case 1, 2: // RRQ, WRQ
		if dstPort != 69 && srcPort != 69 {
			return "", false
		}
		fields := bytes.Split(b[2:], []byte{0})
		if len(fields) < 3 || len(fields[len(fields)-1]) != 0 {
			return "", false
		}
		fields = fields[:len(fields)-1]
		filename := string(fields[0])
		mode := strings.ToLower(string(fields[1]))
		var opts []string
		for i := 2; i+1 < len(fields); i += 2 {
			if len(fields[i]) == 0 {
				break
			}
			opts = append(opts, fmt.Sprintf("%s=%s", strings.ToLower(string(fields[i])), string(fields[i+1])))
		}
		kind := "Read"
		if op == 2 {
			kind = "Write"
		}
		if len(opts) > 0 {
			return fmt.Sprintf("TFTP %s %q (%s, %s)", kind, filename, mode, strings.Join(opts, ", ")), true
		}
		return fmt.Sprintf("TFTP %s %q (%s)", kind, filename, mode), true

	case 3: // DATA
		if srcPort < 1024 || dstPort < 1024 || len(b) > 1472 {
			return "", false
		}
		block := binary.BigEndian.Uint16(b[2:4])
		if block == 0 {
			return "", false
		}
		return fmt.Sprintf("TFTP Data block %d (%d bytes)", block, len(b)-4), true

	case 4: // ACK
		if srcPort < 1024 || dstPort < 1024 || len(b) != 4 {
			return "", false
		}
		block := binary.BigEndian.Uint16(b[2:4])
		return fmt.Sprintf("TFTP Ack block %d", block), true

	case 5: // ERROR
		if len(b) < 5 || b[len(b)-1] != 0 {
			return "", false
		}
		code := binary.BigEndian.Uint16(b[2:4])
		if code > 8 {
			return "", false
		}
		msg := string(bytes.TrimRight(b[4:], "\x00"))
		return fmt.Sprintf("TFTP Error %d %q", code, msg), true

	case 6: // OACK
		if srcPort < 1024 || dstPort < 1024 || b[len(b)-1] != 0 {
			return "", false
		}
		fields := bytes.Split(b[2:len(b)-1], []byte{0})
		if len(fields) == 0 || len(fields)%2 != 0 {
			return "", false
		}
		var opts []string
		for i := 0; i+1 < len(fields); i += 2 {
			k := strings.ToLower(string(fields[i]))
			if k != "blksize" && k != "tsize" && k != "timeout" {
				return "", false
			}
			opts = append(opts, fmt.Sprintf("%s=%s", k, string(fields[i+1])))
		}
		return fmt.Sprintf("TFTP OACK %s", strings.Join(opts, " ")), true
	}
	return "", false
}

func formatBOOTP(b []byte) (string, bool) {
	op := b[0]
	if op != 1 && op != 2 {
		return "", false
	}
	chaddr := net.HardwareAddr(b[28:34])
	yiaddr := netip.AddrFrom4([4]byte(b[16:20]))
	if len(b) >= 240 && b[236] == 99 && b[237] == 130 && b[238] == 83 && b[239] == 99 {
		opts := b[240:]
		for len(opts) > 0 {
			code := opts[0]
			if code == 255 {
				break
			}
			if code == 0 {
				opts = opts[1:]
				continue
			}
			if len(opts) < 2 || int(opts[1])+2 > len(opts) {
				break
			}
			val := opts[2 : 2+int(opts[1])]
			opts = opts[2+int(opts[1]):]
			if code == 53 && len(val) == 1 {
				names := map[byte]string{
					1: "Discover", 2: "Offer", 3: "Request", 4: "Decline",
					5: "ACK", 6: "NAK", 7: "Release", 8: "Inform",
				}
				if name, ok := names[val[0]]; ok {
					return fmt.Sprintf("DHCP %s from %s", name, chaddr), true
				}
			}
		}
	}
	if op == 1 {
		return fmt.Sprintf("BOOTP Request from %s", chaddr), true
	}
	return fmt.Sprintf("BOOTP Reply %s at %s", chaddr, yiaddr), true
}

const (
	progPortmap   = 100000
	progNFS       = 100003
	progNIS       = 100004
	progMount     = 100005
	progBootparam = 100026
)

func isKnownRPCProg(prog uint32) bool {
	switch prog {
	case progPortmap, progNFS, progNIS, progMount, progBootparam:
		return true
	}
	return false
}

func rpcProgName(prog uint32) string {
	switch prog {
	case progPortmap:
		return "portmap"
	case progNFS:
		return "nfs"
	case progNIS:
		return "nis"
	case progMount:
		return "mount"
	case progBootparam:
		return "bootparam"
	default:
		return fmt.Sprintf("prog-%d", prog)
	}
}

func formatONCRPC(srcPort, dstPort uint16, b []byte) (string, bool) {
	if len(b) < 12 {
		return "", false
	}
	dec := oncrpc.NewDecoder(b)
	xid := dec.Uint32()
	mtype := dec.Uint32()
	if dec.Err() != nil {
		return "", false
	}
	isRPCPort := srcPort == oncrpc.PortmapPort || dstPort == oncrpc.PortmapPort ||
		srcPort == oncrpc.NFSPort || dstPort == oncrpc.NFSPort

	switch mtype {
	case 0: // Call
		vers := dec.Uint32()
		prog := dec.Uint32()
		progVers := dec.Uint32()
		proc := dec.Uint32()
		_ = dec.Uint32()      // cred flavor
		_ = dec.Opaque(400)   // cred
		_ = dec.Uint32()      // verf flavor
		_ = dec.Opaque(400)   // verf
		if dec.Err() != nil || vers != 2 {
			return "", false
		}
		if !isKnownRPCProg(prog) && !isRPCPort {
			return "", false
		}
		args := oncrpc.NewDecoder(dec.Rest())
		return fmt.Sprintf("RPC Call xid %#x %s", xid, formatRPCCall(prog, progVers, proc, args)), true

	case 1: // Reply
		if !isRPCPort {
			return "", false
		}
		replyStat := dec.Uint32()
		if dec.Err() != nil || replyStat > 1 {
			return "", false
		}
		svc := "RPC"
		if srcPort == oncrpc.NFSPort {
			svc = "NFS"
		}
		if replyStat == 1 {
			return fmt.Sprintf("%s Reply xid %#x denied", svc, xid), true
		}
		_ = dec.Uint32()    // verf flavor
		_ = dec.Opaque(400) // verf
		acceptStat := dec.Uint32()
		if dec.Err() != nil || acceptStat > 5 {
			return "", false
		}
		statuses := []string{"ok", "prog-unavail", "prog-mismatch", "proc-unavail", "garbage-args", "system-err"}
		return fmt.Sprintf("%s Reply xid %#x %s (%d bytes)", svc, xid, statuses[acceptStat], len(dec.Rest())), true
	}
	return "", false
}

func formatRPCCall(prog, vers, proc uint32, args *oncrpc.Decoder) string {
	if proc == 0 {
		return fmt.Sprintf("%s v%d NULL", rpcProgName(prog), vers)
	}
	switch prog {
	case progPortmap:
		return formatPortmapCall(proc, args)
	case progBootparam:
		return formatBootparamCall(proc, args)
	case progMount:
		return formatMountCall(vers, proc, args)
	case progNFS:
		return formatNFSCall(proc, args)
	case progNIS:
		return formatNISCall(proc, args)
	default:
		return fmt.Sprintf("prog %d v%d proc %d", prog, vers, proc)
	}
}

func formatPortmapCall(proc uint32, args *oncrpc.Decoder) string {
	switch proc {
	case 1:
		return "portmap SET"
	case 2:
		return "portmap UNSET"
	case 3:
		prog, vers, prot := args.Uint32(), args.Uint32(), args.Uint32()
		if args.Err() == nil {
			pname := fmt.Sprintf("proto-%d", prot)
			switch prot {
			case 6:
				pname = "tcp"
			case 17:
				pname = "udp"
			}
			return fmt.Sprintf("portmap GETPORT %s v%d %s", rpcProgName(prog), vers, pname)
		}
		return "portmap GETPORT"
	case 4:
		return "portmap DUMP"
	case 5:
		prog, vers, cproc := args.Uint32(), args.Uint32(), args.Uint32()
		inner := args.Opaque(65536)
		if args.Err() == nil {
			return fmt.Sprintf("portmap CALLIT %s", formatRPCCall(prog, vers, cproc, oncrpc.NewDecoder(inner)))
		}
		return "portmap CALLIT"
	default:
		return fmt.Sprintf("portmap proc %d", proc)
	}
}

func formatBootparamCall(proc uint32, args *oncrpc.Decoder) string {
	switch proc {
	case 1: // WHOAMI
		if args.Uint32() == 1 {
			var a [4]byte
			for i := range a {
				a[i] = byte(args.Uint32())
			}
			if args.Err() == nil {
				return fmt.Sprintf("bootparam WHOAMI %s", netip.AddrFrom4(a))
			}
		}
		return "bootparam WHOAMI"
	case 2: // GETFILE
		client, key := args.String(255), args.String(32)
		if args.Err() == nil {
			return fmt.Sprintf("bootparam GETFILE %s %q", client, key)
		}
		return "bootparam GETFILE"
	default:
		return fmt.Sprintf("bootparam proc %d", proc)
	}
}

func formatMountCall(vers, proc uint32, args *oncrpc.Decoder) string {
	switch proc {
	case 1:
		path := args.String(1024)
		if args.Err() == nil {
			return fmt.Sprintf("mount v%d MNT %q", vers, path)
		}
		return fmt.Sprintf("mount v%d MNT", vers)
	case 2:
		return fmt.Sprintf("mount v%d DUMP", vers)
	case 3:
		path := args.String(1024)
		if args.Err() == nil {
			return fmt.Sprintf("mount v%d UMNT %q", vers, path)
		}
		return fmt.Sprintf("mount v%d UMNT", vers)
	case 4:
		return fmt.Sprintf("mount v%d UMNTALL", vers)
	case 5:
		return fmt.Sprintf("mount v%d EXPORT", vers)
	default:
		return fmt.Sprintf("mount v%d proc %d", vers, proc)
	}
}

func formatNFSCall(proc uint32, args *oncrpc.Decoder) string {
	names := map[uint32]string{
		1: "GETATTR", 2: "SETATTR", 3: "ROOT", 4: "LOOKUP", 5: "READLINK",
		6: "READ", 7: "WRITECACHE", 8: "WRITE", 9: "CREATE", 10: "REMOVE",
		11: "RENAME", 12: "LINK", 13: "SYMLINK", 14: "MKDIR", 15: "RMDIR",
		16: "READDIR", 17: "STATFS",
	}
	name, ok := names[proc]
	if !ok {
		return fmt.Sprintf("nfs proc %d", proc)
	}
	switch proc {
	case 4, 9, 10, 14, 15: // fhandle + filename
		_ = args.Fixed(32)
		fname := args.String(255)
		if args.Err() == nil {
			return fmt.Sprintf("nfs %s %q", name, fname)
		}
	case 6: // READ: fhandle + offset + count + totalcount
		_ = args.Fixed(32)
		offset, count := args.Uint32(), args.Uint32()
		if args.Err() == nil {
			return fmt.Sprintf("nfs READ offset %d count %d", offset, count)
		}
	case 16: // READDIR: fhandle + cookie + count
		_ = args.Fixed(32)
		cookie, count := args.Uint32(), args.Uint32()
		if args.Err() == nil {
			return fmt.Sprintf("nfs READDIR cookie %d count %d", cookie, count)
		}
	}
	return "nfs " + name
}

func formatNISCall(proc uint32, args *oncrpc.Decoder) string {
	switch proc {
	case 1:
		dom := args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis DOMAIN %q", dom)
		}
		return "nis DOMAIN"
	case 2:
		dom := args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis DOMAIN_NONACK %q", dom)
		}
		return "nis DOMAIN_NONACK"
	case 3:
		dom, m := args.String(64), args.String(64)
		key := string(args.Opaque(1024))
		if args.Err() == nil {
			return fmt.Sprintf("nis MATCH %s %s %q", dom, m, key)
		}
		return "nis MATCH"
	case 4:
		dom, m := args.String(64), args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis FIRST %s %s", dom, m)
		}
		return "nis FIRST"
	case 5:
		dom, m := args.String(64), args.String(64)
		key := string(args.Opaque(1024))
		if args.Err() == nil {
			return fmt.Sprintf("nis NEXT %s %s %q", dom, m, key)
		}
		return "nis NEXT"
	case 7:
		return "nis CLEAR"
	case 8:
		dom, m := args.String(64), args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis ALL %s %s", dom, m)
		}
		return "nis ALL"
	case 9:
		dom, m := args.String(64), args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis MASTER %s %s", dom, m)
		}
		return "nis MASTER"
	case 10:
		dom, m := args.String(64), args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis ORDER %s %s", dom, m)
		}
		return "nis ORDER"
	case 11:
		dom := args.String(64)
		if args.Err() == nil {
			return fmt.Sprintf("nis MAPLIST %q", dom)
		}
		return "nis MAPLIST"
	default:
		return fmt.Sprintf("nis proc %d", proc)
	}
}
