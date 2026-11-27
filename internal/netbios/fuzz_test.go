package netbios

import (
	"net"
	"net/netip"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
	"github.com/rpajarola/gobootd/internal/llc"
)

func FuzzQuery(f *testing.F) {
	f.Add(EncodeQuery(1, MakeName("BOOTD", Server), false, true))
	f.Add(EncodeQuery(2, Wildcard, true, false))
	f.Fuzz(func(t *testing.T, b []byte) {
		if q, ok := ParseQuery(b); ok {
			q.Answer(netip.AddrFrom4([4]byte{1, 2, 3, 4}))
			q.StatusAnswer([]Entry{{Name: q.Name}}, net.HardwareAddr{1, 2, 3, 4, 5, 6})
		}
	})
}

// FuzzNBF feeds LLC payloads from one station to an NBF server: name
// queries, link setup and session frames, in sequence.
func FuzzNBF(f *testing.F) {
	srv := MakeName("BOOTD", Server)
	pc := MakeName("PC", 0)
	query := append([]byte{SAP, SAP, 0x03}, header{cmd: nbNameQuery, data2: 1, resp: 9, dst: srv, src: pc}.ui()...)
	sabme := []byte{SAP, SAP, 0x7f}
	init := append([]byte{SAP, SAP, 0x00, 0x00}, header{cmd: nbSessionInit, data2: 1000, xmit: 1, resp: 2, dstNum: 1, srcNum: 1}.session(nil)...)
	data := append([]byte{SAP, SAP, 0x02, 0x00}, header{cmd: nbDataOnlyLast, resp: 3, dstNum: 1, srcNum: 1}.session([]byte("hi"))...)
	f.Add(query, sabme, init, data)
	f.Fuzz(func(t *testing.T, a, b, c, d []byte) {
		mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
		port := &linktest.Recorder{Info: &link.Interface{MAC: mac}}
		st := &llc.Station{SAP: SAP, Port: port}
		n := &NBF{Station: st, Names: []Name{srv}, Accept: func(s *NBFSession) { s.Close() }}
		n.Init()
		from := net.HardwareAddr{2, 0, 0, 0, 0, 2}
		for _, p := range [][]byte{a, b, c, d} {
			st.Handle(link.Build8023(mac, from, p))
		}
	})
}
