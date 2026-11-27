package llc

import (
	"net"
	"testing"

	"github.com/rpajarola/gobootd/internal/link"
	"github.com/rpajarola/gobootd/internal/link/linktest"
)

// FuzzStation feeds frames from one remote station to a station that
// accepts links.
func FuzzStation(f *testing.F) {
	f.Add([]byte{0xf0, 0xf0, ctlSABME | pfU}, []byte{0xf0, 0xf0, 0x00, 0x01, 'x'}, []byte{0xf0, 0xf0, sREJ, 0x01})
	f.Add([]byte{0xf0, 0xf0, ctlXID | pfU, 0x81, 1, 0}, []byte{0xf0, 0xf0, ctlDISC | pfU}, []byte{0xf0, 0xf1, sRR, 0x03})
	f.Fuzz(func(t *testing.T, a, b, c []byte) {
		mac := net.HardwareAddr{2, 0, 0, 0, 0, 1}
		s := &Station{SAP: 0xf0, Port: &linktest.Recorder{Info: &link.Interface{MAC: mac}},
			Accept: func(*Link) Handler { return newRecorder(true) }}
		from := net.HardwareAddr{2, 0, 0, 0, 0, 2}
		for _, p := range [][]byte{a, b, c} {
			s.Handle(link.Build8023(mac, from, p))
		}
	})
}
