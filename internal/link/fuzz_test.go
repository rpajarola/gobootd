package link

import "testing"

func FuzzParse(f *testing.F) {
	f.Add(Build(Broadcast, Broadcast, TypeRARP, make([]byte, 28)))
	f.Add(Build8023(Broadcast, Broadcast, []byte{0xf8, 0xf8, 0x03}))
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, b []byte) {
		fr, ok := Parse(b)
		if !ok {
			return
		}
		if len(fr.Dst) != 6 || len(fr.Src) != 6 || len(fr.Payload) > len(b)-HeaderLen {
			t.Fatalf("bad frame %+v from %d bytes", fr, len(b))
		}
		if fr.Type == 0 && len(fr.Payload) != int(b[12])<<8|int(b[13]) {
			t.Fatalf("802.3 payload %d bytes, length field %d", len(fr.Payload), int(b[12])<<8|int(b[13]))
		}
	})
}
