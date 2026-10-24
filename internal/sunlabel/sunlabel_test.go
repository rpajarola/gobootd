package sunlabel

import (
	"encoding/binary"
	"testing"
)

// make8 builds a label sector.
func make8(cyls, heads, secs int, parts map[byte][2]uint32) []byte {
	b := make([]byte, SectorSize)
	copy(b, "test disk")
	binary.BigEndian.PutUint16(b[432:], uint16(cyls))
	binary.BigEndian.PutUint16(b[436:], uint16(heads))
	binary.BigEndian.PutUint16(b[438:], uint16(secs))
	for p, v := range parts {
		i := int(p - 'a')
		binary.BigEndian.PutUint32(b[444+8*i:], v[0])
		binary.BigEndian.PutUint32(b[448+8*i:], v[1])
	}
	binary.BigEndian.PutUint16(b[508:], magic)
	var sum uint16
	for i := 0; i < 510; i += 2 {
		sum ^= binary.BigEndian.Uint16(b[i:])
	}
	binary.BigEndian.PutUint16(b[510:], sum)
	return b
}

func TestParse(t *testing.T) {
	// The label of the TME disk the SunOS 2.0 Sun-2 was installed on.
	b := make8(544, 16, 120, map[byte][2]uint32{'a': {0, 263040}, 'b': {137, 132480}, 'g': {206, 648960}})
	l, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if l.ASCII != "test disk" || l.Heads != 16 || l.Secs != 120 {
		t.Errorf("label %+v", l)
	}
	for _, tc := range []struct {
		name        string
		start, size int64
	}{{"a", 0, 263040}, {"b", 263040, 132480}, {"g", 395520, 648960}} {
		p, err := l.Partition(tc.name)
		if err != nil || p.Start != tc.start || p.Size != tc.size {
			t.Errorf("%s: %+v, %v", tc.name, p, err)
		}
	}
	if _, err := l.Partition("d"); err == nil {
		t.Error("empty partition d accepted")
	}
	b[100] ^= 1
	if _, err := Parse(b); err == nil {
		t.Error("bad checksum accepted")
	}
}
