// Package sunlabel reads the disk label Sun workstations keep in the first
// sector of a disk: the geometry and eight partitions.
package sunlabel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// SectorSize is the size of a disk sector.
const SectorSize = 512

const magic = 0xdabe

// Partition is a partition in sectors.
type Partition struct {
	Start, Size int64
}

// Label is a Sun disk label.
type Label struct {
	ASCII             string
	Cyls, Heads, Secs int
	Partitions        [8]Partition
}

// Read reads the label from the first sector of r.
func Read(r io.ReaderAt) (*Label, error) {
	b := make([]byte, SectorSize)
	if _, err := r.ReadAt(b, 0); err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse parses a label sector.
func Parse(b []byte) (*Label, error) {
	if len(b) < SectorSize || binary.BigEndian.Uint16(b[508:]) != magic {
		return nil, errors.New("no Sun disk label")
	}
	var sum uint16
	for i := 0; i < SectorSize; i += 2 {
		sum ^= binary.BigEndian.Uint16(b[i:])
	}
	if sum != 0 {
		return nil, errors.New("Sun disk label has a bad checksum")
	}
	u16 := func(o int) int { return int(binary.BigEndian.Uint16(b[o:])) }
	l := &Label{Cyls: u16(432), Heads: u16(436), Secs: u16(438)}
	if i := indexNUL(b[:128]); i >= 0 {
		l.ASCII = string(b[:i])
	}
	for i := range l.Partitions {
		cyl := int64(binary.BigEndian.Uint32(b[444+8*i:]))
		l.Partitions[i] = Partition{
			Start: cyl * int64(l.Heads) * int64(l.Secs),
			Size:  int64(binary.BigEndian.Uint32(b[448+8*i:])),
		}
	}
	return l, nil
}

// Partition returns partition "a" to "h".
func (l *Label) Partition(name string) (Partition, error) {
	if len(name) != 1 || name[0] < 'a' || name[0] > 'h' {
		return Partition{}, fmt.Errorf("partition %q is not a to h", name)
	}
	p := l.Partitions[name[0]-'a']
	if p.Size == 0 {
		return Partition{}, fmt.Errorf("partition %s is empty", name)
	}
	return p, nil
}

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
