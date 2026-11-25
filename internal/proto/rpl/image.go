package rpl

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/rpajarola/gobootd/internal/inventory"
	"github.com/rpajarola/gobootd/internal/service"
)

// ramdisk is the loader that boots a floppy image from memory, built from
// ramdisk.S.
//
//go:generate ./mkramdisk.sh
//go:embed ramdisk.bin
var ramdisk []byte

const (
	// ramdiskTop is where a floppy image ends in the client's memory.
	// The top of conventional memory is left alone: the BIOS and boot
	// ROMs keep data there.
	ramdiskTop = 0x90000
	// minDOS is the least memory left below the loader for DOS.
	minDOS = 0x20000
)

// piece is a part of a boot image: a file, or the RAM disk loader.
type piece struct {
	name string
	load uint32
	data []byte // the loader; nil for a file
	path string
	size int64
}

// Plan is what RPL loads into a client, and where.
type Plan struct {
	pieces []piece
	exec   uint32
	floppy string // geometry of a floppy image, or ""
}

// String describes the plan.
func (p *Plan) String() string {
	var b strings.Builder
	if p.floppy != "" {
		fmt.Fprintf(&b, "floppy image (%s) as drive A: in memory; ", p.floppy)
	}
	for i, pc := range p.pieces {
		if i > 0 {
			b.WriteString(", ")
		}
		fmt.Fprintf(&b, "%s at %#x-%#x", pc.name, pc.load, int64(pc.load)+pc.size-1)
	}
	fmt.Fprintf(&b, "; starts at %#x", p.exec)
	return b.String()
}

// MakePlan works out what RPL loads into h: its RPL files at their load
// addresses, or a floppy image with the RAM disk loader.
func MakePlan(h *inventory.Host) (*Plan, error) {
	files := h.FilesFor(service.RPL)
	if len(files) == 0 {
		return nil, errors.New("no rpl file configured for this host")
	}
	for _, f := range files {
		if f.Floppy {
			if len(files) > 1 {
				return nil, fmt.Errorf("%s is a floppy image, which must be the host's only rpl file", f.Label)
			}
			return floppyPlan(f)
		}
	}
	p := &Plan{}
	for _, f := range files {
		if !f.HasLoad {
			return nil, fmt.Errorf("%s has no load address", f.Label)
		}
		st, err := os.Stat(f.Path)
		if err != nil {
			return nil, err
		}
		if int64(f.Load)+st.Size() > 1<<32 {
			return nil, fmt.Errorf("%s does not fit in memory at %#x", f.Label, f.Load)
		}
		pc := piece{name: f.Label, load: f.Load, path: f.Path, size: st.Size()}
		for _, o := range p.pieces {
			if pc.size > 0 && o.size > 0 && int64(pc.load) < int64(o.load)+o.size && int64(o.load) < int64(pc.load)+pc.size {
				return nil, fmt.Errorf("%s overlaps %s in memory", f.Label, o.name)
			}
		}
		p.pieces = append(p.pieces, pc)
	}
	// The first execute address wins; without one, the client starts at
	// the first file.
	p.exec = files[0].Load
	for _, f := range files {
		if f.HasExecute {
			p.exec = f.Execute
			break
		}
	}
	return p, nil
}

// Floppy geometries by size: cylinders, heads, sectors per track.
var floppies = map[int64][3]int{
	160 << 10: {40, 1, 8},
	180 << 10: {40, 1, 9},
	320 << 10: {40, 2, 8},
	360 << 10: {40, 2, 9},
}

// floppyPlan loads a floppy image below ramdiskTop and the loader below
// it.
func floppyPlan(f *inventory.File) (*Plan, error) {
	fd, err := os.Open(f.Path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	st, err := fd.Stat()
	if err != nil {
		return nil, err
	}
	size := st.Size()
	var boot [512]byte
	if _, err := io.ReadFull(fd, boot[:]); err != nil {
		return nil, fmt.Errorf("%s: %w", f.Label, err)
	}
	g, ok := floppies[size]
	if !ok {
		// Other sizes need a BIOS parameter block.
		bps, spt, heads := binary.LittleEndian.Uint16(boot[11:]), int(binary.LittleEndian.Uint16(boot[24:])), int(binary.LittleEndian.Uint16(boot[26:]))
		if bps != 512 || spt < 1 || spt > 63 || heads < 1 || heads > 2 || size%int64(512*spt*heads) != 0 {
			return nil, fmt.Errorf("%s: %d bytes is not a floppy size, and the boot sector has no usable geometry", f.Label, size)
		}
		g = [3]int{int(size / int64(512*spt*heads)), heads, spt}
	}
	if g[0] > 1024 {
		return nil, fmt.Errorf("%s: too many cylinders", f.Label)
	}
	img := (ramdiskTop - size) &^ 0x3ff
	ldr := img - (int64(len(ramdisk))+0x3ff)&^0x3ff
	if ldr < minDOS {
		return nil, fmt.Errorf("%s: %d KB is too large: images up to %d KB fit in conventional memory", f.Label, size>>10, (ramdiskTop-minDOS-0x400)>>10)
	}
	stub := append([]byte{}, ramdisk...)
	if string(stub[4:8]) != "RDSK" {
		return nil, errors.New("RAM disk loader is corrupt")
	}
	le := binary.LittleEndian
	le.PutUint16(stub[8:], uint16(img>>4))
	le.PutUint16(stub[10:], uint16(size/512))
	stub[12] = byte(g[2])
	stub[13] = byte(g[1])
	le.PutUint16(stub[14:], uint16(g[0]))
	stub[16] = 1 // 360 KB drive
	if g[0] > 40 {
		stub[16] = 3 // 720 KB drive
	}
	le.PutUint16(stub[18:], uint16(ldr>>10))
	le.PutUint16(stub[20:], ramdiskTop>>10)
	return &Plan{
		pieces: []piece{
			{name: "RAM disk loader", load: uint32(ldr), data: stub, size: int64(len(stub))},
			{name: f.Label, load: uint32(img), path: f.Path, size: size},
		},
		exec:   uint32(ldr),
		floppy: fmt.Sprintf("%d KB, %d/%d/%d", size>>10, g[0], g[1], g[2]),
	}, nil
}

// blocks is the number of blocks of piece pc.
func blocks(pc piece, bs int) uint32 {
	return uint32((pc.size + int64(bs) - 1) / int64(bs))
}

// total is the number of blocks of the plan. Each piece starts a block.
func (p *Plan) total(bs int) uint32 {
	var n uint32
	for _, pc := range p.pieces {
		n += blocks(pc, bs)
	}
	return n
}

// image reads the blocks of a plan from its open files.
type image struct {
	*Plan
	files []*os.File // by piece; nil for the loader
}

// open opens the files of the plan.
func (p *Plan) open() (*image, error) {
	im := &image{Plan: p, files: make([]*os.File, len(p.pieces))}
	for i, pc := range p.pieces {
		if pc.data != nil {
			continue
		}
		f, err := os.Open(pc.path)
		if err != nil {
			im.Close()
			return nil, err
		}
		im.files[i] = f
	}
	return im, nil
}

// Close closes the files.
func (im *image) Close() {
	for _, f := range im.files {
		if f != nil {
			f.Close()
		}
	}
}

// block reads block n: its load address and data.
func (im *image) block(n uint32, bs int) (uint32, []byte, error) {
	for i, pc := range im.pieces {
		b := blocks(pc, bs)
		if n >= b {
			n -= b
			continue
		}
		off := int64(n) * int64(bs)
		size := min(int64(bs), pc.size-off)
		load := pc.load + uint32(off)
		if pc.data != nil {
			return load, pc.data[off : off+size], nil
		}
		buf := make([]byte, size)
		if _, err := im.files[i].ReadAt(buf, off); err != nil {
			return 0, nil, fmt.Errorf("%s: %w", pc.path, err)
		}
		return load, buf, nil
	}
	return 0, nil, fmt.Errorf("block %d is past the end", n)
}
