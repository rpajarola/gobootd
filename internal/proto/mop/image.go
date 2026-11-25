package mop

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// image is a boot image as it is loaded into the client's memory: a
// contiguous range from load, made of pieces of the file and zeros.
type image struct {
	format     string
	load, xfer uint32
	segs       []segment
	size       int64
}

// segment is a piece of the image: n bytes of the file from offset file, or
// n zeros if file is negative.
type segment struct {
	file, n int64
}

func (im *image) add(file, n int64) {
	if n > 0 {
		im.segs = append(im.segs, segment{file, n})
		im.size += n
	}
}

// readAt reads the image from offset off.
func (im *image) readAt(r io.ReaderAt, b []byte, off int64) (int, error) {
	done := 0
	pos := int64(0)
	for _, s := range im.segs {
		if done == len(b) {
			break
		}
		if off+int64(done) >= pos+s.n {
			pos += s.n
			continue
		}
		in := off + int64(done) - pos
		chunk := b[done:min(len(b), done+int(s.n-in))]
		if s.file < 0 {
			clear(chunk)
		} else if n, err := r.ReadAt(chunk, s.file+in); n < len(chunk) {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return done + n, err
		}
		done += len(chunk)
		pos += s.n
	}
	return done, nil
}

func (im *image) String() string {
	return fmt.Sprintf("%s image, %d bytes at %#x, transfer address %#x", im.format, im.size, im.load, im.xfer)
}

var errFormat = errors.New("not an ELF, a.out or MOP image")

// loadImage works out how to load a file, as NetBSD's mopd does: ELF32
// and a.out files are loaded from address 0 (their boot programs relocate
// themselves) with their segments padded to their place in memory, and
// MOP images (VMS system images, with a 512-byte header) at their load
// address.
func loadImage(r io.ReaderAt, size int64) (*image, error) {
	var hdr [512]byte
	n, _ := r.ReadAt(hdr[:], 0)
	switch {
	case n >= 4 && bytes.Equal(hdr[:4], []byte(elf.ELFMAG)):
		return loadELF(r)
	case n >= 32:
		if im, ok := loadAout(hdr[:32], size); ok {
			return im, nil
		}
	}
	if n == len(hdr) {
		return loadMOP(hdr[:], size)
	}
	return nil, errFormat
}

func loadELF(r io.ReaderAt) (*image, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	if f.Class != elf.ELFCLASS32 {
		return nil, fmt.Errorf("%v ELF files are not supported", f.Class)
	}
	var progs []*elf.Prog
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Memsz > 0 {
			progs = append(progs, p)
		}
	}
	if len(progs) == 0 {
		return nil, errors.New("ELF file has nothing to load")
	}
	sort.Slice(progs, func(i, j int) bool { return progs[i].Vaddr < progs[j].Vaddr })
	im := &image{format: fmt.Sprintf("ELF (%v)", f.Machine), xfer: uint32(f.Entry)}
	for i, p := range progs {
		if p.Filesz > p.Memsz {
			return nil, errors.New("ELF segment larger in the file than in memory")
		}
		end := p.Vaddr + p.Memsz
		if i+1 < len(progs) {
			if end > progs[i+1].Vaddr {
				return nil, errors.New("ELF segments overlap")
			}
			end = progs[i+1].Vaddr
		}
		im.add(int64(p.Off), int64(p.Filesz))
		im.add(-1, int64(end-p.Vaddr-p.Filesz))
	}
	if im.size > 1<<32 {
		return nil, errors.New("ELF image larger than 4 GB")
	}
	return im, nil
}

// a.out machine IDs and their page sizes, which segments are padded to.
var aoutMachines = map[uint32]struct {
	name   string
	page   uint32
	little bool
}{
	134: {"i386", 4096, true},
	135: {"m68k", 8192, false},
	136: {"m68k4k", 4096, false},
	137: {"ns32532", 4096, true},
	138: {"sparc", 8192, false},
	139: {"pmax", 4096, true},
	140: {"vax1k", 1024, true},
	141: {"alpha", 8192, true},
	142: {"mips", 4096, false},
	143: {"arm6", 4096, true},
	150: {"vax", 4096, true},
}

const (
	omagic = 0o407
	nmagic = 0o410
	zmagic = 0o413
	qmagic = 0o314
)

// loadAout loads a.out files with a machine ID (NetBSD's format). Text
// follows the 32-byte header, then data; with NMAGIC and ZMAGIC, text,
// data and bss are each padded to a page.
func loadAout(h []byte, size int64) (*image, bool) {
	midmag := binary.BigEndian.Uint32(h)
	mid, magic := midmag>>16&0x3ff, midmag&0xffff
	m, ok := aoutMachines[mid]
	if !ok {
		midmag = binary.LittleEndian.Uint32(h)
		mid, magic = midmag>>16&0x3ff, midmag&0xffff
		if m, ok = aoutMachines[mid]; !ok {
			return nil, false
		}
	}
	switch magic {
	case omagic, nmagic, zmagic, qmagic:
	default:
		return nil, false
	}
	var bo binary.ByteOrder = binary.BigEndian
	if m.little {
		bo = binary.LittleEndian
	}
	text, data, bss, entry := bo.Uint32(h[4:]), bo.Uint32(h[8:]), bo.Uint32(h[12:]), bo.Uint32(h[20:])
	if 32+int64(text)+int64(data) > size {
		return nil, false
	}
	fill := func(n uint32) int64 {
		if magic != zmagic && magic != nmagic {
			return 0
		}
		return int64((m.page - n%m.page) % m.page)
	}
	im := &image{format: "a.out (" + m.name + ")", xfer: entry}
	im.add(32, int64(text))
	im.add(-1, fill(text))
	im.add(32+int64(text), int64(data))
	im.add(-1, fill(data))
	im.add(-1, int64(bss))
	if magic == zmagic || magic == nmagic {
		im.add(-1, fill(bss))
	} else {
		im.add(-1, int64((m.page-(text+data+bss)%m.page)%m.page))
	}
	return im, true
}

// Image header fields of MOP images.
const (
	ihdSize      = 0   // word: offset of the image section descriptor
	ihdActivOff  = 2   // word: offset of the activation data
	ihdHdrBlkCnt = 16  // byte: header blocks
	ihdAlias     = 510 // word: image type
	isdPagCnt    = 2   // word: pages
	isdVPN       = 4   // word: virtual page number
	ihaTfrAdr1   = 0   // long: transfer address
	eihdIsdOff   = 12  // long: Alpha image section descriptor offset
	eihdHdrBlk   = 76  // long: Alpha header blocks
	lBSA         = 0x08
	lBXFR        = 0xe8
	lBBLK        = 0xf0
)

// loadMOP loads a MOP image: a VAX, PMAX or Alpha system image or an RSX
// task image, whose header gives the load and transfer addresses.
func loadMOP(h []byte, size int64) (*image, error) {
	le16 := func(o int) uint32 { return uint32(binary.LittleEndian.Uint16(h[o:])) }
	le32 := func(o int) uint32 {
		if o < 0 || o+4 > len(h) {
			return 0
		}
		return binary.LittleEndian.Uint32(h[o:])
	}
	var im image
	var blocks uint32
	switch int16(le16(ihdAlias)) {
	case -1, 4: // VAX, PMAX
		isd, iha := int(le16(ihdSize)), int(le16(ihdActivOff))
		if isd+8 > len(h) || iha+4 > len(h) {
			return nil, errors.New("MOP image header is corrupt")
		}
		blocks = uint32(h[ihdHdrBlkCnt])
		im.load, im.xfer = le16(isd+isdVPN)*512, le32(iha+ihaTfrAdr1)
		im.format = "MOP (PMAX)"
		if int16(le16(ihdAlias)) == -1 {
			im.format = "MOP (VAX)"
			im.load = le32(isd+isdVPN) & 0x1fffff * 512
			im.xfer &= 0x7fffffff
		}
	case 0:
		im.format = "MOP (RSX)"
		blocks = le16(lBBLK)
		im.load, im.xfer = le16(lBSA), le16(lBXFR)
	case 5:
		im.format = "MOP (Alpha)"
		blocks = le32(eihdHdrBlk)
	default:
		return nil, errFormat
	}
	off := int64(max(blocks, 1)) * 512
	if off > size {
		return nil, errors.New("MOP image header is larger than the file")
	}
	im.add(off, size-off)
	return &im, nil
}
