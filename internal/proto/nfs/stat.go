package nfs

import (
	"io/fs"
	"time"
)

// stat is what NFS reports about a file beyond fs.FileInfo.
type stat struct {
	ino          uint64
	nlink        uint32
	uid, gid     uint32
	rdev         uint32
	blocks       uint64 // 512-byte blocks
	atime, ctime time.Time
}

// statOf returns the system specific details of fi, with defaults for what
// the platform does not provide.
func statOf(fi fs.FileInfo) stat {
	if i, ok := fi.(*info); ok {
		return i.st
	}
	s := stat{nlink: 1, atime: fi.ModTime(), ctime: fi.ModTime(), blocks: uint64(fi.Size()+511) / 512}
	sysStat(fi, &s)
	return s
}
