package nfs

import (
	"io/fs"
	"syscall"
	"time"
)

func sysStat(fi fs.FileInfo, s *stat) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	s.ino, s.nlink, s.uid, s.gid = st.Ino, uint32(st.Nlink), st.Uid, st.Gid
	s.rdev, s.blocks = uint32(st.Rdev), uint64(st.Blocks)
	s.atime = time.Unix(st.Atim.Unix())
	s.ctime = time.Unix(st.Ctim.Unix())
}
