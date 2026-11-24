package nfs

import (
	"os"

	"golang.org/x/sys/unix"
)

// mknodAt makes a device node or fifo name in directory d.
func mknodAt(d *os.File, name string, mode, major, minor uint32) error {
	err := unix.Mknodat(int(d.Fd()), name, mode, int(unix.Mkdev(major, minor)))
	if err != nil {
		return &os.PathError{Op: "mknod", Path: name, Err: err}
	}
	return nil
}
