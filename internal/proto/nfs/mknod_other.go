//go:build !linux

package nfs

import (
	"errors"
	"os"
)

// mknodAt is not available here: device nodes and fifos are kept in the
// spec.
func mknodAt(*os.File, string, uint32, uint32, uint32) error { return errors.ErrUnsupported }
