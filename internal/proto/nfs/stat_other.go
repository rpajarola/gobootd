//go:build !darwin && !linux

package nfs

import "io/fs"

func sysStat(fs.FileInfo, *stat) {}
