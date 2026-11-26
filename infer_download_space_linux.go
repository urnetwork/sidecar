//go:build linux && !ios_extension && !sidecar_http

// The room a model download checks for (DESIGN-COMPUTE §6.5) on Linux and Android: statfs's blocks free to this
// process, times the fragment size it counts them in, or its block size where it reports no fragment size.

package sidecar

import (
	"golang.org/x/sys/unix"
)

// The bytes free to this process on directory's volume.
func inferDownloadFreeByteCount(directory string) (int64, error) {
	stat := unix.Statfs_t{}
	if err := unix.Statfs(directory, &stat); err != nil {
		return 0, err
	}
	blockByteCount := uint64(stat.Frsize)
	if blockByteCount == 0 {
		blockByteCount = uint64(stat.Bsize)
	}
	return inferDownloadByteCountOf(stat.Bavail, blockByteCount), nil
}
