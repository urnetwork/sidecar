//go:build darwin && !ios_extension && !sidecar_http

// The room a model download checks for (DESIGN-COMPUTE §6.5) on macOS and iOS: statfs's blocks free to this process,
// times the volume's block size.

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
	return inferDownloadByteCountOf(stat.Bavail, uint64(stat.Bsize)), nil
}
