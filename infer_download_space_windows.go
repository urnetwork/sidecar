//go:build windows && !ios_extension && !sidecar_http

// The room a model download checks for (DESIGN-COMPUTE §6.5) on Windows: GetDiskFreeSpaceEx's bytes free to this
// process, which a quota lowers.

package sidecar

import (
	"golang.org/x/sys/windows"
)

// The bytes free to this process on directory's volume.
func inferDownloadFreeByteCount(directory string) (int64, error) {
	name, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		return 0, err
	}
	freeByteCount := uint64(0)
	if err := windows.GetDiskFreeSpaceEx(name, &freeByteCount, nil, nil); err != nil {
		return 0, err
	}
	return inferDownloadByteCountOf(freeByteCount, 1), nil
}
