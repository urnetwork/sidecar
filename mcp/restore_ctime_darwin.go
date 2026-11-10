//go:build darwin && !ios

// A file's ctime on darwin, for §16.7's start_ns rule.

package mcp

import (
	"os"
	"syscall"
)

// The file's change time in nanoseconds since the epoch, and whether the system reports one.
func restoreChangeTimeNs(info os.FileInfo) (int64, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Ctimespec.Sec*1e9 + stat.Ctimespec.Nsec, true
}
