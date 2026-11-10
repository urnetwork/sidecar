//go:build linux && !android

// A file's ctime on linux, for §16.7's start_ns rule.

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
	return stat.Ctim.Sec*1e9 + stat.Ctim.Nsec, true
}
