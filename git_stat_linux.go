//go:build !ios_extension && !sidecar_http

// A file's stat values as git keeps them in an index entry (git's fill_stat_data), on linux and android: each
// truncated to 32 bits, the nanoseconds kept, as a git built with USE_NSEC keeps them.

package sidecar

import (
	"io/fs"
	"syscall"
)

// The stat values of info, an Lstat's answer; only its size and mtime where it carries no stat_t.
func gitStatDataOf(info fs.FileInfo) GitStatData {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return gitStatDataPortable(info)
	}
	return GitStatData{
		CtimeSeconds: uint32(stat.Ctim.Sec), CtimeNanoseconds: uint32(stat.Ctim.Nsec),
		MtimeSeconds: uint32(stat.Mtim.Sec), MtimeNanoseconds: uint32(stat.Mtim.Nsec),
		Dev: uint32(stat.Dev), Ino: uint32(stat.Ino), Uid: stat.Uid, Gid: stat.Gid, Size: gitStatSize(stat.Size),
	}
}
