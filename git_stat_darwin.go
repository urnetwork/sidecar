//go:build !ios_extension && !sidecar_http

// A file's stat values as git keeps them in an index entry (git's fill_stat_data), on darwin and ios: each truncated
// to 32 bits, the nanoseconds kept, as a git built with USE_NSEC keeps them.

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
		CtimeSeconds: uint32(stat.Ctimespec.Sec), CtimeNanoseconds: uint32(stat.Ctimespec.Nsec),
		MtimeSeconds: uint32(stat.Mtimespec.Sec), MtimeNanoseconds: uint32(stat.Mtimespec.Nsec),
		Dev: uint32(stat.Dev), Ino: uint32(stat.Ino), Uid: stat.Uid, Gid: stat.Gid, Size: gitStatSize(stat.Size),
	}
}
