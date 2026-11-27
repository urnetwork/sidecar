//go:build !ios_extension && !sidecar_http && !darwin && !linux

// A file's stat values as git keeps them in an index entry, on the legs whose file information carries no unix
// stat_t this code reads (windows, js): its size and mtime alone, the mtime standing for the ctime, as git for
// Windows keeps them.

package sidecar

import (
	"io/fs"
)

// The stat values of info, an Lstat's answer.
func gitStatDataOf(info fs.FileInfo) GitStatData {
	return gitStatDataPortable(info)
}
