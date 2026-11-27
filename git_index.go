//go:build !ios_extension && !sidecar_http

// The worktree's index (DESIGN-COMPUTE §13.4's workspace row; GIT-M13-01): git's .git/index at version 2, which
// stock git reads and writes, byte for byte as its update-index writes one:
//
//	header    "DIRC", the version 2 and the entry count, each 32 bits big-endian
//	entries   in git's order, by path bytes then stage: ctime and mtime (seconds, nanoseconds), dev, ino, mode, uid,
//	          gid and size, each 32 bits, git truncating the stat values to 32; the oid; 16 bits of flags (assume-valid,
//	          extended, which version 2 holds 0, the stage, and the path's length, 0xfff for 4095 bytes or more); the
//	          path; then 1 to 8 NULs, so each entry is a multiple of 8 bytes
//	trailer   the SHA-1 of everything before it (or, from stock git's index.skipHash, 20 zero bytes, which reads too)
//
// Extensions: none is written. A read skips the optional ones stock git may have added (a first letter A-Z: the cache
// tree, the untracked cache, the end-of-entries marker) and refuses a required one (split index, sparse directories),
// which this index cannot keep. Versions 3 and 4 are refused, so a sparse or skip-worktree index of stock git's is
// not misread.
//
// The assume-valid bit is the mark §13.4's collisions row and GIT-M13-02's sparse checkout put on an entry whose file
// the worktree does not hold by design: the losing side of a folding collision, or a path outside the sparse prefix.
// Status takes a missing file there as unchanged, as stock git does for an assume-unchanged entry, so neither reports
// it deleted. Version 2 has no skip-worktree bit, which is why a sparse or lazily fetched worktree does not open in
// stock git (D-GIT-1).
//
// A read holds every entry to gitCheckPath and to the modes an index holds, refuses entries out of order, twice or
// a path that is both a file and a directory, and holds the whole file to GitSettings.IndexByteCount and
// FileCount. A GitIndex is not safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
)

// The index's name, its lock's, and the format's fixed parts.
const (
	gitIndexName          = ".git/index"
	gitIndexLockName      = ".git/index.lock"
	gitIndexSignature     = "DIRC"
	gitIndexVersion       = 2
	gitIndexHeaderSize    = 12
	gitIndexEntryFixed    = 62
	gitIndexNameMask      = 0x0fff
	gitIndexStageShift    = 12
	gitIndexStageMask     = 0x3000
	gitIndexExtendedFlag  = 0x4000
	gitIndexAssumeValid   = 0x8000
	gitIndexExtensionHead = 8
)

// An index that does not read as one this git keeps: refused, never repaired.
var ErrGitIndexInvalid = errors.New("git: an index ur git does not read")

// A file's stat values as git keeps them in an entry, each truncated to 32 bits.
type GitStatData struct {
	CtimeSeconds     uint32
	CtimeNanoseconds uint32
	MtimeSeconds     uint32
	MtimeNanoseconds uint32
	Dev              uint32
	Ino              uint32
	Uid              uint32
	Gid              uint32
	Size             uint32
}

// git's munge_st_size: a size truncated to 32 bits, a nonzero size that truncates to 0 kept as 0x80000000, so it never
// reads as empty.
func gitStatSize(size int64) uint32 {
	truncated := uint32(size)
	if truncated == 0 && size != 0 {
		return 0x80000000
	}
	return truncated
}

// One entry of the index.
type GitIndexEntry struct {
	// Names joined by '/', raw bytes held in a string.
	Path string
	// 100644, 100755, 120000 or 160000, as git keeps a mode in its index.
	Mode uint32
	Oid  EvsGitOid
	// 0, or 1 to 3 for a conflict's base, ours and theirs.
	Stage int
	// The assume-valid bit: the worktree holds no file here by design (see the file header).
	Unwritten bool
	Stat      GitStatData
}

// The index's entries, in git's order.
type GitIndex struct {
	Entries []*GitIndexEntry
}

// git's index order: path bytes, then stage.
func gitIndexEntryCompare(a *GitIndexEntry, b *GitIndexEntry) int {
	if order := strings.Compare(a.Path, b.Path); order != 0 {
		return order
	}
	return a.Stage - b.Stage
}

// The mode git keeps in its index for a tree entry's mode (create_ce_mode): a regular file's 100755 or 100644 by its
// owner's execute bit, 100664 among them read as 100644.
func gitIndexMode(mode uint32) uint32 {
	switch EvsGitCanonMode(mode) {
	case EvsGitModeExecutable:
		return EvsGitModeExecutable
	case EvsGitModeFile, EvsGitModeFileGroupWritable:
		return EvsGitModeFile
	}
	return EvsGitCanonMode(mode)
}

// Whether mode is one an index entry holds.
func gitIndexModeValid(mode uint32) bool {
	switch mode {
	case EvsGitModeFile, EvsGitModeExecutable, EvsGitModeSymlink, EvsGitModeGitlink:
		return true
	}
	return false
}

// The entry at path and stage, nil for none.
func (self *GitIndex) Entry(path string, stage int) *GitIndexEntry {
	probe := &GitIndexEntry{Path: path, Stage: stage}
	index, found := slices.BinarySearchFunc(self.Entries, probe, gitIndexEntryCompare)
	if !found {
		return nil
	}
	return self.Entries[index]
}

// Every entry of path, its stages in order.
func (self *GitIndex) Stages(path string) []*GitIndexEntry {
	start, _ := slices.BinarySearchFunc(self.Entries, &GitIndexEntry{Path: path}, gitIndexEntryCompare)
	stages := []*GitIndexEntry{}
	for index := start; index < len(self.Entries) && self.Entries[index].Path == path; index += 1 {
		stages = append(stages, self.Entries[index])
	}
	return stages
}

// Puts entry in its place, replacing one of its path and stage. A stage-0 entry replaces its path's conflict stages,
// and a conflict stage its path's stage 0, as git's add does. Refused: an unsafe path, a mode an index does not hold,
// a path a file entry already holds as a directory or a directory entry's prefix holds as a file (git's
// check_file_directory_conflict), which the caller removes first.
func (self *GitIndex) Set(entry *GitIndexEntry) error {
	if err := gitCheckPath(entry.Path, entry.Mode); err != nil {
		return err
	}
	if !gitIndexModeValid(entry.Mode) || entry.Stage < 0 || 3 < entry.Stage {
		return fmt.Errorf("%w: an entry of mode %o stage %d", ErrGitIndexInvalid, entry.Mode, entry.Stage)
	}
	// a file of a directory's name above it, or entries below it
	for prefix := entry.Path; ; {
		slash := strings.LastIndexByte(prefix, '/')
		if slash < 0 {
			break
		}
		prefix = prefix[:slash]
		if 0 < len(self.Stages(prefix)) {
			return fmt.Errorf("%w: a path under a file's name", ErrGitIndexInvalid)
		}
	}
	below, _ := slices.BinarySearchFunc(self.Entries, &GitIndexEntry{Path: entry.Path + "/"}, gitIndexEntryCompare)
	if below < len(self.Entries) && strings.HasPrefix(self.Entries[below].Path, entry.Path+"/") {
		return fmt.Errorf("%w: a file of a directory's name", ErrGitIndexInvalid)
	}
	kept := self.Entries[:0:0]
	for _, held := range self.Entries {
		if held.Path == entry.Path && (held.Stage == entry.Stage || held.Stage == 0 || entry.Stage == 0) {
			continue
		}
		kept = append(kept, held)
	}
	index, _ := slices.BinarySearchFunc(kept, entry, gitIndexEntryCompare)
	self.Entries = slices.Insert(kept, index, entry)
	return nil
}

// Removes every stage of path; false when it held none.
func (self *GitIndex) Remove(path string) bool {
	before := len(self.Entries)
	self.Entries = slices.DeleteFunc(self.Entries, func(entry *GitIndexEntry) bool { return entry.Path == path })
	return len(self.Entries) != before
}

// Whether any path holds a conflict stage.
func (self *GitIndex) Conflicted() bool {
	return slices.ContainsFunc(self.Entries, func(entry *GitIndexEntry) bool { return entry.Stage != 0 })
}

// The index's bytes: see the file header. Refuses an entry the format cannot hold, out of order or twice.
func (self *GitIndex) Encode() ([]byte, error) {
	encoded := make([]byte, 0, gitIndexHeaderSize+len(self.Entries)*(gitIndexEntryFixed+32)+sha1.Size)
	encoded = append(encoded, gitIndexSignature...)
	encoded = binary.BigEndian.AppendUint32(encoded, gitIndexVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.Entries)))
	for index, entry := range self.Entries {
		if 0 < index && 0 <= gitIndexEntryCompare(self.Entries[index-1], entry) {
			return nil, fmt.Errorf("%w: entries out of git's order or twice", ErrGitIndexInvalid)
		}
		if !gitIndexModeValid(entry.Mode) || entry.Stage < 0 || 3 < entry.Stage || entry.Path == "" ||
			strings.IndexByte(entry.Path, 0) != -1 {
			return nil, fmt.Errorf("%w: an entry the format cannot hold", ErrGitIndexInvalid)
		}
		stat := entry.Stat
		for _, value := range []uint32{
			stat.CtimeSeconds, stat.CtimeNanoseconds, stat.MtimeSeconds, stat.MtimeNanoseconds, stat.Dev, stat.Ino,
			entry.Mode, stat.Uid, stat.Gid, stat.Size,
		} {
			encoded = binary.BigEndian.AppendUint32(encoded, value)
		}
		encoded = append(encoded, entry.Oid[:]...)
		flags := uint16(min(len(entry.Path), gitIndexNameMask)) | uint16(entry.Stage)<<gitIndexStageShift
		if entry.Unwritten {
			flags |= gitIndexAssumeValid
		}
		encoded = binary.BigEndian.AppendUint16(encoded, flags)
		encoded = append(encoded, entry.Path...)
		size := gitIndexEntryFixed + len(entry.Path)
		padding := (size+8)&^7 - size
		encoded = append(encoded, make([]byte, padding)...)
	}
	trailer := sha1.Sum(encoded)
	return append(encoded, trailer[:]...), nil
}

// An index from its bytes, held to the file header's rules: entries past FileCount, a version but 2, a required
// extension, a bad trailer, an unsafe path, a bad mode or order all refused.
func GitIndexDecode(encoded []byte, settings *GitSettings) (*GitIndex, error) {
	refused := func(what string) error {
		return fmt.Errorf("%w: %s", ErrGitIndexInvalid, what)
	}
	if int64(len(encoded)) > settings.IndexByteCount {
		return nil, fmt.Errorf("%w: an index past %d bytes", ErrGitFileTooLarge, settings.IndexByteCount)
	}
	if len(encoded) < gitIndexHeaderSize+sha1.Size || string(encoded[:4]) != gitIndexSignature {
		return nil, refused("no index header")
	}
	version := binary.BigEndian.Uint32(encoded[4:8])
	if version != gitIndexVersion {
		return nil, refused(fmt.Sprintf("an index of version %d, where ur git reads version 2 alone", version))
	}
	body := encoded[:len(encoded)-sha1.Size]
	trailer := encoded[len(encoded)-sha1.Size:]
	if sum := sha1.Sum(body); !bytes.Equal(trailer, sum[:]) && !bytes.Equal(trailer, make([]byte, sha1.Size)) {
		return nil, refused("its trailer is not its hash")
	}
	count := binary.BigEndian.Uint32(encoded[8:12])
	if uint64(settings.FileCount) < uint64(count) {
		return nil, refused(fmt.Sprintf("%d entries, past %d", count, settings.FileCount))
	}
	index := &GitIndex{Entries: make([]*GitIndexEntry, 0, count)}
	// every path read so far, so a path under one is refused whatever lies between them
	paths := map[string]bool{}
	rest := body[gitIndexHeaderSize:]
	for range count {
		if len(rest) < gitIndexEntryFixed+1 {
			return nil, refused("an entry cut short")
		}
		values := make([]uint32, 10)
		for at := range values {
			values[at] = binary.BigEndian.Uint32(rest[at*4:])
		}
		entry := &GitIndexEntry{
			Stat: GitStatData{
				CtimeSeconds: values[0], CtimeNanoseconds: values[1], MtimeSeconds: values[2], MtimeNanoseconds: values[3],
				Dev: values[4], Ino: values[5], Uid: values[7], Gid: values[8], Size: values[9],
			},
			Mode: values[6],
		}
		copy(entry.Oid[:], rest[40:60])
		flags := binary.BigEndian.Uint16(rest[60:62])
		if flags&gitIndexExtendedFlag != 0 {
			return nil, refused("an extended entry, which version 2 holds none of")
		}
		entry.Stage = int(flags&gitIndexStageMask) >> gitIndexStageShift
		entry.Unwritten = flags&gitIndexAssumeValid != 0
		nameLength := int(flags & gitIndexNameMask)
		nul := bytes.IndexByte(rest[gitIndexEntryFixed:], 0)
		if nul < 0 || (nameLength < gitIndexNameMask && nul != nameLength) || (nameLength == gitIndexNameMask && nul < nameLength) {
			return nil, refused("an entry's path does not end where its length says")
		}
		entry.Path = string(rest[gitIndexEntryFixed : gitIndexEntryFixed+nul])
		size := gitIndexEntryFixed + nul
		padded := (size + 8) &^ 7
		if len(rest) < padded || !bytes.Equal(rest[size:padded], make([]byte, padded-size)) {
			return nil, refused("an entry's padding is not NULs")
		}
		if !gitIndexModeValid(entry.Mode) {
			return nil, refused(fmt.Sprintf("an entry of mode %o", entry.Mode))
		}
		if err := gitCheckPath(entry.Path, entry.Mode); err != nil {
			return nil, err
		}
		if 0 < len(index.Entries) {
			previous := index.Entries[len(index.Entries)-1]
			if 0 <= gitIndexEntryCompare(previous, entry) {
				return nil, refused("entries out of git's order or twice")
			}
			if previous.Path == entry.Path && (previous.Stage == 0 || entry.Stage == 0) {
				return nil, refused("a path both merged and in conflict")
			}
		}
		for prefix := entry.Path; strings.LastIndexByte(prefix, '/') != -1; {
			prefix = prefix[:strings.LastIndexByte(prefix, '/')]
			if paths[prefix] {
				return nil, refused("a path that is both a file and a directory")
			}
		}
		paths[entry.Path] = true
		index.Entries = append(index.Entries, entry)
		rest = rest[padded:]
	}
	for 0 < len(rest) {
		if len(rest) < gitIndexExtensionHead {
			return nil, refused("an extension cut short")
		}
		signature := rest[:4]
		size := binary.BigEndian.Uint32(rest[4:8])
		if uint64(len(rest)-gitIndexExtensionHead) < uint64(size) {
			return nil, refused("an extension past the index's end")
		}
		if signature[0] < 'A' || 'Z' < signature[0] {
			return nil, refused("a required extension ur git does not read")
		}
		rest = rest[gitIndexExtensionHead+int(size):]
	}
	return index, nil
}

// The stat values every file information carries: its size and mtime, the mtime standing for the ctime.
func gitStatDataPortable(info fs.FileInfo) GitStatData {
	modified := info.ModTime()
	return GitStatData{
		CtimeSeconds: uint32(modified.Unix()), CtimeNanoseconds: uint32(modified.Nanosecond()),
		MtimeSeconds: uint32(modified.Unix()), MtimeNanoseconds: uint32(modified.Nanosecond()),
		Size: gitStatSize(info.Size()),
	}
}
