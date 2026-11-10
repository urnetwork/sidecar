// Directory deltas (§11.7's directory and name rows): a push's directory change is a delta {names added, child tokens
// removed}, which evs merges without a path-level CAS, since each child's own path is checked, but for the two-way
// check of a removed directory. A row is the child's token, its kind and its name sealed alone under manifest_p of
// the path epoch whose tokens it uses (evs_name.go), so a reader checks each name against its token.
//
// For each directory below the root that a plan's writes reach: one the plan creates a child under takes a row for
// it, and a removed child's token leaves its table; a directory that does not stand is created (base 0, at
// max(b, m) + 1, m its standing removal's version) with the rows, and its own parent takes a row for it in turn, the
// deepest first so each creation reaches the parent above it; a standing one takes a delta on its newest version,
// at base + 1, as replaying readers hold every path to (evs_replay.go). A child created under a path that stands as a
// file is refused, as git would.
//
// The root, path "" with the empty token path, takes the top-level names' rows as any directory takes its children's,
// sealed under parent t_0 (question evs1-m2-24-root-directory-names, option 1; DESIGN-DETAILS 9.2.8): a top-level
// creation or removal gives it a delta, the first one creating it, and nothing holds the root itself. A directory
// whose last child goes stays, empty, until it is removed itself.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// A directory below the root as a plan's read found it.
type evsDirectoryRead struct {
	path      string
	tokenPath EvsTokenPath
	// it stands as a directory, or as a file
	directory bool
	file      bool
	// its newest version while it stands, and its standing removal's version while it does not
	version        uint64
	removalVersion uint64
	// the version it stands at, for history walks
	prevPushId        []byte
	prevCommitVersion uint64
}

// A read directory's state.
func evsDirectoryReadOf(readPath *evsReadPath, verified *EvsVerifiedPath) *evsDirectoryRead {
	read := &evsDirectoryRead{path: readPath.path, tokenPath: readPath.current}
	switch {
	case verified.Entry != nil && verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY):
		read.directory = true
		read.version = evsVerifiedNewestVersion(verified)
		read.prevPushId = verified.Statement.Push.GetPushId()
		read.prevCommitVersion = verified.CommitVersion
	case verified.Entry != nil:
		read.file = true
	case verified.Removal != nil:
		read.removalVersion = verified.Removal.GetPathVersion()
	}
	return read
}

// What one directory's delta does to one child.
type evsChildChange struct {
	name    []byte
	token   EvsToken
	kind    protocol.EvsEntryKind
	removed bool
}

// A directory's depth, the root's -1, so the root takes its delta after every top-level directory it may create.
func evsDirectoryDepth(path string) int {
	if path == "" {
		return -1
	}
	return strings.Count(path, "/")
}

// The path's parent, "" at the top for the root, and its own last name.
func evsSplitParent(path string) (string, []byte) {
	index := strings.LastIndexByte(path, '/')
	if index < 0 {
		return "", []byte(path)
	}
	return path[:index], []byte(path[index+1:])
}

// The directory changes a plan's written paths need: see the file header.
func evsDirectoryChanges(plan *EvsWritePlan, planned map[string]*EvsPlannedPath, directories map[string]*evsDirectoryRead, nameKey *EvsManifestKey) ([]*EvsPlannedPath, error) {
	parentChildren := map[string][]*evsChildChange{}
	note := func(path string, tokenPath EvsTokenPath, kind protocol.EvsEntryKind, removed bool) {
		if path == "" {
			// the root, which no directory holds
			return
		}
		parent, name := evsSplitParent(path)
		parentChildren[parent] = append(parentChildren[parent], &evsChildChange{name: name, token: tokenPath.Last(), kind: kind, removed: removed})
	}
	for path, change := range planned {
		switch {
		case change.Remove:
			note(path, change.TokenPath, change.Kind, true)
		case change.BaseEntryVersion == 0:
			note(path, change.TokenPath, change.Kind, false)
		}
	}
	changes := []*EvsPlannedPath{}
	for 0 < len(parentChildren) {
		// the deepest parent first, so a directory it creates reaches the parent above it
		parents := make([]string, 0, len(parentChildren))
		for parent := range parentChildren {
			parents = append(parents, parent)
		}
		slices.SortFunc(parents, func(a string, b string) int {
			if depth := evsDirectoryDepth(b) - evsDirectoryDepth(a); depth != 0 {
				return depth
			}
			return strings.Compare(a, b)
		})
		parent := parents[0]
		children := parentChildren[parent]
		delete(parentChildren, parent)
		read := directories[parent]
		if read == nil {
			return nil, fmt.Errorf("%w: a parent directory the read did not reach", ErrEvsWriteInvalid)
		}
		if read.file {
			return nil, fmt.Errorf("%w: a path created under a file", ErrEvsPathKind)
		}
		change := &EvsPlannedPath{Path: parent, TokenPath: read.tokenPath, Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY}
		for _, child := range children {
			if child.removed {
				change.RemovedTokens = append(change.RemovedTokens, child.token.Bytes())
				continue
			}
			sealedName, err := EvsNameSeal(nameKey, read.tokenPath.Last(), child.token, child.name)
			if err != nil {
				return nil, err
			}
			change.Names = append(change.Names, &protocol.EvsName{Token: child.token.Bytes(), Kind: uint32(child.kind), SealedName: sealedName})
		}
		slices.SortFunc(change.Names, func(a *protocol.EvsName, b *protocol.EvsName) int {
			return strings.Compare(string(a.GetToken()), string(b.GetToken()))
		})
		if read.directory {
			change.BaseEntryVersion = read.version
			change.Version = read.version + 1
			change.PrevPushId = read.prevPushId
			change.PrevCommitVersion = read.prevCommitVersion
		} else {
			if len(change.Names) == 0 {
				return nil, fmt.Errorf("%w: a removal under a directory that does not stand", ErrEvsWriteInvalid)
			}
			change.RemovedTokens = nil
			change.Version = max(plan.BaseVersion, read.removalVersion) + 1
			note(parent, read.tokenPath, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, false)
		}
		changes = append(changes, change)
	}
	return changes, nil
}
