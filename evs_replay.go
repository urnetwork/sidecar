// What a reader checks across a ref's statements, beyond each one's signature and ref rules (§11.8's replay row,
// §11.7's mode and versions rows, I-16): rules a head reader applies to every walk, and the per-path version rules a
// replaying reader applies once it holds each push's entry versions.
//
// Every walk: a git-mode ref commits only on its tip, so each push's base_version is the version before it and its
// base_chain C there (TIP); a file-mode push is based at most 63 versions back (the 64-version bound) on a chain the
// walk holds; the ref's kind, mode and owner never change; the authorization and generation pins never fall, and an
// equal version carries an equal chain or commitment; the path epoch never falls, and only a PATH_EPOCH push moves it.
//
// With entry versions (EvsReplayPaths): a write's version is its base entry version + 1 and its base the path's
// newest; a creation's is max(b, m) + 1, b the push's base version and m the path's newest removal, so a path's
// versions never restart (I-EVS-8); a removal is one past the path's last; every entry names its own push. A replay
// that starts above version 0 cannot see a removal before it, and holds a creation only to at least b + 1. Removals
// of a directory reach its children through their own markers, which evs folds, so a child's m here is its own.
//
// A git-mode ref (NewEvsReplayPathsOfMode) holds a creation to exactly b + 1, its effective base being its own base
// under TIP, and takes a creation over a standing path of the other kind (DESIGN-DETAILS 8.2.2's kinds row).
//
// A failure raises evs_alarm version_rule, and the walk is refused.
//
// On every leg. EvsReplayPaths is not safe for concurrent use; the functions are.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.7's file-mode bound: a push may be based on any of the 64 versions up to the head it commits on.
const evsBaseVersionWindow = 63

// The rules every walk holds, from the chain at fromVersion on.
func evsCheckWalkRules(walked []*EvsVerifiedStatement, fromVersion uint64, fromChain [sha256.Size]byte) error {
	chainAt := func(version uint64) ([sha256.Size]byte, bool) {
		if version == fromVersion {
			return fromChain, true
		}
		if version < fromVersion || fromVersion+uint64(len(walked)) < version {
			return [sha256.Size]byte{}, false
		}
		return walked[version-fromVersion-1].Chain, true
	}
	var previous *protocol.EvsPush
	for _, statement := range walked {
		push := statement.Statement.Push
		version := statement.Version
		if version <= push.GetBaseVersion() {
			return fmt.Errorf("%w: a push at version %d based at %d", ErrEvsChainBroken, version, push.GetBaseVersion())
		}
		switch protocol.EvsRefMode(push.GetRefMode()) {
		case protocol.EvsRefMode_EVS_REF_GIT:
			if push.GetBaseVersion() != version-1 {
				return fmt.Errorf("%w: a git-mode push off the tip", ErrEvsChainBroken)
			}
		case protocol.EvsRefMode_EVS_REF_FILE:
			if push.GetBaseVersion()+evsBaseVersionWindow < version-1 {
				return fmt.Errorf("%w: a file-mode push past the 64-version bound", ErrEvsChainBroken)
			}
		default:
			return fmt.Errorf("%w: ref mode %d", ErrEvsChainBroken, push.GetRefMode())
		}
		if baseChain, ok := chainAt(push.GetBaseVersion()); ok {
			if push.GetBaseVersion() == 0 && len(push.GetBaseChain()) == 0 {
				// a ref's first push may name C_0 or none
			} else if !bytes.Equal(push.GetBaseChain(), baseChain[:]) {
				return fmt.Errorf("%w: a push based on a chain the ref never held", ErrEvsChainBroken)
			}
		}
		if previous != nil {
			if push.GetRefMode() != previous.GetRefMode() || push.GetRefKind() != previous.GetRefKind() ||
				!bytes.Equal(push.GetOwnerSidecarId(), previous.GetOwnerSidecarId()) {
				return fmt.Errorf("%w: a ref whose kind, mode or owner changed", ErrEvsChainBroken)
			}
			if err := evsCheckPinsRise(previous, push); err != nil {
				return err
			}
		}
		previous = push
	}
	return nil
}

// The pins and the path epoch from one committed push to the next never fall (§11.8's fence row, §11.6).
func evsCheckPinsRise(previous *protocol.EvsPush, push *protocol.EvsPush) error {
	switch {
	case push.GetAuth().GetVersion() < previous.GetAuth().GetVersion():
		return fmt.Errorf("%w: an authorization pin fell", ErrEvsChainBroken)
	case push.GetAuth().GetVersion() == previous.GetAuth().GetVersion() &&
		!bytes.Equal(push.GetAuth().GetChain(), previous.GetAuth().GetChain()):
		return fmt.Errorf("%w: one authorization version under two chains", ErrEvsChainBroken)
	case push.GetGeneration() < previous.GetGeneration():
		return fmt.Errorf("%w: a generation pin fell", ErrEvsChainBroken)
	case push.GetGeneration() == previous.GetGeneration() &&
		(!bytes.Equal(push.GetGroupId(), previous.GetGroupId()) ||
			!bytes.Equal(push.GetGenerationCommitment(), previous.GetGenerationCommitment())):
		return fmt.Errorf("%w: one generation under two commitments", ErrEvsChainBroken)
	case push.GetPathEpoch() < previous.GetPathEpoch():
		return fmt.Errorf("%w: a path epoch fell", ErrEvsChainBroken)
	case push.GetPathEpoch() != previous.GetPathEpoch() && push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) == 0:
		return fmt.Errorf("%w: a path epoch moved without a PATH_EPOCH push", ErrEvsChainBroken)
	}
	return nil
}

// One path's state in a replay.
type evsReplayPath struct {
	// its newest version, a removal's included
	version uint64
	removed bool
	// a directory's entry, else a file's
	directory bool
}

// The per-path version rules of a replaying reader over one ref, fed each committed push with its entry versions in
// order.
type EvsReplayPaths struct {
	// the replay started at version 0, so every removal is in view
	complete bool
	// a git-mode ref (DESIGN-DETAILS 8.2.2's kinds and versions rows): TIP makes every push's effective base its own
	// base b, so a creation is at exactly b + 1 whatever the replay saw before it, and a creation of the other kind
	// over a standing path is a path changing kind, not a conflict
	gitMode bool
	paths   map[string]*evsReplayPath
}

// A replay of a file-mode ref's statements after fromVersion.
func NewEvsReplayPaths(fromVersion uint64) *EvsReplayPaths {
	return NewEvsReplayPathsOfMode(fromVersion, protocol.EvsRefMode_EVS_REF_FILE)
}

// A replay of the statements after fromVersion of a ref of mode: a git-mode ref takes 8.2.2's kinds and versions rows.
func NewEvsReplayPathsOfMode(fromVersion uint64, mode protocol.EvsRefMode) *EvsReplayPaths {
	return &EvsReplayPaths{
		complete: fromVersion == 0, gitMode: mode == protocol.EvsRefMode_EVS_REF_GIT, paths: map[string]*evsReplayPath{},
	}
}

// Applies one verified push with the entry versions its changes name, by their entry_sha256: holds each change to
// §11.7's versions row and path-level CAS where the replay holds the path. entries maps a change's token path key
// to its EvsEntryVersion bytes; a removal has none.
func (self *EvsReplayPaths) Apply(statement *EvsVerifiedStatement, changes []*EvsCheckedChange, entries map[string][]byte) error {
	push := statement.Statement.Push
	for _, change := range changes {
		key := change.TokenPath.KeyString()
		held := self.paths[key]
		baseEntryVersion := change.Change.GetBaseEntryVersion()
		entryBytes, writes := entries[key]
		if writes != (len(change.Change.GetEntrySha256()) != 0) {
			return fmt.Errorf("%w: a change whose entry is missing or unasked", ErrEvsEntryRefused)
		}
		var version uint64
		directory := false
		if writes {
			directory = evsEntryVersionIsDirectory(entryBytes)
			digest := sha256.Sum256(entryBytes)
			if !bytes.Equal(digest[:], change.Change.GetEntrySha256()) {
				return fmt.Errorf("%w: an entry that does not hash to its change", ErrEvsEntryRefused)
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(entryBytes, entry); err != nil {
				return fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
			}
			if !bytes.Equal(entry.GetPushId(), push.GetPushId()) || entry.GetBaseVersion() != push.GetBaseVersion() {
				return fmt.Errorf("%w: an entry of another push", ErrEvsEntryRefused)
			}
			version = entry.GetVersion()
		} else {
			version = baseEntryVersion + 1
		}
		if baseEntryVersion != 0 {
			if writes && version != baseEntryVersion+1 {
				return fmt.Errorf("%w: a write not at its base + 1", ErrEvsVersionRule)
			}
			if held != nil && (held.removed || held.version != baseEntryVersion) {
				return fmt.Errorf("%w: a write based on a version that was not the path's newest", ErrEvsVersionRule)
			}
		} else {
			if !writes {
				return fmt.Errorf("%w: a removal of an absent path", ErrEvsVersionRule)
			}
			if held != nil && !held.removed && (!self.gitMode || held.directory == directory) {
				return fmt.Errorf("%w: a creation of a path that stands", ErrEvsVersionRule)
			}
			standing := uint64(0)
			if held != nil {
				standing = held.version
			}
			least := max(push.GetBaseVersion(), standing) + 1
			if self.gitMode {
				// every earlier version is at most b, so TIP makes max(b, m) + 1 exactly b + 1
				if version != push.GetBaseVersion()+1 {
					return fmt.Errorf("%w: a git-mode creation not at b + 1", ErrEvsVersionRule)
				}
			} else if version < least || (self.complete && version != least) {
				return fmt.Errorf("%w: a creation not at max(b, m) + 1", ErrEvsVersionRule)
			}
		}
		self.paths[key] = &evsReplayPath{version: version, removed: !writes, directory: directory}
	}
	return nil
}
