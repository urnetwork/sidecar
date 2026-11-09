// §11.7's versions row and I-EVS-8: a path's versions never restart, however folds, reruns, copies and collections
// interleave.
//
//   - A write's version is its base_entry_version + 1.
//   - A creation's (base_entry_version 0, naming the path absent, whether never written or removed) is
//     max(b, m) + 1: m the version of the newest removal its marker or the window holds (Newest's RemovalVersion),
//     b its push's effective base version, its base_version plus, on an overlay, the base versions along its chain
//     of EvsOverlay bases, which evs reads at the ref's creation and caches.
//   - A removal is one of the path's versions, one past its last, which its marker keeps.
//
// The path-level CAS beside it: base_entry_version equals the path's newest committed version, 0 naming it absent.
// evs checks both at 5g, answering 409 for any other version, and replaying readers alarm on one. These are the pure
// functions; EVS1-M2-11's 5g calls them with Newest's answer.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/sidecar"
)

var (
	// A change whose base_entry_version is not the path's newest: 409 naming the path (5g's CAS).
	ErrEvsPathConflict = errors.New("evs path changed since its base")
	// A change whose entry version is not the versions rule's: 409, and a replaying reader alarms.
	ErrEvsVersionRule = errors.New("evs entry version off the versions rule")
	// An overlay chain deeper than evs follows, or one that loops.
	ErrEvsOverlayChain = errors.New("evs overlay chain invalid")
)

// How deep an overlay chain evs follows: a ref of a ref of a ref, and no further. A format bound on what a chain
// may be, not a tunable.
const evsOverlayMaxDepth = 16

// A push's effective base version: its base_version plus each base version along its overlay chain.
func EffectiveBaseVersion(baseVersion uint64, overlayBaseVersions []uint64) uint64 {
	effective := baseVersion
	for _, overlayBaseVersion := range overlayBaseVersions {
		effective += overlayBaseVersion
	}
	return effective
}

// The version a change must write: base + 1 for a write, max(b, m) + 1 for a creation.
func ExpectedEntryVersion(baseEntryVersion uint64, effectiveBaseVersion uint64, newestRemovalVersion uint64) uint64 {
	if 0 < baseEntryVersion {
		return baseEntryVersion + 1
	}
	return max(effectiveBaseVersion, newestRemovalVersion) + 1
}

// 5g's two rules for one change of a file: its base names the path's newest (0 for absent), and the version it
// writes, or for a removal the one it removes past, follows the versions rule. entryVersion is the EvsEntryVersion's
// version, 0 for a removal. ErrEvsPathConflict or ErrEvsVersionRule otherwise.
func CheckPathVersion(newest *EvsNewest, baseEntryVersion uint64, entryVersion uint64, removal bool, effectiveBaseVersion uint64) error {
	newestVersion := uint64(0)
	if newest.Exists {
		newestVersion = newest.Version
	}
	if baseEntryVersion != newestVersion {
		return fmt.Errorf("%w: based on %d, newest %d", ErrEvsPathConflict, baseEntryVersion, newestVersion)
	}
	if removal {
		if baseEntryVersion == 0 {
			return fmt.Errorf("%w: a removal of an absent path", ErrEvsPathConflict)
		}
		return nil
	}
	expected := ExpectedEntryVersion(baseEntryVersion, effectiveBaseVersion, newest.RemovalVersion)
	if entryVersion != expected {
		return fmt.Errorf("%w: version %d, the rule's %d", ErrEvsVersionRule, entryVersion, expected)
	}
	return nil
}

// A ref's overlay chain's base versions, read at the ref's creation and kept for the process's life, since a ref's
// base never changes (§11.7's versions row). No push carries a base yet (questions/evs1-m2-01-ref-creation-fields),
// so every head's chain is empty until that is answered; the walk is here for when one does. Safe for concurrent use.
type OverlayChains struct {
	heads    *HeadStore
	settings *EvsSettings

	stateLock       sync.Mutex
	refBaseVersions map[overlayRef][]uint64
}

// One ref of one repo.
type overlayRef struct {
	repoId sidecar.Id
	refId  sidecar.Id
}

// A cache reading heads through heads.
func NewOverlayChains(heads *HeadStore, settings *EvsSettings) *OverlayChains {
	return &OverlayChains{heads: heads, settings: settings, refBaseVersions: map[overlayRef][]uint64{}}
}

// The base versions along the chain of head, the ref's own head: its base's version, its base's base's, and so on,
// each base's head read from the cluster once. Empty for a ref that is no overlay.
func (self *OverlayChains) BaseVersions(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, head *EvsStoredHead) ([]uint64, error) {
	if head.Absent() || head.Head.GetBase() == nil {
		return nil, nil
	}
	key := overlayRef{repoId: repoId, refId: refId}
	cached, ok := func() ([]uint64, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		baseVersions, ok := self.refBaseVersions[key]
		return baseVersions, ok
	}()
	if ok {
		return cached, nil
	}
	baseVersions := []uint64{}
	seen := map[sidecar.Id]bool{refId: true}
	base := head.Head.GetBase()
	for base != nil {
		if evsOverlayMaxDepth <= len(baseVersions) {
			return nil, fmt.Errorf("%w: deeper than %d", ErrEvsOverlayChain, evsOverlayMaxDepth)
		}
		baseRefId, err := sidecar.IdFromBytes(base.GetRefId())
		if err != nil || seen[baseRefId] {
			return nil, fmt.Errorf("%w: a base that is no ref, or loops", ErrEvsOverlayChain)
		}
		seen[baseRefId] = true
		baseVersions = append(baseVersions, base.GetVersion())
		baseHead, err := self.heads.ReadCluster(ctx, cluster, repoId, baseRefId)
		if err != nil {
			return nil, err
		}
		if baseHead.Absent() {
			break
		}
		base = baseHead.Head.GetBase()
	}
	if 0 < self.settings.OverlayCacheCount {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.settings.OverlayCacheCount <= len(self.refBaseVersions) {
				for evicted := range self.refBaseVersions {
					delete(self.refBaseVersions, evicted)
					break
				}
			}
			self.refBaseVersions[key] = baseVersions
		}()
	}
	return baseVersions, nil
}
