//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The replayed name index of a mounted branch (DESIGN-DETAILS 8.2.10, 9.2.7; EVS1-M2-47's seam): what section 9's
// mapper builds a git-mode ref's PATH_EPOCH map from, read from the bare repository the sync engine keeps.
//
//	Head          the ref's EvsGitRef: version, chain, and the epoch state replay recorded at the head it reached
//	Walk          a branch with no base: the root, then git ls-tree -r -t -z <tip>, a directory before what it holds;
//	              an overlay: its held set's standing paths in the same order (an inherited path is the base ref's)
//	born          the born journal replay feeds: a path created while sources stand carries the epoch it was created
//	              in, a path not in it stood before (born 0)
//	CreatedAfter  for each version in (S, Head] the tips log holds: the paths of tree(tip_u) that tree(tip_(u-1))
//	              lacks, by the tree reader, which on an overlay are the paths that version first held
//
// The engine registers one per branch it follows at Mount and as each new branch applies, through
// EvsClient.RegisterNameIndex. It implements EvsNameIndexPublisher, so the mapper's PATH_EPOCH push takes the ref's
// P_r and one device's pushes to one ref take turns (8.2.9). A tag ref holds no path state and takes no map.
//
// Desktop legs only. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
)

// One branch's replayed index.
type evsLocalNameIndex struct {
	engine *EvsGitSyncEngine
	refId  Id
}

// Registers ref's index once, for a git-mode branch with a tip.
func (self *EvsGitSyncEngine) registerIndex(ref *EvsGitRef) {
	if ref.Mode != protocol.EvsRefMode_EVS_REF_GIT || ref.Tip == nil || ref.tag() || len(ref.Name) == 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.indexes[ref.RefId] != nil {
		return
	}
	self.indexes[ref.RefId] = self.client.RegisterNameIndex(self.mount.RepoId, ref.RefId, &evsLocalNameIndex{engine: self, refId: ref.RefId})
}

// Removes every index the engine registered: what the mount's end does.
func (self *EvsGitSyncEngine) unregisterIndexes() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for refId, remove := range self.indexes {
		remove()
		delete(self.indexes, refId)
	}
}

// The ref's replayed head.
func (self *evsLocalNameIndex) Head(ctx context.Context) (*EvsNameIndexHead, error) {
	ref, err := self.engine.loadRef(ctx, self.refId)
	if err != nil {
		return nil, err
	}
	return &EvsNameIndexHead{Version: ref.Version, Chain: ref.Chain, PathEpoch: ref.PathEpoch}, nil
}

// P_r, which the mapper's PATH_EPOCH holds.
func (self *evsLocalNameIndex) LockPublish(ctx context.Context) (func(), error) {
	return self.engine.mount.locks.LockPublish(ctx, self.refId)
}

// Every path standing at the replayed head, the root first and a directory before what it holds.
func (self *evsLocalNameIndex) Walk(ctx context.Context, visit func(path *EvsIndexedPath) error) error {
	engine := self.engine
	ref, err := engine.loadRef(ctx, self.refId)
	if err != nil {
		return err
	}
	born, err := engine.state.born(self.refId)
	if err != nil {
		return err
	}
	if err := visit(&EvsIndexedPath{Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY}); err != nil {
		return err
	}
	if ref.Peeled == nil {
		return nil
	}
	objects, err := engine.mount.Objects(ctx)
	if err != nil {
		return err
	}
	tree, err := evsGitTreeOf(ctx, objects, *ref.Peeled)
	objects.Close()
	if err != nil {
		return err
	}
	paths, err := engine.mount.treePaths(ctx, tree)
	if err != nil {
		return err
	}
	var held evsGitHeldSet
	if ref.Base != nil {
		if held, err = engine.state.held(self.refId); err != nil {
			return err
		}
	}
	for _, path := range paths {
		if held != nil {
			kind := held[path.Path()]
			if kind != evsGitHeldFile && kind != evsGitHeldDirectory {
				// an inherited path is the base ref's to map
				continue
			}
		}
		path.Born = born[path.Path()]
		if err := visit(path); err != nil {
			return err
		}
	}
	return nil
}

// Every path a version in (version, Head] created, by the tips log's consecutive tips.
func (self *evsLocalNameIndex) CreatedAfter(ctx context.Context, version uint64) ([]*EvsIndexedPath, error) {
	engine := self.engine
	ref, err := engine.loadRef(ctx, self.refId)
	if err != nil {
		return nil, err
	}
	objects, err := engine.mount.Objects(ctx)
	if err != nil {
		return nil, err
	}
	defer objects.Close()
	cached := newEvsGitCachedTrees(objects, engine.settings.TreeCacheByteCount)
	created := []*EvsIndexedPath{}
	var previous *EvsGitOid
	if 0 < version {
		previous, _, err = engine.state.tipAt(ref, version)
		if err != nil {
			return nil, err
		}
	}
	for page := evsGitTipPage(version + 1); page <= evsGitTipPage(ref.Version); page += 1 {
		entries, err := engine.state.tipPage(self.refId, page)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.Version <= version {
				continue
			}
			tip, err := evsOidOfText(entry.Tip)
			if err != nil {
				return nil, err
			}
			if tip == nil {
				previous = nil
				continue
			}
			var stood *EvsGitOid
			if previous != nil {
				tree, err := engine.treeOfTip(ctx, cached, *previous)
				if err != nil {
					return nil, err
				}
				stood = &tree
			}
			next, err := engine.treeOfTip(ctx, cached, *tip)
			if err != nil {
				return nil, err
			}
			changes, err := evsGitNetChange(ctx, cached, stood, next)
			if err != nil {
				return nil, err
			}
			for _, change := range changes {
				if change.removes() || change.Path == "" || change.Stood == change.Kind {
					continue
				}
				names, err := evsPathNames(change.Path)
				if err != nil {
					return nil, err
				}
				created = append(created, &EvsIndexedPath{Names: names, Kind: change.Kind, Born: entry.Version})
			}
			previous = tip
		}
	}
	return created, nil
}

// The tree a tip, a commit or an annotated tag, peels to.
func (self *EvsGitSyncEngine) treeOfTip(ctx context.Context, objects EvsGitObjectSource, tip EvsGitOid) (EvsGitOid, error) {
	peeled, _, err := evsGitPeel(ctx, objects, tip)
	if err != nil {
		return EvsGitOid{}, err
	}
	return evsGitTreeOf(ctx, objects, peeled)
}

// Every path of tree, a directory before what it holds, by git ls-tree -r -t -z: its raw names and kind.
func (self *EvsLocalRepo) treePaths(ctx context.Context, tree EvsGitOid) ([]*EvsIndexedPath, error) {
	out, err := self.Git(ctx, "ls-tree", "-r", "-t", "-z", "--full-tree", hex.EncodeToString(tree[:]))
	if err != nil {
		return nil, err
	}
	paths := []*EvsIndexedPath{}
	for _, line := range bytes.Split(out, []byte{0}) {
		if len(line) == 0 {
			continue
		}
		meta, path, found := bytes.Cut(line, []byte{'\t'})
		fields := strings.Fields(string(meta))
		if !found || len(fields) != 3 {
			return nil, fmt.Errorf("%w: ls-tree answered no entry", ErrEvsGitFailed)
		}
		kind := protocol.EvsEntryKind_EVS_ENTRY_FILE
		if fields[1] == evsGitTreeKind {
			kind = protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
		}
		paths = append(paths, &EvsIndexedPath{Names: bytes.Split(slices.Clone(path), []byte{'/'}), Kind: kind})
	}
	return paths, nil
}
