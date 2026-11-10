//go:build !ios_extension

// The mapper's index of every name of a ref (DESIGN-DETAILS 9.2.7; EVS1-M2-47): what a PATH_EPOCH's map is built from.
// Two kinds give it, and either is correct:
//
//	replayed  the local tier's mirror of a mounted repo, or a head-mode mirror, which follows every statement and
//	          registers itself (EvsClient.RegisterNameIndex); its EvsBornJournal holds, for each path created after
//	          the cut-over that listed the oldest standing source, the epoch that creation committed in, a path not in
//	          it having stood before (born 0); a removal drops the path and everything below it; the journal empties
//	          when the sources drop. EVS1-M2-33 and EVS1-M2-35 register one when they land
//	listed    evsListedNameIndex, for a device with no mirror: it lists the tree from the root by 9.2.4's reads, each
//	          row's epoch its path's born (E2), and lists again until one verified head stands through a whole listing,
//	          at most ListedIndexRoundCount rounds; CreatedAfter reads each creating push's record and opens the rows
//	          its directory deltas add, since listings miss a path created and removed between two of them
//
// born is an epoch in which evs was shown the path's token and which is at most the epoch of the path's row, or 0 for
// a path that stood before the oldest standing source was left, for which every listed source qualifies.
//
// On desktop and mobile legs. An EvsBornJournal is safe for concurrent use; a listed index is one mapper's.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Every name of a ref as of one replayed head. On every leg.
type EvsNameIndex interface {
	// The head the index is exact at: its version, chain and epoch state.
	Head(ctx context.Context) (*EvsNameIndexHead, error)
	// Every path standing at that head, a directory before what it holds: its raw names, kind and born epoch.
	Walk(ctx context.Context, visit func(path *EvsIndexedPath) error) error
	// Every path a version in (version, Head] created, standing or not, with its names.
	CreatedAfter(ctx context.Context, version uint64) ([]*EvsIndexedPath, error)
}

// The head an index is exact at.
type EvsNameIndexHead struct {
	Version   uint64
	Chain     [32]byte
	PathEpoch *protocol.EvsPathEpoch
}

// One path of an index.
type EvsIndexedPath struct {
	// Its raw names; none for the root.
	Names [][]byte
	Kind  protocol.EvsEntryKind
	// See the file header.
	Born uint64
}

// The path's names joined by /, as a write names it.
func (self *EvsIndexedPath) Path() string {
	parts := make([]string, len(self.Names))
	for i, name := range self.Names {
		parts[i] = string(name)
	}
	return strings.Join(parts, "/")
}

// What a replaying mirror feeds of each path created while sources stand: see the file header's replayed row.
type EvsBornJournal struct {
	stateLock sync.Mutex
	born      map[string]uint64
}

// An empty journal.
func NewEvsBornJournal() *EvsBornJournal {
	return &EvsBornJournal{born: map[string]uint64{}}
}

// A creation of path committed in epoch while the head lists sources.
func (self *EvsBornJournal) NoteCreated(path string, epoch uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.born[path] = epoch
}

// A removal of path: it and everything below it leave the journal.
func (self *EvsBornJournal) NoteRemoved(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for held := range self.born {
		if held == path || strings.HasPrefix(held, path+"/") || path == "" {
			delete(self.born, held)
		}
	}
}

// The head lists no source: every path stood before the oldest standing source, and the journal empties.
func (self *EvsBornJournal) NoteSourcesDropped() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.born)
}

// path's born epoch, 0 for one not in the journal.
func (self *EvsBornJournal) Born(path string) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.born[path]
}

// The listed index of one ref: see the file header's listed row.
type evsListedNameIndex struct {
	repo  *EvsRepo
	refId Id
	head  *EvsNameIndexHead
	paths []*EvsIndexedPath
}

// Lists the ref's tree until one verified head stands through a whole listing, at most rounds times.
func newEvsListedNameIndex(ctx context.Context, repo *EvsRepo, refId Id, rounds int) (*evsListedNameIndex, error) {
	for round := 0; round < rounds; round += 1 {
		before, err := repo.readHeadAlone(ctx, refId, true)
		if err != nil {
			return nil, err
		}
		paths := []*EvsIndexedPath{{Kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY}}
		queue := []*EvsIndexedPath{paths[0]}
		for 0 < len(queue) {
			directory := queue[0]
			queue = queue[1:]
			listing, err := repo.listingAt(ctx, refId, directory.Path())
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(listing.rows))
			for name := range listing.rows {
				names = append(names, name)
			}
			slices.Sort(names)
			for _, name := range names {
				row := listing.rows[name]
				child := &EvsIndexedPath{Names: append(slices.Clone(directory.Names), []byte(name)), Kind: row.kind, Born: row.epoch}
				paths = append(paths, child)
				if row.kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					queue = append(queue, child)
				}
			}
		}
		after, err := repo.readHeadAlone(ctx, refId, true)
		if err != nil {
			return nil, err
		}
		if after.Version == before.Version && after.Chain == before.Chain {
			return &evsListedNameIndex{
				repo: repo, refId: refId, paths: paths,
				head: &EvsNameIndexHead{Version: after.Version, Chain: after.Chain, PathEpoch: after.Head.GetPathEpoch()},
			}, nil
		}
	}
	return nil, fmt.Errorf("%w: the ref moved through %d listings", errEvsMapperWait, rounds)
}

// The head the listing stood through.
func (self *evsListedNameIndex) Head(ctx context.Context) (*EvsNameIndexHead, error) {
	return self.head, nil
}

// Every listed path, the root first and each directory before what it holds.
func (self *evsListedNameIndex) Walk(ctx context.Context, visit func(path *EvsIndexedPath) error) error {
	for _, path := range self.paths {
		if err := visit(path); err != nil {
			return err
		}
	}
	return nil
}

// Every path a version in (version, the ref's verified head] created: each creating push's record read and the rows
// its directory deltas add opened under the statement's epoch, a directory named by its token path in that epoch as
// the index and each earlier creation give it. It walks the ref from its first version, learning every directory a
// creation names; createdAfterFrom walks from a version whose chain the caller holds.
func (self *evsListedNameIndex) CreatedAfter(ctx context.Context, version uint64) ([]*EvsIndexedPath, error) {
	return self.createdAfterWalk(ctx, version, 0, EvsChainStart(self.repo.repoId, self.refId))
}

// CreatedAfter walking from version, whose chain is chain: a map's source, which its job holds. A delta of a directory
// neither the index nor the walk names, one that stood at version and was removed before the index's head, sends the
// walk back to the ref's first version, which names every directory ever created.
func (self *evsListedNameIndex) createdAfterFrom(ctx context.Context, version uint64, chain [32]byte) ([]*EvsIndexedPath, error) {
	created, err := self.createdAfterWalk(ctx, version, version, chain)
	if errors.Is(err, errEvsIndexDirectoryUnknown) {
		return self.CreatedAfter(ctx, version)
	}
	return created, err
}

// A directory delta of a directory the index and the walk do not name.
var errEvsIndexDirectoryUnknown = errors.New("evs: a delta of a directory the index does not name")

// The walk of CreatedAfter from fromVersion with fromChain, collecting what versions after version create.
func (self *evsListedNameIndex) createdAfterWalk(ctx context.Context, version uint64, fromVersion uint64, fromChain [32]byte) ([]*EvsIndexedPath, error) {
	repo := self.repo
	head, err := repo.readHeadAlone(ctx, self.refId, true)
	if err != nil {
		return nil, err
	}
	if head.Version <= version {
		return nil, nil
	}
	pin, ok, err := repo.client.pins.Pin(repo.repoId, self.refId)
	if err != nil || !ok {
		return nil, fmt.Errorf("%w: no pin to walk from", ErrEvsReplyInvalid)
	}
	walked, err := repo.client.verifier.Walk(ctx, repo.repoId, self.refId, fromVersion, fromChain, pin.Version)
	if err != nil {
		return nil, err
	}
	keys := newEvsReadKeys(repo)
	// every directory the index and the creations name, by its names
	directories := map[string][][]byte{"": {}}
	for _, path := range self.paths {
		if path.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			directories[path.Path()] = path.Names
		}
	}
	created := []*EvsIndexedPath{}
	for _, statement := range walked {
		if statement.Statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			continue
		}
		epoch := max(1, statement.Statement.Push.GetPathEpoch())
		checked, err := repo.pushPayload(ctx, head, statement)
		if err != nil {
			return nil, err
		}
		pathKey, err := keys.path(ctx, epoch)
		if err != nil {
			return nil, err
		}
		manifest, err := keys.manifest(ctx, epoch)
		if err != nil {
			return nil, err
		}
		byTokens := map[string][][]byte{}
		for _, names := range directories {
			tokenPath, err := keys.tokenPathIn(ctx, names, epoch)
			if err != nil {
				return nil, err
			}
			byTokens[string(tokenPath.Bytes())] = names
		}
		for _, change := range checked.Changes {
			if !change.WritesEntry() {
				continue
			}
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, entry); err != nil || entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
				continue
			}
			directoryNames, ok := byTokens[string(change.TokenPath.Bytes())]
			if !ok {
				return nil, errEvsIndexDirectoryUnknown
			}
			for _, row := range entry.GetNames().GetNames() {
				child, err := EvsTokenFromBytes(row.GetToken())
				if err != nil {
					return nil, err
				}
				name, err := EvsNameOpen(manifest, pathKey, change.TokenPath.Last(), child, row.GetSealedName())
				if err != nil {
					return nil, err
				}
				names := append(slices.Clone(directoryNames), name)
				path := &EvsIndexedPath{Names: names, Kind: protocol.EvsEntryKind(row.GetKind()), Born: epoch}
				if path.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					directories[path.Path()] = names
				}
				if version < statement.Version {
					created = append(created, path)
				}
			}
		}
	}
	slices.SortFunc(created, func(a *EvsIndexedPath, b *EvsIndexedPath) int {
		return bytes.Compare([]byte(a.Path()), []byte(b.Path()))
	})
	return created, nil
}
