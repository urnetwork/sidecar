// What a directory admin's moderation of a card does at evs past what FakeDirectoryCards keeps (QD-1148; sidecar's
// directory_cards_erasure.go): the ERASE of the keys a removed card's versions were kept under, which the fake holds
// none of, its contents being the caller's plaintext, committed on the world's erasure ref, where every reader's sync
// reads its sealed note beside the record's own ERASEs (§11.12); and a later CUT that drops, as complete, the erasures
// listing some documents from the cards ref's index erasure set (indexCutSet's listed_since), so a card's return reads
// them unlisted.

package sidecartest

import (
	"bytes"
	"context"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Commits on repoId's erasure ref an ERASE by eraserId of args.Keys, keys of the cards ref's files, its note args.Note
// as given, as evs commits a directory admin's ERASE of a removed card's keys (sidecar.DirectoryErasureFiles'
// EraseCardKeys): 403 SCOPE below admin, as evs refuses it, and 409 NOTHING_TO_ERASE where earlier ERASEs named every
// key it names. It passes record_streams.erase.before and .after as the record's own ERASEs do.
func (self *FakeDirectoryCards) EraseCardKeys(ctx context.Context, repoId sidecar.Id, eraserId sidecar.Id, args *sidecar.EvsEraseArgs) error {
	client := &fakeRecordStreamsClient{world: self.streams, sidecarId: eraserId}
	_, err := client.mutate("erase", repoId, func() (*sidecar.RecordStreamCommit, error) {
		repo, ok := self.streams.repos[repoId]
		if !ok {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND)
		}
		if args == nil || len(args.Keys) == 0 {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_INVALID)
		}
		if !repo.scopes[eraserId].Admin {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE)
		}
		named := map[sidecar.RecordSlotKey]bool{}
		for _, erasure := range repo.erasures {
			for _, key := range erasure.Keys {
				named[*key] = true
			}
		}
		erasure := &sidecar.RecordStreamErasure{
			Version:         uint64(len(repo.erasures) + 1),
			PushId:          sidecar.NewId(),
			TimeMillis:      self.streams.clock.Now().UnixMilli(),
			EraserSidecarId: eraserId,
			ErasureId:       args.ErasureId,
			Complete:        args.Complete,
			SealedNote:      bytes.Clone(args.Note),
		}
		for _, key := range args.Keys {
			slotKey := sidecar.RecordSlotKey{SlotId: key.SlotId, KeyIndex: uint32(key.KeyIndex)}
			if !named[slotKey] {
				erasure.Keys = append(erasure.Keys, &slotKey)
			}
		}
		if len(erasure.Keys) == 0 {
			return nil, fakeRecordRefusal(protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE)
		}
		repo.erasures = append(repo.erasures, erasure)
		repo.raiseWithLock(FakeRecordRef{Kind: FakeRecordRefErasure})
		return &sidecar.RecordStreamCommit{Version: erasure.Version, TimeMillis: erasure.TimeMillis}, nil
	})
	return err
}

// A later CUT by signerId that drops from repoId's cards ref index erasure set, as complete, the erasures listing
// names: a card's return reads each unlisted from then, and the set's version is signerId's.
func (self *FakeDirectoryCards) DropErased(repoId sidecar.Id, signerId sidecar.Id, names ...[]byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	erasure := self.erasureWithLock(repoId)
	if erasure.versions == nil {
		erasure.versions = map[string]uint64{}
	}
	for _, name := range names {
		delete(erasure.versions, string(name))
	}
	erasure.signerId = signerId
}
