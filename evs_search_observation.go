// Names shown by an effective head read stay with its bounded, sealed per-path read record.
// An older store has no observations until the corresponding files are verified again.
package sidecar

import (
	"bytes"
	"crypto/sha256"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The file version actually returned, at the ref and policy the reader verified. No file body is retained.
type evsSearchObservation struct {
	RefName   string            `json:"ref_name,omitempty"`
	Version   uint64            `json:"version"`
	Commit    uint64            `json:"commit"`
	Push      Id                `json:"push"`
	Signer    Id                `json:"signer"`
	TimeMs    int64             `json:"time_ms"`
	Head      uint64            `json:"head"`
	Chain     [sha256.Size]byte `json:"chain"`
	AuthChain []byte            `json:"auth_chain"`
	Tainted   bool              `json:"tainted,omitempty"`
	Outside   bool              `json:"outside,omitempty"`
}

// A search observation can only augment a read record at the very same verified head and effective version.
// A concurrent read, removal, eviction or reseed therefore cannot revive an older name.
func (self *EvsPinStore) observeSearchFile(repo Id, args *EvsReadArgs, info *EvsFileInfo, auth *bridge.AuthPin) error {
	if args.Version != 0 || info.Version == 0 || info.HeadVersion == 0 || len(auth.GetChain()) != sha256.Size {
		return nil
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	self.stateLock.Lock()
	state := self.repoIdRepos[repo]
	if state == nil {
		self.stateLock.Unlock()
		return nil
	}
	pin := state.refIdPins[info.RefId]
	key := evsReadKey{refId: info.RefId, path: args.Path}
	record := state.reads[key]
	if pin == nil || pin.Version != info.HeadVersion || record == nil || record.PinVersion != pin.Version || record.PinChain == nil || *record.PinChain != pin.Chain {
		self.stateLock.Unlock()
		return nil
	}
	if effective := record.Accepted; effective != nil {
		if effective.Absent || effective.Version != info.Version || effective.PushId != info.PushId {
			self.stateLock.Unlock()
			return nil
		}
	} else if record.EntryVersion != info.Version || record.CommitVersion != info.CommitVersion {
		self.stateLock.Unlock()
		return nil
	}
	reads := make(map[evsReadKey]*EvsReadRecord, len(state.reads))
	for k, r := range state.reads {
		reads[k] = r
	}
	observed := *record
	refName := ""
	if args.RefId == nil {
		name := args.RefName
		if name == nil {
			name = EvsMainRefName
		}
		refName = string(name)
	} else if old := record.search; old != nil {
		refName = old.RefName
	}
	observed.search = &evsSearchObservation{RefName: refName, Version: info.Version, Commit: info.CommitVersion, Push: info.PushId, Signer: info.SignerSidecarId, TimeMs: info.Time.UnixMilli(),
		Head: pin.Version, Chain: pin.Chain, AuthChain: bytes.Clone(auth.Chain), Tainted: info.Provenance == nil || info.Provenance.Tainted, Outside: info.Provenance != nil && info.Provenance.Imported}
	reads[key] = &observed
	self.stateLock.Unlock()
	if err := self.writeReadsWithWriteLock(repo, reads); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state.reads = reads
	return nil
}
