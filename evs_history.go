//go:build !ios_extension

// History (§11.7's history row, §18.5): a path's versions, newest first, each read as an older version (§11.9's
// request row) and verified against its own statement as a head read's is. The walk follows each version's
// prev_push_id and prev_commit_version: a write replaces the version one below it, so the walk asks for that one by
// number with commit_version (DESIGN-DETAILS 9.2.4's history) and checks the entry it gets names the push and commit
// the newer one said it replaced; a creation ends the walk, its path's earlier life being a removed one this draft
// does not walk past (§11.7's versions row keeps the numbers apart). At most EvsSettings.HistoryVersionCount versions.
//
// A removed path's walk asks for the version below its removal by number, which evs serves from the entry's folded
// versions as a standing path's (QD-672), so History lists the removed life's versions and their slot keys. Every
// read by number must answer that version or one below it: an answer that does not descend, such as the removal again,
// is a server repeating itself, which is the bug QD-672 fixed or a tamper, so the walk stops there with an alarm and
// History gives the versions walked before it.
//
// Across path epochs: a version written in an epoch the request names no token path in is answered with its
// statement alone, which the reader takes as E4 when its push id is the prev_push_id the newer version names, and
// asks again naming that statement's epoch (evs_epoch_read.go), one more round per epoch boundary the walk crosses.
//
// Format 1's versions are all kept, so each reads state kept. A format-2 reader reports each version's versioning and
// reads a replaced versionless version as collected once evs answers so (EVS2-M10-18); when that is the first version
// the walk reads, nothing newer has shown its replacement, and the reader's gone row decides (evs_read_versionless.go).
// drop_pending and dropped are EVS2-M10-22's.
// Each version carries the slot ids its entry names, read from the verified entry without opening a key, so an
// erasing device names every retained version's slot keys from History even once some are gone (§11.12).
//
// Under the repo's prefix write rules every version is listed, and one this device ignores is marked Ignored with
// its signer (DESIGN-DETAILS 16.2.5's History row); a version nobody can judge, under a rule set this device cannot
// read, is shown as evs has it.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// A path's versions, newest first.
func (self *EvsRepo) History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	ruled, err := self.prefixRuled()
	if err != nil {
		return nil, err
	}
	history := &EvsHistory{RefId: refId, Path: args.Path}
	version := args.Version
	var expectPushId []byte
	var expectCommit uint64
	for len(history.Versions) < self.client.settings.HistoryVersionCount {
		path := &evsReadPath{path: args.Path, version: version}
		if version != 0 {
			path.commitVersion, path.prevPushId = expectCommit, expectPushId
		}
		result, err := self.readPaths(ctx, refId, []*evsReadPath{path}, args.Fresh && version == args.Version)
		if err != nil {
			return nil, err
		}
		result.objects.close()
		if history.HeadVersion == 0 {
			history.HeadVersion = result.head.Version
		}
		verified := result.replies[0]
		if verified.Base != nil {
			return nil, ErrEvsOverlayBase
		}
		if verified.Absent {
			if len(history.Versions) == 0 {
				return nil, ErrEvsPathAbsent
			}
			break
		}
		ignored := false
		if ruled != nil {
			if ignored, err = ruled.ignored(ctx, self, result, 0); err != nil {
				return nil, err
			}
		}
		// a read by number answers that version or one below it; anything else does not descend (see the file header)
		descends := func(served uint64) bool {
			if version == 0 || served <= version {
				return true
			}
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, args.Path, nil)
			return false
		}
		if verified.Removal != nil {
			removal := verified.Removal
			if !descends(removal.GetPathVersion()) {
				break
			}
			pushId, _ := IdFromBytes(removal.GetPushId())
			signerId, _ := IdFromBytes(verified.Statement.Push.GetSignerSidecarId())
			clientId, _ := IdFromBytes(verified.Statement.Push.GetClientId())
			history.Versions = append(history.Versions, &EvsHistoryVersion{
				Version:         removal.GetPathVersion(),
				CommitVersion:   removal.GetRemovalVersion(),
				PushId:          pushId,
				SignerSidecarId: signerId,
				ClientId:        clientId,
				Time:            evsTime(verified.Statement.Push.GetTimeMs()),
				Removed:         true,
				Ignored:         ignored,
				State:           "kept",
			})
			if removal.GetPathVersion() <= 1 {
				break
			}
			version = removal.GetPathVersion() - 1
			expectPushId, expectCommit = nil, 0
			continue
		}
		entry := verified.Entry
		if !descends(entry.GetVersion()) {
			break
		}
		if expectPushId != nil && (!bytes.Equal(entry.GetPushId(), expectPushId) || verified.CommitVersion != expectCommit) {
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, args.Path, nil)
			return nil, fmt.Errorf("%w: a version its successor does not name", ErrEvsEntryRefused)
		}
		state := "kept"
		if verified.Collected {
			if len(history.Versions) == 0 {
				if err := self.versionlessGone(ctx, result, verified); !errors.Is(err, ErrEvsCollected) {
					return nil, err
				}
			}
			state = "collected"
		}
		info := evsFileInfoOf(refId, result.head, verified)
		slotIds := []Id{}
		for _, slotIdBytes := range entry.GetSlotIds() {
			slotId, err := IdFromBytes(slotIdBytes)
			if err != nil {
				return nil, fmt.Errorf("%w: a slot id of %d bytes", ErrEvsEntryRefused, len(slotIdBytes))
			}
			slotIds = append(slotIds, slotId)
		}
		history.Versions = append(history.Versions, &EvsHistoryVersion{
			Version:         entry.GetVersion(),
			CommitVersion:   verified.CommitVersion,
			PushId:          info.PushId,
			SignerSidecarId: info.SignerSidecarId,
			ClientId:        info.ClientId,
			Time:            info.Time,
			Versioning:      entry.GetVersioning(),
			Ignored:         ignored,
			State:           state,
			SlotIds:         slotIds,
		})
		if len(entry.GetPrevPushId()) == 0 || entry.GetVersion() <= 1 {
			break
		}
		expectPushId, expectCommit = entry.GetPrevPushId(), entry.GetPrevCommitVersion()
		version = entry.GetVersion() - 1
	}
	return history, nil
}
