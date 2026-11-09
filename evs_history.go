// History (§11.7's history row, §18.5): a path's versions, newest first, each read as an older version (§11.9's
// request row) and verified against its own statement as a head read's is. The walk follows each version's
// prev_push_id and prev_commit_version: a write replaces the version one below it, so the walk asks for that one and
// checks the entry it gets names the push and commit the newer one said it replaced; a creation ends the walk, its
// path's earlier life being a removed one this draft does not walk past (§11.7's versions row keeps the numbers
// apart). At most EvsSettings.HistoryVersionCount versions.
//
// Format 1's versions are all kept, so each reads state kept; collected, drop_pending and dropped are format 2's.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"fmt"
)

// A path's versions, newest first.
func (self *EvsRepo) History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error) {
	refId, err := self.resolveRefId(ctx, args.RefName, args.RefId)
	if err != nil {
		return nil, err
	}
	history := &EvsHistory{RefId: refId, Path: args.Path}
	version := args.Version
	var expectPushId []byte
	var expectCommit uint64
	for len(history.Versions) < self.client.settings.HistoryVersionCount {
		result, err := self.read(ctx, refId, []string{args.Path}, version, args.Fresh && version == args.Version)
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
		if verified.Removal != nil {
			removal := verified.Removal
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
		if expectPushId != nil && (!bytes.Equal(entry.GetPushId(), expectPushId) || verified.CommitVersion != expectCommit) {
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, args.Path, nil)
			return nil, fmt.Errorf("%w: a version its successor does not name", ErrEvsEntryRefused)
		}
		info := evsFileInfoOf(refId, result.head, verified)
		history.Versions = append(history.Versions, &EvsHistoryVersion{
			Version:         entry.GetVersion(),
			CommitVersion:   verified.CommitVersion,
			PushId:          info.PushId,
			SignerSidecarId: info.SignerSidecarId,
			ClientId:        info.ClientId,
			Time:            info.Time,
			Versioning:      entry.GetVersioning(),
			State:           "kept",
		})
		if len(entry.GetPrevPushId()) == 0 || entry.GetVersion() <= 1 {
			break
		}
		expectPushId, expectCommit = entry.GetPrevPushId(), entry.GetPrevCommitVersion()
		version = entry.GetVersion() - 1
	}
	return history, nil
}
