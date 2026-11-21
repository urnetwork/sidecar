//go:build !ios_extension

// History (§11.7's history row, §18.5): a path's versions, newest first, across its lives, each read as an older
// version (§11.9's request row) and verified against its own statement as a head read's is. The walk follows each
// version's prev_push_id and prev_commit_version: a write replaces the version one below it, so the walk asks for
// that one by number with commit_version (DESIGN-DETAILS 9.2.4's history) and checks the entry it gets names the push
// and commit the newer one said it replaced. At most EvsSettings.HistoryVersionCount versions.
//
// Lives (§11.9's reply row; owner decision 380; QD-888). A creation names no version it replaces, and a removal names
// only the number one past the path's last, so below each the walk asks by number alone, which evs answers with the
// path's newest version or removal at or below it: below a creation, the removal that ended the path's earlier life,
// then that life's versions, and so on down to the path's first creation, below which evs answers nothing and the
// walk ends. So a removed path's walk lists the removed life's versions and their slot keys (QD-672), and a
// re-created path's every life; a History that asks for the newest life alone (EvsReadArgs.NewestLife) ends at its
// creation. Every read by number must answer that version or one below it, and one by number
// alone one committed below the version listed above it: an answer that does not descend, such as the removal again,
// is a server repeating itself, which is the bug QD-672 fixed, or a tamper, so the walk stops there with an alarm and
// History gives the versions walked before it.
//
// A creation whose number passes its push's base by more than one took max(b, m) + 1 over a removal at the number
// just below it (§11.7's versions row, I-EVS-8): on a ref that is no overlay, an answer below it that is not that
// removal raises the version-rule alarm, the walk listing what evs served. Below an overlay's creation evs may answer
// `base`, which ends the walk, its base ref's history being another ref's. A read below a creation or a removal that
// evs refuses with a 429 or a 503, as it answers one past its scan bound, ends the walk with BelowUnknown set; any other
// failure fails History, as a read's anywhere.
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
// read, is shown as evs has it. A listed version a later listed repair names in its sealed written_over is marked
// WrittenOverBy that repair's version (DESIGN-DETAILS 16.2.7's metadata row; QD-833). A repair is the first version
// this device follows above one it ignores, so only such a version's sealed metadata is opened, one more round each;
// the list is for display alone, so one that does not read or open marks nothing and fails nothing.
//
// A History that asks for it (EvsReadArgs.Provenance) gives each listed version's push's sealed provenance, a
// removal's included, one more round per push (evs_read_provenance.go): a push whose metadata does not open fails
// the History, and one evs serves no record of reads nil.
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	return self.historyAt(ctx, refId, args, nil, ruled)
}

// Reads a named path or a deposit's random token. Deposit refs stay in epoch 1 and carry no prefix rules.
func (self *EvsRepo) historyAt(ctx context.Context, refId Id, args *EvsReadArgs, token EvsTokenPath, ruled evsPrefixReader) (*EvsHistory, error) {
	history := &EvsHistory{RefId: refId, Path: args.Path}
	wholeLineage := true
	version := args.Version
	var expectPushId []byte
	var expectCommit uint64
	// a read below a creation or a removal, by number alone (see the file header): the ref version of the one listed
	// above it, which the answer must be committed below, and the number of the removal a creation's own number names
	// below it, 0 for none
	below := false
	belowCommit := uint64(0)
	impliedRemoval := uint64(0)
	// each listed version's statement, beside history.Versions, and the first read's head and keys: what a repair's
	// sealed metadata is read and opened with (markWrittenOver)
	statements := []*EvsVerifiedStatement{}
	var head *EvsVerifiedHead
	var keys *evsReadKeys
	var err error
	for len(history.Versions) < self.client.settings.HistoryVersionCount {
		path := &evsReadPath{path: args.Path, token: token, version: version}
		if version != 0 {
			path.commitVersion, path.prevPushId = expectCommit, expectPushId
		}
		result, err := self.readPaths(ctx, refId, []*evsReadPath{path}, args.Fresh && version == args.Version)
		if err != nil {
			if evsError, ok := EvsErrorOf(err); below && ok && evsError.RefusesNothing() {
				history.BelowUnknown = true
				break
			}
			return nil, err
		}
		result.objects.close()
		if history.HeadVersion == 0 {
			history.HeadVersion = result.head.Version
		}
		if head == nil {
			head, keys = result.head, result.keys
		}
		verified := result.replies[0]
		if verified.Base != nil {
			if len(history.Versions) == 0 {
				return nil, ErrEvsOverlayBase
			}
			break
		}
		if verified.Absent {
			if impliedRemoval != 0 {
				// the creation's number names a removal below it that evs does not show
				self.client.alarm(self.repoId, refId, SidecarEvsAlarmVersionRule, args.Path, nil)
			}
			if len(history.Versions) == 0 {
				return nil, ErrEvsPathAbsent
			}
			// nothing stands below the path's first creation, unless its number named a removal evs did not show;
			// nothing below a removal, whose ended life stands below it, or below a version that names the one it
			// replaced reaches no first version
			history.Whole = impliedRemoval == 0 && history.Versions[len(history.Versions)-1].Created
			break
		}
		ignored := false
		if ruled != nil {
			if ignored, err = ruled.ignored(ctx, self, result, 0); err != nil {
				return nil, err
			}
		}
		// a read by number answers that version or one below it, and one by number alone a version committed below
		// the one listed above it; anything else does not descend (see the file header)
		descends := func(served uint64, commitVersion uint64) bool {
			if version != 0 && (version < served || (below && belowCommit <= commitVersion)) {
				self.client.alarm(self.repoId, refId, SidecarEvsAlarmTamper, args.Path, nil)
				return false
			}
			if len(history.Versions) != 0 {
				newer := history.Versions[len(history.Versions)-1]
				if newer.Created {
					// An earlier life ended in a removal, at exactly the implied number when the creation names it.
					wholeLineage = wholeLineage && verified.Removal != nil && (impliedRemoval == 0 || served == impliedRemoval)
				} else {
					// Both a removal and a replacement follow the file one version below. An older signed answer can
					// still be displayed, but reaching a creation through it cannot account for the skipped keys.
					wholeLineage = wholeLineage && verified.Removal == nil && served == version
				}
			}
			return true
		}
		if verified.Removal != nil {
			removal := verified.Removal
			if !descends(removal.GetPathVersion(), removal.GetRemovalVersion()) {
				break
			}
			if impliedRemoval != 0 && removal.GetPathVersion() != impliedRemoval {
				self.client.alarm(self.repoId, refId, SidecarEvsAlarmVersionRule, args.Path, nil)
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
				Epoch:           verified.Statement.Push.GetPathEpoch(),
			})
			statements = append(statements, &EvsVerifiedStatement{Version: removal.GetRemovalVersion(), Statement: verified.Statement})
			if removal.GetPathVersion() <= 1 {
				history.Whole = true
				break
			}
			// the life the removal ended: its last version, by number alone
			version = removal.GetPathVersion() - 1
			expectPushId, expectCommit = nil, 0
			below, belowCommit, impliedRemoval = true, removal.GetRemovalVersion(), 0
			continue
		}
		entry := verified.Entry
		if !descends(entry.GetVersion(), verified.CommitVersion) {
			break
		}
		if impliedRemoval != 0 {
			// a version where the creation's number names a removal: evs serves the life it ended as standing
			self.client.alarm(self.repoId, refId, SidecarEvsAlarmVersionRule, args.Path, nil)
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
		if name := verified.Drop.Name(self.client.clock.Now()); name != "" && !verified.Collected {
			// a version a checked DROP lists (evs_drop_verify.go); a replaced versionless one stays collected
			state = name
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
		// a creation, base_entry_version 0, which its verified change shows
		created := verified.Change.GetBaseEntryVersion() == 0
		history.Versions = append(history.Versions, &EvsHistoryVersion{
			Version:         entry.GetVersion(),
			CommitVersion:   verified.CommitVersion,
			PushId:          info.PushId,
			SignerSidecarId: info.SignerSidecarId,
			ClientId:        info.ClientId,
			Time:            info.Time,
			Created:         created,
			Versioning:      entry.GetVersioning(),
			Ignored:         ignored,
			State:           state,
			DropId:          evsDropIdOf(verified.Drop),
			DropNotBefore:   evsDropNotBeforeOf(verified.Drop),
			SlotIds:         slotIds,
			kind:            info.Kind,
			paddedSize:      entry.GetPaddedSize(),
			EntrySha256:     evsHistoryEntrySha256(verified),
			Epoch:           verified.Statement.Push.GetPathEpoch(),
		})
		statements = append(statements, &EvsVerifiedStatement{Version: verified.CommitVersion, Statement: verified.Statement})
		if entry.GetVersion() <= 1 {
			history.Whole = true
			break
		}
		if created && args.NewestLife {
			break
		}
		if created {
			// below a creation, by number alone: the removal that ended the path's earlier life, if one did
			version = entry.GetVersion() - 1
			expectPushId, expectCommit = nil, 0
			below, belowCommit, impliedRemoval = true, verified.CommitVersion, 0
			if result.head.Head.GetBase() == nil && verified.Statement.Push.GetBaseVersion()+1 < entry.GetVersion() {
				impliedRemoval = entry.GetVersion() - 1
			}
			continue
		}
		if verified.Drop != nil && verified.Drop.Withheld {
			// evs withheld a dropped version's entry, and with it the version it replaces: below it by number alone
			version = entry.GetVersion() - 1
			expectPushId, expectCommit = nil, 0
			below, belowCommit, impliedRemoval = true, verified.CommitVersion, 0
			continue
		}
		if len(entry.GetPrevPushId()) == 0 {
			// a write that names no version it replaces, which no honest writer makes: the walk ends with it
			break
		}
		expectPushId, expectCommit = entry.GetPrevPushId(), entry.GetPrevCommitVersion()
		version = entry.GetVersion() - 1
		below, belowCommit, impliedRemoval = false, 0, 0
	}
	history.Whole = history.Whole && wholeLineage
	self.markWrittenOver(ctx, history, statements, head, keys)
	if args.Provenance && head != nil {
		reads := newEvsProvenanceReads(self, refId, head, keys)
		for i, listed := range history.Versions {
			if listed.Provenance, err = reads.of(ctx, statements[i]); err != nil {
				return nil, err
			}
		}
	}
	return history, nil
}

// Whether a caller paging History, whose last page ended at below (a creation or a removal), reads the next page's
// error as History's BelowUnknown: evs refused the read of the number below it with a refusal that refuses nothing,
// as History itself reads such a step within a page.
func evsHistoryBelowUnread(below *EvsHistoryVersion, err error) bool {
	evsError, ok := EvsErrorOf(err)
	return below != nil && (below.Created || below.Removed) && ok && evsError.RefusesNothing()
}

// Marks each listed version a later listed repair names in its sealed written_over with that repair's path version
// (the file header): a candidate is a version this device follows directly above one it ignores, and a version takes
// the mark of the nearest candidate above it that names it, the candidates being read oldest first. A push this
// device ignores names nothing, and a push from before the field has no list.
func (self *EvsRepo) markWrittenOver(ctx context.Context, history *EvsHistory, statements []*EvsVerifiedStatement, head *EvsVerifiedHead, keys *evsReadKeys) {
	versions := history.Versions
	for i := len(versions) - 2; 0 <= i; i -= 1 {
		if versions[i].Ignored || !versions[i+1].Ignored {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		pushIds := self.writtenOverOf(ctx, head, keys, statements[i])
		for _, older := range versions[i+1:] {
			if older.WrittenOverBy == 0 && pushIds[older.PushId] {
				older.WrittenOverBy = versions[i].Version
			}
		}
	}
}

// The push ids a version's push names in its sealed written_over, nil for none: no list, a payload or sealed metadata
// that does not read or open, which this display does not alarm on, or a list holding an id of another width, which
// is no list (QD-833).
func (self *EvsRepo) writtenOverOf(ctx context.Context, head *EvsVerifiedHead, keys *evsReadKeys, statement *EvsVerifiedStatement) map[Id]bool {
	payload, err := self.pushContent(ctx, head, statement)
	if err != nil {
		return nil
	}
	manifest, err := keys.manifest(ctx, statement.Statement.Push.GetGeneration())
	if err != nil {
		return nil
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		return nil
	}
	pushIds := map[Id]bool{}
	for _, pushIdBytes := range metadata.GetWrittenOver() {
		pushId, err := IdFromBytes(pushIdBytes)
		if err != nil {
			return nil
		}
		pushIds[pushId] = true
	}
	return pushIds
}

// A version's entry hash, as its statement's change names it, else its verified entry bytes' SHA-256.
func evsHistoryEntrySha256(verified *EvsVerifiedPath) []byte {
	if hash := verified.Change.GetEntrySha256(); len(hash) == sha256.Size {
		return bytes.Clone(hash)
	}
	sum := sha256.Sum256(verified.EntryBytes)
	return sum[:]
}
