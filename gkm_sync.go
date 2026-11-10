// Group sync (KEYS-M2-23; R-KEYS-13, D-KEYS-14, I-16, FI-10; §10.7's KF5 and KF7, DESIGN-DETAILS 6.2.4 and 6.2.6):
// how a device that fell behind comes back to the group's newest epoch and generation.
//
//	behind   at most ResyncReplayMax epochs: each commit gkm holds past this device's is processed in order, judged
//	         at its header's pin and adopted only if it passes (gkm_members.go's Process)
//	resync   further behind, or an epoch was pruned or does not process, or this device held a leaf and holds none
//	         now while its state still seats it (removed as stale, or its MLS state lost): it opens the newest
//	         epoch's sealed GroupInfo, inline at 16 leaves or fewer and group-info above, with K_groupinfo of the
//	         generation it names, and joins by an external commit that removes its own old leaf, carries a path and
//	         GenWrap_{e+1} of the newest generation, and is checked as every member will check it before it is
//	         uploaded (R1 to R4). A device its state no longer seats awaits a re-add, reads by wraps where it is
//	         still a holder, or uses the recovery code
//	R3 wait  an external commit removes only its own old leaf, so while the newest tree holds a leaf that is no key
//	         holder at this device's state the resync waits, ErrGkmDroppedLeafStands, and asks H2
//	H2       a leaf that waits under R3, and a resync that finds no GroupInfo of the newest epoch, asks GET
//	         group-info?want=<epoch> at most once a LateAskInterval, which hints wrap-pending to the group's
//	         writers; a writer so hinted runs the pending engine, which commits the Remove, and above 16 leaves a
//	         leaf that is not read_only writes the newest epoch's GroupInfo, at most once an epoch
//	probe    the newest epoch is found from the group-info pointer, then epochs?after= to the end, uncapped
//	         (D-KEYS-18); gkm serving nothing at or past the epoch this device adopted is a fork
//
// A commit that stands at gkm and fails this device's checks is never resynced over: its refusal stands until a
// later chain shows the group repaired (§10.9), and catch-up answers ErrGkmCommitRefused.
//
// KF7, gkm unreachable: nothing here runs; cached keys serve reads and deposits (gkm_access.go, gkm_dropkey.go),
// and joins, catch-up and membership changes wait for the next hint or resync.
//
// The commit hint's work is SyncRepo. A join through this device's last-resort KeyPackage is noted here: it owes a
// path-only commit at once (gkm_selfupdate.go), and upkeep replaces the package at its next pass, reading
// LastResortJoinedAt through GkmUpkeepRole.

package sidecar

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The keychain name of the time this device last joined through its last-resort KeyPackage.
const gkmLastResortJoinedRecord = "last-resort-joined"

// What an external commit is checked on: the epoch a GroupInfo names, as its tree shows it. It is no group this
// device holds, so nothing commits, processes or exports on it.
type gkmExternalBase struct {
	groupId Id
	epoch   uint64
	roster  []MlsMember
	// this device's old leaf there, or its id alone when it holds none
	self MlsMember
}

var _ MlsGroup = (*gkmExternalBase)(nil)

// The group the GroupInfo names.
func (self *gkmExternalBase) GroupId() Id {
	return self.groupId
}

// The epoch the GroupInfo names.
func (self *gkmExternalBase) Epoch() uint64 {
	return self.epoch
}

// None: this device holds no secret of the epoch.
func (self *gkmExternalBase) EpochAuthenticator() []byte {
	return nil
}

// This device's old leaf.
func (self *gkmExternalBase) Self() MlsMember {
	return self.self
}

// The leaves of the GroupInfo's tree.
func (self *gkmExternalBase) Roster() []MlsMember {
	return self.roster
}

// Refused.
func (self *gkmExternalBase) Exporter(label string, context []byte, length int) ([]byte, error) {
	return nil, ErrMlsNotMember
}

// Refused.
func (self *gkmExternalBase) GroupInfo() ([]byte, error) {
	return nil, ErrMlsNotMember
}

// Refused.
func (self *gkmExternalBase) Commit(args *MlsCommitArgs) (MlsStagedCommit, error) {
	return nil, ErrMlsNotMember
}

// Refused.
func (self *gkmExternalBase) Process(message []byte) (MlsStagedCommit, error) {
	return nil, ErrMlsNotMember
}

// KF5 for one repo, the commit hint's work and each resync's: the generations gkm holds past this device's, the
// epochs past its own by catch-up or resync, and the ladder below whatever it newly opened. A device that holds
// nothing of the repo yet takes its first wrap if one stands. See the file header for what waits.
func (self *GkmGroupClient) SyncRepo(ctx context.Context, repoId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return err
	}
	if err := manager.takeGenerationsInFlow(ctx, state); err != nil && !errors.Is(err, ErrGkmKeyMissing) {
		return err
	}
	if err := manager.syncEpochsInFlow(ctx, state); err != nil {
		return err
	}
	pins, err := self.repoPins(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	// an epoch's GenWrap may have brought a generation this device had no delivery of
	manager.walkLadderForLater(ctx, state, pins.groupId)
	return nil
}

// The behind, resync and probe rows for a device that holds, or held, a leaf of the repo's group. Nothing for one
// that never did: it joins by a Welcome (KF2).
func (self *gkmGroupManager) syncEpochsInFlow(ctx context.Context, state GkmAuthView) error {
	client := self.client
	if client.args.Mls == nil {
		return nil
	}
	pins, err := client.repoPins(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil
	}
	if err != nil {
		return err
	}
	if pins.epoch == 0 && len(pins.epochAuthenticator) == 0 {
		return nil
	}
	if 0 < pins.epoch && 0 < len(pins.epochAuthenticator) {
		// gkm must still serve the epoch this device adopted, or one past it: retention never deletes the newest
		standing, err := client.args.Api.Epochs(ctx, self.repoId, pins.groupId, pins.epoch-1)
		if err != nil {
			return err
		}
		if len(standing.GetEpochs()) == 0 {
			return client.pinForked(self.repoId, pins, HeadForkGroup, pins.groupHead(), nil, nil, true, "gkm serves no epoch at or past the one this device adopted")
		}
	}
	_, err = self.catchUpInFlow(ctx, state)
	if err != nil && !errors.Is(err, ErrGkmResyncNeeded) {
		return err
	}
	if err == nil {
		pins, err = client.repoPins(self.repoId)
		if err != nil {
			return err
		}
		_, err = client.loadGroup(pins.groupId)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrMlsGroupUnknown) && !errors.Is(err, ErrMlsNotMember) {
			return err
		}
		// it held a leaf and holds none: removed, or its state was lost
	}
	_, err = self.resyncInFlow(ctx, state)
	return err
}

// The newest epoch gkm holds of the group, from the group-info pointer and then epochs?after= to the end, with the
// group-info object as gkm served it, nil for none.
func (self *gkmGroupManager) newestEpochInFlow(ctx context.Context, pins *gkmRepoPins) (*protocol.GkmEpochEntry, *protocol.GkmGroupInfoObject, error) {
	client := self.client
	after := pins.epoch
	if 0 < after {
		after -= 1
	}
	groupInfoObject, err := client.args.Api.GroupInfo(ctx, self.repoId, pins.groupId, nil)
	if IsGkmStatus(err, http.StatusNotFound) {
		groupInfoObject, err = nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if after+1 < groupInfoObject.GetEpoch() {
		after = groupInfoObject.GetEpoch() - 1
	}
	var newest *protocol.GkmEpochEntry
	for {
		reply, err := client.args.Api.Epochs(ctx, self.repoId, pins.groupId, after)
		if err != nil {
			return nil, nil, err
		}
		entries := reply.GetEpochs()
		if len(entries) == 0 {
			return newest, groupInfoObject, nil
		}
		newest = entries[len(entries)-1]
		if newest.GetEpoch() <= after {
			return nil, nil, fmt.Errorf("%w: epochs out of order", ErrGkmReplyInvalid)
		}
		after = newest.GetEpoch()
	}
}

// An epoch's header as its commit's clear framing shows it, gkm's copy where the object carries no commit or one
// whose framing does not parse.
func gkmEpochObjectHeader(object *protocol.GkmEpochObject) (*protocol.GkmCommitHeader, error) {
	header := &protocol.GkmCommitHeader{}
	if parsed, err := ParseMlsHeader(object.GetCommit()); err == nil {
		if err := proto.Unmarshal(parsed.AuthenticatedData, header); err == nil {
			return header, nil
		}
	}
	if object.GetHeader() == nil {
		return nil, fmt.Errorf("%w: an epoch with no header", ErrGkmReplyInvalid)
	}
	return object.GetHeader(), nil
}

// The resync row. resynced is false, with no error, for a device its state does not seat: it holds no leaf by right,
// and waits for a re-add or reads by wraps.
func (self *gkmGroupManager) resyncInFlow(ctx context.Context, state GkmAuthView) (resynced bool, err error) {
	client := self.client
	reader, ok := client.args.Mls.(MlsGroupInfoReader)
	if !ok {
		return false, fmt.Errorf("%w: this engine reads no GroupInfo to resync from", ErrGkmResyncNeeded)
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return false, err
	}
	repo := state.Repo(self.repoId)
	if repo == nil {
		return false, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, self.repoId)
	}
	now := client.clock.Now()
	sidecarId := client.args.SidecarId
	holders, err := KeyHolders(state, self.repoId, now)
	if err != nil {
		return false, err
	}
	if !holders.Contains(GkmHolderLeaf, sidecarId.Bytes()) || gkmGroupLeafRanked(repo) && !GkmLeafEntitled(state, self.repoId, sidecarId, now) {
		return false, nil
	}

	// the newest epoch and its sealed GroupInfo
	newest, groupInfoObject, err := self.newestEpochInFlow(ctx, pins)
	if err != nil {
		return false, err
	}
	if newest == nil || newest.GetObject() == nil {
		return false, fmt.Errorf("%w: gkm holds no epoch to resync from", ErrGkmWait)
	}
	epoch := newest.GetEpoch()
	object := newest.GetObject()
	sealedGroupInfo, groupInfoGeneration := object.GetSealedGroupInfo(), object.GetGroupInfoGeneration()
	if len(sealedGroupInfo) == 0 {
		// above 16 leaves the GroupInfo rides group-info, written on request
		if groupInfoObject.GetEpoch() != epoch || len(groupInfoObject.GetSealedGroupInfo()) == 0 {
			client.askWant(ctx, self.repoId, pins.groupId, epoch)
			return false, fmt.Errorf("%w: no GroupInfo of epoch %d yet", ErrGkmWait, epoch)
		}
		sealedGroupInfo, groupInfoGeneration = groupInfoObject.GetSealedGroupInfo(), groupInfoObject.GetGeneration()
	}
	groupInfoHeld, err := client.heldGeneration(self.repoId, groupInfoGeneration)
	if err != nil {
		return false, err
	}
	if groupInfoHeld.key == nil {
		return false, fmt.Errorf("%w: generation %d, which seals the GroupInfo", ErrGkmKeyMissing, groupInfoGeneration)
	}
	groupInfo, err := OpenGkmGroupInfo(groupInfoHeld.key, pins.groupId, epoch, sealedGroupInfo)
	if err != nil {
		return false, err
	}
	groupId, groupInfoEpoch, roster, err := reader.GroupInfoRoster(groupInfo)
	if err != nil {
		return false, err
	}
	if groupId != pins.groupId || groupInfoEpoch != epoch {
		return false, fmt.Errorf("%w: a GroupInfo of another group or epoch", ErrGkmAuthentication)
	}

	// R1, R2: the newest generation, opened and judged, at a state at or past the epoch's pin and its own
	previousHeader, err := gkmEpochObjectHeader(object)
	if err != nil {
		return false, err
	}
	top, headerBytes, err := self.commitHeader(state, previousHeader)
	if err != nil {
		return false, err
	}

	// R3, before anything is staged: every leaf but this device's own old one is a key holder at this state
	base := &gkmExternalBase{groupId: groupId, epoch: epoch, roster: roster, self: MlsMember{SidecarId: sidecarId}}
	args := &MlsCommitArgs{Path: true, AuthenticatedData: headerBytes}
	keptLeafCount := 0
	for _, member := range roster {
		if member.SidecarId == sidecarId {
			base.self = member
			args.Removes = []uint32{member.LeafIndex}
			continue
		}
		keptLeafCount += 1
		if !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()) {
			client.askWant(ctx, self.repoId, groupId, epoch+1)
			return false, fmt.Errorf("%w: a resync waits: %w", ErrGkmWait, ErrGkmDroppedLeafStands)
		}
	}
	if min(max(client.settings.SeatCount, 0), GkmSeatCount) <= keptLeafCount {
		// no free seat: it waits keyless, or reads by wraps (§8.12)
		return false, nil
	}
	staged, err := client.args.Mls.JoinExternal(groupInfo, args)
	if err != nil {
		return false, err
	}
	outcome, err := self.uploadCommitInFlow(ctx, state, base, staged, previousHeader, top, nil)
	if err != nil {
		if errors.Is(err, ErrGkmDroppedLeafStands) {
			client.askWant(ctx, self.repoId, groupId, epoch+1)
		}
		return false, err
	}
	if outcome != gkmCommitAdopted {
		// another's commit took the epoch: the next pass starts over from the newer one
		return false, fmt.Errorf("%w: the resync lost its epoch", ErrGkmWait)
	}
	// an external join is a fresh path
	return true, client.notePathCommitted(self.repoId)
}

// H2's ask, at most once a LateAskInterval for a repo. A lost ask costs latency alone, so its error is dropped.
func (self *GkmGroupClient) askWant(ctx context.Context, repoId Id, groupId Id, epoch uint64) {
	now := self.clock.Now()
	due := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		askedAt, ok := self.repoIdWantAskedAt[repoId]
		if ok && now.Sub(askedAt) < self.settings.LateAskInterval {
			return false
		}
		self.repoIdWantAskedAt[repoId] = now
		return true
	}()
	if !due {
		return
	}
	if _, err := self.args.Api.GroupInfo(ctx, repoId, groupId, &epoch); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm]a want of epoch %d failed: %v", epoch, err)
	}
}

// H2's answer on a writer or any leaf that is not read_only: the pending engine, which commits what the waiting
// leaf needs, and above 16 leaves the newest epoch's GroupInfo at group-info, which rises at each write, so one that
// already stands for the epoch answers 409 and is left.
func (self *GkmGroupClient) AnswerWant(ctx context.Context, repoId Id) error {
	pendingErr := self.RunPending(ctx, repoId)
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return err
	}
	if row := state.SidecarRow(self.args.SidecarId); !gkmRowStanding(row) || gkmRowReadOnly(row) {
		return pendingErr
	}
	pins, err := self.repoPins(repoId)
	if err != nil {
		return errors.Join(pendingErr, err)
	}
	group, err := self.loadGroup(pins.groupId)
	if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
		return pendingErr
	}
	if err != nil {
		return errors.Join(pendingErr, err)
	}
	if len(group.Roster()) <= gkmGroupInfoInlineLeafCount || group.Epoch() != pins.epoch {
		return pendingErr
	}
	top, err := self.newestHeldGeneration(repoId)
	if err != nil || top.key == nil || top.poisoned {
		return errors.Join(pendingErr, err)
	}
	groupInfo, err := group.GroupInfo()
	if err != nil {
		return errors.Join(pendingErr, err)
	}
	sealedGroupInfo, err := SealGkmGroupInfo(top.key, pins.groupId, group.Epoch(), groupInfo)
	if err != nil {
		return errors.Join(pendingErr, err)
	}
	object := &protocol.GkmGroupInfoObject{Epoch: group.Epoch(), Generation: top.generation.Rotate.GetGeneration(), SealedGroupInfo: sealedGroupInfo}
	if err := self.args.Api.UploadGroupInfo(ctx, repoId, pins.groupId, object); err != nil && !IsGkmStatus(err, http.StatusConflict) {
		return errors.Join(pendingErr, err)
	}
	return pendingErr
}

// Notes a join through this device's last-resort KeyPackage: the repo owes a path-only commit at once, and the
// package is due its replacement.
func (self *gkmGroupManager) noteLastResortJoin() error {
	client := self.client
	now := client.clock.Now()
	if err := client.editSyncRecord(self.repoId, func(record *gkmSyncRecord) { record.selfUpdateOwed = true }); err != nil {
		return err
	}
	if err := client.args.Secrets.Put(gkmLastResortJoinedRecord, binary.BigEndian.AppendUint64(nil, uint64(now.UnixMilli()))); err != nil {
		return err
	}
	client.stateLock.Lock()
	defer client.stateLock.Unlock()
	client.lastResortJoinedAt = now
	client.lastResortJoinedLoaded = true
	return nil
}

// When this device last joined a group through its last-resort KeyPackage, zero for never: what GkmUpkeepRole
// carries to upkeep, which replaces a package uploaded before it.
func (self *GkmGroupClient) LastResortJoinedAt() time.Time {
	loaded, joinedAt := func() (bool, time.Time) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.lastResortJoinedLoaded, self.lastResortJoinedAt
	}()
	if loaded {
		return joinedAt
	}
	encoded, err := self.args.Secrets.Get(gkmLastResortJoinedRecord)
	if err == nil && len(encoded) == 8 {
		joinedAt = time.UnixMilli(int64(binary.BigEndian.Uint64(encoded)))
	} else if err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
		// read again at the next ask
		return time.Time{}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if !self.lastResortJoinedLoaded {
		self.lastResortJoinedAt = joinedAt
		self.lastResortJoinedLoaded = true
	}
	return self.lastResortJoinedAt
}
