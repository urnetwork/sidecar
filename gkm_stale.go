// §7.10's group view (KEYS-M4-01; D-TEAM-24, D-TEAM-29, FS-97; DESIGN-DETAILS 6.7): what the act that admits a
// member's page Worker reads of this device's MLS groups, so it revokes only Workers it saw removed as stale and
// never one that holds a leaf again (identity_act_stale.go's SidecarStaleGroupView).
//
//	live     the Worker holds a leaf of the group's current epoch and is not due
//	due      it holds a leaf whose credential's last change is stale_leaf_days and a day behind this clock, the day
//	         the pending engine waits before it commits §10.9's stale Remove (gkm_members.go), so the view says due
//	         exactly when CommitStaleRemove would commit
//	removed  it holds no leaf, and the last commit this device adopted that removed its leaf removed it as stale: a
//	         Remove of a leaf that was still a key holder, leaf-entitled where the group seats by rank, at the
//	         commit's own pin, neither a resync's own old leaf nor a re-add. Any later commit that adds it, or its own
//	         resync, takes the record away, and so does a Remove of it for any other input
//	none     no group of this device seated it: it has no leaf in the answer
//
// Each answer is read at the group's current epoch, fetched first: the view catches up, or resyncs, before it reads
// the tree, and a group it cannot bring current answers an error, so no revocation is signed on a stale tree.
//
// CommitStaleRemove is the pending engine's commit, so the Remove carries every other Remove the roster rule needs
// with it (R3): a stale Remove of a Worker whose tree holds a dropped leaf carries that Remove too.
//
// A Worker whose own self-update or resync waits under R3 is stale for that reason no sooner than any quiet leaf: the
// rule reads its leaf's credential alone, and it returns by resync once the Remove it waited on has landed, which
// takes its record away.
//
// What this device saw removed as stale is one keychain record a repo, <repo_id>/stale, written when a commit is
// adopted. LeafLastChanges serves §5's Devices() the same last-change data, from the trees this device holds.

package sidecar

import (
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The most stale removals a repo's record keeps, the newest by epoch: a group holds at most 1,000 leaves, and a
// member's weekly Workers leave about one a week each.
const gkmStaleRemovalMaxCount = 4096

// One leaf this device saw removed as stale.
type gkmStaleRemoval struct {
	sidecarId Id
	// the epoch its Remove made
	epoch uint64
	// the removed leaf's last change, by its credential; zero where it did not parse
	lastChange time.Time
}

const gkmStaleRemovalByteCount = gkmIdByteCount + 8 + 8

// version | u16 count | { sidecar_id | u64 epoch | u64 last_change_ms }.
func encodeGkmStaleRemovals(removals []*gkmStaleRemoval) []byte {
	encoded := []byte{gkmRecordVersion}
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(removals)))
	for _, removal := range removals {
		encoded = append(encoded, removal.sidecarId.Bytes()...)
		encoded = binary.BigEndian.AppendUint64(encoded, removal.epoch)
		lastChangeMs := uint64(0)
		if !removal.lastChange.IsZero() {
			lastChangeMs = uint64(removal.lastChange.UnixMilli())
		}
		encoded = binary.BigEndian.AppendUint64(encoded, lastChangeMs)
	}
	return encoded
}

// A stale record's removals.
func decodeGkmStaleRemovals(encoded []byte) ([]*gkmStaleRemoval, error) {
	malformed := fmt.Errorf("%w: a stale record", ErrGkmMalformed)
	if len(encoded) < 3 || encoded[0] != gkmRecordVersion {
		return nil, malformed
	}
	count := int(binary.BigEndian.Uint16(encoded[1:3]))
	rest := encoded[3:]
	if len(rest) != count*gkmStaleRemovalByteCount {
		return nil, malformed
	}
	removals := []*gkmStaleRemoval{}
	for ; 0 < len(rest); rest = rest[gkmStaleRemovalByteCount:] {
		sidecarId, err := IdFromBytes(rest[:gkmIdByteCount])
		if err != nil {
			return nil, malformed
		}
		removal := &gkmStaleRemoval{sidecarId: sidecarId, epoch: binary.BigEndian.Uint64(rest[gkmIdByteCount : gkmIdByteCount+8])}
		if lastChangeMs := binary.BigEndian.Uint64(rest[gkmIdByteCount+8 : gkmStaleRemovalByteCount]); lastChangeMs != 0 {
			removal.lastChange = time.UnixMilli(int64(lastChangeMs))
		}
		removals = append(removals, removal)
	}
	return removals, nil
}

// The repo's stale removals, none for no record.
func (self *gkmGroupManager) staleRemovals() ([]*gkmStaleRemoval, error) {
	encoded, err := self.client.getRecord(gkmRepoRecordName(self.repoId, "stale"))
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeGkmStaleRemovals(encoded)
}

// Keeps the repo's stale removals, the newest gkmStaleRemovalMaxCount by epoch, or no record for none.
func (self *gkmGroupManager) putStaleRemovals(removals []*gkmStaleRemoval) error {
	name := gkmRepoRecordName(self.repoId, "stale")
	if len(removals) == 0 {
		return self.client.args.Secrets.Delete(name)
	}
	slices.SortFunc(removals, func(a *gkmStaleRemoval, b *gkmStaleRemoval) int { return cmp.Compare(a.epoch, b.epoch) })
	if gkmStaleRemovalMaxCount < len(removals) {
		removals = removals[len(removals)-gkmStaleRemovalMaxCount:]
	}
	return self.client.args.Secrets.Put(name, encodeGkmStaleRemovals(removals))
}

// A commit this device adopted, its own or another's: the leaves it removed as stale are recorded, and a record of
// any sidecar that holds a leaf of the new epoch, or was removed for another input, is taken away. removed is the
// commit's Removes as they stood in the old epoch, roster the new epoch's leaves, header the commit's own, and at
// the time its roster was judged at. A record that cannot be written is dropped whole, so a failed write never leaves
// a Worker that came back recorded as removed.
func (self *gkmGroupManager) noteRosterChange(state GkmAuthView, header *protocol.GkmCommitHeader, removed []MlsMember, roster []MlsMember, epoch uint64, at time.Time) {
	client := self.client
	removals, err := self.staleRemovals()
	if err == nil && len(removals) == 0 && len(removed) == 0 {
		return
	}
	if err == nil {
		err = self.putStaleRemovals(self.staleRemovalsAfter(state, header, removals, removed, roster, epoch, at))
	}
	if err != nil {
		if client.log.V(1).Enabled() {
			client.log.Infof("[gkm]the stale removals were not kept, and are dropped: %v", err)
		}
		if err := client.args.Secrets.Delete(gkmRepoRecordName(self.repoId, "stale")); err != nil && client.log.V(1).Enabled() {
			client.log.Infof("[gkm]the stale removals were not dropped: %v", err)
		}
	}
}

// removals as one more adopted commit leaves them.
func (self *gkmGroupManager) staleRemovalsAfter(state GkmAuthView, header *protocol.GkmCommitHeader, removals []*gkmStaleRemoval, removed []MlsMember, roster []MlsMember, epoch uint64, at time.Time) []*gkmStaleRemoval {
	seated := map[Id]bool{}
	for _, member := range roster {
		seated[member.SidecarId] = true
	}
	// its own pin's state, where this device retains it: a Remove that cannot be judged records nothing
	var judged GkmAuthView
	var holders GkmHolders
	if judgedAt, err := state.At(header.GetAuth()); err == nil {
		judged = judgedAt
	}
	if judged != nil {
		var err error
		holders, err = KeyHolders(judged, self.repoId, at)
		if err != nil {
			judged = nil
		}
	}
	gone := map[Id]bool{}
	next := []*gkmStaleRemoval{}
	for _, member := range removed {
		gone[member.SidecarId] = true
		if seated[member.SidecarId] || judged == nil {
			// a resync's own old leaf or a re-add; or a pin this device no longer retains
			continue
		}
		// CheckCommit passed the Remove, so one of a leaf that still holds the key and its seat is the stale row's
		if !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()) {
			continue
		}
		if repo := judged.Repo(self.repoId); gkmGroupLeafRanked(repo) && !GkmLeafEntitled(judged, self.repoId, member.SidecarId, at) {
			continue
		}
		next = append(next, &gkmStaleRemoval{sidecarId: member.SidecarId, epoch: epoch, lastChange: gkmLeafLastChange(member)})
	}
	for _, removal := range removals {
		if !seated[removal.sidecarId] && !gone[removal.sidecarId] {
			next = append(next, removal)
		}
	}
	return next
}

// §7.10's group view over one sidecar's gkm client. See the file header.
type GkmStaleGroupView struct {
	client *GkmGroupClient
}

var _ SidecarStaleGroupView = (*GkmStaleGroupView)(nil)

// The view Sidecar.InstallStaleGroupView takes.
func NewGkmStaleGroupView(client *GkmGroupClient) *GkmStaleGroupView {
	return &GkmStaleGroupView{client: client}
}

// Whether this sidecar may commit a Remove from its leaf at a state (§10.9's Remove row): a standing member device
// that is not read_only, a writer or, where the group seats by rank, any such leaf.
func (self *gkmGroupManager) mayCommitRemoves(state GkmAuthView) bool {
	sidecarId := self.client.args.SidecarId
	row := state.SidecarRow(sidecarId)
	if !gkmRowStanding(row) || !gkmRowMemberDevice(row) || gkmRowReadOnly(row) {
		return false
	}
	return gkmWrites(state, self.repoId, sidecarId) || gkmGroupLeafRanked(state.Repo(self.repoId))
}

// Each of workerIds' leaves in the groups this device is a leaf of that seated it, each group read at its current
// epoch, fetched first. An error names a group that could not be brought current: the caller revokes nothing on it.
func (self *GkmStaleGroupView) StaleLeaves(ctx context.Context, workerIds []Id) ([]*SidecarStaleLeaf, error) {
	client := self.client
	repoIds, err := client.heldRepoIds()
	if err != nil {
		return nil, err
	}
	leaves := []*SidecarStaleLeaf{}
	for _, repoId := range repoIds {
		repoLeaves, err := client.manager(repoId).staleLeaves(ctx, workerIds)
		if err != nil {
			return nil, err
		}
		leaves = append(leaves, repoLeaves...)
	}
	return leaves, nil
}

// One group's part of StaleLeaves: nothing for a repo this device holds no leaf of.
func (self *gkmGroupManager) staleLeaves(ctx context.Context, workerIds []Id) ([]*SidecarStaleLeaf, error) {
	self.flowLock.Lock()
	defer self.flowLock.Unlock()
	client := self.client
	state, err := client.currentState()
	if err != nil {
		return nil, err
	}
	if err := self.syncEpochsInFlow(ctx, state); err != nil {
		return nil, err
	}
	pins, err := client.repoPins(self.repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	group, err := client.loadGroup(pins.groupId)
	if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	removals, err := self.staleRemovals()
	if err != nil {
		return nil, err
	}
	now := client.clock.Now()
	writer := self.mayCommitRemoves(state)
	roster := group.Roster()
	leaves := []*SidecarStaleLeaf{}
	for _, workerId := range workerIds {
		leaf := &SidecarStaleLeaf{GroupId: pins.groupId, WorkerId: workerId, Epoch: group.Epoch(), Writer: writer}
		memberIndex := slices.IndexFunc(roster, func(member MlsMember) bool { return member.SidecarId == workerId })
		removalIndex := slices.IndexFunc(removals, func(removal *gkmStaleRemoval) bool { return removal.sidecarId == workerId })
		switch {
		case 0 <= memberIndex:
			leaf.State = SidecarStaleLeafLive
			leaf.LastChange = gkmLeafLastChange(roster[memberIndex])
			if GkmLeafStale(state, roster[memberIndex], now.Add(-gkmStaleRemoveMargin)) {
				leaf.State = SidecarStaleLeafDue
			}
		case 0 <= removalIndex:
			leaf.State = SidecarStaleLeafRemoved
			leaf.LastChange = removals[removalIndex].lastChange
		default:
			// this group never seated it, as far as this device saw
			continue
		}
		leaves = append(leaves, leaf)
	}
	return leaves, nil
}

// Commits §10.9's stale Remove of workerId's leaf in groupId from this device's leaf, at the group's current epoch,
// once its staleness still holds there, with every other pending Remove and Add this device may commit. An error
// leaves the leaf as it was: ErrGkmWait when the leaf is no longer due or another's commit took the epoch,
// ErrGkmNotWriter when this device may not commit it.
func (self *GkmStaleGroupView) CommitStaleRemove(ctx context.Context, groupId Id, workerId Id) error {
	client := self.client
	repoId, ok := client.heldRepoOfGroup(groupId)
	if !ok {
		return fmt.Errorf("%w: no group %s is held", ErrMlsGroupUnknown, groupId)
	}
	manager := client.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := client.currentState()
	if err != nil {
		return err
	}
	if err := manager.syncEpochsInFlow(ctx, state); err != nil {
		return err
	}
	pins, err := client.repoPins(repoId)
	if err != nil {
		return err
	}
	pending, group, err := manager.pendingInFlow(state, pins)
	if err != nil {
		return err
	}
	if group == nil {
		return fmt.Errorf("%w: this device is no leaf of the group", ErrGkmNotWriter)
	}
	roster := group.Roster()
	memberIndex := slices.IndexFunc(roster, func(member MlsMember) bool { return member.SidecarId == workerId })
	if memberIndex < 0 || !GkmLeafStale(state, roster[memberIndex], client.clock.Now().Add(-gkmStaleRemoveMargin)) {
		return fmt.Errorf("%w: the leaf is not due a stale Remove at the group's epoch", ErrGkmWait)
	}
	removes, adds := GkmMayCommit(state, repoId, client.args.SidecarId, roster, pending)
	if !slices.ContainsFunc(removes, func(member MlsMember) bool { return member.SidecarId == workerId }) {
		return fmt.Errorf("%w: this device may not commit the Remove", ErrGkmNotWriter)
	}
	outcome, err := manager.commitMembersInFlow(ctx, state, pins, group, removes, adds)
	if err != nil {
		return err
	}
	if outcome != gkmCommitAdopted {
		return fmt.Errorf("%w: the stale Remove lost its epoch", ErrGkmWait)
	}
	return manager.writeOwedWelcomes(ctx, pins.groupId)
}

// The last change of each of sidecarIds' leaves in the groups this device is a leaf of, the newest across them, by
// the credentials in the trees it holds: what §5's Devices() shows as MemberDevice.LastChange. A sidecar that holds
// no leaf this device sees has no entry. It reads this device's own MLS state and calls nothing.
func (self *GkmGroupClient) LeafLastChanges(sidecarIds []Id) (map[Id]time.Time, error) {
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return nil, err
	}
	sidecarIdLastChanges := map[Id]time.Time{}
	for _, repoId := range repoIds {
		err := func() error {
			manager := self.manager(repoId)
			manager.flowLock.Lock()
			defer manager.flowLock.Unlock()
			pins, err := self.repoPins(repoId)
			if err != nil {
				return err
			}
			group, err := self.loadGroup(pins.groupId)
			if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
				return nil
			}
			if err != nil {
				return err
			}
			for _, member := range group.Roster() {
				if !slices.Contains(sidecarIds, member.SidecarId) {
					continue
				}
				if lastChange := gkmLeafLastChange(member); sidecarIdLastChanges[member.SidecarId].Before(lastChange) {
					sidecarIdLastChanges[member.SidecarId] = lastChange
				}
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return sidecarIdLastChanges, nil
}
