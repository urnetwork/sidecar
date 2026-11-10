// The pending-change engine (KEYS-M2-21; DESIGN-DETAILS 6.2.4): what a group needs changed at a state, which of it
// one device may commit, and the flows that commit it: KF2 and KF3's Adds, KF4's Removes and the rotation after, and
// KF6's loser path. One commit carries every Remove the roster rule needs with every Add (R3), so no honest device
// writes an epoch that others must refuse.
//
//	Pending(S, e) for a leaf of epoch e, H = KeyHolders(S, now):
//	  removes  tree(e) \ H, every dropped leaf; in the config and directory groups a leaf that lost entitlement
//	           (§7.9's move); a stale leaf, a day past §10.9's stale rule; a joiner whose Welcome never appeared
//	           WelcomeTimeout after its epoch, which is added again in the same commit
//	  adds     member devices in H outside the tree: leaf-entitled in the config and directory groups, else seated,
//	           the earliest-admitted first up to SeatCount (§8.12); consented where the repo is owner-bound, an
//	           unconsented device parking and raising approval_pending (§8.5); anchored where a restored binding
//	           admitted it (§10.8); and only with a KeyPackage gkm serves, which the claim tells
//	  rotate   the newest generation does not cover the repo's holders_shrunk_at or an expiry at S, or is older than
//	           ScheduleInterval
//
//	may(c)   c commits removes and adds iff c is a leaf that stands, is a member device and is not read_only, and
//	         writes the repo; in the config and directory groups such a leaf that does not write still commits the
//	         Removes and the Adds of devices whose admission it signed (owner decisions 128, 182); a wrapped writer
//	         commits nothing and rotates
//
//	Run(c)   while something is pending that c may commit: process what gkm holds past c's epoch; commit removes and
//	         adds in one commit; write each owed Welcome and its pointers; rotate if due; look again
//
// Commit is 6.2.4's machine: the commit is staged, its GenWrap sealed under the new epoch's KEK, and the committer
// runs CheckCommit on it before it uploads it; a 200 adopts it and owes its Welcome, a 409 discards it and the
// winner is processed (KF6), a 403 is alarmed, and an outcome it cannot learn is read back from epoch/<n>. Process is
// the same check on a commit another made, at its header's pin: a refusal is alarmed naming the committer and the
// epoch, the commit is never adopted, and a roster refusal poisons the generation its GenWrap carried.
//
// A leaf that may not commit the Remove its tree needs, a read_only one, commits nothing while that leaf stands
// (R3's wait): its own check refuses the commit before any upload, and a writer leaf's Remove releases it.
//
// The first wrap of an agent or of a wrapped member device is a late delivery (gkm_deliver.go), which gkm's
// wrap-pending hint or the granting device's DeliverFirstWrap brings.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The barriers around the epoch's create, keyed <group_id>:<n>.
const (
	gkmBarrierCommitEpochBefore = "gkm.commit.epoch.before"
	gkmBarrierCommitEpochAfter  = "gkm.commit.epoch.after"
)

// A writer leaf commits a stale Remove only a day past §10.9's stale rule (plan-KEYS-stale-remove-evidence), so
// two clocks a minute apart do not disagree on it: a rule every committer follows alike.
const gkmStaleRemoveMargin = 24 * time.Hour

// At most this many leaves, an epoch's object carries its sealed GroupInfo inline; above, group-info holds it
// (§10.6).
const gkmGroupInfoInlineLeafCount = 16

var (
	// A member check refused a commit this device made or received: it is never adopted.
	ErrGkmCommitRefused = errors.New("gkm: a commit failed its member checks")
	// This device's own commit would leave a leaf in the tree that is no key holder at its state, and it may not
	// commit that leaf's Remove: it commits nothing until a writer leaf does (R3's wait). It comes wrapped in
	// ErrGkmCommitRefused.
	ErrGkmDroppedLeafStands = errors.New("gkm: a dropped leaf stands in the tree")
	// This device is too far behind, or cannot process what gkm holds: it resyncs (KF5, KEYS-M2-23).
	ErrGkmResyncNeeded = errors.New("gkm: the group needs a resync")
)

// What a group needs changed at a state, as one leaf sees it. A pure function's answer: nothing here says who may
// commit it.
type GkmPending struct {
	// Leaves due a Remove, by leaf index.
	Removes []MlsMember
	// Member devices due an Add, the earliest-admitted first. A device named in Removes too is a re-add.
	Adds []Id
	// Reading member devices of a data repo left without a seat, the earliest-admitted first: each waits keyless,
	// and the writer's preview names the repo (§8.12).
	Waiting []Id
	// An owner-bound repo's owner devices that have not consented: parked, with no Add and no wrap (§8.5).
	Unconsented []Id
	// Devices a restored binding admitted that are not yet anchored: no Add until they are (§10.8).
	Unanchored []Id
	// Whether a rotation is due, and for what: REMOVE when the newest generation does not cover the state,
	// SCHEDULE when it is only old.
	Rotate      bool
	RotateCause GkmCause
}

// Whether nothing is pending.
func (self *GkmPending) Empty() bool {
	return len(self.Removes) == 0 && len(self.Adds) == 0 && !self.Rotate
}

// What GkmPendingChanges reads beside the state.
type GkmPendingArgs struct {
	RepoId Id
	// tree(e): the leaves of the newest epoch this device adopted.
	Roster []MlsMember
	// gen/<g*>, the newest generation this device holds; nil reads no rotation as due.
	Generation *GkmGeneration
	// Whether this device holds that generation as poisoned.
	GenerationPoisoned bool
	// Leaves added at an epoch whose Welcome has not appeared WelcomeTimeout after it.
	Unwelcomed []Id
	// GkmGroupClientArgs.Anchored; nil reads every device as anchored.
	Anchored func(sidecarId Id) bool
	// GkmSettings.SeatCount and ScheduleInterval.
	SeatCount        int
	ScheduleInterval time.Duration
	Now              time.Time
}

// 6.2.4's Pending(S, e): what the group of args.RepoId needs changed at view and args.Now. Pure, so the tests and
// FS-104's oracle call it as the engine does.
func GkmPendingChanges(view GkmAuthView, args *GkmPendingArgs) (*GkmPending, error) {
	if view == nil || args == nil || args.Now.IsZero() {
		return nil, fmt.Errorf("%w: pending changes need a state and a clock", ErrGkmMalformed)
	}
	repo := view.Repo(args.RepoId)
	if repo == nil {
		return nil, fmt.Errorf("%w: repo %s", ErrGkmNoRepo, args.RepoId)
	}
	holders, err := KeyHolders(view, args.RepoId, args.Now)
	if err != nil {
		return nil, err
	}
	leafRanked := gkmGroupLeafRanked(repo)
	seatCount := min(max(args.SeatCount, 0), GkmSeatCount)
	pending := &GkmPending{}

	inTree := map[Id]bool{}
	removed := map[Id]bool{}
	for _, member := range args.Roster {
		inTree[member.SidecarId] = true
		switch {
		case !holders.Contains(GkmHolderLeaf, member.SidecarId.Bytes()):
			// dropped: a revocation, park, Suspend, grant end or expiry
		case leafRanked && !GkmLeafEntitled(view, args.RepoId, member.SidecarId, args.Now):
			// §7.9's move: it reads on by wraps
		case GkmLeafStale(view, member, args.Now.Add(-gkmStaleRemoveMargin)):
			// quiet past stale_leaf_days: it returns by resync
		case slices.Contains(args.Unwelcomed, member.SidecarId):
			// its Welcome never appeared: removed here and added again below
		default:
			continue
		}
		removed[member.SidecarId] = true
		pending.Removes = append(pending.Removes, member)
	}
	slices.SortFunc(pending.Removes, func(a MlsMember, b MlsMember) int { return cmp.Compare(a.LeafIndex, b.LeafIndex) })

	// the member devices that read and have no leaf, or lose theirs to a re-add
	candidateIds := []Id{}
	for _, holder := range holders {
		if holder.Kind != GkmHolderLeaf {
			continue
		}
		sidecarId, err := IdFromBytes(holder.Id)
		if err != nil {
			return nil, fmt.Errorf("%w: a holder's id", ErrGkmMalformed)
		}
		if inTree[sidecarId] && !slices.Contains(args.Unwelcomed, sidecarId) {
			continue
		}
		row := view.SidecarRow(sidecarId)
		if !gkmRowMemberDevice(row) || !gkmRowStanding(row) {
			continue
		}
		if ownerMemberId := repo.GetOwnerMemberId(); 0 < len(ownerMemberId) && bytes.Equal(ownerMemberId, row.GetMemberId()) &&
			!slices.ContainsFunc(repo.GetConsentedSidecarIds(), func(consented []byte) bool { return bytes.Equal(consented, sidecarId.Bytes()) }) {
			pending.Unconsented = append(pending.Unconsented, sidecarId)
			continue
		}
		if args.Anchored != nil && !args.Anchored(sidecarId) {
			pending.Unanchored = append(pending.Unanchored, sidecarId)
			continue
		}
		if leafRanked && !GkmLeafEntitled(view, args.RepoId, sidecarId, args.Now) {
			// past the first 1,000: it reads by wraps
			continue
		}
		candidateIds = append(candidateIds, sidecarId)
	}
	keptLeafCount := len(args.Roster) - len(pending.Removes)
	pending.Adds, pending.Waiting = gkmFillSeats(view, candidateIds, max(seatCount-keptLeafCount, 0))

	if args.Generation != nil && args.Generation.Rotate != nil {
		rotate := args.Generation.Rotate
		generationTime := time.UnixMilli(rotate.GetTimeMs())
		gate := GkmGateCheck(view, args.RepoId, rotate.GetAuth(), generationTime, args.Now)
		switch {
		case args.GenerationPoisoned || errors.Is(gate, ErrGkmGateClosed):
			pending.Rotate = true
			pending.RotateCause = GkmCauseRemove
		case gate != nil:
			// the pin is above this state, or the state cannot answer: nothing is rotated on a guess
		case 0 < args.ScheduleInterval && generationTime.Add(args.ScheduleInterval).Before(args.Now):
			pending.Rotate = true
			pending.RotateCause = GkmCauseSchedule
		}
	}
	return pending, nil
}

// 6.2.4's may(c): which of pending this sidecar may commit from its leaf at a state. The Removes are all or none,
// since a commit that carries only some breaks the roster rule; the Adds are those it may make.
func GkmMayCommit(view GkmAuthView, repoId Id, sidecarId Id, roster []MlsMember, pending *GkmPending) (removes []MlsMember, adds []Id) {
	repo := view.Repo(repoId)
	row := view.SidecarRow(sidecarId)
	isLeaf := slices.ContainsFunc(roster, func(member MlsMember) bool { return member.SidecarId == sidecarId })
	if repo == nil || pending == nil || !isLeaf || !gkmRowStanding(row) || !gkmRowMemberDevice(row) || gkmRowReadOnly(row) {
		return nil, nil
	}
	if slices.ContainsFunc(pending.Removes, func(member MlsMember) bool { return member.SidecarId == sidecarId }) {
		// a leaf never removes itself, and one due a Remove commits nothing
		return nil, nil
	}
	if gkmWrites(view, repoId, sidecarId) {
		return pending.Removes, pending.Adds
	}
	if !gkmGroupLeafRanked(repo) {
		return nil, nil
	}
	for _, addId := range pending.Adds {
		addRow := view.SidecarRow(addId)
		if addRow != nil && slices.ContainsFunc(addRow.GetAdmissionSigners(), func(signer []byte) bool { return bytes.Equal(signer, sidecarId.Bytes()) }) {
			adds = append(adds, addId)
		}
	}
	return pending.Removes, adds
}

// Whether this sidecar signed the admission of a device pending changes would add: the granting device, which
// commits at once while other writer leaves wait PendingCommitDelay (KF2, KF3).
func GkmGrantingDevice(view GkmAuthView, sidecarId Id, pending *GkmPending) bool {
	for _, addId := range pending.Adds {
		row := view.SidecarRow(addId)
		if row != nil && slices.ContainsFunc(row.GetAdmissionSigners(), func(signer []byte) bool { return bytes.Equal(signer, sidecarId.Bytes()) }) {
			return true
		}
	}
	return false
}

// What a device sees pending for a repo now, and whether it is the granting device: what its driver reads to decide
// when to run the engine. ErrGkmKeyMissing for a repo this device holds no group of.
func (self *GkmGroupClient) Pending(ctx context.Context, repoId Id) (*GkmPending, bool, error) {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return nil, false, err
	}
	pins, err := self.repoPins(repoId)
	if err != nil {
		return nil, false, err
	}
	pending, _, err := manager.pendingInFlow(state, pins)
	if err != nil {
		return nil, false, err
	}
	return pending, GkmGrantingDevice(state, self.args.SidecarId, pending), nil
}

// How long this device's driver waits before it runs the engine for a pending change: nothing for the granting
// device, PendingCommitDelay plus jitter for every other writer.
func (self *GkmGroupClient) PendingCommitWait(granting bool) time.Duration {
	if granting {
		return 0
	}
	return self.settings.PendingCommitDelay + self.jitter(self.settings.PendingCommitJitter)
}

// Pending at a state for this device: its tree where it is a leaf, an empty one where it holds no leaf.
func (self *gkmGroupManager) pendingInFlow(state GkmAuthView, pins *gkmRepoPins) (*GkmPending, MlsGroup, error) {
	client := self.client
	args := &GkmPendingArgs{
		RepoId:           self.repoId,
		Anchored:         client.args.Anchored,
		SeatCount:        client.settings.SeatCount,
		ScheduleInterval: client.settings.ScheduleInterval,
		Now:              client.clock.Now(),
	}
	group, err := client.loadGroup(pins.groupId)
	switch {
	case err == nil:
		args.Roster = group.Roster()
	case errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember):
		group = nil
	default:
		return nil, nil, err
	}
	if top, err := client.newestHeldGeneration(self.repoId); err == nil {
		args.Generation = top.generation
		args.GenerationPoisoned = top.poisoned
	} else if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, nil, err
	}
	// Unwelcomed stays empty: no route shows a leaf whether another's Welcome was written, so the WelcomeTimeout
	// re-add waits on question keys-m2-19-welcome-timeout-evidence and fails closed. This device's own Welcomes
	// are never lost: they are in the keychain before their commit is uploaded (writeOwedWelcomes).
	pending, err := GkmPendingChanges(state, args)
	if err != nil {
		return nil, nil, err
	}
	if group == nil {
		// a sidecar that holds no leaf sees no tree: it commits nothing, and only its rotation is its own
		pending.Adds, pending.Removes, pending.Waiting = nil, nil, nil
	}
	return pending, group, nil
}

// EnsureWritable's step 2 and the pending hint's work (6.2.4's Run(c)): processes what gkm holds past this device's
// epoch, commits every pending Remove and Add this device may, writes the Welcomes it owes, and rotates when the
// newest generation does not cover its state or is past its schedule, until nothing it may do is left. It returns
// nil when the group needs nothing of this device, ErrGkmCommitRefused when a commit that stands at gkm failed its
// checks, and the wait errors of its flows.
func (self *GkmGroupClient) RunPending(ctx context.Context, repoId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	return manager.runPendingInFlow(ctx)
}

// RunPending with the group's flow held.
func (self *gkmGroupManager) runPendingInFlow(ctx context.Context) error {
	client := self.client
	for passCount := 0; passCount < max(1, client.settings.PendingPassCount); passCount += 1 {
		state, err := client.currentState()
		if err != nil {
			return err
		}
		pins, err := client.repoPins(self.repoId)
		if err != nil {
			return err
		}
		// a Welcome owed from before a kill goes first: its joiners wait on it
		if err := self.writeOwedWelcomes(ctx, pins.groupId); err != nil {
			return err
		}
		if _, err := self.catchUpInFlow(ctx, state); err != nil {
			return err
		}
		pins, err = client.repoPins(self.repoId)
		if err != nil {
			return err
		}
		pending, group, err := self.pendingInFlow(state, pins)
		if err != nil {
			return err
		}
		for _, sidecarId := range pending.Unconsented {
			client.alarm(&GkmAlarm{Kind: GkmAlarmApprovalPending, RepoId: self.repoId, GroupId: pins.groupId, SidecarId: sidecarId, Detail: "an owner-bound repo's device waits for consent"})
		}
		lost := false
		if group != nil {
			removes, adds := GkmMayCommit(state, self.repoId, client.args.SidecarId, group.Roster(), pending)
			if 0 < len(removes) || 0 < len(adds) {
				outcome, err := self.commitMembersInFlow(ctx, state, pins, group, removes, adds)
				if err != nil {
					return err
				}
				switch outcome {
				case gkmCommitLost:
					// KF6: the winner is processed at the next pass, and what remains is committed after
					lost = true
				case gkmCommitNothing:
					// no Remove to make and no KeyPackage to add with: the joiners wait
				}
				if err := self.writeOwedWelcomes(ctx, pins.groupId); err != nil {
					return err
				}
			}
		}
		if lost {
			continue
		}
		if pending.Rotate {
			holders, err := KeyHolders(state, self.repoId, client.clock.Now())
			if err != nil {
				return err
			}
			if self.mayRotate(state, holders, client.clock.Now()) == nil {
				if _, err := self.rotateInFlow(ctx, pending.RotateCause); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return fmt.Errorf("%w: the commit was lost %d times", ErrGkmWait, max(1, client.settings.PendingPassCount))
}

// How a commit of this device ended.
type gkmCommitOutcome int

const (
	// gkm answered 200 and the commit is adopted.
	gkmCommitAdopted gkmCommitOutcome = iota + 1
	// gkm answered 409: another's commit holds the epoch, and this one is discarded.
	gkmCommitLost
	// Nothing was committed: no Remove was due and no device to add had a KeyPackage.
	gkmCommitNothing
)

// One KeyPackage claimed for an Add.
type gkmClaimedKeyPackage struct {
	sidecarId  Id
	ref        []byte
	keyPackage []byte
}

// KF2 to KF4's commit: claims a KeyPackage for each Add, a device with none waiting, and commits them with every
// Remove in one commit.
func (self *gkmGroupManager) commitMembersInFlow(ctx context.Context, state GkmAuthView, pins *gkmRepoPins, group MlsGroup, removes []MlsMember, adds []Id) (gkmCommitOutcome, error) {
	client := self.client
	claimed := []*gkmClaimedKeyPackage{}
	for _, addId := range adds {
		reply, err := client.args.Api.ClaimKeyPackage(ctx, self.repoId, pins.groupId, addId)
		if IsGkmStatus(err, http.StatusNotFound) {
			// it has uploaded none yet: it waits, and where the group wraps it reads by a first wrap
			continue
		}
		if err != nil {
			return 0, err
		}
		claimed = append(claimed, &gkmClaimedKeyPackage{sidecarId: addId, ref: reply.GetKeyPackageRef(), keyPackage: reply.GetKeyPackage()})
	}
	// a re-add needs its KeyPackage: without one the joiner keeps its leaf and its Welcome is still owed by another
	keptRemoves := []MlsMember{}
	for _, member := range removes {
		readded := slices.Contains(adds, member.SidecarId)
		if readded && !slices.ContainsFunc(claimed, func(keyPackage *gkmClaimedKeyPackage) bool { return keyPackage.sidecarId == member.SidecarId }) {
			continue
		}
		keptRemoves = append(keptRemoves, member)
	}
	if len(keptRemoves) == 0 && len(claimed) == 0 {
		return gkmCommitNothing, nil
	}
	args := &MlsCommitArgs{Path: 0 < len(keptRemoves)}
	for _, member := range keptRemoves {
		args.Removes = append(args.Removes, member.LeafIndex)
	}
	recipients := []*protocol.GkmWelcomeRecipient{}
	for _, keyPackage := range claimed {
		args.Adds = append(args.Adds, keyPackage.keyPackage)
		recipients = append(recipients, &protocol.GkmWelcomeRecipient{SidecarId: keyPackage.sidecarId.Bytes(), KeyPackageRef: keyPackage.ref})
	}
	return self.commitInFlow(ctx, state, pins, group, args, recipients)
}

// A path-only commit of this device's leaf, a self-update (§10.4, D-KEYS-26), under the same rules as any commit: a
// read_only leaf's too, which its own check refuses while its tree holds a dropped leaf (R3's wait).
func (self *GkmGroupClient) SelfUpdate(ctx context.Context, repoId Id) error {
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return err
	}
	if _, err := manager.catchUpInFlow(ctx, state); err != nil {
		return err
	}
	pins, err := self.repoPins(repoId)
	if err != nil {
		return err
	}
	group, err := self.loadGroup(pins.groupId)
	if err != nil {
		return err
	}
	outcome, err := manager.commitInFlow(ctx, state, pins, group, &MlsCommitArgs{Path: true}, nil)
	if err != nil {
		return err
	}
	if outcome == gkmCommitLost {
		// another's commit took the epoch: the next pass processes it, and the self-update is due again after
		return fmt.Errorf("%w: the self-update lost its epoch", ErrGkmWait)
	}
	return nil
}

// 6.2.4's Commit: stages args on group, seals GenWrap_{e+1} and, at 16 leaves or fewer, GroupInfo_{e+1}, checks the
// staged commit as every member will, and uploads it.
func (self *gkmGroupManager) commitInFlow(ctx context.Context, state GkmAuthView, pins *gkmRepoPins, group MlsGroup, args *MlsCommitArgs, recipients []*protocol.GkmWelcomeRecipient) (gkmCommitOutcome, error) {
	client := self.client
	// R1: at the newest epoch this device adopted, with a state at or past its pin and the generation's
	if group.Epoch() != pins.epoch {
		return 0, fmt.Errorf("%w: the engine's epoch %d is not the pinned %d", ErrGkmResyncNeeded, group.Epoch(), pins.epoch)
	}
	previousHeader := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(pins.epochHeader, previousHeader); err != nil {
		return 0, fmt.Errorf("%w: the pinned epoch's header", ErrGkmMalformed)
	}
	top, headerBytes, err := self.commitHeader(state, previousHeader)
	if err != nil {
		return 0, err
	}
	stagedArgs := *args
	stagedArgs.AuthenticatedData = headerBytes
	staged, err := group.Commit(&stagedArgs)
	if err != nil {
		return 0, err
	}
	outcome, err := self.uploadCommitInFlow(ctx, state, group, staged, previousHeader, top, recipients)
	if err == nil && outcome == gkmCommitAdopted && args.Path {
		// this leaf's path is fresh: the self-update interval starts over, and a last-resort join's is paid
		err = client.notePathCommitted(self.repoId)
	}
	return outcome, err
}

// The generation a commit carries and its header, under R1 and R2: the newest generation this device holds, opened
// and not poisoned, with this state at or past the previous epoch's pin and that generation's.
func (self *gkmGroupManager) commitHeader(state GkmAuthView, previousHeader *protocol.GkmCommitHeader) (*gkmHeldGeneration, []byte, error) {
	top, err := self.client.newestHeldGeneration(self.repoId)
	if err != nil {
		return nil, nil, err
	}
	if top.key == nil || top.poisoned {
		// nothing is sealed to a poisoned generation: the rotation past it comes first
		return nil, nil, fmt.Errorf("%w: generation %d is poisoned or unopened", ErrGkmWait, top.generation.Rotate.GetGeneration())
	}
	if state.Pin().GetVersion() < previousHeader.GetAuth().GetVersion() || state.Pin().GetVersion() < top.generation.Rotate.GetAuth().GetVersion() {
		return nil, nil, fmt.Errorf("%w: this state is below the epoch's or the generation's pin", ErrGkmAuthAhead)
	}
	header := &protocol.GkmCommitHeader{Generation: top.generation.Rotate.GetGeneration(), Auth: state.Pin()}
	headerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		return nil, nil, err
	}
	return top, headerBytes, nil
}

// The rest of 6.2.4's Commit for a commit staged on base's epoch, a member's on its own group or a resync's external
// commit on the epoch its GroupInfo names: GenWrap_{e+1}, the committer's own check, GroupInfo_{e+1}, the upload and
// its outcome. A staged commit that is not adopted is discarded.
func (self *gkmGroupManager) uploadCommitInFlow(ctx context.Context, state GkmAuthView, base MlsGroup, staged MlsStagedCommit, previousHeader *protocol.GkmCommitHeader, top *gkmHeldGeneration, recipients []*protocol.GkmWelcomeRecipient) (gkmCommitOutcome, error) {
	client := self.client
	groupId := base.GroupId()
	generation := top.generation.Rotate.GetGeneration()
	headerBytes := staged.AuthenticatedData()
	adopted := false
	defer func() {
		if !adopted {
			staged.Discard()
		}
	}()
	epoch := staged.Epoch()
	kek, err := MlsKek(staged, self.repoId)
	if err != nil {
		return 0, err
	}
	genWrap, err := SealGkmGenWrap(top.key, groupId, epoch, kek)
	clear(kek)
	if err != nil {
		return 0, err
	}
	now := client.clock.Now()
	// the committer's own check: a commit others must refuse leaks the moment it stands, so it is never uploaded
	check, err := CheckCommit(state, base, staged, &GkmCommitCheckArgs{
		RepoId: self.repoId, PreviousHeader: previousHeader, Generation: top.generation, GenWrap: genWrap, Time: now, Now: now,
	})
	if err != nil {
		return 0, err
	}
	if check.Verdict.Refused {
		if check.Verdict.Reason == GkmRefusalRoster {
			// R3's wait: a leaf this commit may not remove stands in the tree, and a writer leaf's Remove releases it
			return 0, fmt.Errorf("%w: %w: %s", ErrGkmCommitRefused, ErrGkmDroppedLeafStands, check.Verdict.Detail)
		}
		return 0, fmt.Errorf("%w: %s: %s", ErrGkmCommitRefused, check.Verdict.Reason, check.Verdict.Detail)
	}
	request := &protocol.GkmEpochRequest{Commit: staged.Message(), GenWrap: genWrap}
	var groupInfoObject *protocol.GkmGroupInfoObject
	groupInfo, err := staged.GroupInfo()
	if err != nil {
		return 0, err
	}
	sealedGroupInfo, err := SealGkmGroupInfo(top.key, groupId, epoch, groupInfo)
	if err != nil {
		return 0, err
	}
	if len(check.Roster) <= gkmGroupInfoInlineLeafCount {
		request.SealedGroupInfo = sealedGroupInfo
		request.GroupInfoGeneration = generation
	} else {
		groupInfoObject = &protocol.GkmGroupInfoObject{Epoch: epoch, Generation: generation, SealedGroupInfo: sealedGroupInfo}
	}

	// the Welcome this commit will owe, kept before the upload: a kill after the 200 loses nothing
	owes := 0 < len(recipients) && 0 < len(staged.Welcome())
	if owes {
		if err := self.oweWelcome(epoch, request.GetCommit(), &protocol.GkmWelcomeRequest{Welcome: staged.Welcome(), Recipients: recipients}); err != nil {
			return 0, err
		}
	}
	lose := func() (gkmCommitOutcome, error) {
		if owes {
			if err := self.dropOwedWelcome(epoch); err != nil {
				return 0, err
			}
		}
		return gkmCommitLost, nil
	}
	barrierKey := gkmPathId(groupId) + ":" + strconv.FormatUint(epoch, 10)
	landed := false
	for sendCount := 0; !landed; sendCount += 1 {
		if max(1, client.settings.CommitSendCount) <= sendCount {
			return 0, fmt.Errorf("%w: the commit of epoch %d got no answer", ErrGkmUnavailable, epoch)
		}
		testHookBarrier(gkmBarrierCommitEpochBefore, barrierKey)
		err := client.args.Api.CommitEpoch(ctx, self.repoId, groupId, epoch, request)
		testHookBarrier(gkmBarrierCommitEpochAfter, barrierKey)
		gkmError, refused := GkmErrorOf(err)
		switch {
		case err == nil:
			landed = true
		case refused && gkmError.Status == http.StatusConflict:
			return lose()
		case refused && gkmError.Status == http.StatusForbidden:
			// its rate, pin or header check, where this device's own passed
			client.alarm(&GkmAlarm{Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: groupId, Epoch: epoch, SidecarId: client.args.SidecarId, Detail: "gkm refused a commit this device's checks passed"})
			return 0, fmt.Errorf("%w: gkm refused the commit of epoch %d", ErrGkmWait, epoch)
		case refused:
			return 0, err
		case ctx.Err() != nil:
			return 0, err
		default:
			// unknown: what stands at epoch/<n> says what happened
			standing, readErr := client.args.Api.Epochs(ctx, self.repoId, groupId, epoch-1)
			if readErr != nil {
				return 0, readErr
			}
			if 0 < len(standing.GetEpochs()) && standing.GetEpochs()[0].GetEpoch() == epoch {
				if !bytes.Equal(standing.GetEpochs()[0].GetObject().GetCommit(), request.GetCommit()) {
					return lose()
				}
				landed = true
			}
			// nothing there: the same bytes go again
		}
	}
	// 200: adopt
	epochAuthenticator := staged.EpochAuthenticator()
	if _, err := staged.Adopt(); err != nil {
		return 0, err
	}
	adopted = true
	err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
		pins.groupId = groupId
		pins.epoch = epoch
		pins.epochAuthenticator = epochAuthenticator
		pins.epochHeader = headerBytes
	})
	if err != nil {
		return 0, err
	}
	if groupInfoObject != nil {
		// above 16 leaves the GroupInfo rides group-info, which rises at each write; a lost one is asked for again
		// by a joiner's or a resyncer's ?want=
		if err := client.args.Api.UploadGroupInfo(ctx, self.repoId, groupId, groupInfoObject); err != nil && client.log.V(1).Enabled() {
			client.log.Infof("[gkm]group-info of epoch %d was not written: %v", epoch, err)
		}
	}
	return gkmCommitAdopted, nil
}

// gen/<g> as this device may build on it: its own record where it holds one, else fetched, verified and judged by
// the rotation checks, with gen/<g-1> for the chain. A refused one is recorded as poisoned and alarmed.
func (self *gkmGroupManager) judgedGeneration(ctx context.Context, state GkmAuthView, groupId Id, generation uint64) (*gkmHeldGeneration, error) {
	client := self.client
	held, err := client.heldGeneration(self.repoId, generation)
	if err == nil {
		return held, nil
	}
	if !errors.Is(err, ErrGkmKeyMissing) {
		return nil, err
	}
	fetched, err := client.fetchGeneration(ctx, state, self.repoId, groupId, generation)
	if err != nil {
		return nil, err
	}
	checkArgs := &GkmRotationCheckArgs{RepoId: self.repoId, Generation: fetched, DropKeyLifetime: client.settings.DropKeyLifetime, Now: client.clock.Now()}
	if 1 < generation {
		if parent, err := client.heldGeneration(self.repoId, generation-1); err == nil {
			checkArgs.Parent = parent.generation
			checkArgs.ParentPoisoned = parent.poisoned
		} else if errors.Is(err, ErrGkmKeyMissing) {
			checkArgs.Parent, err = client.fetchGeneration(ctx, state, self.repoId, groupId, generation-1)
			if err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	}
	verdict, err := CheckRotation(state, checkArgs)
	if err != nil {
		return nil, err
	}
	held = &gkmHeldGeneration{generation: fetched, poisoned: verdict.Refused}
	if verdict.Refused {
		client.alarm(&GkmAlarm{Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: groupId, Generation: generation, SidecarId: fetched.SignerId, Reason: verdict.Reason, Detail: verdict.Detail})
		if err := client.putHeldGeneration(self.repoId, held); err != nil {
			return nil, err
		}
	}
	return held, nil
}

// 6.2.4's Process, for every epoch gkm holds past this device's: each commit is staged, judged at its header's pin
// and adopted only if it passes. Returns how many it adopted. A device no longer a leaf, or one that holds no leaf,
// has nothing to process.
func (self *gkmGroupManager) catchUpInFlow(ctx context.Context, state GkmAuthView) (int, error) {
	client := self.client
	adoptedCount := 0
	yield := client.newYield()
	for {
		pins, err := client.repoPins(self.repoId)
		if err != nil {
			return adoptedCount, err
		}
		group, err := client.loadGroup(pins.groupId)
		if errors.Is(err, ErrMlsGroupUnknown) || errors.Is(err, ErrMlsNotMember) {
			return adoptedCount, nil
		}
		if err != nil {
			return adoptedCount, err
		}
		reply, err := client.args.Api.Epochs(ctx, self.repoId, pins.groupId, group.Epoch())
		if err != nil {
			return adoptedCount, err
		}
		entries := reply.GetEpochs()
		if len(entries) == 0 {
			return adoptedCount, nil
		}
		if client.settings.ResyncReplayMax < len(entries) {
			return adoptedCount, fmt.Errorf("%w: %d epochs behind", ErrGkmResyncNeeded, len(entries))
		}
		for _, entry := range entries {
			yield.step()
			left, err := self.processInFlow(ctx, state, group, entry)
			if err != nil {
				return adoptedCount, err
			}
			adoptedCount += 1
			if left {
				return adoptedCount, nil
			}
			group, err = client.loadGroup(pins.groupId)
			if err != nil {
				return adoptedCount, err
			}
		}
	}
}

// Processes one stored commit on group. left says the commit removed this device, which then holds no leaf.
func (self *gkmGroupManager) processInFlow(ctx context.Context, state GkmAuthView, group MlsGroup, entry *protocol.GkmEpochEntry) (left bool, err error) {
	client := self.client
	groupId := group.GroupId()
	object := entry.GetObject()
	if entry.GetEpoch() != group.Epoch()+1 || object == nil {
		return false, fmt.Errorf("%w: epoch %d after epoch %d", ErrGkmResyncNeeded, entry.GetEpoch(), group.Epoch())
	}
	pins, err := client.repoPins(self.repoId)
	if err != nil {
		return false, err
	}
	previousHeader := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(pins.epochHeader, previousHeader); err != nil {
		return false, fmt.Errorf("%w: the pinned epoch's header", ErrGkmMalformed)
	}
	staged, err := group.Process(object.GetCommit())
	if err != nil {
		// the subset refuses it: nothing of it is adopted, and this device returns by a resync
		return false, fmt.Errorf("%w: epoch %d does not process: %w", ErrGkmResyncNeeded, entry.GetEpoch(), err)
	}
	adopted := false
	defer func() {
		if !adopted {
			staged.Discard()
		}
	}()
	header := &protocol.GkmCommitHeader{}
	if err := proto.Unmarshal(staged.AuthenticatedData(), header); err != nil {
		header = &protocol.GkmCommitHeader{}
	}
	refuse := func(verdict GkmVerdict) (bool, error) {
		client.alarm(&GkmAlarm{
			Kind: GkmAlarmRefused, RepoId: self.repoId, GroupId: groupId, Epoch: entry.GetEpoch(), Generation: verdict.Poisoned,
			SidecarId: staged.Committer().SidecarId, Reason: verdict.Reason, Detail: verdict.Detail,
		})
		if verdict.Poisoned != 0 {
			// never seal to the generation its GenWrap carried into that tree, and rotate at once
			if poisoned, err := client.heldGeneration(self.repoId, verdict.Poisoned); err == nil {
				poisoned.poisoned = true
				if err := client.putHeldGeneration(self.repoId, poisoned); err != nil {
					return false, err
				}
			}
		}
		return false, fmt.Errorf("%w: epoch %d: %s", ErrGkmCommitRefused, entry.GetEpoch(), verdict.Reason)
	}
	checkArgs := &GkmCommitCheckArgs{
		RepoId: self.repoId, PreviousHeader: previousHeader, GenWrap: object.GetGenWrap(),
		Time: time.UnixMilli(object.GetTimeMs()), Now: client.clock.Now(),
	}
	if header.GetGeneration() != 0 {
		held, err := self.judgedGeneration(ctx, state, groupId, header.GetGeneration())
		if err != nil {
			return false, err
		}
		if held.poisoned {
			verdict := gkmRefuse(GkmRefusalGenWrap, "a commit carrying a poisoned generation")
			return refuse(verdict)
		}
		checkArgs.Generation = held.generation
	}
	check, err := CheckCommit(state, group, staged, checkArgs)
	if err != nil {
		return false, err
	}
	if check.Verdict.Refused {
		return refuse(check.Verdict)
	}
	if check.Verdict.NotJudged && check.Key == nil && checkArgs.Generation != nil {
		// a pin this reader no longer retains: the rows are not judged, and the key its GenWrap carries is still
		// accepted only against gen/<g>'s C_g
		if kek, err := MlsKek(staged, self.repoId); err == nil {
			if key, err := OpenGkmGenWrap(checkArgs.Generation, groupId, entry.GetEpoch(), kek, object.GetGenWrap()); err == nil {
				check.Key = key
			}
			clear(kek)
		}
	}
	epochAuthenticator := staged.EpochAuthenticator()
	headerBytes := staged.AuthenticatedData()
	_, adoptErr := staged.Adopt()
	adopted = true
	if adoptErr != nil && !errors.Is(adoptErr, ErrMlsNotMember) {
		return false, adoptErr
	}
	// the generation its GenWrap carried, where this device did not hold it yet
	if check.Key != nil {
		if err := client.putHeldGeneration(self.repoId, &gkmHeldGeneration{generation: checkArgs.Generation, key: check.Key}); err != nil {
			return false, err
		}
	}
	err = client.advancePins(self.repoId, func(pins *gkmRepoPins) {
		pins.epoch = entry.GetEpoch()
		pins.epochAuthenticator = epochAuthenticator
		pins.epochHeader = headerBytes
		if check.Key != nil && pins.generation < check.Key.Generation() {
			pins.generation = check.Key.Generation()
			pins.commitment = check.Key.Commitment()
		}
	})
	if err != nil {
		return false, err
	}
	// removed: it keeps every RK_g it holds and reads on by wraps if it is still a holder
	return errors.Is(adoptErr, ErrMlsNotMember), nil
}
