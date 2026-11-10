// A repo's pins as the rest of a sidecar reads them (KEYS-M2-23; R8, I-16, D-PROTO-14, D-TRUST-10; DESIGN-DETAILS
// 6.2.6): the epoch pin (group_id, e, epoch_authenticator) and the generation pin (group_id, g, C_g), which the
// group flows move forward and nothing moves back, compared here with every value another source shows.
//
//	same position   the same value, else a fork
//	higher          the lower side reads gen?since= or epochs?after= up to it, checking the chain; a chain that does
//	                not extend its own pin, or does not reach the value shown, is a fork
//	lower           a generation this device still holds is compared by its C_g, a conflict being a fork; an epoch
//	                below its own it keeps no authenticator of, so nothing is said of it
//	rollback        gkm serving nothing at this device's own pin, a newest epoch or generation below it, is a fork
//
// A fork raises head_alarm with both values, is reported to HeadStopState (ReportFork), and stops sealing in the
// repo here until the chain extends the pin it was seen at: EnsureWritable refuses with ErrGkmForked. Rotations,
// Removes and catch-up never stop for it (owner decision 129).
//
// GkmGroupClient is §6.4's HeadCheckGenSource and HeadCheckGroupSource. Their reads answer from memory, as
// HeadCheck's seam asks: the pins of every repo held and, for the groups this device is a leaf of, the leaves of the
// epoch it adopted, which LoadHeads reads once and every pin's move keeps current. GroupHeads names only groups
// both peers are leaves of, GenHeads the repos both read, each in group id order so the transport rotates through
// them, 16 a round.
//
// Beside the pins a repo keeps one more keychain record of this file's, <repo_id>/sync: when this leaf last
// committed a path, whether a join through its last-resort KeyPackage still owes its self-update, and the pin a fork
// was seen at.
//
// A reading: comparing a GenHead of another group of the repo, a re-formed one, along the GroupForm chain is
// KEYS-M2-25's; until it lands such a head is not compared.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Sealing in the repo is stopped at a forked pin, until the chain extends it (6.2.6).
var ErrGkmForked = errors.New("gkm: sealing stopped at a forked pin")

// What a pin shown from elsewhere came to against this device's.
type GkmPinStanding int

const (
	// The same position and the same value, or a lower generation this device holds with the same C_g.
	GkmPinAgrees GkmPinStanding = iota + 1
	// A lower position this device keeps nothing to compare with: the other side's to catch up.
	GkmPinBehind
	// Above this device's pin: it catches up, and the chain it reads must extend its own.
	GkmPinAhead
	// A conflict at a position this device holds: a fork, alarmed and reported.
	GkmPinForked
	// A repo or group this device holds no pin of, or one it is no leaf of: nothing to compare.
	GkmPinUnheld
)

// What memory keeps of one repo for HeadCheck and the acks.
type gkmRepoHead struct {
	pins *gkmRepoPins
	// the sidecars with a leaf in the epoch the pins name, sorted; nil while this device holds no leaf there
	leafIds []Id
}

// The flags of a sync record.
const (
	gkmSyncSelfUpdateOwed  = 1 << 0
	gkmSyncEpochFork       = 1 << 1
	gkmSyncGenerationFork  = 1 << 2
	gkmSyncRecordByteCount = 2 + 8 + 8 + 8
)

// A repo's sync record: see the file header.
type gkmSyncRecord struct {
	// zero before this leaf's first path commit here
	pathCommittedAt time.Time
	selfUpdateOwed  bool
	// the pins a fork was seen at; sealing resumes once the pin passes them
	epochFork        bool
	forkedEpoch      uint64
	generationFork   bool
	forkedGeneration uint64
}

// version | flags | u64 path_committed_at_ms | u64 forked_epoch | u64 forked_generation.
func (self *gkmSyncRecord) encode() []byte {
	flags := byte(0)
	if self.selfUpdateOwed {
		flags |= gkmSyncSelfUpdateOwed
	}
	if self.epochFork {
		flags |= gkmSyncEpochFork
	}
	if self.generationFork {
		flags |= gkmSyncGenerationFork
	}
	encoded := []byte{gkmRecordVersion, flags}
	pathCommittedAtMs := uint64(0)
	if !self.pathCommittedAt.IsZero() {
		pathCommittedAtMs = uint64(self.pathCommittedAt.UnixMilli())
	}
	encoded = binary.BigEndian.AppendUint64(encoded, pathCommittedAtMs)
	encoded = binary.BigEndian.AppendUint64(encoded, self.forkedEpoch)
	return binary.BigEndian.AppendUint64(encoded, self.forkedGeneration)
}

// A sync record's fields.
func decodeGkmSyncRecord(encoded []byte) (*gkmSyncRecord, error) {
	if len(encoded) != gkmSyncRecordByteCount || encoded[0] != gkmRecordVersion {
		return nil, fmt.Errorf("%w: a sync record", ErrGkmMalformed)
	}
	record := &gkmSyncRecord{
		selfUpdateOwed:   encoded[1]&gkmSyncSelfUpdateOwed != 0,
		epochFork:        encoded[1]&gkmSyncEpochFork != 0,
		generationFork:   encoded[1]&gkmSyncGenerationFork != 0,
		forkedEpoch:      binary.BigEndian.Uint64(encoded[10:18]),
		forkedGeneration: binary.BigEndian.Uint64(encoded[18:26]),
	}
	if pathCommittedAtMs := binary.BigEndian.Uint64(encoded[2:10]); pathCommittedAtMs != 0 {
		record.pathCommittedAt = time.UnixMilli(int64(pathCommittedAtMs))
	}
	return record, nil
}

// The repo's sync record, empty for none.
func (self *GkmGroupClient) syncRecord(repoId Id) (*gkmSyncRecord, error) {
	encoded, err := self.getRecord(gkmRepoRecordName(repoId, "sync"))
	if errors.Is(err, ErrGkmKeyMissing) {
		return &gkmSyncRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeGkmSyncRecord(encoded)
}

// Changes the repo's sync record by edit.
func (self *GkmGroupClient) editSyncRecord(repoId Id, edit func(record *gkmSyncRecord)) error {
	record, err := self.syncRecord(repoId)
	if err != nil {
		return err
	}
	edit(record)
	return self.args.Secrets.Put(gkmRepoRecordName(repoId, "sync"), record.encode())
}

// Whether this process holds the network's state (GkmGroupClientArgs.HoldsState).
func (self *GkmGroupClient) holdsState() bool {
	return self.args.HoldsState == nil || self.args.HoldsState()
}

// The sidecars with a leaf in the epoch pins names, sorted, or nil when this device's engine does not hold that
// epoch.
func (self *GkmGroupClient) pinnedLeafIds(pins *gkmRepoPins) []Id {
	if len(pins.epochAuthenticator) == 0 {
		return nil
	}
	group, err := self.loadGroup(pins.groupId)
	if err != nil || group.Epoch() != pins.epoch {
		return nil
	}
	leafIds := []Id{}
	for _, member := range group.Roster() {
		leafIds = append(leafIds, member.SidecarId)
	}
	slices.SortFunc(leafIds, func(a Id, b Id) int { return bytes.Compare(a[:], b[:]) })
	return leafIds
}

// advancePins' hook, after the keychain took the new pins: memory follows, and a fork's stop ends once the chain
// has extended the pin it was seen at.
func (self *GkmGroupClient) pinsMoved(repoId Id, stored *gkmRepoPins, next *gkmRepoPins) {
	epochMoved := next.epoch != stored.epoch || next.groupId != stored.groupId || !bytes.Equal(next.epochAuthenticator, stored.epochAuthenticator)
	var leafIds []Id
	if epochMoved {
		leafIds = self.pinnedLeafIds(next)
	}
	kept := *next
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		head, ok := self.repoIdHeads[repoId]
		if !ok {
			head = &gkmRepoHead{}
			self.repoIdHeads[repoId] = head
		}
		head.pins = &kept
		if epochMoved {
			head.leafIds = leafIds
		}
	}()
	if stored.epoch < next.epoch || stored.generation < next.generation {
		record, err := self.syncRecord(repoId)
		if err != nil || !record.epochFork && !record.generationFork {
			return
		}
		epochFork := record.epochFork && next.epoch <= record.forkedEpoch
		generationFork := record.generationFork && next.generation <= record.forkedGeneration
		if epochFork == record.epochFork && generationFork == record.generationFork {
			return
		}
		err = self.editSyncRecord(repoId, func(record *gkmSyncRecord) {
			record.epochFork, record.generationFork = epochFork, generationFork
		})
		if err != nil && self.log.V(1).Enabled() {
			self.log.Infof("[gkm]a fork's stop was not lifted: %v", err)
		}
	}
}

// Reads every held repo's pins, and for each group this device is a leaf of its epoch's leaves, into memory: what
// GenHeads, GroupHeads and AckGroups answer from. Run once when the client starts and at each resync; every pin's
// move keeps it current between.
func (self *GkmGroupClient) LoadHeads() error {
	repoIds, err := self.heldRepoIds()
	if err != nil {
		return err
	}
	repoIdHeads := map[Id]*gkmRepoHead{}
	for _, repoId := range repoIds {
		pins, err := self.repoPins(repoId)
		if err != nil {
			continue
		}
		repoIdHeads[repoId] = &gkmRepoHead{pins: pins, leafIds: self.pinnedLeafIds(pins)}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.repoIdHeads = repoIdHeads
	return nil
}

// A snapshot of the heads memory holds, in group id order, with the newest state.
func (self *GkmGroupClient) heads() (GkmAuthView, []Id, []*gkmRepoHead) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoIds := []Id{}
	for repoId := range self.repoIdHeads {
		repoIds = append(repoIds, repoId)
	}
	slices.SortFunc(repoIds, func(a Id, b Id) int {
		return cmp.Or(bytes.Compare(self.repoIdHeads[a].pins.groupId[:], self.repoIdHeads[b].pins.groupId[:]), bytes.Compare(a[:], b[:]))
	})
	heads := []*gkmRepoHead{}
	for _, repoId := range repoIds {
		head := self.repoIdHeads[repoId]
		heads = append(heads, &gkmRepoHead{pins: head.pins, leafIds: head.leafIds})
	}
	return self.state, repoIds, heads
}

// A generation pin in HeadCheck's form, nil for a repo this device holds no generation of.
func (self *gkmRepoPins) genHead() *protocol.GenHead {
	if self.generation == 0 || len(self.commitment) == 0 {
		return nil
	}
	return &protocol.GenHead{GroupId: self.groupId.Bytes(), Generation: self.generation, Commitment: bytes.Clone(self.commitment)}
}

// An epoch pin in HeadCheck's form, nil while this device is no leaf of the group.
func (self *gkmRepoPins) groupHead() *protocol.GroupHead {
	if len(self.epochAuthenticator) == 0 {
		return nil
	}
	return &protocol.GroupHead{GroupId: self.groupId.Bytes(), Epoch: self.epoch, EpochAuthenticator: bytes.Clone(self.epochAuthenticator)}
}

var _ HeadCheckGenSource = (*GkmGroupClient)(nil)
var _ HeadCheckGroupSource = (*GkmGroupClient)(nil)

// The generation pins of the repos the peer also reads, by a grant or under a live Delegation, in group id order.
// From memory.
func (self *GkmGroupClient) GenHeads(peerSidecarId Id) []*protocol.GenHead {
	state, repoIds, heads := self.heads()
	genHeads := []*protocol.GenHead{}
	if state == nil {
		return genHeads
	}
	now := self.clock.Now()
	for index, head := range heads {
		genHead := head.pins.genHead()
		if genHead == nil {
			continue
		}
		repoId := repoIds[index]
		if _, reads := gkmFindId(state.RepoReadersAt(repoId, now), peerSidecarId); reads || GkmCovered(state, peerSidecarId, repoId, now) {
			genHeads = append(genHeads, genHead)
		}
	}
	return genHeads
}

// This device's generation pin for one group. From memory.
func (self *GkmGroupClient) GenHead(groupId Id) (*protocol.GenHead, bool) {
	_, _, heads := self.heads()
	for _, head := range heads {
		if head.pins.groupId == groupId {
			genHead := head.pins.genHead()
			return genHead, genHead != nil
		}
	}
	return nil, false
}

// The epoch pins of the groups this device and the peer are both leaves of, in group id order. From memory.
func (self *GkmGroupClient) GroupHeads(peerSidecarId Id) []*protocol.GroupHead {
	_, _, heads := self.heads()
	groupHeads := []*protocol.GroupHead{}
	for _, head := range heads {
		groupHead := head.pins.groupHead()
		if groupHead == nil || !slices.Contains(head.leafIds, self.args.SidecarId) || !slices.Contains(head.leafIds, peerSidecarId) {
			continue
		}
		groupHeads = append(groupHeads, groupHead)
	}
	return groupHeads
}

// This device's epoch pin for a group it is a leaf of. From memory.
func (self *GkmGroupClient) GroupHead(groupId Id) (*protocol.GroupHead, bool) {
	_, _, heads := self.heads()
	for _, head := range heads {
		if head.pins.groupId == groupId && slices.Contains(head.leafIds, self.args.SidecarId) {
			groupHead := head.pins.groupHead()
			return groupHead, groupHead != nil
		}
	}
	return nil, false
}

// The groups this device is a leaf of, with their newest adopted epochs: what upkeep acks daily (§10.6's ack row,
// GkmUpkeepArgs.AckGroups). From memory.
func (self *GkmGroupClient) AckGroups() []*GkmAckGroup {
	_, repoIds, heads := self.heads()
	ackGroups := []*GkmAckGroup{}
	for index, head := range heads {
		if len(head.pins.epochAuthenticator) == 0 || !slices.Contains(head.leafIds, self.args.SidecarId) {
			continue
		}
		ackGroups = append(ackGroups, &GkmAckGroup{RepoId: repoIds[index], GroupId: head.pins.groupId, Epoch: head.pins.epoch})
	}
	return ackGroups
}

// A fork at one of the repo's pins: head_alarm with both values, HeadStopState told unless the caller's own engine
// reports it, and sealing stopped here until the chain extends the pin. Returns ErrGkmAuthOffChain for the caller to
// answer with.
func (self *GkmGroupClient) pinForked(repoId Id, pins *gkmRepoPins, kind HeadForkKind, local proto.Message, remote proto.Message, peerId *Id, report bool, detail string) error {
	encode := func(message proto.Message) []byte {
		if message == nil {
			return nil
		}
		encoded, _ := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		return encoded
	}
	localBytes, remoteBytes := encode(local), encode(remote)
	alarm := &GkmAlarm{
		Kind: GkmAlarmHead, RepoId: repoId, GroupId: pins.groupId, Epoch: pins.epoch, Generation: pins.generation,
		Reason: GkmRefusalFork, Detail: fmt.Sprintf("%s: local %x remote %x", detail, localBytes, remoteBytes),
	}
	if peerId != nil {
		alarm.SidecarId = *peerId
	}
	self.alarm(alarm)
	err := self.editSyncRecord(repoId, func(record *gkmSyncRecord) {
		if kind == HeadForkGroup {
			record.epochFork = true
			record.forkedEpoch = max(record.forkedEpoch, pins.epoch)
		} else {
			record.generationFork = true
			record.forkedGeneration = max(record.forkedGeneration, pins.generation)
		}
	})
	if report && self.args.ReportFork != nil {
		self.args.ReportFork(HeadFork{Kind: kind, GroupId: pins.groupId, Local: localBytes, Remote: remoteBytes, PeerId: peerId})
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: %s", ErrGkmAuthOffChain, detail)
}

// ErrGkmForked while a fork stops sealing in the repo.
func (self *GkmGroupClient) sealStopped(repoId Id) error {
	record, err := self.syncRecord(repoId)
	if err != nil {
		return err
	}
	if record.epochFork {
		return fmt.Errorf("%w: epoch %d", ErrGkmForked, record.forkedEpoch)
	}
	if record.generationFork {
		return fmt.Errorf("%w: generation %d", ErrGkmForked, record.forkedGeneration)
	}
	return nil
}

// Compares a generation pin another source shows for the repo, a head's (§11.8), a push's or a peer's, with this
// device's. A conflict at a generation it holds is a fork: alarmed, reported and sealing stopped. peerId names the
// peer that showed it, nil for a pin a store served.
func (self *GkmGroupClient) ObserveGenHead(repoId Id, head *protocol.GenHead, peerId *Id) (GkmPinStanding, error) {
	if head == nil || len(head.GetCommitment()) != gkmCommitmentByteCount {
		return 0, fmt.Errorf("%w: a generation pin", ErrGkmMalformed)
	}
	pins, err := self.repoPins(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return GkmPinUnheld, nil
	}
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(head.GetGroupId(), pins.groupId.Bytes()) || pins.generation == 0 {
		// another group of the repo is a re-form's, compared along the form chain (KEYS-M2-25)
		return GkmPinUnheld, nil
	}
	if pins.generation < head.GetGeneration() {
		return GkmPinAhead, nil
	}
	commitment := pins.commitment
	if head.GetGeneration() < pins.generation {
		held, err := self.heldGeneration(repoId, head.GetGeneration())
		if errors.Is(err, ErrGkmKeyMissing) {
			return GkmPinBehind, nil
		}
		if err != nil {
			return 0, err
		}
		commitment = held.generation.Rotate.GetCommitment()
	}
	if bytes.Equal(commitment, head.GetCommitment()) {
		return GkmPinAgrees, nil
	}
	local := &protocol.GenHead{GroupId: pins.groupId.Bytes(), Generation: head.GetGeneration(), Commitment: commitment}
	err = self.pinForked(repoId, pins, HeadForkGen, local, head, peerId, true, "a second commitment at a generation this device holds")
	if errors.Is(err, ErrGkmAuthOffChain) {
		return GkmPinForked, nil
	}
	return GkmPinForked, err
}

// Compares an epoch pin another source shows for the repo, the (group_id, epoch, epoch_authenticator) a push seals
// (§11.6) or a peer's, with this device's. A second authenticator at its own epoch is a fork: alarmed, reported and
// sealing stopped.
func (self *GkmGroupClient) ObserveGroupHead(repoId Id, head *protocol.GroupHead, peerId *Id) (GkmPinStanding, error) {
	if head == nil || len(head.GetEpochAuthenticator()) == 0 {
		return 0, fmt.Errorf("%w: an epoch pin", ErrGkmMalformed)
	}
	pins, err := self.repoPins(repoId)
	if errors.Is(err, ErrGkmKeyMissing) {
		return GkmPinUnheld, nil
	}
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(head.GetGroupId(), pins.groupId.Bytes()) || len(pins.epochAuthenticator) == 0 {
		// no leaf here: this device compares generations instead (§6.4's witnesses)
		return GkmPinUnheld, nil
	}
	switch {
	case pins.epoch < head.GetEpoch():
		return GkmPinAhead, nil
	case head.GetEpoch() < pins.epoch:
		return GkmPinBehind, nil
	case bytes.Equal(pins.epochAuthenticator, head.GetEpochAuthenticator()):
		return GkmPinAgrees, nil
	}
	err = self.pinForked(repoId, pins, HeadForkGroup, pins.groupHead(), head, peerId, true, "a second epoch_authenticator at this device's epoch")
	if errors.Is(err, ErrGkmAuthOffChain) {
		return GkmPinForked, nil
	}
	return GkmPinForked, err
}

// §6.4's forward read of gen/ from this device's pin up to a peer's: each statement verified and judged as any
// claim is, each link held to its parent's commitment. HeadCheckCaughtUp when the chain reaches the peer's pin,
// HeadCheckCatchUpForked when it does not extend this device's or holds another commitment there, which is alarmed
// here and stops sealing, and HeadCheckCatchUpUnserved when gkm served too little to say. The engine that asked
// reports a fork with its peer, so this reports none to HeadStopState itself.
func (self *GkmGroupClient) CatchUpGen(ctx context.Context, through *protocol.GenHead) (HeadCheckCatchUp, error) {
	groupId, err := IdFromBytes(through.GetGroupId())
	if err != nil || len(through.GetCommitment()) != gkmCommitmentByteCount {
		return HeadCheckCatchUpUnserved, fmt.Errorf("%w: a generation pin", ErrGkmMalformed)
	}
	repoId, ok := self.heldRepoOfGroup(groupId)
	if !ok {
		return HeadCheckCatchUpUnserved, nil
	}
	manager := self.manager(repoId)
	manager.flowLock.Lock()
	defer manager.flowLock.Unlock()
	state, err := self.currentState()
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	if err := manager.refreshGenerationsInFlow(ctx, state); err != nil {
		if errors.Is(err, ErrGkmAuthOffChain) {
			return HeadCheckCatchUpForked, nil
		}
		return HeadCheckCatchUpUnserved, err
	}
	pins, err := self.repoPins(repoId)
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	if pins.generation < through.GetGeneration() {
		return HeadCheckCatchUpUnserved, nil
	}
	held, err := self.heldGeneration(repoId, through.GetGeneration())
	if errors.Is(err, ErrGkmKeyMissing) {
		return HeadCheckCatchUpUnserved, nil
	}
	if err != nil {
		return HeadCheckCatchUpUnserved, err
	}
	if bytes.Equal(held.generation.Rotate.GetCommitment(), through.GetCommitment()) {
		return HeadCheckCaughtUp, nil
	}
	local := &protocol.GenHead{GroupId: groupId.Bytes(), Generation: through.GetGeneration(), Commitment: held.generation.Rotate.GetCommitment()}
	err = self.pinForked(repoId, pins, HeadForkGen, local, through, nil, false, "the gen/ chain does not reach the peer's pin")
	if errors.Is(err, ErrGkmAuthOffChain) {
		err = nil
	}
	return HeadCheckCatchUpForked, err
}
