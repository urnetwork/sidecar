// §7.10's stale row on the device (CORE-M4-02, D-TEAM-29, D-CORE-20, FS-97): the act that admits a member's page Worker,
// signed by the member's consented device or an admin's, also signs SidecarRevoke{reason: removed} for each of that
// member's page Workers this device sees as stale, so evictions pile up only as the row bounds. A Worker is stale here
// when at least one group this device is a leaf of seated it, and in every such group §10.9 removed its leaf as stale
// with no later Add or resync (KF2, KF5), or it is due for that Remove (stale_leaf_days past its leaf's last change)
// and this device, a writer leaf there, commits the Remove first. The revocations ride the act: they add no second
// confirmation and no second presence check (D-CORE-20, owner decision 187), and the act posts them before the
// admission, so the room they free counts at config_admissions' cap (§20.7).
//
// The decision is made at each group's current epoch, fetched first, and again before each post or retry (§5.9): a
// revocation whose Worker holds a leaf again is dropped unposted, and a due Remove is committed only then, after the
// person confirmed and the presence check passed. The act's records keep, beside each pending statement, its act and
// place in it and, for a stale revocation, its Worker, so PostPendingStatements reposts the same bytes in act order and
// re-checks each (identity_pending.go).
//
// Who revokes what (owner decision 126): an admin's device revokes only the Workers it saw so removed and offers none,
// leaving the member's live devices to the member; the member's consented device revokes the same way those its groups
// show, and offers the member's other page Workers, each with its leaf's last change, to revoke through §5.6's calls.
// A Worker no group of this device seated is never revoked here. For an AdminSet member's Worker at k > 1, each
// revocation is its own AuthorityProposal beside the admission's, the admitting device counting as one (§7.9's counted
// row).
//
// The group view is KEYS-M4-01's, which its gkm client installs (InstallStaleGroupView). With none installed this device
// sees no group, so it revokes nothing and offers every Worker: no revocation is ever signed without the evidence. The
// page Workers are the member's read_only member devices, which SidecarAuthority.MemberDevices lists (TEAM-M4-01's
// ConfigState.PageWorkers). On every leg: root Id, no connect type.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a page Worker's leaf is in one group this device is a leaf of, at the group's current epoch.
type SidecarStaleLeafState int

const (
	// It holds a leaf: never removed, or back by an Add or a resync after a stale Remove (KF2, KF5), and not due.
	SidecarStaleLeafLive SidecarStaleLeafState = iota + 1
	// §10.9 removed its leaf as stale, with no later Add or resync.
	SidecarStaleLeafRemoved
	// stale_leaf_days past its leaf's last change: due for §10.9's stale Remove, which a writer leaf commits.
	SidecarStaleLeafDue
)

// One page Worker's leaf in one group this device is a leaf of that seated it, at that group's current epoch.
type SidecarStaleLeaf struct {
	GroupId  Id
	WorkerId Id
	// The epoch it was judged at, which the view fetched first.
	Epoch uint64
	State SidecarStaleLeafState
	// Whether this device is a writer leaf of the group, so it may commit a due Remove (§10.9's Remove row).
	Writer bool
	// The leaf's last change, by the epochs' times; zero where none is known.
	LastChange time.Time
}

// What §7.10's stale row reads of this device's MLS groups: KEYS-M4-01's group view, over its gkm client. Safe for
// concurrent use.
type SidecarStaleGroupView interface {
	// Fetches the current epoch of each group this device is a leaf of, then answers each of workerIds' leaves in the
	// groups among them that seated it. A Worker no such group seated has no leaf in the answer.
	StaleLeaves(ctx context.Context, workerIds []Id) ([]*SidecarStaleLeaf, error)
	// Commits §10.9's stale Remove of workerId's leaf in groupId as a writer leaf there, at the group's current epoch,
	// once its staleness still holds. An error leaves the leaf as it was.
	CommitStaleRemove(ctx context.Context, groupId Id, workerId Id) error
}

// An authority that also answers §7.9's several row for a statement this device would sign: TEAM's adapter, once
// ConfigState's counted rule is behind the seam. Optional: without it, a stale revocation goes as a plain statement,
// which verifiers refuse where k > 1 asks for a proposal, so nothing is revoked.
type SidecarProposalAuthority interface {
	// Whether the statement, signed by its signer at the newest state, needs more than one counted signer, so it goes
	// as an AuthorityProposal (§7.9's several, proposal and counted rows).
	ProposalRequired(statement *SidecarStatement) bool
}

// What the act revokes and offers.
type SidecarStaleRevocations struct {
	// The page Workers revoked in the act, as the act signs them.
	Revoked []Id
	// The member's other page Workers, offered to revoke through §5.6's calls, each with its leaf's last change: only
	// on the member's own consented device, never an admin's.
	Offered []MemberDevice
}

// The view an act reads, under its own lock.
type sidecarStaleGroupViews struct {
	stateLock sync.Mutex
	view      SidecarStaleGroupView
}

// Installs view as this device's group view, which stale revocations read, replacing any before; the answer removes
// it, if it is still the installed one. KEYS-M4-01's gkm client installs it; a test installs a fake.
func (self *Sidecar) InstallStaleGroupView(view SidecarStaleGroupView) func() {
	func() {
		self.staleGroupViews.stateLock.Lock()
		defer self.staleGroupViews.stateLock.Unlock()
		self.staleGroupViews.view = view
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			self.staleGroupViews.stateLock.Lock()
			defer self.staleGroupViews.stateLock.Unlock()
			if self.staleGroupViews.view == view {
				self.staleGroupViews.view = nil
			}
		})
	}
}

// The installed group view, nil for none.
func (self *Sidecar) staleGroupView() SidecarStaleGroupView {
	self.staleGroupViews.stateLock.Lock()
	defer self.staleGroupViews.stateLock.Unlock()
	return self.staleGroupViews.view
}

// A stale revocation's Worker, kept beside its pending statement so each post and retry re-checks it.
type sidecarStaleRevocation struct {
	workerId Id
	memberId Id
}

// One page Worker this device judged stale.
type sidecarStaleWorker struct {
	sidecarId Id
	// the groups whose due Remove this device commits before the revocation posts
	dueGroupIds []Id
}

// The verdict on one Worker's leaves: stale when at least one group seated it and every such group removed it as stale
// or has it due with this device a writer leaf; due names those groups.
func sidecarStaleVerdict(leaves []*SidecarStaleLeaf) (stale bool, dueGroupIds []Id) {
	if len(leaves) == 0 {
		return false, nil
	}
	for _, leaf := range leaves {
		switch leaf.State {
		case SidecarStaleLeafRemoved:
		case SidecarStaleLeafDue:
			if !leaf.Writer {
				return false, nil
			}
			dueGroupIds = append(dueGroupIds, leaf.GroupId)
		default:
			return false, nil
		}
	}
	return true, dueGroupIds
}

// Each Worker's leaves in an answer, by Worker; an answer naming a Worker it was not asked about is the view's fault.
func sidecarStaleLeavesByWorker(leaves []*SidecarStaleLeaf, workerIds []Id) (map[Id][]*SidecarStaleLeaf, error) {
	byWorker := map[Id][]*SidecarStaleLeaf{}
	for _, leaf := range leaves {
		if leaf == nil || !slices.Contains(workerIds, leaf.WorkerId) {
			return nil, errors.New("the group view answered a leaf it was not asked about")
		}
		byWorker[leaf.WorkerId] = append(byWorker[leaf.WorkerId], leaf)
	}
	return byWorker, nil
}

// The member's admitted page Workers: its read_only member devices, not revoked, the one being admitted left out.
func sidecarPageWorkers(authority SidecarAuthority, memberId Id, admittedId *Id) []*AclSidecar {
	workers := []*AclSidecar{}
	for _, device := range authority.MemberDevices(memberId) {
		row := device.Row
		if row == nil || row.GetRevokedAt() != 0 || 0 < len(device.TagIds) ||
			row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) == 0 {
			continue
		}
		sidecarId, err := IdFromBytes(row.GetSidecarId())
		if err != nil || (admittedId != nil && sidecarId == *admittedId) {
			continue
		}
		workers = append(workers, device)
	}
	return workers
}

// The member's page Workers this device sees as stale, judged at each group's current epoch, and, on the member's own
// consented device, the others to offer. memberDevice says which this device is: the member's consented device, or an
// admin's, which offers none.
func (self *Sidecar) sidecarStaleWorkers(ctx context.Context, authority SidecarAuthority, memberId Id, admittedId *Id,
	memberDevice bool) ([]*sidecarStaleWorker, []MemberDevice, error) {
	workers := sidecarPageWorkers(authority, memberId, admittedId)
	if len(workers) == 0 {
		return nil, nil, nil
	}
	workerIds := make([]Id, 0, len(workers))
	for _, worker := range workers {
		sidecarId, _ := IdFromBytes(worker.Row.GetSidecarId())
		workerIds = append(workerIds, sidecarId)
	}
	byWorker := map[Id][]*SidecarStaleLeaf{}
	if view := self.staleGroupView(); view != nil {
		leaves, err := view.StaleLeaves(ctx, workerIds)
		if err != nil {
			return nil, nil, err
		}
		if byWorker, err = sidecarStaleLeavesByWorker(leaves, workerIds); err != nil {
			return nil, nil, err
		}
	}
	stale := []*sidecarStaleWorker{}
	offered := []MemberDevice{}
	for _, workerId := range workerIds {
		leaves := byWorker[workerId]
		if isStale, dueGroupIds := sidecarStaleVerdict(leaves); isStale {
			stale = append(stale, &sidecarStaleWorker{sidecarId: workerId, dueGroupIds: dueGroupIds})
			continue
		}
		if !memberDevice {
			// an admin's device offers none, leaving the member's live devices to the member (owner decision 126)
			continue
		}
		offer := MemberDevice{SidecarId: workerId, ReadOnly: true, State: "live"}
		for _, leaf := range leaves {
			if offer.LastChange.Before(leaf.LastChange) {
				offer.LastChange = leaf.LastChange
			}
		}
		offered = append(offered, offer)
	}
	return stale, offered, nil
}

// The statement header Add would set, for a statement a proposal carries: this network, the act's pin, a fresh nonce
// and the act's not_after.
func (self *sidecarAct) proposedStatementBytes(statement proto.Message) ([]byte, error) {
	headerField := statement.ProtoReflect().Descriptor().Fields().ByNumber(1)
	if headerField == nil || headerField.Message() == nil ||
		headerField.Message().FullName() != (&bridge.StatementHeader{}).ProtoReflect().Descriptor().FullName() {
		return nil, fmt.Errorf("%w: the statement carries no StatementHeader", ErrSidecarSignRefused)
	}
	nonce := make([]byte, configNonceByteCount)
	if _, err := io.ReadFull(self.random, nonce); err != nil {
		return nil, fmt.Errorf("no randomness for a nonce: %w", err)
	}
	header := &bridge.StatementHeader{
		NetworkId:  self.identity.NetworkId.Bytes(),
		At:         &bridge.AuthPin{Version: self.at.GetVersion(), Chain: bytes.Clone(self.at.GetChain())},
		Nonce:      nonce,
		NotAfterMs: self.notAfterMs(),
	}
	withHeader := proto.Clone(statement)
	withHeader.ProtoReflect().Set(headerField, protoreflect.ValueOfMessage(header.ProtoReflect()))
	return proto.MarshalOptions{Deterministic: true}.Marshal(withHeader)
}

// Adds, before every statement already in the act, SidecarRevoke{reason: removed} for each of memberId's page Workers
// this device sees as stale (§7.10's stale row), admittedId being the Worker the act admits or confirms, which is never
// one of them. A Worker whose revocation needs k > 1 goes as its own AuthorityProposal. Answers what it revoked and,
// on the member's own consented device, what it offers. The act must be a person's confirmation, as an admission's
// is; with no group view installed nothing is revoked.
func (self *sidecarAct) AddStaleRevocations(ctx context.Context, memberId Id, admittedId *Id) (*SidecarStaleRevocations, error) {
	if self.ran {
		return nil, ErrSidecarActState
	}
	if self.origin != SidecarActConfirmed {
		return nil, ErrSidecarActMode
	}
	memberDevice := self.sidecar.consentedFor(self.authority, memberId)
	stale, offered, err := self.sidecar.sidecarStaleWorkers(ctx, self.authority, memberId, admittedId, memberDevice)
	if err != nil {
		return nil, err
	}
	revocations := &SidecarStaleRevocations{Offered: offered}
	// built apart, then put first, so the act posts them before what it admits; an error leaves the act as it was
	added := []*sidecarActStatement{}
	statements := self.statements
	self.statements = nil
	restore := func(err error) (*SidecarStaleRevocations, error) {
		self.statements = statements
		return nil, err
	}
	for _, worker := range stale {
		revoke := &bridge.SidecarRevoke{
			SidecarId: worker.sidecarId.Bytes(),
			Reason:    bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED,
		}
		proposal := false
		if proposals, ok := self.authority.(SidecarProposalAuthority); ok {
			body, err := proto.MarshalOptions{Deterministic: true}.Marshal(revoke)
			if err != nil {
				return restore(err)
			}
			proposal = proposals.ProposalRequired(&SidecarStatement{
				SignerId: self.identity.SidecarId,
				Type:     bridge.SignedType_SIGNED_SIDECAR_REVOKE,
				Body:     body,
			})
		}
		if proposal {
			proposedBytes, err := self.proposedStatementBytes(revoke)
			if err != nil {
				return restore(err)
			}
			err = self.Add(bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL, &protocol.AuthorityProposal{
				StatementType: uint32(bridge.SignedType_SIGNED_SIDECAR_REVOKE),
				Statement:     proposedBytes,
			})
			if err != nil {
				return restore(err)
			}
		} else if err := self.Add(bridge.SignedType_SIGNED_SIDECAR_REVOKE, revoke); err != nil {
			return restore(err)
		}
		statement := self.statements[0]
		self.statements = nil
		statement.stale = &sidecarStaleRevocation{workerId: worker.sidecarId, memberId: memberId}
		added = append(added, statement)
		revocations.Revoked = append(revocations.Revoked, worker.sidecarId)
	}
	self.statements = append(added, statements...)
	return revocations, nil
}

// Re-checks a stale revocation before its post or retry: at each group's current epoch, fetched again, its Worker is
// still stale in this device's view, and each due Remove is committed first. post false drops it unposted, its Worker
// holding a leaf again; an error, a view that does not answer or a Remove that does not commit, leaves it pending.
func (self *Sidecar) recheckStaleRevocation(ctx context.Context, stale *sidecarStaleRevocation) (post bool, err error) {
	view := self.staleGroupView()
	if view == nil {
		return false, errors.New("no group view to re-check a stale revocation against")
	}
	testHookBarrier("identity.stale.recheck.before", stale.workerId.String())
	leaves, err := view.StaleLeaves(ctx, []Id{stale.workerId})
	testHookBarrier("identity.stale.recheck.after", stale.workerId.String())
	if err != nil {
		return false, err
	}
	byWorker, err := sidecarStaleLeavesByWorker(leaves, []Id{stale.workerId})
	if err != nil {
		return false, err
	}
	isStale, dueGroupIds := sidecarStaleVerdict(byWorker[stale.workerId])
	if !isStale {
		if self.log.V(1).Enabled() {
			self.log.Infof("[identity]a stale revocation's Worker holds a leaf again: dropped unposted")
		}
		return false, nil
	}
	for _, groupId := range dueGroupIds {
		if err := view.CommitStaleRemove(ctx, groupId, stale.workerId); err != nil {
			return false, fmt.Errorf("a stale Remove did not commit: %w", err)
		}
	}
	return true, nil
}
