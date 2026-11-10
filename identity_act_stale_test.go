package sidecar

// CORE-M4-02: §7.10's stale row on the admitting device. The revocations ride the admission's act, under its one
// presence check, and post before the admission; each post and retry re-checks the Worker at its groups' current epoch,
// dropping one that holds a leaf again; a kill between them reposts the same bytes in the same order; an admin's device
// revokes only what it saw removed and offers nothing; an AdminSet member's Worker goes as its own proposal.

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The admitting device's group view as a test scripts it: each Worker's leaves by group, which a test may change between
// the act's decision and its post, and every Remove it commits.
type testStaleGroupView struct {
	stateLock sync.Mutex
	leaves    map[Id][]*SidecarStaleLeaf
	// calls to StaleLeaves so far, and a change run before the answer to the call of that number
	calls      int
	changeAt   map[int]func()
	commits    [][2]Id
	commitErr  error
	answerErr  error
	commitSeen func()
}

func newTestStaleGroupView() *testStaleGroupView {
	return &testStaleGroupView{leaves: map[Id][]*SidecarStaleLeaf{}, changeAt: map[int]func(){}}
}

// Sets workerId's leaf in groupId.
func (self *testStaleGroupView) set(groupId Id, workerId Id, state SidecarStaleLeafState, writer bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	leaves := slices.DeleteFunc(self.leaves[workerId], func(leaf *SidecarStaleLeaf) bool { return leaf.GroupId == groupId })
	self.leaves[workerId] = append(leaves, &SidecarStaleLeaf{
		GroupId:    groupId,
		WorkerId:   workerId,
		Epoch:      7,
		State:      state,
		Writer:     writer,
		LastChange: time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC),
	})
}

func (self *testStaleGroupView) StaleLeaves(ctx context.Context, workerIds []Id) ([]*SidecarStaleLeaf, error) {
	self.stateLock.Lock()
	self.calls += 1
	change := self.changeAt[self.calls]
	self.stateLock.Unlock()
	if change != nil {
		change()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.answerErr != nil {
		return nil, self.answerErr
	}
	answer := []*SidecarStaleLeaf{}
	for _, workerId := range workerIds {
		for _, leaf := range self.leaves[workerId] {
			copied := *leaf
			answer = append(answer, &copied)
		}
	}
	return answer, nil
}

func (self *testStaleGroupView) CommitStaleRemove(ctx context.Context, groupId Id, workerId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.commitErr != nil {
		return self.commitErr
	}
	self.commits = append(self.commits, [2]Id{groupId, workerId})
	if self.commitSeen != nil {
		self.commitSeen()
	}
	for _, leaf := range self.leaves[workerId] {
		if leaf.GroupId == groupId {
			leaf.State = SidecarStaleLeafRemoved
		}
	}
	return nil
}

// The test's world: this device, a member, and the member's page Workers.
type testStaleWorld struct {
	sidecar   *Sidecar
	authority *testActAuthority
	deltaApi  *testDeltaApi
	view      *testStaleGroupView
	memberId  Id
	groupId   Id
	// the Worker being admitted
	newWorkerId Id
}

// This device as memberId's consented device (member true) or an admin's device of another member (member false), with
// a group view installed.
func newTestStaleWorld(t *testing.T, member bool) *testStaleWorld {
	t.Helper()
	sidecar, authority, deltaApi := newActTestSidecar(t)
	world := &testStaleWorld{
		sidecar:     sidecar,
		authority:   authority,
		deltaApi:    deltaApi,
		view:        newTestStaleGroupView(),
		memberId:    NewId(),
		groupId:     NewId(),
		newWorkerId: NewId(),
	}
	identity := sidecar.currentIdentity()
	ownMemberId := world.memberId
	if !member {
		ownMemberId = NewId()
	}
	authority.stateLock.Lock()
	authority.sidecars[identity.SidecarId] = &AclSidecar{
		Row:      &bridge.SidecarRow{SidecarId: identity.SidecarId.Bytes(), AdmittedAt: 1, MemberId: ownMemberId.Bytes()},
		MemberId: ownMemberId,
	}
	authority.consents[[2]Id{identity.SidecarId, ownMemberId}] = true
	authority.stateLock.Unlock()
	t.Cleanup(sidecar.InstallStaleGroupView(world.view))
	return world
}

// Admits a page Worker of the member, read_only.
func (self *testStaleWorld) admitWorker() Id {
	workerId := NewId()
	self.authority.stateLock.Lock()
	defer self.authority.stateLock.Unlock()
	self.authority.sidecars[workerId] = &AclSidecar{
		Row: &bridge.SidecarRow{
			SidecarId:    workerId.Bytes(),
			AdmittedAt:   2,
			MemberId:     self.memberId.Bytes(),
			Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY),
		},
		MemberId: self.memberId,
	}
	return workerId
}

// An act admitting the new Worker, with the stale revocations it carries.
func (self *testStaleWorld) admissionAct(t *testing.T) (*sidecarAct, *SidecarStaleRevocations) {
	t.Helper()
	act, err := self.sidecar.newAct(SidecarActConfirmed)
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Add(bridge.SignedType_SIGNED_SIDECAR_ADMIT, &protocol.SidecarAdmit{
		SidecarId:    self.newWorkerId.Bytes(),
		MemberId:     self.memberId.Bytes(),
		Capabilities: uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY),
	}); err != nil {
		t.Fatal(err)
	}
	revocations, err := act.AddStaleRevocations(t.Context(), self.memberId, &self.newWorkerId)
	if err != nil {
		t.Fatal(err)
	}
	return act, revocations
}

// What a post carried: its type, and the sidecar a revocation or admission names.
func testPostedStatement(t *testing.T, post []byte) (bridge.SignedType, Id) {
	t.Helper()
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(post, signed); err != nil {
		t.Fatal(err)
	}
	signedType := bridge.SignedType(signed.GetType())
	var sidecarId []byte
	switch signedType {
	case bridge.SignedType_SIGNED_SIDECAR_REVOKE:
		revoke := &bridge.SidecarRevoke{}
		if err := proto.Unmarshal(signed.GetBody(), revoke); err != nil {
			t.Fatal(err)
		}
		if revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED {
			t.Errorf("reason %s", revoke.GetReason())
		}
		sidecarId = revoke.GetSidecarId()
	case bridge.SignedType_SIGNED_SIDECAR_ADMIT:
		admit := &protocol.SidecarAdmit{}
		if err := proto.Unmarshal(signed.GetBody(), admit); err != nil {
			t.Fatal(err)
		}
		sidecarId = admit.GetSidecarId()
	}
	id, _ := IdFromBytes(sidecarId)
	return signedType, id
}

// A presence key whose check covers admissions and revocations, counting each check.
func (self *testStaleWorld) presence(t *testing.T) (SidecarPresenceCheck, *int, *[]byte) {
	t.Helper()
	key, keyId := addTestPresenceKey(t, self.authority)
	self.authority.stateLock.Lock()
	self.authority.covered[bridge.SignedType_SIGNED_SIDECAR_ADMIT] = true
	self.authority.covered[bridge.SignedType_SIGNED_SIDECAR_REVOKE] = true
	self.authority.stateLock.Unlock()
	checks := 0
	var seen []byte
	check := testPresenceCheck(t, key, keyId, &seen)
	return func(countersignedBytes []byte) (*bridge.WebAuthnEvidence, error) {
		checks += 1
		return check(countersignedBytes)
	}, &checks, &seen
}

// D-CORE-20: the stale revocations are statements of the admission's own act, so the person's one confirmation and the
// one presence check cover them with the admission; nothing asks again.
func TestStaleRevocationRidesTheAct(t *testing.T) {
	world := newTestStaleWorld(t, true)
	stale := world.admitWorker()
	live := world.admitWorker()
	world.view.set(world.groupId, stale, SidecarStaleLeafRemoved, true)
	world.view.set(world.groupId, live, SidecarStaleLeafLive, true)
	check, checks, seen := world.presence(t)

	act, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 1 || revocations.Revoked[0] != stale {
		t.Fatalf("revoked %v", revocations.Revoked)
	}
	if len(revocations.Offered) != 1 || revocations.Offered[0].SidecarId != live || revocations.Offered[0].LastChange.IsZero() {
		t.Errorf("offered %+v", revocations.Offered)
	}
	pins, err := act.Run(t.Context(), check)
	if err != nil {
		t.Fatal(err)
	}
	if *checks != 1 {
		t.Errorf("%d presence checks", *checks)
	}
	if len(pins) != 2 || !bytes.Equal(*seen, act.countersigned) {
		t.Fatalf("%d pins; the check saw the act's bytes: %v", len(pins), bytes.Equal(*seen, act.countersigned))
	}
	// the one check's countersignature rides both statements, each with its place in an act of two
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 2 {
		t.Fatalf("%d posts", len(posts))
	}
	for index, post := range posts {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		if signed.GetWebauthn().GetActSize() != 2 || signed.GetWebauthn().GetActIndex() != uint32(index) {
			t.Errorf("post %d countersigned as %d of %d", index, signed.GetWebauthn().GetActIndex(), signed.GetWebauthn().GetActSize())
		}
	}
}

// §7.10: the revocations post before the admission, so the room they free counts at config_admissions' cap.
func TestRevocationsPostBeforeAdmission(t *testing.T) {
	world := newTestStaleWorld(t, true)
	first := world.admitWorker()
	second := world.admitWorker()
	world.view.set(world.groupId, first, SidecarStaleLeafRemoved, true)
	world.view.set(world.groupId, second, SidecarStaleLeafRemoved, true)

	act, _ := world.admissionAct(t)
	if _, err := act.Run(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 3 {
		t.Fatalf("%d posts", len(posts))
	}
	revoked := []Id{}
	for _, post := range posts[:2] {
		signedType, sidecarId := testPostedStatement(t, post)
		if signedType != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
			t.Fatalf("posted %s before the admission", signedType)
		}
		revoked = append(revoked, sidecarId)
	}
	if !slices.Contains(revoked, first) || !slices.Contains(revoked, second) {
		t.Errorf("revoked %v", revoked)
	}
	if signedType, sidecarId := testPostedStatement(t, posts[2]); signedType != bridge.SignedType_SIGNED_SIDECAR_ADMIT || sidecarId != world.newWorkerId {
		t.Errorf("last posted %s of %s", signedType, sidecarId)
	}
}

// §7.10 and §5.9: the decision is made again before the post. A Worker back in a group by a resync between the act's
// decision and its post is not revoked: its revocation is dropped unposted, and the admission still goes.
func TestRecheckDropsWorkerBackInAGroup(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	world.view.set(world.groupId, worker, SidecarStaleLeafRemoved, true)
	// the re-check, the view's second answer, finds it resynced (KF5)
	world.view.changeAt[2] = func() {
		world.view.set(world.groupId, worker, SidecarStaleLeafLive, true)
	}

	act, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 1 {
		t.Fatalf("revoked %v", revocations.Revoked)
	}
	pins, err := act.Run(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 2 || pins[0] != nil || pins[1] == nil {
		t.Errorf("pins %v", pins)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 1 {
		t.Fatalf("%d posts", len(posts))
	}
	if signedType, _ := testPostedStatement(t, posts[0]); signedType != bridge.SignedType_SIGNED_SIDECAR_ADMIT {
		t.Errorf("posted %s", signedType)
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 0 {
		t.Errorf("%d pending: %v", len(pendings), err)
	}
}

// A due Remove is this device's to commit, and it commits it after the decision and before the revocation posts; a
// Worker due in a group where this device is no writer leaf is not stale in its view.
func TestDueRemoveCommitsBeforeTheRevocation(t *testing.T) {
	world := newTestStaleWorld(t, true)
	due := world.admitWorker()
	notWriter := world.admitWorker()
	world.view.set(world.groupId, due, SidecarStaleLeafDue, true)
	world.view.set(world.groupId, notWriter, SidecarStaleLeafDue, false)
	postsAtCommit := -1
	world.view.commitSeen = func() {
		postsAtCommit = len(world.deltaApi.postsSoFar())
	}

	act, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 1 || revocations.Revoked[0] != due {
		t.Fatalf("revoked %v", revocations.Revoked)
	}
	if len(world.view.commits) != 0 {
		t.Fatal("a Remove committed before the act ran")
	}
	if _, err := act.Run(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	if len(world.view.commits) != 1 || world.view.commits[0] != [2]Id{world.groupId, due} {
		t.Errorf("commits %v", world.view.commits)
	}
	if postsAtCommit != 0 {
		t.Errorf("the Remove committed after %d posts", postsAtCommit)
	}
}

// §5.6's sign row with §7.10: a kill between the revocations and the admission leaves the rest pending, and the next
// start posts the very same bytes in the act's order, the revocation re-checked first.
func TestKillBetweenAdmissionAndRevocationsRepostsSameBytes(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	world.view.set(world.groupId, worker, SidecarStaleLeafRemoved, true)

	act, _ := world.admissionAct(t)
	// the revocation's answer is lost: the admission is not posted ahead of it
	world.deltaApi.answers = []string{"lost"}
	if _, err := act.Run(t.Context(), nil); !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("a lost answer: %v", err)
	}
	firstPosts := world.deltaApi.postsSoFar()
	if len(firstPosts) != 1 {
		t.Fatalf("%d posts before the kill", len(firstPosts))
	}
	if pendings, err := world.sidecar.pendingStatements(); err != nil || len(pendings) != 2 {
		t.Fatalf("pending %d: %v", len(pendings), err)
	}

	// the restarted daemon reposts both, the revocation first and byte for byte, then the admission
	if err := world.sidecar.PostPendingStatements(t.Context()); err != nil {
		t.Fatal(err)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 3 {
		t.Fatalf("%d posts", len(posts))
	}
	if !bytes.Equal(posts[1], firstPosts[0]) {
		t.Error("the revocation was not reposted byte for byte")
	}
	if signedType, _ := testPostedStatement(t, posts[2]); signedType != bridge.SignedType_SIGNED_SIDECAR_ADMIT {
		t.Errorf("then %s", signedType)
	}
	if pendings, _ := world.sidecar.pendingStatements(); len(pendings) != 0 {
		t.Errorf("%d still pending", len(pendings))
	}

	// and a kill after the revocation landed reposts only the admission, its same bytes
	again := newTestStaleWorld(t, true)
	againWorker := again.admitWorker()
	again.view.set(again.groupId, againWorker, SidecarStaleLeafRemoved, true)
	againAct, _ := again.admissionAct(t)
	again.deltaApi.answers = []string{"ok", "lost"}
	if _, err := againAct.Run(t.Context(), nil); !errors.Is(err, ErrSidecarActPending) {
		t.Fatalf("a lost answer: %v", err)
	}
	if err := again.sidecar.PostPendingStatements(t.Context()); err != nil {
		t.Fatal(err)
	}
	againPosts := again.deltaApi.postsSoFar()
	if len(againPosts) != 3 || !bytes.Equal(againPosts[2], againPosts[1]) {
		t.Errorf("%d posts; the admission reposted the same: %v", len(againPosts), len(againPosts) == 3 && bytes.Equal(againPosts[2], againPosts[1]))
	}
}

// A retry whose re-check cannot run keeps the revocation, and the admission behind it, pending: neither is posted
// without the decision.
func TestRetryWithoutTheViewKeepsTheActPending(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	world.view.set(world.groupId, worker, SidecarStaleLeafRemoved, true)
	act, _ := world.admissionAct(t)
	world.deltaApi.answers = []string{"lost"}
	act.Run(t.Context(), nil)
	world.view.stateLock.Lock()
	world.view.answerErr = errors.New("gkm unavailable")
	world.view.stateLock.Unlock()
	if err := world.sidecar.PostPendingStatements(t.Context()); err == nil {
		t.Fatal("no error from a re-check that could not run")
	}
	if posts := world.deltaApi.postsSoFar(); len(posts) != 1 {
		t.Errorf("%d posts", len(posts))
	}
	if pendings, _ := world.sidecar.pendingStatements(); len(pendings) != 2 {
		t.Errorf("%d pending", len(pendings))
	}
}

// Owner decision 126: an admin's device revokes only the Workers it saw removed as stale in its own groups, and offers
// none; a Worker none of its groups seated, or one still live, is the member's to revoke.
func TestAdminRevokesOnlyWhatItSaw(t *testing.T) {
	world := newTestStaleWorld(t, false)
	seen := world.admitWorker()
	unseated := world.admitWorker()
	live := world.admitWorker()
	world.view.set(world.groupId, seen, SidecarStaleLeafRemoved, true)
	world.view.set(world.groupId, live, SidecarStaleLeafLive, true)
	_ = unseated

	act, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 1 || revocations.Revoked[0] != seen {
		t.Errorf("revoked %v", revocations.Revoked)
	}
	if len(revocations.Offered) != 0 {
		t.Errorf("an admin's device offered %v", revocations.Offered)
	}
	if _, err := act.Run(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	for _, post := range world.deltaApi.postsSoFar() {
		if signedType, sidecarId := testPostedStatement(t, post); signedType == bridge.SignedType_SIGNED_SIDECAR_REVOKE && sidecarId != seen {
			t.Errorf("revoked %s, which it did not see removed", sidecarId)
		}
	}
}

// A Worker no group of this device seated, and every Worker while no group view is installed, is never revoked here:
// the member's consented device offers it instead.
func TestNoGroupSeatedRevokesNothing(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	_, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 0 || len(revocations.Offered) != 1 || revocations.Offered[0].SidecarId != worker {
		t.Errorf("revoked %v, offered %+v", revocations.Revoked, revocations.Offered)
	}

	none := newTestStaleWorld(t, true)
	noneWorker := none.admitWorker()
	none.view.set(none.groupId, noneWorker, SidecarStaleLeafRemoved, true)
	none.sidecar.InstallStaleGroupView(nil)
	_, noViewRevocations := none.admissionAct(t)
	if len(noViewRevocations.Revoked) != 0 {
		t.Errorf("revoked %v with no group view", noViewRevocations.Revoked)
	}
}

// An authority answering §7.9's several row: every SidecarRevoke this device signs needs k > 1.
type testProposalAuthority struct {
	*testActAuthority
}

func (self *testProposalAuthority) ProposalRequired(statement *SidecarStatement) bool {
	return statement.Type == bridge.SignedType_SIGNED_SIDECAR_REVOKE
}

// §7.10 at k > 1: an AdminSet member's stale Worker goes as its own AuthorityProposal beside the admission's, carrying
// the SidecarRevoke as signed, and the act still posts it first.
func TestAdminSetMemberGetsItsOwnProposal(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	world.view.set(world.groupId, worker, SidecarStaleLeafRemoved, true)
	t.Cleanup(world.sidecar.InstallAuthority(&testProposalAuthority{testActAuthority: world.authority}))

	act, revocations := world.admissionAct(t)
	if len(revocations.Revoked) != 1 {
		t.Fatalf("revoked %v", revocations.Revoked)
	}
	if _, err := act.Run(t.Context(), nil); err != nil {
		t.Fatal(err)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 2 {
		t.Fatalf("%d posts", len(posts))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(posts[0], signed); err != nil {
		t.Fatal(err)
	}
	if bridge.SignedType(signed.GetType()) != bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL {
		t.Fatalf("posted %s first", bridge.SignedType(signed.GetType()))
	}
	proposal := &protocol.AuthorityProposal{}
	if err := proto.Unmarshal(signed.GetBody(), proposal); err != nil {
		t.Fatal(err)
	}
	revoke := &bridge.SidecarRevoke{}
	if bridge.SignedType(proposal.GetStatementType()) != bridge.SignedType_SIGNED_SIDECAR_REVOKE || proto.Unmarshal(proposal.GetStatement(), revoke) != nil {
		t.Fatal("the proposal carries no SidecarRevoke")
	}
	if !bytes.Equal(revoke.GetSidecarId(), worker.Bytes()) || revoke.GetReason() != bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED ||
		revoke.GetHeader() == nil || proposal.GetHeader() == nil {
		t.Errorf("the proposed revocation %v", revoke)
	}
}

// The member's admission of a page Worker through ur approve carries the stale revocations, posted first.
func TestPageWorkerAdmissionCarriesStaleRevocations(t *testing.T) {
	world := newTestStaleWorld(t, true)
	worker := world.admitWorker()
	world.view.set(world.groupId, worker, SidecarStaleLeafRemoved, true)
	approvalId, err := world.sidecar.OpenAdmission(&SidecarAdmissionRequest{
		SidecarId:         world.newWorkerId,
		MemberId:          world.memberId,
		IdentityPublicKey: bytes.Repeat([]byte{7}, 32),
		Capabilities:      uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.sidecar.DecideApproval(t.Context(), approvalId, SidecarDecisionApprove, SidecarActConfirmed, nil); err != nil {
		t.Fatal(err)
	}
	posts := world.deltaApi.postsSoFar()
	if len(posts) != 2 {
		t.Fatalf("%d posts", len(posts))
	}
	if signedType, sidecarId := testPostedStatement(t, posts[0]); signedType != bridge.SignedType_SIGNED_SIDECAR_REVOKE || sidecarId != worker {
		t.Errorf("first %s of %s", signedType, sidecarId)
	}
	if signedType, sidecarId := testPostedStatement(t, posts[1]); signedType != bridge.SignedType_SIGNED_SIDECAR_ADMIT || sidecarId != world.newWorkerId {
		t.Errorf("then %s of %s", signedType, sidecarId)
	}
}

// The act record round-trips, and bytes no version writes are a failure, never a plain statement.
func TestPendingActRecordRoundTrip(t *testing.T) {
	for _, act := range []*sidecarPendingAct{
		{actId: NewId(), index: 3},
		{actId: NewId(), index: 0, stale: &sidecarStaleRevocation{workerId: NewId(), memberId: NewId()}},
	} {
		decoded, err := decodeSidecarPendingAct(act.encode())
		if err != nil {
			t.Fatal(err)
		}
		if decoded.actId != act.actId || decoded.index != act.index || (decoded.stale == nil) != (act.stale == nil) ||
			(act.stale != nil && *decoded.stale != *act.stale) {
			t.Errorf("%+v became %+v", act, decoded)
		}
		encoded := act.encode()
		for _, damaged := range [][]byte{encoded[:len(encoded)-1], append([]byte{2}, encoded[1:]...), append(bytes.Clone(encoded), 0)} {
			if _, err := decodeSidecarPendingAct(damaged); !errors.Is(err, ErrSidecarStoreFailed) {
				t.Errorf("damaged record: %v", err)
			}
		}
	}
}
