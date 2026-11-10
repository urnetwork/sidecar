// EVS2-M10-05's tests of the migration's raise (§11.6's format row, D-EVS-39, FS-72's M10 cases on T2): the raise
// changing only repo/'s format; two racing raises making one write; a raise racing a RepoDelete and a shred, one
// winner and no deleted or shredded repo revived; a raise killed before and after its write and resumed by its
// push's next attempt; a push that fails after its raise leaving format 2 over format-1 data, on which a format-1
// client's versioned push still commits; and a push whose raise meets a repo deleted under it refused by 5c's rule.

package evsservice

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The raise's writes cost nothing in these tests: the class is the caller's.
func raiseTestClassify(ctx context.Context, objectByteCount int) context.Context {
	return ctx
}

// repo/ written whole over what is there, without telling the engine's cache: what another process wrote.
func (self *pushFixture) writeRepo(object *protocol.EvsRepoObject) {
	self.t.Helper()
	repoBytes, err := sidecar.MarshalEvsRepoObject(object)
	if err != nil {
		self.t.Fatal(err)
	}
	info, err := self.cluster.Head(self.ctx, RepoKey(self.check.repoId))
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := self.cluster.PutIfMatch(self.ctx, RepoKey(self.check.repoId), info.Etag, repoBytes, nil); err != nil {
		self.t.Fatal(err)
	}
}

// The fixture's repo/ with every field a raise must keep set, in state.
func (self *pushFixture) fullRepo(state protocol.EvsRepoState, format uint32) *protocol.EvsRepoObject {
	object := &protocol.EvsRepoObject{
		RepoId: self.check.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL, OwnerMemberId: testId("owner member").Bytes(),
		State: state, StateMs: self.clock.Now().UnixMilli(), Format: format, SealedName: []byte("sealed name"),
		NetworkId: self.check.networkId.Bytes(),
	}
	switch state {
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		object.DeletionId = testId("deletion").Bytes()
		object.StateSigner = self.check.signerId.Bytes()
	case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
		object.DeletionId = testId("deletion").Bytes()
	}
	return object
}

// The raise writes format 2 by one If-Match and changes nothing else; a second raise finds it done and writes
// nothing.
func TestRaiseRepoFormatChangesOnlyTheFormat(t *testing.T) {
	fixture := newPushFixture(t, nil)
	before := fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat1)
	fixture.writeRepo(before)
	repos := NewRepoCache(fixture.clock, fixture.settings)
	raised, err := RaiseRepoFormat(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify)
	if err != nil {
		t.Fatal(err)
	}
	stored, etag := fixture.repo()
	want := proto.Clone(before).(*protocol.EvsRepoObject)
	want.Format = sidecar.EvsRepoFormat2
	if !proto.Equal(stored, want) || !proto.Equal(raised.Object, want) || raised.Etag != etag {
		t.Fatalf("raised repo/ %v, want %v", stored, want)
	}
	again, err := RaiseRepoFormat(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify)
	if err != nil || again.Etag != etag || again.Object.GetFormat() != sidecar.EvsRepoFormat2 {
		t.Fatalf("a second raise: %v %v", again, err)
	}
	if _, after := fixture.repo(); after != etag {
		t.Fatal("a second raise wrote repo/")
	}
}

// Two raises that both read format 1: the second's If-Match meets a 412, its reread finds format 2 and it writes
// nothing, so repo/ is written once.
func TestTwoRacingRaisesWriteOnce(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.writeRepo(fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat1))
	repos, siblingRepos := NewRepoCache(fixture.clock, fixture.settings), NewRepoCache(fixture.clock, fixture.settings)
	var siblingEtag string
	var siblingErr error
	raced := false
	decide := decideRaiseFormat()
	outer, err := transitionRepo(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify, func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		if !raced {
			// the sibling's whole raise, between this one's read and its If-Match
			raced = true
			var sibling *EvsRepoRead
			sibling, siblingErr = RaiseRepoFormat(fixture.ctx, fixture.cluster, siblingRepos, fixture.check.repoId, 8, raiseTestClassify)
			if siblingErr == nil {
				siblingEtag = sibling.Etag
			}
		}
		return decide(read)
	})
	if err != nil || siblingErr != nil {
		t.Fatalf("racing raises: %v, %v", err, siblingErr)
	}
	stored, etag := fixture.repo()
	if stored.GetFormat() != sidecar.EvsRepoFormat2 || etag != siblingEtag || outer.Etag != siblingEtag {
		t.Fatalf("repo/ format %d written past the sibling's raise", stored.GetFormat())
	}
}

// A raise racing a RepoDelete, either way round: when the delete lands first the raise's 412 rereads a deleted repo
// and refuses REPO_DELETED, writing nothing, so the deletion stands whole; when the raise lands first the delete's
// 412 rereads format 2 and deletes that, keeping the format. One winner each time, and no state is lost.
func TestRaiseRacingARepoDelete(t *testing.T) {
	for _, deleteFirst := range []bool{true, false} {
		fixture := newPushFixture(t, nil)
		fixture.writeRepo(fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE, sidecar.EvsRepoFormat1))
		repos, otherRepos := NewRepoCache(fixture.clock, fixture.settings), NewRepoCache(fixture.clock, fixture.settings)
		deletion := &EvsRepoDeletionFacts{DeletionId: testId("deletion"), Time: fixture.clock.Now(), SignerSidecarId: fixture.check.signerId}
		raise, remove := decideRaiseFormat(), decideDelete(deletion, fixture.clock.Now())
		outerDecide, innerDecide := raise, remove
		if !deleteFirst {
			outerDecide, innerDecide = remove, raise
		}
		var innerErr error
		raced := false
		_, outerErr := transitionRepo(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify, func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
			if !raced {
				raced = true
				_, innerErr = transitionRepo(fixture.ctx, fixture.cluster, otherRepos, fixture.check.repoId, 8, raiseTestClassify, innerDecide)
			}
			return outerDecide(read)
		})
		stored, _ := fixture.repo()
		if stored.GetState() != protocol.EvsRepoState_EVS_REPO_DELETED || sidecar.Id(stored.GetDeletionId()) != deletion.DeletionId ||
			sidecar.Id(stored.GetStateSigner()) != deletion.SignerSidecarId || string(stored.GetSealedName()) != "sealed name" {
			t.Fatalf("delete first %t: repo/ %v", deleteFirst, stored)
		}
		var refusal *EvsRepoRefusal
		switch {
		case deleteFirst:
			if innerErr != nil || !errors.As(outerErr, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED {
				t.Errorf("the raise after the delete: %v, %v", innerErr, outerErr)
			}
			if stored.GetFormat() != sidecar.EvsRepoFormat1 {
				t.Errorf("a raise wrote a deleted repo: format %d", stored.GetFormat())
			}
		default:
			if innerErr != nil || outerErr != nil || stored.GetFormat() != sidecar.EvsRepoFormat2 {
				t.Errorf("the delete after the raise: %v, %v, format %d", innerErr, outerErr, stored.GetFormat())
			}
		}
	}
}

// A raise racing a shred's start, and a raise of a repo in every state but active: it refuses by 5c's rule and
// writes nothing, so no keying, deleted, shredding or shredded repo is revived or changed.
func TestRaiseNeverWritesARepoThatIsNotActive(t *testing.T) {
	fixture := newPushFixture(t, nil)
	// a deleted repo whose shred starts between the raise's read and its decision
	fixture.writeRepo(fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_DELETED, sidecar.EvsRepoFormat1))
	repos, shredRepos := NewRepoCache(fixture.clock, fixture.settings), NewRepoCache(fixture.clock, fixture.settings)
	raise := decideRaiseFormat()
	var shredErr error
	raced := false
	_, err := transitionRepo(fixture.ctx, fixture.cluster, repos, fixture.check.repoId, 8, raiseTestClassify, func(read *EvsRepoRead) (*protocol.EvsRepoObject, error) {
		if !raced {
			raced = true
			_, shredErr = transitionRepo(fixture.ctx, fixture.cluster, shredRepos, fixture.check.repoId, 8, raiseTestClassify, decideStartShred(testId("deletion"), fixture.clock.Now()))
		}
		return raise(read)
	})
	var refusal *EvsRepoRefusal
	if shredErr != nil || !errors.As(err, &refusal) || refusal.Code != protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED {
		t.Fatalf("a raise beside a shred's start: %v, %v", shredErr, err)
	}
	if stored, _ := fixture.repo(); stored.GetState() != protocol.EvsRepoState_EVS_REPO_SHREDDING || stored.GetFormat() != sidecar.EvsRepoFormat1 {
		t.Fatalf("repo/ after the shred's start: %v", stored)
	}

	for state, code := range map[protocol.EvsRepoState]protocol.EvsRefusalCode{
		protocol.EvsRepoState_EVS_REPO_KEYING:    protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING,
		protocol.EvsRepoState_EVS_REPO_DELETED:   protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED,
		protocol.EvsRepoState_EVS_REPO_SHREDDING: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING,
		protocol.EvsRepoState_EVS_REPO_SHREDDED:  protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING,
	} {
		fixture := newPushFixture(t, nil)
		before := fixture.fullRepo(state, sidecar.EvsRepoFormat1)
		fixture.writeRepo(before)
		_, etag := fixture.repo()
		_, err := RaiseRepoFormat(fixture.ctx, fixture.cluster, NewRepoCache(fixture.clock, fixture.settings), fixture.check.repoId, 8, raiseTestClassify)
		var refusal *EvsRepoRefusal
		if !errors.As(err, &refusal) || refusal.Code != code {
			t.Errorf("%s: a raise answered %v, want %s", state, err, code)
		}
		if stored, after := fixture.repo(); after != etag || !proto.Equal(stored, before) {
			t.Errorf("%s: a raise wrote repo/: %v", state, stored)
		}
	}
}

// The first format-2 push from a network in the gate raises its format-1 repo after step 6's record and before
// step 7, then commits; the next one finds format 2 and writes repo/ no more; GET .../refs' format follows.
func TestPushInTheGateRaisesItsRepoThenCommits(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2()
	token := fixture.token(fixture.check.signerId)
	_, created := fixture.repo()
	first := fixture.plan()
	fixture.createVersionless(first, "a")
	fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(first)), 1)
	raised, etag := fixture.repo()
	if raised.GetFormat() != sidecar.EvsRepoFormat2 || raised.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE || etag == created ||
		sidecar.Id(raised.GetNetworkId()) != fixture.check.networkId {
		t.Fatalf("repo/ after the first format-2 push: %v", raised)
	}
	second := fixture.plan()
	fixture.createVersionless(second, "b")
	fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(second)), 2)
	if _, after := fixture.repo(); after != etag {
		t.Fatal("a format-2 push on a format-2 repo wrote repo/")
	}
	// a format-1 client's versioned push still commits on the raised repo (FS-72's M10 case)
	versioned := fixture.plan()
	fixture.create(versioned, "c")
	fixture.requireCommitted(fixture.push(versioned), 3)
}

// A raise killed before its write (the store never took it) leaves format 1 and refuses nothing, and one killed
// after it (the write landed, its answer lost) is found by the reread; either way the push's next attempt, or the
// same one, commits with repo/ written once, so no repo is left half-migrated. FailBeforeApply and ApplyThenDrop are
// what a kill at evs.migrate.raise.before and at evs.migrate.raise.after leave in the store.
func TestRaiseKilledBeforeAndAfterItsWriteResumes(t *testing.T) {
	for _, result := range []sidecartest.FaultResult{sidecartest.FailBeforeApply, sidecartest.ApplyThenDrop} {
		fixture := newPushFixture(t, nil)
		fixture.openFormat2()
		token := fixture.token(fixture.check.signerId)
		plan := fixture.plan()
		fixture.createVersionless(plan, "a")
		body := fixture.bodyFormat2(plan)
		_, created := fixture.repo()
		repeat := 0
		if result == sidecartest.FailBeforeApply {
			// every try of this attempt's raise dies before the store takes it
			repeat = fixture.settings.RepoTransitionRetryCount
		}
		if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
			Op: sidecartest.FaultOpPut, KeyPrefix: RepoKey(fixture.check.repoId), Result: result, Repeat: repeat,
		}); err != nil {
			t.Fatal(err)
		}
		recorder := fixture.post(token, body)
		switch result {
		case sidecartest.FailBeforeApply:
			requireRefusal(t, recorder, http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
			if stored, etag := fixture.repo(); stored.GetFormat() != sidecar.EvsRepoFormat1 || etag != created {
				t.Fatalf("%s: repo/ format %d", result, stored.GetFormat())
			}
			if head := fixture.head(); head.Version() != 0 || len(head.Head.GetRefused()) != 0 {
				t.Fatalf("%s: a raise that never landed committed or refused its push", result)
			}
			fixture.requireCommitted(fixture.post(token, body), 1)
		default:
			fixture.requireCommitted(recorder, 1)
		}
		stored, etag := fixture.repo()
		if stored.GetFormat() != sidecar.EvsRepoFormat2 || etag == created {
			t.Fatalf("%s: repo/ format %d after the resumed push", result, stored.GetFormat())
		}
		// repo/ was written once: the next format-2 push finds format 2 and commits on the same ETag
		next := fixture.plan()
		fixture.createVersionless(next, "b")
		fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(next)), 2)
		if _, after := fixture.repo(); after != etag {
			t.Fatalf("%s: repo/ written again past its raise", result)
		}
	}
}

// A push whose step 7 fails after its raise leaves a format-2 repo holding only format-1 data, which is valid: no
// step undoes the raise, the push's retry commits on it, and a format-1 client's versioned push commits too.
func TestPushFailingAfterItsRaiseLeavesFormat2OverFormat1Data(t *testing.T) {
	fixture := newPushFixture(t, nil)
	token := fixture.token(fixture.check.signerId)
	versioned := fixture.plan()
	fixture.create(versioned, "kept")
	fixture.requireCommitted(fixture.push(versioned), 1)
	fixture.openFormat2()
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	body := fixture.bodyFormat2(plan)
	if _, err := fixture.host.Blobs.Faults().Add(&sidecartest.FaultPlan{
		Op: sidecartest.FaultOpPut, KeyPrefix: HeadKey(fixture.check.repoId, fixture.check.refId), Result: sidecartest.Precondition,
		Repeat: fixture.settings.PushConflictRetryCount,
	}); err != nil {
		t.Fatal(err)
	}
	requireRefusal(t, fixture.post(token, body), http.StatusTooManyRequests, protocol.EvsRefusalCode_EVS_REFUSAL_BUSY)
	stored, etag := fixture.repo()
	if stored.GetFormat() != sidecar.EvsRepoFormat2 || fixture.head().Version() != 1 {
		t.Fatalf("after the failed push: format %d, head %d", stored.GetFormat(), fixture.head().Version())
	}
	// format-1 data under format 2: a format-1 client's versioned push commits
	plain := fixture.plan()
	fixture.create(plain, "b")
	fixture.requireCommitted(fixture.push(plain), 2)
	// and the failed push's statement, built on version 1, is now judged on the head as it stands
	next := fixture.plan()
	fixture.createVersionless(next, "c")
	fixture.requireCommitted(fixture.post(token, fixture.bodyFormat2(next)), 3)
	if _, after := fixture.repo(); after != etag {
		t.Fatal("repo/ written again past its raise")
	}
}

// A repo deleted under a process that still caches it active: the push passes 5c on the cached repo/, its raise
// reads the cluster's, finds it deleted and writes nothing, and the rerun of steps 4 and 5 refuses by 5c's rule,
// 409 REPO_DELETED, recorded; the deleted repo keeps format 1 and its deletion.
func TestPushWhoseRaiseMeetsADeletedRepoIsRefusedBy5c(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.openFormat2()
	token := fixture.token(fixture.check.signerId)
	warm := fixture.plan()
	fixture.create(warm, "warm")
	fixture.requireCommitted(fixture.push(warm), 1)
	deleted := fixture.fullRepo(protocol.EvsRepoState_EVS_REPO_DELETED, sidecar.EvsRepoFormat1)
	fixture.writeRepo(deleted)
	_, etag := fixture.repo()
	plan := fixture.plan()
	fixture.createVersionless(plan, "a")
	body := fixture.bodyFormat2(plan)
	recorder := fixture.post(token, body)
	requireRefusal(t, recorder, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	if stored, after := fixture.repo(); after != etag || !proto.Equal(stored, deleted) {
		t.Fatalf("a raise wrote a deleted repo: %v", stored)
	}
	head := fixture.head()
	if head.Version() != 1 || len(head.Head.GetRefused()) != sidecar.EvsRefusalByteCount {
		t.Fatalf("the refusal was not recorded: version %d, %d refused bytes", head.Version(), len(head.Head.GetRefused()))
	}
	again := fixture.post(token, body)
	requireRefusal(t, again, http.StatusConflict, protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED)
	if !refusalOf(t, again).GetRecorded() {
		t.Fatal("the retry answered without recorded: true")
	}
}
