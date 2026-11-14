// DESIGN-DETAILS 16.6's second gate bullet (EVS1-M6-07; QD-803): the rules clause's refusal through the engine on
// FakeBlobs, and why its fate is recorded. A stale-pin push creating a shared ref leaves a placeholder head holding
// its refusal record and no version; a second attempt of the same push id is answered from the record, by this engine
// and by a sibling whose state does not hold the set yet; that sibling commits the same update on a ref whose head
// holds no record, which is what a final, unrecorded refusal would have let it do on this one; the update built again
// at the set's position commits as version 1 over the placeholder. On a deleted head the record goes into the
// tombstone and the next version follows the DELETE's. A part of a creating push in parts is refused with no record.

package evsservice

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Gate views holding one state whatever the check fixture appends after it: a sibling process that has not loaded
// the newest state.
type pushRulesHeldGateViews struct {
	networkId sidecar.Id
	view      sidecar.GkmAuthView
}

func (self *pushRulesHeldGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, EvsAuthAnswer) {
	if networkId != self.networkId {
		return nil, EvsAuthUnknown
	}
	return self.view, EvsAuthAllowed
}

// Files a rule set for the fixture's repo: the next position of the engine's state holds the repo's row with a set at
// that position. Its pin, the set's own, is returned.
func (self *pushFixture) fileRuleSet() *bridge.AuthPin {
	at := self.check.auth.Pin().GetVersion() + 1
	return self.check.appendRepoState(self.check.rulesRepo(at)).Pin()
}

// A second engine on the fixture's host and cluster, its gate views holding view: a sibling process of the fixture's
// engine, sharing its store.
func (self *pushFixture) sibling(view sidecar.GkmAuthView) *EvsEngine {
	self.t.Helper()
	engine, err := NewEvsEngine(self.ctx, self.host.ServiceHost(), self.settings, &EvsEngineDeps{
		AuthState: self.auth,
		Uploads:   &EvsUploadDeps{Keys: self.check.receiptKeys, Quota: self.check.quota.gate},
		GateViews: &pushRulesHeldGateViews{networkId: self.check.networkId, view: view},
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(engine.Close)
	return engine
}

// One POST .../push of body under token, served by engine.
func (self *pushFixture) postTo(engine *EvsEngine, token string, body *protocol.EvsPushRequest) *httptest.ResponseRecorder {
	bodyBytes, err := proto.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	request := httptest.NewRequestWithContext(self.ctx, http.MethodPost, "/evs/v1/repos/"+sidecar.EvsKeyId(self.check.repoId)+"/push", bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	engine.Handler().ServeHTTP(recorder, request)
	return recorder
}

// Holds an answer to the clause's 412 GATE_CLOSED, recorded as asked: false on the attempt that records it, true on
// one the record answers.
func requireRulesAnswer(t *testing.T, name string, recorder *httptest.ResponseRecorder, recorded bool) {
	t.Helper()
	requireRefusal(t, recorder, http.StatusPreconditionFailed, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
	if got := refusalOf(t, recorder).GetRecorded(); got != recorded {
		t.Fatalf("%s: answered recorded %t, want %t", name, got, recorded)
	}
}

// The head's refusal records: exactly one, of pushId and GATE_CLOSED.
func requireOneRulesRecord(t *testing.T, name string, head *protocol.EvsHead, pushId sidecar.Id) {
	t.Helper()
	records, err := sidecar.DecodeEvsRefusals(head.GetRefused())
	if err != nil || len(records) != 1 || !records[0].RecordsPush(pushId) || records[0].Code != protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
		t.Fatalf("%s: records %v (%v), want one GATE_CLOSED of the push", name, records, err)
	}
}

// On no head: the stale-pin creation is recorded in a placeholder, answered from the record by this engine and by a
// sibling that has not loaded the set, which commits the same update where no record stands; built again at the set's
// position it commits as version 1 over the placeholder, keeping the record.
func TestPushRecordsAStalePinCreationInAPlaceholderHead(t *testing.T) {
	fixture := newPushFixture(t, nil)
	unset := fixture.check.auth
	setPin := fixture.fileRuleSet()
	token := fixture.token(fixture.check.signerId)

	// pinned at 1, below the set at 2
	plan := fixture.plan()
	fixture.create(plan, "a")
	body := fixture.body(plan)
	requireRulesAnswer(t, "the stale-pin creation", fixture.post(token, body), false)
	placeholder := fixture.head()
	if placeholder.Absent() || placeholder.Version() != 0 || placeholder.Head.GetRefKind() != 0 || placeholder.Head.GetRefMode() != 0 ||
		len(placeholder.Head.GetWindow()) != 0 || placeholder.Head.GetFence() != 1 || len(placeholder.Head.GetRefused()) != sidecar.EvsRefusalByteCount {
		t.Fatalf("placeholder %v", placeholder.Head)
	}
	requireOneRulesRecord(t, "the placeholder", placeholder.Head, plan.PushId)

	// a second attempt of the same push id, at this engine and at a sibling whose state does not hold the set yet
	requireRulesAnswer(t, "a second attempt", fixture.post(token, body), true)
	sibling := fixture.sibling(unset)
	requireRulesAnswer(t, "a second attempt at the sibling", fixture.postTo(sibling, token, body), true)
	if head := fixture.head(); head.Etag != placeholder.Etag {
		t.Fatal("an attempt the record answered wrote the head")
	}

	// why the fate is recorded: where no record stands, the sibling commits the same update at the same stale pin
	elsewhere := *plan
	elsewhere.RefId = testId("rules elsewhere ref")
	elsewhere.BaseChain = sidecar.EvsChainStart(fixture.check.repoId, elsewhere.RefId)
	fixture.requireCommitted(fixture.postTo(sibling, token, fixture.body(&elsewhere)), 1)
	fixture.awaitStepEights()
	if head := fixture.headOf(elsewhere.RefId); head.Version() != 1 || head.Head.GetAuth().GetVersion() != plan.Auth.GetVersion() {
		t.Fatalf("the sibling's commit at %d under pin %d", head.Version(), head.Head.GetAuth().GetVersion())
	}

	// the same update built again at the set's position commits as version 1 over the placeholder, keeping its record
	rebuilt := fixture.plan()
	rebuilt.Auth = setPin
	fixture.create(rebuilt, "a")
	fixture.requireCommitted(fixture.post(token, fixture.body(rebuilt)), 1)
	fixture.awaitStepEights()
	head := fixture.head()
	if head.Version() != 1 || sidecar.Id(head.Head.GetPushId()) != rebuilt.PushId || head.Head.GetAuth().GetVersion() != setPin.GetVersion() ||
		!bytes.Equal(head.Head.GetRefused(), placeholder.Head.GetRefused()) {
		t.Fatalf("the rebuilt commit: version %d, pin %d, records kept %t", head.Version(), head.Head.GetAuth().GetVersion(),
			bytes.Equal(head.Head.GetRefused(), placeholder.Head.GetRefused()))
	}
	// and the held attempt is still answered from its record
	requireRulesAnswer(t, "the held attempt after the commit", fixture.post(token, body), true)
}

// On a deleted head, at the DELETE's pin and below the set: the record goes into the tombstone, and the push built
// again at the set's position commits at the version after the DELETE's.
func TestPushRecordsAStalePinRecreationInTheTombstone(t *testing.T) {
	fixture := newPushFixture(t, nil)
	// a shared ref's DELETE needs admin
	fixture.auth.grant(fixture.check.signerId, fixture.check.repoId, sidecar.AclEvsAdmin)
	token := fixture.token(fixture.check.signerId, "admin")

	first := fixture.plan()
	fixture.create(first, "a")
	fixture.requireCommitted(fixture.post(token, fixture.body(first)), 1)
	fixture.awaitStepEights()
	deletion := fixture.plan()
	deletion.Flags = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
	fixture.requireCommitted(fixture.post(token, fixture.body(deletion)), 2)
	fixture.awaitStepEights()
	tombstone := fixture.head()
	if !tombstone.Head.GetDeleted() || tombstone.Version() != 2 || len(tombstone.Head.GetRefused()) != 0 {
		t.Fatalf("the tombstone %v", tombstone.Head)
	}

	setPin := fixture.fileRuleSet()
	// re-created at the DELETE's pin, 1, below the set at 2
	again := fixture.plan()
	fixture.create(again, "b")
	body := fixture.body(again)
	requireRulesAnswer(t, "the stale-pin re-creation", fixture.post(token, body), false)
	recorded := fixture.head()
	if !recorded.Head.GetDeleted() || recorded.Version() != 2 || recorded.Etag == tombstone.Etag || !bytes.Equal(recorded.Head.GetChain(), tombstone.Head.GetChain()) {
		t.Fatalf("the tombstone after the refusal %v", recorded.Head)
	}
	requireOneRulesRecord(t, "the tombstone", recorded.Head, again.PushId)
	requireRulesAnswer(t, "a second attempt", fixture.post(token, body), true)

	// built again at the set's position: the next version follows the DELETE's
	rebuilt := fixture.plan()
	rebuilt.Auth = setPin
	fixture.create(rebuilt, "b")
	fixture.requireCommitted(fixture.post(token, fixture.body(rebuilt)), 3)
	fixture.awaitStepEights()
	if head := fixture.head(); head.Head.GetDeleted() || head.Version() != 3 || head.Head.GetAuth().GetVersion() != setPin.GetVersion() {
		t.Fatalf("the re-created head: deleted %t at %d under pin %d", head.Head.GetDeleted(), head.Version(), head.Head.GetAuth().GetVersion())
	}
}

// A part of a creating push in parts, pinned below the set, is refused with no record: only its push's seal commits.
func TestPushRefusesAStalePinPartWithNoRecord(t *testing.T) {
	fixture := newPushFixture(t, nil)
	fixture.fileRuleSet()
	token := fixture.token(fixture.check.signerId)
	built := fixture.built(fixture.partsPlan(protocol.EvsRefMode_EVS_REF_FILE, 1100))
	if len(built.Parts) < 2 {
		t.Fatalf("a push in %d parts", len(built.Parts))
	}
	requireRulesAnswer(t, "a part", fixture.postPart(token, built, 0), false)
	if !fixture.head().Absent() {
		t.Fatal("a part's refusal wrote a head")
	}
}
