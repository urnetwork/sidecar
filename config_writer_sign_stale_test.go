//go:build !sidecar_http && !js && !ios_extension

// A config writer's publish when the tip moves between a plan and its signing: signBase signed a plan at the log's tip
// as it found it, so another writer's base landing after the plan was made had the plan, its fold, its rows and the
// pushes it carries all judged against the base before, signed at a tip past that base, and api refused it (403):
// config_version below the newest base's, or a pushes walk that starts at the wrong head. The writer now signs only at
// the tip its plan was made or kept at, and plans again where the log moved: a plan kept where no other base landed,
// a new plan where one did. A publish whose head another writer's base already names, pushed past or as it is, folded
// as far as its plan would, lands at that base, as it now does after api's 409 for the same race. The race is forced
// at the last read a plan makes, of the pushes its base carries, after its tip check, its edit and its push: the
// writer's ref runs a hook there, which lands a rival writer's save, or a statement, and waits for the writer's client
// to apply it. On T2's fake api and the in-memory config ref, every base checked by the client as a full reader.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One device's ref to the config repo whose reads of the pushes a base carries, a save's alone, run a hook first: the
// last read a plan makes, after its tip check, its edit and its push, so what lands there moves the tip between the
// plan and its signing. Its reads of the current head count and hook as testTipMovedHeads' do. Safe for concurrent
// use.
type testSignStaleHeads struct {
	*testTipMovedHeads

	stateLock sync.Mutex
	// the save's reads of pushes so far
	pushReads int
	// runs before the save's read of pushes numbered read, from 1; nil runs none
	beforePushes func(ctx context.Context, read int)
}

func (self *testSignStaleHeads) ConfigHeadPushes(ctx context.Context, after uint64, through uint64) ([][]byte, error) {
	if ctx.Value(testTipMovedSaveKey{}) != nil {
		read, beforePushes := func() (int, func(context.Context, int)) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.pushReads += 1
			return self.pushReads, self.beforePushes
		}()
		if beforePushes != nil {
			beforePushes(ctx, read)
		}
	}
	return self.testTipMovedHeads.ConfigHeadPushes(ctx, after, through)
}

// The save's reads of pushes so far.
func (self *testSignStaleHeads) pushReadCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pushReads
}

// The owner's ref, its hooks unset.
func (self *testWriterWorld) signStaleHeads() *testSignStaleHeads {
	return &testSignStaleHeads{testTipMovedHeads: self.tipMovedHeads()}
}

// Another writer of the owner's, on a client of its own caught up to the tip, saving to the shared ref with no hook:
// the rival whose base lands under a plan.
type testSignStaleRival struct {
	world  *testWriterWorld
	client *sidecar.ConfigClient
	writer *sidecar.ConfigWriter
}

func (self *testWriterWorld) signStaleRival() *testSignStaleRival {
	self.t.Helper()
	client := self.client()
	self.caughtUp(client)
	return &testSignStaleRival{
		world:  self,
		client: client,
		writer: self.tipMovedWriter(client, self.heads.For(self.owner.sidecarId, self.owner.key), nil, nil),
	}
}

// The rival's base, published by publish once the rival's client stands at api's tip, and then applied by client, the
// writer's under test: a base landing between that writer's plan and its signing. Answers the base's pin, nil where it
// did not land, which the test is failed for. Runs inside a save, so it fails the test without stopping it.
func (self *testSignStaleRival) land(ctx context.Context, client *sidecar.ConfigClient, publish func(ctx context.Context, writer *sidecar.ConfigWriter) (*bridge.AuthPin, error)) *bridge.AuthPin {
	t := self.world.t
	waitCtx, cancel := context.WithTimeout(self.world.ctx, 30*time.Second)
	defer cancel()
	tip, err := self.world.api.Tip(waitCtx, self.world.networkId)
	if err != nil {
		t.Errorf("api's tip: %v", err)
		return nil
	}
	if _, err := self.client.WaitFor(waitCtx, tip.GetVersion()); err != nil {
		t.Errorf("the rival's client at %d: %v", tip.GetVersion(), err)
		return nil
	}
	// the rival's own context: none of the save's hooks
	pin, err := publish(waitCtx, self.writer)
	if err != nil {
		t.Errorf("the rival's base: %v", err)
		return nil
	}
	if _, err := client.WaitFor(waitCtx, pin.GetVersion()); err != nil {
		t.Errorf("applying the rival's base at %d: %v", pin.GetVersion(), err)
		return nil
	}
	return pin
}

// A rival's ACL save of source, planned on the head the ref holds then at the rival client's state, as `ur acl push`
// plans one: every ACL file a reader compiles, saved with its base.
func (self *testSignStaleRival) aclSave(source string) func(ctx context.Context, writer *sidecar.ConfigWriter) (*bridge.AuthPin, error) {
	return func(ctx context.Context, writer *sidecar.ConfigWriter) (*bridge.AuthPin, error) {
		head, _, _, err := self.world.heads.For(self.world.owner.sidecarId, self.world.owner.key).CurrentConfigHead(ctx)
		if err != nil {
			return nil, err
		}
		plan, err := sidecar.PlanAclSave(ctx, &sidecar.AclSaveInput{Policy: []byte(source), Head: head, State: self.client.State(), Now: self.world.clock.Now()})
		if err != nil {
			return nil, err
		}
		if err := plan.Tests.Err(); err != nil {
			return nil, err
		}
		return sidecar.AclSave(ctx, writer, plan)
	}
}

// A rival's save that marks the policy file of the head it reads.
func testSignStaleRivalSave(ctx context.Context, writer *sidecar.ConfigWriter) (*bridge.AuthPin, error) {
	return writer.SaveHead(ctx, func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		return head.WithFile(sidecar.ConfigHeadPolicyPath, append(bytes.Clone(head.File(sidecar.ConfigHeadPolicyPath)), testSignStaleRivalMark...))
	})
}

// What a rival's save appends to the policy file.
var testSignStaleRivalMark = []byte("\n// rival")

// The head the client's newest base names, and that base.
func (self *testWriterWorld) baseHead(client *sidecar.ConfigClient) (*sidecar.ConfigHead, *bridge.ProjectionHeader) {
	self.t.Helper()
	base := self.caughtUp(client).Base()
	head, err := self.heads.ReadConfigHead(self.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		self.t.Fatal(err)
	}
	return head, base
}

// The brief's race: a rival writer's save lands its base, on a head pushed past the save's own, between the save's plan
// and its signing. The save does not sign its stale plan, which api refused (403, config_version below the rival's base's)
// before this change; it plans again, finds the rival's base names a head past its push with the fold it would publish,
// and lands there, answering that base, its edit in force under the rival's: one edit, one push, no base of its own.
func TestABaseLandingBetweenASavesPlanAndItsSigningPlansTheSaveAgainAndLandsIt(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	var landed *bridge.AuthPin
	heads.beforePushes = func(ctx context.Context, read int) {
		if read == 1 {
			landed = rival.land(ctx, client, testSignStaleRivalSave)
		}
	}
	writer := world.tipMovedWriter(client, heads, nil, nil)
	versionBefore := world.heads.Version()
	edits := 0
	pin, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	if landed == nil {
		t.Fatal("no rival base landed between the plan and its signing")
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 2 || pushReads != 1 || edits != 1 {
		t.Fatalf("the save read the head %d times and its pushes %d times, and made its edit %d times", reads, pushReads, edits)
	}
	if pin.GetVersion() != landed.GetVersion() || !bytes.Equal(pin.GetChain(), landed.GetChain()) {
		t.Fatalf("the save answered the base at %d, the rival's landed at %d", pin.GetVersion(), landed.GetVersion())
	}
	head, base := world.baseHead(client)
	if base.GetVersion() != landed.GetVersion() {
		t.Fatalf("a base at %d past the rival's at %d", base.GetVersion(), landed.GetVersion())
	}
	if version := world.heads.Version(); version != versionBefore+2 || base.GetConfigVersion() != version {
		t.Fatalf("the ref at %d, %d before the save, the base naming %d", version, versionBefore, base.GetConfigVersion())
	}
	if want := append(bytes.Clone(testTipMovedPolicy), testSignStaleRivalMark...); !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), want) {
		t.Errorf("the base's head holds the policy %q", head.File(sidecar.ConfigHeadPolicyPath))
	}
}

// A fold whose plan another writer's base overtakes before it is signed plans again, folding through the new tip, so
// its base carries that base's record, and lands its own base on the new tip. Before this change api refused the stale
// plan (403).
func TestAFoldOvertakenBetweenItsPlanAndItsSigningLandsItsOwnBase(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	var landed *bridge.AuthPin
	heads.beforePushes = func(ctx context.Context, read int) {
		if read == 1 {
			landed = rival.land(ctx, client, testSignStaleRivalSave)
		}
	}
	writer := world.tipMovedWriter(client, heads, nil, nil)
	versionBefore := world.heads.Version()
	pin, err := writer.PublishBase(testTipMovedSaveContext(world.ctx), true)
	if err != nil {
		t.Fatalf("the fold: %v", err)
	}
	if landed == nil {
		t.Fatal("no rival base landed between the plan and its signing")
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 2 || pushReads != 2 {
		t.Fatalf("the fold read the head %d times and its pushes %d times", reads, pushReads)
	}
	if pin.GetVersion() != landed.GetVersion()+1 {
		t.Fatalf("the fold landed at %d, the rival's base at %d", pin.GetVersion(), landed.GetVersion())
	}
	head, base := world.baseHead(client)
	if base.GetVersion() != pin.GetVersion() || base.GetFoldedThrough() != landed.GetVersion() {
		t.Fatalf("the base at %d folds through %d", base.GetVersion(), base.GetFoldedThrough())
	}
	if version := world.heads.Version(); version != versionBefore+3 || base.GetConfigVersion() != version {
		t.Fatalf("the ref at %d, %d before the fold, the base naming %d", version, versionBefore, base.GetConfigVersion())
	}
	records, err := head.RecordsIn(landed.GetVersion()-1, landed.GetVersion())
	if err != nil || len(records) != 1 || records[0].GetKind() != bridge.AuthEntryKindBase || records[0].GetN() != landed.GetVersion() {
		t.Errorf("the fold's records past the rival's: %v", err)
	}
}

// A fold whose plan another writer's base overtakes before every signing gives up once PublishAttemptCount plans have
// met a moved tip, with ErrConfigTipMoved under ErrConfigWriterGaveUp: it planned and pushed that many times and landed
// no base, and every rival base landed.
func TestAFoldOvertakenBeforeEverySigningGivesUpWithTipMoved(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	rivalPins := []*bridge.AuthPin{}
	heads.beforePushes = func(ctx context.Context, read int) {
		if pin := rival.land(ctx, client, testSignStaleRivalSave); pin != nil {
			rivalPins = append(rivalPins, pin)
		}
	}
	writer := world.tipMovedWriter(client, heads, nil, func(settings *sidecar.ConfigWriterSettings) {
		settings.PublishAttemptCount = 3
	})
	versionBefore := world.heads.Version()
	_, err := writer.PublishBase(testTipMovedSaveContext(world.ctx), true)
	if !errors.Is(err, sidecar.ErrConfigTipMoved) || !errors.Is(err, sidecar.ErrConfigWriterGaveUp) {
		t.Fatalf("a fold whose tip kept moving: %v", err)
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 3 || pushReads != 3 || len(rivalPins) != 3 {
		t.Fatalf("the fold read the head %d times and its pushes %d times, and %d rival bases landed", reads, pushReads, len(rivalPins))
	}
	if version := world.heads.Version(); version != versionBefore+6 {
		t.Fatalf("the ref at %d, %d before the fold", version, versionBefore)
	}
	if base := world.caughtUp(client).Base(); base.GetVersion() != rivalPins[2].GetVersion() {
		t.Fatalf("a base at %d past the rival's last at %d", base.GetVersion(), rivalPins[2].GetVersion())
	}
}

// A statement landing between a save's plan and its signing moves the tip and no base: the save plans again, keeps the
// plan it made, reading no head again, and signs it at the new tip, landing past the statement and naming its push.
func TestAStatementLandingBetweenASavesPlanAndItsSigningKeepsThePlan(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	heads := world.signStaleHeads()
	var late *bridge.AuthPin
	heads.beforePushes = func(ctx context.Context, read int) {
		if read == 1 {
			late = world.landAndApply(ctx, client, "late")
		}
	}
	writer := world.tipMovedWriter(client, heads, nil, nil)
	versionBefore := world.heads.Version()
	edits := 0
	pin, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	if late == nil {
		t.Fatal("no statement landed between the plan and its signing")
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 1 || pushReads != 1 || edits != 1 {
		t.Fatalf("the save read the head %d times and its pushes %d times, and made its edit %d times", reads, pushReads, edits)
	}
	if pin.GetVersion() != late.GetVersion()+1 {
		t.Fatalf("the base landed at %d, the statement at %d", pin.GetVersion(), late.GetVersion())
	}
	head, base := world.baseHead(client)
	if base.GetVersion() != pin.GetVersion() || world.caughtUp(client).Member(testWriterId("late")) == nil {
		t.Fatalf("the client's base at %d", base.GetVersion())
	}
	if version := world.heads.Version(); version != versionBefore+1 || base.GetConfigVersion() != version {
		t.Fatalf("the ref at %d, %d before the save, the base naming %d", version, versionBefore, base.GetConfigVersion())
	}
	if !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), testTipMovedPolicy) {
		t.Error("the base's head lacks the save's policy")
	}
}

// The same race met at api, an adjacent case: a rival's save lands its base, on a head pushed past the save's, after the
// save signed and before its base reached api, which answers 409. The save plans again and lands at the rival's base,
// which names a head past its push with the fold it would publish. Before this change the save failed there with
// ErrConfigWriterNothing, its head in force under the rival's base.
func TestASaveWhoseBaseMeetsARivalBaseNamingAHeadPastItsPushLandsAtThatBase(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	publisher := world.publisher()
	publishes := 0
	var landed *bridge.AuthPin
	publisher.Before = func(ctx context.Context) {
		publishes += 1
		if publishes != 1 {
			return
		}
		pin, err := testSignStaleRivalSave(world.ctx, rival.writer)
		if err != nil {
			t.Errorf("the rival's base: %v", err)
			return
		}
		landed = pin
	}
	writer := world.tipMovedWriter(client, heads, publisher, nil)
	versionBefore := world.heads.Version()
	edits := 0
	pin, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	if landed == nil || publishes != 1 || edits != 1 {
		t.Fatalf("the save published %d times and made its edit %d times, a rival base landed: %v", publishes, edits, landed != nil)
	}
	if reads := heads.readCount(); reads != 2 {
		t.Fatalf("the save read the head %d times", reads)
	}
	if pin.GetVersion() != landed.GetVersion() || !bytes.Equal(pin.GetChain(), landed.GetChain()) {
		t.Fatalf("the save answered the base at %d, the rival's landed at %d", pin.GetVersion(), landed.GetVersion())
	}
	head, base := world.baseHead(client)
	if base.GetVersion() != landed.GetVersion() || world.heads.Version() != versionBefore+2 || base.GetConfigVersion() != versionBefore+2 {
		t.Fatalf("a base at %d naming %d, the ref at %d", base.GetVersion(), base.GetConfigVersion(), world.heads.Version())
	}
	if want := append(bytes.Clone(testTipMovedPolicy), testSignStaleRivalMark...); !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), want) {
		t.Errorf("the base's head holds the policy %q", head.File(sidecar.ConfigHeadPolicyPath))
	}
}

// A confirmed ACL save (EXACT_HEAD, QD-1213) whose plan pushed its head, overtaken before its signing by a rival save
// pushed on top of that head with its base, plans again and is refused there, ErrConfigHeadConflict, a new preview
// needed: its config ref moved past the push it confirmed. No base of the save's lands; the rival's names the rival's
// head. Before this change api refused the stale plan (403) instead.
func TestAConfirmedSaveOvertakenBetweenItsPlanAndItsSigningIsRefusedWhenItsRefMoved(t *testing.T) {
	world := newTestTipMovedAclWorld(t)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	plan := world.confirmedPlan(heads, testAclSavePolicyA)
	versionBefore := world.heads.Version()
	var landed *bridge.AuthPin
	heads.beforePushes = func(ctx context.Context, read int) {
		if read == 1 {
			landed = rival.land(ctx, world.client, rival.aclSave(testAclSavePolicyB))
		}
	}
	writer := world.tipMovedWriter(world.client, heads, nil, nil)
	if _, err := sidecar.AclSave(testTipMovedSaveContext(world.ctx), writer, plan); !errors.Is(err, sidecar.ErrConfigHeadConflict) {
		t.Fatalf("a confirmed save whose ref moved: %v", err)
	}
	if landed == nil {
		t.Fatal("no rival base landed between the plan and its signing")
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 2 || pushReads != 1 {
		t.Fatalf("the save read the head %d times and its pushes %d times", reads, pushReads)
	}
	head, version := world.head()
	if version != versionBefore+2 || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(testAclSavePolicyB)) {
		t.Fatalf("the ref at %d, %d before the save, holding another policy than the rival's", version, versionBefore)
	}
	if base := world.caughtUp(world.client).Base(); base.GetVersion() != landed.GetVersion() || base.GetConfigVersion() != version {
		t.Fatalf("a base at %d naming %d", base.GetVersion(), base.GetConfigVersion())
	}
}

// A confirmed ACL save whose pushed head a rival's base names as it is, before the save signed its own, plans again and
// lands at that base: the base names the exact head the person confirmed (EXACT_HEAD), so nothing is left to publish.
// Before this change api refused the stale plan (403, its pushes walked from the wrong head).
func TestAConfirmedSaveWhoseExactHeadARivalBasePublishedLandsAtThatBase(t *testing.T) {
	world := newTestTipMovedAclWorld(t)
	rival := world.signStaleRival()
	heads := world.signStaleHeads()
	plan := world.confirmedPlan(heads, testAclSavePolicyA)
	versionBefore := world.heads.Version()
	var landed *bridge.AuthPin
	heads.beforePushes = func(ctx context.Context, read int) {
		if read == 1 {
			landed = rival.land(ctx, world.client, func(ctx context.Context, writer *sidecar.ConfigWriter) (*bridge.AuthPin, error) {
				return writer.PublishBase(ctx, false)
			})
		}
	}
	writer := world.tipMovedWriter(world.client, heads, nil, nil)
	pin, err := sidecar.AclSave(testTipMovedSaveContext(world.ctx), writer, plan)
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	if landed == nil {
		t.Fatal("no rival base landed between the plan and its signing")
	}
	if pin.GetVersion() != landed.GetVersion() || !bytes.Equal(pin.GetChain(), landed.GetChain()) {
		t.Fatalf("the save answered the base at %d, the rival's landed at %d", pin.GetVersion(), landed.GetVersion())
	}
	if reads, pushReads := heads.readCount(), heads.pushReadCount(); reads != 2 || pushReads != 1 {
		t.Fatalf("the save read the head %d times and its pushes %d times", reads, pushReads)
	}
	head, version := world.head()
	if version != versionBefore+1 || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(testAclSavePolicyA)) {
		t.Fatalf("the ref at %d, %d before the save, holding another policy than the save's", version, versionBefore)
	}
	state := world.caughtUp(world.client)
	if base := state.Base(); base.GetVersion() != landed.GetVersion() || base.GetConfigVersion() != version {
		t.Fatalf("a base at %d naming %d", base.GetVersion(), base.GetConfigVersion())
	}
	acl, err := state.Acl()
	if err != nil || !acl.HasDocument() {
		t.Errorf("the reader's rows: %v", err)
	}
}
