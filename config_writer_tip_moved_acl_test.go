//go:build !sidecar_http && !js && !ios_extension

// A confirmed ACL save (EXACT_HEAD, QD-1213; §7's native ACL confirmation) when the tip moves while its base is planned:
// publish plans it again as it plans any save again, and every refusal a confirmed save owes still holds there. A
// config ref another push moved is refused, ErrConfigHeadConflict, and a signed state the save's preview stood on that
// moved is refused, ErrAclSaveStale, each a new preview needed; and a save whose push already landed keeps requiring
// that push's head, so it lands its base rather than refusing its own head. Each save is PlanAclSave's plan pinned to
// the exact ref position its head was read at, as `ur acl push` pins one once the person confirmed, on the writer
// tests' world with every reader's real ACL compile (acl_save_test.go's).

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar"
)

// A confirmed save of source on the ref as heads reads it now and on the client's state: PlanAclSave's plan, its tests
// passing, pinned to that exact position.
func (self *testAclSaveWorld) confirmedPlan(heads sidecar.ConfigHeadRef, source string) *sidecar.AclSavePlan {
	self.t.Helper()
	head, version, chain, err := heads.CurrentConfigHead(self.ctx)
	if err != nil {
		self.t.Fatal(err)
	}
	plan, err := sidecar.PlanAclSave(self.ctx, &sidecar.AclSaveInput{Policy: []byte(source), Head: head, State: self.caughtUp(self.client), Now: self.clock.Now()})
	if err != nil {
		self.t.Fatal(err)
	}
	if !plan.Tests.Passed() {
		self.t.Fatalf("tests: %v", plan.Tests.Err())
	}
	return sidecar.AclSavePlanAtRef(plan, &sidecar.ConfigHeadTip{Head: head, Version: version, Chain: chain, SupportsExactHead: true})
}

// The ACL save world with the owner's writer closed, so the writers the tests start are the only ones.
func newTestTipMovedAclWorld(t *testing.T) *testAclSaveWorld {
	world := newTestAclSaveWorld(t)
	world.ownerWriter.Close()
	return world
}

// A confirmed save whose plan meets a moved tip plans again, and when another writer's push has moved the config ref
// by then, that plan refuses it, ErrConfigHeadConflict, rather than saving on a head the person never previewed: the
// ref holds the other push alone and no base of the save landed.
func TestAConfirmedSaveWhoseHeadMovedIsRefusedWhenItPlansAgain(t *testing.T) {
	world := newTestTipMovedAclWorld(t)
	heads := world.tipMovedHeads()
	plan := world.confirmedPlan(heads, testAclSavePolicyA)
	versionBefore := world.heads.Version()
	heads.beforeRead = func(ctx context.Context, read int) {
		switch read {
		case 1:
			world.landAndApply(ctx, world.client, "late")
		case 2:
			// another writer's push of another policy lands at the ref
			other := world.heads.For(world.owner.sidecarId, world.owner.key)
			head, version, _, err := other.CurrentConfigHead(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			next, err := head.WithFile(sidecar.ConfigHeadPolicyPath, []byte(testAclSavePolicyB))
			if err != nil {
				t.Error(err)
				return
			}
			push, err := other.PrepareConfigHead(ctx, next, version)
			if err != nil {
				t.Error(err)
				return
			}
			if err := other.CommitConfigHead(ctx, push); err != nil {
				t.Error(err)
			}
		}
	}
	writer := world.tipMovedWriter(world.client, heads, nil, nil)
	if _, err := sidecar.AclSave(testTipMovedSaveContext(world.ctx), writer, plan); !errors.Is(err, sidecar.ErrConfigHeadConflict) {
		t.Fatalf("a confirmed save whose head moved: %v", err)
	}
	if reads := heads.readCount(); reads != 2 {
		t.Fatalf("the save read the head %d times", reads)
	}
	head, version := world.head()
	if version != versionBefore+1 || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(testAclSavePolicyB)) {
		t.Fatalf("the ref at %d, %d before the save, holding another policy than the other push's", version, versionBefore)
	}
	state := world.caughtUp(world.client)
	if base := state.Base(); base.GetVersion() != 1 || base.GetConfigVersion() != versionBefore || state.Member(testWriterId("late")) == nil {
		t.Fatalf("a base at %d naming %d", base.GetVersion(), base.GetConfigVersion())
	}
}

// A confirmed save whose plan meets a moved tip, the config ref unchanged, plans again, and the save's own check
// refuses it there, ErrAclSaveStale, since the signed state its plan stood on moved (AclSave): nothing is saved on a
// state the person never previewed, no head pushed and no base landed.
func TestAConfirmedSaveWhoseStateMovedWhilePlannedIsRefusedStale(t *testing.T) {
	world := newTestTipMovedAclWorld(t)
	heads := world.tipMovedHeads()
	plan := world.confirmedPlan(heads, testAclSavePolicyA)
	versionBefore := world.heads.Version()
	heads.beforeRead = func(ctx context.Context, read int) {
		if read == 1 {
			world.landAndApply(ctx, world.client, "late")
		}
	}
	writer := world.tipMovedWriter(world.client, heads, nil, nil)
	if _, err := sidecar.AclSave(testTipMovedSaveContext(world.ctx), writer, plan); !errors.Is(err, sidecar.ErrAclSaveStale) {
		t.Fatalf("a confirmed save whose state moved: %v", err)
	}
	if reads := heads.readCount(); reads != 2 {
		t.Fatalf("the save read the head %d times", reads)
	}
	if _, version := world.head(); version != versionBefore {
		t.Fatalf("the ref at %d, %d before the save", version, versionBefore)
	}
	state := world.caughtUp(world.client)
	if base := state.Base(); base.GetVersion() != 1 || state.Member(testWriterId("late")) == nil {
		t.Fatalf("a base at %d", base.GetVersion())
	}
}

// A confirmed save whose push landed and whose base met api's 409 plans again from the newest base, its tail past
// FoldEntryCount, and meets a moved tip there. It keeps the plan whose push landed, so the head it requires is that
// push's, and lands its base naming it, the ref moved by that one push. Planning again without that plan would require
// the previewed head the push replaced and refuse the save with its head pushed and no base; before this change the
// save failed with the plan's ErrConfigTipMoved, its head left the same way.
func TestAConfirmedSaveWhosePushLandedLandsItsBaseWhenItsReplanMeetsAMovedTip(t *testing.T) {
	world := newTestTipMovedAclWorld(t)
	heads := world.tipMovedHeads()
	plan := world.confirmedPlan(heads, testAclSavePolicyA)
	versionBefore := world.heads.Version()
	heads.beforeRead = func(ctx context.Context, read int) {
		if read == 2 {
			world.landAndApply(ctx, world.client, "late plan")
		}
	}
	publisher := world.publisher()
	publishes := 0
	publisher.Before = func(ctx context.Context) {
		publishes += 1
		if publishes == 1 {
			if _, err := world.admitMember("late publish"); err != nil {
				t.Error(err)
			}
		}
	}
	writer := world.tipMovedWriter(world.client, heads, publisher, func(settings *sidecar.ConfigWriterSettings) {
		settings.FoldEntryCount = 1
	})
	pin, err := sidecar.AclSave(testTipMovedSaveContext(world.ctx), writer, plan)
	if err != nil {
		t.Fatalf("the save: %v", err)
	}
	if reads := heads.readCount(); reads != 3 || publishes != 2 {
		t.Fatalf("the save read the head %d times and published %d times", reads, publishes)
	}
	head, version := world.head()
	if version != versionBefore+1 || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(testAclSavePolicyA)) {
		t.Fatalf("the ref at %d, %d before the save, holding another policy than the save's", version, versionBefore)
	}
	state := world.caughtUp(world.client)
	base := state.Base()
	if base.GetVersion() != pin.GetVersion() || base.GetConfigVersion() != version {
		t.Fatalf("the base at %d naming %d, the save's at %d", base.GetVersion(), base.GetConfigVersion(), pin.GetVersion())
	}
	if state.Member(testWriterId("late plan")) == nil || state.Member(testWriterId("late publish")) == nil {
		t.Error("the statements that moved the tip did not land")
	}
	acl, err := state.Acl()
	if err != nil || !acl.HasDocument() {
		t.Errorf("the reader's rows: %v", err)
	}
}
