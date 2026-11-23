//go:build !sidecar_http && !js

// A config writer's publish when the tip moves while a base is planned (churn finding A, e2e-all-rerun's
// TestE2eChurnLoad): the plan reads the config head between taking the client's state and its fold under the follow
// lock, and an entry the client applied meanwhile made the plan answer ErrConfigTipMoved, which publish returned, so a
// save failed where api's 409 for the same race is caught up and re-signed. A save that meets it now lands on the new
// tip, a tip that keeps moving gives up past PublishAttemptCount attempts with ErrConfigTipMoved, and both kinds of
// moved tip spend that one bound. The race is forced at the read itself: the writer's ref runs a hook before each read
// its save makes, which lands a statement at api and waits for the client to apply it. On T2's fake api and the
// in-memory config ref, every base checked by the client as a full reader.

package sidecar_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Marks a save's context, so only the save's own reads of the current head meet testTipMovedHeads' hook and its
// writer's fold loop reads pass by.
type testTipMovedSaveKey struct{}

// ctx as a save's.
func testTipMovedSaveContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, testTipMovedSaveKey{}, true)
}

// One device's ref to the config repo whose reads of the current head, a save's alone, run a hook first: what lands
// at api or at the ref while a base is planned, which the plan then reads. Safe for concurrent use.
type testTipMovedHeads struct {
	*sidecartest.FakeConfigHeadRef

	stateLock sync.Mutex
	// the save's reads so far
	reads int
	// runs before the save's read numbered read, from 1; nil runs none
	beforeRead func(ctx context.Context, read int)
}

func (self *testTipMovedHeads) CurrentConfigHead(ctx context.Context) (*sidecar.ConfigHead, uint64, [sha256.Size]byte, error) {
	if ctx.Value(testTipMovedSaveKey{}) != nil {
		read, beforeRead := func() (int, func(context.Context, int)) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.reads += 1
			return self.reads, self.beforeRead
		}()
		if beforeRead != nil {
			beforeRead(ctx, read)
		}
	}
	return self.FakeConfigHeadRef.CurrentConfigHead(ctx)
}

// The save's reads so far.
func (self *testTipMovedHeads) readCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.reads
}

// The owner's ref, its hook unset.
func (self *testWriterWorld) tipMovedHeads() *testTipMovedHeads {
	return &testTipMovedHeads{FakeConfigHeadRef: self.heads.For(self.owner.sidecarId, self.owner.key)}
}

// A writer of the owner's over client, saving through heads and publishing through publisher (the world's when nil),
// its settings as configure leaves them. Its fold loop runs on the world's clock, which no test here advances, and a
// fold it finds due waits half of FoldDelayMax, so the loop publishes no base of its own.
func (self *testWriterWorld) tipMovedWriter(client *sidecar.ConfigClient, heads sidecar.ConfigHeadRef, publisher sidecar.ConfigBasePublisher, configure func(settings *sidecar.ConfigWriterSettings)) *sidecar.ConfigWriter {
	self.t.Helper()
	settings := sidecar.DefaultConfigWriterSettings()
	settings.Clock = self.clock
	settings.Random = func() float64 { return 0.5 }
	settings.Log = sidecar.NewNoopLogger()
	if configure != nil {
		configure(settings)
	}
	if publisher == nil {
		publisher = self.publisher()
	}
	writer, err := sidecar.NewConfigWriter(self.ctx, &sidecar.ConfigWriterArgs{
		SidecarId: self.owner.sidecarId,
		Sign:      self.owner.sign(),
		Client:    client,
		Heads:     heads,
		Publisher: publisher,
		Settings:  settings,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(writer.Close)
	return writer
}

// A member admitted at api, which client then applies: an entry landing while a base is planned. Answers its pin, nil
// where it did not land, which the test is failed for. Runs inside a save, so it fails the test without stopping it.
func (self *testWriterWorld) landAndApply(ctx context.Context, client *sidecar.ConfigClient, label string) *bridge.AuthPin {
	pin, err := self.admitMember(label)
	if err != nil {
		self.t.Errorf("admitting %s: %v", label, err)
		return nil
	}
	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := client.WaitFor(waitCtx, pin.GetVersion()); err != nil {
		self.t.Errorf("applying %s at %d: %v", label, pin.GetVersion(), err)
		return nil
	}
	return pin
}

// The policy file a writer test's save writes.
var testTipMovedPolicy = []byte("{\"grants\": []}")

// A save's edit, counting each time it is made.
func testTipMovedEdit(edits *int) func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
	return func(head *sidecar.ConfigHead) (*sidecar.ConfigHead, error) {
		*edits += 1
		return head.WithFile(sidecar.ConfigHeadPolicyPath, testTipMovedPolicy)
	}
}

// Churn finding A: a member admitted at api, which the writer's client applies while the save's plan reads the config
// head, moves the tip under the plan. The save catches up and plans again, as after api's 409: the edit, which the
// first plan stopped before, is made once on the head read again, one head is pushed, and the base lands at the new
// tip, past the member, naming that head. Before this change the save failed with the plan's ErrConfigTipMoved.
func TestAStatementLandingWhileASaveIsPlannedLandsTheSaveOnTheNewTip(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	heads := world.tipMovedHeads()
	var late *bridge.AuthPin
	heads.beforeRead = func(ctx context.Context, read int) {
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
		t.Fatal("no statement landed while the save was planned")
	}
	if reads := heads.readCount(); reads != 2 || edits != 1 {
		t.Fatalf("the save read the head %d times and made its edit %d times", reads, edits)
	}
	if pin.GetVersion() != late.GetVersion()+1 {
		t.Fatalf("the base landed at %d, the statement at %d", pin.GetVersion(), late.GetVersion())
	}
	state := world.caughtUp(client)
	base := state.Base()
	if base.GetVersion() != pin.GetVersion() || state.Member(testWriterId("late")) == nil {
		t.Fatalf("the client's base is at %d, the member admitted: %v", base.GetVersion(), state.Member(testWriterId("late")) != nil)
	}
	if version := world.heads.Version(); version != versionBefore+1 || base.GetConfigVersion() != version {
		t.Fatalf("the ref at %d, %d before the save, the base naming %d", version, versionBefore, base.GetConfigVersion())
	}
	head, err := world.heads.ReadConfigHead(world.ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), testTipMovedPolicy) {
		t.Error("the base's head lacks the save's policy")
	}
}

// A save whose tip moves while each of its plans reads the config head gives up once PublishAttemptCount plans have
// met a moved tip, with ErrConfigTipMoved under ErrConfigWriterGaveUp, as one whose base meets api's 409 that often
// does. It planned that many times and no more, and since each plan stopped before its edit, it made no edit, pushed
// no head and landed no base; the statements that moved it all landed.
func TestASaveWhoseTipKeepsMovingWhilePlannedGivesUpWithTipMoved(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	heads := world.tipMovedHeads()
	heads.beforeRead = func(ctx context.Context, read int) {
		world.landAndApply(ctx, client, fmt.Sprintf("late %d", read))
	}
	writer := world.tipMovedWriter(client, heads, nil, func(settings *sidecar.ConfigWriterSettings) {
		settings.PublishAttemptCount = 3
	})
	versionBefore := world.heads.Version()
	edits := 0
	_, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	if !errors.Is(err, sidecar.ErrConfigTipMoved) || !errors.Is(err, sidecar.ErrConfigWriterGaveUp) {
		t.Fatalf("a save whose tip kept moving: %v", err)
	}
	if reads := heads.readCount(); reads != 3 || edits != 0 {
		t.Fatalf("the save read the head %d times and made its edit %d times", reads, edits)
	}
	if version := world.heads.Version(); version != versionBefore {
		t.Fatalf("the ref at %d, %d before the save", version, versionBefore)
	}
	state := world.caughtUp(client)
	if base := state.Base(); base.GetVersion() != 1 || base.GetConfigVersion() != versionBefore {
		t.Fatalf("a base at %d naming %d", base.GetVersion(), base.GetConfigVersion())
	}
	for read := 1; read <= 3; read += 1 {
		if state.Member(testWriterId(fmt.Sprintf("late %d", read))) == nil {
			t.Errorf("the statement before read %d did not land", read)
		}
	}
}

// The two ways a tip moves spend one bound: a save whose first plan meets a moved tip and whose base meets api's 409
// at each of its next two attempts gives up after the three PublishAttemptCount allows, with ErrConfigTipMoved. Its
// second plan made the edit and pushed its head, which waits for a base as any pending head does, and its third kept
// that plan, reading no head.
func TestATipMovingWhilePlannedAndAtApiSpendsOneBound(t *testing.T) {
	world := newTestWriterWorld(t)
	world.started()
	client := world.client()
	world.caughtUp(client)
	heads := world.tipMovedHeads()
	heads.beforeRead = func(ctx context.Context, read int) {
		if read == 1 {
			world.landAndApply(ctx, client, "late plan")
		}
	}
	publisher := world.publisher()
	publishes := 0
	publisher.Before = func(ctx context.Context) {
		publishes += 1
		if _, err := world.admitMember(fmt.Sprintf("late publish %d", publishes)); err != nil {
			t.Error(err)
		}
	}
	writer := world.tipMovedWriter(client, heads, publisher, func(settings *sidecar.ConfigWriterSettings) {
		settings.PublishAttemptCount = 3
	})
	versionBefore := world.heads.Version()
	edits := 0
	_, err := writer.SaveHead(testTipMovedSaveContext(world.ctx), testTipMovedEdit(&edits))
	if !errors.Is(err, sidecar.ErrConfigTipMoved) || !errors.Is(err, sidecar.ErrConfigWriterGaveUp) {
		t.Fatalf("a save whose tip kept moving: %v", err)
	}
	if reads := heads.readCount(); reads != 2 || publishes != 2 || edits != 1 {
		t.Fatalf("the save read the head %d times, published %d times and made its edit %d times", reads, publishes, edits)
	}
	if version := world.heads.Version(); version != versionBefore+1 {
		t.Fatalf("the ref at %d, %d before the save", version, versionBefore)
	}
	if base := world.caughtUp(client).Base(); base.GetVersion() != 1 || base.GetConfigVersion() != versionBefore {
		t.Fatalf("a base at %d naming %d", base.GetVersion(), base.GetConfigVersion())
	}
}
