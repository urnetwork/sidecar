package sidecartest

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The suite RECORD-M3-12's binding passes on T2, here on the fake.
func TestFakeRecordStreamsConforms(t *testing.T) {
	world := NewFakeRecordStreams(nil, nil, nil)
	RunRecordStreamsSuite(t, world)
	if violations := world.Violations(); len(violations) != 0 {
		t.Errorf("the suite broke rules: %v", violations)
	}
}

// A push held at its commit's barrier has not moved its stream, and moves it once released, with .after passed.
func TestFakeRecordStreamsHoldsAPushAtItsCommit(t *testing.T) {
	driver, table := newBarrierFixture(t, nil)
	world := NewFakeRecordStreams(nil, driver, nil)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	readerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	if err := world.Grant(repoId, readerId, RecordStreamsScope{Read: true}); err != nil {
		t.Fatal(err)
	}
	site := BarrierSite("record_streams.append.before", hex.EncodeToString(repoId[:]))
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	run := driver.Start(table.Actor(t.Context(), "writer"), func() error {
		_, err := world.For(writerId).Append(context.Background(), repoId, recordStreamsSuitePush(writerId, "e/0/0/1"))
		return err
	})
	if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
		t.Fatal(err)
	}
	if version, err := recordStreamVersion(t.Context(), world.For(readerId), repoId, writerId); err != nil || version != 0 {
		t.Fatalf("a held push moved the stream to %d: %v", version, err)
	}
	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	awaitEnded(t, run)
	if run.Err() != nil {
		t.Fatal(run.Err())
	}
	if version, err := recordStreamVersion(t.Context(), world.For(readerId), repoId, writerId); err != nil || version != 1 {
		t.Fatalf("the released push left the stream at %d: %v", version, err)
	}
	passedAfter := slices.ContainsFunc(driver.Trace(), func(event *BarrierEvent) bool {
		return event.Name == "record_streams.append.after" && event.Key == hex.EncodeToString(repoId[:])
	})
	if !passedAfter {
		t.Error("the push did not pass record_streams.append.after")
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("barrier names broke the rule: %v", violations)
	}
}

// A push naming a slot another push holds is something evs answers with no code of its own: unavailable, and a
// violation for the test to see.
func TestFakeRecordStreamsReportsAReusedSlotId(t *testing.T) {
	reported := []string{}
	settings := DefaultFakeRecordStreamsSettings()
	settings.Report = func(violation string) { reported = append(reported, violation) }
	world := NewFakeRecordStreams(nil, nil, settings)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(writerId)
	first := recordStreamsSuitePush(writerId, "e/0/0/1")
	if _, err := streams.Append(t.Context(), repoId, first); err != nil {
		t.Fatal(err)
	}
	second := recordStreamsSuitePush(writerId, "e/0/0/2")
	second.SlotId = first.SlotId
	if err := wantRecordStreamRefusal("a reused slot", errOf(streams.Append(t.Context(), repoId, second)), protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE); err != nil {
		t.Error(err)
	}
	if len(reported) != 1 || len(world.Violations()) != 1 {
		t.Errorf("reported %v", reported)
	}
}

// What a caller gets back is its own: changing it changes nothing a later read returns.
func TestFakeRecordStreamsSharesNothing(t *testing.T) {
	world := NewFakeRecordStreams(nil, nil, nil)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	writerId := sidecar.NewId()
	if err := world.Grant(repoId, writerId, RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams := world.For(writerId)
	push := recordStreamsSuitePush(writerId, "e/0/0/1")
	if _, err := streams.Append(t.Context(), repoId, push); err != nil {
		t.Fatal(err)
	}
	push.Entries[0].Entry[0] ^= 0xff
	push.SlotRows[0].Row[0] ^= 0xff
	versions, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	versions[0].Entries[0].Entry[1] ^= 0xff
	again, err := streams.ReadStream(t.Context(), repoId, writerId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again[0].Entries[0].Entry, []byte("entry e/0/0/1")) {
		t.Error("a caller's change reached the fake's entry")
	}
	slot, err := streams.ReadSlot(t.Context(), repoId, push.SlotId)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(slot.Rows[0].Row, bytes.Repeat([]byte{0x01}, 64)) {
		t.Error("a caller's change reached the fake's slot")
	}
}

// A fixture state for the auth view's tests.
func testRecordAuthFixture(writerId sidecar.Id, repoId sidecar.Id) *FakeRecordAuthFixture {
	memberId := sidecar.NewId()
	return &FakeRecordAuthFixture{
		IdentityKeys:     map[sidecar.Id][]byte{writerId: bytes.Repeat([]byte{0x0e}, 32)},
		Members:          map[sidecar.Id]sidecar.Id{writerId: memberId},
		Repos:            map[sidecar.Id]*FakeRecordRepoAuth{repoId: {Readers: []sidecar.Id{writerId}, Writers: []sidecar.Id{writerId}, Consented: []sidecar.Id{writerId}}},
		CompromisedSince: map[sidecar.Id]uint64{},
		Vaults:           map[sidecar.Id]sidecar.Id{memberId: repoId},
	}
}

// A verdict at a past pin comes from that pin's state; a pin ahead, not retained or off the chain is refused, and an
// appended state never changes.
func TestFakeRecordAuthJudgesAtAPin(t *testing.T) {
	auth := NewFakeRecordAuth()
	writerId := sidecar.NewId()
	repoId := sidecar.NewId()
	fixture := testRecordAuthFixture(writerId, repoId)
	first := auth.Append(fixture)
	// the writer is removed at position 2, and a compromise revocation voids it from position 2
	removed := testRecordAuthFixture(writerId, repoId)
	removed.Repos[repoId].Writers = nil
	removed.CompromisedSince[writerId] = 2
	auth.Append(removed)
	tip := auth.Append(removed)
	if tip.Pin().GetVersion() != 3 || auth.Tip().Pin().GetVersion() != 3 {
		t.Fatalf("the tip is at %d", tip.Pin().GetVersion())
	}
	if tip.Writes(repoId, writerId) {
		t.Error("a removed writer writes at the tip")
	}
	if since, ok := tip.CompromisedSince(writerId); !ok || since != 2 {
		t.Errorf("the compromise reads %d, %v", since, ok)
	}
	atFirst, err := tip.At(first.Pin())
	if err != nil {
		t.Fatal(err)
	}
	if !atFirst.Writes(repoId, writerId) || !atFirst.Consented(repoId, writerId) || !atFirst.Reads(repoId, writerId) {
		t.Error("the writer's right at its own pin is gone")
	}
	if !bytes.Equal(atFirst.IdentityKey(writerId), bytes.Repeat([]byte{0x0e}, 32)) {
		t.Error("the identity key at the first pin")
	}
	if vaultId, ok := atFirst.Vault(fixture.Members[writerId]); !ok || vaultId != repoId {
		t.Error("the member's vault")
	}

	// A fixture changed after Append changes no state.
	fixture.Repos[repoId].Writers = nil
	fixture.IdentityKeys[writerId][0] ^= 0xff
	if !first.Writes(repoId, writerId) || first.IdentityKey(writerId)[0] != 0x0e {
		t.Error("an appended state changed with its fixture")
	}

	if _, err := first.At(tip.Pin()); !errors.Is(err, sidecar.ErrRecordAuthAhead) {
		t.Errorf("a pin above the state: %v", err)
	}
	offChain := first.Pin()
	offChain.Chain[0] ^= 0xff
	if _, err := tip.At(offChain); !errors.Is(err, sidecar.ErrRecordAuthOffChain) {
		t.Errorf("a pin off the chain: %v", err)
	}
	auth.RetainFrom(2)
	if _, err := tip.At(first.Pin()); !errors.Is(err, sidecar.ErrRecordAuthNotRetained) {
		t.Errorf("a pin no longer retained: %v", err)
	}
	if _, err := tip.At(&bridge.AuthPin{Version: 0}); !errors.Is(err, sidecar.ErrRecordAuthNotRetained) {
		t.Errorf("pin 0: %v", err)
	}
	if logs := tip.Logs(); logs == nil || logs.Team || logs.TeamRecordId != nil {
		t.Errorf("a fixture with no logs reads %+v", logs)
	}
}

// A run with no readable file is tainted, a run's taint never clears, and a lost file reads tainted (D-MCP-16).
func TestFakeRunViewFailsClosed(t *testing.T) {
	runs := NewFakeRunView()
	runId := sidecar.NewId()
	if !runs.RunTainted(runId) {
		t.Error("a run with no file reads untainted")
	}
	runs.StartRun(runId)
	if runs.RunTainted(runId) {
		t.Error("a started run reads tainted")
	}
	runs.Taint(runId)
	runs.StartRun(runId)
	if !runs.RunTainted(runId) {
		t.Error("a run's taint cleared")
	}
	otherId := sidecar.NewId()
	runs.StartRun(otherId)
	runs.LoseRun(otherId)
	if !runs.RunTainted(otherId) {
		t.Error("a run that lost its file reads untainted")
	}
}

// Each seam's unbound value refuses or answers the closed way, so nothing built on it reads as written, admitted or
// untainted.
func TestRecordSeamsFailClosedUnbound(t *testing.T) {
	ctx := t.Context()
	streams := sidecar.RecordStreamsUnavailable{}
	repoId := sidecar.NewId()
	errs := []error{
		errOf(streams.Append(ctx, repoId, recordStreamsSuitePush(repoId, "e/0/0/1"))),
		errOf(streams.Streams(ctx, repoId)),
		errOf(streams.ReadStream(ctx, repoId, repoId, 0)),
		errOf(streams.ReadSlot(ctx, repoId, repoId)),
		errOf(streams.Deposit(ctx, repoId, recordStreamsSuiteDeposit(repoId, 1))),
		errOf(streams.DepositRefs(ctx, repoId)),
		errOf(streams.ReadDeposits(ctx, repoId, repoId)),
		errOf(streams.Consume(ctx, repoId, &sidecar.RecordStreamConsume{})),
		errOf(streams.Erase(ctx, repoId, &sidecar.RecordStreamErase{})),
		errOf(streams.ReadErasures(ctx, repoId, 0)),
	}
	for i, err := range errs {
		if !errors.Is(err, sidecar.ErrRecordStreamsUnavailable) {
			t.Errorf("call %d: %v", i, err)
		}
		if _, ok := sidecar.RecordStreamRefusalCode(err); ok {
			t.Errorf("call %d reads as an evs refusal", i)
		}
	}
	streams.Subscribe(repoId, func(sidecar.Id) { t.Error("an unbound subscription fired") })()

	auth := sidecar.RecordAuthUnavailable{}
	sidecarId := sidecar.NewId()
	if auth.Pin() != nil || auth.IdentityKey(sidecarId) != nil || auth.Reads(repoId, sidecarId) ||
		auth.Writes(repoId, sidecarId) || auth.Deposits(repoId, sidecarId) || auth.Consented(repoId, sidecarId) ||
		!auth.ReceiptOnly(repoId, sidecarId) {
		t.Error("the unbound auth view grants something")
	}
	if _, ok := auth.Member(sidecarId); ok {
		t.Error("the unbound auth view names a member")
	}
	if _, ok := auth.Sponsor(sidecarId); ok {
		t.Error("the unbound auth view names a sponsor")
	}
	if _, ok := auth.Vault(sidecarId); ok {
		t.Error("the unbound auth view names a vault")
	}
	if since, ok := auth.CompromisedSince(sidecarId); !ok || since != 0 {
		t.Error("the unbound auth view lets a filing stand")
	}
	if _, err := auth.At(&bridge.AuthPin{Version: 1}); !errors.Is(err, sidecar.ErrRecordAuthAhead) {
		t.Errorf("the unbound auth view judges at a pin: %v", err)
	}
	if !(sidecar.RecordRunViewMissing{}).RunTainted(sidecar.NewId()) {
		t.Error("the missing run view reads a run untainted")
	}
}

// A refusal names its code and status, and reads back through RecordStreamRefusalCode however it is wrapped.
func TestRecordStreamRefusalReadsBack(t *testing.T) {
	refusal := &sidecar.RecordStreamRefusal{Code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE, Recorded: true}
	if refusal.Error() != "record stream refused: 409 EVS_REFUSAL_NOTHING_TO_ERASE" {
		t.Errorf("the refusal reads %q", refusal.Error())
	}
	wrapped := errors.Join(errors.New("the push"), refusal)
	if code, ok := sidecar.RecordStreamRefusalCode(wrapped); !ok || code != refusal.Code {
		t.Errorf("a wrapped refusal reads %v, %v", code, ok)
	}
	if _, ok := sidecar.RecordStreamRefusalCode(errors.New("unreachable")); ok {
		t.Error("an error that is no refusal reads as one")
	}
}
