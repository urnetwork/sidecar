// QD-1193 on the fixture network: a personal network's owner adds a second device after base 1, and the second device
// saves an ACL document as base 3, a base that keeps base 1's fold, so its rows, like base 1's, do not name its signer.
// Between states the save waits for a compile and the denials after it apply under the rows held; the compile's state
// takes it, whether the posture followed it or re-anchors on it, its identities naming the signer; and a restart
// verifies it under the key the manifest kept. A base by a sidecar no state names stays refused under every state, one
// by a sidecar the rows name that is no config writer stays refused between states, and a state past a base the
// posture followed needs that base's run. Before QD-1193 the save was refused, as a delta and under every state, so
// the posture kept base 1's rules.

package device

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The fixture network with its owner's second device, admitted at 2, after base 1 by the owner's phone.
type postureLaterWriterFixture struct {
	*postureFixture
	// the owner's second device, a config writer from its admission, which base 1's rows do not name
	second *postureFixtureSidecar
	// rows at base 1's fold, without the second device, holding the document the second device's save adds
	foldDocumentRows []byte
}

// Base 1 with no document, folding through 0, then the second device's admission at 2; rows the fixture writes from
// then on name the second device.
func newPostureLaterWriterFixture(t *testing.T) *postureLaterWriterFixture {
	fixture := newPostureFixture(t)
	foldDocumentRows := fixture.rows(true)
	fixture.base(fixture.ownerPhone, false)
	second := &postureFixtureSidecar{id: postureFixtureId(0x16), key: postureFixtureKey(0x16), member: fixture.owner}
	fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_SIDECAR_ADMIT)
	fixture.sidecars = append(fixture.sidecars, second)
	return &postureLaterWriterFixture{postureFixture: fixture, second: second, foldDocumentRows: foldDocumentRows}
}

// A base at the next position over rows, keeping foldedThrough and naming configHead, signed by signer.
func (self *postureLaterWriterFixture) baseOver(signer *postureFixtureSidecar, rows []byte, foldedThrough uint64, configHead []byte) uint64 {
	rowsSha256 := sha256.Sum256(rows)
	self.rowsBySha256[rowsSha256] = rows
	n := self.tip() + 1
	prev := self.chain(n - 1)
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.ProjectionHeader{
		NetworkId: self.networkId, Version: n, PrevChain: prev[:], FoldedThrough: foldedThrough, ConfigVersion: n,
		ConfigHeadSha256: configHead, RowsSha256: rowsSha256[:], RowsByteCount: uint32(len(rows)), Threshold: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.append(bridge.AuthEntryKindBase, self.sign(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
	return n
}

// An ACL document's save by signer at the next position, as a writer publishes a save that does not fold: a base over
// base 1's fold with the document, of a new config head.
func (self *postureLaterWriterFixture) save(signer *postureFixtureSidecar) uint64 {
	return self.baseOver(signer, self.foldDocumentRows, 0, postureFixtureId(0x42))
}

// A state at n whose identities name sidecars under their keys, as a compile's name the subjects its rules let reach
// this host.
func (self *postureLaterWriterFixture) stateNaming(n uint64, hasDocument bool, sidecars ...*postureFixtureSidecar) *bridge.BridgeState {
	state := self.state(n, hasDocument)
	for _, sidecar := range sidecars {
		state.Identities = append(state.Identities, &bridge.BridgeIdentity{
			SidecarId: sidecar.id, IdentityPublicKey: sidecar.publicKey(), AdmittedAt: 2,
		})
	}
	return state
}

// A posture on store, enforcing with no document on base 1's state at 2.
func (self *postureLaterWriterFixture) enforcingAt2(store PostureStore, settings *PostureSettings) *Posture {
	self.t.Helper()
	posture, _ := NewPosture(store, settings)
	if _, err := posture.SetPending(self.pending()); err != nil {
		self.t.Fatal(err)
	}
	decision, err := posture.SetState(self.state(2, false), self.log(1, 2))
	if err != nil || decision.State != PostureEnforcingNoDocument {
		self.t.Fatalf("enforcing at 2: %v, %v", err, decision.State)
	}
	return posture
}

// The second device's save waits between states, a revocation after it applying under base 1's rows, and a restart
// keeps it waiting; the compile's state, its run from the save and its identities naming the second device, takes it,
// and a restart verifies it under the key the manifest kept, which a base its own rows' writer signed never needs.
func TestALaterWritersBaseWaitsAndTheCompileTakesIt(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	store := newMemoryPostureStore()
	settings := testPostureSettings()
	posture := fixture.enforcingAt2(store, settings)
	if manifest, err := decodePostureManifest(store.record(postureManifestName)); err != nil || manifest.baseSignerPublicKey != nil {
		t.Fatalf("base 1's manifest keeps a signer key: %v", err)
	}
	saved := fixture.save(fixture.second)
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)

	decision, err := posture.ApplyDeltas(fixture.log(saved, revoke))
	if err != nil || postureAlarmed(decision, PostureAlarmBaseRefused) || decision.Pin.GetVersion() != revoke {
		t.Fatalf("the save between states: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	if !postureWaits(decision, saved) || !decision.CompileWanted {
		t.Errorf("the save does not wait for a compile: %v, %v", decision.Waiting, decision.CompileWanted)
	}
	// base 1's state stays in force: the save's document neither opens nor narrows before the compile
	if decision.State != PostureEnforcingNoDocument || decision.BridgeState.GetAuth().GetVersion() != 2 {
		t.Errorf("in force: %v at %d", decision.State, decision.BridgeState.GetAuth().GetVersion())
	}
	if !slices.ContainsFunc(decision.Overlay, func(entry PostureOverlayEntry) bool {
		return entry.Kind == PostureOverlaySidecarRevoke && entry.N == revoke && bytes.Equal(entry.Id, fixture.aliceLaptop.id)
	}) {
		t.Errorf("the revocation after the save is not applied: %+v", decision.Overlay)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) || !postureWaits(restored, saved) {
		t.Errorf("restored with the save waiting: %v, %v, %v", postureDecisionSays(restored), restored.Waiting, restored.Alarms)
	}

	decision, err = posture.SetState(fixture.stateNaming(revoke, true, fixture.second), fixture.log(saved, revoke))
	if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != revoke {
		t.Fatalf("the compile's state on the save: %v, %v, %v, %v", err, decision.State, decision.Pin, decision.Alarms)
	}
	if posture.held.base.entry.GetN() != saved || len(decision.Waiting) != 0 || len(decision.Overlay) != 0 {
		t.Errorf("after the state: base %d, waiting %v, overlay %v", posture.held.base.entry.GetN(), decision.Waiting, decision.Overlay)
	}
	manifest, err := decodePostureManifest(store.record(postureManifestName))
	if err != nil || !bytes.Equal(manifest.baseSignerPublicKey, fixture.second.publicKey()) {
		t.Fatalf("the manifest keeps no signer key for the save: %v", err)
	}
	_, restored = NewPosture(store.survivor(), settings)
	if len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored on the save: %v, %v", postureDecisionSays(restored), restored.Alarms)
	}

	// a later state on the save stands on the base held, its identities naming the second device or not
	tick := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(tick, tick)); err != nil {
		t.Fatal(err)
	}
	decision, err = posture.SetState(fixture.state(tick, true), fixture.log(saved, tick))
	if err != nil || decision.BridgeState.GetAuth().GetVersion() != tick || decision.State != PostureEnforcingDocument {
		t.Errorf("a later state on the save: %v, %v, %v", err, decision.State, decision.Alarms)
	}
}

// A state whose run holds the save takes it each way a run can hold it: from pending, as a new device's or a compile's
// after a reset; from enforcing at 2, its run chaining from the pin, the posture that followed the log; and from
// enforcing at 1, its log neither chaining from the pin nor reaching it, a re-anchor. Each restarts without an alarm.
func TestAStateWhoseRunHoldsALaterWritersBaseTakesIt(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	saved := fixture.save(fixture.second)
	tick := fixture.tick()
	settings := testPostureSettings()
	cases := []struct {
		name string
		// a posture on store before the state
		open func(store PostureStore) *Posture
	}{
		{
			name: "from pending",
			open: func(store PostureStore) *Posture {
				posture, _ := NewPosture(store, settings)
				if _, err := posture.SetPending(fixture.pending()); err != nil {
					t.Fatal(err)
				}
				return posture
			},
		},
		{
			name: "from enforcing at 2",
			open: func(store PostureStore) *Posture {
				return fixture.enforcingAt2(store, settings)
			},
		},
		{
			name: "from enforcing at 1",
			open: func(store PostureStore) *Posture {
				posture, _ := NewPosture(store, settings)
				if _, err := posture.SetPending(fixture.pending()); err != nil {
					t.Fatal(err)
				}
				if _, err := posture.SetState(fixture.state(1, false), fixture.log(1, 1)); err != nil {
					t.Fatal(err)
				}
				return posture
			},
		},
	}
	for _, c := range cases {
		store := newMemoryPostureStore()
		posture := c.open(store)
		decision, err := posture.SetState(fixture.stateNaming(tick, true, fixture.second), fixture.log(saved, tick))
		if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != tick || posture.held.base.entry.GetN() != saved {
			t.Errorf("%s: %v, %v, %v, %v", c.name, err, decision.State, decision.Pin, decision.Alarms)
			continue
		}
		if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
			t.Errorf("%s: restored %v, %v", c.name, postureDecisionSays(restored), restored.Alarms)
		}
	}
}

// A base by the second device that folds through its admission names it in its own rows, which a state lets vouch for
// its key though the state's identities do not name it; between states those rows are its own word, so it waits.
func TestAStateTakesALaterWritersFoldingBaseByItsOwnRows(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	folded := fixture.baseOver(fixture.second, fixture.rows(true), 2, postureFixtureId(0x42))
	settings := testPostureSettings()

	store := newMemoryPostureStore()
	posture := fixture.enforcingAt2(store, settings)
	decision, err := posture.ApplyDeltas(fixture.log(folded, folded))
	if err != nil || !postureWaits(decision, folded) || posture.held.base.entry.GetN() != 1 {
		t.Fatalf("the folding base between states: %v, %v, %v", err, decision.Waiting, decision.Alarms)
	}

	store = newMemoryPostureStore()
	posture = fixture.enforcingAt2(store, settings)
	decision, err = posture.SetState(fixture.state(folded, true), fixture.log(folded, folded))
	if err != nil || decision.State != PostureEnforcingDocument || posture.held.base.entry.GetN() != folded {
		t.Fatalf("a state on the folding base: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	if manifest, err := decodePostureManifest(store.record(postureManifestName)); err != nil || manifest.baseSignerPublicKey != nil {
		t.Errorf("a base its own rows' writer signed keeps a signer key: %v", err)
	}
	if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || restored.State != PostureEnforcingDocument {
		t.Errorf("restored %v, %v", restored.State, restored.Alarms)
	}
}

// A base by a sidecar no state names waits between states like the save, since the posture cannot tell the two apart;
// a state on it whose identities do not name its signer, or name it under another key, is refused, the state in force
// standing and the base still waiting, and so is a re-anchor on it from pending. A base by alice's laptop, which the
// rows held name and not as a config writer, is refused between states as before.
func TestABaseBySidecarNoStateNamesIsRefused(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	stranger := &postureFixtureSidecar{id: postureFixtureId(0x7b), key: postureFixtureKey(0x7b), member: fixture.owner}
	store := newMemoryPostureStore()
	settings := testPostureSettings()
	posture := fixture.enforcingAt2(store, settings)
	forged := fixture.save(stranger)
	decision, err := posture.ApplyDeltas(fixture.log(forged, forged))
	if err != nil || !postureWaits(decision, forged) || postureAlarmed(decision, PostureAlarmBaseRefused) {
		t.Fatalf("the stranger's base between states: %v, %v, %v", err, decision.Waiting, decision.Alarms)
	}
	impostor := fixture.state(forged, true)
	impostor.Identities = []*bridge.BridgeIdentity{{SidecarId: stranger.id, IdentityPublicKey: fixture.second.publicKey()}}
	for _, state := range []*bridge.BridgeState{fixture.stateNaming(forged, true, fixture.second), impostor} {
		decision, err = posture.SetState(state, fixture.log(forged, forged))
		if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.State != PostureEnforcingNoDocument ||
			decision.BridgeState.GetAuth().GetVersion() != 2 || !postureWaits(decision, forged) {
			t.Errorf("a state on the stranger's base: %v, %v, %v, %v", err, decision.State, decision.Waiting, decision.Alarms)
		}
	}
	if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}

	fresh, _ := NewPosture(newMemoryPostureStore(), settings)
	if _, err := fresh.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	decision, err = fresh.SetState(fixture.stateNaming(forged, true, fixture.second), fixture.log(forged, forged))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.State != PosturePending {
		t.Errorf("a re-anchor on the stranger's base: %v, %v, %v", err, decision.State, decision.Alarms)
	}

	other := newPostureLaterWriterFixture(t)
	posture = other.enforcingAt2(newMemoryPostureStore(), settings)
	byMember := other.save(other.aliceLaptop)
	decision, err = posture.ApplyDeltas(other.log(byMember, byMember))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || postureWaits(decision, byMember) ||
		decision.Pin.GetVersion() != 2 {
		t.Errorf("a base by a member's device between states: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
}

// While the save waits, denials the rows held let the posture check still apply, each in a later follow: a
// revocation and a suspension by the owner's phone; a revocation by the second device, which those rows do not name,
// waits as a statement the posture cannot check does. The save's wait is bounded as a base of another config head's
// is: once it has waited NarrowingOverdueTimeout the posture reports it Overdue and raises narrowing_overdue for it.
func TestDenialsApplyWhileALaterWritersBaseWaits(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	clock := newPostureTestClock()
	settings := testPostureSettingsOn(clock)
	posture := fixture.enforcingAt2(newMemoryPostureStore(), settings)
	saved := fixture.save(fixture.second)
	if _, err := posture.ApplyDeltas(fixture.log(saved, saved)); err != nil {
		t.Fatal(err)
	}
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	suspend := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x84))
	bySecond := fixture.sidecarRevoke(fixture.second, fixture.aliceWorker, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	decision, err := posture.ApplyDeltas(fixture.log(revoke, bySecond))
	if err != nil || decision.Pin.GetVersion() != bySecond {
		t.Fatalf("the denials after the save: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	overlayKinds := map[uint64]PostureOverlayKind{}
	for _, entry := range decision.Overlay {
		overlayKinds[entry.N] = entry.Kind
	}
	if len(overlayKinds) != 2 || overlayKinds[revoke] != PostureOverlaySidecarRevoke || overlayKinds[suspend] != PostureOverlaySuspend {
		t.Errorf("the overlay while the save waits: %+v", decision.Overlay)
	}
	if !postureWaits(decision, saved) || !postureWaits(decision, bySecond) || !postureAlarmed(decision, PostureAlarmStatementRefused) {
		t.Errorf("what waits while the save waits: %v, %v", decision.Waiting, decision.Alarms)
	}
	if decision.State != PostureEnforcingNoDocument || decision.BridgeState.GetAuth().GetVersion() != 2 {
		t.Errorf("in force: %v at %d", decision.State, decision.BridgeState.GetAuth().GetVersion())
	}
	clock.advance(settings.NarrowingOverdueTimeout)
	decision = posture.Decision()
	if decision.Overdue == nil || decision.Overdue.N != saved || !postureAlarmed(decision, PostureAlarmCompileOverdue) ||
		decision.State != PostureEnforcingNoDocument {
		t.Errorf("the save's wait past the timeout: %+v, %v, %v", decision.Overdue, decision.Alarms, decision.State)
	}
}

// The compile's state may reach only part of what the posture followed: after the posture followed the save to 6, a
// state at 4 on the save takes it and keeps the pin and the entries after 4, a revocation past the state's pin
// applied and a tick waiting, under a floor at 6 that a re-anchor on the save would have fallen below. A restart
// restores it, and the next delta chains on.
func TestAStateBelowThePinTakesAFollowedBase(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	floor := &testPostureFloor{}
	settings := testPostureSettingsWithFloor(floor)
	store := newMemoryPostureStore()
	posture := fixture.enforcingAt2(store, settings)
	saved := fixture.save(fixture.second)
	statePinN := fixture.tick()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	tip := fixture.tick()
	if decision, err := posture.ApplyDeltas(fixture.log(saved, tip)); err != nil || decision.Pin.GetVersion() != tip {
		t.Fatalf("following the save: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	decision, err := posture.SetState(fixture.stateNaming(statePinN, true, fixture.second), fixture.log(saved, statePinN))
	if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != tip ||
		decision.BridgeState.GetAuth().GetVersion() != statePinN {
		t.Fatalf("a state at %d on the save: %v, %v, %v, %v", statePinN, err, decision.State, decision.Pin, decision.Alarms)
	}
	if held := posture.held; held.base.entry.GetN() != saved || held.entriesCount != tip-saved || held.untakenBaseN != 0 {
		t.Errorf("held: base %d, %d entries since, untaken %d", held.base.entry.GetN(), held.entriesCount, held.untakenBaseN)
	}
	if !slices.ContainsFunc(decision.Overlay, func(entry PostureOverlayEntry) bool { return entry.N == revoke }) ||
		!postureWaits(decision, tip) || postureWaits(decision, saved) {
		t.Errorf("past the state's pin: overlay %+v, waiting %v", decision.Overlay, decision.Waiting)
	}
	if want := fixture.chain(tip); floor.n != tip || !bytes.Equal(floor.chain, want[:]) {
		t.Errorf("the floor at %d", floor.n)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}
	next := fixture.tick()
	if decision, err := posture.ApplyDeltas(fixture.log(next, next)); err != nil || decision.Pin.GetVersion() != next {
		t.Errorf("the next delta: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
}

// A state at or past a base the posture followed needs the run from its newest base: one with no log, or with a log
// from base 1, is refused with base_refused, the state in force standing; a state below the save stands.
func TestAStatePastAFollowedBaseNeedsItsRun(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	settings := testPostureSettings()
	posture := fixture.enforcingAt2(newMemoryPostureStore(), settings)
	saved := fixture.save(fixture.second)
	tick := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(saved, tick)); err != nil {
		t.Fatal(err)
	}
	for _, log := range []*PostureLog{nil, fixture.log(1, tick)} {
		decision, err := posture.SetState(fixture.stateNaming(tick, true, fixture.second), log)
		if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) ||
			decision.BridgeState.GetAuth().GetVersion() != 2 || !postureWaits(decision, saved) {
			t.Errorf("a state past the save with no run from it: %v, %v, %v", err, decision.BridgeState.GetAuth(), decision.Alarms)
		}
	}
	decision, err := posture.SetState(fixture.state(2, false), nil)
	if err != nil || decision.State != PostureEnforcingNoDocument || !postureWaits(decision, saved) {
		t.Errorf("a state below the save: %v, %v, %v", err, decision.State, decision.Alarms)
	}
}

// A base by a config writer the rows held name, after the save, is taken between states as ever; the save's wait
// stays until a state passes it, and a restart restores both.
func TestAWritersBaseAfterALaterWritersBaseIsTaken(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	store := newMemoryPostureStore()
	settings := testPostureSettings()
	posture := fixture.enforcingAt2(store, settings)
	saved := fixture.save(fixture.second)
	folded := fixture.base(fixture.ownerPhone, true)
	decision, err := posture.ApplyDeltas(fixture.log(saved, folded))
	if err != nil || posture.held.base.entry.GetN() != folded || posture.held.untakenBaseN != 0 || decision.Pin.GetVersion() != folded {
		t.Fatalf("the owner's base after the save: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	if !postureWaits(decision, saved) || decision.State != PostureEnforcingDocument {
		t.Errorf("after the owner's base: %v, %v", decision.Waiting, decision.State)
	}
	if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) ||
		!postureWaits(restored, saved) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}
	decision, err = posture.SetState(fixture.state(folded, true), fixture.log(folded, folded))
	if err != nil || len(decision.Waiting) != 0 || decision.BridgeState.GetAuth().GetVersion() != folded {
		t.Errorf("a state on the owner's base: %v, %v, %v", err, decision.Waiting, decision.Alarms)
	}
}

// The save counts among the entries kept since base 1, the bound only a base the posture takes resets: past
// EntriesMaxCount it is refused as malformed, as any other entry would be.
func TestALaterWritersBaseCountsTowardTheEntriesBound(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	settings := testPostureSettings()
	settings.EntriesMaxCount = 2
	posture := fixture.enforcingAt2(newMemoryPostureStore(), settings)
	tick := fixture.tick()
	saved := fixture.save(fixture.second)
	if _, err := posture.ApplyDeltas(fixture.log(tick, tick)); err != nil {
		t.Fatal(err)
	}
	decision, err := posture.ApplyDeltas(fixture.log(saved, saved))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmMalformed) || decision.Pin.GetVersion() != tick {
		t.Errorf("the save past the bound: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
}

// The key the manifest keeps is what a restart verifies the save under: without it, with one of another length, or
// with another device's, the store does not verify and the posture restores pending.
func TestTheKeptSignerKeyVerifiesALaterWritersBaseOnRestart(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	store := newMemoryPostureStore()
	settings := testPostureSettings()
	posture, _ := NewPosture(store, settings)
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	saved := fixture.save(fixture.second)
	if _, err := posture.SetState(fixture.stateNaming(saved, true, fixture.second), fixture.log(saved, saved)); err != nil {
		t.Fatal(err)
	}
	manifest, err := decodePostureManifest(store.record(postureManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range [][]byte{nil, fixture.second.publicKey()[:31], fixture.ownerPhone.publicKey()} {
		changed := *manifest
		changed.baseSignerPublicKey = key
		survivor := store.survivor()
		survivor.setRecord(postureManifestName, changed.encode())
		_, restored := NewPosture(survivor, settings)
		if restored.State != PosturePending || !postureAlarmed(restored, PostureAlarmStoreUnverified) {
			t.Errorf("a manifest whose signer key is %x: %v, %v", key, restored.State, restored.Alarms)
		}
	}
}
