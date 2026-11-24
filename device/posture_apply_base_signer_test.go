// QD-1200 on the fixture network: a compiled state carries the key its newest base verified under at S(b-1)
// (BridgeState.base_signer_identity_public_key), and under the state the posture tries it for that base's signer past
// the rows' writers and the state's identities. So a state takes a later writer's save whose signer no rule lets reach
// this host, a save whose signer was revoked before the compile, which a new device re-anchors on, and a base by a
// writer the tail promoted; a state whose key does not verify its base is refused. As posture-later-writer-base built
// it, each such state was refused with base_refused, a new device staying pending, unless its identities named the
// signer.

package device

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A state at n saying hasDocument whose identities name sidecars, as a compile's name the subjects its rules let reach
// this host, and which says its newest base verified under baseSignerKey.
func (self *postureLaterWriterFixture) stateWithBaseSigner(n uint64, hasDocument bool, baseSignerKey []byte, sidecars ...*postureFixtureSidecar) *bridge.BridgeState {
	state := self.stateNaming(n, hasDocument, sidecars...)
	state.BaseSignerIdentityPublicKey = baseSignerKey
	return state
}

// The second device's save stands for an admin's device admitted after the last fold saving an ACL document, and the
// posture for a device no rule lets that admin's device reach: the compile's identities name alice's laptop alone.
// Followed between states, the save waits; a state on it naming no key for its signer is refused, as before; the state
// naming the key the save verified under takes it, the manifest keeping that key, and a restart verifies the save
// under it.
func TestAStateTakesALaterAdminsSaveWhoseSignerNoRuleLetsReachTheHost(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	store := newMemoryPostureStore()
	settings := testPostureSettings()
	posture := fixture.enforcingAt2(store, settings)
	saved := fixture.save(fixture.second)
	tick := fixture.tick()
	decision, err := posture.ApplyDeltas(fixture.log(saved, tick))
	if err != nil || !postureWaits(decision, saved) || decision.Pin.GetVersion() != tick {
		t.Fatalf("the save between states: %v, %v, %v", err, decision.Waiting, decision.Alarms)
	}

	decision, err = posture.SetState(fixture.stateNaming(tick, true, fixture.aliceLaptop), fixture.log(saved, tick))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) ||
		decision.BridgeState.GetAuth().GetVersion() != 2 || !postureWaits(decision, saved) {
		t.Fatalf("a state naming no key for the save's signer: %v, %v, %v", err, decision.BridgeState.GetAuth(), decision.Alarms)
	}

	decision, err = posture.SetState(fixture.stateWithBaseSigner(tick, true, fixture.second.publicKey(), fixture.aliceLaptop), fixture.log(saved, tick))
	if err != nil || decision.State != PostureEnforcingDocument || decision.BridgeState.GetAuth().GetVersion() != tick || decision.Pin.GetVersion() != tick {
		t.Fatalf("the state naming the save's key: %v, %v, %v, %v", err, decision.State, decision.Pin, decision.Alarms)
	}
	if posture.held.base.entry.GetN() != saved || len(decision.Waiting) != 0 || posture.held.untakenBaseN != 0 {
		t.Errorf("after the state: base %d, waiting %v, untaken %d", posture.held.base.entry.GetN(), decision.Waiting, posture.held.untakenBaseN)
	}
	manifest, err := decodePostureManifest(store.record(postureManifestName))
	if err != nil || !bytes.Equal(manifest.baseSignerPublicKey, fixture.second.publicKey()) {
		t.Fatalf("the manifest keeps no signer key for the save: %v", err)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}
}

// A personal network's second device saves an ACL document, then is lost and revoked before the next compile, so no
// state names it among its identities. A new device, pending, re-anchors on the save under the state that names the
// key the save verified under, and restarts on it; under a state naming none it stays pending, as before. The
// owner's phone's revocation after it then applies between states under the save's rows.
func TestANewDeviceReanchorsOnASaveWhoseSignerWasRevoked(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	saved := fixture.save(fixture.second)
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.second, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	settings := testPostureSettings()
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}

	decision, err := posture.SetState(fixture.stateNaming(revoke, true, fixture.aliceLaptop), fixture.log(saved, revoke))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.State != PosturePending {
		t.Fatalf("a re-anchor under a state naming no key for the save's signer: %v, %v, %v", err, decision.State, decision.Alarms)
	}

	decision, err = posture.SetState(fixture.stateWithBaseSigner(revoke, true, fixture.second.publicKey(), fixture.aliceLaptop), fixture.log(saved, revoke))
	if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != revoke || posture.held.base.entry.GetN() != saved {
		t.Fatalf("a re-anchor under the state naming the save's key: %v, %v, %v, %v", err, decision.State, decision.Pin, decision.Alarms)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}

	denial := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	decision, err = posture.ApplyDeltas(fixture.log(denial, denial))
	if err != nil || len(decision.Overlay) != 1 || decision.Overlay[0].Kind != PostureOverlaySidecarRevoke || decision.Overlay[0].N != denial {
		t.Errorf("a revocation after the save: %v, %+v, %v", err, decision.Overlay, decision.Alarms)
	}
}

// Alice is a member the rows hold, not an admin, and the tail's AdminSet makes her one: a base by her laptop keeping
// the fold is refused between states, the rows held naming her laptop as no config writer, as before. A state naming
// none of its identities for her laptop is refused too; the state naming the key the base verified under takes it.
func TestAStateTakesABaseByAWriterTheTailPromoted(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	settings := testPostureSettings()
	store := newMemoryPostureStore()
	posture := fixture.enforcingAt2(store, settings)
	promote := fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_ADMIN_SET)
	promoted := fixture.save(fixture.aliceLaptop)
	decision, err := posture.ApplyDeltas(fixture.log(promote, promoted))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.Pin.GetVersion() != promote ||
		postureWaits(decision, promoted) {
		t.Fatalf("the promoted writer's base between states: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}

	decision, err = posture.SetState(fixture.stateNaming(promoted, true, fixture.second), fixture.log(promoted, promoted))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.BridgeState.GetAuth().GetVersion() != 2 {
		t.Fatalf("a state naming no key for the promoted writer: %v, %v, %v", err, decision.BridgeState.GetAuth(), decision.Alarms)
	}

	decision, err = posture.SetState(fixture.stateWithBaseSigner(promoted, true, fixture.aliceLaptop.publicKey(), fixture.second), fixture.log(promoted, promoted))
	if err != nil || decision.State != PostureEnforcingDocument || decision.Pin.GetVersion() != promoted || posture.held.base.entry.GetN() != promoted {
		t.Fatalf("the state naming the promoted writer's key: %v, %v, %v, %v", err, decision.State, decision.Pin, decision.Alarms)
	}
	if manifest, err := decodePostureManifest(store.record(postureManifestName)); err != nil || !bytes.Equal(manifest.baseSignerPublicKey, fixture.aliceLaptop.publicKey()) {
		t.Errorf("the manifest keeps no signer key for the base: %v", err)
	}
	if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || postureDecisionSays(restored) != postureDecisionSays(decision) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}
}

// A state whose key is not the one the save verified under is refused with base_refused: the key of a writer the rows
// name, of a member's device, of no sidecar, and the save's key cut short. The state in force stands and the save keeps
// waiting, and a new device re-anchoring under such a state stays pending.
func TestAStateWhoseBaseSignerKeyDoesNotVerifyItsBaseIsRefused(t *testing.T) {
	fixture := newPostureLaterWriterFixture(t)
	settings := testPostureSettings()
	store := newMemoryPostureStore()
	posture := fixture.enforcingAt2(store, settings)
	saved := fixture.save(fixture.second)
	if _, err := posture.ApplyDeltas(fixture.log(saved, saved)); err != nil {
		t.Fatal(err)
	}
	stranger := &postureFixtureSidecar{id: postureFixtureId(0x7c), key: postureFixtureKey(0x7c), member: fixture.owner}
	keys := [][]byte{fixture.ownerPhone.publicKey(), fixture.aliceLaptop.publicKey(), stranger.publicKey(), fixture.second.publicKey()[:31]}
	for _, key := range keys {
		decision, err := posture.SetState(fixture.stateWithBaseSigner(saved, true, key), fixture.log(saved, saved))
		if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.State != PostureEnforcingNoDocument ||
			decision.BridgeState.GetAuth().GetVersion() != 2 || !postureWaits(decision, saved) {
			t.Errorf("a state saying the save verified under %x: %v, %v, %v", key, err, decision.State, decision.Alarms)
		}
	}
	if _, restored := NewPosture(store.survivor(), settings); len(restored.Alarms) != 0 || restored.State != PostureEnforcingNoDocument ||
		!postureWaits(restored, saved) {
		t.Errorf("restored %v, %v", postureDecisionSays(restored), restored.Alarms)
	}

	fresh, _ := NewPosture(newMemoryPostureStore(), settings)
	if _, err := fresh.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	decision, err := fresh.SetState(fixture.stateWithBaseSigner(saved, true, fixture.ownerPhone.publicKey()), fixture.log(saved, saved))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmBaseRefused) || decision.State != PosturePending {
		t.Errorf("a re-anchor under a key that does not verify the save: %v, %v, %v", err, decision.State, decision.Alarms)
	}
}
