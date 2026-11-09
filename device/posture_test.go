// §18.6's posture and DP1 on a synthetic network (posture_fixture_test.go): every edge of the machine, legal and not,
// and each way DP1 says enforcement must not fall.

package device

import (
	"bytes"
	"errors"
	"io"
	"runtime"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Every edge §17.8 draws and every one it forbids, each from a fresh store.
func TestPostureTransitions(t *testing.T) {
	cases := []struct {
		name string
		// builds a posture in its from state and takes the edge, returning the decision and error the edge gave
		run       func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error)
		wantState PostureState
		wantErr   error
		wantAlarm PostureAlarmKind
	}{
		{
			name: "legacy, Pending: pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture, _ := fixture.open(store)
				return posture.SetPending(fixture.pending())
			},
			wantState: PosturePending,
		},
		{
			name: "legacy, a state: refused, legacy",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.ownerPhone, true)
				posture, _ := fixture.open(store)
				return posture.SetState(fixture.state(1, true), fixture.log(1, 1))
			},
			wantState: PostureLegacy,
			wantErr:   ErrPostureLegacy,
		},
		{
			name: "legacy, deltas: refused, legacy",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.ownerPhone, true)
				posture, _ := fixture.open(store)
				return posture.ApplyDeltas(fixture.log(1, 1))
			},
			wantState: PostureLegacy,
			wantErr:   ErrPostureLegacy,
		},
		{
			name: "pending, a verified state with a document: enforcing{doc}",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				return posture.Decision(), nil
			},
			wantState: PostureEnforcingDocument,
		},
		{
			name: "pending, a verified state with no document: enforcing{nodoc}",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, false)
				return posture.Decision(), nil
			},
			wantState: PostureEnforcingNoDocument,
		},
		{
			name: "pending, a state with no log: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.ownerPhone, true)
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				return posture.SetState(fixture.state(1, true), nil)
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmChainBreak,
		},
		{
			name: "pending, a state for another anchor: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.ownerPhone, true)
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				state := fixture.state(1, true)
				state.GenesisSha256 = postureFixtureId(0x50)
				return posture.SetState(state, fixture.log(1, 1))
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmAnchor,
		},
		{
			name: "pending, a state whose log ends off its pin: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.ownerPhone, true)
				fixture.tick()
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				return posture.SetState(fixture.state(2, true), fixture.log(1, 1))
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmChainBreak,
		},
		{
			name: "pending, a state over a base by no config writer: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				fixture.base(fixture.aliceLaptop, true)
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				return posture.SetState(fixture.state(1, true), fixture.log(1, 1))
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmBaseRefused,
		},
		{
			name: "pending, a Pending for another network: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				other := fixture.pending()
				other.NetworkId = postureFixtureId(0x51)
				return posture.SetPending(other)
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmAnchor,
		},
		{
			name: "pending, its own sign-out alone: legacy",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				fixture.sidecarRevoke(fixture.self, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
				return posture.ApplyDeltas(fixture.log(1, 1))
			},
			wantState: PostureLegacy,
		},
		{
			name: "pending, another sidecar's sign-out: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				fixture.sidecarRevoke(fixture.aliceLaptop, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
				return posture.ApplyDeltas(fixture.log(1, 1))
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmStatementRefused,
		},
		{
			name: "pending, an admin's revocation of this sidecar: refused, pending",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture, _ := fixture.open(store)
				posture.SetPending(fixture.pending())
				fixture.sidecarRevoke(fixture.ownerPhone, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
				return posture.ApplyDeltas(fixture.log(1, 1))
			},
			wantState: PosturePending,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmStatementRefused,
		},
		{
			name: "enforcing, its own sign-out as a chained delta: legacy",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				n := fixture.sidecarRevoke(fixture.self, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED)
				return posture.ApplyDeltas(fixture.log(n, n))
			},
			wantState: PostureLegacy,
		},
		{
			name: "enforcing, an admin's revocation of this sidecar: enforcing, an overlay",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				n := fixture.sidecarRevoke(fixture.ownerPhone, fixture.self, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
				return posture.ApplyDeltas(fixture.log(n, n))
			},
			wantState: PostureEnforcingDocument,
		},
		{
			name: "enforcing, a Pending for the same anchor with new ids: enforcing",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				pending := fixture.pending()
				pending.SidecarId = postureFixtureId(0x52)
				return posture.SetPending(pending)
			},
			wantState: PostureEnforcingDocument,
		},
		{
			name: "enforcing, a Pending for another anchor: refused, enforcing",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				pending := fixture.pending()
				pending.GenesisSha256 = postureFixtureId(0x53)
				pending.GenesisSha256 = append(pending.GenesisSha256, pending.GenesisSha256...)
				return posture.SetPending(pending)
			},
			wantState: PostureEnforcingDocument,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmAnchor,
		},
		{
			name: "enforcing{doc}, a verified base with no document above the latch: enforcing{nodoc}",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				n := fixture.base(fixture.ownerPhone, false)
				return posture.ApplyDeltas(fixture.log(n, n))
			},
			wantState: PostureEnforcingNoDocument,
		},
		{
			name: "enforcing{nodoc}, a verified base with a document: enforcing{doc}",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, false)
				n := fixture.base(fixture.ownerPhone, true)
				return posture.ApplyDeltas(fixture.log(n, n))
			},
			wantState: PostureEnforcingDocument,
		},
		{
			name: "enforcing{doc}, a state saying no document: refused, enforcing{doc}",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				return posture.SetState(fixture.state(fixture.tip(), false), nil)
			},
			wantState: PostureEnforcingDocument,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmDocument,
		},
		{
			name: "enforcing, a state below the last one: refused, enforcing",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				return posture.SetState(fixture.state(fixture.tip()-1, true), nil)
			},
			wantState: PostureEnforcingDocument,
			wantErr:   ErrPostureRefused,
			wantAlarm: PostureAlarmLowerPin,
		},
		{
			name: "enforcing, a later state chained from the pin: enforcing",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				from := fixture.tip() + 1
				n := fixture.tick()
				return posture.SetState(fixture.state(n, true), fixture.log(from, n))
			},
			wantState: PostureEnforcingDocument,
		},
		{
			name: "enforcing, a later state on a newer base: enforcing",
			run: func(fixture *postureFixture, store *memoryPostureStore) (PostureDecision, error) {
				posture := fixture.enforcing(store, true)
				fixture.tick()
				base := fixture.base(fixture.ownerPhone, true)
				n := fixture.tick()
				return posture.SetState(fixture.state(n, true), fixture.log(base, n))
			},
			wantState: PostureEnforcingDocument,
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		store := newMemoryPostureStore()
		decision, err := c.run(fixture, store)
		if !errors.Is(err, c.wantErr) || (c.wantErr == nil && err != nil) {
			t.Errorf("%s: error %v, want %v", c.name, err, c.wantErr)
		}
		if decision.State != c.wantState {
			t.Errorf("%s: state %v, want %v (alarms %v)", c.name, decision.State, c.wantState, decision.Alarms)
		}
		if c.wantAlarm != "" && !postureAlarmed(decision, c.wantAlarm) {
			t.Errorf("%s: alarms %v, want %s", c.name, decision.Alarms, c.wantAlarm)
		}
		// what is in force is what a restart restores
		_, restored := fixture.open(store.survivor())
		if restored.State != decision.State || len(restored.Alarms) != 0 {
			t.Errorf("%s: restored %v with alarms %v, want %v", c.name, restored.State, restored.Alarms, decision.State)
		}
	}
}

// DP1: a restart restores enforcing{doc}, then a forged base saying no document, its state saying no document, does
// not lower it, whether it comes as deltas or as a state's log.
func TestForgedNoDocumentAfterRestartKeepsEnforcing(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	fixture.enforcing(store, true)

	posture, decision := fixture.open(store.survivor())
	if decision.State != PostureEnforcingDocument {
		t.Fatalf("restored %v", decision.State)
	}
	// a base no config writer signed, rows saying no document: the server forging it, signed by alice's laptop
	forged := fixture.base(fixture.aliceLaptop, false)
	decision, err := posture.ApplyDeltas(fixture.log(forged, forged))
	if !errors.Is(err, ErrPostureRefused) || decision.State != PostureEnforcingDocument || !postureAlarmed(decision, PostureAlarmBaseRefused) {
		t.Errorf("forged base as a delta: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	decision, err = posture.SetState(fixture.state(forged, false), fixture.log(forged, forged))
	if !errors.Is(err, ErrPostureRefused) || decision.State != PostureEnforcingDocument || !postureAlarmed(decision, PostureAlarmBaseRefused) {
		t.Errorf("forged base under a state: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	// and the same after another restart
	_, decision = fixture.open(store.survivor())
	if decision.State != PostureEnforcingDocument {
		t.Errorf("restored %v", decision.State)
	}
}

// An unsigned has_document = false, in a state whose verified rows say true, changes nothing and alarms.
func TestUnsignedHasDocumentIgnored(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	from := fixture.tip() + 1
	n := fixture.tick()
	decision, err := posture.SetState(fixture.state(n, false), fixture.log(from, n))
	if !errors.Is(err, ErrPostureRefused) || decision.State != PostureEnforcingDocument || !postureAlarmed(decision, PostureAlarmDocument) {
		t.Errorf("%v, %v, %v", err, decision.State, decision.Alarms)
	}
	if decision.BridgeState.GetAuth().GetVersion() != 3 || decision.Changed {
		t.Errorf("the state in force moved to %d", decision.BridgeState.GetAuth().GetVersion())
	}
}

// A state below the last, and a delta below the pin, are refused, alarm, and change nothing.
func TestLowerPinRefused(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	from := fixture.tip() + 1
	n := fixture.tick()
	if _, err := posture.SetState(fixture.state(n, true), fixture.log(from, n)); err != nil {
		t.Fatal(err)
	}
	decision, err := posture.SetState(fixture.state(n-1, true), nil)
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmLowerPin) {
		t.Errorf("a lower state: %v, %v", err, decision.Alarms)
	}
	decision, err = posture.ApplyDeltas(fixture.log(n, n))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmLowerPin) {
		t.Errorf("a delta at the pin: %v, %v", err, decision.Alarms)
	}
	if decision.Pin.GetVersion() != n || decision.BridgeState.GetAuth().GetVersion() != n {
		t.Errorf("pin %d, state %d", decision.Pin.GetVersion(), decision.BridgeState.GetAuth().GetVersion())
	}
}

// A delta whose prev_chain is not the pin's alarms and changes nothing; the true one then applies.
func TestDeltaThatDoesNotChainAlarms(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	n := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(fixture.entries[n-1], entry); err != nil {
		t.Fatal(err)
	}
	entry.PrevChain = postureFixtureId(0x60)
	entry.PrevChain = append(entry.PrevChain, entry.PrevChain...)
	forkedBytes, err := proto.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	log := fixture.log(n, n)
	log.Entries[0] = forkedBytes
	decision, err := posture.ApplyDeltas(log)
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmChainBreak) || len(decision.Overlay) != 0 {
		t.Errorf("%v, %v, %v", err, decision.Alarms, decision.Overlay)
	}
	decision, err = posture.ApplyDeltas(fixture.log(n, n))
	if err != nil || len(decision.Overlay) != 1 || decision.Pin.GetVersion() != n {
		t.Errorf("the true delta: %v, %v", err, decision.Overlay)
	}
}

// A store that exists and cannot be read or does not verify restores pending with an alarm, never legacy.
func TestCorruptStoreIsPendingNeverLegacy(t *testing.T) {
	cases := []struct {
		name      string
		corrupt   func(store *memoryPostureStore)
		wantAlarm PostureAlarmKind
	}{
		{
			name:      "a manifest with a byte flipped",
			corrupt:   func(store *memoryPostureStore) { postureFlipByte(store, postureManifestName, 0) },
			wantAlarm: PostureAlarmStoreUnreadable,
		},
		{
			name: "a manifest cut short",
			corrupt: func(store *memoryPostureStore) {
				store.setRecord(postureManifestName, store.record(postureManifestName)[:7])
			},
			wantAlarm: PostureAlarmStoreUnreadable,
		},
		{
			name:      "a manifest that cannot be opened",
			corrupt:   func(store *memoryPostureStore) { store.unreadableNames[postureManifestName] = true },
			wantAlarm: PostureAlarmStoreUnreadable,
		},
		{
			name: "rows with a byte flipped",
			corrupt: func(store *memoryPostureStore) {
				postureFlipByte(store, store.recordOf("rows"), len(store.record(store.recordOf("rows")))/2)
			},
			wantAlarm: PostureAlarmStoreUnverified,
		},
		{
			name:      "rows gone",
			corrupt:   func(store *memoryPostureStore) { delete(store.nameRecords, store.recordOf("rows")) },
			wantAlarm: PostureAlarmStoreUnverified,
		},
		{
			name:      "a state with a byte flipped",
			corrupt:   func(store *memoryPostureStore) { postureFlipByte(store, store.recordOf("state"), 3) },
			wantAlarm: PostureAlarmStoreUnverified,
		},
		{
			name: "entries cut short",
			corrupt: func(store *memoryPostureStore) {
				store.setRecord(store.recordOf("entries"), store.record(store.recordOf("entries"))[:10])
			},
			wantAlarm: PostureAlarmStoreUnverified,
		},
		{
			name:      "the manifest gone, its records left",
			corrupt:   func(store *memoryPostureStore) { delete(store.nameRecords, postureManifestName) },
			wantAlarm: PostureAlarmStoreUnverified,
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		store := newMemoryPostureStore()
		fixture.enforcing(store, false)
		survivor := store.survivor()
		c.corrupt(survivor)
		posture, decision := fixture.open(survivor)
		if decision.State != PosturePending || !postureAlarmed(decision, c.wantAlarm) {
			t.Errorf("%s: %v, alarms %v", c.name, decision.State, decision.Alarms)
		}
		// pending keeps the anchor where the manifest still reads, so the next state restores enforcement
		if c.wantAlarm == PostureAlarmStoreUnverified && c.name != "the manifest gone, its records left" {
			decision, err := posture.SetState(fixture.state(fixture.tip(), false), fixture.log(1, fixture.tip()))
			if err != nil || decision.State != PostureEnforcingNoDocument {
				t.Errorf("%s: the next state: %v, %v", c.name, err, decision.State)
			}
		}
	}
}

// Flips one bit of a record.
func postureFlipByte(store *memoryPostureStore, name string, index int) {
	record := bytes.Clone(store.record(name))
	record[index] ^= 0x01
	store.setRecord(name, record)
}

// NewPosture returns only once the store has been read and verified, so the restored state is in force before
// anything can ask it about a packet: held at the store's open, it has not returned, and released, it returns
// enforcing.
func TestRestoredBeforeFirstPacket(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	fixture.enforcing(store, true)
	survivor := store.survivor()
	survivor.openGate, survivor.opened = make(chan struct{}), make(chan struct{})
	returned := make(chan PostureDecision)
	go func() {
		_, decision := fixture.open(survivor)
		returned <- decision
	}()
	<-survivor.opened
	select {
	case decision := <-returned:
		t.Fatalf("NewPosture returned %v before its store answered", decision.State)
	default:
	}
	close(survivor.openGate)
	decision := <-returned
	if decision.State != PostureEnforcingDocument || decision.BridgeState == nil || !decision.Changed {
		t.Errorf("restored %v, state %v", decision.State, decision.BridgeState)
	}
}

// doc to nodoc only on a verified base above the latch: a stored base saying no document at or below the latch
// restores enforcing{doc}, and one above it enforcing{nodoc}.
func TestDocToNodocNeedsBaseAboveLatch(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	if posture.Decision().State != PostureEnforcingDocument {
		t.Fatal(posture.Decision().State)
	}
	n := fixture.base(fixture.ownerPhone, false)
	decision, err := posture.ApplyDeltas(fixture.log(n, n))
	if err != nil || decision.State != PostureEnforcingNoDocument {
		t.Fatalf("%v, %v", err, decision.State)
	}
	// the latch raised to the base's position, as a store written past it would hold: doc again
	manifest, err := decodePostureManifest(store.record(postureManifestName))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.documentSeenAt != n-1 {
		t.Errorf("latch %d, want %d", manifest.documentSeenAt, n-1)
	}
	manifest.documentSeenAt = n
	survivor := store.survivor()
	survivor.setRecord(postureManifestName, manifest.encode())
	_, decision = fixture.open(survivor)
	if decision.State != PostureEnforcingDocument {
		t.Errorf("a base at the latch restored %v", decision.State)
	}
	manifest.documentSeenAt = n - 1
	survivor.setRecord(postureManifestName, manifest.encode())
	_, decision = fixture.open(survivor)
	if decision.State != PostureEnforcingNoDocument {
		t.Errorf("a base above the latch restored %v", decision.State)
	}
}

// A covered revocation applies at once as a denial, Covered, and the next state, which judges its countersignature,
// confirms or reverses it: either way the overlay entry leaves, and the state's rules decide.
func TestCoveredRevocationAppliesAsDenialThenReverses(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	suspend := fixture.suspend(fixture.aliceLaptop, fixture.agent.id, postureFixtureId(0x70))
	decision, err := posture.ApplyDeltas(fixture.log(revoke, suspend))
	if err != nil {
		t.Fatal(err)
	}
	// alice's laptop was revoked before it signed the Suspend, so only the revocation stands
	if len(decision.Overlay) != 1 || decision.Overlay[0].Kind != PostureOverlaySidecarRevoke || !decision.Overlay[0].Covered ||
		!bytes.Equal(decision.Overlay[0].Id, fixture.aliceLaptop.id) || !postureAlarmed(decision, PostureAlarmStatementRefused) {
		t.Errorf("overlay %v, alarms %v", decision.Overlay, decision.Alarms)
	}
	// the overlay survives a restart
	posture, decision = fixture.open(store.survivor())
	if len(decision.Overlay) != 1 {
		t.Fatalf("restored overlay %v", decision.Overlay)
	}
	// the sidecar role's next state, past it, reverses it: its rules no longer carry the revocation
	from := fixture.tip() + 1
	n := fixture.tick()
	state := fixture.state(n, true)
	state.Rules = []byte("rules with alice's laptop")
	decision, err = posture.SetState(state, fixture.log(from, n))
	if err != nil || len(decision.Overlay) != 0 || !bytes.Equal(decision.BridgeState.GetRules(), state.Rules) {
		t.Errorf("%v, overlay %v", err, decision.Overlay)
	}
}

// Rows of about 4 MiB stream through: the live heap, sampled with a collection at every read of the rows, never grows
// by the rows' size, and what stays after is under the iOS tunnel's 1 MiB budget (§18.4).
func TestRowsNeverHeldWhole(t *testing.T) {
	fixture := newPostureFixture(t)
	// 2,000 more of alice's devices and an acl filler bring the rows near 4 MiB
	for index := 0; index < 2000; index += 1 {
		seed := []byte{byte(0x80 + index%64), byte(index / 64)}
		sidecar := &postureFixtureSidecar{
			id:     bytes.Repeat(seed, postureIdByteCount/2),
			key:    postureFixtureKey(byte(0x80 + index%64)),
			member: fixture.alice,
		}
		fixture.sidecars = append(fixture.sidecars, sidecar)
	}
	fixture.aclFillerByteCount = 3*1024*1024 + 512*1024
	fixture.base(fixture.ownerPhone, true)
	rows := fixture.rowsBySha256[[32]byte(fixture.rowsSha256Of(1))]
	if len(rows) < 3*1024*1024+512*1024 || postureRowsMaxByteCount < len(rows) {
		t.Fatalf("rows of %d bytes", len(rows))
	}
	fixture.rowsBySha256 = nil
	store, err := NewFilePostureStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	posture, _ := fixture.open(store)
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}

	liveHeap := func() uint64 {
		runtime.GC()
		stats := runtime.MemStats{}
		runtime.ReadMemStats(&stats)
		return stats.HeapAlloc
	}
	log := fixture.log(1, 1)
	// the test's own copy of the rows is the source's, so the bound is on growth past it
	source := &postureSampledReader{reader: bytes.NewReader(rows), sample: liveHeap}
	log.OpenRows = func(rowsSha256 []byte) (io.ReadCloser, error) {
		return io.NopCloser(source), nil
	}
	before := liveHeap()
	decision, err := posture.SetState(fixture.state(1, true), log)
	if err != nil || decision.State != PostureEnforcingDocument {
		t.Fatalf("%v, %v", err, decision.State)
	}
	after := liveHeap()
	runtime.KeepAlive(rows)
	if bound := uint64(1024 * 1024); before+bound < source.peak {
		t.Errorf("the live heap peaked %d bytes above its start while %d bytes of rows streamed", source.peak-before, len(rows))
	}
	if after > before && 1024*1024 < after-before {
		t.Errorf("the posture keeps %d bytes once the rows are stored", after-before)
	}
}

// A reader that samples the live heap at every read.
type postureSampledReader struct {
	reader io.Reader
	sample func() uint64
	peak   uint64
}

func (self *postureSampledReader) Read(p []byte) (int, error) {
	if sampled := self.sample(); self.peak < sampled {
		self.peak = sampled
	}
	return self.reader.Read(p)
}

// The rows_sha256 the base at n names.
func (self *postureFixture) rowsSha256Of(n uint64) []byte {
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(self.entries[n-1], entry); err != nil {
		self.t.Fatal(err)
	}
	_, header, _, err := parsePostureBase(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	return header.GetRowsSha256()
}

// A tick the server changed chains from the pin, since no signature covers a tick, and moves the posture onto a chain
// the true log does not continue. A true state then resyncs it when its log starts at its base, with an alarm, and is
// refused without one; enforcement never falls in between.
func TestStateOnItsBaseResyncsADivergedPosture(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	tick := fixture.tick()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	changed := fixture.log(tick, tick)
	entry := &bridge.AuthEntry{}
	if err := proto.Unmarshal(changed.Entries[0], entry); err != nil {
		t.Fatal(err)
	}
	entry.TimeMs += 1
	changedBytes, err := proto.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	changed.Entries[0] = changedBytes
	if _, err := posture.ApplyDeltas(changed); err != nil {
		t.Fatal(err)
	}
	decision, err := posture.ApplyDeltas(fixture.log(revoke, revoke))
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmChainBreak) || decision.State != PostureEnforcingDocument {
		t.Fatalf("the true delta on a diverged pin: %v, %v, %v", err, decision.State, decision.Alarms)
	}
	decision, err = posture.SetState(fixture.state(tick, true), nil)
	if !errors.Is(err, ErrPostureRefused) || !postureAlarmed(decision, PostureAlarmChainBreak) || decision.BridgeState.GetAuth().GetVersion() != 3 {
		t.Errorf("a true state with no log: %v, %v", err, decision.Alarms)
	}
	decision, err = posture.SetState(fixture.state(revoke, true), fixture.log(1, revoke))
	if err != nil || !postureAlarmed(decision, PostureAlarmChainBreak) || decision.Pin.GetVersion() != revoke {
		t.Fatalf("a true state on its base: %v, %v, %v", err, decision.Pin, decision.Alarms)
	}
	if want := fixture.chain(revoke); !bytes.Equal(decision.Pin.GetChain(), want[:]) {
		t.Errorf("resynced off the true chain")
	}
	_, restored := fixture.open(store.survivor())
	if restored.Pin.GetVersion() != revoke || len(restored.Alarms) != 0 {
		t.Errorf("restored %v, %v", restored.Pin, restored.Alarms)
	}
}
