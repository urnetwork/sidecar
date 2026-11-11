// The forwarding role's tier 1 (DESIGN-DETAILS 4.2.5, SDK-M8-17) on the fixture network: the two denial kinds decision
// 197 adds, each with its positive twin and a wrong signer; an Unsuspend that lifts nothing; what may narrow waits and
// alarms on a fake clock, never making the decision pending; a state keeps what lies above its pin, a lower one is
// dropped (Fwd.tla's StateDropsOverlay and LowerStateAccepted twins on real code); a fork holds pending; a base
// between states opens nothing; and a full overlay holds pending until a state past what it could not hold.

package device

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A clock a test moves.
type postureTestClock struct {
	stateLock sync.Mutex
	now       time.Time
}

// A clock at a fixed synthetic time.
func newPostureTestClock() *postureTestClock {
	return &postureTestClock{now: time.UnixMilli(1_800_000_000_000)}
}

func (self *postureTestClock) Now() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.now
}

// Moves the clock on by timeout.
func (self *postureTestClock) advance(timeout time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.now = self.now.Add(timeout)
}

// config.proto's Delegation body, written by wire as protocol's deterministic encoder writes it: its header, pubkey and
// reader key, and for a forwarding one field 7 (posture_wire_test.go holds the two encoders equal).
func postureFixtureDelegationBody(header *bridge.StatementHeader, pubkey []byte, readerKey []byte, forward *bridge.ForwardScope) []byte {
	body := []byte{}
	appendBytes := func(number protowire.Number, value []byte) {
		if len(value) != 0 {
			body = protowire.AppendBytes(protowire.AppendTag(body, number, protowire.BytesType), value)
		}
	}
	marshal := func(message proto.Message) []byte {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			panic(err)
		}
		return encoded
	}
	body = protowire.AppendBytes(protowire.AppendTag(body, postureDelegationFieldHeader, protowire.BytesType), marshal(header))
	appendBytes(2, pubkey)
	appendBytes(3, readerKey)
	if forward != nil {
		body = protowire.AppendBytes(protowire.AppendTag(body, postureDelegationFieldForward, protowire.BytesType), marshal(forward))
	}
	return body
}

// config.proto's DelegationRevoke body, by wire as protocol's deterministic encoder writes it.
func postureFixtureDelegationRevokeBody(header *bridge.StatementHeader, delegationId []byte, sinceN uint64) []byte {
	headerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		panic(err)
	}
	body := protowire.AppendBytes(protowire.AppendTag(nil, postureDelegationRevokeFieldHeader, protowire.BytesType), headerBytes)
	body = protowire.AppendBytes(protowire.AppendTag(body, postureDelegationRevokeFieldId, protowire.BytesType), delegationId)
	if sinceN != 0 {
		body = protowire.AppendVarint(protowire.AppendTag(body, postureDelegationRevokeFieldSinceN, protowire.VarintType), sinceN)
	}
	return body
}

// The fixture's encoders, for posture_wire_test.go, which links config.proto.
var (
	PostureFixtureDelegationBodyForTest       = postureFixtureDelegationBody
	PostureFixtureDelegationRevokeBodyForTest = postureFixtureDelegationRevokeBody
)

// A Delegation by signer at the next position, a forwarding one for forwardSidecar unless that is nil, with its
// delegation_id.
func (self *postureFixture) delegation(signer *postureFixtureSidecar, forwardSidecar *postureFixtureSidecar) (uint64, []byte) {
	var forward *bridge.ForwardScope
	if forwardSidecar != nil {
		forward = &bridge.ForwardScope{ForwardSidecarId: forwardSidecar.id}
	}
	self.nonce += 1
	forwardKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{self.nonce}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	body := postureFixtureDelegationBody(self.header(), forwardKey, bytes.Repeat([]byte{0xd0}, 1216), forward)
	self.append(bridge.AuthEntryKindStatement, self.sign(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, body))
	delegationId := bridge.SignedBytesSha256(bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION, body)
	return self.tip(), delegationId[:]
}

// A DelegationRevoke of delegationId by signer at the next position.
func (self *postureFixture) delegationRevoke(signer *postureFixtureSidecar, delegationId []byte, sinceN uint64) uint64 {
	body := postureFixtureDelegationRevokeBody(self.header(), delegationId, sinceN)
	self.append(bridge.AuthEntryKindStatement, self.sign(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_DELEGATION_REVOKE, body))
	return self.tip()
}

// A statement of signedType whose body this role never reads, by signer at the next position.
func (self *postureFixture) opaqueStatement(signer *postureFixtureSidecar, purpose string, signedType bridge.SignedType) uint64 {
	self.append(bridge.AuthEntryKindStatement, self.sign(signer, purpose, signedType, []byte("a body this role never reads")))
	return self.tip()
}

// A base like base's, naming configHead as its config head.
func (self *postureFixture) baseWithHead(signer *postureFixtureSidecar, hasDocument bool, configHead []byte) uint64 {
	rows := self.rows(hasDocument)
	rowsSha256 := sha256.Sum256(rows)
	n := self.tip() + 1
	prev := self.chain(n - 1)
	header, err := proto.MarshalOptions{Deterministic: true}.Marshal(&bridge.ProjectionHeader{
		NetworkId: self.networkId, Version: n, PrevChain: prev[:], FoldedThrough: n - 1, ConfigVersion: n,
		ConfigHeadSha256: configHead, RowsSha256: rowsSha256[:], RowsByteCount: uint32(len(rows)), Threshold: 1,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.append(bridge.AuthEntryKindBase, self.sign(signer, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_PROJECTION_HEADER, header))
	return n
}

// A state at n whose identities show alice's laptop's forwarding Delegation delegationId live.
func (self *postureFixture) forwardingState(n uint64, hasDocument bool, delegationId []byte) *bridge.BridgeState {
	state := self.state(n, hasDocument)
	state.Identities = []*bridge.BridgeIdentity{{
		SidecarId: self.aliceLaptop.id, IdentityPublicKey: self.aliceLaptop.publicKey(), ForwardDelegationId: delegationId,
		ForwardPublicKey: bytes.Repeat([]byte{0xf0}, ed25519.PublicKeySize),
	}}
	return state
}

// A posture enforcing at base 1 and pin 3 on clock, whose state shows alice's laptop's forwarding Delegation, filed at
// 2, live: what it returns.
func (self *postureFixture) forwarding(store PostureStore, settings *PostureSettings) (*Posture, []byte) {
	self.t.Helper()
	self.base(self.ownerPhone, true)
	_, delegationId := self.delegation(self.aliceLaptop, self.aliceLaptop)
	self.tick()
	posture, _ := NewPosture(store, settings)
	if _, err := posture.SetPending(self.pending()); err != nil {
		self.t.Fatal(err)
	}
	decision, err := posture.SetState(self.forwardingState(3, true, delegationId), self.log(1, 3))
	if err != nil || decision.State != PostureEnforcingDocument {
		self.t.Fatalf("%v, %v", err, decision.State)
	}
	return posture, delegationId
}

// Settings on clock.
func testPostureSettingsOn(clock *postureTestClock) *PostureSettings {
	settings := testPostureSettings()
	settings.Now = clock.Now
	return settings
}

// Whether waiting holds an entry standing for n.
func postureWaits(decision PostureDecision, n uint64) bool {
	return slices.ContainsFunc(decision.Waiting, func(entry PostureWaitingEntry) bool {
		return entry.N <= n && n <= entry.ThroughN
	})
}

// A DelegationRevoke of a forwarding Delegation the state shows live denies its key at once, by a standing signer, and
// since_n > 0 makes it covered; a wrong signer, a read_only one, a forged signature, a delegation the state does not
// show and a body that does not read by wire each leave the overlay as it was and wait.
func TestADelegationRevokeDeniesItsKeyAtOnce(t *testing.T) {
	stranger := &postureFixtureSidecar{id: postureFixtureId(0x7a), key: postureFixtureKey(0x7a)}
	cases := []struct {
		name string
		file func(fixture *postureFixture, delegationId []byte) uint64
		// whether it applies, and covered
		applies   bool
		covered   bool
		wantAlarm bool
	}{
		{
			name: "an admin's",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				return fixture.delegationRevoke(fixture.ownerPhone, delegationId, 0)
			},
			applies: true,
		},
		{
			name: "its own sidecar's",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				return fixture.delegationRevoke(fixture.aliceLaptop, delegationId, 0)
			},
			applies: true,
		},
		{
			name: "a leaked bundle's, from a position",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				return fixture.delegationRevoke(fixture.ownerPhone, delegationId, 2)
			},
			applies: true,
			covered: true,
		},
		{
			name: "a stranger's",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				stranger.member = fixture.owner
				return fixture.delegationRevoke(stranger, delegationId, 0)
			},
			wantAlarm: true,
		},
		{
			name: "a forged signature",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				impostor := &postureFixtureSidecar{id: fixture.ownerPhone.id, key: postureFixtureKey(0x77), member: fixture.owner}
				return fixture.delegationRevoke(impostor, delegationId, 0)
			},
			wantAlarm: true,
		},
		{
			name: "a read_only device's",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				return fixture.delegationRevoke(fixture.aliceWorker, delegationId, 0)
			},
			wantAlarm: true,
		},
		{
			name: "of a delegation the state does not show",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				return fixture.delegationRevoke(fixture.ownerPhone, bytes.Repeat([]byte{0xa7}, 32), 0)
			},
		},
		{
			name: "a body whose delegation_id is a varint",
			file: func(fixture *postureFixture, delegationId []byte) uint64 {
				headerBytes, _ := proto.Marshal(fixture.header())
				body := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), headerBytes)
				body = protowire.AppendVarint(protowire.AppendTag(body, 2, protowire.VarintType), 7)
				fixture.append(bridge.AuthEntryKindStatement, fixture.sign(fixture.ownerPhone, bridge.SignedPurposeAuthority,
					bridge.SignedType_SIGNED_DELEGATION_REVOKE, body))
				return fixture.tip()
			},
			wantAlarm: true,
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		store := newMemoryPostureStore()
		posture, delegationId := fixture.forwarding(store, testPostureSettings())
		n := c.file(fixture, delegationId)
		decision, err := posture.ApplyDeltas(fixture.log(n, n))
		if err != nil || decision.Pin.GetVersion() != n || decision.State != PostureEnforcingDocument {
			t.Errorf("%s: %v, pin %v, %v", c.name, err, decision.Pin, decision.State)
			continue
		}
		if c.applies {
			want := PostureOverlayEntry{Kind: PostureOverlayDelegationRevoke, N: n, Id: delegationId, Covered: c.covered}
			if len(decision.Overlay) != 1 || !postureOverlayEntryEqual(decision.Overlay[0], want) || len(decision.Waiting) != 0 ||
				len(decision.Alarms) != 0 || decision.CompileWanted {
				t.Errorf("%s: overlay %+v, waiting %v, alarms %v", c.name, decision.Overlay, decision.Waiting, decision.Alarms)
			}
		} else if len(decision.Overlay) != 0 || !postureWaits(decision, n) || !decision.CompileWanted ||
			postureAlarmed(decision, PostureAlarmStatementRefused) != c.wantAlarm {
			t.Errorf("%s: overlay %+v, waiting %v, alarms %v", c.name, decision.Overlay, decision.Waiting, decision.Alarms)
		}
		// what the overlay and Waiting hold survives a restart
		_, restored := NewPosture(store.survivor(), testPostureSettings())
		if !slices.EqualFunc(restored.Overlay, decision.Overlay, postureOverlayEntryEqual) || len(restored.Waiting) != len(decision.Waiting) ||
			len(restored.Alarms) != 0 {
			t.Errorf("%s: restored %+v, %v, %v", c.name, restored.Overlay, restored.Waiting, restored.Alarms)
		}
	}
}

// A forwarding Delegation naming its own signer supersedes that sidecar's older keys at once, denying every key but
// its own, which itself waits for the compile; one naming another sidecar, one forged and one by a read_only device
// wait; a Delegation that is not a forwarding one is an opening, which only wants a compile.
func TestANewerDelegationDeniesTheOlderKey(t *testing.T) {
	cases := []struct {
		name      string
		file      func(fixture *postureFixture) (uint64, []byte)
		supersede bool
		waits     bool
	}{
		{
			name: "its sidecar's own",
			file: func(fixture *postureFixture) (uint64, []byte) {
				return fixture.delegation(fixture.aliceLaptop, fixture.aliceLaptop)
			},
			supersede: true,
		},
		{
			name: "for another sidecar than its signer",
			file: func(fixture *postureFixture) (uint64, []byte) {
				return fixture.delegation(fixture.aliceLaptop, fixture.agent)
			},
			waits: true,
		},
		{
			name: "forged",
			file: func(fixture *postureFixture) (uint64, []byte) {
				impostor := &postureFixtureSidecar{id: fixture.aliceLaptop.id, key: postureFixtureKey(0x78), member: fixture.alice}
				return fixture.delegation(impostor, impostor)
			},
			waits: true,
		},
		{
			name: "a read_only device's",
			file: func(fixture *postureFixture) (uint64, []byte) {
				return fixture.delegation(fixture.aliceWorker, fixture.aliceWorker)
			},
			waits: true,
		},
		{
			name: "not a forwarding one",
			file: func(fixture *postureFixture) (uint64, []byte) { return fixture.delegation(fixture.ownerPhone, nil) },
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		store := newMemoryPostureStore()
		posture, _ := fixture.forwarding(store, testPostureSettings())
		n, delegationId := c.file(fixture)
		decision, err := posture.ApplyDeltas(fixture.log(n, n))
		if err != nil || decision.Pin.GetVersion() != n {
			t.Errorf("%s: %v, %v", c.name, err, decision.Pin)
			continue
		}
		if !decision.CompileWanted {
			t.Errorf("%s: wants no compile", c.name)
		}
		switch {
		case c.supersede:
			want := PostureOverlayEntry{Kind: PostureOverlayForwardSupersede, N: n, Id: fixture.aliceLaptop.id, DelegationId: delegationId}
			if len(decision.Overlay) != 1 || !postureOverlayEntryEqual(decision.Overlay[0], want) || len(decision.Waiting) != 0 ||
				len(decision.Alarms) != 0 {
				t.Errorf("%s: overlay %+v, waiting %v, alarms %v", c.name, decision.Overlay, decision.Waiting, decision.Alarms)
			}
		case c.waits:
			if len(decision.Overlay) != 0 || !postureWaits(decision, n) || !postureAlarmed(decision, PostureAlarmStatementRefused) {
				t.Errorf("%s: overlay %+v, waiting %v, alarms %v", c.name, decision.Overlay, decision.Waiting, decision.Alarms)
			}
		default:
			if len(decision.Overlay) != 0 || len(decision.Waiting) != 0 || len(decision.Alarms) != 0 {
				t.Errorf("%s: overlay %+v, waiting %v, alarms %v", c.name, decision.Overlay, decision.Waiting, decision.Alarms)
			}
		}
	}
}

// An Unsuspend after an overlay Suspend leaves the subject denied, before and after a restart, and wants a compile;
// only a state past both decides.
func TestAnUnsuspendLiftsNothingUntilAState(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	suspend := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x78))
	decision, err := posture.ApplyDeltas(fixture.log(suspend, suspend))
	if err != nil || len(decision.Overlay) != 1 || decision.CompileWanted {
		t.Fatalf("the Suspend: %v, %+v", err, decision.Overlay)
	}
	unsuspend := fixture.unsuspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x78))
	decision, err = posture.ApplyDeltas(fixture.log(unsuspend, unsuspend))
	if err != nil || len(decision.Overlay) != 1 || decision.Overlay[0].Kind != PostureOverlaySuspend || decision.Overlay[0].N != suspend ||
		!decision.CompileWanted || len(decision.Waiting) != 0 || len(decision.Alarms) != 0 || decision.Changed {
		t.Fatalf("the Unsuspend: %v, overlay %+v, waiting %v, alarms %v", err, decision.Overlay, decision.Waiting, decision.Alarms)
	}
	posture, decision = fixture.open(store.survivor())
	if len(decision.Overlay) != 1 {
		t.Fatalf("restored %+v", decision.Overlay)
	}
	decision, err = posture.SetState(fixture.state(unsuspend, true), nil)
	if err != nil || len(decision.Overlay) != 0 || decision.BridgeState.GetAuth().GetVersion() != unsuspend {
		t.Errorf("the state past both: %v, %+v", err, decision.Overlay)
	}
}

// A SidecarRevoke the posture cannot check, by a signer the rows do not hold, leaves the decision and the state in
// force as they were and waits; at 10 minutes on a fake clock the decision reports it Overdue and the posture alarms,
// once, then again at 20, across a restart, which raises it once more at its first decision; a state at its position
// clears it, and nothing is ever pending.
func TestAnUncheckableRevocationAlarmsAndKeepsTheState(t *testing.T) {
	fixture := newPostureFixture(t)
	clock := newPostureTestClock()
	settings := testPostureSettingsOn(clock)
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	firstSeen := clock.Now()
	stranger := &postureFixtureSidecar{id: postureFixtureId(0x7a), key: postureFixtureKey(0x7a), member: fixture.owner}
	revoke := fixture.sidecarRevoke(stranger, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	decision, err := posture.ApplyDeltas(fixture.log(revoke, revoke))
	if err != nil || decision.State != PostureEnforcingDocument || decision.BridgeState.GetAuth().GetVersion() != 3 ||
		len(decision.Overlay) != 0 || len(decision.Waiting) != 1 || decision.Waiting[0].N != revoke ||
		!decision.Waiting[0].FirstSeen.Equal(firstSeen) || decision.Overdue != nil || decision.Changed {
		t.Fatalf("the revocation: %v, %v, overlay %+v, waiting %+v, overdue %+v", err, decision.State, decision.Overlay, decision.Waiting, decision.Overdue)
	}
	overdueAlarms := func(decision PostureDecision) []PostureAlarm {
		alarms := []PostureAlarm{}
		for _, alarm := range decision.Alarms {
			if alarm.Kind == PostureAlarmCompileOverdue {
				alarms = append(alarms, alarm)
			}
		}
		return alarms
	}
	clock.advance(10*time.Minute - time.Second)
	if decision := posture.Decision(); decision.Overdue != nil || len(overdueAlarms(decision)) != 0 {
		t.Fatalf("before 10 min: %+v, %v", decision.Overdue, decision.Alarms)
	}
	clock.advance(time.Second)
	decision = posture.Decision()
	alarms := overdueAlarms(decision)
	if decision.State != PostureEnforcingDocument || decision.Overdue == nil || decision.Overdue.N != revoke ||
		decision.Overdue.Age != 10*time.Minute || !decision.Overdue.NextAlarmAt.Equal(firstSeen.Add(20*time.Minute)) ||
		len(alarms) != 1 || alarms[0].N != revoke || alarms[0].Age != 10*time.Minute {
		t.Fatalf("at 10 min: %v, %+v, %v", decision.State, decision.Overdue, decision.Alarms)
	}
	// raised once a point: the same alarm is what a later read finds
	clock.advance(5 * time.Minute)
	decision = posture.Decision()
	if alarms := overdueAlarms(decision); decision.Overdue.Age != 15*time.Minute || len(alarms) != 1 || alarms[0].Age != 10*time.Minute {
		t.Fatalf("at 15 min: %+v, %v", decision.Overdue, decision.Alarms)
	}
	// a restart keeps the first sight, and raises the alarm once at its first decision
	posture, decision = NewPosture(store.survivor(), settings)
	alarms = overdueAlarms(decision)
	if decision.State != PostureEnforcingDocument || len(decision.Waiting) != 1 || !decision.Waiting[0].FirstSeen.Equal(firstSeen) ||
		decision.Overdue == nil || decision.Overdue.Age != 15*time.Minute || len(alarms) != 1 || alarms[0].Age != 15*time.Minute {
		t.Fatalf("restored at 15 min: %v, %+v, %+v, %v", decision.State, decision.Waiting, decision.Overdue, decision.Alarms)
	}
	clock.advance(time.Minute)
	if alarms := overdueAlarms(posture.Decision()); len(alarms) != 1 || alarms[0].Age != 15*time.Minute {
		t.Fatalf("at 16 min: %v", alarms)
	}
	clock.advance(4 * time.Minute)
	decision = posture.Decision()
	alarms = overdueAlarms(decision)
	if decision.Overdue == nil || !decision.Overdue.NextAlarmAt.Equal(firstSeen.Add(30*time.Minute)) || len(alarms) != 1 ||
		alarms[0].Age != 20*time.Minute || decision.State != PostureEnforcingDocument {
		t.Fatalf("at 20 min: %+v, %v", decision.Overdue, decision.Alarms)
	}
	// the state that judged it clears it
	decision, err = posture.SetState(fixture.state(revoke, true), nil)
	if err != nil || len(decision.Waiting) != 0 || decision.Overdue != nil || len(overdueAlarms(decision)) != 0 {
		t.Fatalf("the state: %v, %+v, %+v, %v", err, decision.Waiting, decision.Overdue, decision.Alarms)
	}
	clock.advance(time.Hour)
	if decision := posture.Decision(); decision.Overdue != nil || len(overdueAlarms(decision)) != 0 {
		t.Errorf("after the state: %+v, %v", decision.Overdue, decision.Alarms)
	}
}

// A state below the posture's pin keeps every overlay and waiting entry above its own pin and drops the rest, which
// it judged (Fwd.tla's StateDropsOverlay twin): the revocation after it stands, and the tick after it still waits.
func TestAStateKeepsTheOverlayAboveItsPin(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	tick := fixture.tick()
	suspend := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x79))
	lastTick := fixture.tick()
	decision, err := posture.ApplyDeltas(fixture.log(revoke, lastTick))
	if err != nil || len(decision.Overlay) != 2 || len(decision.Waiting) != 2 {
		t.Fatalf("%v, overlay %+v, waiting %+v", err, decision.Overlay, decision.Waiting)
	}
	decision, err = posture.SetState(fixture.state(tick, true), nil)
	if err != nil || decision.BridgeState.GetAuth().GetVersion() != tick || decision.Pin.GetVersion() != lastTick {
		t.Fatalf("the state: %v, %v", err, decision.Pin)
	}
	if len(decision.Overlay) != 1 || decision.Overlay[0].N != suspend || len(decision.Waiting) != 1 || decision.Waiting[0].N != lastTick {
		t.Errorf("overlay %+v, waiting %+v", decision.Overlay, decision.Waiting)
	}
	_, restored := fixture.open(store.survivor())
	if len(restored.Overlay) != 1 || len(restored.Waiting) != 1 || len(restored.Alarms) != 0 {
		t.Errorf("restored %+v, %+v, %v", restored.Overlay, restored.Waiting, restored.Alarms)
	}
}

// A compile that captured an older pin and finished after a newer one hands a state below the one in force: it is
// dropped, with no error and no alarm, so the revocation the newer state embodied is not lost (Fwd.tla's
// LowerStateAccepted twin), and a state at the one in force is taken.
func TestALowerStateIsDropped(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, true)
	older := fixture.tick()
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	if _, err := posture.ApplyDeltas(fixture.log(older, revoke)); err != nil {
		t.Fatal(err)
	}
	newer := fixture.state(revoke, true)
	newer.Rules = []byte("rules with alice's laptop revoked")
	if _, err := posture.SetState(newer, nil); err != nil {
		t.Fatal(err)
	}
	decision, err := posture.SetState(fixture.state(older, true), nil)
	if err != nil || len(decision.Alarms) != 0 || decision.Changed || !bytes.Equal(decision.BridgeState.GetRules(), newer.Rules) {
		t.Fatalf("the lower state: %v, %v, changed %v, rules %q", err, decision.Alarms, decision.Changed, decision.BridgeState.GetRules())
	}
	_, restored := fixture.open(store.survivor())
	if !bytes.Equal(restored.BridgeState.GetRules(), newer.Rules) {
		t.Errorf("restored %q", restored.BridgeState.GetRules())
	}
}

// What may narrow and that this role never applies waits; what opens or is neutral only wants a compile; a denial
// wants none.
func TestWhatMayNarrowWaitsAndWhatOpensWantsACompile(t *testing.T) {
	cases := []struct {
		name  string
		file  func(fixture *postureFixture) uint64
		waits bool
		// a denial: neither waits nor wants a compile
		denies bool
	}{
		{name: "a tick", file: func(fixture *postureFixture) uint64 { return fixture.tick() }, waits: true},
		{
			name: "a base of another config head",
			file: func(fixture *postureFixture) uint64 {
				return fixture.baseWithHead(fixture.ownerPhone, true, postureFixtureId(0x41))
			},
			waits: true,
		},
		{
			name: "a base of the same config head",
			file: func(fixture *postureFixture) uint64 {
				return fixture.baseWithHead(fixture.ownerPhone, true, postureFixtureId(0x40))
			},
		},
		{
			name: "an AdminSet",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_ADMIN_SET)
			},
			waits: true,
		},
		{
			name: "an AuthorityProposal",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL)
			},
			waits: true,
		},
		{
			name: "an AuthorityCosign",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_AUTHORITY_COSIGN)
			},
			waits: true,
		},
		{
			name: "a RecoveryRebind",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeAuthority, bridge.SignedType_SIGNED_RECOVERY_REBIND)
			},
			waits: true,
		},
		{
			name: "a BridgeEgress",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.ownerPhone, bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_EGRESS)
			},
			waits: true,
		},
		{
			name: "an Unsuspend",
			file: func(fixture *postureFixture) uint64 {
				return fixture.unsuspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x7b))
			},
		},
		{
			name: "a BridgeRoute",
			file: func(fixture *postureFixture) uint64 {
				return fixture.opaqueStatement(fixture.aliceLaptop, bridge.SignedPurposeBridge, bridge.SignedType_SIGNED_BRIDGE_ROUTE)
			},
		},
		{
			name: "a body that is no Signed",
			file: func(fixture *postureFixture) uint64 {
				fixture.append(bridge.AuthEntryKindStatement, []byte{0xff, 0xff})
				return fixture.tip()
			},
		},
		{
			name: "a SidecarRevoke this role checks",
			file: func(fixture *postureFixture) uint64 {
				return fixture.sidecarRevoke(fixture.ownerPhone, fixture.agent, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
			},
			denies: true,
		},
	}
	for _, c := range cases {
		fixture := newPostureFixture(t)
		store := newMemoryPostureStore()
		posture := fixture.enforcing(store, true)
		n := c.file(fixture)
		decision, err := posture.ApplyDeltas(fixture.log(n, n))
		if err != nil || decision.Pin.GetVersion() != n || decision.State != PostureEnforcingDocument {
			t.Errorf("%s: %v, %v, %v", c.name, err, decision.Pin, decision.Alarms)
			continue
		}
		if postureWaits(decision, n) != c.waits || decision.CompileWanted == c.denies || (len(decision.Overlay) != 0) != c.denies {
			t.Errorf("%s: waiting %+v, compile wanted %v, overlay %+v", c.name, decision.Waiting, decision.CompileWanted, decision.Overlay)
		}
	}
}

// A fork holds an enforcing posture at pending, across a restart, while denials go on applying beneath it; clearing
// it restores what was in force with them. Legacy refuses one.
func TestForkHoldsPendingUntilCleared(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	legacy, _ := fixture.open(newMemoryPostureStore())
	if _, err := legacy.SetFork(true); !errors.Is(err, ErrPostureLegacy) {
		t.Errorf("legacy: %v", err)
	}
	posture := fixture.enforcing(store, true)
	decision, err := posture.SetFork(true)
	if err != nil || decision.State != PosturePending || !decision.Fork || decision.BridgeState != nil || !decision.Changed {
		t.Fatalf("the fork: %v, %v, %v", err, decision.State, decision.Fork)
	}
	if decision, err := posture.SetFork(true); err != nil || decision.Changed {
		t.Errorf("the fork again: %v, %v", err, decision.Changed)
	}
	revoke := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	if decision, err := posture.ApplyDeltas(fixture.log(revoke, revoke)); err != nil || decision.State != PosturePending {
		t.Fatalf("a denial under the fork: %v, %v", err, decision.State)
	}
	posture, decision = fixture.open(store.survivor())
	if decision.State != PosturePending || !decision.Fork || len(decision.Alarms) != 0 {
		t.Fatalf("restored: %v, %v, %v", decision.State, decision.Fork, decision.Alarms)
	}
	decision, err = posture.SetFork(false)
	if err != nil || decision.State != PostureEnforcingDocument || decision.Fork || decision.BridgeState.GetAuth().GetVersion() != 3 ||
		len(decision.Overlay) != 1 || decision.Overlay[0].N != revoke {
		t.Errorf("cleared: %v, %v, %+v", err, decision.State, decision.Overlay)
	}
}

// A base between states narrows nodoc to doc at once, and a later one saying no document again lifts nothing: the
// posture stays doc until a state on that base says nodoc.
func TestABaseBetweenStatesOpensNothing(t *testing.T) {
	fixture := newPostureFixture(t)
	store := newMemoryPostureStore()
	posture := fixture.enforcing(store, false)
	documented := fixture.base(fixture.ownerPhone, true)
	decision, err := posture.ApplyDeltas(fixture.log(documented, documented))
	if err != nil || decision.State != PostureEnforcingDocument {
		t.Fatalf("a base with a document: %v, %v", err, decision.State)
	}
	tick := fixture.tick()
	undocumented := fixture.base(fixture.ownerPhone, false)
	decision, err = posture.ApplyDeltas(fixture.log(tick, undocumented))
	if err != nil || decision.State != PostureEnforcingDocument {
		t.Fatalf("a base with none again: %v, %v", err, decision.State)
	}
	if _, restored := fixture.open(store.survivor()); restored.State != PostureEnforcingDocument {
		t.Fatalf("restored %v", restored.State)
	}
	decision, err = posture.SetState(fixture.state(undocumented, false), nil)
	if err != nil || decision.State != PostureEnforcingNoDocument {
		t.Errorf("a state on it: %v, %v", err, decision.State)
	}
}

// Past WaitingMaxCount the newest waiting entries merge, waiting from the older's sight through the newer's position,
// so a state reaching only part of a merged entry keeps it, from after its pin.
func TestWaitingMergesPastItsBound(t *testing.T) {
	fixture := newPostureFixture(t)
	clock := newPostureTestClock()
	settings := testPostureSettingsOn(clock)
	settings.WaitingMaxCount = 2
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	posture.SetPending(fixture.pending())
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	firstSeen := clock.Now()
	first := fixture.tick()
	if _, err := posture.ApplyDeltas(fixture.log(first, first)); err != nil {
		t.Fatal(err)
	}
	clock.advance(time.Minute)
	second := fixture.tick()
	third := fixture.tick()
	for _, n := range []uint64{second, third} {
		if _, err := posture.ApplyDeltas(fixture.log(n, n)); err != nil {
			t.Fatal(err)
		}
	}
	decision := posture.Decision()
	if len(decision.Waiting) != 2 || decision.Waiting[0].N != first || decision.Waiting[0].ThroughN != first ||
		decision.Waiting[1].N != second || decision.Waiting[1].ThroughN != third || !decision.Waiting[0].FirstSeen.Equal(firstSeen) {
		t.Fatalf("waiting %+v", decision.Waiting)
	}
	decision, err := posture.SetState(fixture.state(second, true), nil)
	if err != nil || len(decision.Waiting) != 1 || decision.Waiting[0].N != third || decision.Waiting[0].ThroughN != third {
		t.Fatalf("a state inside the merged entry: %v, %+v", err, decision.Waiting)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if len(restored.Waiting) != 1 || restored.Waiting[0].N != third || len(restored.Alarms) != 0 {
		t.Errorf("restored %+v, %v", restored.Waiting, restored.Alarms)
	}
}

// Past OverlayMaxCount a denial the posture verified and cannot hold makes it pending, persisted, rather than leave a
// revocation it could check unapplied, and it follows the chain meanwhile, holding every denial it held; a state below
// the newest such denial leaves it pending, and one at it restores enforcement, with room again for the next denial
// (question sdk-m8-17-overlay-bound-without-compiles, the closed direction until it is answered). At the bound itself
// nothing changes.
func TestAFullOverlayHoldsPendingUntilAStatePastIt(t *testing.T) {
	fixture := newPostureFixture(t)
	settings := testPostureSettings()
	settings.OverlayMaxCount = 2
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	grantRevoke := func(seed byte) uint64 {
		return fixture.statement(fixture.ownerPhone, bridge.SignedPurposeAcl, bridge.SignedType_SIGNED_GRANT_REVOKE,
			&bridge.GrantRevoke{Header: fixture.header(), GrantId: postureFixtureId(seed)})
	}
	first := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	second := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x79))
	decision, err := posture.ApplyDeltas(fixture.log(first, second))
	if err != nil || decision.State != PostureEnforcingDocument || len(decision.Overlay) != 2 || decision.OverlayFullThroughN != 0 ||
		len(decision.Alarms) != 0 {
		t.Fatalf("at the bound: %v, %v, overlay %+v, full %d, %v", err, decision.State, decision.Overlay, decision.OverlayFullThroughN,
			decision.Alarms)
	}
	third := grantRevoke(0x83)
	fourth := grantRevoke(0x84)
	decision, err = posture.ApplyDeltas(fixture.log(third, fourth))
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != fourth || decision.BridgeState != nil ||
		!decision.Changed || !decision.CompileWanted {
		t.Fatalf("past the bound: %v, %v, full %d, changed %v, compile wanted %v", err, decision.State, decision.OverlayFullThroughN,
			decision.Changed, decision.CompileWanted)
	}
	// one alarm a call, at the first denial it could not hold
	full := slices.DeleteFunc(slices.Clone(decision.Alarms), func(alarm PostureAlarm) bool {
		return alarm.Kind != PostureAlarmMalformed
	})
	if len(full) != 1 || full[0].N != third {
		t.Errorf("alarms %+v", decision.Alarms)
	}
	if held := posture.held; held.pinN != fourth || len(held.overlay) != 2 || held.statePinN() != 3 {
		t.Errorf("held: pin %d, overlay %+v, state at %d", held.pinN, held.overlay, held.statePinN())
	}
	fifth := grantRevoke(0x85)
	decision, err = posture.ApplyDeltas(fixture.log(fifth, fifth))
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != fifth {
		t.Fatalf("a later denial: %v, %v, full %d", err, decision.State, decision.OverlayFullThroughN)
	}
	// a restart restores it, with no alarm
	store = store.survivor()
	posture, decision = NewPosture(store, settings)
	if decision.State != PosturePending || decision.OverlayFullThroughN != fifth || len(decision.Alarms) != 0 {
		t.Fatalf("restored: %v, full %d, %v", decision.State, decision.OverlayFullThroughN, decision.Alarms)
	}
	// a state below the newest denial it could not hold leaves it pending, though it takes the state
	decision, err = posture.SetState(fixture.state(fourth, true), nil)
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != fifth || posture.held.statePinN() != fourth {
		t.Fatalf("a state below it: %v, %v, full %d", err, decision.State, decision.OverlayFullThroughN)
	}
	// a state at it restores enforcement, and the overlay holds a denial again
	decision, err = posture.SetState(fixture.state(fifth, true), nil)
	if err != nil || decision.State != PostureEnforcingDocument || decision.OverlayFullThroughN != 0 || len(decision.Overlay) != 0 ||
		!decision.Changed {
		t.Fatalf("a state at it: %v, %v, full %d, overlay %+v", err, decision.State, decision.OverlayFullThroughN, decision.Overlay)
	}
	sixth := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x7a))
	decision, err = posture.ApplyDeltas(fixture.log(sixth, sixth))
	if err != nil || decision.State != PostureEnforcingDocument || len(decision.Overlay) != 1 || decision.Overlay[0].N != sixth {
		t.Errorf("after it: %v, %v, overlay %+v", err, decision.State, decision.Overlay)
	}
	_, restored := NewPosture(store.survivor(), settings)
	if restored.State != PostureEnforcingDocument || restored.OverlayFullThroughN != 0 || len(restored.Alarms) != 0 {
		t.Errorf("restored after it: %v, full %d, %v", restored.State, restored.OverlayFullThroughN, restored.Alarms)
	}
}

// A stored full overlay's position at or before the state's pin, which that state would have cleared, is a store that
// does not verify: pending, with an alarm.
func TestAFullOverlayAtTheStateIsUnverified(t *testing.T) {
	fixture := newPostureFixture(t)
	settings := testPostureSettings()
	settings.OverlayMaxCount = 1
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	first := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	second := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x79))
	decision, err := posture.ApplyDeltas(fixture.log(first, second))
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != second {
		t.Fatalf("past the bound: %v, %v, full %d", err, decision.State, decision.OverlayFullThroughN)
	}
	manifest, err := decodePostureManifest(store.record(postureManifestName))
	if err != nil {
		t.Fatal(err)
	}
	// the positive twin: as written, it restores
	if _, restored := NewPosture(store.survivor(), settings); restored.State != PosturePending || restored.OverlayFullThroughN != second ||
		len(restored.Alarms) != 0 {
		t.Fatalf("as written: %v, full %d, %v", restored.State, restored.OverlayFullThroughN, restored.Alarms)
	}
	for _, n := range []uint64{3, 2} {
		changed := store.survivor()
		manifest.overlayFullThroughN = n
		changed.setRecord(postureManifestName, manifest.encode())
		_, restored := NewPosture(changed, settings)
		if restored.State != PosturePending || !postureAlarmed(restored, PostureAlarmStoreUnverified) {
			t.Errorf("a full overlay at %d: %v, %v", n, restored.State, restored.Alarms)
		}
	}
}

// A resync to a state below a denial the full overlay could not hold keeps the posture pending past the new pin, and
// a restart restores that with no alarm, as it restores the overlay entries a resync keeps; following on from the new
// pin, a state past the denial restores enforcement.
func TestAFullOverlayStandsPastAResyncedPin(t *testing.T) {
	fixture := newPostureFixture(t)
	settings := testPostureSettings()
	settings.OverlayMaxCount = 1
	store := newMemoryPostureStore()
	posture, _ := NewPosture(store, settings)
	fixture.base(fixture.ownerPhone, true)
	fixture.tick()
	fixture.tick()
	if _, err := posture.SetPending(fixture.pending()); err != nil {
		t.Fatal(err)
	}
	if _, err := posture.SetState(fixture.state(3, true), fixture.log(1, 3)); err != nil {
		t.Fatal(err)
	}
	first := fixture.sidecarRevoke(fixture.ownerPhone, fixture.aliceLaptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST)
	second := fixture.suspend(fixture.ownerPhone, fixture.agent.id, postureFixtureId(0x79))
	base := fixture.base(fixture.ownerPhone, true)
	decision, err := posture.ApplyDeltas(fixture.log(first, base))
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != second || posture.held.base.entry.GetN() != base {
		t.Fatalf("past the bound: %v, %v, full %d", err, decision.State, decision.OverlayFullThroughN)
	}
	// a state older than the newest base, on its own base's log, resyncs below the denial the overlay could not hold
	decision, err = posture.SetState(fixture.state(first, true), fixture.log(1, first))
	if err != nil || decision.State != PosturePending || decision.OverlayFullThroughN != second || posture.held.pinN != first {
		t.Fatalf("the resync: %v, %v, full %d, pin %d", err, decision.State, decision.OverlayFullThroughN, posture.held.pinN)
	}
	store = store.survivor()
	posture, decision = NewPosture(store, settings)
	if decision.State != PosturePending || decision.OverlayFullThroughN != second || len(decision.Alarms) != 0 {
		t.Fatalf("restored: %v, full %d, %v", decision.State, decision.OverlayFullThroughN, decision.Alarms)
	}
	if decision, err = posture.ApplyDeltas(fixture.log(second, base)); err != nil || decision.State != PosturePending {
		t.Fatalf("following on: %v, %v", err, decision.State)
	}
	decision, err = posture.SetState(fixture.state(base, true), nil)
	if err != nil || decision.State != PostureEnforcingDocument || decision.OverlayFullThroughN != 0 {
		t.Errorf("a state past it: %v, %v, full %d", err, decision.State, decision.OverlayFullThroughN)
	}
}
