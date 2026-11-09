package sidecar

// CORE-M2-03: §5.6's alarm row on a device, each clause a top-level test on a hand-moved clock, the entries' verdicts
// as TEAM-M2-05 would give them: admission_alarm and approval_pending, recovery_rebind, recovery_window and
// recovery_unseen (FS-16's device rows: a backdated proposal and a late veto), admissions_near_cap, a component's
// relayed alarm, Status's HeadCheck half, and an alarm raised once across a restart.

import (
	"crypto/sha256"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Collects a sidecar's events.
type alarmTestEvents struct {
	stateLock sync.Mutex
	events    []SidecarEvent
}

func (self *alarmTestEvents) add(event SidecarEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.events = append(self.events, event)
}

// The events of kind so far.
func (self *alarmTestEvents) of(kind SidecarEventKind) []SidecarEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	events := []SidecarEvent{}
	for _, event := range self.events {
		if event.Kind == kind {
			events = append(events, event)
		}
	}
	return events
}

// A member device of member M on an act authority, with its events collected, and M's other device.
type alarmTestWorld struct {
	sidecar   *Sidecar
	authority *testActAuthority
	events    *alarmTestEvents
	clock     *identityTestClock
	memberId  Id
	otherId   Id
	n         uint64
}

func newAlarmTestWorld(t *testing.T) *alarmTestWorld {
	t.Helper()
	sidecar, authority, _ := newActTestSidecar(t)
	world := &alarmTestWorld{
		sidecar:   sidecar,
		authority: authority,
		events:    &alarmTestEvents{},
		clock:     sidecar.clock.(*identityTestClock),
		memberId:  NewId(),
		otherId:   NewId(),
		n:         authority.Pin().GetVersion(),
	}
	identity := sidecar.currentIdentity()
	world.admit(identity.SidecarId, world.memberId)
	world.admit(world.otherId, world.memberId)
	t.Cleanup(sidecar.AddEventCallback(world.events.add))
	return world
}

// Puts a member device's admission in the authority's state.
func (self *alarmTestWorld) admit(sidecarId Id, memberId Id) {
	self.authority.stateLock.Lock()
	defer self.authority.stateLock.Unlock()
	self.authority.sidecars[sidecarId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), MemberId: memberId.Bytes()}, MemberId: memberId}
}

// Applies the next entry with what it carries.
func (self *alarmTestWorld) apply(edit func(entry *SidecarAuthorityEntry)) *SidecarAuthorityEntry {
	self.n += 1
	chain := sha256.Sum256([]byte{byte(self.n), byte(self.n >> 8)})
	entry := &SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: self.n, Chain: chain[:]}, TimeMs: self.clock.Now().UnixMilli(), Applied: true}
	if edit != nil {
		edit(entry)
	}
	self.authority.apply(entry)
	return entry
}

// A SidecarAdmit effect admitting sidecarId under memberId, signed by signers.
func alarmTestAdmit(t *testing.T, sidecarId Id, memberId Id, signers ...ConfigSigner) *SidecarAuthorityEffect {
	t.Helper()
	body, err := proto.Marshal(&protocol.SidecarAdmit{SidecarId: sidecarId.Bytes(), MemberId: memberId.Bytes()})
	if err != nil {
		t.Fatal(err)
	}
	return &SidecarAuthorityEffect{Type: bridge.SignedType_SIGNED_SIDECAR_ADMIT, Body: body, Signers: signers}
}

// A sidecar signer.
func alarmTestSigner(sidecarId Id) ConfigSigner {
	return ConfigSigner{Kind: ConfigSignerSidecar, SidecarId: sidecarId}
}

// §5.6's alarm row: an admission under this device's member that none of its devices signed, an admin's included,
// raises admission_alarm, and approval_pending beside it while the member has not consented; one its other device
// signed raises neither; an admission under another member is not this device's.
func TestAdmissionAlarmForAnAdmissionNoDeviceSigned(t *testing.T) {
	world := newAlarmTestWorld(t)
	adminDevice := NewId()
	byAdmin := NewId()
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, byAdmin, world.memberId, alarmTestSigner(adminDevice))}
	})
	alarms := world.events.of(SidecarEventAdmissionAlarm)
	if len(alarms) != 1 || alarms[0].SidecarId == nil || *alarms[0].SidecarId != byAdmin {
		t.Fatalf("admission alarms %+v", alarms)
	}
	if pending := world.events.of(SidecarEventApprovalPending); len(pending) != 1 || *pending[0].SidecarId != byAdmin || pending[0].ApprovalId == nil {
		t.Errorf("approval_pending %+v", pending)
	}

	bySelf := NewId()
	world.authority.stateLock.Lock()
	world.authority.consents[[2]Id{bySelf, world.memberId}] = true
	world.authority.stateLock.Unlock()
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, bySelf, world.memberId, alarmTestSigner(world.otherId))}
	})
	otherMember := NewId()
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, NewId(), otherMember, alarmTestSigner(adminDevice))}
	})
	if alarms := world.events.of(SidecarEventAdmissionAlarm); len(alarms) != 1 {
		t.Errorf("%d admission alarms", len(alarms))
	}
	if pending := world.events.of(SidecarEventApprovalPending); len(pending) != 1 {
		t.Errorf("%d approval_pending", len(pending))
	}
}

// Every recovery-key admission under the member raises admission_alarm, a recovery key being no device of the
// member's (§22.7's admission suite).
func TestRecoveryKeyAdmissionAlarms(t *testing.T) {
	world := newAlarmTestWorld(t)
	recovered := NewId()
	keyHash := sha256.Sum256([]byte("a recovery key"))
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, recovered, world.memberId, ConfigSigner{Kind: ConfigSignerRecovery, MemberId: world.memberId, RecoveryKeySha256: keyHash[:]})}
	})
	if alarms := world.events.of(SidecarEventAdmissionAlarm); len(alarms) != 1 || *alarms[0].SidecarId != recovered {
		t.Errorf("%+v", alarms)
	}
}

// Each of the member's devices alarms on a RecoveryRebind of its member it did not sign, another device of the
// member's included, and on a binding of its member a cascade voids; its own rebind raises nothing.
func TestRecoveryRebindAlarm(t *testing.T) {
	world := newAlarmTestWorld(t)
	rebind := func(signer Id) *SidecarAuthorityEffect {
		keyHash := sha256.Sum256(signer.Bytes())
		body, err := proto.Marshal(&protocol.RecoveryRebind{MemberId: world.memberId.Bytes(), Ed25519PublicKeySha256: keyHash[:]})
		if err != nil {
			t.Fatal(err)
		}
		return &SidecarAuthorityEffect{Type: bridge.SignedType_SIGNED_RECOVERY_REBIND, Body: body, Signers: []ConfigSigner{alarmTestSigner(signer)}}
	}
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{rebind(world.otherId)}
	})
	alarms := world.events.of(SidecarEventRecoveryRebind)
	if len(alarms) != 1 || alarms[0].SidecarId == nil || *alarms[0].SidecarId != world.otherId {
		t.Fatalf("%+v", alarms)
	}
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{rebind(world.sidecar.currentIdentity().SidecarId)}
	})
	if alarms := world.events.of(SidecarEventRecoveryRebind); len(alarms) != 1 {
		t.Errorf("its own rebind alarmed: %d", len(alarms))
	}
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.VoidedBindings = []SidecarVoidedBinding{{MemberId: world.memberId, KeySha256: make([]byte, 32), Signer: world.otherId.Bytes()}}
	})
	if alarms := world.events.of(SidecarEventRecoveryRebind); len(alarms) != 2 {
		t.Errorf("a voided binding: %d alarms", len(alarms))
	}
}

// A window from its start p: recovery_window while pending, and on activation a full 72 h after this device applied p
// no recovery_unseen.
func TestRecoveryWindowRunsItsCourse(t *testing.T) {
	world := newAlarmTestWorld(t)
	proposalId := sha256.Sum256([]byte("a proposal"))
	start := world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: proposalId[:], State: SidecarRecoveryWindowPending, Start: world.n + 1, MemberId: world.memberId, RecoverySigned: true}}
	}).Pin.GetVersion()
	if windows := world.events.of(SidecarEventRecoveryWindow); len(windows) != 1 {
		t.Fatalf("%d recovery_window", len(windows))
	}
	world.clock.advance(72 * time.Hour)
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: proposalId[:], State: SidecarRecoveryWindowActivated, Start: start, MemberId: world.memberId}}
	})
	if unseen := world.events.of(SidecarEventRecoveryUnseen); len(unseen) != 0 {
		t.Errorf("%d recovery_unseen after a full window", len(unseen))
	}
}

// FS-16's device rows: a proposal api backdated 72 h activates almost as soon as this device applied p, which by its
// own clock is under 72 h minus 10 min, so recovery_unseen; and a valid veto this device first verifies only after
// applying the activation raises it too.
func TestBackdatedProposalAndLateVetoRaiseRecoveryUnseen(t *testing.T) {
	world := newAlarmTestWorld(t)
	recovered := NewId()
	backdated := sha256.Sum256([]byte("a backdated proposal"))
	world.apply(func(entry *SidecarAuthorityEntry) {
		// api's time says three days ago; this device applies p now
		entry.TimeMs = world.clock.Now().Add(-72 * time.Hour).UnixMilli()
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: backdated[:], State: SidecarRecoveryWindowPending, Start: world.n + 1, MemberId: world.memberId, SidecarId: &recovered}}
	})
	world.clock.advance(time.Minute)
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: backdated[:], State: SidecarRecoveryWindowActivated, MemberId: world.memberId, SidecarId: &recovered}}
	})
	unseen := world.events.of(SidecarEventRecoveryUnseen)
	if len(unseen) != 1 || unseen[0].SidecarId == nil || *unseen[0].SidecarId != recovered {
		t.Fatalf("backdated: %+v", unseen)
	}

	vetoed := sha256.Sum256([]byte("a vetoed proposal"))
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: vetoed[:], State: SidecarRecoveryWindowPending, Start: world.n + 1, MemberId: world.memberId}}
	})
	world.clock.advance(80 * time.Hour)
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: vetoed[:], State: SidecarRecoveryWindowActivated, MemberId: world.memberId}}
	})
	if unseen := world.events.of(SidecarEventRecoveryUnseen); len(unseen) != 1 {
		t.Fatalf("a full window alarmed: %d", len(unseen))
	}
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Windows = []SidecarRecoveryWindow{{ProposalId: vetoed[:], State: SidecarRecoveryWindowVetoed, MemberId: world.memberId}}
	})
	if unseen := world.events.of(SidecarEventRecoveryUnseen); len(unseen) != 2 {
		t.Errorf("a late veto: %d recovery_unseen", len(unseen))
	}
}

// Admin devices raise admissions_near_cap from 90% of config_admissions, once each time the count rises past it.
func TestAdmissionsNearCapOnAdminDevices(t *testing.T) {
	world := newAlarmTestWorld(t)
	near := func(count int, admins []Id) {
		world.apply(func(entry *SidecarAuthorityEntry) {
			entry.AdmissionCount = count
			entry.AdmissionCap = 10
			entry.AdminMemberIds = admins
		})
	}
	near(9, nil)
	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 0 {
		t.Fatal("a non-admin device alarmed")
	}
	admins := []Id{world.memberId}
	near(8, admins)
	near(9, admins)
	near(9, admins)
	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 1 {
		t.Fatalf("%d at 9 of 10", len(raised))
	}
	near(10, admins)
	if raised := world.events.of(SidecarEventAdmissionsNearCap); len(raised) != 2 {
		t.Errorf("%d at 10 of 10", len(raised))
	}
}

// What has been raised persists with the newest entry applied, so a follower that delivers an entry again after a
// restart raises nothing twice, and the next entry still alarms.
func TestAlarmSurvivesRestartOnce(t *testing.T) {
	world := newAlarmTestWorld(t)
	byAdmin := NewId()
	entry := world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, byAdmin, world.memberId, alarmTestSigner(NewId()))}
	})
	// a restart: the watcher subscribes again, and the follower redelivers from its own persisted pin
	remove := world.sidecar.InstallAuthority(world.authority)
	defer remove()
	world.authority.apply(entry)
	if alarms := world.events.of(SidecarEventAdmissionAlarm); len(alarms) != 1 {
		t.Fatalf("%d alarms after a redelivery", len(alarms))
	}
	world.apply(func(entry *SidecarAuthorityEntry) {
		entry.Effects = []*SidecarAuthorityEffect{alarmTestAdmit(t, NewId(), world.memberId, alarmTestSigner(NewId()))}
	})
	if alarms := world.events.of(SidecarEventAdmissionAlarm); len(alarms) != 2 {
		t.Errorf("%d alarms after the next entry", len(alarms))
	}
}

// A component's head_alarm reaches the sidecar's events with both pins as Evidence and no path; §5.6's own kinds are
// the watcher's, refused from a component.
func TestHeadAlarmRelaysWithBothPins(t *testing.T) {
	world := newAlarmTestWorld(t)
	peerId := NewId()
	err := world.sidecar.Alarm(SidecarEvent{Kind: SidecarEventHeadAlarm, HeadAlarm: SidecarHeadAlarmFork, SidecarId: &peerId, Evidence: [2][]byte{[]byte("mine"), []byte("theirs")}, Path: "a/local/path"})
	if err != nil {
		t.Fatal(err)
	}
	alarms := world.events.of(SidecarEventHeadAlarm)
	if len(alarms) != 1 || string(alarms[0].Evidence[1]) != "theirs" || alarms[0].Path != "" {
		t.Fatalf("%+v", alarms)
	}
	if err := world.sidecar.Alarm(SidecarEvent{Kind: SidecarEventAdmissionAlarm}); err == nil {
		t.Error("a component raised admission_alarm")
	}
}

// §6.4's state as Status shows it.
type testHeadCheckStatus struct {
	witnessedAt time.Time
	unverified  [][]byte
}

func (self *testHeadCheckStatus) WitnessedAt() time.Time {
	return self.witnessedAt
}

func (self *testHeadCheckStatus) Unverified() [][]byte {
	return self.unverified
}

// Status adds witnessed_at and the UNVERIFIED pins as AuthPin bytes from the installed §6.4 state, and nothing once
// it is removed.
func TestStatusShowsWitnessedAtAndUnverified(t *testing.T) {
	world := newAlarmTestWorld(t)
	pin, _ := proto.Marshal(&bridge.AuthPin{Version: 9, Chain: make([]byte, 32)})
	headCheck := &testHeadCheckStatus{witnessedAt: world.clock.Now(), unverified: [][]byte{pin}}
	remove := world.sidecar.InstallHeadCheckStatus(headCheck)
	status := world.sidecar.Status()
	if !status.WitnessedAt.Equal(headCheck.witnessedAt) || len(status.Unverified) != 1 || !slices.Equal(status.Unverified[0], pin) {
		t.Fatalf("%+v", status)
	}
	remove()
	if status := world.sidecar.Status(); !status.WitnessedAt.IsZero() || len(status.Unverified) != 0 {
		t.Errorf("%+v", status)
	}
}
