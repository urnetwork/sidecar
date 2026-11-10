package sidecar

// CORE-M3-02's device list, and the authority and world §5.6's revocation tests and the recovery tests share: the
// act tests' authority with a member's bindings, cascades, suspensions, counted signatures, registered keys and entry
// times set as plain facts, as sidecartest.FakeAuthority holds them for other packages.

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

type revokeTestCascadeKey struct {
	targetId Id
	sinceN   uint64
}

// The act authority, with what §5.6's revocation and the recovery sealer read.
type revokeTestAuthority struct {
	*testActAuthority
	bindings   map[Id]*bridge.RecoveryBindingRow
	restored   map[Id]bool
	cascades   map[revokeTestCascadeKey][]DeviceRevokeItem
	suspended  map[Id]bool
	signatures map[Id]int
	keys       map[Id][]*bridge.KeyRow
	entryTimes map[uint64]time.Time
	// the types that need more than one counted signer, beside SidecarRevokes of a target with signatures > 1
	proposalTypes map[bridge.SignedType]bool
}

var (
	_ SidecarRevokeAuthority   = (*revokeTestAuthority)(nil)
	_ SidecarRecoveryAuthority = (*revokeTestAuthority)(nil)
	_ SidecarProposalAuthority = (*revokeTestAuthority)(nil)
)

func newRevokeTestAuthority(base *testActAuthority) *revokeTestAuthority {
	return &revokeTestAuthority{
		testActAuthority: base,
		bindings:         map[Id]*bridge.RecoveryBindingRow{},
		restored:         map[Id]bool{},
		cascades:         map[revokeTestCascadeKey][]DeviceRevokeItem{},
		suspended:        map[Id]bool{},
		signatures:       map[Id]int{},
		keys:             map[Id][]*bridge.KeyRow{},
		entryTimes:       map[uint64]time.Time{},
		proposalTypes:    map[bridge.SignedType]bool{},
	}
}

func (self *revokeTestAuthority) Admission(sidecarId Id) *AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admission := self.sidecars[sidecarId]
	if admission == nil {
		return nil
	}
	clone := *admission
	clone.Row = proto.Clone(admission.Row).(*bridge.SidecarRow)
	return &clone
}

func (self *revokeTestAuthority) CurrentBinding(memberId Id) *bridge.RecoveryBindingRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if binding := self.bindings[memberId]; binding != nil {
		return proto.Clone(binding).(*bridge.RecoveryBindingRow)
	}
	return nil
}

func (self *revokeTestAuthority) BindingRestored(memberId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.restored[memberId]
}

func (self *revokeTestAuthority) Cascade(targetId Id, sinceN uint64) ([]DeviceRevokeItem, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.cascades[revokeTestCascadeKey{targetId: targetId, sinceN: sinceN}]), nil
}

func (self *revokeTestAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	positions := []uint64{}
	for n := range self.entryTimes {
		positions = append(positions, n)
	}
	slices.Sort(positions)
	for _, n := range positions {
		if !self.entryTimes[n].Before(lostAt) {
			return n, self.entryTimes[n], true
		}
	}
	return 0, time.Time{}, false
}

func (self *revokeTestAuthority) ApprovalCapable(sidecarId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admission := self.sidecars[sidecarId]
	if admission == nil || 0 < len(admission.TagIds) || admission.Ephemeral || admission.Row.GetRevokedAt() != 0 ||
		admission.Row.GetParkedAt() != 0 || sidecarIsPageWorker(admission.Row.GetCapabilities()) {
		return false
	}
	return self.consents[[2]Id{sidecarId, admission.MemberId}] && !self.suspended[sidecarId]
}

func (self *revokeTestAuthority) Suspended(sidecarId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.suspended[sidecarId]
}

func (self *revokeTestAuthority) RevokeSignatures(targetId Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return max(1, self.signatures[targetId])
}

func (self *revokeTestAuthority) RegisteredKeys(sidecarId Id) []*bridge.KeyRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := slices.Clone(self.keys[sidecarId])
	slices.SortFunc(keys, func(a *bridge.KeyRow, b *bridge.KeyRow) int {
		return bytes.Compare(a.GetKeyId(), b.GetKeyId())
	})
	return keys
}

func (self *revokeTestAuthority) EntryTime(n uint64) (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entryTime, ok := self.entryTimes[n]
	return entryTime, ok
}

func (self *revokeTestAuthority) ProposalRequired(statement *SidecarStatement) bool {
	self.stateLock.Lock()
	byType := self.proposalTypes[statement.Type]
	self.stateLock.Unlock()
	if byType {
		return true
	}
	if statement.Type != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
		return false
	}
	revoke := &bridge.SidecarRevoke{}
	if err := proto.Unmarshal(statement.Body, revoke); err != nil {
		return false
	}
	targetId, err := IdFromBytes(revoke.GetSidecarId())
	return err == nil && 1 < self.RevokeSignatures(targetId)
}

// Changes the authority's facts under its lock.
func (self *revokeTestAuthority) edit(change func()) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	change()
}

// A sidecar past enrollment, its member's consented device, beside another device of the member, on the revoke
// authority and the scripted delta route.
type revokeTestWorld struct {
	sidecar   *Sidecar
	instance  *SidecarInstance
	authority *revokeTestAuthority
	deltaApi  *testDeltaApi
	clock     *identityTestClock
	events    *alarmTestEvents
	selfId    Id
	memberId  Id
	otherId   Id
	n         uint64
}

func newRevokeTestWorld(t *testing.T) *revokeTestWorld {
	t.Helper()
	sidecar, instance, _ := newIdentityTestSidecar(t)
	sidecar.instance = instance
	sidecar.clock = newIdentityTestClock()
	deltaApi := &testDeltaApi{}
	api, err := newSidecarApi(sidecar.settings, deltaApi, sidecar.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	api.SetByJwt("a-synthetic-client-token-for-the-revoke-tests")
	sidecar.sidecarApi = api
	if !sidecar.applyTransition(sidecarTransition{to: SidecarStateOffline, generation: 1}) {
		t.Fatal("no move to offline")
	}
	base := newTestActAuthority()
	world := &revokeTestWorld{
		sidecar:   sidecar,
		instance:  instance,
		authority: newRevokeTestAuthority(base),
		deltaApi:  deltaApi,
		clock:     sidecar.clock.(*identityTestClock),
		events:    &alarmTestEvents{},
		selfId:    sidecar.currentIdentity().SidecarId,
		memberId:  NewId(),
		otherId:   NewId(),
		n:         base.Pin().GetVersion(),
	}
	world.admit(world.selfId, world.memberId, 3)
	world.admit(world.otherId, world.memberId, 7)
	world.authority.edit(func() {
		world.authority.consents[[2]Id{world.selfId, world.memberId}] = true
		world.authority.entryTimes[world.n] = world.clock.Now()
	})
	t.Cleanup(sidecar.InstallAuthority(world.authority))
	t.Cleanup(sidecar.AddEventCallback(world.events.add))
	return world
}

// Puts a member device's admission, carried at position at, in the authority's state.
func (self *revokeTestWorld) admit(sidecarId Id, memberId Id, at uint64) {
	self.authority.edit(func() {
		self.authority.sidecars[sidecarId] = &AclSidecar{
			Row:      &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), MemberId: memberId.Bytes(), AdmittedAt: at},
			MemberId: memberId,
		}
	})
}

// Edits a sidecar's row, as a later entry would.
func (self *revokeTestWorld) editRow(sidecarId Id, edit func(row *bridge.SidecarRow)) {
	self.authority.edit(func() {
		edit(self.authority.sidecars[sidecarId].Row)
	})
}

// Applies the next entry with what it carries, after the clock moved on a minute.
func (self *revokeTestWorld) apply(edit func(entry *SidecarAuthorityEntry)) *SidecarAuthorityEntry {
	self.clock.advance(time.Minute)
	self.n += 1
	chain := sha256.Sum256([]byte{byte(self.n), byte(self.n >> 8)})
	entry := &SidecarAuthorityEntry{Pin: &bridge.AuthPin{Version: self.n, Chain: chain[:]}, TimeMs: self.clock.Now().UnixMilli(), Applied: true}
	if edit != nil {
		edit(entry)
	}
	self.authority.edit(func() {
		self.authority.entryTimes[self.n] = self.clock.Now()
	})
	self.authority.apply(entry)
	return entry
}

// The statements the delta route took, decoded.
func (self *revokeTestWorld) posted(t *testing.T) []*bridge.Signed {
	t.Helper()
	signeds := []*bridge.Signed{}
	for _, post := range self.deltaApi.postsSoFar() {
		signed := &bridge.Signed{}
		if err := proto.Unmarshal(post, signed); err != nil {
			t.Fatal(err)
		}
		signeds = append(signeds, signed)
	}
	return signeds
}

// Devices lists this member's admitted sidecars, this one first, each with the state the log gives it, and never
// another member's or a tagged one; Locked or Unenrolled answers FAILED_PRECONDITION.
func TestDevicesListsThisMembersSidecars(t *testing.T) {
	world := newRevokeTestWorld(t)
	parkedId, revokedId, suspendedId, workerId, burnerId := NewId(), NewId(), NewId(), NewId(), NewId()
	world.admit(parkedId, world.memberId, 9)
	world.editRow(parkedId, func(row *bridge.SidecarRow) { row.ParkedAt = 30 })
	world.admit(revokedId, world.memberId, 10)
	world.editRow(revokedId, func(row *bridge.SidecarRow) { row.RevokedAt = 31 })
	world.admit(suspendedId, world.memberId, 11)
	world.authority.edit(func() { world.authority.suspended[suspendedId] = true })
	world.admit(workerId, world.memberId, 12)
	world.editRow(workerId, func(row *bridge.SidecarRow) {
		row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	})
	world.admit(burnerId, world.memberId, 13)
	world.authority.edit(func() { world.authority.sidecars[burnerId].Ephemeral = true })
	// another member's device and a tagged agent this member sponsors are no devices of its
	world.admit(NewId(), NewId(), 14)
	agentId := NewId()
	world.authority.edit(func() {
		world.authority.sidecars[agentId] = &AclSidecar{Row: &bridge.SidecarRow{SidecarId: agentId.Bytes(), Sponsor: world.memberId.Bytes()}, TagIds: []Id{NewId()}}
	})

	devices, err := world.sidecar.Devices()
	if err != nil {
		t.Fatal(err)
	}
	wantStates := map[Id]string{
		world.selfId: MemberDeviceLive, world.otherId: MemberDeviceLive, parkedId: MemberDeviceParked,
		revokedId: MemberDeviceRevoked, suspendedId: MemberDevicePending, workerId: MemberDeviceLive, burnerId: MemberDeviceLive,
	}
	if len(devices) != len(wantStates) || !devices[0].This || devices[0].SidecarId != world.selfId {
		t.Fatalf("devices %+v", devices)
	}
	for index, device := range devices {
		if wantStates[device.SidecarId] != device.State || device.This != (index == 0) || !device.LastChange.IsZero() {
			t.Errorf("device %s: %+v", device.SidecarId, device)
		}
		if device.ReadOnly != (device.SidecarId == workerId) || device.Ephemeral != (device.SidecarId == burnerId) {
			t.Errorf("device %s flags: %+v", device.SidecarId, device)
		}
	}

	world.sidecar.applyTransition(sidecarTransition{to: SidecarStateUnenrolled, generation: 1})
	if _, err := world.sidecar.Devices(); err != ErrSidecarDevicesPrecondition {
		t.Errorf("unenrolled: %v", err)
	}
}
