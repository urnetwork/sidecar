//go:build !sidecar_http && !ios_extension

// What §8.10's contract gate reads, as a test outside the root writes it: FakeAclView, the narrow view of one state
// sidecar.NewAclState reads (sidecar.AclAuthView), built a member and a sidecar at a time, and
// FakeAclContractStates, a sidecar.AclContractStateSource of hand-made states standing in for the process's
// AclGateCache, which records each load the gate asks for. Server's TestCreateContractAcl* build on them, so a test of
// CreateContract can give a network any rows and admissions without a log. The rows stay the test's own: atoms,
// rules and targets as CompileAcl would write them (FakeAclSidecarAtom names a sidecar).
//
// Safe for concurrent use once built; a view must not change after a state is built from it.

package sidecartest

import (
	"crypto/sha256"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One state's admissions and members, as a test writes them.
type FakeAclView struct {
	stateLock sync.Mutex
	pin       *bridge.AuthPin
	sidecars  map[sidecar.Id]*sidecar.AclSidecar
	members   map[sidecar.Id]*bridge.MemberRow
	parked    map[sidecar.Id]bool
	sponsors  map[sidecar.Id]sidecar.Id
	position  uint64
}

var _ sidecar.AclAuthView = (*FakeAclView)(nil)

// A view at position 1, holding nothing and no genesis.
func NewFakeAclView() *FakeAclView {
	return &FakeAclView{
		pin:      &bridge.AuthPin{Version: 1, Chain: make([]byte, sha256.Size)},
		sidecars: map[sidecar.Id]*sidecar.AclSidecar{},
		members:  map[sidecar.Id]*bridge.MemberRow{},
		parked:   map[sidecar.Id]bool{},
		sponsors: map[sidecar.Id]sidecar.Id{},
		position: 1,
	}
}

// The next log position an admission takes.
func (self *FakeAclView) nextWithLock() uint64 {
	self.position += 1
	return self.position
}

// A member of role, its id.
func (self *FakeAclView) AddMember(role bridge.MemberRole) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	memberId := sidecar.NewId()
	self.members[memberId] = &bridge.MemberRow{MemberId: memberId.Bytes(), Role: role}
	return memberId
}

// An untagged sidecar of the member, admitted at the next position: a member device.
func (self *FakeAclView) AddDevice(memberId sidecar.Id) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecarId := sidecar.NewId()
	self.sidecars[sidecarId] = &sidecar.AclSidecar{
		Row:      &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: self.nextWithLock(), MemberId: memberId.Bytes()},
		MemberId: memberId,
	}
	return sidecarId
}

// A tagged sidecar its sponsor admitted at the next position, carrying tagIds. A rows' tag atom lists the sidecars
// that carry it, which the test writes into its rows.
func (self *FakeAclView) AddAgent(sponsorId sidecar.Id, tagIds ...sidecar.Id) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecarId := sidecar.NewId()
	self.sidecars[sidecarId] = &sidecar.AclSidecar{
		Row:    &bridge.SidecarRow{SidecarId: sidecarId.Bytes(), AdmittedAt: self.nextWithLock(), Sponsor: sponsorId.Bytes()},
		TagIds: slices.Clone(tagIds),
	}
	self.sponsors[sidecarId] = sponsorId
	return sidecarId
}

// Revokes a sidecar at the next position.
func (self *FakeAclView) Revoke(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if admission := self.sidecars[sidecarId]; admission != nil {
		admission.Row.RevokedAt = self.nextWithLock()
	}
}

// Parks a sidecar, as §7.9's compromise cascade does.
func (self *FakeAclView) Park(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.parked[sidecarId] = true
}

func (self *FakeAclView) Pin() *bridge.AuthPin {
	return self.pin
}

// None: no fake device signed a genesis, so §8.5's genesis clause consents none.
func (self *FakeAclView) Genesis() *bridge.Genesis {
	return nil
}

func (self *FakeAclView) SidecarIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sidecarIds := []sidecar.Id{}
	for sidecarId := range self.sidecars {
		sidecarIds = append(sidecarIds, sidecarId)
	}
	return sidecarIds
}

func (self *FakeAclView) Sidecar(sidecarId sidecar.Id) *sidecar.AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.sidecars[sidecarId]
}

func (self *FakeAclView) Member(memberId sidecar.Id) *bridge.MemberRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.members[memberId]
}

// No fake sidecar writes config heads.
func (self *FakeAclView) IsConfigWriter(sidecarId sidecar.Id) bool {
	return false
}

func (self *FakeAclView) Parked(sidecarId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.parked[sidecarId]
}

func (self *FakeAclView) Sponsor(sidecarId sidecar.Id) (sidecar.Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sponsorId, found := self.sponsors[sidecarId]
	return sponsorId, found
}

// No fake cascade voids anything.
func (self *FakeAclView) CascadeVoids(signer []byte, at uint64) bool {
	return false
}

// A derived sidecar:<id> atom row, as plan-ACL-nonsidecar-subjects derives a selector with no table name; its Atom is
// the id a rule's src or target names.
func FakeAclSidecarAtom(sidecarId sidecar.Id) *protocol.AclAtom {
	atom := sidecar.AclDerivedAtom(sidecar.AclDerivedAtomSidecar, sidecarId.Bytes())
	return &protocol.AclAtom{Atom: atom.Bytes(), SidecarIds: [][]byte{sidecarId.Bytes()}}
}

// Each network's verified state as a test installs it, a sidecar.AclContractStateSource. A network with none reads
// as the cache's unknown, and each load the gate asks for is kept.
type FakeAclContractStates struct {
	stateLock sync.Mutex
	snapshots map[sidecar.Id]*sidecar.AclGateSnapshot
	changed   []sidecar.Id
}

var _ sidecar.AclContractStateSource = (*FakeAclContractStates)(nil)

func NewFakeAclContractStates() *FakeAclContractStates {
	return &FakeAclContractStates{snapshots: map[sidecar.Id]*sidecar.AclGateSnapshot{}}
}

// Builds the network's state from rows and view and installs it in place of any before.
func (self *FakeAclContractStates) Install(networkId sidecar.Id, rows *protocol.AclRows, view sidecar.AclAuthView) error {
	state, err := sidecar.NewAclState(rows, view)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.snapshots[networkId] = &sidecar.AclGateSnapshot{Pin: view.Pin(), Acl: state}
	return nil
}

// Drops the network's state, so it reads as never loaded.
func (self *FakeAclContractStates) Remove(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.snapshots, networkId)
}

func (self *FakeAclContractStates) State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	snapshot := self.snapshots[networkId]
	if snapshot == nil {
		return nil, sidecar.AclGateUnknown
	}
	return snapshot, sidecar.AclGateLoaded
}

func (self *FakeAclContractStates) Changed(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.changed = append(self.changed, networkId)
}

// Each load the gate asked for, in order.
func (self *FakeAclContractStates) ChangedNetworks() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.changed)
}
