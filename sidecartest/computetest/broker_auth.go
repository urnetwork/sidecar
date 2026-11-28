// computetest.FakeComputeAuthState (CTEST-M12-01; DESIGN-COMPUTE §14.2's Auth row, §16.4, §16.6): the broker's newest
// verified authorization state as a test sets it, computeservice.ComputeAuthState's fake, which the real one reads from
// the process's AclGateCache and rev/ (auth_state.go). A test sets what the log would say, never a bypass:
//
//	networks   each loaded or not, with the authorization features its newest base turns on (§16.6); an unloaded
//	           network answers unknown, which the broker answers 503 and never allows
//	members    each with its role (§8.2's MemberRole)
//	sidecars   each admitted in one network: an untagged one's member, or a tagged one's tags, its consent, the
//	           admission flags (read_only, ephemeral, Delegation-admitted, capability bit 3) and its standing (parked,
//	           suspended, past its not_after), every one of which a broker reads from the row
//	rev/       subjects a rev/ object voids, and a fault that makes rev/ unreadable
//	compute    the network's compute block (§16.4), which ComputePolicy views with §16.5's defaults, and its budget
//	           lines, which BudgetLines answers beside §16.5's defaults, standing in for CACL's resolver (C§16.4)
//
// Every answer of the state is three-valued as the real one's: a sidecar the state does not hold, one of another
// network, a removed or parked or suspended one, or an untagged one whose member is gone, is denied; only a held
// admission is allowed. The state keeps no snapshot (ComputeCaller.Snapshot is nil), so an area that reads the
// projection from the caller reads it as unknown, as the real state's absence reads.
//
// Safe for concurrent use: one lock guards the state, and no method calls out while holding it.

package computetest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/computeservice"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	// A test asked the state for a network, member or sidecar it does not hold.
	ErrFakeComputeAuthUnknown = errors.New("computetest: the fake auth state holds no such network, member or sidecar")
	// A test added what the state holds already, or a sidecar the state cannot admit: an untagged one naming no
	// member of its network, a tagged one naming a member.
	ErrFakeComputeAuthInvalid = errors.New("computetest: the fake auth state cannot hold that")
)

// One admitted sidecar as a test sets it.
type FakeComputeSidecar struct {
	SidecarId sidecar.Id
	ClientId  sidecar.Id
	// An untagged admission's member; the zero id for a tagged one.
	MemberId sidecar.Id
	// A tagged admission's opaque tag ids; empty for an untagged one.
	TagIds []sidecar.Id
	// §8.5's consent: one of its member's consented devices.
	Consented bool
	// Capability bit 1: a page Worker's admission.
	ReadOnly  bool
	Ephemeral bool
	// Admitted under a Delegation.
	DelegationAdmitted bool
	// Capability bit 3: an enclave incarnation.
	EnclaveIncarnation bool
	// Its standing: a parked or suspended sidecar, or one past its not_after, is no admission a broker honors.
	Parked    bool
	Suspended bool
	// The zero time for none.
	NotAfter time.Time
}

// One network the state holds.
type fakeComputeNetwork struct {
	loaded   bool
	features computeservice.ComputeAuthFeatures
	// members by id, each with its role
	memberIdRoles map[sidecar.Id]bridge.MemberRole
	block         *sidecar.AclComputeBlock
	// the policy's budgets as CACL's resolver would give them
	budgetLines []*model.ComputeBudgetLine
}

// The state's settings (QD-702).
type FakeComputeAuthStateSettings struct {
	// The ledger's, whose default budgets (§16.5) BudgetLines answers beside the policy's. Nil takes
	// model.DefaultComputeLedgerSettings.
	Ledger *model.ComputeLedgerSettings
}

// The defaults, the only place one is set.
func DefaultFakeComputeAuthStateSettings() *FakeComputeAuthStateSettings {
	return &FakeComputeAuthStateSettings{
		Ledger: model.DefaultComputeLedgerSettings(),
	}
}

// See the file header.
type FakeComputeAuthState struct {
	settings *FakeComputeAuthStateSettings
	clock    sidecar.Clock

	stateLock        sync.Mutex
	networks         map[sidecar.Id]*fakeComputeNetwork
	sidecarIdSidecar map[sidecar.Id]*FakeComputeSidecar
	// each sidecar's network
	sidecarIdNetworkId map[sidecar.Id]sidecar.Id
	// subjects a rev/ object voids: a client, a sidecar or a member
	revokedSubjectIds map[sidecar.Id]bool
	// rev/ cannot be read: every CheckRevocation answers it
	revocationFault error
	// how many times Caller was asked
	callerCount int
}

var _ computeservice.ComputeAuthState = (*FakeComputeAuthState)(nil)

// A state holding nothing, judging not_after on clock (nil: a FakeClock at sidecartest.DefaultClockStart) under settings
// (nil: the defaults).
func NewFakeComputeAuthState(settings *FakeComputeAuthStateSettings, clock sidecar.Clock) *FakeComputeAuthState {
	if settings == nil {
		settings = DefaultFakeComputeAuthStateSettings()
	}
	if settings.Ledger == nil {
		withLedger := *settings
		withLedger.Ledger = model.DefaultComputeLedgerSettings()
		settings = &withLedger
	}
	if clock == nil {
		clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	}
	return &FakeComputeAuthState{
		settings:           settings,
		clock:              clock,
		networks:           map[sidecar.Id]*fakeComputeNetwork{},
		sidecarIdSidecar:   map[sidecar.Id]*FakeComputeSidecar{},
		sidecarIdNetworkId: map[sidecar.Id]sidecar.Id{},
		revokedSubjectIds:  map[sidecar.Id]bool{},
	}
}

// The network's entry, made where absent. Called with the lock.
func (self *FakeComputeAuthState) networkWithLock(networkId sidecar.Id) *fakeComputeNetwork {
	network, ok := self.networks[networkId]
	if !ok {
		network = &fakeComputeNetwork{memberIdRoles: map[sidecar.Id]bridge.MemberRole{}}
		self.networks[networkId] = network
	}
	return network
}

// Loads networkId's state with the features its newest base turns on, as the gate cache does once it has read the
// network's head; a network held already keeps its members and sidecars.
func (self *FakeComputeAuthState) LoadNetwork(networkId sidecar.Id, features computeservice.ComputeAuthFeatures) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	network.loaded = true
	network.features = features
}

// Forgets that networkId's state is loaded, as a cold cache holds none: its members and sidecars stay for a later
// load.
func (self *FakeComputeAuthState) UnloadNetwork(networkId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if network, ok := self.networks[networkId]; ok {
		network.loaded = false
	}
}

// Adds memberId to networkId with role, or sets the role of a member held already.
func (self *FakeComputeAuthState) SetMember(networkId sidecar.Id, memberId sidecar.Id, role bridge.MemberRole) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).memberIdRoles[memberId] = role
}

// Removes memberId from networkId, as a member's removal does: its sidecars stay admitted in the rows until their own
// removal, and the broker denies them, since no member names them.
func (self *FakeComputeAuthState) RemoveMember(networkId sidecar.Id, memberId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if network, ok := self.networks[networkId]; ok {
		delete(network.memberIdRoles, memberId)
	}
}

// Admits admitted in networkId: an untagged sidecar names a member the network holds, a tagged one names none. A
// sidecar held already is replaced, so a test changes a flag by admitting it again.
func (self *FakeComputeAuthState) Admit(networkId sidecar.Id, admitted *FakeComputeSidecar) error {
	if admitted == nil || admitted.SidecarId == (sidecar.Id{}) || admitted.ClientId == (sidecar.Id{}) {
		return fmt.Errorf("%w: a sidecar needs its id and its client's", ErrFakeComputeAuthInvalid)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network := self.networkWithLock(networkId)
	tagged := 0 < len(admitted.TagIds)
	switch {
	case tagged && admitted.MemberId != (sidecar.Id{}):
		return fmt.Errorf("%w: a tagged sidecar names no member", ErrFakeComputeAuthInvalid)
	case !tagged:
		if _, ok := network.memberIdRoles[admitted.MemberId]; !ok {
			return fmt.Errorf("%w: an untagged sidecar names a member of its network", ErrFakeComputeAuthInvalid)
		}
	}
	if otherNetworkId, ok := self.sidecarIdNetworkId[admitted.SidecarId]; ok && otherNetworkId != networkId {
		return fmt.Errorf("%w: the sidecar is admitted in another network", ErrFakeComputeAuthInvalid)
	}
	copied := *admitted
	copied.TagIds = slices.Clone(admitted.TagIds)
	self.sidecarIdSidecar[admitted.SidecarId] = &copied
	self.sidecarIdNetworkId[admitted.SidecarId] = networkId
	return nil
}

// Removes sidecarId's admission, as a SidecarRevoke does.
func (self *FakeComputeAuthState) Remove(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.sidecarIdSidecar, sidecarId)
	delete(self.sidecarIdNetworkId, sidecarId)
}

// Changes sidecarId's row with change, under the lock: its standing, consent or flags. ErrFakeComputeAuthUnknown for
// a sidecar the state does not hold.
func (self *FakeComputeAuthState) Change(sidecarId sidecar.Id, change func(admitted *FakeComputeSidecar)) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admitted, ok := self.sidecarIdSidecar[sidecarId]
	if !ok {
		return ErrFakeComputeAuthUnknown
	}
	change(admitted)
	return nil
}

// A copy of sidecarId's row, nil for none.
func (self *FakeComputeAuthState) Sidecar(sidecarId sidecar.Id) *FakeComputeSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admitted, ok := self.sidecarIdSidecar[sidecarId]
	if !ok {
		return nil
	}
	copied := *admitted
	copied.TagIds = slices.Clone(admitted.TagIds)
	return &copied
}

// Voids every token of subjectId, a client, sidecar or member, as a rev/ object for it does (§7.8).
func (self *FakeComputeAuthState) Revoke(subjectId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revokedSubjectIds[subjectId] = true
}

// Makes rev/ unreadable, so every CheckRevocation answers err, which the broker answers 503; nil reads it again.
func (self *FakeComputeAuthState) SetRevocationFault(err error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revocationFault = err
}

// Sets networkId's compute block (§16.4), nil for none, which ComputePolicy views with §16.5's defaults.
func (self *FakeComputeAuthState) SetComputeBlock(networkId sidecar.Id, block *sidecar.AclComputeBlock) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).block = block
}

// The view of networkId's compute block, under the network's compute_policy feature as its state stands:
// sidecar.ErrComputePolicyUnread for a network whose state is not loaded, as a device that has not read its head
// answers.
func (self *FakeComputeAuthState) ComputePolicy(networkId sidecar.Id) (*sidecar.ComputePolicyView, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network, ok := self.networks[networkId]
	if !ok || !network.loaded {
		return nil, sidecar.ErrComputePolicyUnread
	}
	featureOn := network.features&computeservice.ComputeAuthFeatureComputePolicy != 0
	return sidecar.NewComputePolicyView(network.block, featureOn), nil
}

// Sets networkId's policy budgets, each a subject's day or month cap, as CACL's resolver reads them from the block's
// budgets (§16.4); nil for none.
func (self *FakeComputeAuthState) SetBudgetLines(networkId sidecar.Id, lines []*model.ComputeBudgetLine) {
	copied := make([]*model.ComputeBudgetLine, 0, len(lines))
	for _, line := range lines {
		lineCopy := *line
		copied = append(copied, &lineCopy)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.networkWithLock(networkId).budgetLines = copied
}

// The budget lines an operation's subjects count to (controller.ComputeBudgetLines): §16.5's defaults by sidecar and
// agent, which bind whatever the policy says (§16.4), then the policy's lines whose subject is the operation's
// sidecar, agent, member or network. ErrFakeComputeAuthUnknown for a network the state does not hold, so no hold
// passes a budget the state was never told.
func (self *FakeComputeAuthState) BudgetLines(ctx context.Context, subjects *controller.ComputeBudgetSubjects) ([]*model.ComputeBudgetLine, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if subjects == nil {
		return nil, ErrFakeComputeAuthInvalid
	}
	tagged, policyLines, err := func() (bool, []*model.ComputeBudgetLine, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		network, ok := self.networks[subjects.NetworkId]
		if !ok {
			return false, nil, ErrFakeComputeAuthUnknown
		}
		tagged := false
		if admitted, ok := self.sidecarIdSidecar[subjects.SidecarId]; ok {
			tagged = 0 < len(admitted.TagIds)
		}
		subjectIds := []sidecar.Id{subjects.NetworkId, subjects.SidecarId}
		if subjects.AgentId != nil {
			subjectIds = append(subjectIds, *subjects.AgentId)
		}
		if subjects.MemberId != nil {
			subjectIds = append(subjectIds, *subjects.MemberId)
		}
		lines := []*model.ComputeBudgetLine{}
		for _, line := range network.budgetLines {
			if slices.Contains(subjectIds, line.SubjectId) {
				lineCopy := *line
				lines = append(lines, &lineCopy)
			}
		}
		return tagged, lines, nil
	}()
	if err != nil {
		return nil, err
	}
	lines, err := model.ComputeDefaultBudgetLines(self.settings.Ledger, &model.ComputeBudgetCaller{
		SidecarId: subjects.SidecarId,
		AgentId:   subjects.AgentId,
		Tagged:    tagged,
	})
	if err != nil {
		return nil, err
	}
	return append(lines, policyLines...), nil
}

// How many times Caller was asked.
func (self *FakeComputeAuthState) CallerCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.callerCount
}

// See computeservice.ComputeAuthState: ErrComputeTokenRevoked where a rev/ object voids the token's client, sidecar
// or member, the fault where one is set.
func (self *FakeComputeAuthState) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if principal == nil {
		return ErrFakeComputeAuthInvalid
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.revocationFault != nil {
		return self.revocationFault
	}
	subjectIds := []sidecar.Id{sidecar.Id(principal.ClientId)}
	if principal.SidecarId != nil {
		subjectIds = append(subjectIds, sidecar.Id(*principal.SidecarId))
	}
	if principal.MemberId != nil {
		subjectIds = append(subjectIds, sidecar.Id(*principal.MemberId))
	}
	for _, subjectId := range subjectIds {
		if self.revokedSubjectIds[subjectId] {
			return computeservice.ErrComputeTokenRevoked
		}
	}
	return nil
}

// See computeservice.ComputeAuthState and the file header.
func (self *FakeComputeAuthState) Caller(principal *sidecar.Principal) (*computeservice.ComputeCaller, computeservice.ComputeAuthAnswer) {
	if principal == nil {
		return nil, computeservice.ComputeAuthUnknown
	}
	now := self.clock.Now()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.callerCount += 1
	networkId := sidecar.Id(principal.NetworkId)
	network, ok := self.networks[networkId]
	if !ok || !network.loaded {
		return nil, computeservice.ComputeAuthUnknown
	}
	if principal.SidecarId == nil {
		return nil, computeservice.ComputeAuthDenied
	}
	sidecarId := sidecar.Id(*principal.SidecarId)
	admitted, ok := self.sidecarIdSidecar[sidecarId]
	if !ok || self.sidecarIdNetworkId[sidecarId] != networkId || admitted.Parked || admitted.Suspended {
		return nil, computeservice.ComputeAuthDenied
	}
	if !admitted.NotAfter.IsZero() && !now.Before(admitted.NotAfter) {
		return nil, computeservice.ComputeAuthDenied
	}
	caller := &computeservice.ComputeCaller{
		Principal:          principal,
		NetworkId:          networkId,
		ClientId:           sidecar.Id(principal.ClientId),
		SidecarId:          sidecarId,
		TagIds:             slices.Clone(admitted.TagIds),
		Consented:          admitted.Consented,
		ReadOnly:           admitted.ReadOnly,
		Ephemeral:          admitted.Ephemeral,
		DelegationAdmitted: admitted.DelegationAdmitted,
		EnclaveIncarnation: admitted.EnclaveIncarnation,
	}
	if len(admitted.TagIds) == 0 {
		role, ok := network.memberIdRoles[admitted.MemberId]
		if !ok {
			// an untagged admission whose member is gone is no admission
			return nil, computeservice.ComputeAuthDenied
		}
		caller.MemberId = admitted.MemberId
		caller.Role = role
	}
	return caller, computeservice.ComputeAuthAllowed
}

// See computeservice.ComputeAuthState: the features networkId's newest base turns on, unknown for a network whose
// state is not loaded.
func (self *FakeComputeAuthState) Features(networkId sidecar.Id) (computeservice.ComputeAuthFeatures, computeservice.ComputeAuthAnswer) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	network, ok := self.networks[networkId]
	if !ok || !network.loaded {
		return 0, computeservice.ComputeAuthUnknown
	}
	return network.features, computeservice.ComputeAuthAllowed
}
