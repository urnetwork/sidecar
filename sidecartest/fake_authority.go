// sidecar.SidecarAuthority faked (CORE-M2-01, C-10): §7.9's verified state as a device act reads it, held as plain
// facts a test sets, so §5's M2-M3 tasks run before TEAM's ConfigClient follows a real log. Each answer is the fact as
// set, never a rule re-derived here, except PresenceRequired's default, which reads §7.9's covers list (TEAM-M2-06's
// Build line) over the live keys set, so an act test gets the log's answer without writing the rule itself; a test
// that needs another sets SetPresenceRule.
//
// Apply moves the pin and calls every entry callback in order, as TEAM-M2-10's follower does once per applied entry.
// Safe for concurrent use; callbacks run on Apply's goroutine, outside the lock.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One sidecar's admission facts, which AdmitSidecar takes.
type FakeAuthorityAdmission struct {
	SidecarId sidecar.Id
	// Zero for a tagged sidecar.
	MemberId sidecar.Id
	TagIds   []sidecar.Id
	// The SidecarAdmit's signers, each a sidecar_id's bytes, a recovery key's hash or a delegation_id.
	Signers   [][]byte
	Ephemeral bool
	// SidecarCapability bits: read_only, invited.
	Capabilities      uint32
	IdentityPublicKey []byte
	// ms since the epoch; agents only. Zero for none.
	NotAfter int64
}

// One entry of the fake's retained tail, for ProposedSince.
type fakeAuthorityEntryTime struct {
	n      uint64
	timeMs int64
}

// The fake. Construct with NewFakeAuthority.
type FakeAuthority struct {
	callbacks *sidecar.CallbackList[sidecar.SidecarAuthorityEntryFunction]

	stateLock    sync.Mutex
	pin          *bridge.AuthPin
	sidecars     map[sidecar.Id]*sidecar.AclSidecar
	consents     map[[2]sidecar.Id]bool
	bindings     map[sidecar.Id]*bridge.RecoveryBindingRow
	liveKeys     map[sidecar.Id][]*bridge.KeyRow
	cascades     map[fakeAuthorityCascadeKey][]sidecar.DeviceRevokeItem
	entryTimes   []fakeAuthorityEntryTime
	presenceRule func(statement *sidecar.SidecarStatement, liveKeys []*bridge.KeyRow) bool
	// what CatchUp runs, and how many times it has
	catchUp      func(ctx context.Context) error
	catchUpCount int
	// the open proposals and settings PendingProposal and Settings answer (DESIGN-DETAILS 5.7)
	pendingProposals map[string]*bridge.ProposalRow
	settings         *bridge.ProjectionSettings
	// what §5.6's device revocation reads (sidecar.SidecarRevokeAuthority), and the recovery sealer
	suspended        map[sidecar.Id]bool
	revokeSignatures map[sidecar.Id]int
	registeredKeys   map[sidecar.Id][]*bridge.KeyRow
	restoredBindings map[sidecar.Id]bool
	proposalRule     func(statement *sidecar.SidecarStatement) bool
}

type fakeAuthorityCascadeKey struct {
	targetId sidecar.Id
	sinceN   uint64
}

var (
	_ sidecar.SidecarAuthority          = (*FakeAuthority)(nil)
	_ sidecar.SidecarAuthorityCatchUp   = (*FakeAuthority)(nil)
	_ sidecar.SidecarAuthorityProposals = (*FakeAuthority)(nil)
	_ sidecar.SidecarRevokeAuthority    = (*FakeAuthority)(nil)
	_ sidecar.SidecarRecoveryAuthority  = (*FakeAuthority)(nil)
	_ sidecar.SidecarProposalAuthority  = (*FakeAuthority)(nil)
)

// An authority at pin (0, chain) holding nothing.
func NewFakeAuthority() *FakeAuthority {
	return &FakeAuthority{
		callbacks: sidecar.NewCallbackList[sidecar.SidecarAuthorityEntryFunction](),
		pin:       &bridge.AuthPin{Version: 0, Chain: make([]byte, sha256.Size)},
		sidecars:  map[sidecar.Id]*sidecar.AclSidecar{},
		consents:  map[[2]sidecar.Id]bool{},
		bindings:  map[sidecar.Id]*bridge.RecoveryBindingRow{},
		liveKeys:  map[sidecar.Id][]*bridge.KeyRow{},
		cascades:  map[fakeAuthorityCascadeKey][]sidecar.DeviceRevokeItem{},

		pendingProposals: map[string]*bridge.ProposalRow{},
		settings:         &bridge.ProjectionSettings{},
		suspended:        map[sidecar.Id]bool{},
		revokeSignatures: map[sidecar.Id]int{},
		registeredKeys:   map[sidecar.Id][]*bridge.KeyRow{},
		restoredBindings: map[sidecar.Id]bool{},
	}
}

// Sets whether an active Suspend names the sidecar.
func (self *FakeAuthority) SetSuspended(sidecarId sidecar.Id, suspended bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.suspended[sidecarId] = suspended
}

// Sets the counted signatures a SidecarRevoke of targetId needs: k for an AdminSet member's device. 1 until set.
func (self *FakeAuthority) SetRevokeSignatures(targetId sidecar.Id, signatures int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.revokeSignatures[targetId] = signatures
}

// Registers a presence or SSH key the sidecar signed the KeyRegister of, still registered.
func (self *FakeAuthority) AddRegisteredKey(sidecarId sidecar.Id, key *bridge.KeyRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.registeredKeys[sidecarId] = append(self.registeredKeys[sidecarId], proto.Clone(key).(*bridge.KeyRow))
}

// Drops a registered key, as its KeyRevoke applied would.
func (self *FakeAuthority) RemoveRegisteredKey(sidecarId sidecar.Id, keyId []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.registeredKeys[sidecarId] = slices.DeleteFunc(self.registeredKeys[sidecarId], func(key *bridge.KeyRow) bool {
		return bytes.Equal(key.GetKeyId(), keyId)
	})
}

// Sets whether the member's binding in effect is one a cascade void restored.
func (self *FakeAuthority) SetBindingRestored(memberId sidecar.Id, restored bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.restoredBindings[memberId] = restored
}

// Sets ProposalRequired's rule: whether a statement needs more than one counted signer. nil, the default, answers
// from SetRevokeSignatures for a SidecarRevoke and false for anything else.
func (self *FakeAuthority) SetProposalRule(rule func(statement *sidecar.SidecarStatement) bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.proposalRule = rule
}

// sidecar.SidecarRevokeAuthority: consented for its member, untagged, not ephemeral, not read_only, not revoked or
// parked, and not suspended, from the facts set.
func (self *FakeAuthority) ApprovalCapable(sidecarId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admission := self.sidecars[sidecarId]
	if admission == nil || admission.Row == nil || 0 < len(admission.TagIds) || admission.Ephemeral ||
		admission.Row.GetRevokedAt() != 0 || admission.Row.GetParkedAt() != 0 ||
		admission.Row.GetCapabilities()&uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY) != 0 {
		return false
	}
	return self.consents[[2]sidecar.Id{sidecarId, admission.MemberId}] && !self.suspended[sidecarId]
}

// sidecar.SidecarRevokeAuthority: the fact SetSuspended set.
func (self *FakeAuthority) Suspended(sidecarId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.suspended[sidecarId]
}

// sidecar.SidecarRevokeAuthority: the count SetRevokeSignatures set, 1 until one is.
func (self *FakeAuthority) RevokeSignatures(targetId sidecar.Id) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return max(1, self.revokeSignatures[targetId])
}

// sidecar.SidecarRevokeAuthority: the keys AddRegisteredKey set, by key_id.
func (self *FakeAuthority) RegisteredKeys(sidecarId sidecar.Id) []*bridge.KeyRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	keys := []*bridge.KeyRow{}
	for _, key := range self.registeredKeys[sidecarId] {
		keys = append(keys, proto.Clone(key).(*bridge.KeyRow))
	}
	slices.SortFunc(keys, func(a *bridge.KeyRow, b *bridge.KeyRow) int {
		return bytes.Compare(a.GetKeyId(), b.GetKeyId())
	})
	return keys
}

// sidecar.SidecarRevokeAuthority: the time of the entry Apply retained at n.
func (self *FakeAuthority) EntryTime(n uint64) (time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entry := range self.entryTimes {
		if entry.n == n {
			return time.UnixMilli(entry.timeMs), true
		}
	}
	return time.Time{}, false
}

// sidecar.SidecarRecoveryAuthority: the fact SetBindingRestored set.
func (self *FakeAuthority) BindingRestored(memberId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.restoredBindings[memberId]
}

// sidecar.SidecarProposalAuthority: SetProposalRule's answer, or by default whether a SidecarRevoke's target needs
// more than one counted signature.
func (self *FakeAuthority) ProposalRequired(statement *sidecar.SidecarStatement) bool {
	self.stateLock.Lock()
	rule := self.proposalRule
	self.stateLock.Unlock()
	if rule != nil {
		return rule(statement)
	}
	if statement.Type != bridge.SignedType_SIGNED_SIDECAR_REVOKE {
		return false
	}
	revoke := &bridge.SidecarRevoke{}
	if err := proto.Unmarshal(statement.Body, revoke); err != nil {
		return false
	}
	targetId, err := sidecar.IdFromBytes(revoke.GetSidecarId())
	return err == nil && 1 < self.RevokeSignatures(targetId)
}

// Sets a proposal open at the newest state, as a follower that applied its AuthorityProposal would; nil closes it.
func (self *FakeAuthority) SetPendingProposal(proposalId []byte, row *bridge.ProposalRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if row == nil {
		delete(self.pendingProposals, string(proposalId))
		return
	}
	self.pendingProposals[string(proposalId)] = proto.Clone(row).(*bridge.ProposalRow)
}

// Sets the settings a verifier judges by.
func (self *FakeAuthority) SetSettings(settings *bridge.ProjectionSettings) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.settings = proto.Clone(settings).(*bridge.ProjectionSettings)
}

// sidecar.SidecarAuthorityProposals: the row SetPendingProposal set, nil for none.
func (self *FakeAuthority) PendingProposal(proposalId []byte) *bridge.ProposalRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row := self.pendingProposals[string(proposalId)]
	if row == nil {
		return nil
	}
	return proto.Clone(row).(*bridge.ProposalRow)
}

// sidecar.SidecarAuthorityProposals: the settings SetSettings set, the defaults until one does.
func (self *FakeAuthority) Settings() *bridge.ProjectionSettings {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return proto.Clone(self.settings).(*bridge.ProjectionSettings)
}

// §7.9's presence row's covered statements (TEAM-M2-06's Build line): a statement of one of these types, of an
// untagged sidecar where that matters, signed by a sidecar holding a live presence key, needs a check. The fake judges
// the type alone; a test that needs a target's tags judged sets SetPresenceRule.
var fakeAuthorityPresenceTypes = map[bridge.SignedType]bool{
	bridge.SignedType_SIGNED_SIDECAR_REVOKE:     true,
	bridge.SignedType_SIGNED_KEY_REGISTER:       true,
	bridge.SignedType_SIGNED_KEY_REVOKE:         true,
	bridge.SignedType_SIGNED_SUSPEND:            true,
	bridge.SignedType_SIGNED_RECOVERY_VETO:      true,
	bridge.SignedType_SIGNED_SIDECAR_ADMIT:      true,
	bridge.SignedType_SIGNED_ADMISSION_CONFIRM:  true,
	bridge.SignedType_SIGNED_OWNER_CONFIRM:      true,
	bridge.SignedType_SIGNED_ADMIN_SET:          true,
	bridge.SignedType_SIGNED_MEMBER_REVOKE:      true,
	bridge.SignedType_SIGNED_RECOVERY_BIND:      true,
	bridge.SignedType_SIGNED_RECOVERY_REBIND:    true,
	bridge.SignedType_SIGNED_AUTHORITY_PROPOSAL: true,
	bridge.SignedType_SIGNED_AUTHORITY_COSIGN:   true,
	bridge.SignedType_SIGNED_DELEGATION_REVOKE:  true,
}

// The newest pin.
func (self *FakeAuthority) Pin() *bridge.AuthPin {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return &bridge.AuthPin{Version: self.pin.GetVersion(), Chain: bytes.Clone(self.pin.GetChain())}
}

// Sets the pin, as a follower verifying a new entry would.
func (self *FakeAuthority) SetPin(pin *bridge.AuthPin) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pin = &bridge.AuthPin{Version: pin.GetVersion(), Chain: bytes.Clone(pin.GetChain())}
}

// A copy of an admission, sharing nothing.
func cloneFakeAdmission(admission *sidecar.AclSidecar) *sidecar.AclSidecar {
	if admission == nil {
		return nil
	}
	clone := *admission
	clone.TagIds = slices.Clone(admission.TagIds)
	if admission.Row != nil {
		clone.Row = cloneSidecarRow(admission.Row)
	}
	return &clone
}

// A deep copy of a row, its confirmations and cascade spans included.
func cloneSidecarRow(row *bridge.SidecarRow) *bridge.SidecarRow {
	return proto.Clone(row).(*bridge.SidecarRow)
}

// Admits a sidecar at the current pin's next position, as a SidecarAdmit applied there. Returns its row's position.
func (self *FakeAuthority) AdmitSidecar(admission *FakeAuthorityAdmission) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	at := self.pin.GetVersion() + 1
	row := &bridge.SidecarRow{
		SidecarId:         admission.SidecarId.Bytes(),
		AdmittedAt:        at,
		Capabilities:      admission.Capabilities,
		NotAfter:          admission.NotAfter,
		IdentityPublicKey: bytes.Clone(admission.IdentityPublicKey),
		IdentityAlg:       "ed25519",
		Ephemeral:         admission.Ephemeral,
		LiveSince:         at,
	}
	for _, signer := range admission.Signers {
		row.AdmissionSigners = append(row.AdmissionSigners, bytes.Clone(signer))
	}
	aclSidecar := &sidecar.AclSidecar{Row: row, Ephemeral: admission.Ephemeral}
	if 0 < len(admission.TagIds) {
		for _, tagId := range admission.TagIds {
			row.TagIds = append(row.TagIds, tagId.Bytes())
		}
		aclSidecar.TagIds = slices.Clone(admission.TagIds)
	} else {
		row.MemberId = admission.MemberId.Bytes()
		aclSidecar.MemberId = admission.MemberId
	}
	self.sidecars[admission.SidecarId] = aclSidecar
	return at
}

// Edits a sidecar's row in place, as a later entry would: a revocation, a park, a confirmation.
func (self *FakeAuthority) EditSidecar(sidecarId sidecar.Id, edit func(row *bridge.SidecarRow)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	admission := self.sidecars[sidecarId]
	if admission == nil {
		return
	}
	next := cloneFakeAdmission(admission)
	edit(next.Row)
	self.sidecars[sidecarId] = next
}

// Sets §8.5's consented(d, M).
func (self *FakeAuthority) SetConsented(sidecarId sidecar.Id, memberId sidecar.Id, consented bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.consents[[2]sidecar.Id{sidecarId, memberId}] = consented
}

// Sets a member's recovery binding in effect; nil removes it.
func (self *FakeAuthority) SetCurrentBinding(memberId sidecar.Id, binding *bridge.RecoveryBindingRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if binding == nil {
		delete(self.bindings, memberId)
		return
	}
	self.bindings[memberId] = binding
}

// Registers a live presence key of a sidecar.
func (self *FakeAuthority) AddLiveKey(sidecarId sidecar.Id, key *bridge.KeyRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.liveKeys[sidecarId] = append(self.liveKeys[sidecarId], key)
}

// Drops a sidecar's live presence keys.
func (self *FakeAuthority) ClearLiveKeys(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.liveKeys, sidecarId)
}

// Sets the cascade a compromise revocation of targetId from sinceN derives.
func (self *FakeAuthority) SetCascade(targetId sidecar.Id, sinceN uint64, items []sidecar.DeviceRevokeItem) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.cascades[fakeAuthorityCascadeKey{targetId: targetId, sinceN: sinceN}] = slices.Clone(items)
}

// Replaces PresenceRequired's rule. nil restores the default, the covers list over the signer's live keys.
func (self *FakeAuthority) SetPresenceRule(rule func(statement *sidecar.SidecarStatement, liveKeys []*bridge.KeyRow) bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.presenceRule = rule
}

// Applies entry: its pin becomes the authority's, its time joins the retained tail, and every callback sees it, in
// order, outside the lock.
func (self *FakeAuthority) Apply(entry *sidecar.SidecarAuthorityEntry) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry.Pin != nil {
			self.pin = &bridge.AuthPin{Version: entry.Pin.GetVersion(), Chain: bytes.Clone(entry.Pin.GetChain())}
			self.entryTimes = append(self.entryTimes, fakeAuthorityEntryTime{n: entry.Pin.GetVersion(), timeMs: entry.TimeMs})
		}
	}()
	for _, callback := range self.callbacks.Get() {
		callback(entry)
	}
}

func (self *FakeAuthority) Admission(sidecarId sidecar.Id) *sidecar.AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return cloneFakeAdmission(self.sidecars[sidecarId])
}

func (self *FakeAuthority) MemberDevices(memberId sidecar.Id) []*sidecar.AclSidecar {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	devices := []*sidecar.AclSidecar{}
	for _, admission := range self.sidecars {
		if len(admission.TagIds) == 0 && admission.MemberId == memberId {
			devices = append(devices, cloneFakeAdmission(admission))
		}
	}
	slices.SortFunc(devices, func(a *sidecar.AclSidecar, b *sidecar.AclSidecar) int {
		return bytes.Compare(a.Row.GetSidecarId(), b.Row.GetSidecarId())
	})
	return devices
}

func (self *FakeAuthority) Consented(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.consents[[2]sidecar.Id{sidecarId, memberId}]
}

func (self *FakeAuthority) CurrentBinding(memberId sidecar.Id) *bridge.RecoveryBindingRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	binding := self.bindings[memberId]
	if binding == nil {
		return nil
	}
	return &bridge.RecoveryBindingRow{
		KeySha256: bytes.Clone(binding.GetKeySha256()),
		Signer:    bytes.Clone(binding.GetSigner()),
		At:        binding.GetAt(),
		Reason:    binding.GetReason(),
	}
}

func (self *FakeAuthority) PresenceRequired(statement *sidecar.SidecarStatement) bool {
	self.stateLock.Lock()
	rule := self.presenceRule
	liveKeys := slices.Clone(self.liveKeys[statement.SignerId])
	self.stateLock.Unlock()
	if rule != nil {
		return rule(statement, liveKeys)
	}
	return 0 < len(liveKeys) && fakeAuthorityPresenceTypes[statement.Type]
}

func (self *FakeAuthority) LiveKeys(sidecarId sidecar.Id) []*bridge.KeyRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.liveKeys[sidecarId])
}

func (self *FakeAuthority) Cascade(targetId sidecar.Id, sinceN uint64) ([]sidecar.DeviceRevokeItem, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.cascades[fakeAuthorityCascadeKey{targetId: targetId, sinceN: sinceN}]), nil
}

func (self *FakeAuthority) ProposedSince(lostAt time.Time) (uint64, time.Time, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, entry := range self.entryTimes {
		if lostAt.UnixMilli() <= entry.timeMs {
			return entry.n, time.UnixMilli(entry.timeMs), true
		}
	}
	return 0, time.Time{}, false
}

func (self *FakeAuthority) AddEntryCallback(callback sidecar.SidecarAuthorityEntryFunction) func() {
	callbackId := self.callbacks.Add(callback)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.callbacks.Remove(callbackId)
		})
	}
}

// Sets what CatchUp runs: a test admits a sidecar there, as a follower that applied a late entry would. nil
// restores the default, which applies nothing.
func (self *FakeAuthority) SetCatchUp(catchUp func(ctx context.Context) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.catchUp = catchUp
}

// sidecar.SidecarAuthorityCatchUp: runs what SetCatchUp gave, outside the lock, counting each call.
func (self *FakeAuthority) CatchUp(ctx context.Context) error {
	var catchUp func(ctx context.Context) error
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.catchUpCount += 1
		catchUp = self.catchUp
	}()
	if catchUp == nil {
		return nil
	}
	return catchUp(ctx)
}

// How many times CatchUp has run.
func (self *FakeAuthority) CatchUpCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.catchUpCount
}
