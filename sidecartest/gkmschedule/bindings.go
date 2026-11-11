package gkmschedule

// The world's recovery bindings and Delegations (§7.9's binding and delegation rows, §10.5's recovery(m) and
// delegation(d) holders, §10.8's recovery): what FS-20, FS-22, FS-18 and FS-102 add to the world.
//
//   - A binding is the member's recovery code's derived keys (§5.9's RecoveryKeys): its X-Wing key, which every
//     rotation wraps RK_g to while the binding is current, and its Ed25519 key's SHA-256, whose b8 names its wraps.
//     BindRecovery files the member's RecoveryBind, RebindRecovery a RecoveryRebind, whose compromise reason
//     shrinks every repo the member reads (§7.9's compromise clause). AddRecovered is the device the code admits,
//     standing in no state until AdmitRecovered.
//   - A Delegation carries its reader seed's X-Wing key, which every agent it admits and every copy of its bundle
//     holds, and one tag atom whose grants reach the world's repo. AddCoveredAgent admits an agent under it, which
//     reads through the Delegation's DelegationWrap while it covers; Suspend drops the Delegation's key (§10.5's
//     table), RevokeDelegation ends it, Reap tombstones a covered agent with no shrink, and each of the first two
//     is a shrink of every repo it reaches.

import (
	"bytes"
	"context"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One recovery binding of the world's member.
type FsKeysRecoveryBinding struct {
	Label      string
	PrivateKey hpke.PrivateKey
	// SHA-256 of the binding's Ed25519 key: b8 is its first 8 bytes.
	KeySha256 []byte
	signer    []byte
	at        uint64
	reason    bridge.RecoveryRebindReason
}

// The binding as recovery reads it.
func (self *FsKeysRecoveryBinding) Binding(memberId sidecar.Id) *sidecar.GkmRecoveryBinding {
	return &sidecar.GkmRecoveryBinding{MemberId: memberId, PrivateKey: self.PrivateKey, KeySha256: bytes.Clone(self.KeySha256)}
}

// The binding's public key, as the config publishes it for rotators and a rebind's re-wrap.
func (self *FsKeysRecoveryBinding) Key() *sidecar.GkmRecoveryKey {
	return &sidecar.GkmRecoveryKey{XwingPublicKey: self.PrivateKey.PublicKey().Bytes(), BindingKeySha256: bytes.Clone(self.KeySha256)}
}

// The member row's entry.
func (self *FsKeysRecoveryBinding) row() *bridge.RecoveryBindingRow {
	return &bridge.RecoveryBindingRow{KeySha256: bytes.Clone(self.KeySha256), Signer: bytes.Clone(self.signer), At: self.at, Reason: self.reason}
}

// A binding derived from label, deterministic, as a recovery code derives its keys.
func (self *FsKeysWorld) newBinding(label string, signer *FsKeysDevice, reason bridge.RecoveryRebindReason) *FsKeysRecoveryBinding {
	self.t.Helper()
	seed := sha256.Sum256([]byte("fs keys recovery seed of " + label))
	privateKey, err := sidecar.LoadGkmDelegationKey(seed[:])
	if err != nil {
		self.t.Fatal(err)
	}
	keySha256 := sha256.Sum256([]byte("fs keys recovery Ed25519 key of " + label))
	return &FsKeysRecoveryBinding{
		Label: label, PrivateKey: privateKey, KeySha256: keySha256[:], signer: signer.SidecarId().Bytes(), at: self.nextPosition(), reason: reason,
	}
}

// The member's RecoveryBind, signed by signer, at the next position: from it every rotation in a repo the member's
// devices read wraps to the binding (D-KEYS-18).
func (self *FsKeysWorld) BindRecovery(label string, signer *FsKeysDevice) *FsKeysRecoveryBinding {
	binding := self.newBinding(label, signer, bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_UNSPECIFIED)
	self.bindings = append([]*FsKeysRecoveryBinding{binding}, self.bindings...)
	return binding
}

// The member's RecoveryRebind to a new binding at the next position, signed by signer. A compromise rebind shrinks
// every repo the member reads there, so the next rotation of each is cause REMOVE; a routine one shrinks nothing.
func (self *FsKeysWorld) RebindRecovery(label string, signer *FsKeysDevice, compromise bool) *FsKeysRecoveryBinding {
	reason := bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_ROUTINE
	if compromise {
		reason = bridge.RecoveryRebindReason_RECOVERY_REBIND_REASON_COMPROMISE
	}
	binding := self.newBinding(label, signer, reason)
	self.bindings = append([]*FsKeysRecoveryBinding{binding}, self.bindings...)
	if compromise {
		self.shrink(binding.at, self.RepoId, self.ConfigRepoId)
	}
	return binding
}

// What the config publishes of a member's current binding for a rotator: the newest, for the world's member, nil for
// any other member or none.
func (self *FsKeysWorld) recoveryKey(memberId sidecar.Id) (*sidecar.GkmRecoveryKey, error) {
	if memberId != self.MemberId || len(self.bindings) == 0 {
		return nil, nil
	}
	return self.bindings[0].Key(), nil
}

// A member device of the world's member that binding's code admits (§5.6's recovery): its admission signed by the
// binding, so gkm takes its generation-0 self-join, and standing in no state until AdmitRecovered. It holds a real
// MLS engine, an empty store and keychain, and no ReaderKey yet.
func (self *FsKeysWorld) AddRecovered(label string, binding *FsKeysRecoveryBinding) *FsKeysDevice {
	self.t.Helper()
	device := self.admit(label)
	device.row.MemberId = self.MemberId.Bytes()
	device.row.AdmissionSigners = [][]byte{bytes.Clone(binding.KeySha256)}
	device.unadmitted = true
	device.Restart()
	return device
}

// The recovered device's SidecarAdmit lands at the next position.
func (self *FsKeysWorld) AdmitRecovered(device *FsKeysDevice) {
	position := self.nextPosition()
	device.unadmitted = false
	device.row.AdmittedAt = position
	device.row.LiveSince = position
}

// What CORE-M2-06 composes for a device binding's code admitted: its RecoverArgs, the anchor standing in for §7.9's
// check as the config group's generation gkm stores, whose commitment the opened key must be.
func (self *FsKeysWorld) RecoverArgs(binding *FsKeysRecoveryBinding) *sidecar.GkmRecoverArgs {
	return &sidecar.GkmRecoverArgs{
		Binding:      binding.Binding(self.MemberId),
		ConfigRepoId: self.ConfigRepoId,
		Anchor: func(ctx context.Context, key *sidecar.EvsRepoKey) error {
			stored := self.GenerationIn(self.ConfigGroupId, key.Generation())
			if !bytes.Equal(stored.Rotate.GetCommitment(), key.Commitment()) {
				return sidecar.ErrGkmRecoveryAnchor
			}
			return nil
		},
	}
}

// The b8s of the member's RecoveryWraps gkm holds of groupId's generation, by b8 in hex.
func (self *FsKeysWorld) RecoveryWrapBindings(groupId sidecar.Id, generation uint64) map[string]bool {
	self.t.Helper()
	prefix := gkmservice.GkmRecoveryMemberPrefix(self.MemberId) + sidecar.EvsKeyId(groupId) + "/"
	bindings := map[string]bool{}
	for key := range self.objects(prefix) {
		parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
		if len(parts) != 3 {
			continue
		}
		if number, err := parseFsKeysNumber(parts[0]); err == nil && number == generation {
			bindings[parts[2]] = true
		}
	}
	return bindings
}

// The b8 of a binding, in hex.
func (self *FsKeysRecoveryBinding) B8() string {
	return hex.EncodeToString(self.KeySha256[:8])
}

// The newest generation of groupId a binding's private key opens from every RecoveryWrap gkm holds, whatever
// binding path it lies at: what a code's derived keys reach.
func (self *FsKeysWorld) RecoveryReach(binding *FsKeysRecoveryBinding, groupId sidecar.Id) uint64 {
	self.t.Helper()
	prefix := gkmservice.GkmRecoveryMemberPrefix(self.MemberId) + sidecar.EvsKeyId(groupId) + "/"
	reach := uint64(0)
	for key, ciphertext := range self.objects(prefix) {
		parts := strings.Split(strings.TrimPrefix(key, prefix), "/")
		if len(parts) != 3 {
			continue
		}
		generation, err := parseFsKeysNumber(parts[0])
		if err != nil || generation <= reach || uint64(self.GenerationCountIn(groupId)) < generation {
			continue
		}
		args := &sidecar.GkmRecoveryArgs{
			MemberId: self.MemberId, GroupId: groupId, RecoveryPublicKey: binding.PrivateKey.PublicKey().Bytes(), BindingKeySha256: binding.KeySha256,
		}
		if _, err := sidecar.OpenGkmRecoveryWrap(ciphertext, self.GenerationIn(groupId, generation), args, binding.PrivateKey); err == nil {
			reach = generation
		}
	}
	return reach
}

// One Delegation of the world.
type FsKeysDelegation struct {
	Label string
	// 32 bytes
	Id []byte
	// the reader seed's X-Wing key, which its agents and every copy of its bundle hold
	ReaderPrivateKey hpke.PrivateKey
	row              *bridge.DelegationRow
	atom             sidecar.Id
}

// A Delegation signed by signer, an admin device, at the next position, valid until notAfter, reaching the world's
// repo through its one tag atom, and the config with every Delegation (§10.5's reach).
func (self *FsKeysWorld) AddDelegation(label string, signer *FsKeysDevice, notAfter time.Time) *FsKeysDelegation {
	self.t.Helper()
	id := sha256.Sum256([]byte("fs keys delegation " + label))
	seed := sha256.Sum256([]byte("fs keys delegation reader seed of " + label))
	readerPrivateKey, err := sidecar.LoadGkmDelegationKey(seed[:])
	if err != nil {
		self.t.Fatal(err)
	}
	signingKey := sha256.Sum256([]byte("fs keys delegation signing key of " + label))
	atom := sidecar.NewId()
	delegation := &FsKeysDelegation{
		Label:            label,
		Id:               id[:],
		ReaderPrivateKey: readerPrivateKey,
		atom:             atom,
		row: &bridge.DelegationRow{
			DelegationId:         id[:],
			Signer:               signer.SidecarId().Bytes(),
			At:                   self.nextPosition(),
			TagAtoms:             [][]byte{atom.Bytes()},
			NotAfter:             notAfter.UnixMilli(),
			Pubkey:               signingKey[:],
			ReaderXwingPublicKey: readerPrivateKey.PublicKey().Bytes(),
			MaxAdmits:            10,
		},
	}
	self.delegations = append(self.delegations, delegation)
	return delegation
}

// The Delegation's id in hex, as a d: wrap path names it.
func (self *FsKeysDelegation) Hex() string {
	return hex.EncodeToString(self.Id)
}

// An agent the Delegation admits, carrying its tags, which reads the repo through the Delegation's wrap while the
// Delegation covers it, and an ephemeral one with ephemeral.
func (self *FsKeysWorld) AddCoveredAgent(label string, delegation *FsKeysDelegation, ephemeral bool) *FsKeysDevice {
	self.t.Helper()
	device := self.admit(label)
	device.row.TagIds = [][]byte{delegation.atom.Bytes()}
	device.row.DelegationId = bytes.Clone(delegation.Id)
	device.row.AdmissionSigners = [][]byte{bytes.Clone(delegation.Id)}
	device.row.Ephemeral = ephemeral
	delegation.row.Admissions += 1
	device.Restart()
	return device
}

// The Delegation that admitted the device, nil for none.
func (self *FsKeysWorld) admittingDelegation(device *FsKeysDevice) *FsKeysDelegation {
	for _, delegation := range self.delegations {
		if bytes.Equal(delegation.Id, device.row.GetDelegationId()) {
			return delegation
		}
	}
	return nil
}

// A Suspend of device at the next position (§8.8): it reads and writes nothing until Unsuspend, and, for an agent a
// Delegation admitted, the Delegation's key drops there, a shrink of every repo it reaches (§10.5's table; owner
// decision 114). An uncovered sidecar's Suspend is a shrink of what it read.
func (self *FsKeysWorld) Suspend(device *FsKeysDevice) {
	at := self.nextPosition()
	self.suspended[device.SidecarId()] = true
	if delegation := self.admittingDelegation(device); delegation != nil && delegation.row.GetKeyDroppedAt() == 0 {
		delegation.row.KeyDroppedAt = at
	}
	self.shrink(at, self.RepoId, self.ConfigRepoId)
}

// An Unsuspend of device at the next position: it reads again, uncovered where its Delegation's key dropped, and no
// one is dropped (§10.6's never list).
func (self *FsKeysWorld) Unsuspend(device *FsKeysDevice) {
	delete(self.suspended, device.SidecarId())
}

// A DelegationRevoke of delegation at the next position: it ends there, its agents uncovered holders from then, a
// shrink of every repo it reached.
func (self *FsKeysWorld) RevokeDelegation(delegation *FsKeysDelegation) {
	at := self.nextPosition()
	delegation.row.EndedAt = at
	if delegation.row.GetKeyDroppedAt() == 0 {
		delegation.row.KeyDroppedAt = at
	}
	self.shrink(at, self.RepoId, self.ConfigRepoId)
}

// A SidecarRevoke{reason: compromise} of device from a since_n, at the next position, under the cascade's rule for a
// Delegation that admitted it (§10.5's table): the Delegation ends there, its later agents parked, the rest
// uncovered holders, a shrink of everything it reached. parkedAgents are the agents it admitted from since_n.
func (self *FsKeysWorld) RevokeForCompromise(device *FsKeysDevice, parkedAgents ...*FsKeysDevice) {
	at := self.nextPosition()
	if delegation := self.admittingDelegation(device); delegation != nil {
		delegation.row.EndedAt = at
		if delegation.row.GetKeyDroppedAt() == 0 {
			delegation.row.KeyDroppedAt = at
		}
	}
	for _, parked := range parkedAgents {
		parked.row.ParkedAt = at
	}
	self.Revoke(device)
}

// api's reap of an agent at the next position: a tombstone. A covered agent's reap drops no holder, so nothing
// shrinks; an uncovered one's is a shrink of what it read (§10.5's table).
func (self *FsKeysWorld) Reap(device *FsKeysDevice) {
	at := self.nextPosition()
	covered := false
	if delegation := self.admittingDelegation(device); delegation != nil {
		if tip := self.Log.Tip(); tip != nil {
			covered = sidecar.GkmCovered(tip, device.SidecarId(), self.RepoId, self.Clock.Now())
		}
	}
	device.row.RevokedAt = at
	drop := func(ids []sidecar.Id) []sidecar.Id {
		return slices.DeleteFunc(ids, func(id sidecar.Id) bool { return id == device.SidecarId() })
	}
	self.readers = drop(self.readers)
	self.writers = drop(self.writers)
	if !covered {
		self.shrink(at, self.RepoId, self.ConfigRepoId)
	}
}

// Whether the Delegation's reader key opens a DelegationWrap gkm holds of the repo's generation.
func (self *FsKeysWorld) DelegationOpens(delegation *FsKeysDelegation, generation uint64) bool {
	self.t.Helper()
	return self.opensDelivery(self.GroupId, generation, sidecar.GkmWrapTypeDelegation, delegation.Id, []hpke.PrivateKey{delegation.ReaderPrivateKey})
}

// The newest generation of the repo any of keys opens from every delivery gkm holds to device or, through its
// reader seed, to delegation, nil for none: what a party holding those keys reaches, its ladder opening only
// downward.
func (self *FsKeysWorld) KeysReach(device *FsKeysDevice, keys []hpke.PrivateKey, delegation *FsKeysDelegation) uint64 {
	self.t.Helper()
	reach := uint64(0)
	for generation := uint64(1); generation <= uint64(self.GenerationCount()); generation += 1 {
		if device != nil && self.opensDelivery(self.GroupId, generation, sidecar.GkmWrapTypeReader, device.SidecarId().Bytes(), keys) {
			reach = generation
		}
		if delegation != nil && self.opensDelivery(self.GroupId, generation, sidecar.GkmWrapTypeDelegation, delegation.Id, []hpke.PrivateKey{delegation.ReaderPrivateKey}) {
			reach = generation
		}
	}
	return reach
}

// A covered agent's read of a generation through its Delegation's wrap, at gkm's read route under its own token:
// gkm serves a covered agent the d: deliveries of the Delegation covering it (§10.6's read row), and the agent
// opens one with the reader seed. False when gkm serves none or none opens.
func (self *FsKeysWorld) CoveredRead(agent *FsKeysDevice, delegation *FsKeysDelegation, generation uint64) bool {
	self.t.Helper()
	if uint64(self.GenerationCount()) < generation {
		return false
	}
	reply, err := agent.Api.Wraps(self.Ctx, self.RepoId, self.GroupId, generation, &sidecar.GkmWrapsQuery{Recipient: "d:" + delegation.Hex()})
	if err != nil {
		return false
	}
	parsed := self.GenerationIn(self.GroupId, generation)
	for _, signed := range reply.GetWraps() {
		delivery, err := sidecar.ParseGkmDelivery(signed, sidecar.GkmWrapTypeDelegation, sidecar.GkmIdentityKeys(self.Log.Tip()))
		if err != nil {
			continue
		}
		if _, err := sidecar.OpenGkmDelivery(delivery, parsed, delegation.Id, delegation.ReaderPrivateKey); err == nil {
			return true
		}
	}
	return false
}

// A key number of gkm's object keys, its 20 digits read back.
func parseFsKeysNumber(segment string) (uint64, error) {
	var number uint64
	for _, c := range segment {
		if c < '0' || '9' < c {
			return 0, sidecar.ErrGkmMalformed
		}
		number = number*10 + uint64(c-'0')
	}
	if segment == "" {
		return 0, sidecar.ErrGkmMalformed
	}
	return number, nil
}

// The group's generation as the member's recovery wraps name it: whether gkm holds a RecoveryWrap of it to binding.
func (self *FsKeysWorld) HoldsRecoveryWrap(groupId sidecar.Id, generation uint64, binding *FsKeysRecoveryBinding) bool {
	return self.RecoveryWrapBindings(groupId, generation)[binding.B8()]
}

// gen/<generation>'s statement with its holders counted at the pin it names, as a member recomputes them.
func (self *FsKeysWorld) GenerationHolders(groupId sidecar.Id, repoId sidecar.Id, generation uint64) sidecar.GkmHolders {
	self.t.Helper()
	rotate := self.GenerationIn(groupId, generation).Rotate
	state, err := self.Log.Tip().At(rotate.GetAuth())
	if err != nil {
		self.t.Fatalf("gen/%d's pin: %v", generation, err)
	}
	holders, err := sidecar.KeyHolders(state, repoId, time.UnixMilli(rotate.GetTimeMs()))
	if err != nil {
		self.t.Fatal(err)
	}
	return holders
}
