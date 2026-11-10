// Devices (CORE-M3-02, D-CORE-20, §5.4): this member's admitted sidecars as `ur devices` and §18.5's GetDevices list
// them, and what §5.6's device revocation reads of §7.9's verified state beyond SidecarAuthority's own methods.
//
// Every fact is the log's, read through the installed authority, never re-derived here (C-01): a device is a sidecar
// whose untagged admission names this sidecar's member, page Workers and quick burners, parked, stale and
// admin-admitted ones included, revoked tombstones too; its State is revoked, parked, pending (a Suspend holds it,
// as while its revocation awaits cosigns), or live. stale and LastChange are the device's newest leaf change in a
// group this device is a leaf of, which KEYS-M4-01's group view supplies; until it does, no row is stale and every
// LastChange is zero.
//
// On every leg: root Id, no connect type.

package sidecar

import (
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// MemberDevice.State's values.
const (
	MemberDeviceLive    = "live"
	MemberDevicePending = "pending"
	MemberDeviceParked  = "parked"
	MemberDeviceStale   = "stale"
	MemberDeviceRevoked = "revoked"
)

// §5.4's FAILED_PRECONDITION of Devices, PreviewDeviceRevoke and RevokeDevice: this sidecar is Locked or Unenrolled,
// or holds no identity.
var ErrSidecarDevicesPrecondition = errors.New("FAILED_PRECONDITION: this sidecar is locked or unenrolled")

// What §5.6's device list and revocation read of §7.9's state beyond SidecarAuthority: TEAM's adapter answers each
// from ConfigState, and sidecartest.FakeAuthority as a test sets it. Optional beside SidecarAuthority, as C-10 fixes
// that interface's methods; an authority without it lists devices with no suspension or time, and revokes nothing
// (REVOKE_NOT_CAPABLE), since whether this device is approval-capable and unsuspended is then unknown.
type SidecarRevokeAuthority interface {
	// §16.6's approval-capable device at the newest state: consented, untagged, not ephemeral, not read_only and not
	// suspended (AclState.ApprovalCapable).
	ApprovalCapable(sidecarId Id) bool
	// Whether an active Suspend names the sidecar (ConfigState.Suspended).
	Suspended(sidecarId Id) bool
	// The counted signatures a SidecarRevoke of targetId needs: 1, or k for an AdminSet member's device (§7.9's
	// authority and counted rows).
	RevokeSignatures(targetId Id) int
	// Every presence or SSH key the sidecar registered that is still registered (KeyRow.signer), by key_id.
	RegisteredKeys(sidecarId Id) []*bridge.KeyRow
	// api's time for entry n, from the retained entries; false for one not retained.
	EntryTime(n uint64) (time.Time, bool)
}

// The state the log gives a device's row, before any group view speaks.
func memberDeviceState(admission *AclSidecar, suspended bool) string {
	switch {
	case admission.Row.GetRevokedAt() != 0:
		return MemberDeviceRevoked
	case admission.Row.GetParkedAt() != 0:
		return MemberDeviceParked
	case suspended:
		return MemberDevicePending
	}
	return MemberDeviceLive
}

// Whether this sidecar is past Locked and Unenrolled and holds an identity: what §5.6's device calls need.
func (self *Sidecar) devicesReady() (*SidecarIdentity, error) {
	state := func() SidecarState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.lifecycle.state
	}()
	identity := self.currentIdentity()
	if identity == nil || state == SidecarStateLocked || state == SidecarStateUnenrolled {
		return nil, ErrSidecarDevicesPrecondition
	}
	return identity, nil
}

// This member's admitted sidecars, this one first, then by admission position and id. ErrSidecarDevicesPrecondition
// while Locked or Unenrolled; ErrSidecarActNoAuthority while no verified state is installed. A tagged sidecar has no
// member's devices and lists itself alone.
func (self *Sidecar) Devices() ([]MemberDevice, error) {
	identity, err := self.devicesReady()
	if err != nil {
		return nil, err
	}
	authority := self.authority()
	if authority == nil {
		return nil, ErrSidecarActNoAuthority
	}
	own := authority.Admission(identity.SidecarId)
	if own == nil || own.Row == nil {
		return []MemberDevice{}, nil
	}
	revokes, _ := authority.(SidecarRevokeAuthority)
	device := func(admission *AclSidecar) MemberDevice {
		sidecarId, _ := IdFromBytes(admission.Row.GetSidecarId())
		memberDevice := MemberDevice{
			SidecarId: sidecarId,
			This:      sidecarId == identity.SidecarId,
			ReadOnly:  sidecarIsPageWorker(admission.Row.GetCapabilities()),
			Ephemeral: admission.Ephemeral,
			State:     memberDeviceState(admission, revokes != nil && revokes.Suspended(sidecarId)),
		}
		if revokes != nil {
			if admittedAt, ok := revokes.EntryTime(admission.Row.GetAdmittedAt()); ok {
				memberDevice.AdmittedAt = admittedAt
			}
		}
		return memberDevice
	}
	if 0 < len(own.TagIds) {
		return []MemberDevice{device(own)}, nil
	}
	admissions := []*AclSidecar{}
	for _, admission := range authority.MemberDevices(own.MemberId) {
		if admission != nil && admission.Row != nil && len(admission.TagIds) == 0 {
			admissions = append(admissions, admission)
		}
	}
	slices.SortStableFunc(admissions, func(a *AclSidecar, b *AclSidecar) int {
		if a.Row.GetAdmittedAt() != b.Row.GetAdmittedAt() {
			if a.Row.GetAdmittedAt() < b.Row.GetAdmittedAt() {
				return -1
			}
			return 1
		}
		return slices.Compare(a.Row.GetSidecarId(), b.Row.GetSidecarId())
	})
	devices := []MemberDevice{device(own)}
	for _, admission := range admissions {
		if memberDevice := device(admission); !memberDevice.This {
			devices = append(devices, memberDevice)
		}
	}
	return devices, nil
}

// SidecarRevokeAuthority over ConfigState: §16.6's approval-capable device, ACL's predicate.
func (self *ConfigAuthority) ApprovalCapable(sidecarId Id) bool {
	state := self.client.State()
	if state == nil {
		return false
	}
	acl, err := state.Acl()
	return err == nil && acl.ApprovalCapable(sidecarId)
}

// SidecarRevokeAuthority over ConfigState: whether an active Suspend names the sidecar.
func (self *ConfigAuthority) Suspended(sidecarId Id) bool {
	state := self.client.State()
	return state != nil && state.Suspended(sidecarId)
}

// SidecarRevokeAuthority over ConfigState: k for a device of an AdminSet member, whose revocation needs authority
// (ConfigState.revokeSigners), else 1.
func (self *ConfigAuthority) RevokeSignatures(targetId Id) int {
	state := self.client.State()
	if state == nil {
		return 1
	}
	memberId, untagged := configRowMember(state.SidecarRow(targetId))
	if member := state.Member(memberId); untagged && member != nil && configRoleInAdminSet(member.GetRole()) {
		k, _ := state.Threshold()
		return k
	}
	return 1
}

// SidecarRevokeAuthority over ConfigState: the registered keys whose KeyRow names the sidecar as signer, by key_id.
func (self *ConfigAuthority) RegisteredKeys(sidecarId Id) []*bridge.KeyRow {
	keys := []*bridge.KeyRow{}
	state := self.client.State()
	if state == nil {
		return keys
	}
	for _, key := range state.keys {
		if key.GetRevokedAt() == 0 && slices.Equal(key.GetSigner(), sidecarId.Bytes()) {
			keys = append(keys, proto.Clone(key).(*bridge.KeyRow))
		}
	}
	slices.SortFunc(keys, func(a *bridge.KeyRow, b *bridge.KeyRow) int {
		return slices.Compare(a.GetKeyId(), b.GetKeyId())
	})
	return keys
}

// SidecarRevokeAuthority over the client's retained entries: api's time for entry n.
func (self *ConfigAuthority) EntryTime(n uint64) (time.Time, bool) {
	self.client.followLock.Lock()
	defer self.client.followLock.Unlock()
	log := self.client.configLog.Load()
	if log == nil {
		return time.Time{}, false
	}
	for _, kept := range log.kept {
		if kept.n == n {
			return time.UnixMilli(kept.entry.GetTimeMs()), true
		}
	}
	return time.Time{}, false
}
