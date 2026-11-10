// §7.10's stale and cleanup rows as the log answers them (TEAM-M4-01, D-TEAM-29, FS-97): a member's page Workers with
// their admission positions, what config_admissions counts, and the list every admin device shows from 90% of the cap.
// The device act that revokes stale Workers in an admission is CORE-M4-02's (identity_act_stale.go), and the cleanup
// prompt CORE-M6-04's; this file supplies what both read from the log.
//
// The log cannot see a leaf's staleness. §10.9 judges it from each group's tree, which only a device that is a leaf of
// the group reads (§7.10's stale row), so nothing here decides staleness or drops a Worker by age: PageWorkers lists
// every read_only member device the log holds admitted, however long ago, and CleanupList orders Workers by their
// admission positions alone. That is why an admin's device revokes, in an admission act, only what its own groups showed
// removed, and why the cleanup list leaves each revocation to an admin's choice.
//
// Everything here is a function of one state alone, its rows and pin, so every device at one pin answers alike, a
// rows-only gate included; admissions_near_cap's list is then the same on every admin device.
//
// The verifier rules these Workers' revocations pass are the ordinary ones, and this file adds none: a
// SidecarRevoke{reason: removed} of a page Worker by an admin's device or the member's consented device passes
// config_admit.go's signer row, under config_presence.go's presence row where the signer holds a live presence key; an
// AdminSet member's Worker at k > 1 goes only by an AuthorityProposal of its own, the member's existing device counting
// as one (config_authority.go's counted row); a proposal short of k closes at its not_after, and the next admission
// proposes the revocation again as a statement of its own, which no replay row refuses.
//
// On every leg, the sidecar_http page Worker's included: root Id, no connect type. Nothing here creates, derives or
// unwraps a key, so nothing calls testHookSecret.

package sidecar

import (
	"cmp"
	"slices"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One of a member's page Workers (§18.8): a read_only member device of the member that the log holds admitted.
type ConfigPageWorker struct {
	SidecarId Id
	// The position its admission took effect at (SidecarRow.admitted_at): its SidecarAdmit's entry, or the cosign or
	// tick that completed its proposal.
	AdmittedAt uint64
}

// One member's part of §7.10's cleanup list.
type ConfigCleanupMember struct {
	MemberId Id
	// Its page Workers but its newest, oldest first.
	Workers []ConfigPageWorker
}

// What an authority answers of §7.10's page Workers, beside SidecarAuthority: ConfigAuthority's, over the newest
// verified state. An act admitting a page Worker (CORE-M4-02) and the cleanup prompt (CORE-M6-04) read these through it;
// an authority without it, a test's fake, answers neither.
type SidecarPageWorkerAuthority interface {
	// ConfigState.PageWorkers at the newest verified state.
	PageWorkers(memberId Id) []ConfigPageWorker
	// ConfigState.AdmissionCount at the newest verified state.
	AdmissionCount() int
	// CleanupList at the newest verified state.
	CleanupList(admissionCap int) []ConfigCleanupMember
}

var _ SidecarPageWorkerAuthority = (*ConfigAuthority)(nil)

// Whether a row's admission stands at timeMs, which is what config_admissions counts: not revoked, and not past its
// own not_after, which only a tagged or ephemeral admission carries. A parked or suspended one still stands, since
// neither is a removal, and a revoked row stays a tombstone that counts for nothing.
func configAdmissionStands(row *bridge.SidecarRow, timeMs int64) bool {
	if row == nil || row.GetRevokedAt() != 0 {
		return false
	}
	return row.GetNotAfter() == 0 || timeMs < row.GetNotAfter()
}

// Whether count stands at or past 90% of admissionCap (§7.10's cleanup row), by the threshold admissions_near_cap's
// alarm raises at (identity_alarms.go's sidecarAdmissionsNearCapTenths), so the alarm and the list agree. Nothing is
// near no cap.
func configAdmissionsNearCap(count int, admissionCap int) bool {
	return 0 < admissionCap && admissionCap*sidecarAdmissionsNearCapTenths <= count*10
}

// The member a row's page Worker belongs to, false for a row that is no page Worker standing at timeMs: a read_only
// member device, untagged and not ephemeral, whose admission stands, parked and suspended ones included since each
// still holds an admission.
func configPageWorkerMember(row *bridge.SidecarRow, timeMs int64) (Id, bool) {
	memberId, untagged := configRowMember(row)
	if !untagged || row.GetEphemeral() || !configRowReadOnly(row) || !configAdmissionStands(row, timeMs) {
		return Id{}, false
	}
	return memberId, true
}

// Oldest admission first, ties by sidecar_id, so the order is the log's alone.
func configSortPageWorkers(workers []ConfigPageWorker) {
	slices.SortFunc(workers, func(a ConfigPageWorker, b ConfigPageWorker) int {
		if order := cmp.Compare(a.AdmittedAt, b.AdmittedAt); order != 0 {
			return order
		}
		return a.SidecarId.Cmp(b.SidecarId)
	})
}

// The member's page Workers: its read_only member devices whose admission stands at this state's time, oldest
// admission first. Empty for an id no admission names, a removed member's among them, since its removal revoked its
// devices.
func (self *ConfigState) PageWorkers(memberId Id) []ConfigPageWorker {
	workers := []ConfigPageWorker{}
	for sidecarId, row := range self.sidecars {
		if rowMemberId, ok := configPageWorkerMember(row, self.timeMs); ok && rowMemberId == memberId {
			workers = append(workers, ConfigPageWorker{SidecarId: sidecarId, AdmittedAt: row.GetAdmittedAt()})
		}
	}
	configSortPageWorkers(workers)
	return workers
}

// What config_admissions bounds (§20.4) at this state's time: every admission that stands, member devices and agents
// alike, with no member-device cap. Every device at one pin counts alike, since the time is the entry's (§7.9's
// AuthEntry.time_ms).
func (self *ConfigState) AdmissionCount() int {
	return self.AdmissionCountAt(self.timeMs)
}

// AdmissionCount at timeMs, as api's verifier counts at the tip it appends at and its own time (§20.7): a tagged or
// ephemeral admission whose not_after has passed by then no longer counts.
func (self *ConfigState) AdmissionCountAt(timeMs int64) int {
	count := 0
	for _, row := range self.sidecars {
		if configAdmissionStands(row, timeMs) {
			count += 1
		}
	}
	return count
}

// §7.10's cleanup row: from 90% of config_admissions until the count falls below it, per member, its page Workers but
// its newest, oldest admission first, for an admin to revoke, so Workers that no member device answers for are freed
// before api refuses an admission at the cap. admissionCap is the network's config_admissions from GET /sidecar/limits
// (QD-250), which no reader can derive from the log; non-positive lists nothing. Members come in id order, and a member
// with one Worker or none is left out. Whether this device is an admin's, and each Worker's leaf's last change where a
// group of this device shows one, are the caller's to add (CORE-M6-04): the list is the log's alone, so every admin
// device at one pin shows the same.
func CleanupList(state *ConfigState, admissionCap int) []ConfigCleanupMember {
	members := []ConfigCleanupMember{}
	if state == nil || !configAdmissionsNearCap(state.AdmissionCount(), admissionCap) {
		return members
	}
	workersByMember := map[Id][]ConfigPageWorker{}
	for sidecarId, row := range state.sidecars {
		if memberId, ok := configPageWorkerMember(row, state.timeMs); ok {
			workersByMember[memberId] = append(workersByMember[memberId], ConfigPageWorker{SidecarId: sidecarId, AdmittedAt: row.GetAdmittedAt()})
		}
	}
	memberIds := make([]Id, 0, len(workersByMember))
	for memberId := range workersByMember {
		memberIds = append(memberIds, memberId)
	}
	slices.SortFunc(memberIds, Id.Cmp)
	for _, memberId := range memberIds {
		workers := workersByMember[memberId]
		if len(workers) < 2 {
			continue
		}
		configSortPageWorkers(workers)
		// all but the newest, which the member may still be using
		members = append(members, ConfigCleanupMember{MemberId: memberId, Workers: workers[: len(workers)-1 : len(workers)-1]})
	}
	return members
}

// The member's page Workers at the newest verified state; empty before the client reads its first.
func (self *ConfigAuthority) PageWorkers(memberId Id) []ConfigPageWorker {
	state := self.client.State()
	if state == nil {
		return []ConfigPageWorker{}
	}
	return state.PageWorkers(memberId)
}

// The admissions config_admissions counts at the newest verified state; 0 before the client reads its first.
func (self *ConfigAuthority) AdmissionCount() int {
	state := self.client.State()
	if state == nil {
		return 0
	}
	return state.AdmissionCount()
}

// §7.10's cleanup list at the newest verified state; empty before the client reads its first.
func (self *ConfigAuthority) CleanupList(admissionCap int) []ConfigCleanupMember {
	return CleanupList(self.client.State(), admissionCap)
}
