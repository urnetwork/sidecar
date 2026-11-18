// §5.6's alarm row on the device (CORE-M2-03, D-CORE-13, R-CORE-17): one watcher on the installed authority's
// AddEntryCallback turns each applied entry's effects and recovery verdicts into this device's alarms, TEAM-M2-05's
// verdicts being the same for every device and the alarm each device's own:
//
//	admission_alarm      on member M's devices, every admission under M none of them signed, recovery-key ones
//	                     included; approval_pending beside it for one M has not consented
//	recovery_rebind      on each of M's devices, every RecoveryRebind of M it did not itself sign, another device of
//	                     M's included, and each binding of M a cascade voids
//	recovery_window      on every member device, while an authority statement with a recovery-key signature is
//	                     pending, from its window start p
//	recovery_unseen      when the window activates under 72 h minus 10 min after this device applied p, or a valid
//	                     veto first verifies only after this device applied the activation
//	admissions_near_cap  on admin devices, from 90% of config_admissions, once each time the count rises past it,
//	                     with one cleanup item open while the count stays there (§7.10's cleanup row,
//	                     identity_cleanup.go); the cap is the entry's where the authority gives one, else the one GET
//	                     /sidecar/limits last answered (QD-250), which no reader derives from the log
//
// §7.9's time row compares device-local application times, never api's entry times, which are server-asserted: so
// the watcher keeps, per window, the time this device applied p, by its own clock. What it has raised persists in
// the core namespace's alarms record with the newest entry it applied, so an entry a restarted follower delivers
// again raises nothing twice (at least once: a kill between an alarm and its record raises it once more). Each alarm
// that a person answers also opens an approval item, which PendingApprovals lists until DecideApproval closes it
// (identity_approvals.go).
//
// head_alarm, member_added, member_removed, key_changed and refused come from the components that see them (§6.4's
// HeadStopState, gkm's upkeep, the MLS groups), which relay them through Sidecar.Alarm. Evidence and events carry
// opaque ids only (I-13).
//
// On every leg: root Id, no connect type. The watcher runs on the follower's goroutine and holds no lock while it
// emits.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The keychain record of the core's namespace holding what the watcher has applied and raised.
const sidecarAlarmRecordName = "alarms"

// admissions_near_cap's threshold, 90% of config_admissions as tenths (§7.10's cleanup row): the list's own value,
// which TEAM-M4-01's CleanupList(state, cap), a pure function every admin device answers alike, reads beside the
// alarm, so it stays here until that function takes it from a settings object (QD-706's sweep). §7.9's Recovery
// window and §5.6's tolerance on it are SidecarAlarmSettings'.
const sidecarAdmissionsNearCapTenths = 9

// The kinds of approval item an alarm opens (§18.5's GetPending; CORE-M2-04 dispatches on these).
const (
	// An admission this device may sign, or cosign at k > 1.
	SidecarApprovalAdmission = "admission"
	// An admission under this device's member none of its devices signed: approve signs OwnerConfirm, revoke runs
	// RevokeDevice, deny dismisses.
	SidecarApprovalAdmissionAlarm = "admission_alarm"
	// A recovery window pending: deny signs RecoveryVeto.
	SidecarApprovalRecoveryWindow = "recovery_window"
	// A RecoveryRebind this device did not sign, or a voided binding: revoke offers a compromise revocation.
	SidecarApprovalRecoveryRebind = "recovery_rebind"
	// A recovery activated too soon for this device to have seen it: revoke offers the recovered device's revocation.
	SidecarApprovalRecoveryUnseen = "recovery_unseen"
	// admissions_near_cap's cleanup list (§7.10, CORE-M6-04).
	SidecarApprovalCleanup = "cleanup"
)

// One window as this device holds it.
type sidecarAlarmWindow struct {
	ProposalId string `json:"proposal_id"`
	Start      uint64 `json:"start"`
	// when this device applied p, by its own clock, ms
	AppliedAtMs int64 `json:"applied_at_ms"`
	// when this device applied the activation, ms; zero before
	ActivatedAtMs int64 `json:"activated_at_ms,omitempty"`
	MemberId      Id    `json:"member_id"`
	SidecarId     *Id   `json:"sidecar_id,omitempty"`
	Closed        bool  `json:"closed,omitempty"`
}

// One open item a person answers.
type sidecarApprovalRecord struct {
	ItemId    Id     `json:"item_id"`
	Kind      string `json:"kind"`
	SidecarId *Id    `json:"sidecar_id,omitempty"`
	MemberId  *Id    `json:"member_id,omitempty"`
	// a window's or a proposal's 32-byte id, hex
	ProposalId string `json:"proposal_id,omitempty"`
	// the entry that opened it, where a compromise revocation's since_n starts
	Position   uint64 `json:"position"`
	RaisedAtMs int64  `json:"raised_at_ms"`
	Decided    bool   `json:"decided,omitempty"`
	Decision   string `json:"decision,omitempty"`
	// an admission request's: the new device's identity key and the capabilities its admission carries
	IdentityPublicKey []byte `json:"identity_public_key,omitempty"`
	Capabilities      uint32 `json:"capabilities,omitempty"`
}

// The persisted record.
type sidecarAlarmRecord struct {
	Version int `json:"version"`
	// the newest entry applied
	AppliedThrough uint64                         `json:"applied_through"`
	Windows        map[string]*sidecarAlarmWindow `json:"windows"`
	Items          []*sidecarApprovalRecord       `json:"items"`
	// admissions_near_cap was raised at this count, so it raises again only once the count rises past it
	NearCapRaisedCount int `json:"near_cap_raised_count,omitempty"`
	// the AdminSet's members as the newest entry that named them left it, whose devices veto and alarm near the cap
	AdminMemberIds []Id `json:"admin_member_ids,omitempty"`
}

// The watcher's state on a Sidecar, under its own lock.
type sidecarAlarms struct {
	stateLock sync.Mutex
	// the subscription to the installed authority's entries
	removeCallback func()
	// config_admissions as GET /sidecar/limits last answered it (QD-250; identity_cleanup.go reads it), which
	// admissions_near_cap compares the count with where an entry carries no cap of its own: 0 before any read and
	// for a tier that does not include admissions, -1 for none; either puts nothing near a cap
	admissionCap int
}

// §7.10's cleanup on a Sidecar (identity_cleanup.go), under its own lock, which is never held while the alarm lock is
// taken. Plain values, so this file, which the forwarding leg links, holds them while the cleanup's code stays off
// that leg, which admits no Worker and raises no alarm.
type sidecarCleanups struct {
	stateLock sync.Mutex
	// when GET /sidecar/limits last answered config_admissions, by this device's clock; zero before
	capReadAt time.Time
	// a read runs now, off the follower's goroutine
	capReading bool
	// the list a person was shown, by item: its ListId, which a revoke answer signs only while the list at the tip
	// still has it
	previews map[Id]Id
}

// Subscribes the watcher to authority's entries, ending any earlier subscription. nil ends it.
func (self *Sidecar) authorityInstalled(authority SidecarAuthority) {
	var previous func()
	func() {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		previous = self.alarms.removeCallback
		self.alarms.removeCallback = nil
	}()
	if previous != nil {
		previous()
	}
	if authority == nil {
		return
	}
	// keychain.wrap's recovery copy comes to the member's current binding as this authority's newest state has it,
	// and again at each entry, before the entry's alarms, so a void's alarm names the span the void just ended
	if pin := authority.Pin(); pin != nil {
		if err := self.syncRecoverySeal(authority, pin); err != nil && !errors.Is(err, ErrSidecarNoIdentity) {
			self.log.Warningf("[keys]keychain.wrap's recovery copy was not brought to the current binding: %s", err)
		}
	}
	remove := authority.AddEntryCallback(func(entry *SidecarAuthorityEntry) {
		self.applyRecoverySealEntry(authority, entry)
		self.applyAlarmEntry(authority, entry)
		self.applyRevokeEntry(authority, entry)
		for _, kind := range sidecarApprovalKinds {
			if kind.entryApplied != nil {
				kind.entryApplied(self, authority, entry)
			}
		}
	})
	func() {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		self.alarms.removeCallback = remove
	}()
}

// The record as persisted, or a fresh one.
func (self *Sidecar) loadAlarmRecord() (*sidecarAlarmRecord, error) {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return nil, ErrSidecarNoIdentity
	}
	encoded, err := secrets.Get(sidecarAlarmRecordName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return &sidecarAlarmRecord{Version: 1, Windows: map[string]*sidecarAlarmWindow{}}, nil
	}
	if err != nil {
		return nil, err
	}
	record := &sidecarAlarmRecord{}
	if err := json.Unmarshal(encoded, record); err != nil || record.Version != 1 {
		return nil, fmt.Errorf("%w: the alarm record", ErrSidecarStoreFailed)
	}
	if record.Windows == nil {
		record.Windows = map[string]*sidecarAlarmWindow{}
	}
	return record, nil
}

// Persists the record.
func (self *Sidecar) persistAlarmRecord(record *sidecarAlarmRecord) error {
	secrets := self.currentCoreSecrets()
	if secrets == nil {
		return ErrSidecarNoIdentity
	}
	// closed windows and decided items past the newest entry's window are history the watcher no longer needs
	for proposalId, window := range record.Windows {
		if window.Closed {
			delete(record.Windows, proposalId)
		}
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	return secrets.Put(sidecarAlarmRecordName, encoded)
}

// An item's id: the first 16 bytes of SHA-256(kind || subject || position), so each fact opens one item.
func sidecarApprovalItemId(kind string, subject []byte, position uint64) Id {
	hash := sha256.New()
	hash.Write([]byte(kind))
	hash.Write([]byte{0x00})
	hash.Write(subject)
	hash.Write([]byte(fmt.Sprintf(":%d", position)))
	var id Id
	copy(id[:], hash.Sum(nil))
	return id
}

// Opens an item once.
func (self *sidecarAlarmRecord) open(item *sidecarApprovalRecord) {
	for _, existing := range self.Items {
		if existing.ItemId == item.ItemId {
			return
		}
	}
	self.Items = append(self.Items, item)
}

// Whether signers include one of devices, each a sidecar's admission.
func sidecarSignedByOneOf(signers []ConfigSigner, devices []*AclSidecar) bool {
	for _, signer := range signers {
		if signer.Kind != ConfigSignerSidecar {
			continue
		}
		for _, device := range devices {
			if device.Row != nil && bytes.Equal(device.Row.GetSidecarId(), signer.SidecarId.Bytes()) {
				return true
			}
		}
	}
	return false
}

// Whether signers include sidecarId.
func sidecarSignedBy(signers []ConfigSigner, sidecarId Id) bool {
	return slices.ContainsFunc(signers, func(signer ConfigSigner) bool {
		return signer.Kind == ConfigSignerSidecar && signer.SidecarId == sidecarId
	})
}

// The sidecar signer among signers, nil for none.
func sidecarSignerOf(signers []ConfigSigner) *Id {
	for _, signer := range signers {
		if signer.Kind == ConfigSignerSidecar {
			sidecarId := signer.SidecarId
			return &sidecarId
		}
	}
	return nil
}

// What one entry's alarms need of the verified state, read before the record's lock, so no authority call runs
// under it (connect/CODESTYLE.md:234).
type sidecarAlarmFacts struct {
	// this device is a member device: admitted, not revoked, untagged and not ephemeral (§7.9's leaves row)
	memberDevice bool
	memberId     Id
	// per sidecar an entry admits under this device's member: whether none of the member's other devices signed it,
	// and whether the member has not consented to it
	admissions map[Id]*sidecarAlarmAdmissionFacts
}

// One admission's facts.
type sidecarAlarmAdmissionFacts struct {
	unsigned    bool
	unconsented bool
}

// Reads what entry's alarms need of authority, as this device stands in it now.
func sidecarReadAlarmFacts(authority SidecarAuthority, identity *SidecarIdentity, entry *SidecarAuthorityEntry) *sidecarAlarmFacts {
	facts := &sidecarAlarmFacts{admissions: map[Id]*sidecarAlarmAdmissionFacts{}}
	own := authority.Admission(identity.SidecarId)
	facts.memberDevice = own != nil && own.Row != nil && own.Row.GetRevokedAt() == 0 && len(own.TagIds) == 0 && !own.Ephemeral
	if !facts.memberDevice {
		return facts
	}
	facts.memberId = own.MemberId
	for _, effect := range entry.Effects {
		if effect.Type != bridge.SignedType_SIGNED_SIDECAR_ADMIT {
			continue
		}
		admit := &protocol.SidecarAdmit{}
		if proto.Unmarshal(effect.Body, admit) != nil {
			continue
		}
		admittedId, err := IdFromBytes(admit.GetSidecarId())
		admittedMemberId, memberErr := IdFromBytes(admit.GetMemberId())
		if err != nil || memberErr != nil || admittedMemberId != facts.memberId || admittedId == identity.SidecarId {
			continue
		}
		devices := slices.DeleteFunc(authority.MemberDevices(facts.memberId), func(device *AclSidecar) bool {
			return device.Row == nil || bytes.Equal(device.Row.GetSidecarId(), admittedId.Bytes())
		})
		facts.admissions[admittedId] = &sidecarAlarmAdmissionFacts{
			unsigned:    !sidecarSignedByOneOf(effect.Signers, devices),
			unconsented: !admit.GetEphemeral() && !authority.Consented(admittedId, facts.memberId),
		}
	}
	return facts
}

// Applies one entry: raises its alarms, records them and the windows, then emits, once per entry. The verified state
// is read first, outside the record's lock; the follower delivers one entry at a time.
func (self *Sidecar) applyAlarmEntry(authority SidecarAuthority, entry *SidecarAuthorityEntry) {
	if entry == nil || entry.Pin == nil {
		return
	}
	identity := self.currentIdentity()
	if identity == nil {
		return
	}
	facts := sidecarReadAlarmFacts(authority, identity, entry)
	events := []SidecarEvent{}
	err := func() error {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		record, err := self.loadAlarmRecord()
		if err != nil {
			return err
		}
		n := entry.Pin.GetVersion()
		if n <= record.AppliedThrough {
			// a follower's redelivery after a restart: raised already
			return nil
		}
		events = self.alarmsOfEntry(facts, identity, entry, record)
		record.AppliedThrough = n
		return self.persistAlarmRecord(record)
	}()
	if err != nil {
		self.log.Warningf("[identity]an entry's alarms were not recorded: %s", err)
	}
	for _, event := range events {
		self.emitEvent(event)
	}
}

// The alarms one entry raises on this device, given facts, recorded in record. Runs under the alarm lock and calls
// nothing outside this sidecar.
func (self *Sidecar) alarmsOfEntry(facts *sidecarAlarmFacts, identity *SidecarIdentity, entry *SidecarAuthorityEntry, record *sidecarAlarmRecord) []SidecarEvent {
	events := []SidecarEvent{}
	n := entry.Pin.GetVersion()
	nowMs := self.clock.Now().UnixMilli()
	memberDevice := facts.memberDevice
	memberId := facts.memberId

	for _, effect := range entry.Effects {
		switch effect.Type {
		case bridge.SignedType_SIGNED_SIDECAR_ADMIT:
			admit := &protocol.SidecarAdmit{}
			if proto.Unmarshal(effect.Body, admit) != nil || !memberDevice {
				continue
			}
			admittedId, err := IdFromBytes(admit.GetSidecarId())
			admission := facts.admissions[admittedId]
			if err != nil || admission == nil || (!admission.unsigned && !admission.unconsented) {
				continue
			}
			// one item, which approve answers with OwnerConfirm, revoke with RevokeDevice and deny dismisses
			itemId := sidecarApprovalItemId(SidecarApprovalAdmissionAlarm, admittedId.Bytes(), n)
			record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalAdmissionAlarm, SidecarId: &admittedId, MemberId: &memberId, Position: n, RaisedAtMs: nowMs})
			if admission.unsigned {
				events = append(events, SidecarEvent{Kind: SidecarEventAdmissionAlarm, SidecarId: &admittedId})
			}
			if admission.unconsented {
				events = append(events, SidecarEvent{Kind: SidecarEventApprovalPending, SidecarId: &admittedId, ApprovalId: &itemId})
			}

		case bridge.SignedType_SIGNED_RECOVERY_REBIND:
			rebind := &protocol.RecoveryRebind{}
			if proto.Unmarshal(effect.Body, rebind) != nil || !memberDevice {
				continue
			}
			rebindMemberId, err := IdFromBytes(rebind.GetMemberId())
			if err != nil || rebindMemberId != memberId || sidecarSignedBy(effect.Signers, identity.SidecarId) {
				continue
			}
			signerId := sidecarSignerOf(effect.Signers)
			events = append(events, SidecarEvent{Kind: SidecarEventRecoveryRebind, SidecarId: signerId})
			subject := rebind.GetEd25519PublicKeySha256()
			itemId := sidecarApprovalItemId(SidecarApprovalRecoveryRebind, subject, n)
			record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalRecoveryRebind, SidecarId: signerId, MemberId: &memberId, Position: n, RaisedAtMs: nowMs})
		}
	}

	for _, voided := range entry.VoidedBindings {
		if !memberDevice || voided.MemberId != memberId {
			continue
		}
		var signerId *Id
		if id, err := IdFromBytes(voided.Signer); err == nil {
			signerId = &id
		}
		// the span this device's keychain.wrap was sealed to the voided binding (§5.9's backup rule): a backup taken
		// inside it holds a sealing to that binding
		events = append(events, SidecarEvent{Kind: SidecarEventRecoveryRebind, SidecarId: signerId, Evidence: self.recoverySealEvidence(voided.KeySha256, entry.Pin)})
		itemId := sidecarApprovalItemId(SidecarApprovalRecoveryRebind, voided.KeySha256, n)
		record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalRecoveryRebind, SidecarId: signerId, MemberId: &memberId, Position: n, RaisedAtMs: nowMs})
	}

	for _, window := range entry.Windows {
		if !memberDevice || len(window.ProposalId) != sha256.Size {
			continue
		}
		proposalId := hex.EncodeToString(window.ProposalId)
		held := record.Windows[proposalId]
		switch window.State {
		case SidecarRecoveryWindowPending:
			if held == nil || held.Start != window.Start {
				// p applied now, by this device's clock; a late recovery cosign moves p and restarts it
				held = &sidecarAlarmWindow{ProposalId: proposalId, Start: window.Start, AppliedAtMs: nowMs, MemberId: window.MemberId, SidecarId: window.SidecarId}
				record.Windows[proposalId] = held
				events = append(events, SidecarEvent{Kind: SidecarEventRecoveryWindow, SidecarId: window.SidecarId})
				itemId := sidecarApprovalItemId(SidecarApprovalRecoveryWindow, window.ProposalId, window.Start)
				windowMemberId := window.MemberId
				record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalRecoveryWindow, SidecarId: window.SidecarId, MemberId: &windowMemberId, ProposalId: proposalId, Position: window.Start, RaisedAtMs: nowMs})
			}
		case SidecarRecoveryWindowActivated:
			// a window this device never applied p of is one it could not have seen at all
			alarmSettings := self.settings.alarmSettings()
			tooSoon := held == nil || time.Duration(nowMs-held.AppliedAtMs)*time.Millisecond < alarmSettings.Recovery.Window-alarmSettings.RecoveryUnseenTolerance
			if tooSoon {
				events = append(events, SidecarEvent{Kind: SidecarEventRecoveryUnseen, SidecarId: window.SidecarId})
				itemId := sidecarApprovalItemId(SidecarApprovalRecoveryUnseen, window.ProposalId, n)
				windowMemberId := window.MemberId
				record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalRecoveryUnseen, SidecarId: window.SidecarId, MemberId: &windowMemberId, ProposalId: proposalId, Position: n, RaisedAtMs: nowMs})
			}
			if held == nil {
				held = &sidecarAlarmWindow{ProposalId: proposalId, Start: window.Start, MemberId: window.MemberId, SidecarId: window.SidecarId}
				record.Windows[proposalId] = held
			}
			held.ActivatedAtMs = nowMs
			record.closeItems(SidecarApprovalRecoveryWindow, proposalId)
		case SidecarRecoveryWindowVetoed:
			if held != nil && held.ActivatedAtMs != 0 {
				// a valid veto this device first verifies after applying the activation
				events = append(events, SidecarEvent{Kind: SidecarEventRecoveryUnseen, SidecarId: window.SidecarId})
				itemId := sidecarApprovalItemId(SidecarApprovalRecoveryUnseen, window.ProposalId, n)
				windowMemberId := window.MemberId
				record.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalRecoveryUnseen, SidecarId: window.SidecarId, MemberId: &windowMemberId, ProposalId: proposalId, Position: n, RaisedAtMs: nowMs})
			}
			if held != nil {
				held.Closed = true
			}
			record.closeItems(SidecarApprovalRecoveryWindow, proposalId)
		case SidecarRecoveryWindowExpired:
			if held != nil {
				held.Closed = true
			}
			record.closeItems(SidecarApprovalRecoveryWindow, proposalId)
		}
	}

	if entry.AdminMemberIds != nil {
		record.AdminMemberIds = slices.Clone(entry.AdminMemberIds)
	}
	if memberDevice && slices.Contains(record.AdminMemberIds, memberId) {
		admissionCap := entry.AdmissionCap
		if admissionCap == 0 {
			admissionCap = self.alarms.admissionCap
		}
		events = append(events, record.nearCap(entry.AdmissionCount, admissionCap, n, nowMs)...)
	}
	return events
}

// admissions_near_cap's step at count of admissionCap, on an admin device (§7.10's cleanup row): from 90% of the cap,
// raised once each time the count rises past the count it was raised at, opening the cleanup item unless one is open;
// below 90% the raise resets and an open cleanup item closes, since the list is gone. A cap of 0 or -1 changes nothing,
// as no cap is known. position is the entry it is judged at, which names a new item.
func (self *sidecarAlarmRecord) nearCap(count int, admissionCap int, position uint64, nowMs int64) []SidecarEvent {
	if admissionCap <= 0 {
		return nil
	}
	if count*10 < admissionCap*sidecarAdmissionsNearCapTenths {
		self.NearCapRaisedCount = 0
		for _, item := range self.Items {
			if item.Kind == SidecarApprovalCleanup && !item.Decided {
				item.Decided = true
				item.Decision = "closed"
			}
		}
		return nil
	}
	if count <= self.NearCapRaisedCount {
		return nil
	}
	self.NearCapRaisedCount = count
	// the event names the open item, a new one unless one is open still
	itemId := sidecarApprovalItemId(SidecarApprovalCleanup, nil, position)
	if index := slices.IndexFunc(self.Items, func(item *sidecarApprovalRecord) bool {
		return item.Kind == SidecarApprovalCleanup && !item.Decided
	}); 0 <= index {
		itemId = self.Items[index].ItemId
	} else {
		self.open(&sidecarApprovalRecord{ItemId: itemId, Kind: SidecarApprovalCleanup, Position: position, RaisedAtMs: nowMs})
	}
	return []SidecarEvent{{Kind: SidecarEventAdmissionsNearCap, ApprovalId: &itemId}}
}

// A fresh read of config_admissions, admissionCap (identity_cleanup.go): kept as the cap the watcher compares with, and,
// on an admin device, admissions_near_cap judged at once at count, what config_admissions counts at the newest
// verified state, whose position is position, so a cap read after the entries that reached it still raises.
// memberDevice and memberId are this device's standing in that state, read before the lock.
func (self *Sidecar) admissionCapRead(admissionCap int, count int, position uint64, memberDevice bool, memberId Id) {
	events := []SidecarEvent{}
	err := func() error {
		self.alarms.stateLock.Lock()
		defer self.alarms.stateLock.Unlock()
		self.alarms.admissionCap = admissionCap
		if !memberDevice {
			return nil
		}
		record, err := self.loadAlarmRecord()
		if err != nil {
			return err
		}
		if !slices.Contains(record.AdminMemberIds, memberId) {
			return nil
		}
		events = record.nearCap(count, admissionCap, position, self.clock.Now().UnixMilli())
		return self.persistAlarmRecord(record)
	}()
	if err != nil {
		self.log.Warningf("[identity]admissions_near_cap was not judged at a fresh cap: %s", err)
		return
	}
	for _, event := range events {
		self.emitEvent(event)
	}
}

// Closes every open item of kind for a window.
func (self *sidecarAlarmRecord) closeItems(kind string, proposalId string) {
	for _, item := range self.Items {
		if item.Kind == kind && item.ProposalId == proposalId && !item.Decided {
			item.Decided = true
			item.Decision = "closed"
		}
	}
}

// The event kinds a component relays through Alarm: what §6.4's HeadStopState, gkm's upkeep and the MLS groups see.
var sidecarRelayedEventKinds = map[SidecarEventKind]bool{
	SidecarEventHeadAlarm:     true,
	SidecarEventMemberAdded:   true,
	SidecarEventMemberRemoved: true,
	SidecarEventKeyChanged:    true,
	SidecarEventRefused:       true,
	// D-TRUST-9's zone watch (DnsWatch)
	SidecarEventDnsAlarm: true,
	// D-TLS-8's CT watch (tls_ct.go)
	SidecarEventCtAlarm: true,
}

// Raises a component's alarm as this sidecar's event (§5.6's alarm row): head_alarm with both pins as Evidence,
// member_added and member_removed with their group, key_changed and refused. Any other kind is refused, since §5.6's
// own alarms are the watcher's to raise. Never blocks; safe from any goroutine.
func (self *Sidecar) Alarm(event SidecarEvent) error {
	if !sidecarRelayedEventKinds[event.Kind] {
		return fmt.Errorf("%w: a component relays no %s", errInvalidSettings, event.Kind)
	}
	// a path is local to this device, never an alarm's (I-13)
	event.Path = ""
	self.emitEvent(event)
	return nil
}
