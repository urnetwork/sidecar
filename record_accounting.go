// RECORD.md section 4.2's mirrors row and §16.8's header comment, on every leg: membership and key entries mirror §5's
// SidecarEvents, admission alarms included, into each affected log.
//
// At M3 the affected log is the affected member's vault, and only that member's own devices write there (owner
// decision 126): on reading the statement, the member's consented device writes the entry, or another of its sidecars
// deposits it, unless the vault already holds one naming that statement_sha256 for the same event, and readers show
// one per (event, statement_sha256). An admin's device never writes another member's vault; the team record's copy,
// which also records a removed member's removal, is RECORD-M6-01's. A member's own device revocation names its approval
// evidence: presence with the WebAuthn assertion as stored, or a confirmation (§5.6).
//
// The entries carry no session: a membership or key change is the daemon's own act (section 5.3's none row), so they
// seal untainted, source observed, with no action_id. SidecarEvent carries the group and sidecar, not the statement's
// hash, position or type, so events taken from AddEventCallback mirror with those empty and are not deduplicated by
// statement; the follower that applies the statement (TEAM-M2-10, CORE-M2-03) fills RecordAccountingEvent whole.
//
// Events arrive on whatever goroutine raised them and must not block (SidecarEventFunction), so Queue only queues, and
// the record's loop mirrors what waits (SidecarRecord.Run). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A member's own device revocation's evidence (MembershipBody.evidence).
type RecordMembershipEvidence uint32

const (
	RecordMembershipEvidenceNone         RecordMembershipEvidence = 0
	RecordMembershipEvidencePresence     RecordMembershipEvidence = 1
	RecordMembershipEvidenceConfirmation RecordMembershipEvidence = 2
)

// MembershipBody.event, by §5.4's event names.
var recordMembershipEvents = map[SidecarEventKind]uint32{
	SidecarEventMemberAdded:    1,
	SidecarEventMemberRemoved:  2,
	SidecarEventAdmissionAlarm: 3,
	SidecarEventRecoveryRebind: 4,
	SidecarEventRecoveryWindow: 5,
	SidecarEventRecoveryUnseen: 6,
}

// An event that is no membership or key event.
var ErrRecordAccountingKind = errors.New("record accounting event of another kind")

// One membership or key event as the record mirrors it: §5.4's SidecarEvent, with what the statement that raised it
// adds.
type RecordAccountingEvent struct {
	Kind SidecarEventKind
	// the member the event is about; resolved from SidecarId when nil
	MemberId  *Id
	SidecarId *Id
	GroupId   *Id
	// the statement's log position, 0 for an alarm
	AuthPosition uint64
	// SHA-256 of the statement's Signed as stored, empty for an alarm
	StatementSha256 []byte
	// §6.11's type of the statement that raised it
	SignedType bridge.SignedType
	// a member's own device revocation's evidence, and with presence its assertion as stored
	Evidence  RecordMembershipEvidence
	Assertion []byte
	// the revocation's reason, as its statement gives it
	Reason uint32
	// key_changed: the generation, §10.5's GenRotate cause, and the key
	Generation uint64
	Cause      uint32
	KeyId      []byte
}

// The record's mirror of membership and key events into this device's member's vault.
type RecordAccounting struct {
	writer *recordWriter
	reader *RecordReader

	stateLock sync.Mutex
	queued    []*RecordAccountingEvent
}

// A RecordAccountingEvent from a SidecarEvent, with what the event carries; false for another kind.
func RecordAccountingEventOf(event SidecarEvent) (*RecordAccountingEvent, bool) {
	if _, ok := recordMembershipEvents[event.Kind]; !ok && event.Kind != SidecarEventKeyChanged {
		return nil, false
	}
	return &RecordAccountingEvent{Kind: event.Kind, SidecarId: event.SidecarId, GroupId: event.GroupId}, true
}

// Queues event for the record's loop, without waiting: what an AddEventCallback callback calls.
func (self *RecordAccounting) Queue(event *RecordAccountingEvent) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.queued = append(self.queued, event)
	}()
	self.writer.signal()
}

// Mirrors every queued event, each once; one that fails is logged and dropped, since the statement stays in the log
// for a later reader.
func (self *RecordAccounting) mirrorQueued(ctx context.Context) {
	queued := func() []*RecordAccountingEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queued := self.queued
		self.queued = nil
		return queued
	}()
	for _, event := range queued {
		if _, err := self.Mirror(ctx, event); err != nil {
			self.writer.log.Warningf("[record]a %s event was not mirrored: %s", event.Kind, err)
		}
	}
}

// The entry an event mirrors as: its kind and body.
func recordAccountingBody(event *RecordAccountingEvent, memberId Id) (RecordKind, proto.Message, error) {
	if event.Kind == SidecarEventKeyChanged {
		body := &protocol.KeyBody{
			Event:           1,
			Generation:      event.Generation,
			Cause:           event.Cause,
			KeyId:           bytes.Clone(event.KeyId),
			AuthPosition:    event.AuthPosition,
			StatementSha256: bytes.Clone(event.StatementSha256),
			SignedType:      uint32(event.SignedType),
		}
		if event.GroupId != nil {
			body.GroupId = event.GroupId.Bytes()
		}
		return RecordKindKey, body, nil
	}
	number, ok := recordMembershipEvents[event.Kind]
	if !ok {
		return RecordKindUnspecified, nil, fmt.Errorf("%w: %s", ErrRecordAccountingKind, event.Kind)
	}
	body := &protocol.MembershipBody{
		Event:           number,
		MemberId:        memberId.Bytes(),
		AuthPosition:    event.AuthPosition,
		StatementSha256: bytes.Clone(event.StatementSha256),
		Evidence:        uint32(event.Evidence),
		Assertion:       bytes.Clone(event.Assertion),
		Reason:          event.Reason,
		SignedType:      uint32(event.SignedType),
	}
	if event.SidecarId != nil {
		body.SidecarId = event.SidecarId.Bytes()
	}
	if event.GroupId != nil {
		body.GroupId = event.GroupId.Bytes()
	}
	return RecordKindMembership, body, nil
}

// Mirrors one event into this device's member's vault, when the event is about that member: nil and no error for an
// event about another member, whose own devices mirror it, and for one the vault already holds by statement_sha256.
func (self *RecordAccounting) Mirror(ctx context.Context, event *RecordAccountingEvent) (*RecordEntryRef, error) {
	auth := self.writer.auth()
	selfMemberId, ok := auth.Member(self.writer.sidecarId)
	if !ok {
		// a tagged sidecar mirrors nothing: only the member's own devices write its vault's accounting
		return nil, nil
	}
	memberId := Id{}
	switch {
	case event.MemberId != nil:
		memberId = *event.MemberId
	case event.SidecarId != nil:
		resolved, ok := auth.Member(*event.SidecarId)
		if !ok {
			return nil, nil
		}
		memberId = resolved
	default:
		return nil, nil
	}
	if memberId != selfMemberId {
		return nil, nil
	}
	kind, body, err := recordAccountingBody(event, memberId)
	if err != nil {
		return nil, err
	}
	if len(event.StatementSha256) != 0 && self.held(ctx, auth, kind, body) {
		return nil, nil
	}
	refs, err := self.writer.Append(&RecordDraft{Kind: kind, Source: RecordSourceObserved, NoSession: true, Body: body})
	if err != nil {
		return nil, err
	}
	return refs[0], nil
}

// Whether the vault already holds an entry of kind naming body's event and statement_sha256, as read now.
func (self *RecordAccounting) held(ctx context.Context, auth RecordAuthView, kind RecordKind, body proto.Message) bool {
	route, err := recordVaultRoute(auth, self.writer.sidecarId)
	if err != nil || route.deposit {
		// a depositor reads no vault: readers show one per (event, statement_sha256)
		return false
	}
	if err := self.reader.Sync(ctx, route.logId); err != nil {
		return false
	}
	event, statement := recordAccountingKey(body)
	for _, entry := range self.reader.Entries(route.logId) {
		if entry.Kind() != kind || entry.Body == nil {
			continue
		}
		held, ok := kind.NewBody()
		if !ok || proto.Unmarshal(entry.Body, held) != nil {
			continue
		}
		heldEvent, heldStatement := recordAccountingKey(held)
		if heldEvent == event && bytes.Equal(heldStatement, statement) {
			return true
		}
	}
	return false
}

// A membership or key body's (event, statement_sha256).
func recordAccountingKey(body proto.Message) (uint32, []byte) {
	switch typed := body.(type) {
	case *protocol.MembershipBody:
		return typed.GetEvent(), typed.GetStatementSha256()
	case *protocol.KeyBody:
		return typed.GetEvent(), typed.GetStatementSha256()
	}
	return 0, nil
}
