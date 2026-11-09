//go:build !sidecar_http

// record_accounting.go on sidecartest's streams: each §5.4 membership kind mirrored as one entry into the affected
// member's vault, by that member's own device, and none by a device of another member; a member's own device
// revocation carrying its presence assertion; one entry a statement, however often it is mirrored; key_changed as a
// key entry; and every one sealed untainted, source observed. External, as record_writer_test.go.

package sidecar_test

import (
	"bytes"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The membership bodies in the vault, as a reader reads them.
func (self *testRecordWorld) membershipBodies(t *testing.T) []*protocol.MembershipBody {
	t.Helper()
	bodies := []*protocol.MembershipBody{}
	for _, entry := range self.newReader(nil, nil).sync(t, self) {
		if entry.Kind() != sidecar.RecordKindMembership {
			continue
		}
		if entry.Flagged || sidecar.RecordSource(entry.Header.Header.GetSource()) != sidecar.RecordSourceObserved {
			t.Errorf("a membership entry sealed tainted %t, source %d", entry.Flagged, entry.Header.Header.GetSource())
		}
		body := &protocol.MembershipBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil {
			t.Fatal(err)
		}
		bodies = append(bodies, body)
	}
	return bodies
}

// Each of §5.4's membership kinds about the member becomes one entry in its vault, with its event number; an event
// about another member writes nothing here.
func TestRecordAccountingMirrorsEachMembershipKind(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	kinds := []sidecar.SidecarEventKind{
		sidecar.SidecarEventMemberAdded,
		sidecar.SidecarEventMemberRemoved,
		sidecar.SidecarEventAdmissionAlarm,
		sidecar.SidecarEventRecoveryRebind,
		sidecar.SidecarEventRecoveryWindow,
		sidecar.SidecarEventRecoveryUnseen,
	}
	for _, kind := range kinds {
		subjectId := sidecar.NewId()
		ref, err := record.Accounting().Mirror(t.Context(), &sidecar.RecordAccountingEvent{Kind: kind, MemberId: &world.memberId, SidecarId: &subjectId})
		if err != nil || ref == nil {
			t.Fatalf("%s: %+v, %v", kind, ref, err)
		}
	}
	otherMemberId := sidecar.NewId()
	if ref, err := record.Accounting().Mirror(t.Context(), &sidecar.RecordAccountingEvent{Kind: sidecar.SidecarEventMemberAdded, MemberId: &otherMemberId}); ref != nil || err != nil {
		t.Errorf("another member's event: %+v, %v", ref, err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	events := []uint32{}
	for _, body := range world.membershipBodies(t) {
		events = append(events, body.GetEvent())
		if !bytes.Equal(body.GetMemberId(), world.memberId[:]) {
			t.Errorf("event %d names another member", body.GetEvent())
		}
	}
	if !slices.Equal(events, []uint32{1, 2, 3, 4, 5, 6}) {
		t.Errorf("events %v", events)
	}
}

// A member's own device revocation names its approval evidence: presence, with the assertion as stored (§5.6).
func TestRecordAccountingRevocationCarriesItsPresenceAssertion(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	revokedId := sidecar.NewId()
	assertion := []byte("a WebAuthnEvidence as stored")
	statement := bytes.Repeat([]byte{0x77}, 32)
	event := &sidecar.RecordAccountingEvent{
		Kind:            sidecar.SidecarEventMemberRemoved,
		MemberId:        &world.memberId,
		SidecarId:       &revokedId,
		AuthPosition:    9,
		StatementSha256: statement,
		Evidence:        sidecar.RecordMembershipEvidencePresence,
		Assertion:       assertion,
		Reason:          1,
	}
	if _, err := record.Accounting().Mirror(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	// the same statement mirrored again, as a second pass or a second device's would: no second entry
	if ref, err := record.Accounting().Mirror(t.Context(), event); ref != nil || err != nil {
		t.Errorf("a statement mirrored twice: %+v, %v", ref, err)
	}
	bodies := world.membershipBodies(t)
	if len(bodies) != 1 {
		t.Fatalf("%d entries", len(bodies))
	}
	body := bodies[0]
	if body.GetEvidence() != 1 || !bytes.Equal(body.GetAssertion(), assertion) || !bytes.Equal(body.GetStatementSha256(), statement) ||
		body.GetAuthPosition() != 9 || !bytes.Equal(body.GetSidecarId(), revokedId[:]) {
		t.Errorf("the revocation's entry: %v", body)
	}
}

// key_changed mirrors as a key entry; a SidecarEvent of another kind is none of the record's.
func TestRecordAccountingMirrorsAKeyChange(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	groupId := sidecar.NewId()
	event, ok := sidecar.RecordAccountingEventOf(sidecar.SidecarEvent{Kind: sidecar.SidecarEventKeyChanged, SidecarId: &device.sidecarId, GroupId: &groupId})
	if !ok {
		t.Fatal("key_changed is not mirrored")
	}
	if _, ok := sidecar.RecordAccountingEventOf(sidecar.SidecarEvent{Kind: sidecar.SidecarEventHeadAlarm}); ok {
		t.Error("head_alarm read as membership")
	}
	if _, err := record.Accounting().Mirror(t.Context(), event); err != nil {
		t.Fatal(err)
	}
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}
	keys := 0
	for _, entry := range world.newReader(nil, nil).sync(t, world) {
		if entry.Kind() != sidecar.RecordKindKey {
			continue
		}
		body := &protocol.KeyBody{}
		if err := proto.Unmarshal(entry.Body, body); err != nil || body.GetEvent() != 1 || !bytes.Equal(body.GetGroupId(), groupId[:]) {
			t.Errorf("the key entry: %v, %v", body, err)
		}
		keys += 1
	}
	if keys != 1 {
		t.Errorf("%d key entries", keys)
	}
}
