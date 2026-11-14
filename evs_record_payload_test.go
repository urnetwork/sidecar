// QD-806's record form of a payload (question record-slot-104-push-record-slot-bodies, option 1): EvsRecordPayload
// takes section 7 out and leaves every other section's bytes as received, so the statement's hashes hold over the
// record as over the push; a stored record's checks take section 7 absent while a push's still hold it to the new
// slots; and a push in parts, whose bodies ride inside its parts under parts_sha256, still carries them there (question
// push-record-no-slot-bodies-part-slot-bodies).

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A slot object of two keys, each wrapped key's bytes drawn from label.
func evsTestSlotBody(t testing.TB, label string) []byte {
	t.Helper()
	slot := &protocol.EvsSlotObject{}
	for keyIndex := range uint32(2) {
		// evsTestBytes gives at most a digest's 32 bytes, so a wrapped key's are joined from several
		wrapped := []byte{}
		for block := 0; len(wrapped) < EvsWrappedKeyByteCount; block += 1 {
			wrapped = append(wrapped, evsTestBytes(fmt.Sprint("wrapped ", label, " ", keyIndex, " ", block), 32)...)
		}
		slot.Keys = append(slot.Keys, &protocol.EvsSlotKey{KeyIndex: keyIndex, Generation: 2, Wrapped: wrapped[:EvsWrappedKeyByteCount]})
	}
	body, err := EvsEncodeSlotObject(slot)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// evsTestPlan's push with slotCount new slots, and the head's sources standing so section 12 follows section 7: the
// sections on each side of it are present.
func evsTestSlotPlan(t testing.TB, signer *evsTestSigner, label string, changeCount int, slotCount int) *EvsPushPlan {
	t.Helper()
	plan := evsTestPlan(t, signer, label, changeCount)
	for i := range slotCount {
		slotId := evsTestId(fmt.Sprint("slot ", label, " ", i))
		plan.NewObjects = append(plan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()})
		plan.SlotBodies = append(plan.SlotBodies, evsTestSlotBody(t, fmt.Sprint(label, " ", i)))
	}
	plan.SourcesStand = true
	return plan
}

// The record form drops section 7, its header and items, and nothing else: every other section is the bytes the push
// carried, no body or wrapped key is left in it, a second pass changes nothing, a payload with no section 7 comes back
// as it is, and one that does not parse is refused.
func TestEvsRecordPayloadTakesOutTheSlotBodiesAlone(t *testing.T) {
	signer := newEvsTestSigner("record payload")
	plan := evsTestSlotPlan(t, signer, "record", 3, 2)
	built, _ := evsTestBuildAndCheck(t, signer, plan)
	received, err := ParseEvsPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	slotSection := received.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES)
	if len(slotSection) == 0 || len(received.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SOURCE_PATHS)) == 0 {
		t.Fatal("the push carries no section 7, or none after it")
	}

	recordPayload, err := EvsRecordPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(recordPayload) != len(built.Payload)-evsPayloadSectionHeaderByteCount-len(slotSection) {
		t.Fatalf("a record payload of %d bytes from %d, section 7 being %d", len(recordPayload), len(built.Payload), len(slotSection))
	}
	kept, err := ParseEvsPayload(recordPayload)
	if err != nil {
		t.Fatal(err)
	}
	for sectionType := protocol.EvsPayloadSection(1); sectionType <= evsPayloadMaxSectionType; sectionType += 1 {
		if sectionType == protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES {
			if len(kept.Section(sectionType)) != 0 {
				t.Error("the record keeps section 7")
			}
			continue
		}
		if !bytes.Equal(kept.Section(sectionType), received.Section(sectionType)) {
			t.Errorf("section %d differs from the push's", sectionType)
		}
	}
	for _, body := range plan.SlotBodies {
		slot, err := EvsDecodeSlotObject(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, slotKey := range slot.GetKeys() {
			if bytes.Contains(recordPayload, slotKey.GetWrapped()) {
				t.Fatalf("the record holds key %d of a new slot", slotKey.GetKeyIndex())
			}
		}
	}

	again, err := EvsRecordPayload(recordPayload)
	if err != nil || !bytes.Equal(again, recordPayload) {
		t.Fatalf("a second pass: %v", err)
	}
	slotless, _ := evsTestBuildAndCheck(t, signer, evsTestPlan(t, signer, "slotless", 2))
	if same, err := EvsRecordPayload(slotless.Payload); err != nil || !bytes.Equal(same, slotless.Payload) {
		t.Fatalf("a payload with no section 7: %v", err)
	}
	if _, err := EvsRecordPayload(append(bytes.Clone(built.Payload), 0x01)); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a payload with a byte past its last section: %v", err)
	}
}

// A push that drops section 7 beside new slots is refused, as before; its record, which never holds it, checks as a
// record with no slot body, against the same signed statement; a record that still carries section 7 is checked as
// the push was, and one whose section 7 is out of step with the new slots is refused.
func TestEvsRecordChecksTakeSectionSevenAbsentAndAPushsDoNot(t *testing.T) {
	signer := newEvsTestSigner("record checks")
	plan := evsTestSlotPlan(t, signer, "checks", 3, 2)
	built, pushed := evsTestBuildAndCheck(t, signer, plan)
	if len(pushed.SlotBodies) != 2 {
		t.Fatalf("the push checked %d bodies", len(pushed.SlotBodies))
	}
	recordPayload, err := EvsRecordPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EvsCheckPayload(built.Statement, recordPayload); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a push with new slots and no section 7: %v", err)
	}
	slotCount := func(checked *EvsCheckedPayload) int {
		count := 0
		for _, object := range checked.NewObjects {
			if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
				count += 1
			}
		}
		return count
	}
	for label, check := range map[string]func(*EvsStatement, []byte) (*EvsCheckedPayload, error){
		"the record check": EvsCheckRecordPayload,
		"the stored check": EvsCheckStoredPayload,
	} {
		checked, err := check(built.Statement, recordPayload)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		if checked.SlotBodies != nil || slotCount(checked) != 2 || len(checked.Changes) != 3 {
			t.Errorf("%s: %d bodies, %d new slots, %d changes", label, len(checked.SlotBodies), slotCount(checked), len(checked.Changes))
		}
		carried, err := check(built.Statement, built.Payload)
		if err != nil || len(carried.SlotBodies) != 2 {
			t.Errorf("%s over a record that still carries section 7: %v", label, err)
		}
	}

	short, err := ParseEvsPayload(built.Payload)
	if err != nil {
		t.Fatal(err)
	}
	short.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, evsJoinItems(plan.SlotBodies[:1]))
	if _, err := EvsCheckRecordPayload(built.Statement, short.Encode()); !errors.Is(err, ErrEvsPushInvalid) {
		t.Errorf("a record with one body for two new slots: %v", err)
	}
}

// The open part (question push-record-no-slot-bodies-part-slot-bodies): a push in parts carries its slot bodies in
// its parts' sections, which parts_sha256 covers, so a part record keeps them and a stored seal's check reads them
// back. This holds until that question is answered.
func TestEvsPushInPartsStillCarriesItsSlotBodiesInItsParts(t *testing.T) {
	signer := newEvsTestSigner("parts")
	plan := evsTestChangelessPlan(t, signer, 30, 1536*1024)
	slotBody := evsTestSlotBody(t, "parts")
	plan.NewObjects = append(plan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: evsTestId("slot parts").Bytes()})
	plan.SlotBodies = append(plan.SlotBodies, slotBody)
	built, _ := evsTestBuildAndCheck(t, signer, plan)
	if built.Statement.Push.GetPartCount() < 2 {
		t.Fatalf("%d parts", built.Statement.Push.GetPartCount())
	}
	// a slice may split anywhere, so the parts' slices are joined
	joined := []byte{}
	for _, partBytes := range built.Parts {
		part, _, err := parseEvsPushPart(partBytes)
		if err != nil {
			t.Fatal(err)
		}
		sections, err := ParseEvsPayload(part.GetSections())
		if err != nil {
			t.Fatal(err)
		}
		joined = append(joined, sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES)...)
	}
	if !bytes.Equal(joined, evsJoinItems([][]byte{slotBody})) {
		t.Fatal("the parts do not carry the slot body")
	}
	checked, _, err := EvsCheckStoredSeal(built.Statement, built.Parts)
	if err != nil || len(checked.SlotBodies) != 1 {
		t.Fatalf("the stored seal: %v", err)
	}
}
