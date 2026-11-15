// QD-806's record form of a payload (question record-slot-104-push-record-slot-bodies, option 1): EvsRecordPayload
// takes section 7 out and leaves every other section's bytes as received, so the statement's hashes hold over the
// record as over the push; a stored record's checks take section 7 absent while a push's still hold it to the new
// slots. And QD-819's push in parts (question push-record-no-slot-bodies-part-slot-bodies): its bodies ride whole in
// its seal and in none of its parts, a part holding them is refused wherever it is read, its seal's checks hold them
// to the new slots within their bound, and a builder refuses a push whose bodies pass it before signing anything.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
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

// The new slots the checked payload lists.
func evsTestSlotCount(checked *EvsCheckedPayload) int {
	count := 0
	for _, object := range checked.NewObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			count += 1
		}
	}
	return count
}

// A push in parts of evsTestChangelessPlan's shape, 30 changes and sealed metadata past one part, with slotCount new
// slots.
func evsTestSlotPartsPlan(t testing.TB, signer *evsTestSigner, label string, slotCount int) *EvsPushPlan {
	t.Helper()
	plan := evsTestChangelessPlan(t, signer, 30, 1536*1024)
	for i := range slotCount {
		slotId := evsTestId(fmt.Sprint("slot ", label, " ", i))
		plan.NewObjects = append(plan.NewObjects, &EvsNewObject{Kind: protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, Id: slotId.Bytes()})
		plan.SlotBodies = append(plan.SlotBodies, evsTestSlotBody(t, fmt.Sprint(label, " ", i)))
	}
	return plan
}

// Whether any of the bytes holds a slot body of plan's, or any wrapped key in one.
func evsTestHoldsSlotKey(t testing.TB, plan *EvsPushPlan, held ...[]byte) bool {
	t.Helper()
	for _, body := range plan.SlotBodies {
		slot, err := EvsDecodeSlotObject(body)
		if err != nil {
			t.Fatal(err)
		}
		for _, heldBytes := range held {
			if bytes.Contains(heldBytes, body) {
				return true
			}
			for _, slotKey := range slot.GetKeys() {
				if bytes.Contains(heldBytes, slotKey.GetWrapped()) {
					return true
				}
			}
		}
	}
	return false
}

// QD-819 (question push-record-no-slot-bodies-part-slot-bodies): a push in parts carries its slot bodies whole in
// its seal and in none of its parts. No part holds section 7, a body or a wrapped key of one; the built push holds
// section 7 for the seal request; the seal's check joins it and holds it to the new slots, refusing it absent, short
// or out of shape; and the push read back from its records, stored or as a re-seed reads it, takes it absent.
func TestEvsPushInPartsCarriesItsSlotBodiesInItsSealAlone(t *testing.T) {
	signer := newEvsTestSigner("parts")
	plan := evsTestSlotPartsPlan(t, signer, "seal alone", 2)
	built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	if built.Statement.Push.GetPartCount() < 2 || built.Payload != nil {
		t.Fatalf("%d parts", built.Statement.Push.GetPartCount())
	}
	for i, partBytes := range built.Parts {
		part, _, err := parseEvsPushPart(partBytes)
		if err != nil {
			t.Fatal(err)
		}
		sections, err := ParseEvsPayload(part.GetSections())
		if err != nil {
			t.Fatal(err)
		}
		if len(sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES)) != 0 {
			t.Fatalf("part %d holds section 7", i+1)
		}
	}
	if evsTestHoldsSlotKey(t, plan, built.Parts...) {
		t.Fatal("a part holds a slot body or a key of one")
	}
	if !bytes.Equal(built.SlotBodies, evsJoinItems(plan.SlotBodies)) {
		t.Fatalf("the built push holds %d bytes of slot bodies", len(built.SlotBodies))
	}

	checked, _, err := EvsCheckSeal(built.Statement, built.Parts, built.SlotBodies)
	if err != nil || len(checked.SlotBodies) != 2 || evsTestSlotCount(checked) != 2 {
		t.Fatalf("the seal: %v", err)
	}
	for i, body := range checked.SlotBodies {
		if !bytes.Equal(body, plan.SlotBodies[i]) {
			t.Fatalf("slot body %d checked as other bytes", i)
		}
	}
	notASlot := evsJoinItems([][]byte{plan.SlotBodies[0], []byte("not a slot object")})
	for label, slotBodies := range map[string][]byte{
		"none":           nil,
		"one of two":     evsJoinItems(plan.SlotBodies[:1]),
		"three of two":   evsJoinItems(append(slices.Clone(plan.SlotBodies), plan.SlotBodies[0])),
		"not a slot":     notASlot,
		"an item cut":    built.SlotBodies[:len(built.SlotBodies)-1],
		"past the bound": make([]byte, DefaultEvsFormatSettings().SealSlotBodiesMaxByteCount+1),
	} {
		if _, _, err := EvsCheckSeal(built.Statement, built.Parts, slotBodies); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a seal with slot bodies %s: %v", label, err)
		}
		if _, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, make([][]byte, len(built.Parts)), slotBodies); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("a format-2 seal with slot bodies %s: %v", label, err)
		}
	}
	if checked, _, err := EvsCheckSealFormat2(built.Statement, built.Parts, make([][]byte, len(built.Parts)), built.SlotBodies); err != nil || len(checked.SlotBodies) != 2 {
		t.Fatalf("the format-2 seal: %v", err)
	}

	for label, check := range map[string]func(*EvsStatement, [][]byte) (*EvsCheckedPayload, []*EvsCheckedPart, error){
		"stored": EvsCheckStoredSeal,
		"record": EvsCheckRecordSeal,
	} {
		checked, _, err := check(built.Statement, built.Parts)
		if err != nil || checked.SlotBodies != nil || evsTestSlotCount(checked) != 2 || len(checked.Changes) != 30 {
			t.Errorf("the %s seal: %v", label, err)
		}
	}
}

// A part whose sections hold section 7 is INVALID wherever it is read (QD-819): as it arrives, in either format, as a
// record keeps it, and inside every seal, even with the seal's own bodies matching. Its statement is signed again over
// the changed part, so only section 7 refuses it.
func TestEvsPartHoldingSlotBodiesIsRefused(t *testing.T) {
	signer := newEvsTestSigner("part holding")
	plan := evsTestSlotPartsPlan(t, signer, "part holding", 1)
	built, err := NewEvsStatementBuilder(signer.sign).Build(plan)
	if err != nil {
		t.Fatal(err)
	}
	last := len(built.Parts) - 1
	message := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(built.Parts[last], message); err != nil {
		t.Fatal(err)
	}
	sections, err := ParseEvsPayload(message.GetSections())
	if err != nil {
		t.Fatal(err)
	}
	sections.SetSection(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES, built.SlotBodies)
	message.Sections = sections.Encode()
	holding, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		t.Fatal(err)
	}
	parts := append(slices.Clone(built.Parts[:last]), holding)
	partHashes := []byte{}
	for _, partBytes := range parts {
		digest := sha256.Sum256(partBytes)
		partHashes = append(partHashes, digest[:]...)
	}
	push := proto.Clone(built.Statement.Push).(*protocol.EvsPush)
	partsDigest := sha256.Sum256(partHashes)
	push.PartsSha256 = partsDigest[:]
	statement := evsTestResign(t, signer, push)

	if _, err := EvsCheckPart(statement, parts[0]); err != nil {
		t.Fatalf("the part holding no body: %v", err)
	}
	for label, check := range map[string]func() error{
		"arriving": func() error { _, err := EvsCheckPart(statement, holding); return err },
		"format 2": func() error { _, err := EvsCheckPartFormat2(statement, holding, nil); return err },
		"stored":   func() error { _, err := EvsCheckStoredPart(statement, holding); return err },
		"seal":     func() error { _, _, err := EvsCheckSeal(statement, parts, built.SlotBodies); return err },
		"seal of format 2": func() error {
			_, _, err := EvsCheckSealFormat2(statement, parts, make([][]byte, len(parts)), built.SlotBodies)
			return err
		},
		"seal with no bodies": func() error { _, _, err := EvsCheckSeal(statement, parts, nil); return err },
		"record seal":         func() error { _, _, err := EvsCheckRecordSeal(statement, parts); return err },
		"stored seal":         func() error { _, _, err := EvsCheckStoredSeal(statement, parts); return err },
	} {
		if err := check(); !errors.Is(err, ErrEvsPushInvalid) {
			t.Errorf("%s: %v", label, err)
		}
	}
}

// The seal's bound (QD-819): a push in parts whose slot bodies pass it is ErrEvsSlotBodiesTooLarge before anything is
// signed, one at the bound builds, and a one-part push keeps the same bodies in its payload whatever the bound.
func TestEvsBuildRefusesSlotBodiesPastTheSealsBound(t *testing.T) {
	signer := newEvsTestSigner("bound")
	signed := 0
	sign := func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
		signed += 1
		return signer.sign(purpose, signedType, body, agentId)
	}
	plan := evsTestSlotPartsPlan(t, signer, "bound", 3)
	format := DefaultEvsFormatSettings()
	format.SealSlotBodiesMaxByteCount = len(evsJoinItems(plan.SlotBodies)) - 1
	builder := &EvsStatementBuilder{sign: sign, format: format}
	if _, err := builder.Build(plan); !errors.Is(err, ErrEvsSlotBodiesTooLarge) || signed != 0 {
		t.Fatalf("bodies past the bound: %v, %d signed", err, signed)
	}
	format.SealSlotBodiesMaxByteCount += 1
	built, err := builder.Build(plan)
	if err != nil || len(built.Parts) < 2 || !bytes.Equal(built.SlotBodies, evsJoinItems(plan.SlotBodies)) {
		t.Fatalf("bodies at the bound: %v", err)
	}
	format.SealSlotBodiesMaxByteCount = 1
	onePart := evsTestSlotPlan(t, signer, "bound one part", 3, 3)
	built, err = builder.Build(onePart)
	if err != nil || len(built.Parts) != 0 || built.SlotBodies != nil {
		t.Fatalf("a one-part push: %v", err)
	}
	payload, err := ParseEvsPayload(built.Payload)
	if err != nil || !bytes.Equal(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES), evsJoinItems(onePart.SlotBodies)) {
		t.Fatalf("a one-part push's section 7: %v", err)
	}
}
