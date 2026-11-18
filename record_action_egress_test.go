// An egress change's requirement of default egress, require_default_egress = 41 (QD-1060), as every leg's parse and
// template match read it: an approver built before the field refuses an action that sets it, since its parse refuses
// a field it cannot name, the closed direction; and a template binds the requirement whether it sets it or not
// (TemplateBound), so the template an approver saw without it covers no use that carries it. The gate's side is
// record_gate_egress_test.go's.

package sidecar

import (
	"bytes"
	"encoding/hex"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One subject's egress change to exits through one sidecar, with the requirement of default egress or without it, a
// template where scope.
func testEgressExitsAction(t *testing.T, requireDefaultEgress bool, scope bool) *StoredCanonicalAction {
	t.Helper()
	return buildTestAction(t, &protocol.CanonicalAction{
		Kind:                 uint32(SidecarActionEgressChange),
		Scope:                scope,
		Subject:              testConfigId("egress subject").Bytes(),
		EgressMode:           uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS),
		GrantDst:             []string{"sidecar:" + hex.EncodeToString(testConfigId("egress exit").Bytes())},
		RequireDefaultEgress: requireDefaultEgress,
	})
}

// CanonicalAction as a build before QD-1060 declares it: record.proto's registered descriptor with field 41 taken out.
func testCanonicalActionBeforeRequirement(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	registered, err := protoregistry.GlobalFiles.FindFileByPath(protocol.File_protocol_record_proto.Path())
	if err != nil {
		t.Fatal(err)
	}
	fileProto := proto.Clone(protodesc.ToFileDescriptorProto(registered)).(*descriptorpb.FileDescriptorProto)
	found := false
	for _, message := range fileProto.MessageType {
		if message.GetName() != "CanonicalAction" {
			continue
		}
		fields := []*descriptorpb.FieldDescriptorProto{}
		for _, field := range message.Field {
			if field.GetNumber() == canonicalActionFieldRequireDefaultEgress {
				found = true
				continue
			}
			fields = append(fields, field)
		}
		message.Field = fields
	}
	if !found {
		t.Fatal("record.proto's CanonicalAction declares no field 41")
	}
	older, err := protodesc.NewFile(fileProto, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return older.Messages().ByName("CanonicalAction")
}

// An approver built before require_default_egress refuses an action that sets it (QD-1060's closed direction): read
// under its CanonicalAction, which declares no field 41, the requirement's bytes leave exactly field 41's record as a
// field it cannot name, and held as that build holds it, every field it names set and that record kept, the bytes are
// the requirement's own and the parse's rules refuse them. The same exits without the requirement leave it nothing it
// cannot name, so it reads them as before, and this build names the field and reads both.
func TestEgressChangeRequirementRefusedByAnOlderParse(t *testing.T) {
	plain := testEgressExitsAction(t, false, false)
	required := testEgressExitsAction(t, true, false)
	older := testCanonicalActionBeforeRequirement(t)
	readOlder := func(stored []byte) protoreflect.Message {
		message := dynamicpb.NewMessage(older)
		if err := proto.Unmarshal(stored, message); err != nil {
			t.Fatal(err)
		}
		return message
	}

	unknown := readOlder(required.Bytes).GetUnknown()
	want := protowire.AppendVarint(protowire.AppendTag(nil, canonicalActionFieldRequireDefaultEgress, protowire.VarintType), 1)
	if !bytes.Equal(unknown, want) {
		t.Fatalf("an older build cannot name %x of the requirement's bytes, want %x", unknown, want)
	}
	if plainUnknown := readOlder(plain.Bytes).GetUnknown(); len(plainUnknown) != 0 {
		t.Fatalf("an older build cannot name %x of the exits alone", plainUnknown)
	}

	asOlder := proto.Clone(required.Action).(*protocol.CanonicalAction)
	asOlder.RequireDefaultEgress = false
	asOlder.ProtoReflect().SetUnknown(unknown)
	if !bytes.Equal(testRecordStored(t, asOlder), required.Bytes) {
		t.Fatal("the older build holds other bytes than the requirement's")
	}
	if err := canonicalActionCheck(asOlder, CanonicalActionVersionKnown); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("the requirement as an older build holds it: %v", err)
	}
	// the builder takes no field it cannot name either
	if _, err := NewCanonicalAction(asOlder); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("an action built with the requirement unnamed: %v", err)
	}

	for name, stored := range map[string]*StoredCanonicalAction{"the exits alone": plain, "the requirement": required} {
		parsed, err := ParseStoredCanonicalAction(stored.Bytes)
		if err != nil {
			t.Errorf("%s: this build's parse: %v", name, err)
			continue
		}
		if parsed.Action.GetRequireDefaultEgress() != (stored == required) {
			t.Errorf("%s: this build reads require_default_egress %t", name, parsed.Action.GetRequireDefaultEgress())
		}
	}
}

// A template binds the requirement whether it sets it or not (TemplateBound; question
// egress-lock-action-field-template-requirement): one of the exits without the requirement covers those exits and
// not the same exits with it, whose requirement its approver never saw, and one that requires it covers the
// requirement's filing and not the exits alone. A template of other exits covers neither, and another kind's template
// still matches anything in a field it leaves empty, its row binding none.
func TestEgressChangeTemplateBindsTheRequirement(t *testing.T) {
	plain := testEgressExitsAction(t, false, false)
	required := testEgressExitsAction(t, true, false)
	template := testEgressExitsAction(t, false, true)
	requiring := testEgressExitsAction(t, true, true)
	for _, c := range []struct {
		name     string
		template *StoredCanonicalAction
		use      *StoredCanonicalAction
		want     bool
	}{
		{name: "the exits alone under their template", template: template, use: plain, want: true},
		{name: "the requirement under the exits' template", template: template, use: required, want: false},
		{name: "the requirement under its template", template: requiring, use: required, want: true},
		{name: "the exits alone under the requirement's template", template: requiring, use: plain, want: false},
	} {
		if got := ActionMatchesTemplate(c.template, c.use); got != c.want {
			t.Errorf("%s: matches %t", c.name, got)
		}
	}
	other := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionEgressChange), Scope: true, Subject: testConfigId("egress subject").Bytes(),
		EgressMode: uint32(bridge.BridgeEgressMode_BRIDGE_EGRESS_MODE_EXITS),
		GrantDst:   []string{"sidecar:" + hex.EncodeToString(testConfigId("egress other exit").Bytes())},
	})
	if ActionMatchesTemplate(other, plain) || ActionMatchesTemplate(other, required) {
		t.Error("a template of other exits covers these")
	}

	// mail's row binds nothing: its template still matches a use whatever the fields it leaves empty hold
	mailTemplate := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Scope: true, Recipients: []string{"a@example.com", "b@example.com"}, Alias: "me",
	})
	mailUse := buildTestAction(t, &protocol.CanonicalAction{
		Kind: uint32(SidecarActionMail), Recipients: []string{"a@example.com"}, BodySha256: bytes.Repeat([]byte{0x61}, 32),
		Alias: "me", Preview: "a preview",
	})
	if !ActionMatchesTemplate(mailTemplate, mailUse) {
		t.Error("a mail template no longer covers a use filling what it leaves empty")
	}
	if row, ok := CanonicalActionFields(SidecarActionMail); !ok || len(row.TemplateBound) != 0 {
		t.Error("mail's row binds a field in its templates")
	}
}

// Every field a row binds in its templates is one of its optional fields, which a use may leave empty: a required one
// every use fills, so a template leaving it empty would cover nothing, and one outside the row no action sets. Only
// egress_change binds one, its requirement of default egress.
func TestTemplateBoundFieldsAreOptional(t *testing.T) {
	fields := (&protocol.CanonicalAction{}).ProtoReflect().Descriptor().Fields()
	bindingKinds := []SidecarActionKind{}
	for _, row := range canonicalActionKindRows {
		for _, number := range row.TemplateBound {
			if fields.ByNumber(number) == nil || !slices.Contains(row.Optional, number) {
				t.Errorf("kind %d binds field %d in its templates, which is none of its optional fields", row.Kind, number)
			}
		}
		if 0 < len(row.TemplateBound) {
			bindingKinds = append(bindingKinds, row.Kind)
		}
	}
	row, _ := CanonicalActionFields(SidecarActionEgressChange)
	if !slices.Equal(bindingKinds, []SidecarActionKind{SidecarActionEgressChange}) ||
		!slices.Equal(row.TemplateBound, []protoreflect.FieldNumber{canonicalActionFieldRequireDefaultEgress}) {
		t.Errorf("kinds %v bind fields in their templates, egress_change's %v", bindingKinds, row.TemplateBound)
	}
}
