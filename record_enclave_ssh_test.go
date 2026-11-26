//go:build !sidecar_http && !js

// CTXH-M11-08's record formats (DESIGN-COMPUTE §11.12, §12.7; compute-plan-enc-readings readings 2 and 3, QD-1243;
// CONTRACTS C-26): kind 57 enclave with EnclaveEntryBody, and ReachReceipt's kind 7 ssh with its session fields 12 to 16,
// by their descriptors, round trips and registry rows; the enclave body naming no key or secret by any field's name; a
// reader built before this change keeping an entry of each, the enclave entry as an unknown kind and the receipt's new
// fields as unknown bytes, and verifying the chain past them; DESIGN §22.7's guard finding no server field in either.
// External, on record_writer_test.go's world, and off the js leg, whose tests open no files.

package sidecar_test

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One field a test expects of a message's descriptor.
type testEnclaveSshField struct {
	name   string
	number protoreflect.FieldNumber
	kind   protoreflect.Kind
}

// Holds message's descriptor to fields, each by name, number and kind.
func testEnclaveSshDescriptor(t *testing.T, message proto.Message, fields []testEnclaveSshField, whole bool) {
	t.Helper()
	descriptor := message.ProtoReflect().Descriptor()
	for _, want := range fields {
		field := descriptor.Fields().ByName(protoreflect.Name(want.name))
		if field == nil {
			t.Errorf("%s has no field %s", descriptor.FullName(), want.name)
			continue
		}
		if field.Number() != want.number || field.Kind() != want.kind || field.Cardinality() == protoreflect.Repeated {
			t.Errorf("%s.%s is %d %s, not %d %s", descriptor.FullName(), want.name, field.Number(), field.Kind(), want.number, want.kind)
		}
	}
	if whole && descriptor.Fields().Len() != len(fields) {
		t.Errorf("%s holds %d fields, not %d", descriptor.FullName(), descriptor.Fields().Len(), len(fields))
	}
}

// EnclaveEntryBody and ReachReceipt's session fields by their descriptors, each value round tripping.
func TestEnclaveAndSshFormatsByDescriptor(t *testing.T) {
	testEnclaveSshDescriptor(t, &protocol.EnclaveEntryBody{}, []testEnclaveSshField{
		{name: "enclave_id", number: 1, kind: protoreflect.BytesKind},
		{name: "incarnation", number: 2, kind: protoreflect.Uint64Kind},
		{name: "event", number: 3, kind: protoreflect.Uint32Kind},
		{name: "cause", number: 4, kind: protoreflect.Uint32Kind},
		{name: "cause_run_id", number: 5, kind: protoreflect.BytesKind},
		{name: "cause_run_tainted", number: 6, kind: protoreflect.BoolKind},
		{name: "sidecar_id", number: 7, kind: protoreflect.BytesKind},
		{name: "role", number: 8, kind: protoreflect.Uint32Kind},
		{name: "provider", number: 9, kind: protoreflect.StringKind},
		{name: "attestation", number: 10, kind: protoreflect.MessageKind},
		{name: "egress", number: 11, kind: protoreflect.StringKind},
		{name: "approval_id", number: 12, kind: protoreflect.BytesKind},
	}, true)
	testEnclaveSshDescriptor(t, &protocol.ReachReceipt{}, []testEnclaveSshField{
		{name: "ssh_user", number: 12, kind: protoreflect.StringKind},
		{name: "opened_millis", number: 13, kind: protoreflect.Int64Kind},
		{name: "closed_millis", number: 14, kind: protoreflect.Int64Kind},
		{name: "client_byte_count", number: 15, kind: protoreflect.Uint64Kind},
		{name: "server_byte_count", number: 16, kind: protoreflect.Uint64Kind},
	}, false)
	if fields := (&protocol.ReachReceipt{}).ProtoReflect().Descriptor().Fields(); fields.Len() != 16 {
		t.Errorf("ReachReceipt holds %d fields", fields.Len())
	}

	enclave := &protocol.EnclaveEntryBody{
		EnclaveId: sidecar.NewId().Bytes(), Incarnation: 3, Event: 3, Cause: 2, CauseRunId: sidecar.NewId().Bytes(),
		CauseRunTainted: true, SidecarId: sidecar.NewId().Bytes(), Role: 1, Provider: "example-provider",
		Attestation: &protocol.AttestationResult{}, Egress: "auto", ApprovalId: sidecar.NewId().Bytes(),
	}
	receipt := &protocol.ReachReceipt{
		Kind: uint32(sidecar.RecordReachKindSsh), Owner: sidecar.NewId().Bytes(), Peers: [][]byte{sidecar.NewId().Bytes()},
		SshUser: "agent", OpenedMillis: 1_800_000_000_000, ClosedMillis: 1_800_000_060_000, ClientByteCount: 4096, ServerByteCount: 65536,
	}
	for _, message := range []proto.Message{enclave, receipt} {
		encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		decoded := message.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(encoded, decoded); err != nil || !proto.Equal(decoded, message) {
			t.Errorf("%T does not round trip: %v", message, err)
		}
	}
}

// Kind 57 is enclave, class action, its body EnclaveEntryBody, writable and filed whole beside its header, the number
// after 56, which stays auto_verdict's; reach kind 7 is ssh.
func TestRecordKindEnclaveAndReachSshRegistered(t *testing.T) {
	kind, ok := sidecar.RecordKindNamed("enclave")
	if !ok || kind != sidecar.RecordKindEnclave || uint32(sidecar.RecordKindEnclave) != 57 || kind.String() != "enclave" {
		t.Fatalf("enclave is kind %d (%v)", kind, ok)
	}
	if kind.Class() != sidecar.RecordClassAction || !kind.Writable() || kind.BodyApart() || kind.Derived() {
		t.Errorf("kind 57: class %s, writable %v, body apart %v", kind.Class(), kind.Writable(), kind.BodyApart())
	}
	body, ok := kind.NewBody()
	if !ok || proto.MessageName(body) != "urnetwork.sidecar.EnclaveEntryBody" {
		t.Errorf("kind 57's body: %v", body)
	}
	if sidecar.RecordKind(56).Known() {
		t.Error("kind 56 reads as known before auto_verdict lands")
	}
	if sidecar.RecordReachKindSsh != 7 || sidecar.RecordReachKindSsh.String() != "ssh" || !sidecar.RecordReachKindSsh.Known() {
		t.Errorf("reach kind 7 reads %q", sidecar.RecordReachKindSsh)
	}
}

// No field of the enclave body names a key or a secret: what it holds is an enclave's life, never what provisions it.
func TestEnclaveEntryBodyNamesNoKeyOrSecret(t *testing.T) {
	refused := []string{"key", "secret", "seed", "token", "password", "private", "credential", "nonce", "cookie"}
	var walk func(descriptor protoreflect.MessageDescriptor, prefix string, seen map[protoreflect.FullName]bool)
	walk = func(descriptor protoreflect.MessageDescriptor, prefix string, seen map[protoreflect.FullName]bool) {
		if seen[descriptor.FullName()] {
			return
		}
		seen[descriptor.FullName()] = true
		fields := descriptor.Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			name := strings.ToLower(string(field.Name()))
			for _, word := range refused {
				if strings.Contains(name, word) {
					t.Errorf("%s%s names a %s", prefix, field.Name(), word)
				}
			}
		}
	}
	walk((&protocol.EnclaveEntryBody{}).ProtoReflect().Descriptor(), "EnclaveEntryBody.", map[protoreflect.FullName]bool{})
}

// A reader built before this change: kind 57 is a kind it does not know, so it keeps the enclave entry verified and
// shows it generically, with no body, and the note after it chains on with no alarm; the ssh receipt's fields 12 to 16
// are fields its ReachReceipt does not know, which it keeps as unknown bytes of the stored body, so the body it holds
// is the bytes written and a hash over them still holds.
func TestReaderBeforeEnclaveSshKeepsBothAndVerifiesPast(t *testing.T) {
	world := newTestRecordWorld(t)
	device := world.device(true)
	record := device.open()
	enclave := &protocol.EnclaveEntryBody{EnclaveId: sidecar.NewId().Bytes(), Incarnation: 1, Event: 1, Cause: 1, Role: 1, Provider: "example-provider"}
	testRecordAppend(t, record, &sidecar.RecordDraft{Kind: sidecar.RecordKindEnclave, Source: sidecar.RecordSourceObserved, NoSession: true, Body: enclave})
	receipt := &protocol.ReachReceipt{
		Kind: uint32(sidecar.RecordReachKindSsh), Owner: sidecar.NewId().Bytes(), Peers: [][]byte{sidecar.NewId().Bytes()},
		SshUser: "root", OpenedMillis: world.clock.Now().UnixMilli(), ClosedMillis: world.clock.Now().UnixMilli() + 1000,
		ClientByteCount: 10, ServerByteCount: 20,
	}
	testRecordAppend(t, record, &sidecar.RecordDraft{Kind: sidecar.RecordKindReach, Source: sidecar.RecordSourceObserved, NoSession: true, Body: receipt})
	testRecordAppend(t, record, testRecordNote(nil, "after both"))
	if err := record.Flush(t.Context()); err != nil {
		t.Fatal(err)
	}

	forget := sidecar.ForgetRecordKindForTest(sidecar.RecordKindEnclave)
	reader := device.open()
	if err := reader.Reader().Sync(t.Context(), world.vaultId); err != nil {
		forget()
		t.Fatal(err)
	}
	entries := reader.Reader().Entries(world.vaultId)
	forget()
	if len(entries) != 3 {
		t.Fatalf("%d entries read", len(entries))
	}
	unknown, reach, note := entries[0], entries[1], entries[2]
	if unknown.Kind() != sidecar.RecordKindEnclave || unknown.State != sidecar.RecordEntryLive || unknown.BodyInvalid || unknown.Body == nil {
		t.Errorf("the enclave entry as an unknown kind: state %s, invalid %v", unknown.State, unknown.BodyInvalid)
	}
	if note.State != sidecar.RecordEntryLive || note.Header.Header.GetSeq() != unknown.Header.Header.GetSeq()+2 {
		t.Errorf("the note after them: %s at %d", note.State, note.Header.Header.GetSeq())
	}
	for _, reason := range device.alarmReasons() {
		t.Errorf("an alarm: %s", reason)
	}

	// the receipt's body as a ReachReceipt from before fields 12 to 16 reads it: those are unknown bytes it keeps
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reach.Body, stored) {
		t.Fatal("the reach entry's body is not the bytes written")
	}
	older := testReachReceiptBefore(t)
	parsed := dynamicpb.NewMessage(older)
	if err := proto.Unmarshal(reach.Body, parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.GetUnknown()) == 0 {
		t.Fatal("an older ReachReceipt holds the session fields as known")
	}
	kept, err := proto.MarshalOptions{Deterministic: true}.Marshal(parsed)
	if err != nil || len(kept) != len(stored) {
		t.Fatalf("an older reader's ReachReceipt keeps %d of %d bytes: %v", len(kept), len(stored), err)
	}
	if kindValue := parsed.Get(older.Fields().ByName("kind")).Uint(); sidecar.RecordReachKind(kindValue) != sidecar.RecordReachKindSsh {
		t.Errorf("the older reader's kind %d", kindValue)
	}
}

// ReachReceipt's descriptor as a build before CTXH-M11-08 declared it: fields 1 to 11.
func testReachReceiptBefore(t *testing.T) protoreflect.MessageDescriptor {
	t.Helper()
	file := protodesc.ToFileDescriptorProto((&protocol.ReachReceipt{}).ProtoReflect().Descriptor().ParentFile())
	var message *descriptorpb.DescriptorProto
	for _, candidate := range file.GetMessageType() {
		if candidate.GetName() == "ReachReceipt" {
			message = candidate
		}
	}
	if message == nil {
		t.Fatal("record.proto has no ReachReceipt")
	}
	older := &descriptorpb.DescriptorProto{Name: proto.String("ReachReceipt")}
	for _, field := range message.GetField() {
		if field.GetNumber() <= 11 {
			older.Field = append(older.Field, field)
		}
	}
	standalone := &descriptorpb.FileDescriptorProto{
		Name:        proto.String("record_before_ctxh_m11_08.proto"),
		Package:     proto.String("urnetwork.sidecar.before"),
		Syntax:      proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{older},
	}
	built, err := protodesc.NewFile(standalone, nil)
	if err != nil {
		t.Fatal(err)
	}
	return built.Messages().ByName("ReachReceipt")
}

// DESIGN §22.7's metadata guard finds no new server field: the enclave body and the receipt's session fields travel
// only sealed inside an entry, as every record body does, so neither needs a §2.8 row (I-18).
func TestEnclaveAndSshFormatsAddNoServerField(t *testing.T) {
	guard, err := sidecartest.LoadSchemaGuard()
	if err != nil {
		t.Fatal(err)
	}
	findings, err := guard.Check()
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		for _, name := range []string{"EnclaveEntryBody", "ssh_user", "opened_millis", "closed_millis", "client_byte_count", "server_byte_count"} {
			if strings.Contains(finding, name) {
				t.Errorf("the guard names %s: %s", name, finding)
			}
		}
	}
}
