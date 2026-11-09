// §6's wire freeze (D-PROTO-20, D-PROTO-7): wire_lock.json lists every released field number of §6's
// messages, with its name and its kind, and every released value of MessageType, ErrorCode,
// StreamRejectCode, StreamResetCode and SignedType, with the reservations each keeps, and this fails if
// one moves, changes kind or disappears. A new field or value is additive, so it passes, and
// SIDECAR_REGENERATE_WIRE_LOCK=1 adds what is new to the lock, never changing or dropping a line already
// there: M10's SEARCH pair and feature bits, and any value an owner adds to the registries, join it that
// way. The goldens beside it are the root's envelope_wire_test.go, over testdata/wire/.
//
// The lock names messages by full name and no file, so plan-PROTO-device-role-push-types' move of Envelope
// and the push messages into protocol/bridge, whose names and numbers stay, changes nothing here.

package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Where the lock is, from this directory.
const testWireLockPath = "wire_lock.json"

// Set, the lock gains what the descriptors declare beyond it, and nothing it holds changes.
const testWireLockRegenerateEnvironment = "SIDECAR_REGENERATE_WIRE_LOCK"

// §6's messages (§6.5, §6.7, §6.8, §6.9's Signed), and AuthPin, which HeadCheck carries, so its bytes
// freeze with HeadCheck's.
var testWireLockMessages = []protoreflect.FullName{
	"urnetwork.sidecar.Envelope",
	"urnetwork.sidecar.Chunk",
	"urnetwork.sidecar.Error",
	"urnetwork.sidecar.Hello",
	"urnetwork.sidecar.HelloResult",
	"urnetwork.sidecar.HeadCheck",
	"urnetwork.sidecar.HeadCheckResult",
	"urnetwork.sidecar.UnverifiedPin",
	"urnetwork.sidecar.GroupHead",
	"urnetwork.sidecar.GenHead",
	"urnetwork.sidecar.RefHead",
	"urnetwork.sidecar.HeadCheckProofRequest",
	"urnetwork.sidecar.HeadCheckProof",
	"urnetwork.sidecar.AuthPin",
	"urnetwork.sidecar.StreamOpen",
	"urnetwork.sidecar.StreamAccept",
	"urnetwork.sidecar.StreamReject",
	"urnetwork.sidecar.StreamData",
	"urnetwork.sidecar.StreamWindow",
	"urnetwork.sidecar.StreamClose",
	"urnetwork.sidecar.StreamReset",
	"urnetwork.sidecar.PushReset",
	"urnetwork.sidecar.TopicVersion",
	"urnetwork.sidecar.PushHint",
	"urnetwork.sidecar.PollResponse",
	"urnetwork.sidecar.Signed",
	"urnetwork.sidecar.WebAuthnEvidence",
}

// The registries and codes whose numbers are permanent once released (§6.11).
var testWireLockEnums = []protoreflect.FullName{
	"urnetwork.sidecar.MessageType",
	"urnetwork.sidecar.ErrorCode",
	"urnetwork.sidecar.StreamRejectCode",
	"urnetwork.sidecar.StreamResetCode",
	"urnetwork.sidecar.SignedType",
}

// The lock as the file holds it.
type testWireLock struct {
	Comment  []string               `json:"comment"`
	Messages []*testWireLockMessage `json:"messages"`
	Enums    []*testWireLockEnum    `json:"enums"`
}

type testWireLockMessage struct {
	Name            string               `json:"name"`
	Fields          []*testWireLockField `json:"fields"`
	ReservedNumbers [][2]int32           `json:"reserved_numbers,omitempty"`
	ReservedNames   []string             `json:"reserved_names,omitempty"`
}

// One field: its number, its name and what decodes it, "repeated " first for a list and a message's or
// enum's full name after its kind.
type testWireLockField struct {
	Number int32  `json:"number"`
	Name   string `json:"name"`
	Kind   string `json:"kind"`
}

type testWireLockEnum struct {
	Name            string               `json:"name"`
	Values          []*testWireLockValue `json:"values"`
	ReservedNumbers [][2]int32           `json:"reserved_numbers,omitempty"`
	ReservedNames   []string             `json:"reserved_names,omitempty"`
}

type testWireLockValue struct {
	Number int32  `json:"number"`
	Name   string `json:"name"`
}

// What the lock holds about a field's encoding: its cardinality, kind and type, which together fix how
// its bytes decode.
func testWireLockKind(field protoreflect.FieldDescriptor) string {
	kind := field.Kind().String()
	switch {
	case field.Message() != nil:
		kind += " " + string(field.Message().FullName())
	case field.Enum() != nil:
		kind += " " + string(field.Enum().FullName())
	}
	if field.Cardinality() == protoreflect.Repeated {
		kind = "repeated " + kind
	}
	return kind
}

// The reserved ranges of a message or an enum, inclusive at both ends.
func testWireLockRanges(ranges interface {
	Len() int
	Get(i int) [2]protoreflect.FieldNumber
}) [][2]int32 {
	inclusive := [][2]int32{}
	for i := range ranges.Len() {
		r := ranges.Get(i)
		// a message's ranges end exclusive
		inclusive = append(inclusive, [2]int32{int32(r[0]), int32(r[1]) - 1})
	}
	return inclusive
}

func testWireLockEnumRanges(ranges protoreflect.EnumRanges) [][2]int32 {
	inclusive := [][2]int32{}
	for i := range ranges.Len() {
		r := ranges.Get(i)
		inclusive = append(inclusive, [2]int32{int32(r[0]), int32(r[1])})
	}
	return inclusive
}

func testWireLockNames(names protoreflect.Names) []string {
	list := []string{}
	for i := range names.Len() {
		list = append(list, string(names.Get(i)))
	}
	slices.Sort(list)
	return list
}

// A message as the descriptors declare it now.
func testWireLockMessageOf(message protoreflect.MessageDescriptor) *testWireLockMessage {
	locked := &testWireLockMessage{
		Name:            string(message.FullName()),
		ReservedNumbers: testWireLockRanges(message.ReservedRanges()),
		ReservedNames:   testWireLockNames(message.ReservedNames()),
	}
	fields := message.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		locked.Fields = append(locked.Fields, &testWireLockField{Number: int32(field.Number()), Name: string(field.Name()), Kind: testWireLockKind(field)})
	}
	slices.SortFunc(locked.Fields, func(a *testWireLockField, b *testWireLockField) int {
		return int(a.Number - b.Number)
	})
	return locked
}

// An enum as the descriptors declare it now.
func testWireLockEnumOf(enum protoreflect.EnumDescriptor) *testWireLockEnum {
	locked := &testWireLockEnum{
		Name:            string(enum.FullName()),
		ReservedNumbers: testWireLockEnumRanges(enum.ReservedRanges()),
		ReservedNames:   testWireLockNames(enum.ReservedNames()),
	}
	values := enum.Values()
	for i := range values.Len() {
		value := values.Get(i)
		locked.Values = append(locked.Values, &testWireLockValue{Number: int32(value.Number()), Name: string(value.Name())})
	}
	slices.SortFunc(locked.Values, func(a *testWireLockValue, b *testWireLockValue) int {
		return int(a.Number - b.Number)
	})
	return locked
}

// Finds a declaration by full name: the registry's, or a planted one in a test.
type testWireLockFind func(name protoreflect.FullName) (protoreflect.Descriptor, error)

// What the descriptors find breaks the lock: each locked field and value still at its number, with its name
// and its kind, and each reservation kept. What is new passes.
func testWireLockFindings(lock *testWireLock, find testWireLockFind) []string {
	findings := []string{}
	for _, lockedMessage := range lock.Messages {
		descriptor, err := find(protoreflect.FullName(lockedMessage.Name))
		message, ok := descriptor.(protoreflect.MessageDescriptor)
		if err != nil || !ok {
			findings = append(findings, fmt.Sprintf("message %s is gone", lockedMessage.Name))
			continue
		}
		fields := message.Fields()
		for _, lockedField := range lockedMessage.Fields {
			byNumber := fields.ByNumber(protoreflect.FieldNumber(lockedField.Number))
			byName := fields.ByName(protoreflect.Name(lockedField.Name))
			switch {
			case byNumber == nil && byName == nil:
				findings = append(findings, fmt.Sprintf("%s.%s (%d) is gone", lockedMessage.Name, lockedField.Name, lockedField.Number))
			case byName != nil && int32(byName.Number()) != lockedField.Number:
				findings = append(findings, fmt.Sprintf("%s.%s moved from %d to %d", lockedMessage.Name, lockedField.Name, lockedField.Number, byName.Number()))
			case byNumber == nil:
				findings = append(findings, fmt.Sprintf("%s's %d is gone", lockedMessage.Name, lockedField.Number))
			case string(byNumber.Name()) != lockedField.Name:
				findings = append(findings, fmt.Sprintf("%s's %d is %s now, locked as %s", lockedMessage.Name, lockedField.Number, byNumber.Name(), lockedField.Name))
			case testWireLockKind(byNumber) != lockedField.Kind:
				findings = append(findings, fmt.Sprintf("%s.%s is %s now, locked as %s", lockedMessage.Name, lockedField.Name, testWireLockKind(byNumber), lockedField.Kind))
			}
		}
		for _, r := range lockedMessage.ReservedNumbers {
			if !slices.Contains(testWireLockRanges(message.ReservedRanges()), r) {
				findings = append(findings, fmt.Sprintf("%s no longer reserves %d to %d", lockedMessage.Name, r[0], r[1]))
			}
		}
		for _, name := range lockedMessage.ReservedNames {
			if !message.ReservedNames().Has(protoreflect.Name(name)) {
				findings = append(findings, fmt.Sprintf("%s no longer reserves %s", lockedMessage.Name, name))
			}
		}
	}
	for _, lockedEnum := range lock.Enums {
		descriptor, err := find(protoreflect.FullName(lockedEnum.Name))
		enum, ok := descriptor.(protoreflect.EnumDescriptor)
		if err != nil || !ok {
			findings = append(findings, fmt.Sprintf("enum %s is gone", lockedEnum.Name))
			continue
		}
		values := enum.Values()
		for _, lockedValue := range lockedEnum.Values {
			byName := values.ByName(protoreflect.Name(lockedValue.Name))
			byNumber := values.ByNumber(protoreflect.EnumNumber(lockedValue.Number))
			switch {
			case byName == nil && byNumber == nil:
				findings = append(findings, fmt.Sprintf("%s.%s (%d) is gone", lockedEnum.Name, lockedValue.Name, lockedValue.Number))
			case byName != nil && int32(byName.Number()) != lockedValue.Number:
				findings = append(findings, fmt.Sprintf("%s.%s moved from %d to %d", lockedEnum.Name, lockedValue.Name, lockedValue.Number, byName.Number()))
			case byNumber == nil:
				findings = append(findings, fmt.Sprintf("%s's %d is gone", lockedEnum.Name, lockedValue.Number))
			case string(byNumber.Name()) != lockedValue.Name:
				findings = append(findings, fmt.Sprintf("%s's %d is %s now, locked as %s", lockedEnum.Name, lockedValue.Number, byNumber.Name(), lockedValue.Name))
			}
		}
		for _, r := range lockedEnum.ReservedNumbers {
			if !slices.Contains(testWireLockEnumRanges(enum.ReservedRanges()), r) {
				findings = append(findings, fmt.Sprintf("%s no longer reserves %d to %d", lockedEnum.Name, r[0], r[1]))
			}
		}
		for _, name := range lockedEnum.ReservedNames {
			if !enum.ReservedNames().Has(protoreflect.Name(name)) {
				findings = append(findings, fmt.Sprintf("%s no longer reserves %s", lockedEnum.Name, name))
			}
		}
	}
	return findings
}

// What the descriptors declare beyond the lock, as the lines regeneration would add.
func testWireLockAdditions(lock *testWireLock, find testWireLockFind) []string {
	additions := []string{}
	lockedMessages := map[string]*testWireLockMessage{}
	for _, lockedMessage := range lock.Messages {
		lockedMessages[lockedMessage.Name] = lockedMessage
	}
	for _, name := range testWireLockMessages {
		descriptor, err := find(name)
		if err != nil {
			continue
		}
		current := testWireLockMessageOf(descriptor.(protoreflect.MessageDescriptor))
		lockedMessage := lockedMessages[current.Name]
		for _, field := range current.Fields {
			if lockedMessage == nil || !slices.ContainsFunc(lockedMessage.Fields, func(locked *testWireLockField) bool { return locked.Number == field.Number }) {
				additions = append(additions, fmt.Sprintf("%s.%s = %d", current.Name, field.Name, field.Number))
			}
		}
	}
	lockedEnums := map[string]*testWireLockEnum{}
	for _, lockedEnum := range lock.Enums {
		lockedEnums[lockedEnum.Name] = lockedEnum
	}
	for _, name := range testWireLockEnums {
		descriptor, err := find(name)
		if err != nil {
			continue
		}
		current := testWireLockEnumOf(descriptor.(protoreflect.EnumDescriptor))
		lockedEnum := lockedEnums[current.Name]
		for _, value := range current.Values {
			if lockedEnum == nil || !slices.ContainsFunc(lockedEnum.Values, func(locked *testWireLockValue) bool { return locked.Number == value.Number }) {
				additions = append(additions, fmt.Sprintf("%s.%s = %d", current.Name, value.Name, value.Number))
			}
		}
	}
	return additions
}

// The lock with every addition joined, each list in number order, every line it held kept as it was.
func testWireLockRegenerated(lock *testWireLock, find testWireLockFind) *testWireLock {
	regenerated := &testWireLock{Comment: lock.Comment}
	lockedMessages := map[string]*testWireLockMessage{}
	for _, lockedMessage := range lock.Messages {
		lockedMessages[lockedMessage.Name] = lockedMessage
	}
	for _, name := range testWireLockMessages {
		descriptor, err := find(name)
		if err != nil {
			panic(err)
		}
		current := testWireLockMessageOf(descriptor.(protoreflect.MessageDescriptor))
		if lockedMessage := lockedMessages[current.Name]; lockedMessage != nil {
			for _, field := range current.Fields {
				if !slices.ContainsFunc(lockedMessage.Fields, func(locked *testWireLockField) bool { return locked.Number == field.Number }) {
					lockedMessage.Fields = append(lockedMessage.Fields, field)
				}
			}
			slices.SortFunc(lockedMessage.Fields, func(a *testWireLockField, b *testWireLockField) int {
				return int(a.Number - b.Number)
			})
			current.Fields = lockedMessage.Fields
		}
		regenerated.Messages = append(regenerated.Messages, current)
	}
	lockedEnums := map[string]*testWireLockEnum{}
	for _, lockedEnum := range lock.Enums {
		lockedEnums[lockedEnum.Name] = lockedEnum
	}
	for _, name := range testWireLockEnums {
		descriptor, err := find(name)
		if err != nil {
			panic(err)
		}
		current := testWireLockEnumOf(descriptor.(protoreflect.EnumDescriptor))
		if lockedEnum := lockedEnums[current.Name]; lockedEnum != nil {
			for _, value := range current.Values {
				if !slices.ContainsFunc(lockedEnum.Values, func(locked *testWireLockValue) bool { return locked.Number == value.Number }) {
					lockedEnum.Values = append(lockedEnum.Values, value)
				}
			}
			slices.SortFunc(lockedEnum.Values, func(a *testWireLockValue, b *testWireLockValue) int {
				return int(a.Number - b.Number)
			})
			current.Values = lockedEnum.Values
		}
		regenerated.Enums = append(regenerated.Enums, current)
	}
	return regenerated
}

// The lock as the file writes it: one field, value or reservation a line, so a review reads each change.
func testWireLockJson(lock *testWireLock) ([]byte, error) {
	var out bytes.Buffer
	line := func(indent string, value any, last bool) error {
		data, err := json.Marshal(value)
		if err != nil {
			return err
		}
		out.WriteString(indent)
		out.Write(data)
		if !last {
			out.WriteString(",")
		}
		out.WriteString("\n")
		return nil
	}
	list := func(indent string, count int, each func(i int) any) error {
		for i := range count {
			if err := line(indent, each(i), i == count-1); err != nil {
				return err
			}
		}
		return nil
	}
	out.WriteString("{\n  \"comment\": [\n")
	if err := list("    ", len(lock.Comment), func(i int) any { return lock.Comment[i] }); err != nil {
		return nil, err
	}
	out.WriteString("  ],\n  \"messages\": [\n")
	for i, message := range lock.Messages {
		name, _ := json.Marshal(message.Name)
		fmt.Fprintf(&out, "    {\n      \"name\": %s,\n      \"fields\": [\n", name)
		if err := list("        ", len(message.Fields), func(i int) any { return message.Fields[i] }); err != nil {
			return nil, err
		}
		out.WriteString("      ]")
		if 0 < len(message.ReservedNumbers) {
			numbers, _ := json.Marshal(message.ReservedNumbers)
			fmt.Fprintf(&out, ",\n      \"reserved_numbers\": %s", numbers)
		}
		if 0 < len(message.ReservedNames) {
			names, _ := json.Marshal(message.ReservedNames)
			fmt.Fprintf(&out, ",\n      \"reserved_names\": %s", names)
		}
		out.WriteString("\n    }")
		if i < len(lock.Messages)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString("  ],\n  \"enums\": [\n")
	for i, enum := range lock.Enums {
		name, _ := json.Marshal(enum.Name)
		fmt.Fprintf(&out, "    {\n      \"name\": %s,\n      \"values\": [\n", name)
		if err := list("        ", len(enum.Values), func(i int) any { return enum.Values[i] }); err != nil {
			return nil, err
		}
		out.WriteString("      ]")
		if 0 < len(enum.ReservedNumbers) {
			numbers, _ := json.Marshal(enum.ReservedNumbers)
			fmt.Fprintf(&out, ",\n      \"reserved_numbers\": %s", numbers)
		}
		if 0 < len(enum.ReservedNames) {
			names, _ := json.Marshal(enum.ReservedNames)
			fmt.Fprintf(&out, ",\n      \"reserved_names\": %s", names)
		}
		out.WriteString("\n    }")
		if i < len(lock.Enums)-1 {
			out.WriteString(",")
		}
		out.WriteString("\n")
	}
	out.WriteString("  ]\n}\n")
	// what it wrote reads back as the same lock
	reread := &testWireLock{}
	if err := json.Unmarshal(out.Bytes(), reread); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func testReadWireLock(t testing.TB) *testWireLock {
	t.Helper()
	data, err := os.ReadFile(testWireLockPath)
	if err != nil {
		t.Fatal(err)
	}
	lock := &testWireLock{}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(lock); err != nil {
		t.Fatalf("%s: %v", testWireLockPath, err)
	}
	return lock
}

// The registry both packages register into.
func testWireLockRegistry(name protoreflect.FullName) (protoreflect.Descriptor, error) {
	return protoregistry.GlobalFiles.FindDescriptorByName(name)
}

// Every locked number stands: no field or value moved, changed kind or went, and every reservation, the
// withdrawn EvsHeadCheck's 0x1402-0x1403 and its names among them, holds. A run with
// SIDECAR_REGENERATE_WIRE_LOCK set first joins what is new, never touching what the lock held.
func TestWireLockHolds(t *testing.T) {
	// a binary that never linked bridge would find its types gone, which would read as a broken freeze
	_ = bridge.SignedType_SIGNED_TYPE_NONE
	lock := testReadWireLock(t)
	if os.Getenv(testWireLockRegenerateEnvironment) != "" {
		if findings := testWireLockFindings(lock, testWireLockRegistry); 0 < len(findings) {
			t.Fatalf("regenerating would hide a broken freeze:\n%s", strings.Join(findings, "\n"))
		}
		regenerated := testWireLockRegenerated(lock, testWireLockRegistry)
		data, err := testWireLockJson(regenerated)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(testWireLockPath, data, 0o644); err != nil {
			t.Fatal(err)
		}
		lock = testReadWireLock(t)
	}
	for _, finding := range testWireLockFindings(lock, testWireLockRegistry) {
		t.Error(finding)
	}
	// the lock names exactly the messages and enums it freezes, so none is dropped from it by an edit
	names := []string{}
	for _, lockedMessage := range lock.Messages {
		names = append(names, lockedMessage.Name)
	}
	for _, name := range testWireLockMessages {
		if !slices.Contains(names, string(name)) {
			t.Errorf("the lock holds no %s", name)
		}
	}
	enumNames := []string{}
	for _, lockedEnum := range lock.Enums {
		enumNames = append(enumNames, lockedEnum.Name)
	}
	for _, name := range testWireLockEnums {
		if !slices.Contains(enumNames, string(name)) {
			t.Errorf("the lock holds no %s", name)
		}
	}
	// what is additive passes, and says so, so a reviewer sees what a regeneration would freeze
	for _, addition := range testWireLockAdditions(lock, testWireLockRegistry) {
		t.Logf("additive, not yet locked: %s", addition)
	}
}

// The freeze as M2 released it: §6's own messages, the five registries' zeros, and 0x1402-0x1403 still
// reserved with their names, read from the file so an edit that drops one fails here as well.
func TestWireLockHoldsWhatM2Released(t *testing.T) {
	lock := testReadWireLock(t)
	field := func(messageName string, fieldName string) *testWireLockField {
		for _, lockedMessage := range lock.Messages {
			if lockedMessage.Name != messageName {
				continue
			}
			for _, lockedField := range lockedMessage.Fields {
				if lockedField.Name == fieldName {
					return lockedField
				}
			}
		}
		return nil
	}
	for _, c := range []struct {
		message string
		field   string
		number  int32
		kind    string
	}{
		{message: "urnetwork.sidecar.Envelope", field: "request_id", number: 3, kind: "fixed64"},
		{message: "urnetwork.sidecar.Envelope", field: "chunk", number: 7, kind: "message urnetwork.sidecar.Chunk"},
		{message: "urnetwork.sidecar.Envelope", field: "body", number: 15, kind: "bytes"},
		{message: "urnetwork.sidecar.Error", field: "min_version", number: 5, kind: "uint32"},
		{message: "urnetwork.sidecar.Error", field: "max_version", number: 6, kind: "uint32"},
		{message: "urnetwork.sidecar.HeadCheck", field: "unverified", number: 8, kind: "repeated message urnetwork.sidecar.UnverifiedPin"},
		{message: "urnetwork.sidecar.StreamOpen", field: "early_data", number: 5, kind: "bytes"},
		{message: "urnetwork.sidecar.StreamReset", field: "final_offset", number: 2, kind: "uint64"},
		{message: "urnetwork.sidecar.PollResponse", field: "reset", number: 3, kind: "message urnetwork.sidecar.PushReset"},
		{message: "urnetwork.sidecar.Signed", field: "type", number: 6, kind: "uint32"},
	} {
		locked := field(c.message, c.field)
		if locked == nil || locked.Number != c.number || locked.Kind != c.kind {
			t.Errorf("%s.%s: locked as %+v", c.message, c.field, locked)
		}
	}
	for _, lockedEnum := range lock.Enums {
		if len(lockedEnum.Values) == 0 || lockedEnum.Values[0].Number != 0 {
			t.Errorf("%s locks no zero", lockedEnum.Name)
		}
		if lockedEnum.Name != "urnetwork.sidecar.MessageType" {
			continue
		}
		if !slices.Contains(lockedEnum.ReservedNumbers, [2]int32{0x1402, 0x1403}) ||
			!slices.Equal(lockedEnum.ReservedNames, []string{"EVS_HEAD_CHECK", "EVS_HEAD_CHECK_RESULT"}) {
			t.Errorf("MessageType's withdrawn EvsHeadCheck: %v %v", lockedEnum.ReservedNumbers, lockedEnum.ReservedNames)
		}
	}
}

// A file descriptor as the registry holds it, with edit applied, and a finder that answers from it for
// the declarations it holds and from the registry for the rest.
func testPlantedWireFind(t testing.TB, path string, edit func(file *descriptorpb.FileDescriptorProto)) testWireLockFind {
	t.Helper()
	registered, err := protoregistry.GlobalFiles.FindFileByPath(path)
	if err != nil {
		t.Fatal(err)
	}
	fileProto := proto.Clone(protodesc.ToFileDescriptorProto(registered)).(*descriptorpb.FileDescriptorProto)
	edit(fileProto)
	planted, err := protodesc.NewFile(fileProto, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatal(err)
	}
	return func(name protoreflect.FullName) (protoreflect.Descriptor, error) {
		if message := planted.Messages().ByName(name.Name()); message != nil && message.FullName() == name {
			return message, nil
		}
		if enum := planted.Enums().ByName(name.Name()); enum != nil && enum.FullName() == name {
			return enum, nil
		}
		return protoregistry.GlobalFiles.FindDescriptorByName(name)
	}
}

// The lock catches each way a freeze breaks, each planted alone on the registered descriptors: a field
// renumbered, a field's kind changed, a field dropped, a code renumbered, a code's number taken by another
// name, a reservation lifted; and an added field and value pass.
func TestWireLockCatchesPlantedBreaks(t *testing.T) {
	lock := testReadWireLock(t)
	if findings := testWireLockFindings(lock, testWireLockRegistry); 0 < len(findings) {
		t.Fatalf("the registered descriptors break the lock: %v", findings)
	}
	messageNamed := func(file *descriptorpb.FileDescriptorProto, name string) *descriptorpb.DescriptorProto {
		for _, message := range file.MessageType {
			if message.GetName() == name {
				return message
			}
		}
		t.Fatalf("no message %s", name)
		return nil
	}
	enumNamed := func(file *descriptorpb.FileDescriptorProto, name string) *descriptorpb.EnumDescriptorProto {
		for _, enum := range file.EnumType {
			if enum.GetName() == name {
				return enum
			}
		}
		t.Fatalf("no enum %s", name)
		return nil
	}
	cases := []struct {
		name string
		path string
		edit func(file *descriptorpb.FileDescriptorProto)
		// a finding naming this, or none at all for an additive edit
		want string
	}{
		{
			name: "a renumbered field",
			path: "protocol/stream.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				messageNamed(file, "StreamData").Field[0].Number = proto.Int32(9)
			},
			want: "urnetwork.sidecar.StreamData.offset moved from 1 to 9",
		},
		{
			name: "a field's kind changed",
			path: "protocol/envelope.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				messageNamed(file, "Envelope").Field[2].Type = descriptorpb.FieldDescriptorProto_TYPE_UINT64.Enum()
			},
			want: "urnetwork.sidecar.Envelope.request_id is uint64 now, locked as fixed64",
		},
		{
			name: "a field dropped",
			path: "protocol/push.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				hint := messageNamed(file, "PushHint")
				hint.Field = hint.Field[:len(hint.Field)-1]
			},
			want: "urnetwork.sidecar.PushHint.hint (5) is gone",
		},
		{
			name: "a renumbered code",
			path: "protocol/stream.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				for _, value := range enumNamed(file, "StreamResetCode").Value {
					if value.GetName() == "RST_IDENTITY" {
						value.Number = proto.Int32(9)
					}
				}
			},
			want: "urnetwork.sidecar.StreamResetCode.RST_IDENTITY moved from 8 to 9",
		},
		{
			name: "a code's number taken by another name",
			path: "protocol/stream.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				for _, value := range enumNamed(file, "StreamRejectCode").Value {
					if value.GetName() == "SR_QUOTA" {
						value.Name = proto.String("SR_OVER_QUOTA")
					}
				}
			},
			want: "urnetwork.sidecar.StreamRejectCode's 5 is SR_OVER_QUOTA now, locked as SR_QUOTA",
		},
		{
			name: "a reservation lifted",
			path: "protocol/types.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				enumNamed(file, "MessageType").ReservedRange = nil
			},
			want: "urnetwork.sidecar.MessageType no longer reserves 5122 to 5123",
		},
		{
			name: "an added field and value",
			path: "protocol/stream.proto",
			edit: func(file *descriptorpb.FileDescriptorProto) {
				open := messageNamed(file, "StreamOpen")
				open.Field = append(open.Field, &descriptorpb.FieldDescriptorProto{
					Name:     proto.String("planted"),
					JsonName: proto.String("planted"),
					Number:   proto.Int32(14),
					Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
					Type:     descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum(),
				})
				reset := enumNamed(file, "StreamResetCode")
				reset.Value = append(reset.Value, &descriptorpb.EnumValueDescriptorProto{Name: proto.String("RST_PLANTED"), Number: proto.Int32(99)})
			},
		},
	}
	for _, c := range cases {
		findings := testWireLockFindings(lock, testPlantedWireFind(t, c.path, c.edit))
		switch {
		case c.want == "" && 0 < len(findings):
			t.Errorf("%s: an additive edit broke the lock: %v", c.name, findings)
		case c.want != "" && !slices.Contains(findings, c.want):
			t.Errorf("%s: want %q, found %v", c.name, c.want, findings)
		}
	}
}
