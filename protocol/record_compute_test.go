// CACL-M11-04: record.proto's version 5 as DESIGN-COMPUTE.md writes it, read from the registered descriptors, so a
// number, a type or a reservation that leaves §16.3's, §23.9's, §25.10's or §27.9's text fails here as well as in the
// fence guard: CanonicalAction's fields 42 to 70 and the messages they hold, CanonicalActionDetail5, kinds 19 to 26,
// ApprovalDecision's versions 2 and 3, AutoVerdict and channel 4. record.proto froze at M3 for numbers and meanings, so
// each of these is pinned for good, and none holds a oneof (§6.11).

package protocol

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// A field as "number name type", a list's type read "repeated type", a message's by its name.
func testComputeFieldLine(field protoreflect.FieldDescriptor) string {
	typeName := field.Kind().String()
	switch field.Kind() {
	case protoreflect.MessageKind, protoreflect.GroupKind:
		typeName = string(field.Message().Name())
	case protoreflect.EnumKind:
		typeName = string(field.Enum().Name())
	}
	if field.IsList() {
		typeName = "repeated " + typeName
	}
	return fmt.Sprintf("%d %s %s", field.Number(), field.Name(), typeName)
}

// The registered message of this package named name.
func testComputeMessage(t *testing.T, name string) protoreflect.MessageDescriptor {
	t.Helper()
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName("urnetwork.sidecar." + name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	message, ok := descriptor.(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is no message", name)
	}
	if message.ParentFile().Path() != "protocol/record.proto" {
		t.Errorf("%s is in %s", name, message.ParentFile().Path())
	}
	return message
}

// Holds message's fields whose numbers lie in [first, last] to want, in number order, and holds that it nests and
// carries nothing a fence cannot write: no oneof, no optional field, no nested message or enum, no option.
func testComputeMessageFields(t *testing.T, name string, first protoreflect.FieldNumber, last protoreflect.FieldNumber, want []string) {
	t.Helper()
	message := testComputeMessage(t, name)
	inRange := []protoreflect.FieldDescriptor{}
	fields := message.Fields()
	for i := range fields.Len() {
		if field := fields.Get(i); first <= field.Number() && field.Number() <= last {
			inRange = append(inRange, field)
		}
	}
	slices.SortFunc(inRange, func(a protoreflect.FieldDescriptor, b protoreflect.FieldDescriptor) int {
		return int(a.Number()) - int(b.Number())
	})
	got := []string{}
	for _, field := range inRange {
		got = append(got, testComputeFieldLine(field))
		if field.HasOptionalKeyword() || proto.Size(field.Options()) != 0 {
			t.Errorf("%s.%s is optional or sets options", name, field.Name())
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("%s's fields %d to %d:\n got %q\nwant %q", name, first, last, got, want)
	}
	if message.Oneofs().Len() != 0 || message.Messages().Len() != 0 || message.Enums().Len() != 0 {
		t.Errorf("%s holds a oneof or nests a declaration", name)
	}
	if proto.Size(message.Options()) != 0 {
		t.Errorf("%s sets options", name)
	}
}

// The numbers message reserves.
func testComputeReserved(message protoreflect.MessageDescriptor) []protoreflect.FieldNumber {
	numbers := []protoreflect.FieldNumber{}
	ranges := message.ReservedRanges()
	for i := range ranges.Len() {
		for number := ranges.Get(i)[0]; number < ranges.Get(i)[1]; number++ {
			numbers = append(numbers, number)
		}
	}
	slices.Sort(numbers)
	return numbers
}

// Every number from first to last.
func testComputeNumbers(first protoreflect.FieldNumber, last protoreflect.FieldNumber) []protoreflect.FieldNumber {
	numbers := []protoreflect.FieldNumber{}
	for number := first; number <= last; number++ {
		numbers = append(numbers, number)
	}
	return numbers
}

// §16.3's field list: 42 to 49 and their messages, §23.9's 50 to 56 with 57 to 59 reserved, §25.10's 60 with 61 to
// 69 reserved, §27.9's 70 with 71 to 79 reserved, and what field 38 opens to at version 5; DESIGN's 1 to 41 stay as
// they were, 23, 24, 25 and 34 reserved, and no message holds a oneof.
func TestCanonicalActionVersion5Descriptor(t *testing.T) {
	testComputeMessageFields(t, "CanonicalAction", 42, 79, []string{
		"42 enclave EnclaveFields",
		"43 budget BudgetFields",
		"44 url string",
		"45 tool string",
		"46 send SendFields",
		"47 context ContextFields",
		"48 taint_reasons repeated string",
		"49 took_tainted bool",
		"50 calendar_label string",
		"51 calendar_host string",
		"52 calendar_audience string",
		"53 calendar_events repeated CalendarEventAction",
		"54 calendar_link bytes",
		"55 calendar_target bytes",
		"56 calendar_name string",
		"60 service_call ServiceCallFields",
		"70 auto AutoFields",
	})
	action := testComputeMessage(t, "CanonicalAction")
	if action.Fields().Len() != 41-4+17 {
		t.Errorf("CanonicalAction holds %d fields", action.Fields().Len())
	}
	for number := protoreflect.FieldNumber(1); number <= 41; number++ {
		reserved := number == 23 || number == 24 || number == 25 || number == 34
		if (action.Fields().ByNumber(number) == nil) != reserved {
			t.Errorf("CanonicalAction's field %d", number)
		}
	}
	wantReserved := slices.Concat(
		[]protoreflect.FieldNumber{23, 24, 25, 34},
		testComputeNumbers(57, 59), testComputeNumbers(61, 69), testComputeNumbers(71, 79),
	)
	if got := testComputeReserved(action); !slices.Equal(got, wantReserved) {
		t.Errorf("CanonicalAction reserves %v", got)
	}

	testComputeMessageFields(t, "EnclaveFields", 1, 536870911, []string{
		"1 enclave_id bytes", "2 name string", "3 shape string", "4 provider string", "5 label string",
		"6 price_per_hour uint64", "7 incarnation uint64",
	})
	testComputeMessageFields(t, "BudgetFields", 1, 536870911, []string{
		"1 agent_id bytes", "2 period uint32", "3 amount uint64", "4 current uint64",
	})
	testComputeMessageFields(t, "SendFields", 1, 536870911, []string{
		"1 target_agent string", "2 target_agent_id bytes", "3 target_member_id bytes", "4 mode uint32", "5 text string",
		"6 stdin string", "7 cwd string", "8 refs repeated RefFields", "9 model string", "10 tools repeated string",
		"11 budget BudgetFields",
	})
	testComputeMessageFields(t, "RefFields", 1, 536870911, []string{"1 repo_id bytes", "2 path string", "3 version uint64"})
	testComputeMessageFields(t, "ContextFields", 1, 536870911, []string{
		"1 run_id bytes", "2 entry_id bytes", "3 nodes uint32", "4 flagged uint32", "5 untrusted uint32",
		"6 mail_messages uint32", "7 calendar_events uint32", "8 fetched_pages uint32", "9 service_results uint32",
		"10 act uint32",
	})
	testComputeMessageFields(t, "CalendarEventAction", 1, 536870911, []string{
		"1 operation uint32", "2 uid string", "3 occurrence string", "4 expected string", "5 title string",
		"6 start string", "7 end string", "8 zone string", "9 all_day bool", "10 recurrence string", "11 location string",
		"12 reminders repeated string", "13 attendees repeated string", "14 mails repeated string",
		"15 description string", "16 before CalendarEventFields", "17 source string",
	})
	testComputeMessageFields(t, "CalendarEventFields", 1, 536870911, []string{
		"1 title string", "2 start string", "3 end string", "4 zone string", "5 all_day bool", "6 recurrence string",
		"7 location string", "8 reminders repeated string", "9 attendees repeated string", "10 description string",
	})
	testComputeMessageFields(t, "ServiceCallFields", 1, 536870911, []string{
		"1 connection bytes", "2 label string", "3 service string", "4 account string", "5 method string",
		"6 path string", "7 query string", "8 content_type string", "9 body string", "10 class uint32",
		"11 feature string",
	})
	testComputeMessageFields(t, "AutoFields", 1, 536870911, []string{"1 basis uint32", "2 rules repeated uint32"})
	testComputeMessageFields(t, "CanonicalActionDetail5", 1, 536870911, []string{
		"1 name string", "2 role uint32", "3 harness string", "4 grant_id bytes",
	})

	// field 38 stays one bytes field at every version, the version telling its message
	if sealed := action.Fields().ByNumber(38); sealed == nil || sealed.Kind() != protoreflect.BytesKind || sealed.Name() != "sealed_detail" {
		t.Errorf("CanonicalAction's field 38 is %v", sealed)
	}

	// §16.3's kinds, appended to DESIGN's 1 to 18 in their order
	wantKinds := map[int32]string{
		19: "SIDECAR_ACTION_KIND_ENCLAVE_CREATE",
		20: "SIDECAR_ACTION_KIND_ENCLAVE_EGRESS_DIRECT",
		21: "SIDECAR_ACTION_KIND_COMPUTE_BUDGET_RAISE",
		22: "SIDECAR_ACTION_KIND_ENCLAVE_DELETE",
		23: "SIDECAR_ACTION_KIND_FETCH_UNLISTED_URL",
		24: "SIDECAR_ACTION_KIND_TAINTED_SEND",
		25: "SIDECAR_ACTION_KIND_CALENDAR_WRITE",
		26: "SIDECAR_ACTION_KIND_SERVICE_WRITE",
	}
	for number, name := range wantKinds {
		if SidecarActionKind_name[number] != name {
			t.Errorf("kind %d is %q", number, SidecarActionKind_name[number])
		}
	}
	if len(SidecarActionKind_name) != 27 || SidecarActionKind_name[18] != "SIDECAR_ACTION_KIND_MAIL_TLS_UNAUTHENTICATED" {
		t.Errorf("SidecarActionKind holds %d values", len(SidecarActionKind_name))
	}
}

// §23.9's selected at decision version 2, §27.9's auto and auto_verdict at version 3, and channel 4; DESIGN's 1 to 13
// stay as they were.
func TestApprovalDecisionVersions2And3Descriptor(t *testing.T) {
	testComputeMessageFields(t, "ApprovalDecision", 1, 536870911, []string{
		"1 approval_id bytes", "2 request_sha256 bytes", "3 payload_sha256 bytes", "4 decision uint32", "5 uses uint32",
		"6 not_after_millis int64", "7 approver_member_id bytes", "8 channel uint32", "9 sshsig bytes",
		"10 evidence_sha256 bytes", "11 requester_sidecar_id bytes", "12 auth_pin AuthPin", "13 version uint32",
		"14 selected repeated uint32", "15 auto bool", "16 auto_verdict AutoVerdict",
	})
	if len(testComputeReserved(testComputeMessage(t, "ApprovalDecision"))) != 0 {
		t.Error("ApprovalDecision reserves a number")
	}
	if ApprovalChannel_name[4] != "APPROVAL_CHANNEL_AUTO" || len(ApprovalChannel_name) != 5 {
		t.Errorf("ApprovalChannel holds %v", ApprovalChannel_name)
	}
	// selected is packed, as every repeated scalar of proto3 is: one record, whatever the count
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(&ApprovalDecision{Selected: []uint32{0, 2, 3}, Version: 2})
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0x68, 0x02, 0x72, 0x03, 0x00, 0x02, 0x03}; !slices.Equal(encoded, want) {
		t.Errorf("a version-2 decision encodes as %x", encoded)
	}
}

// §27.9's AutoVerdict, field for field as its fence writes it.
func TestAutoVerdictDescriptor(t *testing.T) {
	testComputeMessageFields(t, "AutoVerdict", 1, 536870911, []string{
		"1 verdict uint32", "2 reason uint32", "3 score uint32", "4 threshold uint32", "5 model string",
		"6 model_sha256 bytes", "7 inputs_sha256 bytes", "8 windows uint32", "9 run_count uint32", "10 day_count uint32",
	})
	if len(testComputeReserved(testComputeMessage(t, "AutoVerdict"))) != 0 {
		t.Error("AutoVerdict reserves a number")
	}
}
