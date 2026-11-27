// CACL-M11-05: acl.proto's one change for DESIGN-COMPUTE.md, read from the registered descriptors: §16.2's actions and
// targets, §16.4's compute rows, and the repo kinds and inbox marker the authorization features turn on (§16.6), every
// number appended after the existing ones and every existing value unchanged, so no reader that predates them reads a
// value two ways. None holds a oneof, and one block's rows encode to one byte string.

package protocol

import (
	"fmt"
	"slices"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// acl.proto's path, as protoc registers it.
const testAclProtoPath = "protocol/acl.proto"

// An enum of this package as "number.NAME" lines, in number order.
func testComputeEnumValues(t *testing.T, name string) []string {
	t.Helper()
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName("urnetwork.sidecar." + name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	enum, ok := descriptor.(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatalf("%s is no enum", name)
	}
	if enum.ParentFile().Path() != testAclProtoPath {
		t.Errorf("%s is in %s", name, enum.ParentFile().Path())
	}
	if enum.ReservedRanges().Len() != 0 || proto.Size(enum.Options()) != 0 {
		t.Errorf("%s reserves a value or sets options", name)
	}
	values := []protoreflect.EnumValueDescriptor{}
	for i := range enum.Values().Len() {
		values = append(values, enum.Values().Get(i))
	}
	slices.SortFunc(values, func(a protoreflect.EnumValueDescriptor, b protoreflect.EnumValueDescriptor) int {
		return int(a.Number()) - int(b.Number())
	})
	lines := []string{}
	for _, value := range values {
		lines = append(lines, testComputeValueLine(value))
	}
	return lines
}

// A value as "number.NAME", its number in two digits.
func testComputeValueLine(value protoreflect.EnumValueDescriptor) string {
	return fmt.Sprintf("%02d.%s", value.Number(), value.Name())
}

// §16.2's actions after §8.4's, AclTarget's three compute kinds after its ten and agent_repos' repo_kind after them
// (QD-1433), AclRows' compute_rows after its ten, §16.4's AclComputeRows and AclComputeBudgetRow, and the enums
// ComputeAssurance and AclComputeResource, each number as the plan writes it.
func TestAclComputeDescriptor(t *testing.T) {
	if got, want := testComputeEnumValues(t, "AclAction"), []string{
		"00.ACL_ACTION_UNSPECIFIED", "01.ACL_ACTION_DIAL", "02.ACL_ACTION_LISTEN", "03.ACL_ACTION_ROUTE",
		"04.ACL_ACTION_READ", "05.ACL_ACTION_WRITE", "06.ACL_ACTION_ADMIN", "07.ACL_ACTION_DEPOSIT",
		"08.ACL_ACTION_PUBLISH", "09.ACL_ACTION_SEND", "10.ACL_ACTION_INFER", "11.ACL_ACTION_CREATE",
		"12.ACL_ACTION_BUY", "13.ACL_ACTION_QUERY", "14.ACL_ACTION_SSH",
	}; !slices.Equal(got, want) {
		t.Errorf("AclAction:\n got %q\nwant %q", got, want)
	}
	testComputeMessageFields(t, testAclProtoPath, "AclTarget", 1, protowire.MaxValidNumber, []string{
		"1 atom bytes", "2 sidecar_id bytes", "3 network_id bytes", "4 repo_id bytes", "5 socket_tokens repeated bytes",
		"6 socket_prefix bool", "7 public_name string", "9 mail_send bool", "10 client_id bytes", "11 model_glob string",
		"12 compute_resource AclComputeResource", "13 listener bytes", "14 repo_kind RepoKind",
	})
	if got := testComputeReserved(testComputeMessage(t, testAclProtoPath, "AclTarget")); !slices.Equal(got, []protoreflect.FieldNumber{8}) {
		t.Errorf("AclTarget reserves %v", got)
	}
	testComputeMessageFields(t, testAclProtoPath, "AclRows", 1, protowire.MaxValidNumber, []string{
		"1 has_document bool", "2 atoms repeated AclAtom", "3 rules repeated AclRule", "4 requests repeated AclRequestRule",
		"5 repos repeated AclRepo", "6 bridge bytes", "7 audit AclAudit", "8 suspensions repeated AclSuspension",
		"9 spent_grants repeated AclSpentGrant", "10 evidence_default repeated uint32", "11 compute_rows AclComputeRows",
	})
	testComputeMessageFields(t, testAclProtoPath, "AclComputeRows", 1, protowire.MaxValidNumber, []string{
		"1 assurance_floor ComputeAssurance", "2 enclave_assurance_floor ComputeAssurance", "3 providers repeated string",
		"4 enclave_shapes repeated string", "5 search_enabled bool", "6 search_day_max uint32",
		"7 budgets repeated AclComputeBudgetRow",
	})
	testComputeMessageFields(t, testAclProtoPath, "AclComputeBudgetRow", 1, protowire.MaxValidNumber, []string{
		"1 subject bytes", "2 per uint32", "3 day_nano_usd uint64", "4 month_nano_usd uint64",
	})
	if got, want := testComputeEnumValues(t, "ComputeAssurance"), []string{
		"00.COMPUTE_ASSURANCE_UNSPECIFIED", "01.COMPUTE_ASSURANCE_NONE", "02.COMPUTE_ASSURANCE_AP", "03.COMPUTE_ASSURANCE_A1",
		"04.COMPUTE_ASSURANCE_A2",
	}; !slices.Equal(got, want) {
		t.Errorf("ComputeAssurance:\n got %q\nwant %q", got, want)
	}
	if got, want := testComputeEnumValues(t, "AclComputeResource"), []string{
		"00.ACL_COMPUTE_RESOURCE_UNSPECIFIED", "01.ACL_COMPUTE_RESOURCE_ENCLAVE", "02.ACL_COMPUTE_RESOURCE_BUY",
		"03.ACL_COMPUTE_RESOURCE_SEARCH",
	}; !slices.Equal(got, want) {
		t.Errorf("AclComputeResource:\n got %q\nwant %q", got, want)
	}
}

// The repo kinds and the inbox marker the features turn on, appended in the order the design adds them, every
// existing value as it was.
func TestRepoKindsAppended(t *testing.T) {
	if got, want := testComputeEnumValues(t, "RepoKind"), []string{
		"00.REPO_KIND_UNSPECIFIED", "01.REPO_KIND_GENERAL", "02.REPO_KIND_RECORD", "03.REPO_KIND_CONFIG",
		"04.REPO_KIND_DIRECTORY", "05.REPO_KIND_TEAM_RECORD", "06.REPO_KIND_MAILCFG", "07.REPO_KIND_VAULT",
		"08.REPO_KIND_MAILBOX", "09.REPO_KIND_SECRET", "10.REPO_KIND_AGENTS", "11.REPO_KIND_AGENT",
		"12.REPO_KIND_LISTENERS",
	}; !slices.Equal(got, want) {
		t.Errorf("RepoKind:\n got %q\nwant %q", got, want)
	}
	if got, want := testComputeEnumValues(t, "RepoInbox"), []string{
		"00.REPO_INBOX_NONE", "01.REPO_INBOX_GROUP", "02.REPO_INBOX_ADMIN", "03.REPO_INBOX_TEAM",
	}; !slices.Equal(got, want) {
		t.Errorf("RepoInbox:\n got %q\nwant %q", got, want)
	}
}

// One block's rows encode to the same bytes twice, deterministically, and decode to rows equal to them, so a base's
// rows hash names one block.
func TestAclComputeRowsDeterministic(t *testing.T) {
	rows := &AclRows{HasDocument: true, ComputeRows: &AclComputeRows{
		AssuranceFloor:        ComputeAssurance_COMPUTE_ASSURANCE_AP,
		EnclaveAssuranceFloor: ComputeAssurance_COMPUTE_ASSURANCE_A1,
		Providers:             []string{"chutes", "engy"},
		EnclaveShapes:         []string{"cpu-2", "cpu-4"},
		SearchEnabled:         true,
		SearchDayMax:          2000,
		Budgets: []*AclComputeBudgetRow{
			{Subject: []byte("0123456789abcdef"), Per: 1, DayNanoUsd: 5_000_000_000, MonthNanoUsd: 50_000_000_000},
			{Subject: []byte("fedcba9876543210"), Per: 3, MonthNanoUsd: 100_000_000_000},
		},
	}}
	first, err := proto.MarshalOptions{Deterministic: true}.Marshal(rows)
	if err != nil {
		t.Fatal(err)
	}
	second, err := proto.MarshalOptions{Deterministic: true}.Marshal(proto.Clone(rows))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first, second) {
		t.Errorf("one block's rows encode two ways:\n%x\n%x", first, second)
	}
	parsed := &AclRows{}
	if err := proto.Unmarshal(first, parsed); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(parsed, rows) {
		t.Errorf("the rows read back as %v", parsed)
	}
	// field 11 is last, after every field rows held before it, so rows without it encode as they did
	before := proto.Clone(rows).(*AclRows)
	before.ComputeRows = nil
	beforeBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(before)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(first[:len(beforeBytes)], beforeBytes) || first[len(beforeBytes)] != byte(protowire.EncodeTag(11, protowire.BytesType)) {
		t.Errorf("compute_rows does not follow the rows that predate it: %x", first)
	}
}
