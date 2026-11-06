// Descriptor lints: the registered files, where each type lives, the numbers that are permanent once
// released, and the reservations D-PHASE-9 makes at M2. evs.proto's reservations are its own lint's.

package protocol

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

const testProtoPackage = "urnetwork.sidecar"

var testProtoFiles = []string{
	"protocol/acl.proto",
	"protocol/config.proto",
	"protocol/envelope.proto",
	"protocol/push.proto",
	"protocol/stream.proto",
	"protocol/types.proto",
	"protocol/bridge/auth.proto",
	"protocol/bridge/bridge.proto",
	"protocol/bridge/signed.proto",
}

func testFile(t *testing.T, path string) protoreflect.FileDescriptor {
	file, err := protoregistry.GlobalFiles.FindFileByPath(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return file
}

func testDescriptor(t *testing.T, name string) protoreflect.Descriptor {
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(testProtoPackage + "." + name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return descriptor
}

func testMessage(t *testing.T, name string) protoreflect.MessageDescriptor {
	message, ok := testDescriptor(t, name).(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is no message", name)
	}
	return message
}

func testEnum(t *testing.T, name string) protoreflect.EnumDescriptor {
	enum, ok := testDescriptor(t, name).(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatalf("%s is no enum", name)
	}
	return enum
}

// §4.9: files register by their root-relative paths in one package, and a duplicate would have panicked
// before this ran, so reaching it at all says none exists.
func TestProtoFilesRegisterFromTheRepoRoot(t *testing.T) {
	for _, path := range testProtoFiles {
		file := testFile(t, path)
		if file.Package() != testProtoPackage {
			t.Errorf("%s is in package %q", path, file.Package())
		}
		if file.Syntax() != protoreflect.Proto3 {
			t.Errorf("%s is not proto3", path)
		}
	}
}

// §4.4: every type the device role parses lives only in protocol/bridge, which the iOS extension links
// without protocol (D-SDK-20).
func TestDeviceRoleTypesLiveInBridge(t *testing.T) {
	for _, name := range []string{
		"Signed", "WebAuthnEvidence", "SignedType",
		"AuthEntry", "AuthPin", "ProjectionHeader", "ProjectionRows", "MemberRow", "SidecarRow", "DelegationRow",
		"KeyRow", "ApiTick", "StatementHeader", "Genesis", "SidecarRevoke", "MemberRevoke",
		"GrantRevoke", "Suspend", "Unsuspend",
		"BridgeState", "BridgeIdentity", "BridgeShareKey", "Pending", "BridgeRows", "WindowDelegation", "ShareCert",
		"BridgeShareSigner", "BridgeBlock", "BridgeAddress", "BridgeRoute", "BridgeMap", "BridgeEgress",
		"BridgeAlias", "BridgeWithdraw",
	} {
		path := testDescriptor(t, name).ParentFile().Path()
		if !strings.HasPrefix(path, "protocol/bridge/") {
			t.Errorf("%s is in %s", name, path)
		}
	}
}

// §4.4: protocol imports protocol/bridge, never the reverse.
func TestBridgeProtosImportOnlyBridgeProtos(t *testing.T) {
	for _, path := range testProtoFiles {
		if !strings.HasPrefix(path, "protocol/bridge/") {
			continue
		}
		imports := testFile(t, path).Imports()
		for i := range imports.Len() {
			imported := imports.Get(i).Path()
			if !strings.HasPrefix(imported, "protocol/bridge/") {
				t.Errorf("%s imports %s", path, imported)
			}
		}
	}
}

// §6.11 and §22.5: no oneof in envelope, stream or push messages or anything they carry, walking from each
// message those files declare, so a new message joins the lint by being declared. The allowlist is empty
// in v0.
func TestNoOneofInEnvelopeStreamOrPush(t *testing.T) {
	visited := map[protoreflect.FullName]bool{}
	var walk func(message protoreflect.MessageDescriptor)
	walk = func(message protoreflect.MessageDescriptor) {
		if visited[message.FullName()] {
			return
		}
		visited[message.FullName()] = true
		if message.Oneofs().Len() != 0 {
			t.Errorf("%s holds a oneof", message.FullName())
		}
		fields := message.Fields()
		for i := range fields.Len() {
			if fieldMessage := fields.Get(i).Message(); fieldMessage != nil {
				walk(fieldMessage)
			}
		}
	}
	for _, path := range []string{"protocol/envelope.proto", "protocol/stream.proto", "protocol/push.proto"} {
		messages := testFile(t, path).Messages()
		if messages.Len() == 0 {
			t.Fatalf("%s declares no message", path)
		}
		for i := range messages.Len() {
			walk(messages.Get(i))
		}
	}
	// The walk must reach through HeadCheck into protocol/bridge, or it proves less than it claims.
	if !visited[protoreflect.FullName(testProtoPackage+".AuthPin")] {
		t.Fatal("the walk never reached AuthPin")
	}
}

// §6.5: HelloResult and HeadCheckResult have Hello's and HeadCheck's fields.
func TestResultMessagesHaveTheirRequestsFields(t *testing.T) {
	for request, result := range map[string]string{"Hello": "HelloResult", "HeadCheck": "HeadCheckResult"} {
		requestFields := testMessage(t, request).Fields()
		resultFields := testMessage(t, result).Fields()
		if requestFields.Len() != resultFields.Len() {
			t.Errorf("%s has %d fields, %s %d", request, requestFields.Len(), result, resultFields.Len())
			continue
		}
		for i := range requestFields.Len() {
			requestField := requestFields.Get(i)
			resultField := resultFields.ByName(requestField.Name())
			if resultField == nil {
				t.Errorf("%s lacks %s", result, requestField.Name())
				continue
			}
			sameMessage := requestField.Message() == resultField.Message() ||
				requestField.Message().FullName() == resultField.Message().FullName()
			if resultField.Number() != requestField.Number() || resultField.Kind() != requestField.Kind() ||
				resultField.Cardinality() != requestField.Cardinality() || !sameMessage {
				t.Errorf("%s.%s differs from %s's", result, requestField.Name(), request)
			}
		}
	}
}

// §22.5: enum numbers stable. These are §6's as written, permanent once released (D-PROTO-20).
func TestEnumNumbersStable(t *testing.T) {
	cases := []struct {
		name string
		got  map[string]int32
		want map[string]int32
	}{
		{
			name: "ErrorCode",
			got:  ErrorCode_value,
			want: map[string]int32{
				"ERR_OK": 0, "ERR_CANCELLED": 1, "ERR_INVALID_ARGUMENT": 2, "ERR_DEADLINE_EXCEEDED": 3,
				"ERR_NOT_FOUND": 4, "ERR_ALREADY_EXISTS": 5, "ERR_PERMISSION_DENIED": 6,
				"ERR_RESOURCE_EXHAUSTED": 7, "ERR_FAILED_PRECONDITION": 8, "ERR_ABORTED": 9, "ERR_UNAVAILABLE": 10,
				"ERR_UNIMPLEMENTED": 11, "ERR_UNAUTHENTICATED": 12, "ERR_TOO_LARGE": 13, "ERR_VERSION": 14,
			},
		},
		{
			name: "StreamRejectCode",
			got:  StreamRejectCode_value,
			want: map[string]int32{
				"SR_UNSPECIFIED": 0, "SR_RETRY": 1, "SR_BUSY": 2, "SR_DENIED": 3, "SR_INVALID": 4, "SR_QUOTA": 5,
			},
		},
		{
			name: "StreamResetCode",
			got:  StreamResetCode_value,
			want: map[string]int32{
				"RST_UNSPECIFIED": 0, "RST_DRAINING": 1, "RST_REVOKED": 2, "RST_PEER_TIMEOUT": 3,
				"RST_TRANSFER_FAILED": 4, "RST_PROTOCOL": 5, "RST_CANCELLED": 6, "RST_QUOTA": 7, "RST_IDENTITY": 8,
			},
		},
		{
			name: "MessageType",
			got:  MessageType_value,
			want: map[string]int32{
				"MESSAGE_TYPE_NONE": 0,
				"HELLO":             0x0001, "HELLO_RESULT": 0x0002, "PING": 0x0003, "PONG": 0x0004,
				"CANCEL": 0x0005, "ERROR": 0x0006, "HEAD_CHECK": 0x0007, "HEAD_CHECK_RESULT": 0x0008,
				"HEAD_CHECK_PROOF_REQUEST": 0x0009, "HEAD_CHECK_PROOF": 0x000A,
				"PUSH_RESET": 0x0101, "PUSH_HINT": 0x0102,
				"STREAM_OPEN": 0x0201, "STREAM_ACCEPT": 0x0202, "STREAM_REJECT": 0x0203, "STREAM_DATA": 0x0204,
				"STREAM_WINDOW": 0x0205, "STREAM_CLOSE": 0x0206, "STREAM_RESET": 0x0207,
				"SOCKET_HINT":        0x1001,
				"MEMBERSHIP_CHANGED": 0x1201, "APPROVAL_REQUESTED": 0x1202, "AUTHORITY_HEAD_CHANGED": 0x1203,
				"GKM_HINT":         0x1301,
				"EVS_HEAD_CHANGED": 0x1401, "SEARCH": 0x1404, "SEARCH_RESULT": 0x1405,
				"TLS_EDGE_OPEN": 0x1501, "TLS_HINT": 0x1502,
				"SMTP_PREAMBLE": 0x1601, "SMTP_PREAMBLE_RESULT": 0x1602, "SMTP_OUTCOME": 0x1603, "SMTP_STATUS": 0x1604,
				"SMTP_PROOF": 0x1605, "SMTP_PROOF_RESULT": 0x1606,
				"MAIL_INGRESS": 0x1701, "MAIL_HINT": 0x1702,
				"CORE_HINT":        0x1A01,
				"DNS_ZONE_CHANGED": 0x1B01,
			},
		},
	}
	for _, c := range cases {
		if !maps.Equal(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
}

// §6.11: an RPC's result type is its request's value + 1.
func TestResultTypeIsRequestPlusOne(t *testing.T) {
	for request, result := range map[MessageType]MessageType{
		MessageType_HELLO:                    MessageType_HELLO_RESULT,
		MessageType_PING:                     MessageType_PONG,
		MessageType_HEAD_CHECK:               MessageType_HEAD_CHECK_RESULT,
		MessageType_HEAD_CHECK_PROOF_REQUEST: MessageType_HEAD_CHECK_PROOF,
		MessageType_SEARCH:                   MessageType_SEARCH_RESULT,
		MessageType_SMTP_PROOF:               MessageType_SMTP_PROOF_RESULT,
	} {
		if result != request+1 {
			t.Errorf("%s + 1 is not %s", request, result)
		}
	}
}

// The withdrawn EvsHeadCheck stays reserved, its numbers and names never reused (§6.11, §11).
func TestWithdrawnEvsHeadCheckStaysReserved(t *testing.T) {
	messageType := testEnum(t, "MessageType")
	for _, number := range []protoreflect.EnumNumber{0x1402, 0x1403} {
		if !messageType.ReservedRanges().Has(number) {
			t.Errorf("%#x is not reserved", number)
		}
		if messageType.Values().ByNumber(number) != nil {
			t.Errorf("%#x is in use", number)
		}
	}
	for _, name := range []protoreflect.Name{"EVS_HEAD_CHECK", "EVS_HEAD_CHECK_RESULT"} {
		if !messageType.ReservedNames().Has(name) {
			t.Errorf("%s is not reserved", name)
		}
	}
}

// D-PHASE-9's reservations in these files, fixed at M2 so a later milestone needs no number from a frozen
// format: each is field or value of a name the design gives, at the number this format assigns it.
func TestPhaseReservations(t *testing.T) {
	fields := []struct {
		message string
		field   protoreflect.Name
		number  protoreflect.FieldNumber
	}{
		{message: "EvsShare", field: "expires", number: 4},
		{message: "ServiceSettings", field: "directory", number: 6},
		{message: "ServiceDirectorySettings", field: "runs", number: 1},
		{message: "ServiceDirectorySettings", field: "workers", number: 2},
		{message: "RepoVersioning", field: "repo_id", number: 2},
		{message: "RepoVersioning", field: "lock", number: 3},
		{message: "RepoVersioning", field: "sealed_rules", number: 4},
		{message: "AclRepo", field: "lock", number: 10},
		{message: "AclRepo", field: "holders_shrunk_at", number: 11},
	}
	for _, c := range fields {
		field := testMessage(t, c.message).Fields().ByName(c.field)
		if field == nil {
			t.Errorf("%s.%s is missing", c.message, c.field)
			continue
		}
		if field.Number() != c.number {
			t.Errorf("%s.%s is %d, want %d", c.message, c.field, field.Number(), c.number)
		}
	}

	if AclAutogroup_ACL_AUTOGROUP_DST_OWNER != 14 {
		t.Errorf("autogroup:dst-owner's atom is %d", AclAutogroup_ACL_AUTOGROUP_DST_OWNER)
	}
	if RepoKind_REPO_KIND_DIRECTORY != 4 {
		t.Errorf("the directory kind is %d", RepoKind_REPO_KIND_DIRECTORY)
	}
	if bridge.SignedType_SIGNED_VERSIONING_RULES != 0x1211 {
		t.Errorf("VersioningRules' type is %#x", int32(bridge.SignedType_SIGNED_VERSIONING_RULES))
	}
	if bridge.SignedType_SIGNED_REPO_VERSIONING != 0x110D {
		t.Errorf("RepoVersioning's type is %#x", int32(bridge.SignedType_SIGNED_REPO_VERSIONING))
	}
}

// Owner decision 165: no number is reserved for keep-last-n (D-PHASE-9).
func TestNoNumberForKeepLastN(t *testing.T) {
	refuse := func(name protoreflect.FullName) {
		lower := strings.ToLower(string(name))
		if strings.Contains(lower, "keep_last") || strings.Contains(lower, "keeplast") {
			t.Errorf("%s reserves keep-last-n", name)
		}
	}
	var walk func(message protoreflect.MessageDescriptor)
	walk = func(message protoreflect.MessageDescriptor) {
		refuse(message.FullName())
		fields := message.Fields()
		for i := range fields.Len() {
			refuse(fields.Get(i).FullName())
		}
		reservedNames := message.ReservedNames()
		for i := range reservedNames.Len() {
			refuse(protoreflect.FullName(reservedNames.Get(i)))
		}
		nested := message.Messages()
		for i := range nested.Len() {
			walk(nested.Get(i))
		}
	}
	for _, path := range testProtoFiles {
		messages := testFile(t, path).Messages()
		for i := range messages.Len() {
			walk(messages.Get(i))
		}
	}
}

// §7.9: every statement that enters the log begins with a StatementHeader, which its replay row reads, so
// this runs across the three files that declare them. Genesis has no position to pin, ProjectionHeader
// carries its own, and ServiceSettings, VersioningRules and BridgeBlock ride heads.
func TestStatementsOpenWithHeader(t *testing.T) {
	statements := []string{
		"AdminSet", "MemberAdmit", "MemberRevoke", "SidecarAdmit", "SidecarRevoke", "AdmissionConfirm", "SponsorSet",
		"IndexerSet", "RecoveryBind", "RecoveryRebind", "KeyRegister", "KeyRevoke", "Delegation", "DelegationRevoke",
		"AuthorityProposal", "AuthorityCosign", "RecoveryVeto",
		"GrantActivate", "GrantRevoke", "Suspend", "Unsuspend", "EvsShare", "OwnerConfirm", "RepoCreate", "RepoAdmin",
		"RepoGrant", "RepoRevoke", "RepoDelete", "RepoRestore", "RepoVersioning", "AuditOptIn", "AuditOptOut",
		"BridgeAddress", "BridgeRoute", "BridgeMap", "BridgeEgress", "BridgeAlias", "BridgeWithdraw",
	}
	for _, name := range statements {
		field := testMessage(t, name).Fields().ByNumber(1)
		if field == nil || field.Name() != "header" || field.Message() == nil ||
			field.Message().Name() != "StatementHeader" {
			t.Errorf("%s does not open with a StatementHeader", name)
		}
	}
	for _, name := range []string{"Genesis", "ProjectionHeader", "ServiceSettings", "VersioningRules", "BridgeBlock"} {
		if testMessage(t, name).Fields().ByName("header") != nil {
			t.Errorf("%s carries a header", name)
		}
	}
}

// §2.8: a statement a delta carries shows ids only, so no field of one may hold what §17.8 or §7.9 seal. A
// new field here has to justify itself against api-7, and this list is where that shows.
func TestSealedStatementsShowOnlyIds(t *testing.T) {
	cases := []struct {
		message string
		fields  []string
	}{
		{message: "BridgeAddress", fields: []string{"header", "sealed_body", "sidecar_id"}},
		{message: "BridgeRoute", fields: []string{"advertiser", "header", "route_id", "route_rule_ids", "sealed_body"}},
		{message: "BridgeMap", fields: []string{"expires", "header", "host", "map_id", "sealed_body"}},
		{message: "BridgeEgress", fields: []string{"header", "sealed_body", "subject"}},
		{message: "BridgeAlias", fields: []string{"header", "host", "sealed_body", "share_id"}},
		{message: "BridgeWithdraw", fields: []string{"header", "mode", "rule_id"}},
		{message: "IndexerSet", fields: []string{"header", "retire", "scope", "sealed_services", "sidecar_id"}},
		{
			message: "RecoveryBind",
			fields:  []string{"ed25519_public_key_sha256", "header", "member_id", "prev_sha256", "sealed_body"},
		},
		{
			message: "RecoveryRebind",
			fields:  []string{"ed25519_public_key_sha256", "header", "member_id", "prev_sha256", "reason", "sealed_body"},
		},
	}
	for _, c := range cases {
		messageFields := testMessage(t, c.message).Fields()
		names := make([]string, 0, messageFields.Len())
		for i := range messageFields.Len() {
			names = append(names, string(messageFields.Get(i).Name()))
		}
		slices.Sort(names)
		if !slices.Equal(names, c.fields) {
			t.Errorf("%s shows %v, want %v", c.message, names, c.fields)
		}
	}
}
