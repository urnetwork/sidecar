// Descriptor lints: the registered files, where each type lives, the numbers that are permanent once
// released, and the reservations D-PHASE-9 makes at M2 and M3. evs.proto's reservations are its own lint's, in
// evs_descriptor_test.go.

package protocol

import (
	"maps"
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

// §4.9: one protobuf package across protocol and protocol/bridge, never connect's "bringyour".
const testProtoPackage = "urnetwork.sidecar"

// §4.4's files and those the service sections add, each registered by its root-relative path.
var testProtoFiles = []string{
	"protocol/acl.proto",
	"protocol/config.proto",
	"protocol/directory.proto",
	"protocol/envelope.proto",
	"protocol/evs.proto",
	"protocol/evsindex.proto",
	"protocol/gkm.proto",
	"protocol/mail.proto",
	"protocol/push.proto",
	"protocol/record.proto",
	"protocol/search.proto",
	"protocol/smtp.proto",
	"protocol/socket.proto",
	"protocol/stream.proto",
	"protocol/tls.proto",
	"protocol/types.proto",
	"protocol/bridge/auth.proto",
	"protocol/bridge/bridge.proto",
	"protocol/bridge/signed.proto",
}

// A registered file, by its root-relative path.
func testFile(t *testing.T, path string) protoreflect.FileDescriptor {
	file, err := protoregistry.GlobalFiles.FindFileByPath(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return file
}

// A registered declaration, by its name in this package.
func testDescriptor(t *testing.T, name string) protoreflect.Descriptor {
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(testProtoPackage + "." + name))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return descriptor
}

// As testDescriptor, for a name that must be a message.
func testMessage(t *testing.T, name string) protoreflect.MessageDescriptor {
	message, ok := testDescriptor(t, name).(protoreflect.MessageDescriptor)
	if !ok {
		t.Fatalf("%s is no message", name)
	}
	return message
}

// §4.9: files register by their root-relative paths in one package, and a duplicate would have panicked
// before this ran, so reaching it at all says none exists. The list is the package's whole, because the lints
// below that walk it would otherwise pass a new file by never opening it.
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
	registered := []string{}
	protoregistry.GlobalFiles.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		registered = append(registered, file.Path())
		return true
	})
	slices.Sort(registered)
	if listed := slices.Sorted(slices.Values(testProtoFiles)); !slices.Equal(registered, listed) {
		t.Errorf("the package registers %v, and testProtoFiles lists %v", registered, listed)
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
		"BridgeRules", "BridgeRuleEntry", "BridgeRuleLink", "BridgeRuleMap", "BridgeRuleServed", "BridgeRuleSubject",
		"BridgeRuleReach", "BridgeRuleEgress", "BridgeRuleEntryKind",
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

// §6.11's rule reaches what rides those messages as bytes, which registry_test.go's walk cannot follow: hints in
// PushHint.hint, tickets in StreamOpen.ticket and edge metadata in StreamOpen.metadata. search.proto states the rule
// for itself, and evs.proto's statements are parsed on every push.
func TestNoOneofInWhatStreamsAndPushesCarry(t *testing.T) {
	for _, path := range []string{
		"protocol/evs.proto", "protocol/gkm.proto", "protocol/mail.proto", "protocol/search.proto", "protocol/smtp.proto",
		"protocol/socket.proto", "protocol/tls.proto",
	} {
		messages := testFile(t, path).Messages()
		if messages.Len() == 0 {
			t.Fatalf("%s declares no message", path)
		}
		for i := range messages.Len() {
			if messages.Get(i).Oneofs().Len() != 0 {
				t.Errorf("%s holds a oneof", messages.Get(i).FullName())
			}
		}
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
				"SMTP_PROOF": 0x1605, "SMTP_PROOF_RESULT": 0x1606, "SMTP_HANDSHAKE": 0x1607, "SMTP_HANDSHAKE_RESULT": 0x1608,
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

// §22.5's stability for the service files: §9's, §11.14's and §6.11's numbers as written, with TlsHint's kinds as
// plan-TLS-small-readings#1 numbers them, then evs.proto's bit and kind values, whose reserved ones
// evs_descriptor_test.go reads again, then the values §10 and §15 write as names.
func TestServiceEnumNumbersStable(t *testing.T) {
	cases := []struct {
		name string
		got  map[string]int32
		want map[string]int32
	}{
		{
			name: "SocketHintKind",
			got:  SocketHintKind_value,
			want: map[string]int32{"SOCKET_HINT_KIND_UNSPECIFIED": 0, "SOCKET_HINT_REVOKED": 1, "SOCKET_HINT_DRAIN": 2},
		},
		{
			name: "TlsHintKind",
			got:  TlsHintKind_value,
			want: map[string]int32{
				"TLS_HINT_KIND_UNSPECIFIED": 0, "TLS_HINT_ORDER": 1, "TLS_HINT_ISSUED": 2, "TLS_HINT_REVOKED": 3,
			},
		},
		{
			name: "SearchStatus",
			got:  SearchStatus_value,
			want: map[string]int32{
				"SEARCH_STATUS_UNSPECIFIED": 0, "SEARCH_OK": 1, "SEARCH_PARTIAL": 2, "SEARCH_TOO_BROAD": 3,
				"SEARCH_CURSOR_EXPIRED": 4, "SEARCH_INVALID": 5, "SEARCH_UNSUPPORTED_VERSION": 6,
			},
		},
		{
			name: "SearchServed",
			got:  SearchServed_value,
			want: map[string]int32{
				"SEARCH_SERVED_UNSPECIFIED": 0, "SERVED_TEXT": 1, "SERVED_INDEX": 2, "REFUSED_NOT_READER": 3,
				"REFUSED_NOT_CONSENTED": 4, "REFUSED_SCOPE": 5, "REFUSED_INDEX_OFF": 6, "REFUSED_ALL_ABSENT": 7,
				"REFUSED_FORMAT": 8,
			},
		},
		{
			name: "SmtpPreambleCode",
			got:  SmtpPreambleCode_value,
			want: map[string]int32{
				"SMTP_PREAMBLE_CODE_UNSPECIFIED": 0, "SMTP_PREAMBLE_OK": 1, "SMTP_PREAMBLE_HALTED": 2,
				"SMTP_PREAMBLE_QUOTA": 3, "SMTP_PREAMBLE_DENIED": 4, "SMTP_PREAMBLE_NO_MX": 5, "SMTP_PREAMBLE_NO_TLS": 6,
				"SMTP_PREAMBLE_TRY_LATER": 7,
			},
		},
		{
			name: "SmtpProofCode",
			got:  SmtpProofCode_value,
			want: map[string]int32{"SMTP_PROOF_CODE_UNSPECIFIED": 0, "SMTP_PROOF_OK": 1, "SMTP_PROOF_INVALID": 2},
		},
		{
			name: "SmtpStatusKind",
			got:  SmtpStatusKind_value,
			want: map[string]int32{
				"SMTP_STATUS_KIND_UNSPECIFIED": 0, "SMTP_STATUS_HALTED": 1, "SMTP_STATUS_QUOTA": 2, "SMTP_STATUS_CLEAR": 3,
			},
		},
		{
			name: "SmtpHandshakeCode",
			got:  SmtpHandshakeCode_value,
			want: map[string]int32{"SMTP_HANDSHAKE_CODE_UNSPECIFIED": 0, "SMTP_HANDSHAKE_OK": 1, "SMTP_HANDSHAKE_INVALID": 2},
		},
		{
			name: "EvsPushFlag",
			got:  EvsPushFlag_value,
			want: map[string]int32{
				"EVS_PUSH_FLAG_NONE": 0, "EVS_PUSH_FORCE": 1, "EVS_PUSH_DELETE": 2, "EVS_PUSH_BASE": 4,
				"EVS_PUSH_IMMUTABLE": 8, "EVS_PUSH_CONSUME": 16, "EVS_PUSH_PATH_EPOCH": 32, "EVS_PUSH_ERASE": 64,
				"EVS_PUSH_CLOSURE": 128, "EVS_PUSH_DROP": 256, "EVS_PUSH_CUT": 512,
			},
		},
		{
			name: "EvsLocatorKind",
			got:  EvsLocatorKind_value,
			want: map[string]int32{
				"EVS_LOCATOR_KIND_UNSPECIFIED": 0, "EVS_LOCATOR_SEGMENT": 1, "EVS_LOCATOR_INLINE": 2,
				"EVS_LOCATOR_VERSIONLESS_SEGMENT": 5,
			},
		},
		{
			name: "EvsVersioning",
			got:  EvsVersioning_value,
			want: map[string]int32{"EVS_VERSIONING_KEPT": 0, "EVS_VERSIONING_VERSIONLESS": 1, "EVS_VERSIONING_INDEX": 2},
		},
		{
			name: "EvsWindowFlag",
			got:  EvsWindowFlag_value,
			want: map[string]int32{
				"EVS_WINDOW_FLAG_NONE": 0, "EVS_WINDOW_CREATES_PATH": 1, "EVS_WINDOW_CHANGES_IN_PAYLOAD": 2,
				"EVS_WINDOW_PATH_EPOCH": 4, "EVS_WINDOW_REWRITES_HISTORY": 8, "EVS_WINDOW_VERSIONLESS_REPLACED": 16,
				"EVS_WINDOW_DROP": 32,
			},
		},
		{
			name: "GkmHintKind",
			got:  GkmHintKind_value,
			want: map[string]int32{
				"GKM_HINT_KIND_UNSPECIFIED": 0, "GKM_HINT_COMMIT": 1, "GKM_HINT_PENDING": 2, "GKM_HINT_WELCOME": 3,
				"GKM_HINT_KEY_PACKAGES_LOW": 4, "GKM_HINT_WRAP_PENDING": 5,
			},
		},
		{
			name: "SpfVerdict",
			got:  SpfVerdict_value,
			want: map[string]int32{
				"SPF_VERDICT_UNSPECIFIED": 0, "SPF_PASS": 1, "SPF_FAIL": 2, "SPF_SOFTFAIL": 3, "SPF_NEUTRAL": 4,
				"SPF_NONE": 5, "SPF_TEMPERROR": 6, "SPF_PERMERROR": 7, "SPF_INCOMPLETE": 8,
			},
		},
		{
			name: "DkimVerdict",
			got:  DkimVerdict_value,
			want: map[string]int32{
				"DKIM_VERDICT_UNSPECIFIED": 0, "DKIM_PASS": 1, "DKIM_FAIL": 2, "DKIM_PERMERROR": 3, "DKIM_TEMPERROR": 4,
				"DKIM_INCOMPLETE": 5,
			},
		},
		{
			name: "DmarcVerdict",
			got:  DmarcVerdict_value,
			want: map[string]int32{
				"DMARC_VERDICT_UNSPECIFIED": 0, "DMARC_PASS": 1, "DMARC_FAIL": 2, "DMARC_NONE": 3, "DMARC_TEMPERROR": 4,
			},
		},
		{
			name: "ArcVerdict",
			got:  ArcVerdict_value,
			want: map[string]int32{
				"ARC_VERDICT_UNSPECIFIED": 0, "ARC_NONE": 1, "ARC_PASS": 2, "ARC_FAIL": 3, "ARC_INCOMPLETE": 4,
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
		MessageType_SMTP_HANDSHAKE:           MessageType_SMTP_HANDSHAKE_RESULT,
	} {
		if result != request+1 {
			t.Errorf("%s + 1 is not %s", request, result)
		}
	}
}

// The withdrawn EvsHeadCheck stays reserved, its numbers and names never reused (§6.11, §11).
func TestWithdrawnEvsHeadCheckStaysReserved(t *testing.T) {
	messageType, ok := testDescriptor(t, "MessageType").(protoreflect.EnumDescriptor)
	if !ok {
		t.Fatal("MessageType is no enum")
	}
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

// D-PHASE-9's reservations in these files, fixed at M2 and M3 so a later milestone needs no number from a frozen
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
		{message: "CanonicalAction", field: "versioning", number: 37},
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

// The names in file that spell keep-last-n, in every kind of declaration that can take a number or reserve one:
// messages, fields, oneofs, enums, enum values, extensions and reserved names, nested ones included.
func testKeepLastNNames(file protoreflect.FileDescriptor) []string {
	found := []string{}
	check := func(name string) {
		lower := strings.ToLower(name)
		if strings.Contains(lower, "keep_last") || strings.Contains(lower, "keeplast") {
			found = append(found, name)
		}
	}
	checkReserved := func(names protoreflect.Names) {
		for i := range names.Len() {
			check(string(names.Get(i)))
		}
	}
	checkEnums := func(enums protoreflect.EnumDescriptors) {
		for i := range enums.Len() {
			enum := enums.Get(i)
			check(string(enum.FullName()))
			values := enum.Values()
			for j := range values.Len() {
				check(string(values.Get(j).FullName()))
			}
			checkReserved(enum.ReservedNames())
		}
	}
	checkExtensions := func(extensions protoreflect.ExtensionDescriptors) {
		for i := range extensions.Len() {
			check(string(extensions.Get(i).FullName()))
		}
	}
	var walk func(messages protoreflect.MessageDescriptors)
	walk = func(messages protoreflect.MessageDescriptors) {
		for i := range messages.Len() {
			message := messages.Get(i)
			check(string(message.FullName()))
			fields := message.Fields()
			for j := range fields.Len() {
				check(string(fields.Get(j).FullName()))
			}
			oneofs := message.Oneofs()
			for j := range oneofs.Len() {
				check(string(oneofs.Get(j).FullName()))
			}
			checkReserved(message.ReservedNames())
			checkEnums(message.Enums())
			checkExtensions(message.Extensions())
			walk(message.Messages())
		}
	}
	walk(file.Messages())
	checkEnums(file.Enums())
	checkExtensions(file.Extensions())
	return found
}

// Owner decision 165: no number is reserved for keep-last-n (D-PHASE-9). This walks the registry rather than
// testProtoFiles, so a file joins by being linked.
func TestNoNumberForKeepLastN(t *testing.T) {
	count := 0
	protoregistry.GlobalFiles.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		count++
		for _, name := range testKeepLastNNames(file) {
			t.Errorf("%s: %s reserves keep-last-n", file.Path(), name)
		}
		return true
	})
	if count < len(testProtoFiles) {
		t.Fatalf("walked %d files", count)
	}
}

// Plants keep-last-n in each kind of declaration of a file made here, because a lint that passes the real files
// says nothing about what it would catch.
func TestKeepLastNLintReachesEveryDeclaration(t *testing.T) {
	enumValues := func(names ...string) []*descriptorpb.EnumValueDescriptorProto {
		values := make([]*descriptorpb.EnumValueDescriptorProto, 0, len(names))
		for i, name := range names {
			values = append(values, &descriptorpb.EnumValueDescriptorProto{
				Name:   proto.String(name),
				Number: proto.Int32(int32(i)),
			})
		}
		return values
	}
	field := func(name string) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{
			Name:   proto.String(name),
			Number: proto.Int32(1),
			Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
			Type:   descriptorpb.FieldDescriptorProto_TYPE_UINT32.Enum(),
		}
	}
	file := func(mutate func(file *descriptorpb.FileDescriptorProto)) protoreflect.FileDescriptor {
		fileProto := &descriptorpb.FileDescriptorProto{
			Name:        proto.String("protocol/planted.proto"),
			Package:     proto.String("planted"),
			Syntax:      proto.String("proto3"),
			MessageType: []*descriptorpb.DescriptorProto{{Name: proto.String("Versioning")}},
			EnumType: []*descriptorpb.EnumDescriptorProto{{
				Name:  proto.String("VersioningMode"),
				Value: enumValues("VERSIONING_MODE_UNSPECIFIED"),
			}},
		}
		if mutate != nil {
			mutate(fileProto)
		}
		descriptor, err := protodesc.NewFile(fileProto, nil)
		if err != nil {
			t.Fatal(err)
		}
		return descriptor
	}

	if names := testKeepLastNNames(file(nil)); len(names) != 0 {
		t.Fatalf("the unplanted file reserves %v", names)
	}
	cases := []struct {
		name   string
		mutate func(file *descriptorpb.FileDescriptorProto)
	}{
		{
			name: "a message",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.MessageType[0].Name = proto.String("KeepLastN")
			},
		},
		{
			name: "a nested message",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.MessageType[0].NestedType = []*descriptorpb.DescriptorProto{{Name: proto.String("KeepLastN")}}
			},
		},
		{
			name: "a field",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.MessageType[0].Field = []*descriptorpb.FieldDescriptorProto{field("keep_last_n")}
			},
		},
		{
			name: "a reserved field name",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.MessageType[0].ReservedName = []string{"keep_last_n"}
			},
		},
		{
			name: "a oneof",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				member := field("n")
				member.OneofIndex = proto.Int32(0)
				file.MessageType[0].Field = []*descriptorpb.FieldDescriptorProto{member}
				file.MessageType[0].OneofDecl = []*descriptorpb.OneofDescriptorProto{{Name: proto.String("keep_last")}}
			},
		},
		{
			name: "an enum",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.EnumType[0].Name = proto.String("KeepLastMode")
			},
		},
		{
			name: "an enum value",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.EnumType[0].Value = enumValues("VERSIONING_MODE_UNSPECIFIED", "VERSIONING_MODE_KEEP_LAST_N")
			},
		},
		{
			name: "a reserved enum name",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.EnumType[0].ReservedName = []string{"VERSIONING_MODE_KEEP_LAST_N"}
			},
		},
		{
			name: "a nested enum's value",
			mutate: func(file *descriptorpb.FileDescriptorProto) {
				file.MessageType[0].EnumType = []*descriptorpb.EnumDescriptorProto{{
					Name:  proto.String("Mode"),
					Value: enumValues("MODE_UNSPECIFIED", "MODE_KEEP_LAST_N"),
				}}
			},
		},
	}
	for _, c := range cases {
		if names := testKeepLastNNames(file(c.mutate)); len(names) != 1 {
			t.Errorf("%s: found %v", c.name, names)
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

// D-KEYS-3, owner decision 59: authenticated_data adds only what the gate needs and no roster delta, which §22.7
// asserts of every stored commit. gkm reads this in the clear, so a field here reaches the server.
func TestCommitHeaderCarriesOnlyGenerationAndAuth(t *testing.T) {
	fields := testMessage(t, "GkmCommitHeader").Fields()
	names := make([]string, 0, fields.Len())
	for i := range fields.Len() {
		names = append(names, string(fields.Get(i).Name()))
	}
	slices.Sort(names)
	if !slices.Equal(names, []string{"auth", "generation"}) {
		t.Errorf("GkmCommitHeader shows %v", names)
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
		{message: "BridgeAlias", fields: []string{"header", "sealed_body"}},
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
		{message: "RepoVersioning", fields: []string{"header", "lock", "repo_id", "sealed_rules"}},
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

// FS-72 and D-PHASE-9: what §7's three files hold for a later milestone equals the decided list. Their reservations are
// declared rather than `reserved`: ServiceSettings.directory is a field older readers ignore, and VersioningRules a
// record and a type format 1 verifies and applies nothing from. So these files keep no `reserved` statement, and each
// message a reservation touches holds exactly its decided numbers, lest something undecided freeze beside them at M2.
func TestConfigReservationsEqualTheDecidedList(t *testing.T) {
	for _, path := range []string{"protocol/bridge/auth.proto", "protocol/bridge/signed.proto", "protocol/config.proto"} {
		file := testFile(t, path)
		enums := file.Enums()
		for i := range enums.Len() {
			enum := enums.Get(i)
			if enum.ReservedRanges().Len() != 0 || enum.ReservedNames().Len() != 0 {
				t.Errorf("%s reserves numbers no decision lists", enum.FullName())
			}
		}
		messages := file.Messages()
		for i := range messages.Len() {
			message := messages.Get(i)
			if message.ReservedRanges().Len() != 0 || message.ReservedNames().Len() != 0 {
				t.Errorf("%s reserves numbers no decision lists", message.FullName())
			}
		}
	}

	// Each message the reservations touch, whole: a field added beside these is a number no decision made.
	decided := map[string]map[protoreflect.Name]protoreflect.FieldNumber{
		"ServiceSettings": {
			"team_mail": 1, "stale_leaf_days": 2, "self_admit": 3, "witness_bound_hours": 4, "scim_signer": 5, "directory": 6,
		},
		"ServiceDirectorySettings": {"runs": 1, "workers": 2},
		"VersioningRules":          {"rules": 1},
		"VersioningRule":           {"kinds": 1, "repo_ids": 2, "path_glob": 3, "size_above_bytes": 4, "versioning": 5},
	}
	for name, want := range decided {
		fields := testMessage(t, name).Fields()
		got := map[protoreflect.Name]protoreflect.FieldNumber{}
		for i := range fields.Len() {
			got[fields.Get(i).Name()] = fields.Get(i).Number()
		}
		if !maps.Equal(got, want) {
			t.Errorf("%s holds %v, want %v", name, got, want)
		}
	}
}
