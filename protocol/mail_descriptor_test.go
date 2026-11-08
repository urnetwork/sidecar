// What holds mail.proto beyond the fences, which reach only §15.5's blocks: every message's fields and every enum's
// numbers, the bounds MAIL-FORMAT.md states with their drop orders, and the append rule of i/ and f/. A field moved,
// retyped, added or dropped here fails until these tables say so, and nothing here is hand-built, so a field added
// without a stated width stops the bound tests rather than slipping past them unset.
//
// The builders that enforce the bounds are MAIL-M7-09's and MAIL-M7-19's. The ingress test applies the same order to
// show it always ends within the bound, which is the format's half of the promise.

package protocol

import (
	"bytes"
	"fmt"
	"maps"
	"math"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

const (
	// Where the registry finds this file.
	testMailProtoPath = "protocol/mail.proto"

	// §15.5's bounds.
	testMailIngressBound  = 1024
	testMailEvidenceBound = 8 * 1024
	// §15.7's bounds on an i/ segment, and on an f/ segment's ops.
	testMailSegmentByteBound = 1024 * 1024
	testMailSegmentCount     = 4096
	// MAIL-FORMAT.md's bound on one IndexEntry.
	testMailEntryBound = 16 * 1024

	// A DNS name.
	testMailHostWidth = 253
	// §15.5: the pre-TLS EHLO or HELO argument.
	testMailEhloWidth = 255
	// §15.8's local part, an @ and a DNS name.
	testMailAddressWidth = 64 + 1 + testMailHostWidth
	// An IPv6 sender.
	testMailIpWidth = 16
	// MAIL-FORMAT.md's hold on ip_listings, ahead of any drop.
	testMailListingCount = 16
	testMailListingWidth = 12
)

// Every message of mail.proto, each field as number, optional repeated, type and name. §15.5's fenced messages come
// first; the rest are the format MAIL-FORMAT.md states.
var testMailMessageFields = map[string][]string{
	"MailIngress": {
		"1 uint32 version", "2 bytes sender_ip", "3 uint32 sender_port", "5 string sni", "8 string ehlo_name",
		"9 string ptr_name", "10 repeated string ip_listings", "11 uint64 receive_time_millis",
	},
	"MailAuthEvidence": {
		"1 uint32 version", "2 bytes message_sha256", "3 uint64 receive_time_millis", "4 bytes receiver_sidecar_id",
		"5 SpfResult spf", "6 repeated DkimResult dkim", "7 DmarcResult dmarc", "8 string ptr_name",
		"9 bool sni_tlsa_live", "10 ArcResult arc", "11 bool strict_chain", "12 AuthLimits limits",
	},
	"AuthLimits": {
		"1 uint32 reason", "2 uint32 dkim_seen", "3 uint32 dkim_checked", "4 uint32 arc_sets", "5 uint32 dns_queries",
		"6 uint32 dropped",
	},
	"SpfResult": {"1 SpfVerdict result", "2 string domain", "3 bytes ip", "4 repeated string records"},
	"DkimResult": {
		"1 string domain", "2 string selector", "3 DkimVerdict result", "4 bytes public_key",
	},
	"DmarcResult": {
		"1 string p", "2 string adkim", "3 string aspf", "4 uint32 alignment", "5 DmarcVerdict result",
	},
	"ArcSet":    {"1 string domain", "2 string selector", "3 bytes public_key"},
	"ArcResult": {"1 ArcVerdict cv", "2 repeated ArcSet sets"},
	"MailHint":  {"1 MailHintKind kind", "2 string host"},
	"MailDeposit": {
		"1 uint32 version", "2 MailIngress ingress", "3 MailAuthEvidence evidence", "4 bytes mail_from",
		"5 bool require_tls", "6 repeated string recipients", "7 uint32 tls_version", "8 uint32 tls_suite",
		"9 bytes receiver_sidecar_id",
	},
	"MailAddress": {
		"1 MailAddressKind kind", "2 bytes mailbox", "3 repeated bytes members", "4 bytes creator", "5 bytes effect_key",
	},
	"MailBurner": {
		"1 bytes mailbox", "2 MailBurnerState state", "3 bool replying", "4 uint64 created", "5 bytes effect_key",
	},
	"IndexEntry": {
		"1 bytes id", "2 string address", "3 uint64 time", "4 string from", "5 string subject", "6 string snippet",
		"7 string message_id", "8 bytes thread_key", "9 uint64 size", "10 repeated MailAttachment attachments",
		"11 MailAuthResults auth_results", "12 MailTlsLabel tls_label", "13 MailTlsBasis tls_basis",
		"14 uint32 spam_score", "15 string one_time_code",
	},
	"MailAttachment": {"1 string name", "2 string type", "3 uint64 size"},
	"MailAuthResults": {
		"1 SpfVerdict spf", "2 DkimVerdict dkim", "3 DmarcVerdict dmarc", "4 ArcVerdict arc",
		"5 bool checks_incomplete", "6 bool evidence_unavailable",
	},
	"MailTlsBasis": {
		"1 MailTlsRule rule", "2 string operator_id", "3 uint32 list_version", "4 bool strict_custom_mx",
	},
	"MailIndexSegment": {"1 repeated IndexEntry entries"},
	"MailFlagOp": {
		"1 bytes message_id", "2 MailFlagKind op", "3 bool set", "4 string label", "5 uint64 hlc", "7 bytes sidecar_id",
	},
	"MailFlagSegment": {"1 repeated MailFlagOp ops"},
	"MailGroupRef":    {"1 bytes repo_id", "2 bytes message_id"},
	"VaultEntry": {
		"1 bytes entry_id", "2 string address", "3 string title", "4 string username", "5 string password",
		"6 repeated string password_history", "7 VaultTotp totp", "8 repeated string urls", "9 string notes",
		"10 repeated VaultUsedAt used_at", "11 uint64 created", "12 uint64 updated", "13 VaultEntryState state",
	},
	"VaultTotp": {
		"1 bytes secret", "2 VaultTotpAlgorithm algorithm", "3 uint32 digits", "4 uint32 period",
	},
	"VaultUsedAt":      {"1 string registrable_domain", "2 uint64 first", "3 uint64 last"},
	"MailForward":      {"1 string address", "2 repeated string burners", "3 uint64 verified_time_ms"},
	"MailReverseAlias": {"1 string original_sender", "2 string burner_address"},
	"SmtpOutboxEntry": {
		"1 bytes effect_key", "2 bytes message_sha256", "3 string sender", "4 repeated string recipients",
		"5 uint32 flags", "6 repeated string tl4_domains", "7 uint64 create_time_ms", "8 uint64 approval_not_after",
	},
	"MailOutcome": {
		"1 string domain", "2 MailSendMode mode", "3 uint64 byte_count", "4 uint64 cap_byte_count",
		"5 MailOutcomeKind outcome", "6 uint32 reply_code", "7 uint32 retry_after_ms", "8 uint64 update_time_ms",
		"9 uint32 tls_level",
	},
	"MailOutcomeRecord": {"1 repeated MailOutcome outcomes"},
	"MailProverRecord": {
		"1 uint64 smtp_data_proof_bytes", "2 uint64 data_bytes_per_s", "3 uint64 measure_time_ms",
	},
}

// The widest value of each field a bound test fills, keyed message.field: a string or bytes field's width in bytes, a
// list's count with its elements' width under message.field[], and 0 where the type alone sets the width, which is
// the largest number or the last enum value, so these overstate what a real message takes.
var testMailIngressWidths = map[string]int{
	"MailIngress.version":             0,
	"MailIngress.sender_ip":           testMailIpWidth,
	"MailIngress.sender_port":         0,
	"MailIngress.sni":                 testMailHostWidth,
	"MailIngress.ehlo_name":           testMailEhloWidth,
	"MailIngress.ptr_name":            testMailHostWidth,
	"MailIngress.ip_listings":         0,
	"MailIngress.ip_listings[]":       0,
	"MailIngress.receive_time_millis": 0,
}

// A MailAuthEvidence with every entry and key §15.5's drop rule can take gone, and every identifier left at its widest.
var testMailEvidenceFloorWidths = map[string]int{
	"MailAuthEvidence.version":             0,
	"MailAuthEvidence.message_sha256":      testHashSize,
	"MailAuthEvidence.receive_time_millis": 0,
	"MailAuthEvidence.receiver_sidecar_id": testIdSize,
	"MailAuthEvidence.spf":                 0,
	"MailAuthEvidence.dkim":                0,
	"MailAuthEvidence.dmarc":               0,
	"MailAuthEvidence.ptr_name":            testMailHostWidth,
	"MailAuthEvidence.sni_tlsa_live":       0,
	"MailAuthEvidence.arc":                 0,
	"MailAuthEvidence.strict_chain":        0,
	"MailAuthEvidence.limits":              0,
	"SpfResult.result":                     0,
	"SpfResult.domain":                     testMailHostWidth,
	"SpfResult.ip":                         testMailIpWidth,
	"SpfResult.records":                    0,
	"SpfResult.records[]":                  0,
	"DmarcResult.p":                        testMailHostWidth,
	"DmarcResult.adkim":                    testMailHostWidth,
	"DmarcResult.aspf":                     testMailHostWidth,
	"DmarcResult.alignment":                0,
	"DmarcResult.result":                   0,
	"ArcResult.cv":                         0,
	"ArcResult.sets":                       0,
	"AuthLimits.reason":                    0,
	"AuthLimits.dkim_seen":                 0,
	"AuthLimits.dkim_checked":              0,
	"AuthLimits.arc_sets":                  0,
	"AuthLimits.dns_queries":               0,
	"AuthLimits.dropped":                   0,
}

// An IndexEntry at MAIL-FORMAT.md's caps.
var testMailIndexEntryWidths = map[string]int{
	"IndexEntry.id":                        testIdSize,
	"IndexEntry.address":                   testMailAddressWidth,
	"IndexEntry.time":                      0,
	"IndexEntry.from":                      512,
	"IndexEntry.subject":                   512,
	"IndexEntry.snippet":                   200,
	"IndexEntry.message_id":                256,
	"IndexEntry.thread_key":                testIdSize,
	"IndexEntry.size":                      0,
	"IndexEntry.attachments":               32,
	"IndexEntry.auth_results":              0,
	"IndexEntry.tls_label":                 0,
	"IndexEntry.tls_basis":                 0,
	"IndexEntry.spam_score":                0,
	"IndexEntry.one_time_code":             32,
	"MailAttachment.name":                  256,
	"MailAttachment.type":                  128,
	"MailAttachment.size":                  0,
	"MailAuthResults.spf":                  0,
	"MailAuthResults.dkim":                 0,
	"MailAuthResults.dmarc":                0,
	"MailAuthResults.arc":                  0,
	"MailAuthResults.checks_incomplete":    0,
	"MailAuthResults.evidence_unavailable": 0,
	"MailTlsBasis.rule":                    0,
	"MailTlsBasis.operator_id":             64,
	"MailTlsBasis.list_version":            0,
	"MailTlsBasis.strict_custom_mx":        0,
}

// A MailFlagOp at MAIL-FORMAT.md's caps.
var testMailFlagOpWidths = map[string]int{
	"MailFlagOp.message_id": testIdSize,
	"MailFlagOp.op":         0,
	"MailFlagOp.label":      64,
	"MailFlagOp.set":        0,
	"MailFlagOp.hlc":        0,
	"MailFlagOp.sidecar_id": testIdSize,
}

// Fills message to fieldNameWidths, stopping on a field the table does not name.
func testFillWidest(t *testing.T, message protoreflect.Message, fieldNameWidths map[string]int) {
	t.Helper()
	widest := func(field protoreflect.FieldDescriptor, width int) protoreflect.Value {
		switch field.Kind() {
		case protoreflect.BoolKind:
			return protoreflect.ValueOfBool(true)
		case protoreflect.Uint32Kind:
			return protoreflect.ValueOfUint32(math.MaxUint32)
		case protoreflect.Uint64Kind:
			return protoreflect.ValueOfUint64(math.MaxUint64)
		case protoreflect.EnumKind:
			values := field.Enum().Values()
			return protoreflect.ValueOfEnum(values.Get(values.Len() - 1).Number())
		case protoreflect.StringKind:
			return protoreflect.ValueOfString(strings.Repeat("x", width))
		case protoreflect.BytesKind:
			return protoreflect.ValueOfBytes(testBytes(width))
		}
		t.Fatalf("%s has kind %s, which no width here stands for", field.FullName(), field.Kind())
		return protoreflect.Value{}
	}
	descriptor := message.Descriptor()
	fields := descriptor.Fields()
	for i := range fields.Len() {
		field := fields.Get(i)
		key := string(descriptor.Name()) + "." + string(field.Name())
		width, ok := fieldNameWidths[key]
		if !ok {
			t.Fatalf("%s has no stated width, so no bound here covers it", key)
		}
		switch {
		case field.IsList():
			list := message.Mutable(field).List()
			for range width {
				if field.Message() == nil {
					list.Append(widest(field, fieldNameWidths[key+"[]"]))
					continue
				}
				element := list.NewElement()
				testFillWidest(t, element.Message(), fieldNameWidths)
				list.Append(element)
			}
		case field.Message() != nil:
			testFillWidest(t, message.Mutable(field).Message(), fieldNameWidths)
		default:
			message.Set(field, widest(field, width))
		}
	}
}

// One declaration per name across every file of the package: a second would panic at init wherever both link, and
// this says so even where a shell has set the conflict policy to warn.
func TestMailMessagesRegisterOnce(t *testing.T) {
	nameCounts := map[protoreflect.Name]int{}
	var count func(messages protoreflect.MessageDescriptors)
	count = func(messages protoreflect.MessageDescriptors) {
		for i := range messages.Len() {
			nameCounts[messages.Get(i).Name()]++
			count(messages.Get(i).Messages())
		}
	}
	protoregistry.GlobalFiles.RangeFilesByPackage(testProtoPackage, func(file protoreflect.FileDescriptor) bool {
		count(file.Messages())
		return true
	})
	file := testFile(t, testMailProtoPath)
	if file.Messages().Len() != len(testMailMessageFields) {
		t.Errorf("mail.proto declares %d messages, and this table %d", file.Messages().Len(), len(testMailMessageFields))
	}
	for name := range testMailMessageFields {
		if file.Messages().ByName(protoreflect.Name(name)) == nil {
			t.Errorf("%s is not in mail.proto", name)
		}
		if nameCount := nameCounts[protoreflect.Name(name)]; nameCount != 1 {
			t.Errorf("%s is declared %d times", name, nameCount)
		}
	}
}

// §15.5's numbers and the format's, in number, label, type and name, with nothing added or missing. A proto3 optional
// reads as its own label, because it changes what an unset field means.
func TestMailFieldsKeepTheirNumbers(t *testing.T) {
	shape := func(field protoreflect.FieldDescriptor) string {
		label := ""
		switch {
		case field.HasOptionalKeyword():
			label = "optional "
		case field.IsList():
			label = "repeated "
		}
		typeName := field.Kind().String()
		switch {
		case field.Message() != nil:
			typeName = string(field.Message().Name())
		case field.Enum() != nil:
			typeName = string(field.Enum().Name())
		}
		return fmt.Sprintf("%d %s%s %s", field.Number(), label, typeName, field.Name())
	}
	for name, wantFields := range testMailMessageFields {
		fields := testMessage(t, name).Fields()
		gotFields := make([]string, 0, fields.Len())
		for i := range fields.Len() {
			gotFields = append(gotFields, shape(fields.Get(i)))
		}
		if !slices.Equal(gotFields, wantFields) {
			t.Errorf("%s is\n%q, want\n%q", name, gotFields, wantFields)
		}
	}
}

// §15.5: SNI-only routing took destination_ip, route and burner_id out, and no number of theirs comes back. MailFlagOp
// keeps hlc_count's, since its one clock field holds the two plan-MAIL-format-bytes#5 wrote. Nothing else in the file
// reserves one.
func TestMailReservationsStay(t *testing.T) {
	nameReservedNumbers := map[string][]int32{"MailIngress": {4, 6, 7}, "MailFlagOp": {6}}
	for name := range testMailMessageFields {
		want := append([]int32{}, nameReservedNumbers[name]...)
		if got := testSorted(testReservedNumbers(testMessage(t, name).ReservedRanges())); !slices.Equal(got, want) {
			t.Errorf("%s reserves %v, want %v", name, got, want)
		}
	}
}

// §6.11's rule for what a stream or push carries, and this file's for what an encoding may depend on: no oneof, no
// map, and nothing nested, so a name here is declared where this table reads it.
func TestMailMessagesStayFlat(t *testing.T) {
	file := testFile(t, testMailProtoPath)
	for i := range file.Messages().Len() {
		message := file.Messages().Get(i)
		if message.Oneofs().Len() != 0 {
			t.Errorf("%s holds a oneof", message.Name())
		}
		if message.Messages().Len() != 0 || message.Enums().Len() != 0 {
			t.Errorf("%s nests a declaration", message.Name())
		}
		fields := message.Fields()
		for j := range fields.Len() {
			if fields.Get(j).IsMap() {
				t.Errorf("%s holds a map", fields.Get(j).FullName())
			}
		}
	}
}

// §22.5's stability for every enum this file adds; TestServiceEnumNumbersStable holds the four verdicts.
func TestMailEnumNumbersStable(t *testing.T) {
	cases := []struct {
		name string
		got  map[string]int32
		want map[string]int32
	}{
		{
			name: "MailHintKind",
			got:  MailHintKind_value,
			want: map[string]int32{"MAIL_HINT_KIND_UNSPECIFIED": 0, "MAIL_HINT_DEPOSIT": 1, "MAIL_HINT_RECEIVER_NEEDED": 2},
		},
		{
			name: "MailAddressKind",
			got:  MailAddressKind_value,
			want: map[string]int32{
				"MAIL_ADDRESS_KIND_UNSPECIFIED": 0, "MAIL_ADDRESS_ADMIN": 1, "MAIL_ADDRESS_ID": 2, "MAIL_ADDRESS_GROUP": 3,
				"MAIL_ADDRESS_AGENT": 4, "MAIL_ADDRESS_BURNER": 5, "MAIL_ADDRESS_BOUNCE": 6,
			},
		},
		{
			name: "MailBurnerState",
			got:  MailBurnerState_value,
			want: map[string]int32{
				"MAIL_BURNER_STATE_UNSPECIFIED": 0, "MAIL_BURNER_LIVE": 1, "MAIL_BURNER_PAUSED": 2, "MAIL_BURNER_BURNED": 3,
			},
		},
		{
			name: "MailTlsLabel",
			got:  MailTlsLabel_value,
			want: map[string]int32{
				"MAIL_TLS_LABEL_UNSPECIFIED": 0, "MAIL_TLS_VALIDATED": 1, "MAIL_TLS_OPPORTUNISTIC": 2,
				"MAIL_TLS_MEMBER_SIGNED": 3,
			},
		},
		{
			name: "MailTlsRule",
			got:  MailTlsRule_value,
			want: map[string]int32{
				"MAIL_TLS_RULE_UNSPECIFIED": 0, "MAIL_TLS_RULE_REQUIRETLS": 1, "MAIL_TLS_RULE_OPERATOR": 2,
			},
		},
		{
			name: "MailFlagKind",
			got:  MailFlagKind_value,
			want: map[string]int32{
				"MAIL_FLAG_KIND_UNSPECIFIED": 0, "MAIL_FLAG_SEEN": 1, "MAIL_FLAG_FLAGGED": 2, "MAIL_FLAG_LABEL": 3,
				"MAIL_FLAG_TRASH": 4,
			},
		},
		{
			name: "VaultEntryState",
			got:  VaultEntryState_value,
			want: map[string]int32{"VAULT_ENTRY_STATE_UNSPECIFIED": 0, "VAULT_ENTRY_LIVE": 1, "VAULT_ENTRY_BURNED": 2},
		},
		{
			name: "VaultTotpAlgorithm",
			got:  VaultTotpAlgorithm_value,
			want: map[string]int32{
				"VAULT_TOTP_ALGORITHM_UNSPECIFIED": 0, "VAULT_TOTP_SHA1": 1, "VAULT_TOTP_SHA256": 2, "VAULT_TOTP_SHA512": 3,
			},
		},
		{
			name: "MailSendMode",
			got:  MailSendMode_value,
			want: map[string]int32{"MAIL_SEND_MODE_UNSPECIFIED": 0, "MAIL_SEND_BDAT": 1, "MAIL_SEND_DATA": 2},
		},
		{
			name: "MailOutcomeKind",
			got:  MailOutcomeKind_value,
			want: map[string]int32{
				"MAIL_OUTCOME_KIND_UNSPECIFIED": 0, "MAIL_OUTCOME_SENT": 1, "MAIL_OUTCOME_QUEUED": 2,
				"MAIL_OUTCOME_DEFERRED": 3, "MAIL_OUTCOME_TOO_LARGE": 4, "MAIL_OUTCOME_REFUSED": 5,
				"MAIL_OUTCOME_TLS_REFUSED": 6, "MAIL_OUTCOME_FAILED": 7,
			},
		},
	}
	for _, c := range cases {
		if !maps.Equal(c.got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, c.got, c.want)
		}
	}
	enums := testFile(t, testMailProtoPath).Enums()
	// The four verdicts and each case above: an enum added to the file has to join this test.
	if want := len(cases) + 4; enums.Len() != want {
		t.Errorf("mail.proto declares %d enums, want %d", enums.Len(), want)
	}
}

// §6.11: an unset enum is no choice, so no value that means something may be the zero.
func TestMailEnumsStartUnspecified(t *testing.T) {
	enums := testFile(t, testMailProtoPath).Enums()
	for i := range enums.Len() {
		zero := enums.Get(i).Values().ByNumber(0)
		if zero == nil || !strings.HasSuffix(string(zero.Name()), "_UNSPECIFIED") {
			t.Errorf("%s has no unspecified zero", enums.Get(i).Name())
		}
	}
}

// §6.11's numbers for the two messages this file gives bodies to. A hint's body rides PushHint.hint, so it holds a kind
// and a host mx-3 already names (§2.8: ids and kinds, never content), and TestHintsFitPushHint holds it to §6.8's
// bound.
func TestMailMessageTypesKeepTheirNumbers(t *testing.T) {
	if MessageType_MAIL_INGRESS != 0x1701 || MessageType_MAIL_HINT != 0x1702 {
		t.Errorf("MAIL_INGRESS is %#x and MAIL_HINT %#x", int32(MessageType_MAIL_INGRESS), int32(MessageType_MAIL_HINT))
	}
}

// MAIL-FORMAT.md's order, as the router's builder applies it: listings held to the first 16 of at most 12 B, then,
// past 1,024 B, ptr_name, then listings from the end, one at a time. Nothing else is ever dropped.
func testBuildMailIngress(t *testing.T, ingress *MailIngress) {
	t.Helper()
	held := []string{}
	for _, listing := range ingress.IpListings {
		if len(listing) <= testMailListingWidth && len(held) < testMailListingCount {
			held = append(held, listing)
		}
	}
	ingress.IpListings = held
	if testSize(t, ingress) > testMailIngressBound {
		ingress.PtrName = ""
	}
	for testSize(t, ingress) > testMailIngressBound && len(ingress.IpListings) > 0 {
		ingress.IpListings = ingress.IpListings[:len(ingress.IpListings)-1]
	}
}

// §15.5: every identifier at its widest and listings far past the hold, built within 1,024 B by the order alone. The
// 16 held listings and ptr_name do not fit together, so ptr_name goes and every held listing stays.
func TestMailIngressAtItsWidestBuildsWithinItsBound(t *testing.T) {
	ingress := &MailIngress{}
	testFillWidest(t, ingress.ProtoReflect(), testMailIngressWidths)
	for i := range 64 {
		// Every other listing passes the width, so the hold leaves it out wherever it falls.
		width := testMailListingWidth + i%2
		ingress.IpListings = append(ingress.IpListings, strings.Repeat("x", width))
	}
	testBuildMailIngress(t, ingress)
	if size := testSize(t, ingress); size > testMailIngressBound {
		t.Errorf("a built ingress takes %d B, over %d", size, testMailIngressBound)
	}
	if len(ingress.IpListings) != testMailListingCount {
		t.Errorf("%d listings survived, want the %d the hold keeps", len(ingress.IpListings), testMailListingCount)
	}
	for _, listing := range ingress.IpListings {
		if len(listing) > testMailListingWidth {
			t.Errorf("a %d B listing passed the hold", len(listing))
		}
	}
	if ingress.PtrName != "" {
		t.Error("ptr_name stayed, though it and the held listings pass the bound together")
	}
	if len(ingress.Sni) != testMailHostWidth || len(ingress.EhloName) != testMailEhloWidth ||
		len(ingress.SenderIp) != testMailIpWidth || ingress.ReceiveTimeMillis == 0 {
		t.Error("the order dropped a field it never drops")
	}
}

// The hold is enough for an ordinary sender, so ptr_name stays.
func TestMailIngressKeepsPtrNameWhenTheHeldListingsFit(t *testing.T) {
	ingress := &MailIngress{
		Version:           1,
		SenderIp:          testBytes(testMailIpWidth),
		SenderPort:        49152,
		Sni:               "mx.acme.root.example",
		EhloName:          "mail.sender.example",
		PtrName:           "mail.sender.example",
		ReceiveTimeMillis: math.MaxUint64,
	}
	for range 64 {
		ingress.IpListings = append(ingress.IpListings, strings.Repeat("x", testMailListingWidth))
	}
	testBuildMailIngress(t, ingress)
	if ingress.PtrName == "" || len(ingress.IpListings) != testMailListingCount {
		t.Errorf("ptr_name %q and %d listings, want it kept with %d", ingress.PtrName, len(ingress.IpListings),
			testMailListingCount)
	}
}

// The order always ends by its second step: at every bound the message states, no listings take 811 B and the held
// listings without ptr_name 779 B, so listings go from the end only when a field is past its own bound.
// MAIL-FORMAT.md quotes both sizes.
func TestMailIngressFitsAtEveryBound(t *testing.T) {
	ingress := &MailIngress{}
	testFillWidest(t, ingress.ProtoReflect(), testMailIngressWidths)
	if size := testSize(t, ingress); size != 811 {
		t.Errorf("an ingress with no listings takes %d B, and MAIL-FORMAT.md says 811", size)
	}
	ingress.PtrName = ""
	for range testMailListingCount {
		ingress.IpListings = append(ingress.IpListings, strings.Repeat("x", testMailListingWidth))
	}
	if size := testSize(t, ingress); size != 779 {
		t.Errorf("an ingress with the held listings and no ptr_name takes %d B, and MAIL-FORMAT.md says 779", size)
	}
}

// §15.5's drop rule has a floor: with every entry, key and record it may take gone and the identifiers left at their
// widest, the evidence fits, so the rule can always reach 8,192 B. MailEvidenceBuilder's own cases are FS-121's.
func TestMailEvidenceFloorFitsItsBound(t *testing.T) {
	evidence := &MailAuthEvidence{}
	testFillWidest(t, evidence.ProtoReflect(), testMailEvidenceFloorWidths)
	if size := testSize(t, evidence); size > testMailEvidenceBound {
		t.Errorf("the evidence's floor takes %d B, over %d", size, testMailEvidenceBound)
	}
}

// MAIL-FORMAT.md's caps hold an entry to its bound, and so give a full segment room for many.
func TestIndexEntryFitsItsBound(t *testing.T) {
	entry := &IndexEntry{}
	testFillWidest(t, entry.ProtoReflect(), testMailIndexEntryWidths)
	if size := testSize(t, entry); size > testMailEntryBound {
		t.Errorf("an entry takes %d B, over %d", size, testMailEntryBound)
	}
}

// §15.7 bounds f/ by count alone, which holds only if a segment of the widest ops stays under what i/ takes in bytes.
func TestFlagSegmentFitsAtItsCount(t *testing.T) {
	segment := &MailFlagSegment{}
	for range testMailSegmentCount {
		op := &MailFlagOp{}
		testFillWidest(t, op.ProtoReflect(), testMailFlagOpWidths)
		segment.Ops = append(segment.Ops, op)
	}
	if size := testSize(t, segment); size > testMailSegmentByteBound {
		t.Errorf("a full f/ segment takes %d B, over %d", size, testMailSegmentByteBound)
	}
}

// MAIL-FORMAT.md's append rule: a segment is its records and nothing else, so its bytes are the bytes of it before,
// then one whole record. A writer appends without re-encoding, §11.7's delta against the last version adds only that
// record, and a new segment is its first record alone.
func TestMailSegmentsGrowByAppending(t *testing.T) {
	entry := testFilled((&IndexEntry{}).ProtoReflect().Type()).(*IndexEntry)
	indexRecord := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), testEncode(t, entry))
	index := &MailIndexSegment{}
	for count := 1; count <= 2; count++ {
		indexBefore := testEncode(t, index)
		index.Entries = append(index.Entries, entry)
		if !bytes.Equal(testEncode(t, index), append(indexBefore, indexRecord...)) {
			t.Errorf("an i/ segment did not grow by one record to %d", count)
		}
	}

	op := testFilled((&MailFlagOp{}).ProtoReflect().Type()).(*MailFlagOp)
	flagsRecord := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), testEncode(t, op))
	flags := &MailFlagSegment{}
	for count := 1; count <= 2; count++ {
		flagsBefore := testEncode(t, flags)
		flags.Ops = append(flags.Ops, op)
		if !bytes.Equal(testEncode(t, flags), append(flagsBefore, flagsRecord...)) {
			t.Errorf("an f/ segment did not grow by one record to %d", count)
		}
	}
}

// What a sender controls and a string field would refuse: proto.Marshal fails on bytes that are not UTF-8, which
// would turn a hostile MAIL FROM into a deposit that never lands, so mail_from is bytes. ehlo_name stays §15.5's
// string, so its builder has to clear such a value.
func TestMailFromTakesWhatAStringWouldRefuse(t *testing.T) {
	hostile := []byte{'a', 0xFF, '@', 0xC0, 0x80}
	deposit := &MailDeposit{MailFrom: hostile}
	decoded := &MailDeposit{}
	if err := proto.Unmarshal(testEncode(t, deposit), decoded); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded.MailFrom, hostile) {
		t.Errorf("mail_from came back as %x", decoded.MailFrom)
	}
	if _, err := proto.Marshal(&MailIngress{EhloName: string(hostile)}); err == nil {
		t.Error("ehlo_name took bytes that are not UTF-8, so MAIL-FORMAT.md's rule for it is wrong")
	}
}

// §22.6's every-body targets walk the registry, so reaching here with each message in that walk says they take it.
func TestBodyTargetsTakeEveryMailMessage(t *testing.T) {
	names := map[protoreflect.Name]bool{}
	for _, messageType := range testBodyTypes(t) {
		names[messageType.Descriptor().Name()] = true
	}
	for name := range testMailMessageFields {
		if !names[protoreflect.Name(name)] {
			t.Errorf("%s is no body the targets take", name)
		}
	}
}
