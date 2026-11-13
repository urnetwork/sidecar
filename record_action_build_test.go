// MCP-M3-02's builder and kind table (record_action_build.go, record_action_kinds.go): a field outside a kind's row
// refused, a required one missing refused, templates matched field by field with recipients a subset, an agent only
// raising risk, every server path held to its column, and the descriptor lint that keeps the table and record.proto
// in step. The kinds QD-740 opened build here too: a publish, a listen and an expose at version 1 with no local port,
// weight or ALPN, and a forward at version 4 with its port sealed.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The sidecar a test's forward dials, as grant_dst names it.
const testActionTargetDst = "sidecar:5152535455565758595a5b5c5d5e5f60"

// What a test seals an action's detail to. Which values production binds is question
// canonical-action-detail-seal-context; these are synthetic.
func testActionDetailContext() *ConfigSealContext {
	return &ConfigSealContext{
		SignedType: bridge.SignedType_SIGNED_GRANT_ACTIVATE,
		NetworkId:  testConfigId("network").Bytes(),
		Nonce:      bytes.Repeat([]byte{0x38}, configNonceByteCount),
	}
}

// The key generation a test's details are sealed under.
const testActionDetailGeneration = 3

// detail as an action's sealed_detail, under the test key and a fixed nonce, so a vector's bytes hold.
func testSealActionDetail(detail *protocol.CanonicalActionDetail) []byte {
	sealed, err := SealConfigBody(testConfigSealKey(testActionDetailGeneration), testActionDetailContext(), detail,
		bytes.NewReader(bytes.Repeat([]byte{0x24}, 24)))
	if err != nil {
		panic(err)
	}
	return sealed
}

// What the test's forward seals: its target's port, and the port's text in §8.4's grammar.
func testForwardDetail() *protocol.CanonicalActionDetail {
	return &protocol.CanonicalActionDetail{TargetPort: 8443, GrantDst: []string{testActionTargetDst + ":tcp:8443"}}
}

// One full action of each kind the builder takes, as a daemon fills them: synthetic values only.
func testBuildableActions() map[string]*protocol.CanonicalAction {
	repoId := bytes.Repeat([]byte{0x41}, 16)
	ruleId := bytes.Repeat([]byte{0x46}, 16)
	subject := bytes.Repeat([]byte{0x47}, 16)
	return map[string]*protocol.CanonicalAction{
		"tls_publish": {
			Kind:           uint32(SidecarActionPublish),
			Host:           "blog.example",
			Port:           443,
			Audience:       uint32(protocol.AclAudience_ACL_AUDIENCE_LINK),
			AppMode:        uint32(protocol.AclAppMode_ACL_APP_MODE_RAW),
			ExpiresMillis:  1762387200000,
			GrantDst:       []string{"dns:blog.example"},
			GrantAllow:     []string{"publish"},
			RuleId:         ruleId,
			Subject:        subject,
			LinkSpkiSha256: bytes.Repeat([]byte{0x48}, 32),
		},
		"socket_listen": {
			Kind:          uint32(SidecarActionListen),
			SocketName:    "tls/443/blog",
			ExpiresMillis: 1762387200000,
			GrantDst:      []string{"sock:tls/443/blog"},
			GrantAllow:    []string{"listen"},
			RuleId:        ruleId,
			Subject:       subject,
		},
		"bridge_forward": {
			Kind:          uint32(SidecarActionForward),
			ExpiresMillis: 1762387200000,
			GrantDst:      []string{testActionTargetDst},
			GrantAllow:    []string{"dial"},
			RuleId:        ruleId,
			Subject:       subject,
			SealedDetail:  testSealActionDetail(testForwardDetail()),
		},
		"bridge_expose": {
			Kind:            uint32(SidecarActionExpose),
			ExpiresMillis:   1762387200000,
			Cidrs:           []string{"192.0.2.0/24"},
			TargetSidecarId: bytes.Repeat([]byte{0x49}, 16),
			TargetPort:      8080,
		},
		"mail_send": {
			Kind:       uint32(SidecarActionMail),
			Recipients: []string{"alice@example.com", "bob@example.net"},
			BodySha256: bytes.Repeat([]byte{0x42}, 32),
			Preview:    "the quarterly numbers, as attached",
			Alias:      "ops",
		},
		"alias_create": {
			Kind:       uint32(SidecarActionAliasCreate),
			Alias:      "billing",
			AliasGroup: "finance",
		},
		"alias_delete": {
			Kind:        uint32(SidecarActionAliasDelete),
			Alias:       "billing",
			RepoId:      repoId,
			Path:        "addr/billing",
			BaseVersion: 4,
		},
		"agent_config_write": {
			Kind:          uint32(SidecarActionAgentConfigWrite),
			RepoId:        repoId,
			Path:          "CLAUDE.md",
			ContentSha256: bytes.Repeat([]byte{0x43}, 32),
			BaseVersion:   7,
		},
		"agent_config_delete": {
			Kind:        uint32(SidecarActionAgentConfigDelete),
			RepoId:      repoId,
			Path:        ".mcp.json",
			BaseVersion: 2,
		},
		"dns_set": {
			Kind:          uint32(SidecarActionDnsSet),
			ExpiresMillis: 1762387200000,
			DnsName:       "www",
			DnsType:       "A",
			DnsValue:      "192.0.2.10",
			DnsTtl:        300,
		},
		"dns_delete": {
			Kind:    uint32(SidecarActionDnsDelete),
			DnsName: "old",
			DnsType: "AAAA",
		},
		"restore": {
			Kind:             uint32(SidecarActionRestore),
			RestoreRunId:     bytes.Repeat([]byte{0x44}, 16),
			RestorePaths:     []string{"scripts/deploy.sh"},
			RestorePreviewId: bytes.Repeat([]byte{0x45}, 32),
		},
		"mail_tls_unauthenticated": {
			Kind:          uint32(SidecarActionMailTlsUnauthenticated),
			Host:          "mail.example",
			ExpiresMillis: 1762387200000,
		},
	}
}

// Builds one action, which must take.
func buildTestAction(t *testing.T, action *protocol.CanonicalAction) *StoredCanonicalAction {
	t.Helper()
	stored, err := NewCanonicalAction(action)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

// Every buildable kind builds at its row's version, 1 but for a forward's sealed grant at 4, its bytes parse as the
// verifiers take them, and the caller's message is left as it was.
func TestEveryBuildableKindBuilds(t *testing.T) {
	for name, action := range testBuildableActions() {
		before := proto.Clone(action)
		stored, err := NewCanonicalAction(action)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want := uint32(1)
		if name == "bridge_forward" {
			want = canonicalActionVersionSealedGrant
		}
		if stored.Action.GetVersion() != want {
			t.Errorf("%s: version %d", name, stored.Action.GetVersion())
		}
		if _, err := ParseStoredCanonicalAction(stored.Bytes); err != nil {
			t.Errorf("%s: the stored bytes do not parse: %v", name, err)
		}
		if !proto.Equal(before, action) {
			t.Errorf("%s: the builder changed the caller's message", name)
		}
		again := buildTestAction(t, action)
		if !bytes.Equal(again.Bytes, stored.Bytes) {
			t.Errorf("%s: two builds differ", name)
		}
	}
}

func TestFieldOutsideKindRefused(t *testing.T) {
	for name, action := range testBuildableActions() {
		row, _ := CanonicalActionFields(SidecarActionKind(action.GetKind()))
		message := action.ProtoReflect()
		fields := message.Descriptor().Fields()
		for i := 0; i < fields.Len(); i += 1 {
			field := fields.Get(i)
			if row.allows(field.Number(), row.Versions[0]) {
				continue
			}
			widened := proto.Clone(action).(*protocol.CanonicalAction)
			value := widened.ProtoReflect().NewField(field)
			switch {
			case field.IsList():
				value.List().Append(protoreflect.ValueOfString("synthetic"))
			case field.Kind() == protoreflect.StringKind:
				value = protoreflect.ValueOfString("synthetic")
			case field.Kind() == protoreflect.BytesKind:
				value = protoreflect.ValueOfBytes(bytes.Repeat([]byte{0x01}, 16))
			case field.Kind() == protoreflect.BoolKind:
				value = protoreflect.ValueOfBool(true)
			case field.Kind() == protoreflect.Int32Kind:
				value = protoreflect.ValueOfInt32(1)
			case field.Kind() == protoreflect.Int64Kind:
				value = protoreflect.ValueOfInt64(1)
			case field.Kind() == protoreflect.Uint64Kind:
				value = protoreflect.ValueOfUint64(1)
			default:
				value = protoreflect.ValueOfUint32(1)
			}
			widened.ProtoReflect().Set(field, value)
			if _, err := NewCanonicalAction(widened); !errors.Is(err, ErrCanonicalActionInvalid) &&
				!errors.Is(err, ErrCanonicalActionVersionUnknown) {
				t.Errorf("%s with field %d answered %v", name, field.Number(), err)
			}
		}
	}
}

func TestRequiredFieldMissingRefused(t *testing.T) {
	for name, action := range testBuildableActions() {
		row, _ := CanonicalActionFields(SidecarActionKind(action.GetKind()))
		for _, number := range row.Required {
			missing := proto.Clone(action).(*protocol.CanonicalAction)
			missing.ProtoReflect().Clear(missing.ProtoReflect().Descriptor().Fields().ByNumber(number))
			if _, err := NewCanonicalAction(missing); !errors.Is(err, ErrCanonicalActionInvalid) {
				t.Errorf("%s without field %d answered %v", name, number, err)
			}
			// a template may leave it empty: an empty field matches anything, unless the row has a template fill it
			missing.Scope = true
			_, err := NewCanonicalAction(missing)
			if slices.Contains(row.TemplateRequired, number) {
				if !errors.Is(err, ErrCanonicalActionInvalid) {
					t.Errorf("%s template without field %d answered %v", name, number, err)
				}
			} else if err != nil {
				t.Errorf("%s template without field %d: %v", name, number, err)
			}
		}
	}
}

// QD-729's row: mail_tls_unauthenticated's host is the recipient domain in its one form, so a trailing dot, a
// capital, or anything that is not dot-separated LDH labels is refused rather than folded; the expiry is optional; a
// template names its domain too, so none matches every domain; and no server path takes the kind.
func TestTlsAllowanceHostIsHeldToItsForm(t *testing.T) {
	for _, host := range []string{
		"mail.example.", "Mail.example", "MAIL.EXAMPLE", "mail.Example", "mail..example", ".mail.example", "-mail.example",
		"mail-.example", "mail example", "mail.example/25", "user@mail.example", "mail.exämple", "mail.example\n", ".",
	} {
		action := &protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: host}
		if _, err := NewCanonicalAction(action); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("host %q answered %v", host, err)
		}
		action.Scope = true
		if _, err := NewCanonicalAction(action); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a template of host %q answered %v", host, err)
		}
	}
	for _, host := range []string{"mail.example", "example", "a-b.c1.example", "xn--mnchen-3ya.example"} {
		stored, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: host})
		if err != nil {
			t.Errorf("host %q: %v", host, err)
			continue
		}
		if stored.Action.GetHost() != host || stored.Action.GetExpiresMillis() != 0 || stored.Action.GetVersion() != 1 {
			t.Errorf("host %q built %+v", host, stored.Action)
		}
		if err := CheckCanonicalActionForServer(stored); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("a server path took the allowance: %v", err)
		}
	}
	if _, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Scope: true}); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a template of every domain answered %v", err)
	}
	// the error names no domain, since a log may carry it (I-13)
	_, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "Secret.example"})
	if err == nil || strings.Contains(strings.ToLower(err.Error()), "secret.example") {
		t.Errorf("the refusal: %v", err)
	}
	// two domains are two actions, and one domain's two expiries are two
	first := buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "mail.example"})
	other := buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "other.example"})
	ending := buildTestAction(t, &protocol.CanonicalAction{Kind: uint32(SidecarActionMailTlsUnauthenticated), Host: "mail.example", ExpiresMillis: 1762387200000})
	if bytes.Equal(first.Bytes, other.Bytes) || bytes.Equal(first.Bytes, ending.Bytes) {
		t.Error("two allowances share their bytes")
	}
}

// A kind with no row builds nothing, and neither does a publish, a listen, a forward or an expose that fills none of
// its row.
func TestUnbuiltKindsRefused(t *testing.T) {
	for _, kind := range []SidecarActionKind{
		SidecarActionUnspecified, SidecarActionEgressChange, SidecarActionInvite, SidecarActionShare,
		SidecarActionPayment, SidecarActionPublish, SidecarActionListen, SidecarActionForward, SidecarActionExpose,
		SidecarActionKind(99),
	} {
		if _, err := NewCanonicalAction(&protocol.CanonicalAction{Kind: uint32(kind)}); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("kind %d answered %v", kind, err)
		}
	}
	// access_request's version 3 is unknown until MCP-M6-01
	action := &protocol.CanonicalAction{
		Kind:       uint32(SidecarActionAccessRequest),
		GrantDst:   []string{"sidecar:0102030405060708090a0b0c0d0e0f10"},
		GrantAllow: []string{"dial"},
	}
	if _, err := NewCanonicalAction(action); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("an access request answered %v", err)
	}
}

// Versions a kind does not take, and fields at the wrong size, are refused.
func TestBuilderHoldsVersionsAndSizes(t *testing.T) {
	actions := testBuildableActions()
	wrongVersion := proto.Clone(actions["dns_set"]).(*protocol.CanonicalAction)
	wrongVersion.Version = 3
	if _, err := NewCanonicalAction(wrongVersion); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("dns_set at version 3 answered %v", err)
	}
	// format 2's versioning waits on version 2, which this build does not know yet
	versioned := proto.Clone(actions["agent_config_write"]).(*protocol.CanonicalAction)
	versioned.Version = 2
	versioned.Versioning = 1
	if _, err := NewCanonicalAction(versioned); !errors.Is(err, ErrCanonicalActionVersionUnknown) {
		t.Errorf("version 2 answered %v", err)
	}
	unversioned := proto.Clone(actions["agent_config_write"]).(*protocol.CanonicalAction)
	unversioned.Versioning = 1
	if _, err := NewCanonicalAction(unversioned); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("field 37 at version 1 answered %v", err)
	}
	short := proto.Clone(actions["mail_send"]).(*protocol.CanonicalAction)
	short.BodySha256 = short.BodySha256[:31]
	if _, err := NewCanonicalAction(short); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a short body hash answered %v", err)
	}
	long := proto.Clone(actions["mail_send"]).(*protocol.CanonicalAction)
	long.Preview = string(bytes.Repeat([]byte{'p'}, DefaultCanonicalActionSettings().PreviewMaxByteCount+1))
	if _, err := NewCanonicalAction(long); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a long preview answered %v", err)
	}
	empty := proto.Clone(actions["mail_send"]).(*protocol.CanonicalAction)
	empty.Recipients = append(empty.Recipients, "")
	if _, err := NewCanonicalAction(empty); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("an empty recipient answered %v", err)
	}
}

// A template of mail to three recipients matches a use to any of them, and nothing else.
func TestTemplateRecipientsSubset(t *testing.T) {
	template := proto.Clone(testBuildableActions()["mail_send"]).(*protocol.CanonicalAction)
	template.Scope = true
	template.Recipients = []string{"alice@example.com", "bob@example.net", "carol@example.org"}
	template.BodySha256 = nil
	template.Preview = ""
	storedTemplate := buildTestAction(t, template)
	use := proto.Clone(testBuildableActions()["mail_send"]).(*protocol.CanonicalAction)
	use.Recipients = []string{"carol@example.org", "alice@example.com"}
	if !ActionMatchesTemplate(storedTemplate, buildTestAction(t, use)) {
		t.Error("a use to a subset does not match")
	}
	use.Recipients = []string{"alice@example.com", "mallory@example.com"}
	if ActionMatchesTemplate(storedTemplate, buildTestAction(t, use)) {
		t.Error("a use to an outside recipient matches")
	}
}

func TestTemplateFieldMismatchRefused(t *testing.T) {
	template := proto.Clone(testBuildableActions()["dns_set"]).(*protocol.CanonicalAction)
	template.Scope = true
	template.DnsValue = ""
	template.ExpiresMillis = 0
	template.DnsTtl = 0
	storedTemplate := buildTestAction(t, template)
	use := proto.Clone(testBuildableActions()["dns_set"]).(*protocol.CanonicalAction)
	if !ActionMatchesTemplate(storedTemplate, buildTestAction(t, use)) {
		t.Error("a use within the template does not match")
	}
	use.DnsName = "api"
	if ActionMatchesTemplate(storedTemplate, buildTestAction(t, use)) {
		t.Error("a use naming another record matches")
	}
	// a template's own scope must be set, a use's not, and kinds must agree
	plain := buildTestAction(t, testBuildableActions()["dns_set"])
	if ActionMatchesTemplate(plain, plain) {
		t.Error("an action that is no template matches as one")
	}
	if ActionMatchesTemplate(storedTemplate, storedTemplate) {
		t.Error("a template matches as a use")
	}
	other := buildTestAction(t, testBuildableActions()["dns_delete"])
	if ActionMatchesTemplate(storedTemplate, other) {
		t.Error("another kind matches")
	}
}

func TestAgentMayOnlyRaiseRisk(t *testing.T) {
	action := buildTestAction(t, testBuildableActions()["dns_set"])
	for _, c := range []struct {
		policy     SidecarRisk
		agentAsked SidecarRisk
		want       SidecarRisk
	}{
		{policy: SidecarRiskNormal, agentAsked: SidecarRiskNormal, want: SidecarRiskNormal},
		{policy: SidecarRiskNormal, agentAsked: SidecarRiskHigh, want: SidecarRiskHigh},
		{policy: SidecarRiskHigh, agentAsked: SidecarRiskNormal, want: SidecarRiskHigh},
		{policy: SidecarRiskHigh, agentAsked: SidecarRiskUnspecified, want: SidecarRiskHigh},
		{policy: SidecarRiskUnspecified, agentAsked: SidecarRiskUnspecified, want: SidecarRiskNormal},
		{policy: SidecarRiskNormal, agentAsked: SidecarRisk(7), want: SidecarRiskNormal},
	} {
		if got := CanonicalActionRisk(action, c.policy, c.agentAsked); got != c.want {
			t.Errorf("policy %d, agent %d: %d, want %d", c.policy, c.agentAsked, got, c.want)
		}
	}
}

// Each server path admits its column and nothing more: a dns action's fields pass, a field outside the column and a
// kind no server path takes are refused.
func TestServerPathsHoldToTheirColumns(t *testing.T) {
	actions := testBuildableActions()
	if err := CheckCanonicalActionForServer(buildTestAction(t, actions["dns_set"])); err != nil {
		t.Error(err)
	}
	for _, name := range []string{"mail_send", "agent_config_write", "restore", "alias_create"} {
		if err := CheckCanonicalActionForServer(buildTestAction(t, actions[name])); !errors.Is(err, ErrCanonicalActionInvalid) {
			t.Errorf("%s on a server path answered %v", name, err)
		}
	}
	// an action a gate takes that carries a field outside its column, parsed straight from bytes
	widened := proto.Clone(actions["dns_set"]).(*protocol.CanonicalAction)
	widened.Version = 1
	widened.Preview = "a preview no gate may see"
	stored, err := proto.MarshalOptions{Deterministic: true}.Marshal(widened)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseStoredCanonicalAction(stored)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCanonicalActionForServer(parsed); !errors.Is(err, ErrCanonicalActionInvalid) {
		t.Errorf("a dns action with a preview answered %v", err)
	}
}

// The descriptor lint: every field CanonicalAction declares is claimed by a row or by every action, so a field
// record.proto adds cannot go unbuilt or unrefused; local_port, weight and alpn are gone from it, their numbers
// reserved, and are ApprovalRequest's 14, 15 and 16, which a row's request column names (QD-740); field 37 is filled
// only at version 2 and field 38 only at the versions that seal a detail; and every row's fields exist.
func TestKindTableCoversTheDescriptor(t *testing.T) {
	descriptor := (&protocol.CanonicalAction{}).ProtoReflect().Descriptor()
	fields := descriptor.Fields()
	claimed := map[protoreflect.FieldNumber]bool{}
	for _, number := range canonicalActionCommonFields {
		claimed[number] = true
	}
	for _, number := range []protoreflect.FieldNumber{24, 25, 34} {
		if fields.ByNumber(number) != nil || !descriptor.ReservedRanges().Has(number) {
			t.Errorf("field %d left CanonicalAction, and record.proto does not reserve it", number)
		}
	}
	requestFields := (&protocol.ApprovalRequest{}).ProtoReflect().Descriptor().Fields()
	for number, name := range map[protoreflect.FieldNumber]protoreflect.Name{
		approvalRequestFieldLocalPort: "local_port", approvalRequestFieldWeight: "weight", approvalRequestFieldAlpn: "alpn",
	} {
		if field := requestFields.ByNumber(number); field == nil || field.Name() != name {
			t.Errorf("ApprovalRequest's field %d is not %s", number, name)
		}
		if !slices.Contains(approvalRequestDetailFields, number) {
			t.Errorf("ApprovalRequest's field %d is no detail field", number)
		}
	}
	for _, row := range canonicalActionKindRows {
		for _, number := range slices.Concat(row.Required, row.Optional, row.Version2, row.Server, row.TemplateRequired) {
			if fields.ByNumber(number) == nil {
				t.Errorf("kind %d names field %d, which CanonicalAction lacks", row.Kind, number)
			}
			claimed[number] = true
		}
		for _, number := range row.Request {
			if !slices.Contains(approvalRequestDetailFields, number) {
				t.Errorf("kind %d's request binds field %d, which is none of local_port, weight and alpn", row.Kind, number)
			}
		}
		if slices.Contains(slices.Concat(row.Required, row.Optional), canonicalActionFieldVersioning) {
			t.Errorf("kind %d fills field 37 outside version 2", row.Kind)
		}
		if 0 < len(row.Version2) && !slices.Contains(row.Versions, 2) {
			t.Errorf("kind %d has version-2 fields and no version 2", row.Kind)
		}
		sealedVersion := slices.Contains(row.Versions, canonicalActionVersionAccessRequest) || slices.Contains(row.Versions, canonicalActionVersionSealedGrant)
		if slices.Contains(slices.Concat(row.Required, row.Optional), canonicalActionFieldSealedDetail) != sealedVersion {
			t.Errorf("kind %d fills field 38 outside versions 3 and 4, or takes one of them without it", row.Kind)
		}
		for _, number := range slices.Concat(row.Server, row.TemplateRequired) {
			if !row.allows(number, row.Versions[0]) && !slices.Contains(row.Version2, number) {
				t.Errorf("kind %d lets a server see, or has a template fill, field %d, which it never fills", row.Kind, number)
			}
		}
		// no server path sees a prefix or a target's port in the clear (owner decision 220)
		for _, number := range []protoreflect.FieldNumber{9, 27} {
			if slices.Contains(row.Server, number) {
				t.Errorf("kind %d lets a server see field %d", row.Kind, number)
			}
		}
	}
	for i := 0; i < fields.Len(); i += 1 {
		if number := fields.Get(i).Number(); !claimed[number] {
			t.Errorf("field %d is claimed by no row", number)
		}
	}
	// the rows are SidecarActionKind's, each once, in order
	kinds := []SidecarActionKind{}
	for _, row := range canonicalActionKindRows {
		kinds = append(kinds, row.Kind)
	}
	if !slices.IsSorted(kinds) || len(slices.Compact(slices.Clone(kinds))) != len(kinds) {
		t.Errorf("rows out of order or repeated: %v", kinds)
	}
}
