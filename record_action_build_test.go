// MCP-M3-02's builder and kind table (record_action_build.go, record_action_kinds.go): a field outside a kind's row
// refused, a required one missing refused, templates matched field by field with recipients a subset, an agent only
// raising risk, every server path held to its column, and the descriptor lint that keeps the table and record.proto
// in step.

package sidecar

import (
	"bytes"
	"errors"
	"slices"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// One full action of each kind the builder takes, as a daemon fills them: synthetic values only.
func testBuildableActions() map[string]*protocol.CanonicalAction {
	repoId := bytes.Repeat([]byte{0x41}, 16)
	return map[string]*protocol.CanonicalAction{
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

// Every buildable kind builds at version 1, its bytes parse as the verifiers take them, and the caller's message is
// left as it was.
func TestEveryBuildableKindBuilds(t *testing.T) {
	for name, action := range testBuildableActions() {
		before := proto.Clone(action)
		stored, err := NewCanonicalAction(action)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if stored.Action.GetVersion() != 1 {
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
			if row.allows(field.Number(), 1) {
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
			// a template may leave it empty: an empty field matches anything
			missing.Scope = true
			if _, err := NewCanonicalAction(missing); err != nil {
				t.Errorf("%s template without field %d: %v", name, number, err)
			}
		}
	}
}

// A kind with no row, and the kinds question record-m2-01-canonical-action-detail holds, build nothing.
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
		GrantDst:   []string{"sidecar:0102030405060708090a0b0c0d0e0f10:tcp:22"},
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
	long.Preview = string(bytes.Repeat([]byte{'p'}, canonicalActionPreviewMaxByteCount+1))
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

// The descriptor lint: every field CanonicalAction declares is claimed by a row, by every action, or by QD-064's
// leaving list, so a field record.proto adds cannot go unbuilt or unrefused; field 37 is filled only at version 2; and
// every row's fields exist.
func TestKindTableCoversTheDescriptor(t *testing.T) {
	fields := (&protocol.CanonicalAction{}).ProtoReflect().Descriptor().Fields()
	claimed := map[protoreflect.FieldNumber]bool{}
	for _, number := range canonicalActionCommonFields {
		claimed[number] = true
	}
	for _, number := range canonicalActionLeavingFields {
		claimed[number] = true
	}
	for _, row := range canonicalActionKindRows {
		for _, number := range slices.Concat(row.Required, row.Optional, row.Version2, row.Server) {
			if fields.ByNumber(number) == nil {
				t.Errorf("kind %d names field %d, which CanonicalAction lacks", row.Kind, number)
			}
			if slices.Contains(canonicalActionLeavingFields, number) {
				t.Errorf("kind %d fills field %d, which leaves CanonicalAction", row.Kind, number)
			}
			claimed[number] = true
		}
		if slices.Contains(slices.Concat(row.Required, row.Optional), canonicalActionFieldVersioning) {
			t.Errorf("kind %d fills field 37 outside version 2", row.Kind)
		}
		if 0 < len(row.Version2) && !slices.Contains(row.Versions, 2) {
			t.Errorf("kind %d has version-2 fields and no version 2", row.Kind)
		}
		// a held kind's builder fields and its server column disagree, which is what its question asks: a forward's
		// grant shows 8, 10, 11, 28 and 29 to api (QD-064) while MCP.md's row fills 26 and 27
		for _, number := range row.Server {
			if row.Held == "" && !row.allows(number, row.Versions[0]) && !slices.Contains(row.Version2, number) {
				t.Errorf("kind %d lets a server see field %d, which it never fills", row.Kind, number)
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
