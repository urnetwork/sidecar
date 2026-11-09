//go:build !js

// record_body.go's rules: each body at its caps and one past them, Coverage's codes and nothing else in its lists, T's
// projection of a fixture run holding no title, path, branch or tool name, the V: table held to record.proto's
// comments, the route and publish builders' refusals, and a stored body's unknown field kept through a seal.

package sidecar

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// count strings of length bytes each.
func testRecordStrings(count int, length int) []string {
	values := []string{}
	for range count {
		values = append(values, strings.Repeat("s", length))
	}
	return values
}

// count byte strings of length bytes each.
func testRecordByteStrings(count int, length int) [][]byte {
	values := [][]byte{}
	for range count {
		values = append(values, bytes.Repeat([]byte{0x01}, length))
	}
	return values
}

// Each cap section 6.4 writes, at the cap and one past it.
func TestRecordBodyCapsAtAndPastEachLimit(t *testing.T) {
	cases := []struct {
		name string
		kind RecordKind
		at   proto.Message
		past proto.Message
	}{
		{"claim text", RecordKindClaim, &protocol.CoordinationBody{Text: strings.Repeat("a", 512)}, &protocol.CoordinationBody{Text: strings.Repeat("a", 513)}},
		{"note text", RecordKindNote, &protocol.CoordinationBody{Text: strings.Repeat("a", 1024)}, &protocol.CoordinationBody{Text: strings.Repeat("a", 1025)}},
		{"targets", RecordKindNote, &protocol.CoordinationBody{Targets: testRecordStrings(16, 8)}, &protocol.CoordinationBody{Targets: testRecordStrings(17, 8)}},
		{"check result", RecordKindCheck, &protocol.CoordinationBody{Result: 3}, &protocol.CoordinationBody{Result: 4}},
		{"title", RecordKindContext, &protocol.ContextBody{Stage: 1, Title: strings.Repeat("t", 120)}, &protocol.ContextBody{Stage: 1, Title: strings.Repeat("t", 121)}},
		{"session ids", RecordKindContext, &protocol.ContextBody{Stage: 1, SessionIds: testRecordStrings(4, 64)}, &protocol.ContextBody{Stage: 1, SessionIds: testRecordStrings(5, 64)}},
		{"session id length", RecordKindContext, &protocol.ContextBody{Stage: 2, SessionIds: testRecordStrings(1, 64)}, &protocol.ContextBody{Stage: 2, SessionIds: testRecordStrings(1, 65)}},
		{"agent label", RecordKindContext, &protocol.ContextBody{Stage: 1, AgentLabel: strings.Repeat("a", 64)}, &protocol.ContextBody{Stage: 1, AgentLabel: "Agent"}},
		{"branch", RecordKindContext, &protocol.ContextBody{Stage: 1, Branch: strings.Repeat("b", 128)}, &protocol.ContextBody{Stage: 1, Branch: strings.Repeat("b", 129)}},
		{"truncations", RecordKindContext, &protocol.ContextBody{Stage: 1, Truncations: testRecordStrings(16, 128)}, &protocol.ContextBody{Stage: 1, Truncations: testRecordStrings(17, 128)}},
		{"commits", RecordKindChange, &protocol.ChangeBody{Commits: testRecordStrings(64, 40)}, &protocol.ChangeBody{Commits: testRecordStrings(65, 40)}},
		{"changed paths", RecordKindChange, &protocol.ChangeBody{Paths: make([]*protocol.ChangedPath, 4096)}, &protocol.ChangeBody{Paths: make([]*protocol.ChangedPath, 4097)}},
		{"tool name", RecordKindPermission, &protocol.PermissionBody{ToolName: strings.Repeat("t", 64)}, &protocol.PermissionBody{ToolName: strings.Repeat("t", 65)}},
		{"read objects", RecordKindRead, &protocol.ReadBody{Purpose: 1, ObjectIds: testRecordByteStrings(64, 16)}, &protocol.ReadBody{Purpose: 1, ObjectIds: testRecordByteStrings(65, 16)}},
		{"read object length", RecordKindRead, &protocol.ReadBody{Purpose: 2, ObjectIds: testRecordByteStrings(1, 32)}, &protocol.ReadBody{Purpose: 2, ObjectIds: testRecordByteStrings(1, 20)}},
		{"erased entries", RecordKindErasure, &protocol.ErasureBody{ErasureId: NewId().Bytes(), Reason: 1, EntryIds: testRecordByteStrings(1024, 16)}, &protocol.ErasureBody{ErasureId: NewId().Bytes(), Reason: 1, EntryIds: testRecordByteStrings(1025, 16)}},
		{"inventory agents", RecordKindInventory, &protocol.InventoryBody{Agents: make([]*protocol.InventoryAgent, 64)}, &protocol.InventoryBody{Agents: make([]*protocol.InventoryAgent, 65)}},
		{"restored paths", RecordKindRestore, &protocol.RestoreBody{RestoredRunId: NewId().Bytes(), Paths: make([]*protocol.RestoredPath, 4096)}, &protocol.RestoreBody{RestoredRunId: NewId().Bytes(), Paths: make([]*protocol.RestoredPath, 4097)}},
		{"transcript", RecordKindTranscript, &protocol.TranscriptBody{Lines: make([]byte, 1024*1024)}, &protocol.TranscriptBody{Lines: make([]byte, 1024*1024+1)}},
		{"tool call", RecordKindToolCall, &protocol.ToolCallBody{Input: make([]byte, 512*1024), Output: make([]byte, 512*1024)}, &protocol.ToolCallBody{Input: make([]byte, 512*1024), Output: make([]byte, 512*1024+1)}},
		{"tool paths", RecordKindToolCall, &protocol.ToolCallBody{Paths: testRecordStrings(256, 4)}, &protocol.ToolCallBody{Paths: testRecordStrings(257, 4)}},
		{"hook payload", RecordKindHookEvent, &protocol.HookEventBody{Payload: make([]byte, 1024*1024)}, &protocol.HookEventBody{Payload: make([]byte, 1024*1024+1)}},
		{"blob", RecordKindBlob, &protocol.BlobBody{Content: make([]byte, 8*1024*1024)}, &protocol.BlobBody{Content: make([]byte, 8*1024*1024+1)}},
		{"copy", RecordKindCopy, &protocol.CopyBody{Entries: make([]*protocol.Opening, 64)}, &protocol.CopyBody{Entries: make([]*protocol.Opening, 65)}},
		{"membership evidence", RecordKindMembership, &protocol.MembershipBody{Event: 2, Evidence: 1, Assertion: []byte{1}}, &protocol.MembershipBody{Event: 2, Evidence: 1}},
		{"coverage gap", RecordKindCoverage, &protocol.Coverage{Gaps: []string{"no_vault:2"}}, &protocol.Coverage{Gaps: []string{"no_vault /home/a"}}},
	}
	for _, c := range cases {
		// nil slots in a repeated message field marshal as empty messages: fill them
		for _, body := range []proto.Message{c.at, c.past} {
			testRecordFillNils(body.ProtoReflect())
		}
		if err := RecordBodyValidate(c.kind, c.at); err != nil {
			t.Errorf("%s at its cap: %v", c.name, err)
		}
		if err := RecordBodyValidate(c.kind, c.past); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("%s past its cap: %v", c.name, err)
		}
	}
}

// Replaces nil entries of repeated message fields with empty messages, recursively.
func testRecordFillNils(message protoreflect.Message) {
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		if field.Message() != nil && field.IsList() {
			list := value.List()
			for i := 0; i < list.Len(); i += 1 {
				if !list.Get(i).Message().IsValid() {
					list.Set(i, protoreflect.ValueOfMessage(list.NewElement().Message()))
				}
			}
		}
		return true
	})
}

// Coverage's lists hold codes and counts alone: a gap is "code" once and "code:n" after, as RunStore counts it, and
// any other form, which could carry a path or text, is refused.
func TestRecordCoverageCodesCarryNoText(t *testing.T) {
	if gap, err := RecordCoverageGap(RecordCoverageGapSpoolDrop, 1); err != nil || gap != "spool_drop" {
		t.Errorf("one spool_drop: %q, %v", gap, err)
	}
	if gap, err := RecordCoverageGap(RecordCoverageGapNoVault, 3); err != nil || gap != "no_vault:3" {
		t.Errorf("three no_vault: %q, %v", gap, err)
	}
	gaps := addRunGap(addRunGap(nil, RecordCoverageGapRedaction), RecordCoverageGapRedaction)
	if code, count, ok := RecordCoverageGapParse(gaps[0]); !ok || code != "redaction" || count != 2 {
		t.Errorf("RunStore's count %q parsed as %s %d %t", gaps[0], code, count, ok)
	}
	for _, gap := range []string{"", "hook_failure:", "hook_failure:1", "hook_failure:02", "hook_failure:-3", "secret", "truncation:2:3", "oversize /tmp/x"} {
		if _, _, ok := RecordCoverageGapParse(gap); ok {
			t.Errorf("%q parsed as a gap", gap)
		}
	}
	if _, err := RecordCoverageGap("a path", 1); err == nil {
		t.Error("an unknown code made a gap")
	}
	if !RecordCoverageSourceKnown(RecordCoverageSourceFileEvents) || RecordCoverageSourceKnown("browser") {
		t.Error("the source codes are not section 6.4's")
	}
	coverage := &protocol.Coverage{Sources: []string{"mcp", "hooks"}, Gaps: []string{"hook_failure", "downtime:4"}, FirstSeq: 3, LastSeq: 9}
	if err := RecordBodyValidate(RecordKindCoverage, coverage); err != nil {
		t.Error(err)
	}
	coverage.Sources = append(coverage.Sources, "/home/agent")
	if err := RecordBodyValidate(RecordKindCoverage, coverage); err == nil {
		t.Error("a source that is no code passed")
	}
}

// T's projection is a function of the body: from a fixture run's vault bodies, holding a known title, path, branch,
// tool name and instruction file name, the projections hold none of them, keep their hashes, and leave the vault's
// bodies as they were; a private repo's project goes too.
func TestRecordProjectForTeamHoldsNoVaultField(t *testing.T) {
	secrets := []string{"Fix the payroll export", "src/payroll/export.go", "feature/payroll-v2", "WebFetchSecretTool", "CLAUDE.private.md", "payroll-svc"}
	hash := bytes.Repeat([]byte{0x5a}, 32)
	bodies := []struct {
		kind RecordKind
		body proto.Message
	}{
		{RecordKindContext, &protocol.ContextBody{
			Stage:            1,
			Harness:          "claude-code",
			Title:            secrets[0],
			Branch:           secrets[2],
			Project:          secrets[5],
			Truncations:      []string{secrets[1] + " cut at 1 MiB"},
			InstructionFiles: []*protocol.InstructionFile{{Scope: 3, Name: secrets[4], Sha256: hash, Size: 10}},
		}},
		{RecordKindChange, &protocol.ChangeBody{
			Project: secrets[5],
			Paths:   []*protocol.ChangedPath{{Path: secrets[1], BeforeSha256: hash, AfterSha256: hash, Attribution: 1, BlobEntryId: NewId().Bytes()}},
		}},
		{RecordKindPermission, &protocol.PermissionBody{Decision: 2, ToolName: secrets[3], ArgumentsSha256: hash}},
		{RecordKindRestore, &protocol.RestoreBody{RestoredRunId: NewId().Bytes(), Paths: []*protocol.RestoredPath{{Path: secrets[1], Result: "restored"}}}},
	}
	for _, item := range bodies {
		before, _ := proto.Marshal(item.body)
		projection, err := RecordProjectForTeam(item.kind, item.body, true)
		if err != nil {
			t.Fatalf("%s: %v", item.kind, err)
		}
		projected, err := proto.Marshal(projection)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range secrets {
			if bytes.Contains(projected, []byte(secret)) {
				t.Errorf("T's %s holds %q", item.kind, secret)
			}
		}
		if (item.kind == RecordKindContext || item.kind == RecordKindChange) && !bytes.Contains(projected, hash) {
			t.Errorf("T's %s dropped its hashes", item.kind)
		}
		after, _ := proto.Marshal(item.body)
		if !bytes.Equal(before, after) {
			t.Errorf("projecting %s changed the vault's body", item.kind)
		}
	}
	// a public repo's project stays, as the comment's condition says
	projection, err := RecordProjectForTeam(RecordKindContext, &protocol.ContextBody{Stage: 1, Project: "public-project"}, false)
	if err != nil || projection.(*protocol.ContextBody).GetProject() != "public-project" {
		t.Errorf("a public repo's project: %v", err)
	}
	for _, kind := range []RecordKind{RecordKindToolCall, RecordKindApproval, RecordKindBlob} {
		if _, err := RecordProjectForTeam(kind, &protocol.ToolCallBody{}, false); !errors.Is(err, ErrRecordProjectionNone) {
			t.Errorf("%s projected: %v", kind, err)
		}
	}
}

// The V: table is record.proto's: every field a comment there starts with V: is in it, and nothing else.
func TestRecordTeamStrippedFieldsAreRecordProtosVFields(t *testing.T) {
	file, err := os.Open("protocol/record.proto")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	messagePattern := regexp.MustCompile(`^message (\w+) \{`)
	fieldPattern := regexp.MustCompile(`^\s+(?:repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+;\s*//\s*V:`)
	found := map[protoreflect.FullName][]protoreflect.Name{}
	message := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if match := messagePattern.FindStringSubmatch(line); match != nil {
			message = match[1]
		}
		if match := fieldPattern.FindStringSubmatch(line); match != nil {
			fullName := protoreflect.FullName("urnetwork.sidecar." + message)
			found[fullName] = append(found[fullName], protoreflect.Name(match[1]))
		}
	}
	if len(found) != len(recordTeamStrippedFields) {
		t.Errorf("record.proto marks %d messages, the table %d", len(found), len(recordTeamStrippedFields))
	}
	for fullName, names := range found {
		if !slices.Equal(names, recordTeamStrippedFields[fullName]) {
			t.Errorf("%s: record.proto marks %v, the table %v", fullName, names, recordTeamStrippedFields[fullName])
		}
	}
}

// The route and publish builders refuse what their bodies do not take: a reason on an opened route, none on a closed
// one, an event or kind outside the comment's, and a publish with no host.
func TestRecordRouteAndPublishBuildersHoldTheirRules(t *testing.T) {
	approvalId := NewId()
	if _, err := NewRecordRouteBody(&RecordRouteArgs{Event: 1, Kind: 1, ApprovalId: &approvalId}); err != nil {
		t.Error(err)
	}
	if _, err := NewRecordRouteBody(&RecordRouteArgs{Event: 2, Kind: 3, Reason: 2}); err != nil {
		t.Error(err)
	}
	refused := []*RecordRouteArgs{{Event: 1, Kind: 1, Reason: 2}, {Event: 2, Kind: 1}, {Event: 3, Kind: 1}, {Event: 1, Kind: 5}, {Event: 1, Kind: 2, TargetPort: 70000}}
	for _, args := range refused {
		if _, err := NewRecordRouteBody(args); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("route %+v: %v", args, err)
		}
	}
	if _, err := NewRecordPublishBody(&RecordPublishArgs{Event: 1, Host: "app.example", Port: 443, Audience: 1, AppMode: 1}); err != nil {
		t.Error(err)
	}
	for _, args := range []*RecordPublishArgs{{Event: 1, Port: 443}, {Event: 2, Host: "app.example"}, {Event: 1, Host: "app.example", Reason: 1}} {
		if _, err := NewRecordPublishBody(args); !errors.Is(err, ErrRecordBodyOverCap) {
			t.Errorf("publish %+v: %v", args, err)
		}
	}
}

// A body stored with a field this build cannot name passes its caps and seals as it came, so a reader of a later
// version keeps what it wrote (§16.8's what freezes).
func TestRecordBodyUnknownFieldsSurviveASeal(t *testing.T) {
	body, err := proto.Marshal(&protocol.CoordinationBody{Text: "with a field from later"})
	if err != nil {
		t.Fatal(err)
	}
	body = protowire.AppendTag(body, 99, protowire.BytesType)
	body = protowire.AppendBytes(body, []byte("unknown"))
	if err := RecordBodyValidateStored(RecordKindNote, body); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	writerId := NewId()
	sealed, err := RecordSeal(&RecordSealEnv{Chain: NewRecordChainStore(testRecordStore(t), writerId), Sign: testRecordSigner(writerId, key)}, &RecordSealArgs{
		LogId:      NewId(),
		Kind:       RecordKindNote,
		Source:     RecordSourceAgent,
		TimeMillis: 1762387200000,
		Tainted:    true,
		StoredBody: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	header, err := sealed.Header()
	if err != nil {
		t.Fatal(err)
	}
	opened, err := RecordOpen(header, sealed.SealedBody, sealed.Key, sealed.Salt)
	if err != nil || !bytes.Equal(opened, body) {
		t.Fatalf("the stored body came back as other bytes: %v", err)
	}
}
