//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"encoding/json"
	"testing"
	"time"
)

// An entry's JSON, failing the test where it does not marshal.
func harnessEntryJson(t *testing.T, entry *HarnessPiEntry) string {
	t.Helper()
	encoded, err := entry.Json()
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// A golden timestamp.
func harnessEntryTime(t *testing.T, timestamp string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// Every v3 entry of PiG's fixtures reads and writes back byte for byte, Pi's types this build has no constructor for
// (label, context_edit) and every member included; the Harness's constructors build each type it writes byte for byte;
// and §24.4's link reads and writes as its golden.
func TestHarnessPiEntriesRoundTrip(t *testing.T) {
	lines := harnessGoldenLines(t, "testdata/harness/pi-1.5.0/entries.jsonl")
	types := map[HarnessPiEntryType]bool{}
	roles := map[HarnessPiRole]bool{}
	for i, line := range lines {
		entry := &HarnessPiEntry{}
		if err := json.Unmarshal(line, entry); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if got := harnessEntryJson(t, entry); got != string(line) {
			t.Errorf("line %d read back:\n got %s\nwant %s", i+1, got, line)
		}
		types[entry.Type()] = true
		if message := entry.Message(); message != nil {
			roles[message.Role()] = true
		}
	}
	for _, entryType := range []HarnessPiEntryType{HarnessPiEntrySession, HarnessPiEntryMessage, HarnessPiEntryModelChange,
		HarnessPiEntryThinkingLevelChange, HarnessPiEntryUsage, HarnessPiEntryCompaction, HarnessPiEntryBranchSummary,
		HarnessPiEntryCustom, HarnessPiEntryCustomMessage} {
		if !types[entryType] {
			t.Errorf("no golden %s entry", entryType)
		}
	}
	for _, role := range []HarnessPiRole{HarnessPiRoleSystem, HarnessPiRoleUser, HarnessPiRoleAssistant,
		HarnessPiRoleToolResult, HarnessPiRoleBashExecution} {
		if !roles[role] {
			t.Errorf("no golden %s message", role)
		}
	}

	built := map[int]*HarnessPiEntry{
		1: NewHarnessPiSessionHeader("0199a000-0000-7000-8000-000000000001", harnessEntryTime(t, "2026-01-01T00:00:00.000Z"), "/registry-fixture", ""),
		2: NewHarnessPiModelChangeEntry("e0000001", "", harnessEntryTime(t, "2026-01-01T00:00:01.000Z"),
			&HarnessPiModelChange{Provider: "test-faux", ModelId: "faux-1"}),
		3:  NewHarnessPiThinkingLevelChangeEntry("e0000002", "e0000001", harnessEntryTime(t, "2026-01-01T00:00:02.000Z"), "low"),
		8:  NewHarnessPiBranchSummaryEntry("e0000007", "e0000005", harnessEntryTime(t, "2026-01-01T00:00:07.000Z"), "e0000006", "abandoned summary"),
		9:  NewHarnessPiCustomMessageEntry("e0000008", "e0000007", harnessEntryTime(t, "2026-01-01T00:00:08.000Z"), "note", "custom context", true),
		10: NewHarnessPiCompactionEntry("e0000009", "e0000008", harnessEntryTime(t, "2026-01-01T00:00:09.000Z"), "compacted", "e0000008", 100),
		13: NewHarnessPiCustomEntry("e0000012", "e0000011", harnessEntryTime(t, "2026-01-01T00:00:12.000Z"), "state", json.RawMessage(`{"k":1}`)),
		18: NewHarnessPiMessageEntry("c3d4e5f6", "b2c3d4e5", harnessEntryTime(t, "2024-12-03T14:00:03.000Z"),
			NewHarnessPiToolResultMessage("call_123", "bash", []*HarnessPiBlock{NewHarnessPiTextBlock("output")}, nil, false, 1733234403000)),
		19: NewHarnessPiUsageEntry("f6g7h8i9", "e5f6g7h8", harnessEntryTime(t, "2024-12-03T14:08:00.000Z"), "cache_warm", "anthropic",
			"claude-sonnet-4-5", &HarnessPiUsage{CacheRead: 50000, TotalTokens: 50000,
				Cost: HarnessPiUsageCost{CacheRead: 0.015, Total: 0.015}}),
	}
	for line, entry := range built {
		if got := harnessEntryJson(t, entry); got != string(lines[line-1]) {
			t.Errorf("line %d built:\n got %s\nwant %s", line, got, lines[line-1])
		}
	}

	// the accessors read what they name
	compaction := &HarnessPiEntry{}
	json.Unmarshal(lines[9], compaction)
	summary, firstKept, tokensBefore, ok := compaction.Compaction()
	if !ok || summary != "compacted" || firstKept != "e0000008" || tokensBefore != 100 {
		t.Fatalf("compaction: %q %q %d %v", summary, firstKept, tokensBefore, ok)
	}
	root := &HarnessPiEntry{}
	json.Unmarshal(lines[1], root)
	if _, hasParent := root.ParentId(); hasParent || root.Id() != "e0000001" {
		t.Fatalf("a root reads a parent")
	}
	thinking := &HarnessPiEntry{}
	json.Unmarshal(lines[20], thinking)
	blocks := thinking.Message().Blocks()
	if len(blocks) != 5 || blocks[0].Type() != HarnessPiBlockThinking || blocks[2].Text() != "Resumed answer charlie" {
		t.Fatalf("thinking blocks: %d", len(blocks))
	}

	// §24.4's link: in the parent's tree to its child, and the child's root back to its parent
	agentId, _ := ParseId("019a0000-0000-7000-8000-000000000001")
	childId, _ := ParseId("019a0000-0000-7000-8000-000000000002")
	childRunId, _ := ParseId("019a0000-0000-7000-8000-000000000003")
	parentRunId, _ := ParseId("019a0000-0000-7000-8000-000000000004")
	at := harnessEntryTime(t, "2026-11-24T12:00:00.000Z")
	links := []*HarnessPiEntry{
		NewHarnessPiLinkEntry("a1b2c3d4", "9f8e7d6c", at, &HarnessPiLink{To: HarnessPiLinkChild, AgentId: childId, RunId: childRunId, Place: "local"}),
		NewHarnessPiLinkEntry("0badc0de", "", at, &HarnessPiLink{To: HarnessPiLinkParent, AgentId: agentId, RunId: parentRunId, Place: "local", NodeId: "a1b2c3d4"}),
	}
	linkLines := harnessGoldenLines(t, "testdata/harness/events/link.jsonl")
	for i, entry := range links {
		if got := harnessEntryJson(t, entry); got != string(linkLines[i]) {
			t.Errorf("link %d:\n got %s\nwant %s", i+1, got, linkLines[i])
		}
		read := &HarnessPiEntry{}
		if err := json.Unmarshal(linkLines[i], read); err != nil {
			t.Fatal(err)
		}
		if got := harnessEntryJson(t, read); got != string(linkLines[i]) {
			t.Errorf("link %d read back: %s", i+1, got)
		}
	}
	back := &HarnessPiEntry{}
	json.Unmarshal(linkLines[1], back)
	link := back.Link()
	if link == nil || link.To != HarnessPiLinkParent || link.RunId != parentRunId || link.NodeId != "a1b2c3d4" {
		t.Fatalf("link back: %+v", link)
	}
	if _, hasParent := back.ParentId(); hasParent {
		t.Fatal("a child's link back is not a root")
	}

	// an id is 8 hex characters, and a fresh one each time
	if first, second := NewHarnessPiEntryId(), NewHarnessPiEntryId(); len(first) != 8 || first == second {
		t.Fatalf("ids %q %q", first, second)
	}
}
