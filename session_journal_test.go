//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.4, §24.5 and §24.16's journal cases (CTXH-M11-03) on sidecartest's streams through the record's
// writer: a corpus run journaled whole, each node passing the reader's format checks; the daemon killed between the
// journal and the call, and between a response and its tool, every call made having its context and a lost response
// a coverage gap; a repeated item a same_as node, and no bytes across runs; and every node carrying its run's marks
// and taint. External, as record_writer_test.go: sidecartest imports the root.

package sidecar_test

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A network's journal over one device's record, its reader reading what the device pushed.
type testSessionJournalWorld struct {
	t       *testing.T
	world   *testRecordWorld
	device  *testRecordDevice
	record  *sidecar.SidecarRecord
	store   sidecar.SidecarStore
	journal *sidecar.SessionJournal
	ingest  *sidecar.SidecarIngestSettings
}

func newTestSessionJournalWorld(t *testing.T, settings *sidecar.SessionSettings, ingest *sidecar.SidecarIngestSettings) *testSessionJournalWorld {
	t.Helper()
	world := newTestRecordWorld(t)
	device := world.device(true)
	files := sidecartest.NewFakeStore()
	store, err := files.Root().Directory("session", "session")
	if err != nil {
		t.Fatal(err)
	}
	if ingest == nil {
		ingest = sidecar.DefaultSidecarSettings().Ingest
	}
	self := &testSessionJournalWorld{t: t, world: world, device: device, store: store, ingest: ingest}
	self.open(settings)
	return self
}

// A new process's record and journal, over what the device's stores hold.
func (self *testSessionJournalWorld) open(settings *sidecar.SessionSettings) {
	self.t.Helper()
	self.record = self.device.open()
	redactor, err := sidecar.NewRedactor(bytes.NewReader(bytes.Repeat([]byte{0x52}, 64)))
	if err != nil {
		self.t.Fatal(err)
	}
	self.journal, err = sidecar.NewSessionJournal(&sidecar.SessionJournalArgs{
		Record: self.record, Store: self.store, Redactor: redactor, Settings: settings, Ingest: self.ingest, Clock: self.world.clock,
		Gap: func(runId sidecar.Id, code string) {
			self.device.stateLock.Lock()
			defer self.device.stateLock.Unlock()
			self.device.gaps = append(self.device.gaps, runId.String()+" "+code)
		},
	})
	if err != nil {
		self.t.Fatal(err)
	}
}

// Journals nodes of run, which must take.
func (self *testSessionJournalWorld) journalNodes(run *sidecar.SessionRun, nodes ...*sidecar.SessionNode) []*sidecar.SessionJournaled {
	self.t.Helper()
	journaled, err := self.journal.Journal(self.t.Context(), run, nodes...)
	if err != nil {
		self.t.Fatal(err)
	}
	return journaled
}

// What the vault holds once the device flushes, every body fetched: the session nodes by node id and the blobs by
// entry id.
func (self *testSessionJournalWorld) stored() (map[sidecar.Id]*protocol.SessionEntryBody, map[sidecar.Id]*protocol.SessionBlobBody, []*sidecar.RecordReadEntry) {
	self.t.Helper()
	if err := self.record.Flush(self.t.Context()); err != nil {
		self.t.Fatal(err)
	}
	reader := self.world.newReader(nil, nil)
	reader.sync(self.t, self.world)
	if _, err := reader.reader.FetchBodies(self.t.Context(), self.world.vaultId, nil); err != nil {
		self.t.Fatal(err)
	}
	if reasons := reader.reasons(); len(reasons) != 0 {
		self.t.Errorf("the reader raised %v", reasons)
	}
	nodes := map[sidecar.Id]*protocol.SessionEntryBody{}
	blobs := map[sidecar.Id]*protocol.SessionBlobBody{}
	entries := reader.reader.Entries(self.world.vaultId)
	for _, entry := range entries {
		switch entry.Kind() {
		case sidecar.RecordKindSessionEntry:
			body := &protocol.SessionEntryBody{}
			if err := proto.Unmarshal(entry.Body, body); err != nil {
				self.t.Fatalf("a node's body: %v", err)
			}
			nodes[sidecar.Id(body.GetNodeId())] = body
		case sidecar.RecordKindSessionBlob:
			body := &protocol.SessionBlobBody{}
			if err := proto.Unmarshal(entry.Body, body); err != nil {
				self.t.Fatalf("a blob's body: %v", err)
			}
			blobs[entry.EntryId] = body
		}
	}
	return nodes, blobs, entries
}

// A run of the test.
func testSessionRun() *sidecar.SessionRun {
	runId := sidecar.NewId()
	agentId := sidecar.NewId()
	return &sidecar.SessionRun{RunId: runId, AgentId: &agentId, Tainted: false}
}

// A message node of key under parentKey, its item a Pi entry holding text.
func testSessionMessage(key string, parentKey string, role string, text string) *sidecar.SessionNode {
	parent := `null`
	if parentKey != "" {
		parent = `"` + parentKey + `"`
	}
	item := `{"type":"message","id":"` + key + `","parentId":` + parent + `,"timestamp":"2026-11-06T00:00:00.000Z","message":{"role":"` + role +
		`","content":[{"type":"text","text":` + testSessionJsonString(text) + `}],"timestamp":1762387200000}}`
	return &sidecar.SessionNode{Key: key, ParentKey: parentKey, Type: sidecar.SessionNodeMessage, Item: []byte(item)}
}

// A tool result node of key under parentKey, its text the result.
func testSessionToolResult(key string, parentKey string, tool string, text string, details string, result *sidecar.SessionToolResult) *sidecar.SessionNode {
	if details == "" {
		details = `{}`
	}
	item := `{"type":"message","id":"` + key + `","parentId":"` + parentKey + `","timestamp":"2026-11-06T00:00:00.000Z","message":{"role":"toolResult","toolCallId":"call-` +
		key + `","toolName":"` + tool + `","content":[{"type":"text","text":` + testSessionJsonString(text) + `}],"details":` + details +
		`,"isError":false,"timestamp":1762387200000}}`
	return &sidecar.SessionNode{Key: key, ParentKey: parentKey, Type: sidecar.SessionNodeMessage, Item: []byte(item), Tool: result}
}

// text as a JSON string, unescaped as RFC 8785 writes one.
func testSessionJsonString(text string) string {
	buffer := &bytes.Buffer{}
	encoder := json.NewEncoder(buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(text); err != nil {
		panic(err)
	}
	return strings.TrimSuffix(buffer.String(), "\n")
}

// Every node of a corpus run, journaled in order, keeps its place: each passes the reader's format checks against
// its parent's chain hash, the tree's parents are the run's own, and a branch from one call shares the path above it.
func TestSessionJournalsACorpusRun(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	file, err := os.Open("testdata/session/corpus/harness-run.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	run := testSessionRun()
	scanner := bufio.NewScanner(file)
	keys := []string{}
	for scanner.Scan() {
		entry := &sidecar.HarnessPiEntry{}
		if err := entry.UnmarshalJSON(scanner.Bytes()); err != nil {
			t.Fatal(err)
		}
		if entry.Type() == sidecar.HarnessPiEntrySession {
			continue
		}
		node := &sidecar.SessionNode{Key: entry.Id(), Type: sidecar.SessionNodeTypeOfPi(entry.Type()), Item: bytes.Clone(scanner.Bytes())}
		if parentId, ok := entry.ParentId(); ok {
			node.ParentKey = parentId
		}
		journalWorld.journalNodes(run, node)
		keys = append(keys, entry.Id())
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	nodes, _, _ := journalWorld.stored()
	if len(nodes) != len(keys) {
		t.Fatalf("%d nodes stored of %d", len(nodes), len(keys))
	}
	keyNodes := map[string]*protocol.SessionEntryBody{}
	for _, key := range keys {
		nodeId, _, ok := journalWorld.journal.Node(run.RunId, key)
		if !ok || nodes[nodeId] == nil {
			t.Fatalf("node %s is not stored", key)
		}
		keyNodes[key] = nodes[nodeId]
	}
	for _, body := range nodes {
		args := &sidecar.SessionNodeCheckArgs{}
		if len(body.GetParentNodeId()) != 0 {
			parent := nodes[sidecar.Id(body.GetParentNodeId())]
			if parent == nil {
				t.Fatalf("a node's parent is not the run's")
			}
			args.ParentChainSha256 = parent.GetChainSha256()
		}
		if err := sidecar.SessionNodeCheck(body, args); err != nil {
			t.Errorf("a journaled node fails the reader's check: %v", err)
		}
	}
	if keyNodes["a0000005"].GetType() != uint32(sidecar.SessionNodeModelChange) || keyNodes["a0000007"].GetType() != uint32(sidecar.SessionNodeCompaction) {
		t.Errorf("types %d and %d", keyNodes["a0000005"].GetType(), keyNodes["a0000007"].GetType())
	}
	if !bytes.Equal(keyNodes["a0000008"].GetParentNodeId(), keyNodes["a0000004"].GetParentNodeId()) {
		t.Error("a branch from one call does not share its parent")
	}
	// the address the person typed stays as typed (Q-CTXH-15)
	if !bytes.Contains(keyNodes["a0000002"].GetItem(), []byte("bob@example.com")) {
		t.Error("the typed address was hashed")
	}
}

// Crashers on §24.16's completeness row: the daemon killed after the journal returned and before the call went, and
// again after the response was journaled and before its tool ran; in each the next life's record pushes every node
// journaled, so every call made has its context and a tool started from its response finds it; a response the kill
// took before its journal is a coverage gap.
func TestSessionKilledBetweenJournalAndCall(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	context := journalWorld.journalNodes(run,
		testSessionMessage("system", "", "system", "a synthetic system prompt"),
		testSessionMessage("prompt", "system", "user", "list the synthetic files"),
	)
	// the kill: the call never went, nothing was pushed; the next life replays the writer's journal
	journalWorld.open(nil)
	nodes, _, _ := journalWorld.stored()
	for _, written := range context {
		if nodes[written.NodeId] == nil {
			t.Errorf("node %s journaled before the kill is not in the record", written.Key)
		}
	}
	// the run goes on from its journal's state: a node under the prompt names it
	after := journalWorld.journalNodes(run, testSessionMessage("answer", "prompt", "assistant", "two synthetic files"))
	nodes, _, _ = journalWorld.stored()
	if !bytes.Equal(nodes[after[0].NodeId].GetParentNodeId(), context[1].NodeId.Bytes()) {
		t.Error("the run's next node lost its parent across the restart")
	}
}

// See TestSessionKilledBetweenJournalAndCall.
func TestSessionKilledBetweenResponseAndTool(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	journalWorld.journalNodes(run, testSessionMessage("prompt", "", "user", "read the synthetic file"))
	response := journalWorld.journalNodes(run, testSessionMessage("response", "prompt", "assistant", "calling read on notes.md"))
	// killed before the tool ran: the response, journaled before the event that completes it, survives
	journalWorld.open(nil)
	nodes, _, _ := journalWorld.stored()
	if nodes[response[0].NodeId] == nil {
		t.Fatal("the response journaled before its tool is not in the record")
	}
	// a second call's response the kill took before its journal: the run's coverage counts it lost
	journalWorld.journal.MarkLostResponse(run.RunId)
	if gaps := journalWorld.device.takeGaps(); !slices.Contains(gaps, run.RunId.String()+" "+sidecar.RecordCoverageGapDowntime) {
		t.Errorf("a lost response counted %v", gaps)
	}
}

// An item the run already holds, a file read twice, is a same_as node: its header names the earlier node, with no
// item and no parts, and its item hash is the earlier one's.
func TestSessionSameAsForRepeatedRead(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	item := []byte(`{"type":"function_call_output","call_id":"call-1","output":"the same file, read again"}`)
	journaled := journalWorld.journalNodes(run,
		&sidecar.SessionNode{Key: "first read", Type: sidecar.SessionNodeMessage, Item: item},
		&sidecar.SessionNode{Key: "second read", ParentKey: "first read", Type: sidecar.SessionNodeMessage, Item: item},
	)
	if journaled[1].SameAs == nil || *journaled[1].SameAs != journaled[0].NodeId || journaled[1].ItemSha256 != journaled[0].ItemSha256 {
		t.Fatalf("the second read is no same_as node: %+v", journaled[1])
	}
	nodes, _, _ := journalWorld.stored()
	second := nodes[journaled[1].NodeId]
	if len(second.GetItem()) != 0 || len(second.GetParts()) != 0 || !bytes.Equal(second.GetSameAs(), journaled[0].NodeId.Bytes()) {
		t.Errorf("the same_as node holds %d item bytes", len(second.GetItem()))
	}
	if err := sidecar.SessionNodeCheck(second, &sidecar.SessionNodeCheckArgs{
		ParentChainSha256: nodes[journaled[0].NodeId].GetChainSha256(), SameAs: nodes[journaled[0].NodeId],
	}); err != nil {
		t.Errorf("the same_as node fails its check: %v", err)
	}
}

// Bytes never cross runs: the same item in two runs is written in each, and the same part has blobs in each.
func TestSessionNoBytesAcrossRuns(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	text := string(bytes.Repeat([]byte("a shared result line\n"), 2048))
	first, second := testSessionRun(), testSessionRun()
	one := journalWorld.journalNodes(first, testSessionToolResult("result", "", "read", text, "", nil))
	two := journalWorld.journalNodes(second, testSessionToolResult("result", "", "read", text, "", nil))
	if one[0].SameAs != nil || two[0].SameAs != nil || one[0].NodeId == two[0].NodeId {
		t.Fatal("a node across runs is same_as or shares an id")
	}
	if len(one[0].Parts) != 1 || len(two[0].Parts) != 1 || bytes.Equal(one[0].Parts[0].GetBlobEntryIds()[0], two[0].Parts[0].GetBlobEntryIds()[0]) {
		t.Fatal("a part's blobs are shared across runs")
	}
	_, blobs, _ := journalWorld.stored()
	if len(blobs) != 2 {
		t.Errorf("%d blobs for one part in two runs", len(blobs))
	}
}

// Every node carries its run's marks, private and limited_use, and its header the run's taint at capture.
func TestSessionNodesCarryRunMarks(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	run.Marks = uint32(sidecar.HarnessMarkPrivate | sidecar.HarnessMarkLimitedUse)
	run.Tainted = true
	journaled := journalWorld.journalNodes(run, testSessionMessage("marked", "", "user", "read my calendar"))
	nodes, _, entries := journalWorld.stored()
	if marks := nodes[journaled[0].NodeId].GetMarks(); marks != 3 {
		t.Errorf("marks %d", marks)
	}
	for _, entry := range entries {
		if entry.Kind() == sidecar.RecordKindSessionEntry && !entry.Flagged {
			t.Error("a tainted run's node is not flagged")
		}
	}
}

// sha256 of text, for a test's comparison.
func testSessionSha256(text string) [sha256.Size]byte {
	return sha256.Sum256([]byte(text))
}
