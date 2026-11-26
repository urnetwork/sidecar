//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.9's exceptions as the journal keeps them (CTXH-M11-03; D-CTXH-7, D-CTXH-11; Q-CTXH-3, Q-CTXH-10,
// Q-CTXH-15): synthetic search results carrying marker strings in no node or blob; keep: false honored from a
// built-in alone; a secret marked and counted; an address and a number the person typed kept as typed though the
// harness config hashes PII; a mail tool's result a reference holding the SHA-256 of the text read and none of the
// text, and one with no reference refused. External, as session_journal_test.go.

package sidecar_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Synthetic web search results as Parallel's documented schema shapes them (§21.11), each excerpt carrying a marker
// string a test looks for everywhere the record holds bytes.
const testSessionSearchMarker = "SYNTHETIC-SEARCH-MARKER-7f3a"

func testSessionSearchResults() string {
	results := map[string]any{"search_id": "search-synthetic-1", "results": []any{
		map[string]any{"url": "https://docs.example/a", "title": "A synthetic page", "excerpts": []any{"first " + testSessionSearchMarker + " excerpt"}},
		map[string]any{"url": "https://docs.example/b", "title": "B synthetic page", "excerpts": []any{"second " + testSessionSearchMarker + " excerpt"}},
	}}
	encoded, _ := json.Marshal(results)
	return string(encoded)
}

// Every byte the vault holds of the run: each node's item and each blob's content.
func testSessionStoredBytes(nodes map[sidecar.Id]*protocol.SessionEntryBody, blobs map[sidecar.Id]*protocol.SessionBlobBody) []byte {
	all := []byte{}
	for _, node := range nodes {
		all = append(all, node.GetItem()...)
	}
	for _, blob := range blobs {
		all = append(all, blob.GetContent()...)
	}
	return all
}

// A web search's results, a built-in's keep: false, are in no node or blob: its stub of the call stands in their
// place, counted, the results' text and details nowhere, even past a part's cap.
func TestSessionSyntheticSearchResultsInNoNodeOrBlob(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	results := testSessionSearchResults()
	large := strings.Repeat(results, 4096)
	journaled := journalWorld.journalNodes(run,
		testSessionToolResult("search", "", "web_search", results, `{"results":2,"keep":false,"raw":`+testSessionJsonString(results)+`}`,
			&sidecar.SessionToolResult{Name: "web_search", BuiltIn: true, KeepFalse: true}),
		testSessionToolResult("large", "search", "web_search", large, `{"keep":false}`,
			&sidecar.SessionToolResult{Name: "web_search", BuiltIn: true, KeepFalse: true, SearchStub: []byte(`{"count":8192,"answer_sha256":"00"}`)}),
	)
	for _, written := range journaled {
		if written.Form != sidecar.SessionItemStub || written.Stubs != 1 || len(written.Parts) != 0 {
			t.Errorf("%s: form %d, %d stubs, %d parts", written.Key, written.Form, written.Stubs, len(written.Parts))
		}
	}
	nodes, blobs, _ := journalWorld.stored()
	if all := testSessionStoredBytes(nodes, blobs); bytes.Contains(all, []byte(testSessionSearchMarker)) || bytes.Contains(all, []byte("docs.example")) {
		t.Fatal("a search result's text is in the record")
	}
	node := nodes[journaled[1].NodeId]
	if !bytes.Contains(node.GetItem(), []byte(`"count":8192`)) || !bytes.Contains(node.GetItem(), []byte(`"toolCallId":"call-large"`)) || node.GetStubs() != 1 {
		t.Errorf("the stub with SRCH's fields: %s", node.GetItem())
	}
}

// keep: false is honored from a built-in alone: a harness's or MCP server's tool marking it has its result kept whole.
func TestSessionKeepFalseFromNonBuiltInIgnored(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	journaled := journalWorld.journalNodes(run,
		testSessionToolResult("other", "", "custom_search", "a custom tool's own result", `{"keep":false}`,
			&sidecar.SessionToolResult{Name: "custom_search", BuiltIn: false, KeepFalse: true}),
		testSessionToolResult("builtin", "other", "web_search", "a built-in's result", `{"keep":false}`,
			&sidecar.SessionToolResult{Name: "web_search", BuiltIn: true, KeepFalse: true}),
	)
	if journaled[0].Form != sidecar.SessionItemWhole || journaled[0].Stubs != 0 || journaled[1].Form != sidecar.SessionItemStub {
		t.Fatalf("forms %d and %d", journaled[0].Form, journaled[1].Form)
	}
	nodes, _, _ := journalWorld.stored()
	if !bytes.Contains(nodes[journaled[0].NodeId].GetItem(), []byte("a custom tool's own result")) {
		t.Error("a non-built-in's keep: false dropped its result")
	}
	if bytes.Contains(nodes[journaled[1].NodeId].GetItem(), []byte("a built-in's result")) {
		t.Error("a built-in's keep: false result was kept")
	}
}

// A secret the rules match is a marker in the node, counted in redactions and as the run's redaction gap.
func TestSessionRedactionMarksAndCounts(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	secret := "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	journaled := journalWorld.journalNodes(run, testSessionToolResult("env", "", "bash", "GITHUB_TOKEN="+secret+"\n", "", nil))
	if journaled[0].Redactions != 1 {
		t.Fatalf("%d redactions", journaled[0].Redactions)
	}
	nodes, _, _ := journalWorld.stored()
	node := nodes[journaled[0].NodeId]
	if bytes.Contains(node.GetItem(), []byte(secret)) || !bytes.Contains(node.GetItem(), []byte("[REDACTED:github-pat:")) || node.GetRedactions() != 1 {
		t.Errorf("the redacted node: %s", node.GetItem())
	}
	if gaps := journalWorld.device.takeGaps(); !slices.Contains(gaps, run.RunId.String()+" "+sidecar.RecordCoverageGapRedaction) {
		t.Errorf("gaps %v", gaps)
	}
}

// Q-CTXH-15: the address and number the person typed stay as typed in kinds 54 and 55, though the harness config
// hashes PII in every other entry, while a secret beside them is still marked.
func TestSessionTypedAddressKeptUnhashed(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	journaled := journalWorld.journalNodes(run, testSessionMessage("prompt", "", "user", "invite bob@example.com and call +15555550123"))
	nodes, _, _ := journalWorld.stored()
	item := nodes[journaled[0].NodeId].GetItem()
	if !bytes.Contains(item, []byte("bob@example.com")) || !bytes.Contains(item, []byte("+15555550123")) || journaled[0].Redactions != 0 {
		t.Errorf("the typed address: %s", item)
	}
	// the same redactor hashes them in any other kind's text
	redactor, err := sidecar.NewRedactor(bytes.NewReader(bytes.Repeat([]byte{0x52}, 64)))
	if err != nil {
		t.Fatal(err)
	}
	other, matches := redactor.RedactKind(sidecar.RecordKindTranscript, []byte("invite bob@example.com"))
	if len(matches) != 1 || bytes.Contains(other, []byte("bob@example.com")) {
		t.Errorf("a transcript's address: %s", other)
	}
	kept, matches := redactor.RedactKind(sidecar.RecordKindSessionBlob, []byte("invite bob@example.com"))
	if len(matches) != 0 || !bytes.Contains(kept, []byte("bob@example.com")) {
		t.Errorf("a blob's address: %s", kept)
	}
}

// A mail tool's result is kept as its reference: the mailbox, the messages, the window read and the SHA-256 of the text
// the model read, none of the text; one with no reference is refused rather than kept as text.
func TestSessionMailReferenceHashOfTextRead(t *testing.T) {
	journalWorld := newTestSessionJournalWorld(t, nil, nil)
	run := testSessionRun()
	mailboxId := sidecar.NewId()
	text := "From: a synthetic sender\nSubject: the synthetic quarterly note\n\nA synthetic body the model read."
	journaled := journalWorld.journalNodes(run, testSessionToolResult("mail", "", "mail_read", text, `{"messages":1}`,
		&sidecar.SessionToolResult{Name: "mail_read", BuiltIn: true, MailReference: &sidecar.SessionMailReference{
			RepoId: mailboxId, MessageIds: []string{"message-1"}, Start: 0, MaxChars: 4096,
		}}))
	if journaled[0].Form != sidecar.SessionItemMailReference || journaled[0].Stubs != 0 {
		t.Fatalf("form %d, %d stubs", journaled[0].Form, journaled[0].Stubs)
	}
	nodes, blobs, _ := journalWorld.stored()
	item := nodes[journaled[0].NodeId].GetItem()
	digest := testSessionSha256(text)
	if bytes.Contains(testSessionStoredBytes(nodes, blobs), []byte("synthetic quarterly note")) {
		t.Fatal("the mail's text is in the record")
	}
	for _, want := range []string{hex.EncodeToString(digest[:]), hex.EncodeToString(mailboxId[:]), `"message-1"`, `"max_chars":4096`} {
		if !bytes.Contains(item, []byte(want)) {
			t.Errorf("the reference lacks %s: %s", want, item)
		}
	}
	_, err := journalWorld.journal.Journal(t.Context(), run, testSessionToolResult("unreferenced", "mail", "mail_list", text, "",
		&sidecar.SessionToolResult{Name: "mail_list", BuiltIn: true}))
	if !errors.Is(err, sidecar.ErrSessionMailAsText) {
		t.Errorf("a mail result with no reference: %v", err)
	}
}
