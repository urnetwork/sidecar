//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-32: serving, DESIGN-DETAILS 7.6's search_remote_serve_test.go list and FS-83's serving cases on a fake
// corpus over the Team's real config: the checks in their order, refusals by repo in coverage, the candidate order and
// its watermark, a held hit not claimed, page 0 reading no all shard, ties on resume, too broad, the served record, and
// no query persisted.

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// Each of step 2's Errors comes before the body is read: with a body that would fail step 3, the answer is the Error,
// never an INVALID reply. UNAUTHENTICATED with no verified caller; PERMISSION_DENIED for a caller that is no untagged
// member device, for an indexer serving off, and with no services to open; RESOURCE_EXHAUSTED past the rate.
func TestChecksRunInOrder(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	garbage := bytes.Repeat([]byte{0xff}, fixture.wire.RequestByteCount)
	code := func(err error) protocol.ErrorCode {
		var refusal *SidecarRemoteRefusal
		if errors.As(err, &refusal) {
			return refusal.SubprotocolError().Code
		}
		errorCode, _ := SubprotocolErrorCode(err)
		return errorCode
	}
	if _, err := fixture.server.Handle(t.Context(), &SubprotocolRequest{Body: garbage}); code(err) != protocol.ErrorCode_ERR_UNAUTHENTICATED {
		t.Errorf("no caller: %v", err)
	}
	if _, err := fixture.ask(t, team.agent, garbage); code(err) != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("a tagged caller: %v", err)
	}
	if _, err := fixture.ask(t, team.net.device("never admitted", team.dana), garbage); code(err) != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("an unknown caller: %v", err)
	}
	fixture.settings.RemoteServe = false
	if _, err := fixture.ask(t, team.danaPhone, garbage); code(err) != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("serving off: %v", err)
	}
	fixture.settings.RemoteServe = true
	// a device that holds no designation of its own serves nothing
	undesignated := newTestSearchRemoteServer(t, team, team.danaLaptop)
	if _, err := undesignated.ask(t, team.danaPhone, garbage); code(err) != protocol.ErrorCode_ERR_PERMISSION_DENIED {
		t.Errorf("no designation: %v", err)
	}
	// the burst, each answered INVALID after parsing, then the rate's refusal before it
	for i := 0; i < fixture.settings.RemoteRequesterRate.Burst; i += 1 {
		answer, err := fixture.ask(t, team.danaPhone, garbage)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if reply, ok := searchRemoteAcceptReply(answer, 1, fixture.wire); !ok || reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_INVALID) {
			t.Fatalf("request %d: not INVALID", i)
		}
	}
	if _, err := fixture.ask(t, team.danaPhone, garbage); code(err) != protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED {
		t.Errorf("past the rate: %v", err)
	}
}

// FS-83's refusals by repo, in coverage and never as an error: the requester's own vault and the team repo served; a
// vault it does not read and a secret refused as not reader; and on Ben's NAS, Dana's vault, which the NAS reads by a
// share but Dana never consented, refused as not consented.
func TestRefusalsAreNamedInCoverage(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 7, testSearchRemoteDocs("vault ", 300, 200)...)
	fixture.corpus.serveText(team.teamRepo, 9, testSearchRemoteDocs("team ", 250)...)
	body := testSearchRemoteRequest(t, fixture.wire, 11, 0, "plan", team.danaVault, team.benVault, team.danaSecret, team.teamRepo)
	reply := fixture.page(t, team.danaPhone, body, 11, 0)
	want := []protocol.SearchServed{
		protocol.SearchServed_SERVED_TEXT, protocol.SearchServed_REFUSED_NOT_READER, protocol.SearchServed_REFUSED_NOT_READER,
		protocol.SearchServed_SERVED_TEXT,
	}
	if len(reply.GetCoverage()) != len(want) {
		t.Fatalf("%d rows", len(reply.GetCoverage()))
	}
	for i, row := range reply.GetCoverage() {
		if protocol.SearchServed(row.GetServed()) != want[i] {
			t.Errorf("row %d: %d, want %d", i, row.GetServed(), want[i])
		}
	}
	if reply.GetCoverage()[0].GetRefVersion() != 7 || reply.GetCoverage()[1].GetRefVersion() != 0 {
		t.Errorf("pins: %d, %d", reply.GetCoverage()[0].GetRefVersion(), reply.GetCoverage()[1].GetRefVersion())
	}
	if len(reply.GetHits()) != 3 {
		t.Errorf("%d hits", len(reply.GetHits()))
	}

	benNas := newTestSearchRemoteServer(t, team, team.benNas)
	benNas.corpus.serveText(team.danaVault, 7, testSearchRemoteDocs("vault ", 300)...)
	reply = benNas.page(t, team.benPhone, testSearchRemoteRequest(t, benNas.wire, 12, 0, "plan", team.danaVault), 12, 0)
	if served := protocol.SearchServed(reply.GetCoverage()[0].GetServed()); served != protocol.SearchServed_REFUSED_NOT_CONSENTED {
		t.Errorf("a shared vault on the reader's own indexer: %d", served)
	}
	if len(reply.GetHits()) != 0 || benNas.corpus.opens != 0 {
		t.Errorf("a refused repo reached the corpus")
	}
}

// One order newest first across partitions and repos: a backfilled old message in a bucket follows a recent one in all,
// and at one time the repo named first comes first.
func TestTheOrderIsNewestFirstAcrossPartitions(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	vault := []*testSearchRemoteDoc{
		{label: "recent in all", timeMs: 900, version: 1, matches: true, textHeld: true, all: true},
		{label: "backfilled in a bucket", timeMs: 100, version: 1, matches: true, textHeld: true},
		{label: "tie in the vault", timeMs: 500, version: 1, matches: true, textHeld: true},
	}
	team1 := []*testSearchRemoteDoc{{label: "tie in the team repo", timeMs: 500, version: 1, matches: true, textHeld: true}}
	fixture.corpus.serveText(team.danaVault, 3, vault...)
	fixture.corpus.serveText(team.teamRepo, 3, team1...)
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 21, 0, "plan", team.danaVault, team.teamRepo), 21, 0)
	got := testSearchRemoteLabels(reply.GetHits(), append(vault, team1...)...)
	want := []string{"recent in all", "tie in the vault", "tie in the team repo", "backfilled in a bucket"}
	if len(got) != len(want) {
		t.Fatalf("hits %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("hit %d: %s, want %s", i, got[i], want[i])
		}
	}
	if !reply.GetComplete() || reply.GetCheckedThroughMs() != 0 || reply.GetPhase() != 3 {
		t.Errorf("complete %v, checked through %d, phase %d", reply.GetComplete(), reply.GetCheckedThroughMs(), reply.GetPhase())
	}
}

// 7.1's D, RemoteCursorTwin-WatermarkPastHeld on real code: a page whose verified hits do not all fit one step claims
// none it held back. checked_through_ms is the time of the first hit held, and the next page starts there.
func TestCheckedThroughStopsBeforeAHeldHit(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 12; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune('a' + i)), timeMs: int64(1000 - 10*i), version: 1, matches: true, textHeld: true, large: true})
	}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	first := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 31, 0, "plan", team.danaVault), 31, 0)
	held := len(first.GetHits())
	if held == 0 || len(docs) <= held {
		t.Fatalf("%d hits on page 0", held)
	}
	if want := docs[held].timeMs; first.GetCheckedThroughMs() != want || first.GetComplete() {
		t.Errorf("checked through %d, want the held hit's %d", first.GetCheckedThroughMs(), want)
	}
	second := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 31, 1, ""), 31, 1)
	if got := testSearchRemoteLabels(second.GetHits(), docs...); len(got) == 0 || got[0] != docs[held].label {
		t.Errorf("page 1 starts at %v, want %s", got, docs[held].label)
	}
}

// Page 0 of a search whose buckets fill the page reads no all shard: the corpus's pass stops at the shard's times.
func TestPageZeroReadsNoAllShard(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < fixture.settings.PageCandidateCount+1; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: "bucket " + string(rune(0x4e00+i)), timeMs: int64(1_000_000 - i), version: 1, matches: i%2 == 0, textHeld: true})
	}
	docs = append(docs, &testSearchRemoteDoc{label: "old in all", timeMs: 10, version: 1, matches: true, textHeld: true, all: true})
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 41, 0, "plan", team.danaVault), 41, 0)
	if fixture.corpus.allReads != 0 {
		t.Errorf("page 0 read %d all shards", fixture.corpus.allReads)
	}
	if reply.GetPhase() != 1 || reply.GetComplete() {
		t.Errorf("phase %d, complete %v", reply.GetPhase(), reply.GetComplete())
	}
}

// RemoteCursorTwin-ResumeBelow on real code: a reopened search's until_ms is inclusive, so the candidates at the old
// checked_through_ms, ties included, are examined again.
func TestResumeIncludesTies(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{
		{label: "newer", timeMs: 700, version: 1, matches: true, textHeld: true},
		{label: "tie one", timeMs: 500, version: 1, matches: true, textHeld: true},
		{label: "tie two", timeMs: 500, version: 1, matches: true, textHeld: true},
		{label: "older", timeMs: 300, version: 1, matches: true, textHeld: true},
	}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	request := &protocol.SearchRequest{
		SearchVersion: searchVersion, SearchId: 51, Steps: 1, Scope: 2, Query: "plan", UntilMs: 500,
		Repos: []*protocol.SearchRepo{{RepoId: team.danaVault.Bytes()}},
	}
	body, err := searchRemoteBuildRequest(request, fixture.wire)
	if err != nil {
		t.Fatal(err)
	}
	reply := fixture.page(t, team.danaPhone, body, 51, 0)
	got := testSearchRemoteLabels(reply.GetHits(), docs...)
	if len(got) != 3 || got[0] != "tie one" && got[0] != "tie two" || got[2] != "older" {
		t.Errorf("resumed with %v", got)
	}
}

// TOO_BROAD claims no span: complete, what display fields confirm, and checked_through_ms unmoved from the last claim.
func TestTooBroadClaimsNoSpan(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{
		{label: "header", timeMs: 900, version: 1, matches: true, textHeld: true, headerConfirmed: true},
		{label: "body only", timeMs: 800, version: 1, matches: true, textHeld: true},
	}
	ref := fixture.corpus.serveText(team.danaVault, 5, docs...)
	ref.tooBroad = true
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 61, 0, "a", team.danaVault), 61, 0)
	if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_TOO_BROAD) || !reply.GetComplete() || reply.GetCheckedThroughMs() != 0 {
		t.Fatalf("status %d, complete %v, checked through %d", reply.GetStatus(), reply.GetComplete(), reply.GetCheckedThroughMs())
	}
	if got := testSearchRemoteLabels(reply.GetHits(), docs...); len(got) != 1 || got[0] != "header" {
		t.Errorf("hits %v", got)
	}
	// complete: no later page
	reply = fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 61, 1, ""), 61, 1)
	if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_INVALID) {
		t.Errorf("a page past a complete cursor: %d", reply.GetStatus())
	}
}

// A candidate whose text this indexer does not hold at that version comes back as a phone would judge it.
func TestAnUnverifiableCandidateIsReturned(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{{label: "no text", timeMs: 900, version: 4, matches: true, textHeld: false}}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 71, 0, "plan", team.danaVault), 71, 0)
	if len(reply.GetHits()) != 1 || reply.GetHits()[0].GetState() != uint32(SearchPossible) {
		t.Fatalf("hits %v", reply.GetHits())
	}
}

// §5.9's served record, written at page 0 once a search for a repo the requester reads only by an EvsShare: Ben's phone
// asking Dana's NAS for Dana's shared vault. It names the requester, the repo and the time, and search.state holds no
// byte of the query; Dana's own phone leaves none.
func TestTheServedRecordNamesNoQuery(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	query := "quarterlyneedle"
	fixture.page(t, team.benPhone, testSearchRemoteRequest(t, fixture.wire, 81, 0, query, team.danaVault), 81, 0)
	fixture.page(t, team.benPhone, testSearchRemoteRequest(t, fixture.wire, 81, 0, query, team.danaVault), 81, 0)
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 82, 0, query, team.danaVault), 82, 0)
	records, err := fixture.state.ServedRecords()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].RequesterId != team.benPhone.sidecarId || records[0].RepoId != team.danaVault {
		t.Fatalf("records %v", records)
	}
	if plaintext := fixture.world.plaintext(t); bytes.Contains(plaintext, []byte(query)) {
		t.Errorf("search.state holds the query")
	}
}
