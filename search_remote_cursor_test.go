//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-32: the cursor table, DESIGN-DETAILS 7.6's search_remote_cursor_test.go list, each twin of RemoteCursor.tla
// on real code: a repeat byte-equal and never advancing; an ended id ended for every page, page 0 included; an erasure
// ending the cursor and its reply; a stale page leaving the cursor; a read revoked mid-cursor ending it; a third search
// superseding the oldest.

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A repeat of page n is its stored reply, byte-equal, page 0 and a later page alike.
func TestARepeatIsByteEqual(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 30; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune('A' + i)), timeMs: int64(1000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	pageZero := testSearchRemoteRequest(t, fixture.wire, 101, 0, "plan", team.danaVault)
	first, err := fixture.ask(t, team.danaPhone, pageZero)
	if err != nil {
		t.Fatal(err)
	}
	again, err := fixture.ask(t, team.danaPhone, pageZero)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("page 0 repeated: %v", err)
	}
	pageOne := testSearchRemoteRequest(t, fixture.wire, 101, 1, "")
	first, err = fixture.ask(t, team.danaPhone, pageOne)
	if err != nil {
		t.Fatal(err)
	}
	passes := fixture.corpus.passes
	again, err = fixture.ask(t, team.danaPhone, pageOne)
	if err != nil || !bytes.Equal(first, again) {
		t.Fatalf("page 1 repeated: %v", err)
	}
	if fixture.corpus.passes != passes {
		t.Errorf("a repeat computed a page")
	}
}

// RemoteCursorTwin-RepeatAdvances: repeating page 1 after page 1 never moves the cursor, so page 2 follows page 1.
func TestARepeatedPageNeverAdvances(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 50; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3400 + i)), timeMs: int64(5000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 111, 0, "plan", team.danaVault), 111, 0)
	one := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 111, 1, ""), 111, 1)
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 111, 1, ""), 111, 1)
	two := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 111, 2, ""), 111, 2)
	oneLabels, twoLabels := testSearchRemoteLabels(one.GetHits(), docs...), testSearchRemoteLabels(two.GetHits(), docs...)
	if len(oneLabels) == 0 || len(twoLabels) == 0 {
		t.Fatalf("pages %v, %v", oneLabels, twoLabels)
	}
	last, next := docs[0], docs[0]
	for _, doc := range docs {
		if doc.label == oneLabels[len(oneLabels)-1] {
			last = doc
		}
		if doc.label == twoLabels[0] {
			next = doc
		}
	}
	if next.timeMs != last.timeMs-1 {
		t.Errorf("page 2 starts at %d after page 1 ended at %d", next.timeMs, last.timeMs)
	}
}

// RemoteCursorTwin-ReopenSameId, 7.1's E: once superseded, an id answers CURSOR_EXPIRED for every page, a late copy of
// page 0 included, so no cursor is ever opened under it again.
func TestAnEndedIdStaysEnded(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 300, 200)...)
	pageZero := testSearchRemoteRequest(t, fixture.wire, 121, 0, "plan", team.danaVault)
	fixture.page(t, team.danaPhone, pageZero, 121, 0)
	superseding := &protocol.SearchRequest{
		SearchVersion: searchVersion, SearchId: 122, Supersedes: 121, Steps: 1, Scope: 2, Query: "plan",
		Repos: []*protocol.SearchRepo{{RepoId: team.danaVault.Bytes()}},
	}
	body, err := searchRemoteBuildRequest(superseding, fixture.wire)
	if err != nil {
		t.Fatal(err)
	}
	fixture.page(t, team.danaPhone, body, 122, 0)
	opens := fixture.corpus.opens
	for _, page := range []uint32{0, 1} {
		request := testSearchRemoteRequest(t, fixture.wire, 121, page, "plan", team.danaVault)
		reply := fixture.page(t, team.danaPhone, request, 121, page)
		if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) {
			t.Errorf("page %d of an ended id: %d", page, reply.GetStatus())
		}
	}
	if fixture.corpus.opens != opens {
		t.Errorf("an ended id opened a cursor")
	}
}

// RemoteCursorTwin-KeepReplyAcrossErase: an erasure in a served repo ends the cursor before EndRepo returns, its last
// reply with it, so neither a repeat nor the next page sends what the erasure removed.
func TestAnErasureEndsTheCursorAndItsReply(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 300, 200)...)
	pageZero := testSearchRemoteRequest(t, fixture.wire, 131, 0, "plan", team.danaVault)
	fixture.page(t, team.danaPhone, pageZero, 131, 0)
	fixture.server.EndRepo(team.danaVault)
	if fixture.corpus.openViews != 0 {
		t.Errorf("%d views still open", fixture.corpus.openViews)
	}
	for _, page := range []uint32{0, 1} {
		reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 131, page, "plan", team.danaVault), 131, page)
		if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) || len(reply.GetHits()) != 0 {
			t.Errorf("page %d after the erasure: status %d, %d hits", page, reply.GetStatus(), len(reply.GetHits()))
		}
	}
}

// A request for a page other than the cursor's or the next is INVALID and leaves the cursor where it was.
func TestAStalePageLeavesTheCursor(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 60; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3500 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.corpus.serveText(team.danaVault, 5, docs...)
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 141, 0, "plan", team.danaVault), 141, 0)
	if reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 141, 3, ""), 141, 3); reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_INVALID) {
		t.Errorf("page 3 at page 0: %d", reply.GetStatus())
	}
	if reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 141, 1, ""), 141, 1); reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_OK) {
		t.Errorf("page 1 after the stale page: %d", reply.GetStatus())
	}
	if reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 141, 0, "plan", team.danaVault), 141, 0); reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_INVALID) {
		t.Errorf("page 0 past page 0: %d", reply.GetStatus())
	}
}

// 7.1's K: a read lost mid-cursor ends the cursor at the next page, CURSOR_EXPIRED; Ben's phone reading Dana's mailbox by
// a share that expires between page 0 and page 1.
func TestARevokedReadEndsTheCursor(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	expires := net.timeMs + testConfigHourMs
	net.mustPost(team.danaLaptop, bridge.SignedType_SIGNED_EVS_SHARE, &protocol.EvsShare{
		Header: net.header(), RepoId: team.danaMailbox.Bytes(), Subject: team.benPhone.sidecarId.Bytes(), Expires: expires,
	})
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 40; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3600 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.corpus.serveText(team.danaMailbox, 5, docs...)
	reply := fixture.page(t, team.benPhone, testSearchRemoteRequest(t, fixture.wire, 151, 0, "plan", team.danaMailbox), 151, 0)
	if served := protocol.SearchServed(reply.GetCoverage()[0].GetServed()); served != protocol.SearchServed_SERVED_TEXT {
		t.Fatalf("the shared mailbox: %d", served)
	}
	net.tickAt(expires + 1000)
	reply = fixture.page(t, team.benPhone, testSearchRemoteRequest(t, fixture.wire, 151, 1, ""), 151, 1)
	if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) {
		t.Errorf("a page after the share expired: %d", reply.GetStatus())
	}
	if fixture.corpus.openViews != 0 {
		t.Errorf("the ended cursor kept its view")
	}
}

// A requester holds at most two live cursors at an indexer: a third's page 0 ends the oldest.
func TestAThirdSearchEndsTheOldest(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 300, 200)...)
	for _, searchId := range []uint64{161, 162} {
		fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, searchId, 0, "plan", team.danaVault), searchId, 0)
		fixture.clock.advance(1)
	}
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 163, 0, "plan", team.danaVault), 163, 0)
	if count := fixture.server.table.liveCount(team.danaPhone.sidecarId); count != 2 {
		t.Errorf("%d live cursors", count)
	}
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 161, 1, ""), 161, 1)
	if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) {
		t.Errorf("the oldest: %d", reply.GetStatus())
	}
}

// A cursor idle CursorTimeout ends, and its id is then forgotten after another CursorTimeout.
func TestAnIdleCursorEnds(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	fixture.corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 300, 200)...)
	fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 171, 0, "plan", team.danaVault), 171, 0)
	fixture.clock.advance(fixture.settings.CursorTimeout)
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 171, 1, ""), 171, 1)
	if reply.GetStatus() != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) {
		t.Errorf("an idle cursor's page: %d", reply.GetStatus())
	}
}

// A remote cursor keys its page barriers by its first served repo and ref as <repo>:<ref>, an opaque id a Net's
// barrier driver takes, with no slash, which reads as a path (testhook.go; I-13).
func TestSearchRemoteCursorBarrierKeyIsAnOpaqueId(t *testing.T) {
	repoId, refId := evsTestId("remote repo"), evsTestId("remote ref")
	cursor := &searchRemoteCursor{repos: []*searchRemoteCursorRepo{
		{repoId: evsTestId("unserved repo"), row: &protocol.SearchCoverage{RefId: evsTestId("unserved ref").Bytes()}},
		{repoId: repoId, row: &protocol.SearchCoverage{Served: uint32(protocol.SearchServed_SERVED_INDEX), RefId: refId.Bytes()}},
	}}
	if key := cursor.barrierKey(); key != repoId.String()+":"+refId.String() {
		t.Fatalf("the cursor's barrier key %q", key)
	}
}
