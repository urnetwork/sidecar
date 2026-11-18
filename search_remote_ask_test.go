//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-33: asking, DESIGN-DETAILS 7.6's search_remote_ask_test.go list as amended for QD-707, each twin of
// RemoteAsk.tla on real code, and FS-83's eligibility, notice and failover cases, over the Team's real config with
// in-process indexers on fake corpora. With owner decision 609 no pair is kept warm: a search asks its first two own
// indexers at once with nothing named before it, bit 1 follows the mode and the notice and marks nothing, and the
// dispatcher is told only the foreground and the first-choice own indexer HeadCheck counts there.

import (
	"cmp"
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// QD-707: the first two own indexers are asked at once, with no pair kept warm or named before (owner decision 609),
// both requests built from one reading and sent before either reply comes, and the first page 0 to serve the vault
// wins it.
func TestTheFirstTwoOwnIndexersAreAskedAtOnce(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	second := testSearchRemoteMoreOwn(t, team, "dana nas two")[0]
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	for _, indexer := range []testConfigDevice{team.danaNas, second} {
		fixture.serve(t, indexer).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900, 800)...)
	}
	releaseFirst, releaseSecond := fixture.transport.hold(team.danaNas.sidecarId), fixture.transport.hold(second.sidecarId)
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	// neither answers until both requests are out: a second sent after the first reply would never arrive
	calls := fixture.transport.awaitCalls(t, 2)
	called := testSearchRemoteCalled(calls, true)
	if !slices.Contains(called, team.danaNas.sidecarId) || !slices.Contains(called, second.sidecarId) {
		t.Fatalf("asked %v", called)
	}
	releaseFirst()
	releaseSecond()
	got := <-page
	if got.progress.Remote != SearchRemoteStateAnswered || len(got.hits) != 2 {
		t.Errorf("remote %q, %d hits", got.progress.Remote, len(got.hits))
	}
	for _, hit := range got.hits {
		if hit.State != SearchVerified || hit.By == "" {
			t.Errorf("a hit %v by %q", hit.State, hit.By)
		}
	}
}

// RemoteAskTwin-KeepBoth: the slower own leg's reply is dropped for the repo the faster one won, on every page, and is no
// mismatch.
func TestTheLosingReplyIsDropped(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	second := testSearchRemoteMoreOwn(t, team, "dana nas two")[0]
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	winnerDocs := testSearchRemoteDocs("winner ", 900)
	loserDocs := testSearchRemoteDocs("loser only ", 950)
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, winnerDocs...)
	fixture.serve(t, second).corpus.serveText(team.danaVault, 5, loserDocs...)
	release := fixture.transport.hold(second.sidecarId)
	stream := fixture.search(t, team.danaVault)
	first := testSearchRemoteNext(t, stream)
	if labels := testSearchRemoteHitLabels(first.hits, winnerDocs...); len(labels) != 1 {
		t.Fatalf("first page %v", first.hits)
	}
	release()
	fixture.transport.awaitCalls(t, 2)
	// the loser's page 0 comes in the next step and is dropped for the vault
	for i := 0; i < 3; i += 1 {
		page := testSearchRemoteNext(t, stream)
		if labels := testSearchRemoteHitLabels(page.hits, loserDocs...); len(labels) != 0 {
			t.Fatalf("the loser's hits merged: %v", labels)
		}
	}
	if alarms := fixture.alarms(SidecarEventSearchAlarm); len(alarms) != 0 {
		t.Errorf("the losing reply counted as a mismatch: %v", alarms)
	}
}

// RemoteAskTwin-AskAllOwn: with three own indexers only W's two are asked at once; the third is asked alone, once both
// have failed.
func TestAThirdOwnIndexerIsAskedOnlyAlone(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	more := testSearchRemoteMoreOwn(t, team, "dana nas two", "dana nas three")
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	all := append([]testConfigDevice{team.danaNas}, more...)
	for _, indexer := range all {
		fixture.serve(t, indexer).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	}
	ownAsk := fixture.ownAsk(t, team.danaVault)
	if len(ownAsk) != 2 {
		t.Fatalf("W %v", ownAsk)
	}
	third := Id{}
	for _, indexer := range all {
		if !slices.Contains(ownAsk, indexer.sidecarId) {
			third = indexer.sidecarId
		}
		if slices.Contains(ownAsk, indexer.sidecarId) {
			fixture.transport.dead[indexer.sidecarId] = true
		}
	}
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	calls := fixture.transport.awaitCalls(t, 2)
	if called := testSearchRemoteCalled(calls, true); slices.Contains(called, third) {
		t.Fatalf("the third asked beside W's two: %v", called)
	}
	fixture.clock.awaitPending(t, 2)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	got := <-page
	calls = fixture.transport.callsNow()
	if len(calls) != 3 || calls[2].indexerId != third {
		t.Fatalf("calls %v", testSearchRemoteCalled(calls, false))
	}
	if got.progress.Remote != SearchRemoteStateAnswered {
		t.Errorf("remote %q", got.progress.Remote)
	}
}

// RemoteAskTwin-PlanOnce: eligibility is read at each send. W's two own indexers fail, and the third, retired between
// the first plan and the failover's, is never asked: the vault falls back.
func TestEligibilityIsReadAtEachSend(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	more := testSearchRemoteMoreOwn(t, team, "dana nas two", "dana nas three")
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	all := append([]testConfigDevice{team.danaNas}, more...)
	for _, indexer := range all {
		fixture.serve(t, indexer)
	}
	ownAsk := fixture.ownAsk(t, team.danaVault)
	var third testConfigDevice
	for _, indexer := range all {
		if slices.Contains(ownAsk, indexer.sidecarId) {
			fixture.transport.dead[indexer.sidecarId] = true
		} else {
			third = indexer
		}
	}
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	fixture.transport.awaitCalls(t, 2)
	team.net.mustPost(third, bridge.SignedType_SIGNED_INDEXER_SET, team.net.indexerSet(third, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	fixture.clock.awaitPending(t, 2)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	got := <-page
	if calls := fixture.transport.callsNow(); len(calls) != 2 {
		t.Fatalf("a retired indexer was asked: %v", testSearchRemoteCalled(calls, false))
	}
	if got.progress.Remote != SearchRemoteStateFallback || got.progress.FallbackReason != SearchFallbackOffline {
		t.Errorf("remote %q, reason %q", got.progress.Remote, got.progress.FallbackReason)
	}
	if downloads := fixture.local.downloads(); len(downloads) != 1 || !slices.Equal(downloads[0].Repos, []Id{team.danaVault}) {
		t.Errorf("downloads %v", downloads)
	}
}

// FS-83: an owner-bound repo goes only to its owner's consented own indexers, even with every one down: Dana's vault,
// her NAS dead, falls back and is never asked of the network indexers that read it by a share.
func TestAVaultGoesOnlyToConsentedOwnIndexers(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.serve(t, team.danaNas)
	fixture.serve(t, team.net.owner)
	fixture.serve(t, team.agent)
	fixture.transport.dead[team.danaNas.sidecarId] = true
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	fixture.transport.awaitCalls(t, 1)
	fixture.clock.awaitPending(t, 1)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	got := <-page
	for _, call := range fixture.transport.callsNow() {
		if call.indexerId != team.danaNas.sidecarId {
			t.Errorf("the vault asked of %s", call.indexerId)
		}
	}
	if got.progress.FallbackReason != SearchFallbackOffline {
		t.Errorf("reason %q", got.progress.FallbackReason)
	}
}

// FS-83: no request reaches another member's device before the person answers its notice; the repo is searched on the
// phone meanwhile, the stream naming the notice; an answer that allows it sends the request at the next step.
func TestNoRequestBeforeTheNotice(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	net.mustPost(team.danaNas, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.serve(t, net.owner).corpus.serveText(team.teamRepo, 3, testSearchRemoteDocs("team ", 900)...)
	fixture.serve(t, team.agent).corpus.serveText(team.teamRepo, 3, testSearchRemoteDocs("team ", 900)...)
	stream := fixture.search(t, team.teamRepo)
	first := testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 0 {
		t.Fatalf("asked before the notice: %v", testSearchRemoteCalled(calls, false))
	}
	if first.progress.Remote != SearchRemoteStateNotice || first.progress.RemoteBy == nil || first.progress.FallbackReason != SearchFallbackNotice {
		t.Fatalf("remote %q by %v, reason %q", first.progress.Remote, first.progress.RemoteBy, first.progress.FallbackReason)
	}
	if len(fixture.local.downloads()) != 1 {
		t.Errorf("the phone did not search it itself")
	}
	memberId, ok := searchRemoteNoticeMember(net.log.State(), *first.progress.RemoteBy)
	if !ok {
		t.Fatal("no notice member")
	}
	if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
		t.Fatal(err)
	}
	second := testSearchRemoteNext(t, stream)
	calls := fixture.transport.callsNow()
	if len(calls) != 1 || calls[0].indexerId != *first.progress.RemoteBy {
		t.Fatalf("after the answer: %v", testSearchRemoteCalled(calls, false))
	}
	if second.progress.Remote != SearchRemoteStateAnswered {
		t.Errorf("remote %q", second.progress.Remote)
	}
}

// RemoteAskTwin-PairOthers: another member's indexer is never asked beside any other: one at a time, the first by
// otherKey, alone.
func TestNoOtherMembersIndexerIsAskedBesideAnother(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	net.mustPost(team.danaNas, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	for _, indexer := range []testConfigDevice{net.owner, team.agent} {
		fixture.serve(t, indexer).corpus.serveText(team.teamRepo, 3, testSearchRemoteDocs("team ", 900)...)
		if memberId, ok := searchRemoteNoticeMember(net.log.State(), indexer.sidecarId); ok {
			if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	stream := fixture.search(t, team.teamRepo)
	got := testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Fatalf("another member's indexers asked together: %v", testSearchRemoteCalled(calls, false))
	}
	if got.progress.Remote != SearchRemoteStateAnswered {
		t.Errorf("remote %q", got.progress.Remote)
	}
}

// RemoteAskTwin-KeepOnOwn: "Only my devices" ends every leg to an indexer that is not own: nothing more is asked of it,
// and its repo falls back.
func TestOnlyMyDevicesEndsOtherLegs(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	net.mustPost(team.danaNas, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(team.danaNas, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 40; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3700 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	members := []Id{}
	for _, indexer := range []testConfigDevice{net.owner, team.agent} {
		fixture.serve(t, indexer).corpus.serveText(team.teamRepo, 3, docs...)
		if memberId, ok := searchRemoteNoticeMember(net.log.State(), indexer.sidecarId); ok {
			members = append(members, memberId)
			if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	stream := fixture.search(t, team.teamRepo)
	testSearchRemoteNext(t, stream)
	if err := fixture.world.state.SetAnswer(&members[0], false); err != nil {
		t.Fatal(err)
	}
	got := testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Fatalf("asked after Only my devices: %v", testSearchRemoteCalled(calls, false))
	}
	if got.progress.Remote != SearchRemoteStateFallback && got.progress.Remote != "" {
		t.Errorf("remote %q", got.progress.Remote)
	}
}

// A later page whose reply is lost is asked once more, the same search_id and page, answered from the indexer's cursor.
func TestALostReplyIsAskedOnceMore(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 50; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3800 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, docs...)
	stream := fixture.search(t, team.danaVault)
	testSearchRemoteNext(t, stream)
	fixture.transport.dropFirst[team.danaNas.sidecarId] = 1
	page := testSearchRemoteNextLater(stream)
	fixture.transport.awaitCalls(t, 2)
	fixture.clock.awaitPending(t, 2)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	got := <-page
	calls := fixture.transport.callsNow()
	if len(calls) != 3 || calls[1].request.GetPage() != 1 || calls[2].request.GetPage() != 1 || calls[1].request.GetSearchId() != calls[2].request.GetSearchId() {
		t.Fatalf("calls %v", calls)
	}
	if len(got.hits) == 0 {
		t.Errorf("the repeat brought no page")
	}
}

// Page 0 is never sent twice under one search_id: one that gets no reply fails its leg at the deadline.
func TestPageZeroIsNeverRepeated(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.serve(t, team.danaNas)
	fixture.transport.dead[team.danaNas.sidecarId] = true
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	fixture.transport.awaitCalls(t, 1)
	fixture.clock.awaitPending(t, 1)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	<-page
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Errorf("page 0 sent %d times", len(calls))
	}
}

// CURSOR_EXPIRED on a later page reopens the search once, superseding the old id, resumed by until_ms at the last
// checked_through_ms; the hits already shown stay.
func TestACursorExpiredReopensOnceAndResumes(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 50; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3900 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	server := fixture.serve(t, team.danaNas)
	server.corpus.serveText(team.danaVault, 5, docs...)
	stream := fixture.search(t, team.danaVault)
	testSearchRemoteNext(t, stream)
	server.server.EndRepo(team.danaVault)
	got := testSearchRemoteNext(t, stream)
	calls := fixture.transport.callsNow()
	if len(calls) != 3 {
		t.Fatalf("calls %d", len(calls))
	}
	reopen := calls[2].request
	if reopen.GetPage() != 0 || reopen.GetSupersedes() != calls[0].request.GetSearchId() || reopen.GetUntilMs() == 0 {
		t.Errorf("the reopen: page %d, supersedes %d, until %d", reopen.GetPage(), reopen.GetSupersedes(), reopen.GetUntilMs())
	}
	if len(got.hits) == 0 {
		t.Errorf("the reopen brought no hits")
	}
}

// No page past 0 is asked unless the app asks for more.
func TestNoPageIsAskedUnasked(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 50; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3a00 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, docs...)
	stream := fixture.search(t, team.danaVault)
	testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Fatalf("%d calls after one page", len(calls))
	}
	testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 2 || calls[1].request.GetPage() != 1 {
		t.Errorf("%d calls after two pages", len(calls))
	}
}

// A refused repo goes on: Dana's vault refused by her NAS's index (off) falls back, remembered RemoteRefusedTimeout, and
// the next search does not ask it of that indexer.
func TestARefusedRepoGoesOn(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	ref := fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5)
	ref.row.served = protocol.SearchServed_REFUSED_INDEX_OFF
	got := testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	if got.progress.FallbackReason != SearchFallbackRefused {
		t.Errorf("reason %q", got.progress.FallbackReason)
	}
	testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Errorf("a refused repo asked again within RemoteRefusedTimeout: %d calls", len(calls))
	}
}

// A forged or absent designation is never asked: a device the config does not designate, though the asker could reach it.
func TestAForgedIndexerIsNeverAsked(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.serve(t, team.danaLaptop).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	for _, call := range fixture.transport.callsNow() {
		if call.indexerId == team.danaLaptop.sidecarId {
			t.Errorf("an undesignated device was asked")
		}
	}
}

// Mode off asks nothing: the search is the local engine's download alone, and no indexer is first-choice for HeadCheck.
func TestModeOffAsksNothing(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.serve(t, team.danaNas)
	if err := fixture.world.state.SetMode(SearchRemoteOff); err != nil {
		t.Fatal(err)
	}
	testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	if calls := fixture.transport.callsNow(); len(calls) != 0 {
		t.Errorf("mode off asked %d", len(calls))
	}
	if indexerId, ok := fixture.client.firstOwnIndexer(); ok {
		t.Errorf("mode off named %s first-choice", indexerId)
	}
	if fixture.client.asksSearch(team.danaNas.sidecarId) {
		t.Errorf("mode off sets bit 1")
	}
}

// An indexer that failed and is seen again (a Hello verified after its skip) is asked once more for the repos that fell
// back from it, once a search.
func TestAnIndexerSeenAgainIsAskedOnce(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	nas := team.danaNas.sidecarId
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	fixture.transport.dead[nas] = true
	stream := fixture.search(t, team.danaVault)
	page := testSearchRemoteNextLater(stream)
	fixture.transport.awaitCalls(t, 1)
	fixture.clock.awaitPending(t, 1)
	fixture.clock.advance(fixture.settings.RemoteTimeout[0])
	if got := <-page; got.progress.FallbackReason != SearchFallbackOffline {
		t.Fatalf("reason %q", got.progress.FallbackReason)
	}
	fixture.transport.stateLock.Lock()
	fixture.transport.dead[nas] = false
	fixture.transport.seen[nas] = fixture.clock.Now().Add(1)
	fixture.transport.stateLock.Unlock()
	fixture.clock.advance(1)
	got := testSearchRemoteNext(t, stream)
	if calls := fixture.transport.callsNow(); len(calls) != 2 {
		t.Fatalf("seen again: %d calls", len(calls))
	}
	if got.progress.Remote != SearchRemoteStateAnswered {
		t.Errorf("remote %q", got.progress.Remote)
	}
}

// A third open search at one indexer supersedes the older of the two this device still holds there.
func TestAThirdSearchSupersedesTheOldest(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	docs := []*testSearchRemoteDoc{}
	for i := 0; i < 50; i += 1 {
		docs = append(docs, &testSearchRemoteDoc{label: string(rune(0x3b00 + i)), timeMs: int64(9000 - i), version: 1, matches: true, textHeld: true})
	}
	fixture.serve(t, team.danaNas).corpus.serveText(team.danaVault, 5, docs...)
	for i := 0; i < 3; i += 1 {
		testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	}
	calls := fixture.transport.callsNow()
	if len(calls) != 3 {
		t.Fatalf("calls %d", len(calls))
	}
	if supersedes := calls[2].request.GetSupersedes(); supersedes != calls[0].request.GetSearchId() {
		t.Errorf("the third superseded %d, not the oldest %d", supersedes, calls[0].request.GetSearchId())
	}
	if calls[1].request.GetSupersedes() != 0 {
		t.Errorf("the second superseded %d", calls[1].request.GetSupersedes())
	}
}

// A repo of Dana's that only the network indexers answer, which her phone and the agent read, so the agent, another
// member's indexer, may answer it for her phone once its notice allows.
func testSearchRemoteSharedNotes(t *testing.T, team *testConfigSearchTeam) Id {
	t.Helper()
	net := team.net
	notes := testConfigId("shared notes")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: notes.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	for _, reader := range []testConfigDevice{team.danaPhone, team.agent} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: notes.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	return notes
}

// Bit 1 goes toward each own indexer and never toward a device that is no indexer; toward another member's indexer
// only in mode on, once its notice is answered allowing; and in mode own toward the own ones alone. Setting it sends
// nothing.
func TestBitOneFollowsTheModeAndTheNotice(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	testSearchRemoteSharedNotes(t, team)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	if !fixture.client.asksSearch(team.danaNas.sidecarId) || fixture.client.asksSearch(team.benPhone.sidecarId) {
		t.Errorf("bit 1 toward the wrong peers")
	}
	if fixture.client.asksSearch(team.agent.sidecarId) {
		t.Errorf("bit 1 toward another member's indexer before its notice")
	}
	memberId, ok := searchRemoteNoticeMember(team.net.log.State(), team.agent.sidecarId)
	if !ok {
		t.Fatal("the agent names no notice member")
	}
	if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
		t.Fatal(err)
	}
	if !fixture.client.asksSearch(team.agent.sidecarId) {
		t.Errorf("no bit 1 toward another member's indexer its notice allows")
	}
	if err := fixture.world.state.SetMode(SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	if fixture.client.asksSearch(team.agent.sidecarId) || !fixture.client.asksSearch(team.danaNas.sidecarId) {
		t.Errorf("bit 1 in mode own")
	}
	if calls := fixture.transport.callsNow(); len(calls) != 0 {
		t.Errorf("bit 1 sent %d calls", len(calls))
	}
}

// The first-choice own indexer is W's first over every repo the device reads: with one own indexer that one, with
// three the first by ownKey, and never another member's, even where only that one answers a repo and its notice
// allows.
func TestTheFirstChoiceIsTheFirstOwnIndexer(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	testSearchRemoteSharedNotes(t, team)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	memberId, ok := searchRemoteNoticeMember(team.net.log.State(), team.agent.sidecarId)
	if !ok {
		t.Fatal("the agent names no notice member")
	}
	if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
		t.Fatal(err)
	}
	if indexerId, ok := fixture.client.firstOwnIndexer(); !ok || indexerId != team.danaNas.sidecarId {
		t.Errorf("first choice %s (%t), want Dana's NAS", indexerId, ok)
	}
	// with no own indexer answered yet, ownKey is H(phone, d) alone
	own := []Id{team.danaNas.sidecarId}
	for _, device := range testSearchRemoteMoreOwn(t, team, "dana nas two", "dana nas three") {
		own = append(own, device.sidecarId)
	}
	slices.SortFunc(own, func(a Id, b Id) int {
		return cmp.Compare(searchRemoteRendezvous(team.danaPhone.sidecarId, a), searchRemoteRendezvous(team.danaPhone.sidecarId, b))
	})
	if indexerId, ok := fixture.client.firstOwnIndexer(); !ok || indexerId != own[0] {
		t.Errorf("first choice %s (%t), want %s by ownKey", indexerId, ok, own[0])
	}
	scope := fixture.client.scopeOf(team.net.log.State(), team.danaPhone.sidecarId, &SearchRequest{})
	if ownAsk := fixture.ownAsk(t, scope...); !slices.Equal(ownAsk, own[:2]) {
		t.Errorf("W %v, want %v", ownAsk, own[:2])
	}
}

// At each foreground, and on a config change in it, the client tells the dispatcher the foreground and names the
// first-choice own indexer: one retired in the foreground leaves the one that remains named. In the background it
// tells the dispatcher so and names nothing.
func TestTheFirstChoiceIsNamedAgainOnAConfigChange(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	second := testSearchRemoteMoreOwn(t, team, "dana nas two")[0]
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	foreground := NewMonitorValue(true)
	notify := make(chan func(), 1)
	fixture.client.args.Foreground = foreground.Get
	fixture.client.args.ConfigWatch = func(callback func()) func() {
		notify <- callback
		return func() {}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		fixture.client.follow(ctx, fixture.transport)
	}()
	defer func() {
		cancel()
		<-done
	}()
	first := fixture.transport.awaitNamed(t, 1)[0]
	if foregrounds := fixture.transport.awaitForegrounds(t, 1); !foregrounds[0] {
		t.Errorf("told %v", foregrounds)
	}
	retired, remaining := team.danaNas, second
	if first == second.sidecarId {
		retired, remaining = second, team.danaNas
	} else if first != team.danaNas.sidecarId {
		t.Fatalf("named %s, not an own indexer", first)
	}
	callback := <-notify
	team.net.mustPost(retired, bridge.SignedType_SIGNED_INDEXER_SET, team.net.indexerSet(retired, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	callback()
	if again := fixture.transport.awaitNamed(t, 2)[1]; again != remaining.sidecarId {
		t.Errorf("named again %s, want the remaining own indexer", again)
	}
	if fixture.transport.asks == nil || !fixture.transport.asks(remaining.sidecarId) {
		t.Errorf("bit 1 not set toward the remaining own indexer")
	}
	told := len(fixture.transport.awaitForegrounds(t, 2))
	foreground.Set(false)
	if foregrounds := fixture.transport.awaitForegrounds(t, told+1); foregrounds[len(foregrounds)-1] {
		t.Errorf("the background not told: %v", foregrounds)
	}
	if named := fixture.transport.namings(); len(named) != 2 {
		t.Errorf("named %v, the background naming one", named)
	}
}
