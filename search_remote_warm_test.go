//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-33: the warm pairs and bit 1, DESIGN-DETAILS 7.6's search_remote_warm_test.go list as amended for QD-707:
// two own pairs named at the foreground, one with one own indexer, another member's as a third only in mode on with its
// notice answered and a repo no own indexer answers, the set named again on a config change, and a search asking at once
// only the set the foreground named.

import (
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// With two or more own indexers the foreground names two own pairs, own first, and no other member's where every repo
// has an own indexer.
func TestTheForegroundNamesTwoOwnPairs(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	more := testSearchRemoteMoreOwn(t, team, "dana nas two", "dana nas three")
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.warm(t)
	named := fixture.transport.marked[len(fixture.transport.marked)-1]
	if len(named) != fixture.settings.RemoteOwnAskCount {
		t.Fatalf("named %v", named)
	}
	for _, indexerId := range named {
		if indexerId != team.danaNas.sidecarId && !slices.ContainsFunc(more, func(device testConfigDevice) bool { return device.sidecarId == indexerId }) {
			t.Errorf("named %s, not own", indexerId)
		}
	}
	// bit 1 toward each own indexer, and none toward a device that is no indexer
	if !fixture.client.asksSearch(team.danaNas.sidecarId) || fixture.client.asksSearch(team.benPhone.sidecarId) {
		t.Errorf("bit 1 toward the wrong peers")
	}
}

// One own indexer: one own pair.
func TestOneOwnIndexerNamesOne(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.warm(t)
	if named := fixture.transport.marked[len(fixture.transport.marked)-1]; !slices.Equal(named, []Id{team.danaNas.sidecarId}) {
		t.Errorf("named %v", named)
	}
}

// Another member's pair is a third, beside the own ones, only in mode on, with its notice answered allowing, where some
// repo the device reads has no own indexer; none otherwise.
func TestAnotherMembersPairIsAThird(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	net := team.net
	// a repo Dana's phone reads that her NAS does not, which only the network indexers answer
	notes := testConfigId("shared notes")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: notes.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	for _, reader := range []testConfigDevice{team.danaPhone, team.agent} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: notes.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	fixture.warm(t)
	if named := fixture.transport.marked[len(fixture.transport.marked)-1]; len(named) != 1 {
		t.Fatalf("named before the notice: %v", named)
	}
	memberId, ok := searchRemoteNoticeMember(net.log.State(), team.agent.sidecarId)
	if !ok {
		t.Fatal("the agent names no notice member")
	}
	if err := fixture.world.state.SetAnswer(&memberId, true); err != nil {
		t.Fatal(err)
	}
	fixture.warm(t)
	// the agent's sponsor is the Owner's member, so the answer allows the Owner's device too: the first by otherKey
	named := fixture.transport.marked[len(fixture.transport.marked)-1]
	if len(named) != 2 || named[0] != team.danaNas.sidecarId || named[1] != team.agent.sidecarId && named[1] != net.owner.sidecarId {
		t.Fatalf("named after the notice: %v", named)
	}
	if err := fixture.world.state.SetMode(SearchRemoteOwn); err != nil {
		t.Fatal(err)
	}
	fixture.warm(t)
	if named := fixture.transport.marked[len(fixture.transport.marked)-1]; len(named) != 1 {
		t.Errorf("named in mode own: %v", named)
	}
	if fixture.client.asksSearch(team.agent.sidecarId) {
		t.Errorf("bit 1 toward another member's indexer in mode own")
	}
}

// In the foreground, a config change that retires a warm own indexer names the set again without it, and a move to the
// background tells the dispatcher.
func TestTheWarmSetIsNamedAgainOnAConfigChange(t *testing.T) {
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
	first := fixture.transport.awaitMarked(t, 1)[0]
	if len(first) != 2 {
		t.Fatalf("named %v", first)
	}
	callback := <-notify
	team.net.mustPost(second, bridge.SignedType_SIGNED_INDEXER_SET, team.net.indexerSet(second, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, true))
	callback()
	again := fixture.transport.awaitMarked(t, 2)[1]
	if !slices.Equal(again, []Id{team.danaNas.sidecarId}) {
		t.Errorf("named again %v", again)
	}
	if fixture.transport.asks == nil || !fixture.transport.asks(team.danaNas.sidecarId) {
		t.Errorf("bit 1 not set toward the own indexer")
	}
}

// A search asks at once only the set the foreground named: with no naming yet, the first own indexer alone.
func TestASearchAsksOnlyTheNamedWarmSetAtOnce(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	testSearchRemoteMoreOwn(t, team, "dana nas two")
	fixture := newTestSearchRemoteAsker(t, team, team.danaPhone)
	for _, indexer := range append(testSearchRemoteMoreOwnDevices(team), team.danaNas) {
		fixture.serve(t, indexer).corpus.serveText(team.danaVault, 5, testSearchRemoteDocs("vault ", 900)...)
	}
	testSearchRemoteNext(t, fixture.search(t, team.danaVault))
	if calls := fixture.transport.callsNow(); len(calls) != 1 {
		t.Errorf("with no warm set named, %d asked at once", len(calls))
	}
}

// The own indexers testSearchRemoteMoreOwn added, found by their labels.
func testSearchRemoteMoreOwnDevices(team *testConfigSearchTeam) []testConfigDevice {
	devices := []testConfigDevice{}
	for _, label := range []string{"dana nas two", "dana nas three"} {
		device := team.net.device(label, team.dana)
		if team.net.log.State().Sidecar(device.sidecarId) != nil {
			devices = append(devices, device)
		}
	}
	return devices
}
