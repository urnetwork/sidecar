//go:build !sidecar_http && !ios_extension

package sidecar

// SEARCH-M10-32: 7.2.2's verdict table, DESIGN-DETAILS 7.6's search_remote_eligible_test.go list, over the Team of
// TEAM-M10-02's tests and a personal network: each coverage row, the first that holds; 7.1's A on real code; a personal
// network's network-scope indexer answering its owner.

import (
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Every row of 7.2.2 that the config decides, over the Team: each searcher, repo and indexer with the row it gets.
func TestEligibleTable(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	state := team.net.log.State()
	configRepoId := Id(state.Genesis().GetConfigRepoId())
	cases := []struct {
		label     string
		indexer   testConfigDevice
		requester testConfigDevice
		repoId    Id
		want      protocol.SearchServed
	}{
		{label: "a member's own vault on its own indexer", indexer: team.danaNas, requester: team.danaPhone, repoId: team.danaVault, want: protocol.SearchServed_SERVED_TEXT},
		{label: "a member's own mailbox", indexer: team.danaNas, requester: team.danaPhone, repoId: team.danaMailbox, want: protocol.SearchServed_SERVED_TEXT},
		{label: "a shared vault on its owner's indexer", indexer: team.danaNas, requester: team.benPhone, repoId: team.danaVault, want: protocol.SearchServed_SERVED_TEXT},
		{label: "a shared vault on the reader's own indexer", indexer: team.benNas, requester: team.benPhone, repoId: team.danaVault, want: protocol.SearchServed_REFUSED_NOT_CONSENTED},
		{label: "a vault the requester does not read", indexer: team.benNas, requester: team.danaPhone, repoId: team.benVault, want: protocol.SearchServed_REFUSED_NOT_READER},
		{label: "the audit reader", indexer: team.danaNas, requester: team.auditorLaptop, repoId: team.danaVault, want: protocol.SearchServed_REFUSED_NOT_CONSENTED},
		{label: "a network indexer and a vault", indexer: team.net.owner, requester: team.danaPhone, repoId: team.danaVault, want: protocol.SearchServed_REFUSED_NOT_CONSENTED},
		{label: "a tagged indexer and a vault", indexer: team.agent, requester: team.benPhone, repoId: team.danaVault, want: protocol.SearchServed_REFUSED_NOT_CONSENTED},
		{label: "a secret", indexer: team.danaNas, requester: team.danaPhone, repoId: team.danaSecret, want: protocol.SearchServed_REFUSED_NOT_READER},
		{label: "the config", indexer: team.danaNas, requester: team.danaPhone, repoId: configRepoId, want: protocol.SearchServed_REFUSED_NOT_READER},
		{label: "an unknown repo", indexer: team.danaNas, requester: team.danaPhone, repoId: testConfigId("no such repo"), want: protocol.SearchServed_REFUSED_NOT_READER},
		{label: "a team repo on the member's indexer", indexer: team.danaNas, requester: team.danaPhone, repoId: team.teamRepo, want: protocol.SearchServed_SERVED_TEXT},
		{label: "a team repo on another member's indexer", indexer: team.benNas, requester: team.danaPhone, repoId: team.teamRepo, want: protocol.SearchServed_REFUSED_SCOPE},
		{label: "a team repo on a network indexer", indexer: team.agent, requester: team.danaPhone, repoId: team.teamRepo, want: protocol.SearchServed_SERVED_TEXT},
		{label: "a team repo the indexer does not read", indexer: team.auditorNas, requester: team.auditorLaptop, repoId: team.teamRepo, want: protocol.SearchServed_REFUSED_NOT_READER},
	}
	for _, c := range cases {
		got, ok := searchRemoteConfigVerdict(state, c.indexer.sidecarId, c.requester.sidecarId, c.repoId, testConfigSearchServices)
		if got != c.want || ok != (c.want == protocol.SearchServed_SERVED_TEXT) {
			t.Errorf("%s: %d (%v), want %d", c.label, got, ok, c.want)
		}
	}
}

// 7.1's A, RemoteAskTwin-LandedRule on real code: Ben's NAS, Ben's search indexer, reads Dana's vault by a share and is
// still never let answer it, by the verdict and by the asker's own predicate.
func TestAnOwnerBoundRepoNeedsItsOwnersDevice(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	state := team.net.log.State()
	if served, _ := searchRemoteConfigVerdict(state, team.benNas.sidecarId, team.benPhone.sidecarId, team.danaVault, testConfigSearchServices); served != protocol.SearchServed_REFUSED_NOT_CONSENTED {
		t.Errorf("the reader's own indexer: %d", served)
	}
	if served, ok := searchRemoteConfigVerdict(state, team.danaNas.sidecarId, team.benPhone.sidecarId, team.danaVault, testConfigSearchServices); !ok {
		t.Errorf("the owner's indexer: %d", served)
	}
}

// A personal network's designations are network scope and cover its owner's repos: its NAS answers the owner's
// mailbox. A second member ends that.
func TestAPersonalNetworksIndexerAnswersItsOwner(t *testing.T) {
	net := newTestConfigNet(t)
	phone, nas := net.device("owner phone", net.ownerMemberId), net.device("owner nas", net.ownerMemberId)
	net.admitDevice(net.owner, phone, 0)
	net.admitDevice(net.owner, nas, 0)
	mailbox := testConfigId("owner mailbox")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: mailbox.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX})
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(nas, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false))
	if served, ok := searchRemoteConfigVerdict(net.log.State(), nas.sidecarId, phone.sidecarId, mailbox, testConfigSearchServices); !ok {
		t.Errorf("a personal network's indexer: %d", served)
	}
	if !searchRemoteOwn(net.log.State(), nas.sidecarId, phone.sidecarId) {
		t.Errorf("a personal network's indexer is not own")
	}
	net.consentedMember("second")
	if served, _ := searchRemoteConfigVerdict(net.log.State(), nas.sidecarId, phone.sidecarId, mailbox, testConfigSearchServices); served != protocol.SearchServed_REFUSED_SCOPE {
		t.Errorf("a network of two: %d", served)
	}
}

// The eight rows in order, the first that holds: a repo the requester does not read is not reader whatever else fails;
// an owner-bound repo on an unconsented indexer is not consented before its scope is judged; and the corpus's rows
// follow only where the config's let a repo through.
func TestCoverageVerdictOrder(t *testing.T) {
	team := newTestConfigSearchTeam(t)
	state := team.net.log.State()
	// not a reader first, though the tagged indexer is not consented for Ben's vault either
	if served, _ := searchRemoteConfigVerdict(state, team.agent.sidecarId, team.danaPhone.sidecarId, team.benVault, testConfigSearchServices); served != protocol.SearchServed_REFUSED_NOT_READER {
		t.Errorf("not a reader and not consented: %d", served)
	}
	// not consented before scope: the Owner's network indexer and Dana's vault, read by a share
	if served, _ := searchRemoteConfigVerdict(state, team.net.owner.sidecarId, team.danaPhone.sidecarId, team.danaVault, testConfigSearchServices); served != protocol.SearchServed_REFUSED_NOT_CONSENTED {
		t.Errorf("not consented and out of scope: %d", served)
	}
	// the corpus's rows only for what passes: a refused repo never reaches it
	fixture := newTestSearchRemoteServer(t, team, team.danaNas)
	off := fixture.corpus.serveText(team.danaMailbox, 1)
	off.row.served = protocol.SearchServed_REFUSED_INDEX_OFF
	reply := fixture.page(t, team.danaPhone, testSearchRemoteRequest(t, fixture.wire, 1, 0, "plan", team.benVault, team.danaMailbox), 1, 0)
	if got := []uint32{reply.GetCoverage()[0].GetServed(), reply.GetCoverage()[1].GetServed()}; got[0] != uint32(protocol.SearchServed_REFUSED_NOT_READER) || got[1] != uint32(protocol.SearchServed_REFUSED_INDEX_OFF) {
		t.Errorf("rows %v", got)
	}
}
