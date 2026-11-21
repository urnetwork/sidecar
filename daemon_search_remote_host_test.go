//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http

package sidecar

import (
	"bytes"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// Stores a signed generation exactly as the key client records it after verification.
func testHostedSearchKey(t *testing.T, running *Sidecar, repoId Id, signer testConfigDevice) *EvsRepoKey {
	t.Helper()
	key, rotate, err := newGkmFirstGenerationOver(repoId, gkmTestId("hosted search group"), evsTestRepoKey(repoId, 1).repoKey,
		gkmTestArgs(GkmCauseRequest))
	if err != nil {
		t.Fatal(err)
	}
	generation := gkmTestGeneration(t, &gkmTestSigner{sidecarId: signer.sidecarId, privateKey: signer.key}, rotate)
	record, err := (&gkmHeldGeneration{generation: generation, key: key}).encode()
	if err != nil {
		t.Fatal(err)
	}
	secrets := running.instance.secrets(*running.NetworkId(), gkmUpkeepSecretsNamespace)
	if err := secrets.Put(gkmGenerationRecordName(repoId, 1), record); err != nil {
		t.Fatal(err)
	}
	return key
}

// A verified personal-network designation exposes only a complete local ref. The registered handler
// answers an admitted peer from the Sidecar's real cache without a fetch, then drops the designation.
func TestDaemonHostsRemoteSearchFromSignedDesignationAndHeldIndex(t *testing.T) {
	net := newTestConfigNet(t)
	requester := net.device("search reader", net.ownerMemberId)
	net.admitDevice(net.owner, requester, 0)
	repoId := evsTestId("hosted local search repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT,
	})
	host := newSearchTestSidecar(t, nil)
	running := host.sidecar
	if _, err := host.instance.createKeychain(net.networkId); err != nil {
		t.Fatal(err)
	}
	running.networkId = &net.networkId
	running.identity = &SidecarIdentity{NetworkId: net.networkId, SidecarId: net.owner.sidecarId, IdentityPublicKey: net.owner.publicKey()}
	leg := &sidecarConnectLeg{sidecar: running, budget: NewSubprotocolBudget(running.settings.ProtocolSettings, running.settings.MemoryBudgetByteCount)}
	running.leg = leg
	client := &ConfigClient{args: &ConfigClientArgs{NetworkId: net.networkId}}
	client.configLog.Store(net.log)
	running.configFollower.Store(&SidecarConfigFollower{client: client, state: NewMonitorValue(SidecarConfigFollowerStanding)})
	cache, err := running.SearchCache()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cache.Close)
	world := &testSyncWorld{
		cache:  &testSearchCacheWorld{instance: running.instance, networkId: net.networkId, cache: cache, settings: running.settings.Search, clock: newIdentityTestClock()},
		repoId: repoId, refId: evsTestId("held search ref"), head: testNewHeadWorld(), keepAll: true,
	}
	world.source = newTestSyncSource(t, world.head.ref, world.repoId, world.refId)
	world.restart(t)
	world.head.push(t, net.owner.sidecarId, testEngineDocument(t, "held", 1, 1, "notes/survey.md", "Harbor survey\nMeasurements"))
	world.round(t)
	refValid := true
	engine, err := NewSearchEngine(&SearchEngineArgs{
		Settings: running.settings.Search, Cache: cache, Sync: world.sync, Gkm: newGkmRefusingClient(),
		Scope: &testSearchScope{repos: []*SearchScopeRepo{{RepoId: repoId, Readable: true, Kind: protocol.RepoKind_REPO_KIND_VAULT,
			Refs: []*SearchScopeRef{{RefId: world.refId, Default: true, valid: func() bool { return refValid }}}}}}, Clock: running.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	removeEngine, err := running.InstallSearchEngine(engine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(removeEngine)
	daemon := &Daemon{}
	if err := daemon.AddSidecar(net.networkId, running); err != nil {
		t.Fatal(err)
	}
	budget, err := NewSidecarRemoteBudget(running.settings.Search, running.clock)
	if err != nil {
		t.Fatal(err)
	}
	stop, err := daemon.HostRemoteSearch(net.networkId, budget)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(stop)
	component := leg.componentList()[0].(*searchServeComponent)
	dispatcher := newSearchServeTestDispatcher()
	if registered := component.apply(dispatcher, nil); registered != nil {
		t.Fatal("served without a designation")
	}
	configId := Id(net.log.State().Genesis().GetConfigRepoId())
	configKey := evsTestRepoKey(configId, 1)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.sealedIndexerSet(net.owner,
		protocol.IndexerScope_INDEXER_SCOPE_NETWORK, configKey, protocol.IndexerService_INDEXER_SERVICE_SEARCH))
	if registered := component.apply(dispatcher, nil); registered != nil {
		t.Fatal("served without the sealed designation's key")
	}
	testHostedSearchKey(t, running, configId, net.owner)
	registered := component.apply(dispatcher, nil)
	if registered == nil || dispatcher.features != SubprotocolFeatureServesSearch {
		t.Fatal("a verified search designation did not register")
	}
	defer func() {
		if registered != nil {
			component.unregister(dispatcher, registered)
		}
	}()
	if leg.budget.memoryBudgetByteCount != running.settings.Search.DesignatedMemoryBudgetByteCount {
		t.Fatal("a signed designation did not raise this network's budget")
	}
	wire := &running.settings.ProtocolSettings.Search
	requestBody := func(id uint64) []byte {
		t.Helper()
		body, err := searchRemoteBuildRequest(&protocol.SearchRequest{SearchVersion: searchVersion, SearchId: id, Steps: 1,
			Scope: 1, Query: "survey", Repos: []*protocol.SearchRepo{{RepoId: repoId.Bytes()}}}, wire)
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	ask := func(id uint64) *protocol.SearchReply {
		t.Helper()
		body := requestBody(id)
		reply, err := dispatcher.handler(t.Context(), &SubprotocolRequest{Peer: &SubprotocolPeerIdentity{
			SidecarId: requester.sidecarId, IdentityPublicKey: requester.publicKey()}, Body: body})
		if err != nil {
			t.Fatal(err)
		}
		page, ok := searchRemoteParseReply(reply, 1, id, 0, wire)
		if !ok || len(page.Coverage) != 1 {
			t.Fatalf("no coverage for request %d: %v", id, page)
		}
		return page
	}
	if _, err := dispatcher.handler(t.Context(), &SubprotocolRequest{Peer: &SubprotocolPeerIdentity{
		SidecarId: requester.sidecarId, IdentityPublicKey: net.owner.publicKey()}}); err == nil {
		t.Fatal("the registered handler accepted a different admission key")
	}
	before := len(world.source.fetched())
	if page := ask(1); page.Coverage[0].Served != uint32(protocol.SearchServed_REFUSED_ALL_ABSENT) || len(page.Hits) != 0 {
		t.Fatalf("index key missing: %v", page)
	}
	testHostedSearchKey(t, running, repoId, net.owner)
	page := ask(2)
	if page.Coverage[0].Served != uint32(protocol.SearchServed_SERVED_INDEX) || len(page.Hits) != 1 ||
		page.Hits[0].Locator != "notes/survey.md" || !bytes.Equal(page.Coverage[0].RefId, world.refId.Bytes()) {
		t.Fatalf("held local index: %v", page)
	}
	if before != len(world.source.fetched()) {
		t.Fatal("a remote search triggered an EVS fetch")
	}
	// Losing the content pin invalidates even the byte-identical retry of an old page.
	refValid = false
	body := requestBody(2)
	reply, err := dispatcher.handler(t.Context(), &SubprotocolRequest{Peer: &SubprotocolPeerIdentity{
		SidecarId: requester.sidecarId, IdentityPublicKey: requester.publicKey()}, Body: body})
	if err != nil {
		t.Fatal(err)
	}
	if repeated, ok := searchRemoteParseReply(reply, 1, 2, 0, wire); !ok || repeated.Status != uint32(protocol.SearchStatus_SEARCH_CURSOR_EXPIRED) || len(repeated.Hits) != 0 {
		t.Fatalf("repeated a page after its pin changed: %v", repeated)
	}
	refValid = true
	// A bucket can be evicted while the last manifest still exists.
	snap := world.snapshot(t)
	for _, file := range snap.Files() {
		parsed, ok := indexParsePath(file.Path, false)
		if ok && parsed.kind == indexPathSlot {
			if err := cache.Remove(SearchCacheKey{RepoId: repoId, RefId: world.refId, Path: file.Path, Version: file.Version}); err != nil {
				t.Fatal(err)
			}
			break
		}
	}
	snap.Release()
	if page := ask(3); page.Coverage[0].Served != uint32(protocol.SearchServed_REFUSED_ALL_ABSENT) || len(page.Hits) != 0 {
		t.Fatalf("evicted bucket: %v", page)
	}
	// Locking the index store ends its cursors. The designation can open a new server on a later check.
	cache.Locked()
	if _, err := dispatcher.handler(t.Context(), &SubprotocolRequest{Peer: &SubprotocolPeerIdentity{
		SidecarId: requester.sidecarId, IdentityPublicKey: requester.publicKey()}, Body: body}); err == nil {
		t.Fatal("the old registration survived a cache lock")
	}
	previous := registered
	registered = component.apply(dispatcher, registered)
	if registered == nil || registered == previous {
		t.Fatal("the standing designation did not reopen after cache lock")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(net.owner, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, true))
	registered = component.apply(dispatcher, registered)
	if registered != nil || dispatcher.features != 0 || leg.budget.memoryBudgetByteCount != running.settings.MemoryBudgetByteCount {
		t.Fatal("retirement kept the handler, its feature, or its budget")
	}
}
