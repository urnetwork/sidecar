package main

import (
	"context"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The ordinary daemon control method signs and seals the services on the selected network. A
// second hosted network has its own independent designation and keychain.
func TestDaemonDesignatesSearchOnTheSelectedNetwork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	settings := enginenet.DefaultEnginesSettings()
	settings.FollowBeforeExchange = true
	engines := enginenet.NewEngines(t, net, settings)
	instance, err := net.StartInstance("indexer", &sidecartest.TestInstanceArgs{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	host := func() *sidecar.Sidecar {
		t.Helper()
		networkId := sidecar.NewId()
		engines.OpenNetwork(networkId)
		engines.Api().SetPersonalOwner(networkId, sidecar.NewId())
		running, err := instance.AddSidecarIn(networkId, nil)
		if err != nil {
			t.Fatal(err)
		}
		follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
		if _, err := follower.WaitStanding(ctx); err != nil {
			t.Fatal(err)
		}
		return running
	}
	first, second := host(), host()
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		for _, running := range []*sidecar.Sidecar{first, second} {
			if err := daemon.AddSidecar(*running.NetworkId(), running); err != nil {
				t.Fatal(err)
			}
		}
		for _, method := range urIndexerDesignationMethods(nil) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli, _, _ := newTestUrCli(daemon.socketPath)
	params := &urIndexerParams{Network: second.NetworkId().String(), Scope: int32(protocol.IndexerScope_INDEXER_SCOPE_NETWORK),
		Services: []int32{int32(protocol.IndexerService_INDEXER_SERVICE_SEARCH)}}
	if err := cli.callDaemon(ctx, urMethodIndexerDesignate, params, true, nil); err != nil {
		t.Fatal(err)
	}
	client := second.ConfigFollower().Client()
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	state := client.State()
	records := state.Indexers()
	if len(records) != 1 || records[0].SidecarId != second.Identity().SidecarId || len(first.ConfigFollower().Client().State().Indexers()) != 0 {
		t.Fatalf("designation on the selected network: %v", records)
	}
	repoId := sidecar.Id(state.Genesis().GetConfigRepoId())
	opener := sidecar.ConfigIndexerServicesOpener(func(generation uint64) *sidecar.EvsRepoKey {
		return second.GkmHeldKey(repoId, generation)
	})
	if services, opened := opener(records[0]); !opened || !slices.Equal(services, []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}) {
		t.Fatal("could not open the signed search service under the selected config generation")
	}
	if err := cli.callDaemon(ctx, urMethodIndexerRetireOne, params, true, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if records := client.State().Indexers(); len(records) != 0 {
		t.Fatalf("retired designation: %v", records)
	}
}
