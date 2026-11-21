package main

import (
	"bytes"
	"context"
	"slices"
	"strings"
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
		budget, err := sidecar.NewSidecarRemoteBudget(sidecar.DefaultSidecarSettings().Search, nil)
		if err != nil {
			t.Fatal(err)
		}
		hosted := &urDaemonNetwork{daemon: daemon, searchBudget: budget}
		for _, running := range []*sidecar.Sidecar{first, second} {
			if err := hosted.addSidecar(*running.NetworkId(), running); err != nil {
				t.Fatal(err)
			}
		}
		for _, method := range urIndexerDesignationMethods(nil) {
			if err := daemon.RegisterMethod(method); err != nil {
				t.Fatal(err)
			}
		}
	})
	cli := newUnitTestUrCli(t, daemon.socketPath, t.TempDir(), &testUnitRunner{})
	cli.openTty = func() (urTty, error) { return &testTty{lines: []string{"yes"}}, nil }
	var output bytes.Buffer
	cli.stdout = &output
	command := func(args ...string) string {
		t.Helper()
		output.Reset()
		if code := cli.main(ctx, append([]string{"ur", "indexer"}, args...)); code != urExitOk {
			t.Fatalf("indexer %v: %d: %v", args, code, cli.stderr)
		}
		return output.String()
	}
	selected := "--network=" + second.NetworkId().String()
	command("add", "--services=search", selected)
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
	if shown := command("ls", selected); !strings.Contains(shown, second.Identity().SidecarId.String()) {
		t.Fatalf("selected network indexers: %s", shown)
	}
	if shown := command("ls", "--network="+first.NetworkId().String()); !strings.Contains(shown, "no indexer") {
		t.Fatalf("first network indexers: %s", shown)
	}
	command("rm", selected)
	if err := client.CatchUp(ctx); err != nil {
		t.Fatal(err)
	}
	if records := client.State().Indexers(); len(records) != 0 {
		t.Fatalf("retired designation: %v", records)
	}
}
