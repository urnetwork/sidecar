//go:build sidecar_testhooks

// ur daemon's label refresh in a world as network.start composes it (startUrNetworkLabels): sidecartest's FakeApi
// serves GET /sidecar/label, so each network's refresh, attached by its Sidecar's own client generation, files the
// names the Net's api gives that network in that network's own table under the user root, and the daemon resolves a
// `.ur` naming each to its network. The refresh's write to the table is its linearization point
// (dns_label_refresh.go), which this test waits at, so no row here is filed by hand; the barrier links only on this
// leg, and daemon_label_resolution_test.go's push runs on both.

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Two networks of one instance, each with its label refresh composed as network.start composes it: one's label and
// alias set at the Net's api, the other's label drawn at its first read. Each table resolves its own network's names
// as filed, and the daemon resolves `.ur` by each. On the code before, the Net's api served no GET /sidecar/label, so
// each composed refresh was refused 404 for good and its table held nothing.
func TestDaemonLabelRefreshFilesEachNetworksNamesFromApi(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	api, err := net.Api()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := net.StartInstance("daemon", &sidecartest.TestInstanceArgs{Settings: func() *sidecar.SidecarSettings {
		settings := sidecar.DefaultSidecarSettings()
		settings.UserRoot = testUrLabelRoot
		return settings
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)

	type labeledNetwork struct {
		networkId sidecar.Id
		// what the Net's api names it, nil to draw its label at its first read
		set     *sidecartest.FakeApiNetworkLabel
		running *sidecar.Sidecar
	}
	alpha := &labeledNetwork{networkId: sidecar.NewId(), set: &sidecartest.FakeApiNetworkLabel{Label: "a7q2m9x4k1", Alias: "team-alpha"}}
	bravo := &labeledNetwork{networkId: sidecar.NewId()}
	barriers := net.Barriers()
	for _, network := range []*labeledNetwork{alpha, bravo} {
		if network.set != nil {
			if err := api.SetNetworkLabel(network.networkId, network.set); err != nil {
				t.Fatal(err)
			}
		}
		// held just past the refresh's write to the network's table
		site := sidecartest.BarrierSite("dns.label_refresh.after", network.networkId.String())
		if err := barriers.Arm(site, "", 0); err != nil {
			t.Fatal(err)
		}
		running, err := instance.AddSidecarIn(network.networkId, nil)
		if err != nil {
			t.Fatal(err)
		}
		startUrNetworkLabels(running, nil, sidecar.NewNoopLogger())
		if err := barriers.AwaitHeld(ctx, site, ""); err != nil {
			t.Fatalf("network %s's label refresh: %v", network.networkId, err)
		}
		if err := barriers.Release(site); err != nil {
			t.Fatal(err)
		}
		network.running = running
	}
	bravoNames, ok := api.NetworkLabel(bravo.networkId)
	if !ok {
		t.Fatal("bravo's refresh drew no label at the api")
	}
	names := map[string]*labeledNetwork{"a7q2m9x4k1": alpha, "team-alpha": alpha, bravoNames.Label: bravo}
	kinds := map[string]sidecar.NetworkLabelKind{"a7q2m9x4k1": sidecar.NetworkLabelKindLabel, "team-alpha": sidecar.NetworkLabelKindAlias, bravoNames.Label: sidecar.NetworkLabelKindLabel}
	for name, network := range names {
		table, err := network.running.NetworkLabels()
		if err != nil {
			t.Fatal(err)
		}
		if resolved, kind, err := table.ResolveNetworkLabel(testUrLabelRoot, name, false); err != nil || resolved != network.networkId || kind != kinds[name] {
			t.Errorf("network %s's table resolves %q to %s %s %v", network.networkId, name, resolved, kind, err)
		}
	}

	home := t.TempDir()
	directory := shortTestDirectory(t)
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     filepath.Join(directory, "s"),
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
		LabelRoot:      testUrLabelRoot,
		Home:           home,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []*labeledNetwork{alpha, bravo} {
		if err := daemon.AddSidecar(network.networkId, network.running); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		daemon.Run()
	}()
	t.Cleanup(func() {
		daemon.Close()
		<-done
	})
	for name, network := range names {
		project := filepath.Join(home, "project-"+name)
		writeTestUrDotUr(t, project, name)
		if resolved, err := daemon.ResolveNetwork(&sidecar.DaemonHello{Mode: sidecar.DaemonModeMcp, Cwd: project}, ""); err != nil || resolved != network.networkId {
			t.Errorf(".ur naming %q resolves to %s %v", name, resolved, err)
		}
	}
}
