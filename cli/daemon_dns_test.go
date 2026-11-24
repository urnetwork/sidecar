package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
	"google.golang.org/protobuf/proto"
)

// A component named as the core's dns component is, which adds only where the composition added none.
type testUrNamedComponent struct {
	name string
}

func (self *testUrNamedComponent) Name() string { return self.name }

func (self *testUrNamedComponent) Attach(env *sidecar.SidecarEnv) error { return nil }

func (self *testUrNamedComponent) Close() {}

// ur acl push of a document naming network:<net> through the stock daemon, on a network composed as network.start
// composes each one (daemon_dns.go before the follower): the it bridge case's finding (server/sidecare2e's
// it_bridge_shares_test.go), where no composition fed a DnsClient its label table, so the writer's label read opened
// the table on the Sidecar's classless store and every such push failed with "store has no file class". The network's
// dns component feeds its client the network's own table at its first generation, which keeps the alias the network
// was renamed from; the push names that retiring alias and the live label, previews both as the network, saves on a
// yes, and the signed head's resolution holds both, while the zone's own fetches keep the table's row.
func TestDaemonPushesAPolicyNamingANetworkLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	running, _, _ := bootstrapTestDaemonOwner(t, ctx, net, engines)
	networkId := running.Identity().NetworkId
	api := engines.Api()
	// the dns block's GET /dns/zone for the network's own sidecars: its label, its live alias and its version
	const label, alias, renamedFrom, root = "a7q2m9x4k1", "owner-team", "owner-old", "users.example"
	var zoneReads atomic.Int32
	api.ServeService("dns", http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		bearer, _ := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		principal, err := api.Authenticator().Authenticate(request.Context(), "dns", bearer)
		if err != nil || request.Method != http.MethodGet || request.URL.Path != sidecar.DnsZonePath || principal.NetworkId != connect.Id(networkId) {
			http.Error(w, "refused", http.StatusForbidden)
			return
		}
		zoneReads.Add(1)
		json.NewEncoder(w).Encode(&sidecar.DnsZone{NetworkId: networkId, Root: root, Label: label, Alias: alias, Version: 1})
	}))
	t.Cleanup(func() { api.ServeService("dns", nil) })

	// the zone watch's defaults ask public resolvers, which a test binary refuses, so it watches nothing here
	startUrDns(running, nil, sidecar.NewNoopLogger())
	if remove, err := running.AddComponent(&testUrNamedComponent{name: "dns"}); err == nil {
		remove()
		t.Fatal("the daemon's composition added no dns component")
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	if follower == nil {
		t.Fatal("no follower started")
	}
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// a generation attaches its components in the order they were added, so the follower standing means the dns
	// component has attached: its client feeds the network's table, which nothing in the test opened
	dns, err := running.Dns()
	if err != nil {
		t.Fatal(err)
	}
	labels := dns.Labels()
	if labels == nil {
		t.Fatal("the dns component fed the network's client no label table")
	}
	// what an earlier run of the network kept: the alias it was renamed from, in its 90 days of retiring (§12.5)
	if err := labels.SetNetwork(sidecar.NetworkLabelRow{Root: root, NetworkId: networkId, Label: label, Alias: alias, RetiringAliases: []string{renamedFrom}}); err != nil {
		t.Fatal(err)
	}
	quota := net.Fakes().Quota
	quota.SetEnforced(true)
	quota.SetLimits(connect.Id(networkId), &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{"acl_rules": 50, "acl_network_shares": 1}})
	daemon := startTestUrDaemon(t, shortTestDirectory(t), func(daemon *sidecar.Daemon) {
		if err := daemon.AddSidecar(networkId, running); err != nil {
			t.Fatal(err)
		}
		target := &urDaemonNetwork{daemon: daemon}
		if err := registerUrDaemonMethods(daemon, "test", target, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
			t.Fatal(err)
		}
	})
	policy := `{"grants":[{"src":["network:` + renamedFrom + `","network:` + label + `"],"dst":["autogroup:member"],"allow":["dial"]}]}`
	path := testUrAclPolicyFile(t, policy)
	cli, stdout, stderr := newTestUrCli(daemon.socketPath)
	cli.openTty = func() (urTty, error) {
		return &testTty{lines: []string{"yes"}}, nil
	}
	if code := cli.main(ctx, []string{"ur", "acl", "push", path}); code != urExitOk {
		t.Fatalf("ur acl push of a document naming network:%s and network:%s: exit %d, %s", renamedFrom, label, code, stderr)
	}
	for _, value := range []string{renamedFrom, label, networkId.String(), "in force from the base at"} {
		if !strings.Contains(stdout.String(), value) {
			t.Fatalf("missing %s in the push's output: %s", value, stdout)
		}
	}
	state := client.State()
	head, err := follower.Heads().ReadConfigHead(ctx, state.Base().GetConfigVersion(), state.Base().GetConfigHeadSha256())
	if err != nil || !bytes.Equal(head.File(sidecar.ConfigHeadPolicyPath), []byte(policy)) {
		t.Fatalf("the signed head's policy: %v", err)
	}
	resolution := &protocol.ConfigResolution{}
	if err := proto.Unmarshal(head.File(sidecar.ConfigHeadResolvePath), resolution); err != nil {
		t.Fatal(err)
	}
	resolved := map[string][]byte{}
	for _, row := range resolution.GetNetworks() {
		resolved[row.GetText()] = row.GetNetworkId()
	}
	if len(resolved) != 2 || !bytes.Equal(resolved[renamedFrom], networkId.Bytes()) || !bytes.Equal(resolved[label], networkId.Bytes()) {
		t.Fatalf("the signed head's network resolution: %v", resolution.GetNetworks())
	}
	if zoneReads.Load() == 0 {
		t.Fatal("the writer read no zone for the network's label")
	}
	rows := labels.Networks()
	if len(rows) != 1 || rows[0].Label != label || rows[0].Alias != alias || len(rows[0].RetiringAliases) != 1 || rows[0].RetiringAliases[0] != renamedFrom {
		t.Fatalf("the network's label table after the push: %+v", rows)
	}
}
