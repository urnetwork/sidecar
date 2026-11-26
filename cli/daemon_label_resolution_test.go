package main

// ur daemon's label resolution through its composition (daemon_labels.go; sidecar's daemon_labels.go and
// dns_label_refresh.go): a daemon hosting two networks of one instance, each composed as network.start composes one
// (its dns component, its label refresh, then its follower) and each label table holding its own network's row, the
// one its refresh reads from the Net's api (sidecartest's FakeApi serves GET /sidecar/label), resolves `.ur`'s network
// under the settings' user root, so ur acl push in a project whose `.ur` names one network's label plans and saves on
// that network alone, and the other's head keeps what it held; with no `.ur` the push answers ambiguous before
// planning anything, naming both networks by their labels, where before this the daemon named them by id and no `.ur`
// could pick either. The engines keep evs and gkm open to both networks, the first bootstrap's after the second's.

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/sidecartest/enginenet"
)

// The test's user root, synthetic.
const testUrLabelRoot = "users.example"

// One network of the test's instance: bootstrapped on the engines as its first device, then composed as network.start
// composes each network, its follower standing.
type testUrLabelNetwork struct {
	networkId sidecar.Id
	label     string
	running   *sidecar.Sidecar
	follower  *sidecar.SidecarConfigFollower
	client    *sidecar.ConfigClient
}

// Enrolls a further network on instance, its label at the Net's api, bootstraps it, composes it and files label as its
// own row in its own table.
func newTestUrLabelNetwork(t *testing.T, ctx context.Context, instance *sidecartest.TestInstance, engines *enginenet.Engines, label string) *testUrLabelNetwork {
	t.Helper()
	networkId := sidecar.NewId()
	// what the composed label refresh reads and files, named before it attaches, so no label is drawn in its place
	if err := engines.Api().SetNetworkLabel(networkId, &sidecartest.FakeApiNetworkLabel{Label: label}); err != nil {
		t.Fatal(err)
	}
	running, err := instance.AddSidecarIn(networkId, nil)
	if err != nil {
		t.Fatal(err)
	}
	gkm, err := urDaemonGkmClient(running)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engines.Bootstrap(ctx, &enginenet.BootstrapArgs{Sidecar: running, Gkm: gkm, OwnerMemberId: sidecar.NewId()}, nil); err != nil {
		t.Fatalf("network %s's bootstrap: %v", label, err)
	}
	// network.start's order: the dns component, the label refresh, then the follower, so a generation attaches the
	// first two before the follower stands
	startUrDns(running, nil, sidecar.NewNoopLogger())
	startUrNetworkLabels(running, nil, sidecar.NewNoopLogger())
	for _, name := range []string{"dns", "dns-label"} {
		if remove, err := running.AddComponent(&testUrNamedComponent{name: name}); err == nil {
			remove()
			t.Fatalf("the daemon's composition added no %s component", name)
		}
	}
	follower := startUrConfigFollower(running, sidecar.NewNoopLogger())
	if follower == nil {
		t.Fatal("no follower started")
	}
	client, err := follower.WaitStanding(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// the row the label refresh files from GET /sidecar/label's answer, filed here as well so the push does not wait on
	// that read, which this leg cannot observe; both write the same label, in either order
	// (TestDaemonLabelRefreshFilesEachNetworksNamesFromApi waits for the refresh's own write at its barrier)
	labels, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	if err := labels.SetNetwork(sidecar.NetworkLabelRow{Root: testUrLabelRoot, NetworkId: networkId, Label: label}); err != nil {
		t.Fatal(err)
	}
	return &testUrLabelNetwork{networkId: networkId, label: label, running: running, follower: follower, client: client}
}

// The policy file of the network's signed head as its follower holds it now.
func (self *testUrLabelNetwork) headPolicy(t *testing.T, ctx context.Context) []byte {
	t.Helper()
	base := self.client.State().Base()
	head, err := self.follower.Heads().ReadConfigHead(ctx, base.GetConfigVersion(), base.GetConfigHeadSha256())
	if err != nil {
		t.Fatal(err)
	}
	return head.File(sidecar.ConfigHeadPolicyPath)
}

// Two networks on one daemon: `.ur` naming either's label pushes that network's policy alone, and no `.ur` answers
// ambiguous naming both labels.
func TestDaemonPushesToTheNetworkDotUrNamesByLabel(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*urTestTimeout)
	defer cancel()
	net := sidecartest.NewNet(ctx, nil)
	t.Cleanup(net.Close)
	engines := enginenet.NewEngines(t, net, nil)
	instance, err := net.StartInstance("daemon", &sidecartest.TestInstanceArgs{Settings: func() *sidecar.SidecarSettings {
		settings := sidecar.DefaultSidecarSettings()
		settings.UserRoot = testUrLabelRoot
		return settings
	}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(instance.Close)
	// each bootstrap opens evs and gkm to its network beside the other's, so both push from here on
	alpha := newTestUrLabelNetwork(t, ctx, instance, engines, "a7q2m9x4k1")
	bravo := newTestUrLabelNetwork(t, ctx, instance, engines, "b3k8p2r6t0")
	// a team tier for each, as the single network's push has (daemon_dns_test.go)
	quota := net.Fakes().Quota
	quota.SetEnforced(true)
	for _, network := range []*testUrLabelNetwork{alpha, bravo} {
		quota.SetLimits(connect.Id(network.networkId), &sidecar.QuotaLimits{Tier: "team", Limits: map[string]int64{"acl_rules": 50}})
	}

	home := t.TempDir()
	directory := shortTestDirectory(t)
	socketPath := filepath.Join(directory, "s")
	daemon, err := sidecar.NewDaemon(context.Background(), &sidecar.DaemonSettings{
		Instance:       "test",
		StateDirectory: directory,
		SocketPath:     socketPath,
		Local:          sidecar.DefaultSidecarSettings().LocalSettings,
		Version:        sidecar.Version,
		LabelRoot:      testUrLabelRoot,
		Home:           home,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, network := range []*testUrLabelNetwork{alpha, bravo} {
		if err := daemon.AddSidecar(network.networkId, network.running); err != nil {
			t.Fatal(err)
		}
	}
	if err := registerUrDaemonMethods(daemon, "test", &urDaemonNetwork{daemon: daemon}, osKeyStoreKeyFile, func() []sidecar.SidecarHostCredentialStore { return nil }); err != nil {
		t.Fatal(err)
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

	push := func(cwd string, policy string) (int, string, string) {
		cli, stdout, stderr := newTestUrCli(socketPath)
		cli.cwd = func() (string, error) { return cwd, nil }
		cli.openTty = func() (urTty, error) {
			return &testTty{lines: []string{"yes"}}, nil
		}
		code := cli.main(ctx, []string{"ur", "acl", "push", testUrAclPolicyFile(t, policy)})
		return code, stdout.String(), stderr.String()
	}

	// no .ur: several networks and none chosen, each named by its own table's label
	bare := filepath.Join(home, "bare")
	alphaBefore, bravoBefore := alpha.headPolicy(t, ctx), bravo.headPolicy(t, ctx)
	code, _, stderr := push(bare, `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	if code == urExitOk || !strings.Contains(stderr, "several networks") || !strings.Contains(stderr, alpha.label) ||
		!strings.Contains(stderr, bravo.label) {
		t.Fatalf("a push with no .ur: exit %d, %s", code, stderr)
	}
	if !bytes.Equal(alpha.headPolicy(t, ctx), alphaBefore) || !bytes.Equal(bravo.headPolicy(t, ctx), bravoBefore) {
		t.Fatal("a refused push changed a head")
	}

	// .ur naming each label: that network's head takes the policy, the other's keeps what it held
	for _, step := range []struct {
		network *testUrLabelNetwork
		other   *testUrLabelNetwork
		policy  string
	}{
		{network: alpha, other: bravo, policy: `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:member"],"allow":["dial"]}]}`},
		{network: bravo, other: alpha, policy: `{"grants":[{"src":["autogroup:member"],"dst":["autogroup:self"],"allow":["dial"]}]}`},
	} {
		project := filepath.Join(home, "project-"+step.network.label)
		writeTestUrDotUr(t, project, step.network.label)
		otherBefore := step.other.headPolicy(t, ctx)
		code, stdout, stderr := push(project, step.policy)
		if code != urExitOk || !strings.Contains(stdout, "in force from the base at") {
			t.Fatalf("a push where .ur names %s: exit %d, %s %s", step.network.label, code, stdout, stderr)
		}
		if !bytes.Equal(step.network.headPolicy(t, ctx), []byte(step.policy)) {
			t.Fatalf("network %s's head does not hold the policy pushed to it", step.network.label)
		}
		if !bytes.Equal(step.other.headPolicy(t, ctx), otherBefore) {
			t.Fatalf("a push to %s changed network %s's head", step.network.label, step.other.label)
		}
	}
}

// Writes a `.ur` naming network in directory, making it.
func writeTestUrDotUr(t *testing.T, directory string, network string) {
	t.Helper()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, ".ur"), []byte("network = \""+network+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
