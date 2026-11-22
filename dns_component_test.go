//go:build !sidecar_http && !ios_extension

package sidecar

// The network's label table and the dns component (§12.5's label row; DNS-M2-01, DNS-M5-21): NetworkLabels opens the
// table in the network's dns/ directory under its own class and feeds it to the DnsClient, once; a writer's network:
// label read takes the retiring aliases that table kept, where before it opened the table on the Sidecar's classless
// store and failed (the it bridge case's finding); the component attaches the table and the zone's hints on each
// generation and ends them at its close; and an unchanged zone writes nothing.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
)

// A Sidecar enrolled in networkId on an instance in memory, its DnsClient on a fake block answering zone.
func newTestDnsLabelsSidecar(t *testing.T, networkId Id, zone *DnsZone) (*Sidecar, *SidecarInstance, *DnsClient, *testDnsBlock) {
	t.Helper()
	instance := newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore())
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	enrollTestNetwork(t, instance, networkId)
	running := &Sidecar{instance: instance, networkId: &networkId, settings: validSidecarSettings(), clock: RealClock{}}
	block := newTestDnsBlock(zone)
	client := newTestDnsClient(t, block, nil, networkId)
	running.dns.client = client
	return running, instance, client, block
}

// The table opens once, in dns/ under class dns, and every zone the client fetches from then on writes the network's
// row there, which a reopen reads; under another class the file does not open; a table a host fed the client stands
// in its place. Before the network is known nothing opens.
func TestNetworkLabelsOpenInTheNetworksDnsDirectory(t *testing.T) {
	unenrolled := &Sidecar{instance: newInstanceOn(t, NewSidecarMemoryBackend(), newFakeKeyStore()), settings: validSidecarSettings()}
	if _, err := unenrolled.NetworkLabels(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("before enrollment: %v", err)
	}
	networkId := testConfigId("labelled network")
	running, _, client, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "team-live", Version: 1})
	labels, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	if again, err := running.NetworkLabels(); err != nil || again != labels || client.Labels() != labels {
		t.Fatalf("a second call answered another table: %v", err)
	}
	if _, err := client.Zone(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, labels, "team-live", false, networkId, NetworkLabelKindAlias)
	store, err := running.LocalStore().Directory(dnsDirectoryName, dnsDirectoryName)
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, reopened, "a7q2m9x4k1", false, networkId, NetworkLabelKindLabel)
	requireNetworkLabel(t, reopened, "team-live", false, networkId, NetworkLabelKindAlias)
	otherClass, err := running.LocalStore().Directory(dnsDirectoryName, "search")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNetworkLabelTable(otherClass); err == nil {
		t.Fatal("the label table opened under another file class")
	}
	fed, err := OpenNetworkLabelTable(newTestDnsMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	client.FeedLabels(fed)
	if got, err := running.NetworkLabels(); err != nil || got != fed {
		t.Fatalf("the table a host fed: %v", err)
	}
}

// A locked keychain opens no table and feeds none, and the call after the unlock opens it.
func TestNetworkLabelsWaitForTheKeychain(t *testing.T) {
	networkId := testConfigId("locked network")
	running, instance, client, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Version: 1})
	instance.Lock()
	if _, err := running.NetworkLabels(); !errors.Is(err, ErrSidecarStoreLocked) {
		t.Fatalf("while locked: %v", err)
	}
	if client.Labels() != nil {
		t.Fatal("a locked keychain fed the client a table")
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	if labels, err := running.NetworkLabels(); err != nil || labels == nil || client.Labels() != labels {
		t.Fatalf("after the unlock: %v", err)
	}
}

// The it bridge case's finding (server/sidecare2e's it_bridge_shares_test.go): a writer whose client no composition
// fed a table read its retiring aliases from a table opened on the Sidecar's classless LocalStore, so every plan naming
// network:<net> failed with ErrSidecarStoreNoClass. It now reads the network's own table, which an earlier run left
// holding the alias the network was renamed from: the plan resolves that retiring alias and the live label, and the
// writer's fetch writes the zone's row, keeping the retiring alias.
func TestAclWriterReadsTheNetworksOwnLabelTable(t *testing.T) {
	net := newTestConfigNet(t)
	state, head := net.log.State(), testConfigHead(t, net)
	running, _, client, _ := newTestDnsLabelsSidecar(t, net.networkId, &DnsZone{NetworkId: net.networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "owner-team", Version: 1})
	running.sidecarApi = newTestAclWriterDevice(t).sidecarApi
	store, err := running.LocalStore().Directory(dnsDirectoryName, dnsDirectoryName)
	if err != nil {
		t.Fatal(err)
	}
	kept, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	if err := kept.SetNetwork(NetworkLabelRow{Root: testLabelRoot, NetworkId: net.networkId, Label: "a7q2m9x4k1", Alias: "owner-team", RetiringAliases: []string{"owner-old"}}); err != nil {
		t.Fatal(err)
	}
	if client.Labels() != nil {
		t.Fatal("the case needs a client nothing fed")
	}
	source := []byte(`{"grants":[{"src":["network:owner-old","network:a7q2m9x4k1"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	plan, err := running.aclWriterPlan(t.Context(), source, &AclWriterSubjects{}, state, head)
	if err != nil {
		t.Fatalf("a plan naming the network's retiring alias and label: %v", err)
	}
	resolved := map[string]Id{}
	for _, row := range plan.Preview.Resolutions {
		if row.Kind == "network" {
			resolved[row.Text] = row.Id
		}
	}
	if len(resolved) != 2 || resolved["owner-old"] != net.networkId || resolved["a7q2m9x4k1"] != net.networkId {
		t.Fatalf("network preview: %+v", plan.Preview.Resolutions)
	}
	if client.Labels() == nil {
		t.Fatal("the writer read a table it did not feed the client")
	}
	reopened, err := OpenNetworkLabelTable(store)
	if err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, reopened, "owner-team", false, net.networkId, NetworkLabelKindAlias)
	requireNetworkLabel(t, reopened, "owner-old", false, net.networkId, NetworkLabelKindRetiringAlias)
	requireNetworkLabelUnknown(t, reopened, "owner-unheld", false)
}

// One subscription a fake push took: its callback and whether it was removed.
type testDnsSubscription struct {
	callback   PushNoticeFunction
	removed    chan struct{}
	removeOnce sync.Once
}

// A fake Subprotocol.Subscribe that hands each subscription to subscriptions, failing t for any topic but dns.
func testDnsSubscribe(t *testing.T, subscriptions chan *testDnsSubscription) DnsHintSubscribeFunction {
	return func(topic string, callback PushNoticeFunction) (func(), error) {
		if topic != PushTopicDns {
			t.Errorf("subscribed to %s", topic)
		}
		subscription := &testDnsSubscription{callback: callback, removed: make(chan struct{})}
		subscriptions <- subscription
		return func() { subscription.removeOnce.Do(func() { close(subscription.removed) }) }, nil
	}
}

// The subscription a fake push took by now.
func requireTestDnsSubscription(t *testing.T, subscriptions chan *testDnsSubscription) *testDnsSubscription {
	t.Helper()
	select {
	case subscription := <-subscriptions:
		return subscription
	default:
		t.Fatal("no dns hint subscription")
		return nil
	}
}

// Each generation's attach feeds the client the network's table and subscribes the zone's hints, a hint above the held
// version refetching on the client's loop; the next generation's attach replaces the subscription; a keychain that is
// locked at an attach opens no table but still subscribes, and the next attach opens it; and Close removes the
// subscription and ends the loop, so a later hint fetches nothing. An env with no Subprotocol attaches the table alone.
func TestDnsComponentAttachesTheTableAndTheHints(t *testing.T) {
	networkId := testConfigId("hinted network")
	running, instance, client, block := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Version: 3})
	component := running.NewDnsComponent()
	if component.Name() != "dns" || checkSidecarComponentName(component.Name()) != nil {
		t.Fatalf("component name %q", component.Name())
	}
	dns := component.(*dnsComponent)
	subscriptions := make(chan *testDnsSubscription, 4)
	log := NewNoopLogger()

	instance.Lock()
	dns.attach(t.Context(), testDnsSubscribe(t, subscriptions), log)
	locked := requireTestDnsSubscription(t, subscriptions)
	if client.Labels() != nil {
		t.Fatal("a locked keychain's attach fed a table")
	}
	if err := instance.Unlock(nil); err != nil {
		t.Fatal(err)
	}
	dns.attach(t.Context(), testDnsSubscribe(t, subscriptions), log)
	first := requireTestDnsSubscription(t, subscriptions)
	select {
	case <-locked.removed:
	default:
		t.Fatal("the next attach kept the last generation's subscription")
	}
	labels := client.Labels()
	if labels == nil {
		t.Fatal("the attach fed the client no table")
	}
	if held, err := running.NetworkLabels(); err != nil || held != labels {
		t.Fatalf("the table attached is not the network's: %v", err)
	}
	requireNetworkLabelUnknown(t, labels, "a7q2m9x4k1", false)
	first.callback(PushNotice{Topic: PushTopicDns, Version: 4, Kind: uint32(protocol.MessageType_DNS_ZONE_CHANGED)})
	if count := <-block.fetched; count != 1 {
		t.Fatalf("the hint's fetch was the block's %d", count)
	}

	// the next generation's subscription replaces the first, joining its loop, whose fetch has written its row by then
	ctx, cancel := context.WithCancel(t.Context())
	dns.attach(ctx, testDnsSubscribe(t, subscriptions), log)
	second := requireTestDnsSubscription(t, subscriptions)
	select {
	case <-first.removed:
	default:
		t.Fatal("the next generation's attach kept the first subscription")
	}
	requireNetworkLabel(t, labels, "a7q2m9x4k1", false, networkId, NetworkLabelKindLabel)
	if version := client.Version(); version != 3 {
		t.Fatalf("the hint's fetch holds version %d", version)
	}
	cancel()
	component.Close()
	select {
	case <-second.removed:
	default:
		t.Fatal("Close kept the subscription")
	}
	second.callback(PushNotice{Topic: PushTopicDns, Version: 9, Kind: uint32(protocol.MessageType_DNS_ZONE_CHANGED)})
	if zones, _ := block.counts(); zones != 1 {
		t.Fatalf("a hint after Close fetched: %d fetches", zones)
	}

	bare, _, bareClient, _ := newTestDnsLabelsSidecar(t, networkId, &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Version: 1})
	if err := bare.NewDnsComponent().Attach(&SidecarEnv{Ctx: t.Context(), Log: log}); err != nil || bareClient.Labels() == nil {
		t.Fatalf("an env with no push: %v", err)
	}
}

// A change that leaves every row as it was writes nothing, so a fed client's fetch of an unchanged zone costs no sealed
// write: with every write failing, the same zone again succeeds and a moved alias fails, changing nothing.
func TestNetworkLabelTableWritesNothingUnchanged(t *testing.T) {
	networkId := NewId()
	table, store := testNetworkLabelTable(t)
	zone := &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "team-live", Version: 1}
	if err := table.SetZoneLabel(zone); err != nil {
		t.Fatal(err)
	}
	store.failWritesAfter(0)
	if err := table.SetZoneLabel(zone); err != nil {
		t.Fatalf("an unchanged zone wrote: %v", err)
	}
	if err := table.RemoveNetwork(NewId()); err != nil {
		t.Fatalf("removing a network the table does not hold wrote: %v", err)
	}
	moved := *zone
	moved.Alias = "team-next"
	if err := table.SetZoneLabel(&moved); err == nil {
		t.Fatal("a moved alias wrote through a failing store")
	}
	requireNetworkLabel(t, table, "team-live", false, networkId, NetworkLabelKindAlias)
	requireNetworkLabelUnknown(t, table, "team-next", false)
}
