//go:build !sidecar_http && !ios_extension

// The ACL writer's retiring-alias read (acl_writer_subjects.go) over the network's own label table, which now keeps a
// changed alias for its 90 days (§12.5, D-DNS-10): a plan naming the alias the network's zone moved from resolves it
// to the network until the alias's end and refuses it as unknown after, and a zone that names a retiring alias with
// api's end lets a writer that never saw it live resolve it until then.

package sidecar

import (
	"errors"
	"testing"
	"time"
)

// Answers zone from the next GET /dns/zone on.
func (self *testDnsBlock) setZone(zone *DnsZone) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.zone = zone
}

// A writer on the test network whose Sidecar and label table read clock, the dns block answering zone.
func newTestRetiringAliasWriter(t *testing.T, clock Clock, zone *DnsZone) (*testConfigNet, *Sidecar, *DnsClient, *testDnsBlock) {
	t.Helper()
	net := newTestConfigNet(t)
	zone.NetworkId = net.networkId
	running, _, client, block := newTestDnsLabelsSidecar(t, net.networkId, zone)
	running.clock = clock
	running.sidecarApi = newTestAclWriterDevice(t).sidecarApi
	return net, running, client, block
}

// The network ids a plan's preview resolved, by the text the policy named.
func testAclPlanNetworks(plan *AclSavePlan) map[string]Id {
	resolved := map[string]Id{}
	for _, row := range plan.Preview.Resolutions {
		if row.Kind == "network" {
			resolved[row.Text] = row.Id
		}
	}
	return resolved
}

// The zone moves the network's alias after the writer's table read it live: a plan naming the alias it moved from,
// beside the label and the new alias, resolves all three to the network, where before the table dropped the old one
// and the plan refused it; at the alias's end the old name is unknown again and the others still resolve.
func TestAclWriterResolvesAnAliasTheTableSawRetire(t *testing.T) {
	clock := newTestLabelClock()
	changed := clock.Now()
	net, running, client, block := newTestRetiringAliasWriter(t, clock, &DnsZone{Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "owner-team", Version: 1})
	state, head := net.log.State(), testConfigHead(t, net)
	labels, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Zone(t.Context()); err != nil {
		t.Fatal(err)
	}
	requireNetworkLabel(t, labels, "owner-team", false, net.networkId, NetworkLabelKindAlias)

	block.setZone(&DnsZone{NetworkId: net.networkId, Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "owner-next", Version: 2})
	source := []byte(`{"grants":[{"src":["network:owner-team","network:owner-next","network:a7q2m9x4k1"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	plan, err := running.aclWriterPlan(t.Context(), source, &AclWriterSubjects{}, state, head)
	if err != nil {
		t.Fatalf("a plan naming the alias the network moved from: %v", err)
	}
	resolved := testAclPlanNetworks(plan)
	if len(resolved) != 3 || resolved["owner-team"] != net.networkId || resolved["owner-next"] != net.networkId || resolved["a7q2m9x4k1"] != net.networkId {
		t.Fatalf("network preview: %+v", plan.Preview.Resolutions)
	}
	requireNetworkLabel(t, labels, "owner-team", false, net.networkId, NetworkLabelKindRetiringAlias)

	clock.set(changed.Add(DefaultNetworkLabelTableSettings().RetiringWindow))
	if _, err := running.aclWriterPlan(t.Context(), source, &AclWriterSubjects{}, state, head); !errors.Is(err, ErrNetworkLabelUnknown) {
		t.Fatalf("a plan naming the alias past its end: %v", err)
	}
	current := []byte(`{"grants":[{"src":["network:owner-next","network:a7q2m9x4k1"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	plan, err = running.aclWriterPlan(t.Context(), current, &AclWriterSubjects{}, state, head)
	if err != nil {
		t.Fatalf("a plan naming the live names past the old alias's end: %v", err)
	}
	if resolved := testAclPlanNetworks(plan); len(resolved) != 2 || resolved["owner-next"] != net.networkId || resolved["a7q2m9x4k1"] != net.networkId {
		t.Fatalf("network preview past the end: %+v", plan.Preview.Resolutions)
	}
}

// A writer whose table never held the old alias, as on a device enrolled after the change, reads it from the zone,
// which names it with api's end: the plan resolves it until then and refuses it from then on.
func TestAclWriterResolvesARetiringAliasTheZoneNames(t *testing.T) {
	clock := newTestLabelClock()
	end := clock.Now().Add(3 * 24 * time.Hour)
	net, running, _, _ := newTestRetiringAliasWriter(t, clock, &DnsZone{
		Root:            testLabelRoot,
		Label:           "a7q2m9x4k1",
		Alias:           "owner-next",
		RetiringAliases: []NetworkLabelRetiringAlias{{Alias: "owner-team", TombstoneTime: end}},
		Version:         7,
	})
	state, head := net.log.State(), testConfigHead(t, net)
	source := []byte(`{"grants":[{"src":["network:owner-team"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	plan, err := running.aclWriterPlan(t.Context(), source, &AclWriterSubjects{}, state, head)
	if err != nil {
		t.Fatalf("a plan naming the zone's retiring alias: %v", err)
	}
	if resolved := testAclPlanNetworks(plan); len(resolved) != 1 || resolved["owner-team"] != net.networkId {
		t.Fatalf("network preview: %+v", plan.Preview.Resolutions)
	}
	clock.set(end)
	if _, err := running.aclWriterPlan(t.Context(), source, &AclWriterSubjects{}, state, head); !errors.Is(err, ErrNetworkLabelUnknown) {
		t.Fatalf("a plan naming the zone's retiring alias at its end: %v", err)
	}
}
