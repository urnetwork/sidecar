package dnsservice_test

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §12.6's last clause in the restore step (restore.go's steps 3b and 7; DNS-M6-07), FS-42's M6 step on a fake
// lbmap: the custom-host map raised 2^24 above the restored one, every host's version with it and its readiness
// cleared, so each stays pending until every interface is current again; the hosts the regenerated map adds or
// drops, as lbmap reports them, listed in the incident with one admin event a network; a rerun raising nothing
// more; and a step with no map store skipping the half and saying so.

// A restore whose NS both follow, over a map that stood at version 3 with two hosts ready and two interfaces.
type restoreMapTest struct {
	*restoreTest
	maps *sidecartest.FakeDnsCustomHostMapStore
}

func newRestoreMapTest(t testing.TB) *restoreMapTest {
	t.Helper()
	test := &restoreMapTest{restoreTest: newRestoreTest(t), maps: sidecartest.NewFakeDnsCustomHostMapStore()}
	step, err := dnsservice.NewRestoreStep(test.settings, &dnsservice.RestoreStepDeps{
		Store:          test.store,
		Restore:        test.restore,
		SoaReader:      test.ns,
		Clock:          test.clock,
		CustomHostMaps: test.maps,
	})
	if err != nil {
		t.Fatal(err)
	}
	test.step = step
	ctx := t.Context()
	if err := test.maps.SyncMapInterfaces(ctx, edgeTestRoot, []string{"lb-1", "lb-2"}); err != nil {
		t.Fatal(err)
	}
	test.maps.Raise(3, []string{"a.corp.example", "b.corp.example"}, test.clock.Now())
	if err := test.maps.SetCustomHostReadiness(ctx, edgeTestRoot, map[uint64]bool{3: true}, test.clock.Now()); err != nil {
		t.Fatal(err)
	}
	dumped := test.writeMany(t, 2)
	test.takeDump(t)
	test.loseAndLoad(t)
	test.ns.serve("ns1", uint32(dumped))
	test.ns.serve("ns2", uint32(dumped))
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	return test
}

// lbmap's report from name of version, adding and dropping hosts against the map it held.
func (self *restoreMapTest) report(t testing.TB, name string, version uint64, added []string, dropped []string) {
	t.Helper()
	err := self.maps.RecordMapReport(t.Context(), edgeTestRoot, &dnsservice.DnsCustomHostMapReport{
		Format: dnsservice.DnsFormat, Interface: name, Version: version, Digest: dnsservice.DnsCustomHostMapDigest([]string{"a.corp.example", "b.corp.example"}),
		Master: &dnsservice.DnsMapMaster{Pid: 7, StartTimeMillis: 1}, Added: added, Dropped: dropped,
	}, self.clock.Now(), self.settings.Probe.RouteHostCount, self.settings.Map.ReportHostMaxCount)
	if err != nil {
		t.Fatal(err)
	}
}

// The map rises 2^24 above the restored version, every host with it and none ready; the hosts each interface's
// load added or dropped are listed once each, by network, with one admin event a network; a rerun keeps the
// version and lists nothing twice.
func TestRestoreStepRaisesTheMapAndListsWhatItsLoadChanged(t *testing.T) {
	test := newRestoreMapTest(t)
	networkId := sidecar.NewId()
	test.maps.SetHostNetwork("b.corp.example", networkId)
	test.maps.SetHostNetwork("gone.corp.example", networkId)
	// lbmap held the lost primary's newer map, version 9: b came back with the dump, gone was added after it
	test.report(t, "lb-1", 9, nil, nil)
	test.report(t, "lb-2", 9, nil, nil)
	want := 9 + dnsservice.DnsRestoreSerialJump
	test.maps.SetRestoreRaiseHook(func(version uint64) {
		test.report(t, "lb-1", version, []string{"b.corp.example"}, []string{"gone.corp.example"})
		test.report(t, "lb-2", version, []string{"b.corp.example"}, []string{"gone.corp.example"})
	})
	incidentId := sidecar.NewId()
	progress := test.run(t, incidentId)
	if progress.MapVersion != want || progress.MapSkipped || progress.MapReportedCount != 2 || progress.MapInterfaceCount != 2 || !progress.Done {
		t.Fatalf("progress %+v", progress)
	}
	for _, host := range []string{"a.corp.example", "b.corp.example"} {
		if version := test.maps.HostVersion(host); version != want {
			t.Errorf("%s at version %d", host, version)
		}
		if _, ready := test.maps.Ready(host); ready {
			t.Errorf("%s ready across the restore", host)
		}
	}
	hosts := []string{}
	for _, entry := range progress.Listing.Entries {
		if entry.CustomHost == "" {
			continue
		}
		hosts = append(hosts, entry.CustomHost+" "+entry.CustomHostChange)
		if entry.NetworkId == nil || *entry.NetworkId != networkId {
			t.Errorf("%s listed for %v", entry.CustomHost, entry.NetworkId)
		}
	}
	if !slices.Equal(hosts, []string{"b.corp.example added", "gone.corp.example dropped"}) {
		t.Fatalf("listed %v", hosts)
	}
	if events := test.maps.IncidentEventNetworks(incidentId); len(events) != 1 || events[0] != networkId {
		t.Fatalf("admin events %v", events)
	}
	again := test.run(t, incidentId)
	if again.MapVersion != want {
		t.Fatalf("a rerun raised to %d", again.MapVersion)
	}
	count := 0
	for _, entry := range again.Listing.Entries {
		if entry.CustomHost != "" {
			count += 1
		}
	}
	if count != 2 {
		t.Fatalf("a rerun listed %d hosts", count)
	}
}

// An interface that has not reported the restored version is waited for up to restore.map_wait_s, and what came
// is listed then; a rerun lists what the late one reports.
func TestRestoreStepListsTheMapAfterItsWait(t *testing.T) {
	test := newRestoreMapTest(t)
	want := 3 + dnsservice.DnsRestoreSerialJump
	test.maps.SetRestoreRaiseHook(func(version uint64) {
		test.report(t, "lb-1", version, []string{"b.corp.example"}, nil)
	})
	incidentId := sidecar.NewId()
	type outcome struct {
		progress *dnsservice.DnsRestoreProgress
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		progress, err := test.step.Run(t.Context(), edgeTestRoot, incidentId)
		done <- outcome{progress: progress, err: err}
	}()
	// Keep the clock still through the SOA and diff reads. Once the step reads its
	// incident's map reports, advance a poll at a time until it lists them.
	var result outcome
	finished := false
	for !finished {
		reads, changed := test.maps.RestoreReportReads()
		if 1 <= reads {
			break
		}
		select {
		case result = <-done:
			finished = true
		case <-changed:
		}
	}
	start := test.clock.Now()
	for !finished {
		pending, added := test.clock.WatchTimers()
		select {
		case result = <-done:
			finished = true
			continue
		default:
		}
		if len(pending) == 0 {
			select {
			case result = <-done:
				finished = true
			case <-added:
			}
			continue
		}
		test.clock.Advance(time.Duration(test.settings.Restore.PollSeconds) * time.Second)
	}
	if result.err != nil || result.progress.MapReportedCount != 1 || result.progress.MapInterfaceCount != 2 {
		t.Fatalf("after the wait %+v %v", result.progress, result.err)
	}
	if waited := test.clock.Now().Sub(start); waited < time.Duration(test.settings.Restore.MapWaitSeconds)*time.Second {
		t.Fatalf("listed after %v, before restore.map_wait_s", waited)
	}
	test.report(t, "lb-2", want, []string{"c.corp.example"}, nil)
	again := test.run(t, incidentId)
	hosts := []string{}
	for _, entry := range again.Listing.Entries {
		if entry.CustomHost != "" {
			hosts = append(hosts, entry.CustomHost)
		}
	}
	if !slices.Equal(hosts, []string{"b.corp.example", "c.corp.example"}) {
		t.Fatalf("listed %v", hosts)
	}
}

// A step with no map store skips the half and says so; the RRsets' restore runs as before.
func TestRestoreStepWithNoMapStoreSaysItSkipped(t *testing.T) {
	test := newRestoreTest(t)
	dumped := test.writeMany(t, 2)
	test.takeDump(t)
	test.loseAndLoad(t)
	test.ns.serve("ns1", uint32(dumped))
	test.ns.serve("ns2", uint32(dumped))
	test.ns.follow("ns1", nil, nil)
	test.ns.follow("ns2", nil, nil)
	progress := test.run(t, sidecar.NewId())
	if !progress.MapSkipped || progress.MapVersion != 0 || !progress.Done {
		t.Fatalf("progress %+v", progress)
	}
}

// Every regained host and its network are listed, even after the next ordinary map has loaded.
func TestRestoreListsEveryHostBeyondProbeSample(t *testing.T) {
	test := newRestoreMapTest(t)
	added := []string{}
	networks := map[sidecar.Id]bool{}
	for index := range test.settings.Probe.RouteHostCount + 3 {
		host := fmt.Sprintf("site-%02d.example", index)
		networkId := sidecar.NewId()
		added = append(added, host)
		test.maps.SetHostNetwork(host, networkId)
		networks[networkId] = true
	}
	test.maps.SetRestoreRaiseHook(func(version uint64) {
		for _, name := range []string{"lb-1", "lb-2"} {
			test.report(t, name, version, added, nil)
			test.report(t, name, version+1, []string{"later.example"}, nil)
		}
		if err := test.maps.SyncMapInterfaces(t.Context(), edgeTestRoot, []string{"lb-2", "replacement"}); err != nil {
			t.Fatal(err)
		}
	})
	incident := sidecar.NewId()
	for range 2 {
		progress := test.run(t, incident)
		if !progress.Done || progress.MapReportedCount != 2 || len(progress.Listing.Entries) != len(added) {
			t.Fatalf("restored hosts: %+v", progress)
		}
		for _, entry := range progress.Listing.Entries {
			if !slices.Contains(added, entry.CustomHost) || entry.CustomHostChange != dnsservice.DnsRestoreCustomHostAdded {
				t.Fatalf("unexpected incident entry: %+v", entry)
			}
		}
		events := test.maps.IncidentEventNetworks(incident)
		if len(events) != len(networks) {
			t.Fatalf("listed %d of %d networks", len(events), len(networks))
		}
		for _, networkId := range events {
			if !networks[networkId] {
				t.Fatal("event for an unaffected network")
			}
		}
	}
}
