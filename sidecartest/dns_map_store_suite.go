// The conformance suite for dnsservice.DnsCustomHostMapStore (§13.4; DNS-M6-03): what api_map.go declares,
// run on FakeDnsCustomHostMapStore here and on dnshost.CustomHostMaps in server, so the fake stays honest
// (D-TEST-2). A version with its hosts is made each store's own way through the subject, as the model's raise
// makes one. Interface rows are the deployment's, so each case names interfaces of its own.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
)

// What the suite needs of a store's world beyond the interface.
type DnsCustomHostMapStoreSubject struct {
	Store dnsservice.DnsCustomHostMapStore
	// A root the store knows, with no version yet, a fresh one each call.
	NewRoot func(ctx context.Context) (string, error)
	// Makes the newest version of root's map hold exactly hosts, as the model's raise does, and answers it.
	Raise func(ctx context.Context, root string, hosts []string) (version uint64, err error)
	// Whether host has a ready time.
	HostReady func(ctx context.Context, root string, host string) (bool, error)
}

type dnsMapSuiteCase struct {
	name string
	run  func(ctx context.Context, subject *DnsCustomHostMapStoreSubject, root string, prefix string) error
}

// Runs every case on subject, each on a fresh root with interface names of its own.
func RunDnsCustomHostMapStoreSuite(t testing.TB, subject *DnsCustomHostMapStoreSubject) {
	t.Helper()
	for _, suiteCase := range dnsMapSuiteCases() {
		func() {
			ctx, cancel := context.WithTimeout(context.Background(), dnsSuiteCaseTimeout)
			defer cancel()
			root, err := subject.NewRoot(ctx)
			if err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
				return
			}
			prefix := "if" + sidecar.NewId().String()[28:] + "-"
			if err := suiteCase.run(ctx, subject, root, prefix); err != nil {
				t.Errorf("%s: %v", suiteCase.name, err)
			}
		}()
	}
}

// The state's row for name, or an error.
func dnsMapSuiteInterface(ctx context.Context, store dnsservice.DnsCustomHostMapStore, root string, name string) (*dnsservice.DnsMapInterface, error) {
	state, err := store.CustomHostMapState(ctx, root)
	if err != nil {
		return nil, err
	}
	for _, lbInterface := range state.Interfaces {
		if lbInterface.Name == name {
			return lbInterface, nil
		}
	}
	return nil, fmt.Errorf("no row for %s", name)
}

func dnsMapSuiteCases() []dnsMapSuiteCase {
	suiteTime := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	master := &dnsservice.DnsMapMaster{Pid: 4242, StartTimeMillis: suiteTime.UnixMilli()}
	return []dnsMapSuiteCase{
		{
			name: "no version before a raise, then the newest with its hosts and digest",
			run: func(ctx context.Context, subject *DnsCustomHostMapStoreSubject, root string, prefix string) error {
				customHostMap, err := subject.Store.CustomHostMap(ctx, root)
				if err != nil || customHostMap != nil {
					return fmt.Errorf("before a raise: %+v %v", customHostMap, err)
				}
				hosts := []string{"www.b.example", "shop.a.example"}
				version, err := subject.Raise(ctx, root, hosts)
				if err != nil {
					return err
				}
				customHostMap, err = subject.Store.CustomHostMap(ctx, root)
				if err != nil || customHostMap == nil {
					return fmt.Errorf("after a raise: %+v %v", customHostMap, err)
				}
				if customHostMap.Version != version || customHostMap.Digest != dnsservice.DnsCustomHostMapDigest(hosts) ||
					!slices.Equal(customHostMap.Hosts, []string{"shop.a.example", "www.b.example"}) || customHostMap.Format != dnsservice.DnsFormat {
					return fmt.Errorf("map %+v", customHostMap)
				}
				state, err := subject.Store.CustomHostMapState(ctx, root)
				if err != nil {
					return err
				}
				if !slices.ContainsFunc(state.Versions, func(kept dnsservice.DnsMapVersion) bool { return kept.Version == version }) ||
					!slices.Contains(state.HostVersions, version) {
					return fmt.Errorf("state %+v", state)
				}
				return nil
			},
		},
		{
			name: "a report, its probes and a poll round-trip; sync keeps the inventory's rows",
			run: func(ctx context.Context, subject *DnsCustomHostMapStoreSubject, root string, prefix string) error {
				store := subject.Store
				first, second := prefix+"a", prefix+"b"
				if err := store.SyncMapInterfaces(ctx, root, []string{first, second}); err != nil {
					return err
				}
				version, err := subject.Raise(ctx, root, []string{"h1.x.example", "h2.x.example", "h3.x.example"})
				if err != nil {
					return err
				}
				digest := dnsservice.DnsCustomHostMapDigest([]string{"h1.x.example", "h2.x.example", "h3.x.example"})
				err = store.RecordMapReport(ctx, root, &dnsservice.DnsCustomHostMapReport{
					Format:    dnsservice.DnsFormat,
					Interface: first,
					Version:   version,
					Digest:    digest,
					Master:    master,
					Added:     []string{"h3.x.example", "h1.x.example", "h2.x.example"},
					Dropped:   []string{"old.x.example"},
				}, suiteTime, 2, 16)
				if err != nil {
					return err
				}
				row, err := dnsMapSuiteInterface(ctx, store, root, first)
				if err != nil {
					return err
				}
				if row.ReportedVersion != version || row.Digest != digest || row.Master != "4242:"+fmt.Sprint(suiteTime.UnixMilli()) ||
					!slices.Equal(row.AddedHosts, []string{"h1.x.example", "h2.x.example"}) || !slices.Equal(row.DroppedHosts, []string{"old.x.example"}) ||
					!row.PollTime.Equal(suiteTime) {
					return fmt.Errorf("after the report: %+v", row)
				}
				probeTime := suiteTime.Add(10 * time.Second)
				err = store.RecordRouteProbes(ctx, root, &dnsservice.DnsRouteProbeReport{Format: dnsservice.DnsFormat, Interfaces: []dnsservice.DnsRouteProbeResult{
					{Name: first, Version: version, ProbeName: dnsservice.DnsCustomHostMapProbeName(digest), ProbePassed: true, Hosts: []dnsservice.DnsRouteProbeHost{
						{Host: "h1.x.example", Passed: true}, {Host: "h2.x.example", Passed: false}, {Host: "h3.x.example", Passed: true},
					}},
					{Name: second, Version: version, ProbeName: dnsservice.DnsCustomHostMapProbeName(digest), ProbePassed: true},
				}}, probeTime)
				if err != nil {
					return err
				}
				row, err = dnsMapSuiteInterface(ctx, store, root, first)
				if err != nil {
					return err
				}
				if row.ProbeVersion != version || !row.ProbeTime.Equal(probeTime) || !row.HostProbes["h1.x.example"] || row.HostProbes["h2.x.example"] {
					return fmt.Errorf("after the probes: %+v", row)
				}
				if _, held := row.HostProbes["h3.x.example"]; held {
					return errors.New("a host past the probed ones kept a result")
				}
				// the second reported nothing, so its probe for that version is not taken
				other, err := dnsMapSuiteInterface(ctx, store, root, second)
				if err != nil {
					return err
				}
				if other.ProbeVersion != 0 || other.ReportedVersion != 0 {
					return fmt.Errorf("an interface that reported nothing took probes: %+v", other)
				}
				// a poll from another master takes the report away
				if err := store.RecordMapPoll(ctx, root, &dnsservice.DnsMapPoll{Interface: first, Loaded: version, Master: "1:1", Time: probeTime}); err != nil {
					return err
				}
				if row, err = dnsMapSuiteInterface(ctx, store, root, first); err != nil || row.ReportedVersion != 0 {
					return fmt.Errorf("after another master's poll: %+v %v", row, err)
				}
				if err := store.SyncMapInterfaces(ctx, root, []string{first}); err != nil {
					return err
				}
				if _, err := dnsMapSuiteInterface(ctx, store, root, second); err == nil {
					return errors.New("an interface that left the inventory kept its row")
				}
				return nil
			},
		},
		{
			name: "readiness set and cleared by version",
			run: func(ctx context.Context, subject *DnsCustomHostMapStoreSubject, root string, prefix string) error {
				version, err := subject.Raise(ctx, root, []string{"ready.y.example"})
				if err != nil {
					return err
				}
				if err := subject.Store.SetCustomHostReadiness(ctx, root, map[uint64]bool{version: true}, suiteTime); err != nil {
					return err
				}
				if ready, err := subject.HostReady(ctx, root, "ready.y.example"); err != nil || !ready {
					return fmt.Errorf("ready %t %v", ready, err)
				}
				if err := subject.Store.SetCustomHostReadiness(ctx, root, map[uint64]bool{version: false}, suiteTime); err != nil {
					return err
				}
				if ready, err := subject.HostReady(ctx, root, "ready.y.example"); err != nil || ready {
					return fmt.Errorf("cleared %t %v", ready, err)
				}
				return nil
			},
		},
	}
}
