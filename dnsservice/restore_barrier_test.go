//go:build sidecar_testhooks

package dnsservice_test

import (
	"cmp"
	"errors"
	"slices"
	"testing"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The step's sites, in the order a run passes them.
var restoreTestSites = []string{
	"dnsservice.restore_soa_read.after",
	"dnsservice.restore_commit.after",
	"dnsservice.restore_served",
	"dnsservice.restore_list.after",
	"dnsservice.restore_clear.after",
}

// The incident every barrier fixture restores under, so two fixtures' results compare.
var restoreTestIncidentId = sidecar.Id{0x01, 0x9a, 0x51, 0x2c, 0x40, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15}

// A zone dumped at 3, lost writes to 9, restoring set as the dump loads, both NS ahead at 11 and each
// following the restore with a diff, one network flagged.
func newRestoreBarrierTest(t testing.TB) *restoreTest {
	t.Helper()
	test := newRestoreTest(t)
	test.writeMany(t, 3)
	test.takeDump(t)
	test.writeMany(t, 6)
	test.loseAndLoad(t)
	networkId := sidecar.Id{0x01, 0x9a, 0x51, 0x2c, 0x40, 0x00, 0x70, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	test.restore.SetLabel(edgeTestRoot, "netone", networkId)
	test.restore.SetOpenCase(networkId, true)
	user := dnsservice.DnsRecordKindUser
	test.ns.serve("ns1", 11)
	test.ns.serve("ns2", 11)
	test.ns.follow("ns1", []dnsservice.DnsRecordKey{{Owner: "www.netone." + edgeTestRoot, Type: dns.TypeA}}, []dnsservice.DnsRecordKind{user})
	test.ns.follow("ns2", []dnsservice.DnsRecordKey{{Owner: "www.netone." + edgeTestRoot, Type: dns.TypeA}, {Owner: "mx.netone." + edgeTestRoot, Type: dns.TypeAAAA}}, []dnsservice.DnsRecordKind{user, user})
	return test
}

// What a run comes to, as two runs compare: the root's state, the incident's list, the admin events.
type restoreTestResult struct {
	serial        uint64
	restoreSerial uint64
	restoring     bool
	entries       []dnsservice.DnsRestoreEntry
	eventCount    int
}

func (self *restoreTest) result(t testing.TB) *restoreTestResult {
	t.Helper()
	state := self.state(t)
	entries := slices.Clone(self.restore.Listing(edgeTestRoot, restoreTestIncidentId).Entries)
	slices.SortFunc(entries, func(a dnsservice.DnsRestoreEntry, b dnsservice.DnsRestoreEntry) int {
		return cmp.Or(cmp.Compare(a.Owner, b.Owner), cmp.Compare(a.Type, b.Type))
	})
	return &restoreTestResult{
		serial:        state.Serial,
		restoreSerial: state.RestoreSerial,
		restoring:     state.Restoring,
		entries:       entries,
		eventCount:    len(self.restore.AdminEvents()),
	}
}

// Whether two results are one.
func (self *restoreTestResult) equal(other *restoreTestResult) bool {
	return self.serial == other.serial && self.restoreSerial == other.restoreSerial && self.restoring == other.restoring &&
		self.eventCount == other.eventCount && slices.EqualFunc(self.entries, other.entries, func(a dnsservice.DnsRestoreEntry, b dnsservice.DnsRestoreEntry) bool {
		return a.Owner == b.Owner && a.Type == b.Type && a.Flagged == b.Flagged && (a.NetworkId == nil) == (b.NetworkId == nil) &&
			(a.NetworkId == nil || *a.NetworkId == *b.NetworkId)
	})
}

// Held at each step in turn, the run leaves every dns write refused with ErrDnsRestoring and taking no
// serial, until restoring clears; the next write commits just above restore_serial.
func TestRestoreStepRefusesWritesThroughout(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	test := newRestoreBarrierTest(t)
	held := restoreTestSites[:len(restoreTestSites)-1]
	for _, site := range held {
		if err := driver.Arm(site, "", 0); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	var progress *dnsservice.DnsRestoreProgress
	go func() {
		var err error
		progress, err = test.step.Run(t.Context(), edgeTestRoot, restoreTestIncidentId)
		done <- err
	}()
	for _, site := range held {
		if err := driver.AwaitHeld(t.Context(), site, ""); err != nil {
			t.Fatal(err)
		}
		before := test.state(t)
		_, err := test.store.Write(t.Context(), &dnsservice.DnsZoneWrite{
			Root:    edgeTestRoot,
			Upserts: []dnsservice.DnsRecordSet{{Owner: "late." + edgeTestRoot, Type: dns.TypeTXT, Ttl: 300, Kind: dnsservice.DnsRecordKindUser, Rdata: []string{`"x"`}}},
		})
		if !errors.Is(err, dnsservice.ErrDnsRestoring) {
			t.Errorf("at %s a write: %v", site, err)
		}
		if after := test.state(t); after.Serial != before.Serial || !after.Restoring {
			t.Errorf("at %s the state moved: %+v", site, after)
		}
		if err := driver.Release(site); err != nil {
			t.Fatal(err)
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if serial := test.write(t, "after."+edgeTestRoot); serial != progress.RestoreSerial+1 {
		t.Errorf("the first write after took %d, restore_serial %d", serial, progress.RestoreSerial)
	}
	if violations := driver.Violations(); len(violations) != 0 {
		t.Errorf("violations %v", violations)
	}
}

// A process that dies after any step and a fresh one that reruns the step come to what one run with no
// crash comes to: one restore serial, one list, one admin event a network, restoring clear.
func TestRestoreStepRerunsToTheSameResultAfterACrashAtEachStep(t *testing.T) {
	reference := newRestoreBarrierTest(t)
	if _, err := reference.step.Run(t.Context(), edgeTestRoot, restoreTestIncidentId); err != nil {
		t.Fatal(err)
	}
	want := reference.result(t)
	if want.restoring || len(want.entries) != 2 || want.eventCount != 1 {
		t.Fatalf("the run with no crash %+v", want)
	}
	for _, site := range restoreTestSites {
		func() {
			driver := sidecartest.NewBarrierDriver(nil)
			defer driver.Close()
			remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
			if err != nil {
				t.Fatal(err)
			}
			defer remove()
			test := newRestoreBarrierTest(t)
			table := sidecartest.NewActorTable(test.clock, driver)
			actor := table.Actor(t.Context(), "dns")
			if err := driver.Arm(site, "dns", 0); err != nil {
				t.Fatal(err)
			}
			run := driver.Start(actor, func() error {
				_, err := test.step.Run(actor.Context(), edgeTestRoot, restoreTestIncidentId)
				return err
			})
			if err := driver.AwaitHeld(t.Context(), site, "dns"); err != nil {
				t.Fatal(err)
			}
			actor.Kill()
			driver.AbandonHeld("dns")
			<-run.Ended()

			rerun := test.newStep(t)
			if _, err := rerun.Run(t.Context(), edgeTestRoot, restoreTestIncidentId); err != nil {
				t.Errorf("after a crash at %s: %v", site, err)
				return
			}
			if got := test.result(t); !got.equal(want) {
				t.Errorf("after a crash at %s: %+v, want %+v", site, got, want)
			}
		}()
	}
}
