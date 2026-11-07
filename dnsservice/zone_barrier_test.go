//go:build sidecar_testhooks

package dnsservice_test

import (
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

const barrierRoot = "zone.example."

func barrierSettings(t *testing.T) *dnsservice.DnsSettings {
	t.Helper()
	settings := dnsservice.DefaultDnsSettings()
	settings.Roots = []string{barrierRoot}
	settings.SignaturesPerSecond = 1
	settings.Tcp.ConnectionsPerSource = 1
	settings.Rrl.ResponsesPerSecond = 1
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	return settings
}

func barrierTxt(label string, text string) dnsservice.DnsRecordSet {
	return dnsservice.DnsRecordSet{
		Owner: label + "." + barrierRoot,
		Type:  dns.TypeTXT,
		Ttl:   60,
		Kind:  dnsservice.DnsRecordKindUser,
		Rdata: []string{`"` + text + `"`},
	}
}

// What the view holds at label.
func barrierRead(t *testing.T, view *dnsservice.ZoneView, label string) string {
	t.Helper()
	query := &dns.Msg{}
	query.SetQuestion(label+"."+barrierRoot, dns.TypeTXT)
	reply := dnsservice.Answer(&dnsservice.DnsQuery{Message: query}, view, nil)
	if len(reply.Answer) != 1 {
		t.Fatalf("%s reads %+v", label, reply)
	}
	return reply.Answer[0].(*dns.TXT).Txt[0]
}

// §12.6's atomic apply, at its hardest moment: a build held with both rows written and nothing
// published. A reader sees serial n whole until the swap, then n+1 whole, and one holding the old view
// across the swap still reads n.
func TestZoneApplyHeldMidBuildIsInvisibleToReaders(t *testing.T) {
	driver := sidecartest.NewBarrierDriver(nil)
	t.Cleanup(driver.Close)
	remove, err := sidecartest.InstallTestHooks(nil, driver.Hit)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	table := sidecartest.NewActorTable(sidecartest.NewFakeClock(sidecartest.DefaultClockStart()), driver)

	soa := dnsservice.DnsRecordSet{
		Owner: barrierRoot,
		Type:  dns.TypeSOA,
		Ttl:   3600,
		Kind:  dnsservice.DnsRecordKindSystem,
		Rdata: []string{"ns1.zone.example. hostmaster.zone.example. 1 7200 3600 1209600 60"},
	}
	snapshot := dnsservice.DnsSnapshot{Format: dnsservice.DnsFormat, Root: barrierRoot, Serial: 10}
	view, err := dnsservice.NewZoneView(barrierSettings(t), dnsservice.NewDnsSnapshotRows(snapshot, []dnsservice.DnsRecordSet{
		soa, barrierTxt("a", "ten"), barrierTxt("b", "ten"),
	}))
	if err != nil {
		t.Fatal(err)
	}
	published := atomic.Pointer[dnsservice.ZoneView]{}
	published.Store(view)

	site := "dnsservice.zone_apply"
	if err := driver.Arm(site, "", 0); err != nil {
		t.Fatal(err)
	}
	run := driver.Start(table.Actor(t.Context(), "feed"), func() error {
		next, err := view.Apply([]dnsservice.DnsJournalRow{{
			Format:  dnsservice.DnsFormat,
			Root:    barrierRoot,
			Serial:  11,
			Upserts: []dnsservice.DnsRecordSet{barrierTxt("a", "eleven"), barrierTxt("b", "eleven")},
		}})
		if err != nil {
			return err
		}
		published.Store(next)
		return nil
	})
	if err := driver.AwaitHeld(t.Context(), site, "feed"); err != nil {
		t.Fatal(err)
	}

	held := published.Load()
	if held.Serial() != 10 || barrierRead(t, held, "a") != "ten" || barrierRead(t, held, "b") != "ten" {
		t.Errorf("mid-build a reader sees serial %d: %q, %q", held.Serial(), barrierRead(t, held, "a"), barrierRead(t, held, "b"))
	}

	if err := driver.Release(site); err != nil {
		t.Fatal(err)
	}
	select {
	case <-run.Ended():
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	if err := run.Err(); err != nil {
		t.Fatal(err)
	}
	current := published.Load()
	if current.Serial() != 11 || barrierRead(t, current, "a") != "eleven" || barrierRead(t, current, "b") != "eleven" {
		t.Errorf("after the swap a reader sees serial %d", current.Serial())
	}
	if held.Serial() != 10 || barrierRead(t, held, "a") != "ten" || barrierRead(t, held, "b") != "ten" {
		t.Error("the swap reached the view a reader held")
	}
}
