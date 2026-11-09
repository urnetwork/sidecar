package dnsservice_test

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A release over files, with the block's metrics.
func newTestKeyWindowRelease(t testing.TB, settings *dnsservice.DnsSettings, files ...*dnsservice.DnsKeyWindowFile) (*dnsservice.KeyWindowRelease, *sidecartest.FakeMetrics) {
	t.Helper()
	metrics := sidecartest.NewFakeMetrics(nil)
	release, err := dnsservice.NewKeyWindowRelease(settings, files, metrics, nil)
	if err != nil {
		t.Fatal(err)
	}
	return release, metrics
}

// Release across a quarter, an hour at a time: one window at a time, the newest released, never one not
// yet released, and over 7 d left at every hour until the next ceremony is due.
func TestKeyWindowReleaseAcrossAQuarter(t *testing.T) {
	ceremony := newCeremonyTest(t)
	file := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	coverage, err := dnsservice.VerifyDnsKeyWindowFile(ceremony.settings, file)
	if err != nil {
		t.Fatal(err)
	}
	release, metrics := newTestKeyWindowRelease(t, ceremony.settings, file)
	minLeft := 7 * 24 * time.Hour
	if early := release.Status(ceremonyTestRoot, ceremonyTestFrom.Add(59*time.Minute)); early.Window != nil || !early.Gap {
		t.Error("a window served before its release")
	}
	served := []time.Time{}
	for now := coverage.From; now.Before(coverage.Until); now = now.Add(time.Hour) {
		window := release.Window(ceremonyTestRoot, now)
		if window == nil {
			t.Fatalf("no window at %v", now)
		}
		if now.Before(window.NotBefore.Add(time.Hour)) {
			t.Fatalf("at %v a window released at %v", now, window.NotBefore.Add(time.Hour))
		}
		if window.NotAfter.Sub(now) <= minLeft {
			t.Fatalf("at %v the served window has %v left", now, window.NotAfter.Sub(now))
		}
		for _, other := range file.Windows {
			if other.NotBefore.After(window.NotBefore) && !now.Before(other.NotBefore.Add(time.Hour)) {
				t.Fatalf("at %v a newer window is released and not served", now)
			}
		}
		if len(served) == 0 || !served[len(served)-1].Equal(window.NotBefore) {
			served = append(served, window.NotBefore)
		}
	}
	if len(served) != len(file.Windows) {
		t.Errorf("served %d windows of %d", len(served), len(file.Windows))
	}
	if gaps := metrics.Value("urnetwork_dns_key_window_gaps_total", ceremonyTestRoot); gaps != 0 {
		t.Errorf("%v gaps", gaps)
	}
	// past Until the last window is short: still served, and the gap counted once
	status := release.Status(ceremonyTestRoot, coverage.Until)
	if status.Window == nil || !status.Gap {
		t.Errorf("at Until %+v", status)
	}
	release.Window(ceremonyTestRoot, coverage.Until)
	release.Window(ceremonyTestRoot, coverage.Until.Add(time.Hour))
	if gaps := metrics.Value("urnetwork_dns_key_window_gaps_total", ceremonyTestRoot); gaps != 1 {
		t.Errorf("%v gaps after Until", gaps)
	}
	last := file.Windows[len(file.Windows)-1]
	if release.Window(ceremonyTestRoot, last.NotAfter) != nil {
		t.Error("a window served at its end")
	}
}

// A window missing from the middle is a gap: verify reports where, release still serves the older window
// while it lasts and counts the gap once as it starts, and serves the next once released.
func TestKeyWindowReleaseReportsAGap(t *testing.T) {
	ceremony := newCeremonyTest(t)
	file := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	file.Windows = slices.Delete(file.Windows, 6, 7)
	coverage, err := dnsservice.VerifyDnsKeyWindowFile(ceremony.settings, file)
	if err != nil {
		t.Fatal(err)
	}
	before := file.Windows[5]
	if len(coverage.Gaps) != 1 {
		t.Fatalf("gaps %v", coverage.Gaps)
	}
	gap := coverage.Gaps[0]
	// the window before comes to 7 d left before the one after is released
	if !gap.From.Equal(before.NotAfter.Add(-7*24*time.Hour)) || !gap.Until.Equal(file.Windows[6].NotBefore.Add(time.Hour)) {
		t.Errorf("the gap %v to %v", gap.From, gap.Until)
	}
	release, metrics := newTestKeyWindowRelease(t, ceremony.settings, file)
	status := release.Status(ceremonyTestRoot, gap.From.Add(2*time.Hour))
	if !status.Gap || status.Window == nil || !status.Window.NotBefore.Equal(before.NotBefore) {
		t.Errorf("in the gap %+v", status)
	}
	for now := gap.From.Add(-time.Hour); now.Before(gap.Until.Add(time.Hour)); now = now.Add(time.Hour) {
		release.Window(ceremonyTestRoot, now)
	}
	if gaps := metrics.Value("urnetwork_dns_key_window_gaps_total", ceremonyTestRoot); gaps != 1 {
		t.Errorf("%v gaps counted", gaps)
	}
	if left := metrics.Value("urnetwork_dns_key_window_left_seconds", ceremonyTestRoot); left <= (7 * 24 * time.Hour).Seconds() {
		t.Errorf("after the gap %v s left", left)
	}
}

// §12.6's runbook after a ZSK leak: the standby, in every window, passes an edge's SelfCheck once
// mounted, and a ZSK no window names fails it.
func TestMountingTheStandbyPassesSelfCheckAndAnUnnamedZskFails(t *testing.T) {
	ceremony := newCeremonyTest(t)
	file := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	release, _ := newTestKeyWindowRelease(t, ceremony.settings, file)
	now := ceremonyTestFrom.Add(40 * 24 * time.Hour)
	window := release.Window(ceremonyTestRoot, now)
	view := ceremony.view(t)
	if _, err := dnsservice.SelfCheck(view, &dnsservice.DnsKeySet{Window: window, Zsk: ceremony.standby}, ceremony.anchors(t), now); err != nil {
		t.Errorf("the standby: %v", err)
	}
	unnamed := ceremonyTestKey(t, ceremonyTestOtherScalarHex)
	_, err := dnsservice.SelfCheck(view, &dnsservice.DnsKeySet{Window: window, Zsk: unnamed}, ceremony.anchors(t), now)
	if !errors.Is(err, dnsservice.ErrDnsSelfCheck) {
		t.Errorf("a ZSK no window names: %v", err)
	}
}

// Release takes no file it cannot serve from: one whose RRset changed after signing, one of a root
// dns.yml does not serve, and two for one root.
func TestKeyWindowReleaseRefusesAFileThatDoesNotVerify(t *testing.T) {
	ceremony := newCeremonyTest(t)
	file := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	metrics := sidecartest.NewFakeMetrics(nil)

	grown := *file
	grown.Windows = slices.Clone(file.Windows)
	grown.Windows[2].Dnskeys = append(slices.Clone(grown.Windows[2].Dnskeys), ceremonyTestDnskey(t, ceremonyTestKey(t, ceremonyTestOtherScalarHex), dns.ZONE))
	if _, err := dnsservice.NewKeyWindowRelease(ceremony.settings, []*dnsservice.DnsKeyWindowFile{&grown}, metrics, nil); !errors.Is(err, dnsservice.ErrDnsKeyWindowRefused) {
		t.Errorf("a grown RRset: %v", err)
	}
	other := *ceremony.settings
	other.Roots = []string{"other.example."}
	other.TrustAnchors = map[string][]string{"other.example.": {ceremony.ksk}}
	if _, err := dnsservice.NewKeyWindowRelease(&other, []*dnsservice.DnsKeyWindowFile{file}, metrics, nil); !errors.Is(err, dnsservice.ErrDnsKeyWindowRefused) {
		t.Errorf("another root: %v", err)
	}
	if _, err := dnsservice.NewKeyWindowRelease(ceremony.settings, []*dnsservice.DnsKeyWindowFile{file, file}, metrics, nil); !errors.Is(err, dnsservice.ErrDnsKeyWindowRefused) {
		t.Errorf("two files: %v", err)
	}
}

// A window file that is not one, by its shape alone, never reaches verification.
func TestParseDnsKeyWindowFileRefusesItsShape(t *testing.T) {
	ceremony := newCeremonyTest(t)
	file := ceremony.windows(t, ceremonyTestFrom, ceremonyTestUntil, nil, ceremonyTestFrom)
	data, err := file.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dnsservice.ParseDnsKeyWindowFile(data); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		data string
	}{
		{name: "a later format", data: strings.Replace(string(data), `"format": 1`, `"format": 2`, 1)},
		{name: "no format", data: strings.Replace(string(data), `"format": 1,`, ``, 1)},
		{name: "another root", data: strings.Replace(string(data), `"root": "zone.example."`, `"root": "other.example."`, 1)},
		{name: "a window of another root", data: strings.Replace(string(data), `"root": "zone.example."`, `"root": "other.example."`, 2)},
		{name: "no window", data: `{"format": 1, "root": "zone.example.", "windows": []}`},
		{name: "not JSON", data: `format: 1`},
	}
	for _, c := range cases {
		if _, err := dnsservice.ParseDnsKeyWindowFile([]byte(c.data)); !errors.Is(err, dnsservice.ErrDnsKeyWindowRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	unordered := *file
	unordered.Windows = slices.Clone(file.Windows)
	unordered.Windows[3], unordered.Windows[4] = unordered.Windows[4], unordered.Windows[3]
	unorderedData, err := unordered.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dnsservice.ParseDnsKeyWindowFile(unorderedData); !errors.Is(err, dnsservice.ErrDnsKeyWindowRefused) {
		t.Errorf("out of order: %v", err)
	}
	if name := dnsservice.DnsKeyWindowFileName("Zone.Example"); name != "dns-key-windows-zone.example.json" {
		t.Errorf("file name %s", name)
	}
}

// keys: in dns.yml: the defaults pass, and a step that would let the served window fall to min_left_s
// is refused.
func TestDnsKeySettingsKeepTheServedWindowOverMinLeft(t *testing.T) {
	ceremony := newCeremonyTest(t)
	settings := *ceremony.settings
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(keys *dnsservice.DnsKeySettings){
		func(keys *dnsservice.DnsKeySettings) { keys.StepSeconds = 7 * 24 * 3600 },
		func(keys *dnsservice.DnsKeySettings) { keys.WindowSeconds = 0 },
		func(keys *dnsservice.DnsKeySettings) { keys.MinLeftSeconds = 0 },
		func(keys *dnsservice.DnsKeySettings) { keys.ReleaseDelaySeconds = -1 },
		func(keys *dnsservice.DnsKeySettings) { keys.DnskeyTtl = 0 },
	} {
		changed := *ceremony.settings
		change(&changed.Keys)
		if err := changed.Validate(); !errors.Is(err, dnsservice.ErrDnsSettingsRefused) {
			t.Errorf("%+v: %v", changed.Keys, err)
		}
	}
}
