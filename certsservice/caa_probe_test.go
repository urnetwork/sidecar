// FS-32 on T2 (§12.8, D-DNS-9, D-TLS-11; TLS-M6-04): the walk refuses every topology that lets URnetwork's records
// govern a strong-mode host, and §12.8's probe tells a customer-side ALIAS that also flattens CAA from one that
// synthesizes only addresses, at setup and at renewal, for a host and for an apex host. The scripted parts are
// caa_schedule_test.go's.

package certsservice_test

import (
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
)

// The customer's own records answered by its servers for a host with addresses and no CAA, and the pin at the
// domain: what the walk and the probe both see of an address-only ALIAS.
func (self *testCaaWorld) addressOnly(host string) {
	self.network.records[host] = nil
}

// A host whose ALIAS flattens its target's CAA into its own answers.
func (self *testCaaWorld) flattening(host string, ownerLabel string) {
	self.network.flattens[host] = ownerLabel + ".net1." + testRoot
}

// The host's walk meets <root> through a CNAME, with an empty target or with an operator CAA at the exact target,
// the way FS-32's first clause sets it up: weak mode's topology, which strong mode refuses.
func TestCertsCaaChecksRefuseAnAliasIntoAnOperatorZone(t *testing.T) {
	for _, targetRecords := range [][]string{nil, {`0 issue "ca.example; accounturi=https://ca.example/acme/acct/operator"`}} {
		world := newTestCaaWorld(t)
		world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
		world.network.lookups["app.customer.example"] = &sidecar.TlsCaaAnswer{
			Hops: []*sidecar.TlsCaaHop{
				testCaaHop("app.customer.example", "customer.example"),
				{Name: "web.net1." + testRoot, Zone: "net1." + testRoot, Nameservers: []string{"ns1." + testRoot}},
			},
			Records: targetRecords,
		}
		report := world.run(nil)
		verdict := testCaaVerdict(t, report, "app.customer.example")
		if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonOperatorAlias || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
			t.Fatalf("target %v: %+v", targetRecords, verdict)
		}
		// refused by the walk alone: no canary was published
		if publishes, _, _ := world.dns.log(); len(publishes) != 0 {
			t.Errorf("a refused walk published %d canaries", len(publishes))
		}
		if world.store.row("app.customer.example") != nil {
			t.Errorf("the refused host's row stayed")
		}
	}
}

// A wildcard CNAME into <root> answers for the host as for any name under the domain.
func TestCertsCaaChecksRefuseAWildcardAliasIntoAnOperatorZone(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.network.lookups["app.customer.example"] = &sidecar.TlsCaaAnswer{
		Hops: []*sidecar.TlsCaaHop{
			testCaaHop("app.customer.example", "customer.example"),
			{Name: "edge.net1." + testRoot, Zone: testRoot, Nameservers: []string{"ns1." + testRoot}},
		},
	}
	verdict := testCaaVerdict(t, world.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonOperatorAlias {
		t.Fatalf("%+v", verdict)
	}
}

// QD-175's delegated challenge, a CNAME at _acme-challenge.<host> into <token>.acme.<root>, is no name the host's
// walk reaches, so it refuses nothing; a host delegated whole to URnetwork's servers is refused.
func TestCertsCaaChecksTellADelegatedChallengeFromADelegatedHost(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addHost("api.customer.example", "api", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("app.customer.example")
	world.network.lookups["_acme-challenge.app.customer.example"] = &sidecar.TlsCaaAnswer{
		Hops: []*sidecar.TlsCaaHop{
			testCaaHop("_acme-challenge.app.customer.example", "customer.example"),
			{Name: "token1.acme." + testRoot, Zone: testRoot, Nameservers: []string{"ns1." + testRoot}},
		},
	}
	world.network.lookups["api.customer.example"] = &sidecar.TlsCaaAnswer{
		Hops: []*sidecar.TlsCaaHop{
			{Name: "api.customer.example", Zone: "api.customer.example", Nameservers: []string{"ns1." + testRoot}},
		},
	}
	report := world.run(nil)
	if verdict := testCaaVerdict(t, report, "app.customer.example"); !verdict.Pass || verdict.Outcome != certsservice.CertsCaaOutcomeActivated {
		t.Errorf("delegated challenge: %+v", verdict)
	}
	if verdict := testCaaVerdict(t, report, "api.customer.example"); verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonOperatorAlias {
		t.Errorf("delegated host: %+v", verdict)
	}
}

// A walk that finds no set: no pin keeps URnetwork out, and no canary could carry one.
func TestCertsCaaChecksRefuseAHostWithNoPin(t *testing.T) {
	world := newTestCaaWorld(t)
	world.network.records["customer.example"] = nil
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	verdict := testCaaVerdict(t, world.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonNoPin || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
		t.Fatalf("%+v", verdict)
	}
}

// FS-32's ALIAS cases at setup: one that also flattens CAA shows certs' canary, the customer's pin plus a nonce
// tag, in the host's answers, so the host, still pending and unmapped, is refused; an address-only ALIAS passes.
// Both for a host and for an apex host, whose pin sits at <domain> itself, so only the nonce shows the flattening,
// while the canary sits at a host owner in <net>.<root>, never @. The apex host is another domain's: an apex ALIAS
// that flattens CAA governs every name whose walk climbs to that apex.
func TestCertsCaaChecksAtSetupRefuseAFlatteningAliasAndPassAnAddressOnlyOne(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addHost("apex.example", "apex", sidecar.DnsCustomHostStatePending, time.Time{})
	world.flattening("app.customer.example", "web")
	world.addressOnly("www.customer.example")
	world.network.records["apex.example"] = []string{testCaaPin}
	world.flattening("apex.example", "apex")
	start := world.certs.clock.Now()
	report := world.run(nil)

	if verdict := testCaaVerdict(t, report, "app.customer.example"); verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonNonce || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
		t.Errorf("flattening host: %+v", verdict)
	}
	if verdict := testCaaVerdict(t, report, "www.customer.example"); !verdict.Pass || verdict.Outcome != certsservice.CertsCaaOutcomeActivated {
		t.Errorf("address-only host: %+v", verdict)
	}
	if verdict := testCaaVerdict(t, report, "apex.example"); verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonNonce || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
		t.Errorf("flattening apex host: %+v", verdict)
	}
	if world.store.row("app.customer.example") != nil || world.store.row("apex.example") != nil {
		t.Errorf("a refused host's row stayed")
	}
	if row := world.store.row("www.customer.example"); row.state != sidecar.DnsCustomHostStateActive || !row.chainOk {
		t.Errorf("the passing host: %+v", row)
	}

	// each canary carries the walk's set and sits at the host's owner; every one is deleted
	publishes, deletes, _ := world.dns.log()
	owners := []string{}
	for _, publish := range publishes {
		owners = append(owners, publish.owner)
		if !slices.Equal(publish.caa, []string{testCaaPin}) || publish.replaces != "" {
			t.Errorf("published %+v", publish)
		}
	}
	slices.Sort(owners)
	wantOwners := []string{"apex.net1." + testRoot, "web.net1." + testRoot, "www.net1." + testRoot}
	if !slices.Equal(owners, wantOwners) {
		t.Errorf("canaries at %v, want %v", owners, wantOwners)
	}
	slices.Sort(deletes)
	if !slices.Equal(deletes, wantOwners) {
		t.Errorf("deleted %v", deletes)
	}
	// the pass took the whole window: the queries every 30 s for 10 min, both ends included
	if elapsed := world.certs.clock.Now().Sub(start); elapsed < world.settings.ProbeWindow {
		t.Errorf("the pass ended after %v", elapsed)
	}
	if count := world.network.queries("www.customer.example"); count != 21 {
		t.Errorf("the passing host was queried %d times", count)
	}
}

// FS-32's ALIAS cases at renewal, half the newest chain's life on: a flattening ALIAS clears effective_caa_chain_ok
// and alarms (exposed), the host staying mapped; an address-only one is checked and keeps its standing.
func TestCertsCaaChecksAtRenewalExposeAFlatteningAliasAndKeepItMapped(t *testing.T) {
	world := newTestCaaWorld(t)
	now := world.certs.clock.Now()
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStateActive, now)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStateActive, now)
	world.addHost("apex.example", "apex", sidecar.DnsCustomHostStateActive, now)
	world.flattening("app.customer.example", "web")
	world.addressOnly("www.customer.example")
	world.network.records["apex.example"] = []string{testCaaPin}
	world.flattening("apex.example", "apex")
	report := world.run(nil)
	for _, host := range []string{"app.customer.example", "apex.example"} {
		verdict := testCaaVerdict(t, report, host)
		if verdict.Pass || verdict.Pending || verdict.Reason != certsservice.CertsCaaReasonNonce || verdict.Outcome != certsservice.CertsCaaOutcomeExposed {
			t.Errorf("%s: %+v", host, verdict)
		}
		if row := world.store.row(host); row == nil || row.state != sidecar.DnsCustomHostStateActive || row.chainOk {
			t.Errorf("%s: %+v", host, row)
		}
	}
	if verdict := testCaaVerdict(t, report, "www.customer.example"); !verdict.Pass || verdict.Outcome != certsservice.CertsCaaOutcomeChecked {
		t.Errorf("address-only host: %+v", verdict)
	}
}

// stale before the window and after it: a restore's edges may lack the canary, so it is published again under a new
// nonce naming the one it replaces, and the window starts again; a pass counts only once the serial still stands.
func TestCertsCaaChecksPublishAgainOnStaleAndRestartTheWindow(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("www.customer.example")
	world.dns.readyAnswers = []certsservice.CertsDnsReadiness{
		// before the first window, then after the second's
		certsservice.CertsDnsStale,
		certsservice.CertsDnsReady,
		certsservice.CertsDnsStale,
	}
	verdict := testCaaVerdict(t, world.run(nil), "www.customer.example")
	if !verdict.Pass {
		t.Fatalf("%+v", verdict)
	}
	publishes, deletes, _ := world.dns.log()
	if len(publishes) != 3 || publishes[1].replaces != publishes[0].nonce || publishes[2].replaces != publishes[1].nonce {
		t.Fatalf("publishes %+v", publishes)
	}
	if len(deletes) != 1 {
		t.Errorf("deleted %v", deletes)
	}
	// two whole windows: the one the stale ended and the one that passed
	if count := world.network.queries("www.customer.example"); count != 42 {
		t.Errorf("queried %d times", count)
	}
}

// A canary already in the customer's own set, as a resolver answers it, is a flattening the walk alone shows.
func TestCertsCaaChecksFailOnACanaryInTheWalksSet(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.network.records["app.customer.example"] = []string{testCaaPin, `0 ` + sidecar.TlsCaaCanaryTag + ` "00000000000000000000000000000001"`}
	verdict := testCaaVerdict(t, world.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonNonce || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
		t.Fatalf("%+v", verdict)
	}
	if publishes, _, _ := world.dns.log(); len(publishes) != 0 {
		t.Errorf("published %d canaries", len(publishes))
	}
}

// A flattening provider still serving a canary set it cached from an earlier probe, whatever its nonce, shows the
// flattening to the authoritative queries, though the recursive answer the walk read held none.
func TestCertsCaaChecksFailOnACachedCanaryInTheAnswers(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.network.lookups["app.customer.example"] = &sidecar.TlsCaaAnswer{
		Hops: []*sidecar.TlsCaaHop{testCaaHop("app.customer.example", "customer.example")},
	}
	world.network.records["app.customer.example"] = []string{testCaaPin, `0 ` + sidecar.TlsCaaCanaryTag + ` "00000000000000000000000000000001"`}
	verdict := testCaaVerdict(t, world.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonNonce {
		t.Fatalf("%+v", verdict)
	}
	if _, deletes, _ := world.dns.log(); len(deletes) != 1 {
		t.Errorf("deleted %v", deletes)
	}
}

// canary_failing reads as ready at both of the probe's checks (plan-TLS-canary-signal).
func TestCertsCaaChecksReadCanaryFailingAsReady(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("www.customer.example")
	world.dns.readyAnswers = []certsservice.CertsDnsReadiness{certsservice.CertsDnsCanaryFailing, certsservice.CertsDnsCanaryFailing}
	if verdict := testCaaVerdict(t, world.run(nil), "www.customer.example"); !verdict.Pass {
		t.Fatalf("%+v", verdict)
	}
	if publishes, _, _ := world.dns.log(); len(publishes) != 1 {
		t.Errorf("canary_failing published again: %d", len(publishes))
	}
}

// A CNAME at the host owner makes the lint refuse the canary, which is the failing verdict itself; dns refusing the
// set fails too, since an unprobed host has not passed.
func TestCertsCaaChecksFailOnACanaryRefusal(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("app.customer.example")
	world.dns.lintOwners["web.net1."+testRoot] = true
	verdict := testCaaVerdict(t, world.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonLint || verdict.Outcome != certsservice.CertsCaaOutcomeRefused {
		t.Fatalf("lint: %+v", verdict)
	}

	refused := newTestCaaWorld(t)
	refused.addHost("app.customer.example", "web", sidecar.DnsCustomHostStateActive, refused.certs.clock.Now())
	refused.addressOnly("app.customer.example")
	refused.dns.refuse = true
	verdict = testCaaVerdict(t, refused.run(nil), "app.customer.example")
	if verdict.Pass || verdict.Reason != certsservice.CertsCaaReasonCanaryRefused || verdict.Outcome != certsservice.CertsCaaOutcomeExposed {
		t.Fatalf("refused: %+v", verdict)
	}
}

// A server that never answers in the window leaves the probe with no verdict: the pending host stays pending and
// unmapped, and the canary is deleted all the same. One that answers in some rounds is enough.
func TestCertsCaaChecksJudgeNothingWhileAServerNeverAnswers(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("www.customer.example")
	world.network.silent["ns2.provider.example"] = true
	report := world.run(nil)
	if len(report.Verdicts) != 0 || report.InconclusiveCount != 1 || 0 < len(report.Next.Retries) {
		t.Fatalf("%+v", report)
	}
	if row := world.store.row("www.customer.example"); row.state != sidecar.DnsCustomHostStatePending || row.chainOk {
		t.Errorf("row %+v", row)
	}
	if _, deletes, _ := world.dns.log(); len(deletes) != 1 {
		t.Errorf("deleted %v", deletes)
	}
	// the host is listed again, and judged once its servers answer
	world.network.silent = map[string]bool{}
	if verdict := testCaaVerdict(t, world.run(report.Next), "www.customer.example"); !verdict.Pass {
		t.Fatalf("%+v", verdict)
	}
}

// Another probe's canary standing at the owner is no verdict, and nothing of its is touched.
func TestCertsCaaChecksWaitOutABusyOwner(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("www.customer.example")
	world.dns.canaries["www.net1."+testRoot] = &testCaaCanary{nonce: "ffffffffffffffffffffffffffffffff"}
	report := world.run(nil)
	if len(report.Verdicts) != 0 || report.InconclusiveCount != 1 {
		t.Fatalf("%+v", report)
	}
	if _, deletes, busyCount := world.dns.log(); busyCount != 1 || len(deletes) != 0 {
		t.Errorf("busy %d, deleted %v", busyCount, deletes)
	}
}

// A host whose row went while its probe ran is gone at its verdict, and nothing is written for it.
func TestCertsCaaChecksApplyNothingToAHostThatWent(t *testing.T) {
	world := newTestCaaWorld(t)
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addressOnly("www.customer.example")
	world.dns.onPublish = func() {
		world.store.remove("www.customer.example")
	}
	verdict := testCaaVerdict(t, world.run(nil), "www.customer.example")
	if !verdict.Pass || verdict.Outcome != certsservice.CertsCaaOutcomeGone {
		t.Fatalf("%+v", verdict)
	}
	if world.store.row("www.customer.example") != nil {
		t.Errorf("a gone host came back")
	}
}
