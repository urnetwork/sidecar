// certs' CAA checks on scripted parts (TLS-M6-04; §12.8, FS-32 on T2): a resolver standing for the recursive and
// the customer's authoritative servers, which may flatten the ALIAS target's CAA into the host's answers; the dns
// canary route, which keeps the canary standing at its owner; and the custom-host rows, which apply a verdict as
// model.DnsCustomHostResultInTx does. Every wait is on the fake clock, which each pass is driven through. Names are
// under .example: root.example stands for <root>, customer.example for a Team's verified domain.

package certsservice_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/certsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The customer's pin (RFC 8657), the set every walk here finds unless a test says otherwise.
const testCaaPin = `0 issue "ca.example; accounturi=https://ca.example/acme/acct/1"`

// Runs function on its own goroutine, moving clock to each timer it sets, until it returns.
func testCaaDrive[T any](clock *sidecartest.FakeClock, function func() T) T {
	done := make(chan T, 1)
	go func() {
		done <- function()
	}()
	for {
		select {
		case result := <-done:
			return result
		default:
		}
		pending, added := clock.WatchTimers()
		if 0 < len(pending) {
			clock.AdvanceTo(pending[0])
			continue
		}
		select {
		case result := <-done:
			return result
		case <-added:
		}
	}
}

// One canary as the route keeps it.
type testCaaCanary struct {
	nonce   string
	records []string
}

// One publish, as the route took it.
type testCaaPublish struct {
	owner    string
	caa      []string
	replaces string
	nonce    string
}

// POST /dns/caa-canary and GET /dns/ready in memory: one canary an owner, busy while another stands, the lint's
// refusal at an owner holding a CNAME, and ready answers a test scripts, ready when it scripts nothing.
type testCaaDns struct {
	stateLock    sync.Mutex
	serial       uint64
	canaries     map[string]*testCaaCanary
	lintOwners   map[string]bool
	refuse       bool
	readyAnswers []certsservice.CertsDnsReadiness
	publishes    []*testCaaPublish
	deletes      []string
	busyCount    int
	// called once a publish stands, with no lock held
	onPublish func()
}

func newTestCaaDns() *testCaaDns {
	return &testCaaDns{canaries: map[string]*testCaaCanary{}, lintOwners: map[string]bool{}}
}

func (self *testCaaDns) PublishCaaCanary(ctx context.Context, owner string, caa []string, replaces string) (uint64, string, error) {
	serial, nonce, err := self.publish(owner, caa, replaces)
	if err == nil && self.onPublish != nil {
		self.onPublish()
	}
	return serial, nonce, err
}

func (self *testCaaDns) publish(owner string, caa []string, replaces string) (uint64, string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.lintOwners[owner] {
		return 0, "", certsservice.ErrCertsCaaCanaryLint
	}
	if self.refuse || len(caa) == 0 {
		return 0, "", certsservice.ErrCertsCaaCanaryRefused
	}
	if standing, ok := self.canaries[owner]; ok && standing.nonce != replaces {
		self.busyCount += 1
		return 0, "", certsservice.ErrCertsCaaCanaryBusy
	}
	self.serial += 1
	nonce := fmt.Sprintf("%032x", self.serial)
	self.canaries[owner] = &testCaaCanary{
		nonce:   nonce,
		records: append(slices.Clone(caa), fmt.Sprintf(`0 %s "%s"`, sidecar.TlsCaaCanaryTag, nonce)),
	}
	self.publishes = append(self.publishes, &testCaaPublish{owner: owner, caa: slices.Clone(caa), replaces: replaces, nonce: nonce})
	return self.serial, nonce, nil
}

func (self *testCaaDns) DeleteCaaCanary(ctx context.Context, owner string) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.deletes = append(self.deletes, owner)
	if _, ok := self.canaries[owner]; !ok {
		return 0, nil
	}
	delete(self.canaries, owner)
	self.serial += 1
	return self.serial, nil
}

func (self *testCaaDns) Ready(ctx context.Context, serial uint64) (certsservice.CertsDnsReadiness, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.readyAnswers) {
		answer := self.readyAnswers[0]
		self.readyAnswers = self.readyAnswers[1:]
		return answer, nil
	}
	return certsservice.CertsDnsReady, nil
}

// The records a flattening ALIAS to owner answers: the standing canary's, or none.
func (self *testCaaDns) flattened(owner string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if canary, ok := self.canaries[owner]; ok {
		return slices.Clone(canary.records)
	}
	return nil
}

func (self *testCaaDns) log() ([]*testCaaPublish, []string, int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.publishes), slices.Clone(self.deletes), self.busyCount
}

// The resolver's view of the world: recursive answers, and what the customer's authoritative servers answer, a
// name's own records, or the CAA of the ALIAS target they flatten.
type testCaaNetwork struct {
	dns *testCaaDns

	stateLock sync.Mutex
	lookups   map[string]*sidecar.TlsCaaAnswer
	records   map[string][]string
	// the host name whose servers flatten its ALIAS target's CAA, to that target
	flattens map[string]string
	// the first canary set a flattening server saw, served on after a republish, as a cache would
	cached       map[string][]string
	cacheCanary  bool
	silent       map[string]bool
	queryCounts  map[string]int
	lookupCounts map[string]int
}

func newTestCaaNetwork(dns *testCaaDns) *testCaaNetwork {
	return &testCaaNetwork{
		dns:          dns,
		lookups:      map[string]*sidecar.TlsCaaAnswer{},
		records:      map[string][]string{},
		flattens:     map[string]string{},
		cached:       map[string][]string{},
		silent:       map[string]bool{},
		queryCounts:  map[string]int{},
		lookupCounts: map[string]int{},
	}
}

var _ certsservice.CertsCaaResolver = (*testCaaNetwork)(nil)

// The customer's zone, served by two of its provider's servers.
func testCaaHop(name string, zone string) *sidecar.TlsCaaHop {
	return &sidecar.TlsCaaHop{Name: name, Zone: zone, Nameservers: []string{"ns1.provider.example", "ns2.provider.example"}}
}

func (self *testCaaNetwork) LookupCaa(ctx context.Context, name string) (*sidecar.TlsCaaAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lookupCounts[name] += 1
	if answer, ok := self.lookups[name]; ok {
		return answer, nil
	}
	// a name's zone is its last two labels
	zone := name
	if labels := strings.Split(name, "."); 2 < len(labels) {
		zone = strings.Join(labels[len(labels)-2:], ".")
	}
	return &sidecar.TlsCaaAnswer{Hops: []*sidecar.TlsCaaHop{testCaaHop(name, zone)}, Records: self.records[name]}, nil
}

func (self *testCaaNetwork) AuthoritativeCaa(ctx context.Context, name string, nameservers []string) (map[string][]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.queryCounts[name] += 1
	records := self.records[name]
	if owner, ok := self.flattens[name]; ok {
		records = self.dns.flattened(owner)
		if self.cacheCanary {
			if cached, ok := self.cached[name]; ok {
				records = cached
			} else if 0 < len(records) {
				self.cached[name] = records
			}
		}
	}
	answers := map[string][]string{}
	for _, nameserver := range nameservers {
		if !self.silent[nameserver] {
			answers[nameserver] = slices.Clone(records)
		}
	}
	if len(answers) == 0 {
		return nil, fmt.Errorf("no server answered")
	}
	return answers, nil
}

func (self *testCaaNetwork) queries(name string) int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.queryCounts[name]
}

// One custom host's row, as the store keeps it.
type testCaaHostRow struct {
	host    certsservice.CertsCaaHost
	strong  bool
	state   string
	chainOk bool
	// when its newest chain reaches the recheck fraction; zero for none
	recheck time.Time
}

// The custom-host rows, judged as model.DnsCustomHostResultInTx judges them.
type testCaaStore struct {
	stateLock sync.Mutex
	rows      map[string]*testCaaHostRow
	applied   []string
}

func newTestCaaStore() *testCaaStore {
	return &testCaaStore{rows: map[string]*testCaaHostRow{}}
}

func (self *testCaaStore) add(row *testCaaHostRow) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row.host.Pending = row.state == sidecar.DnsCustomHostStatePending
	self.rows[row.host.Host] = row
}

func (self *testCaaStore) remove(host string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.rows, host)
}

func (self *testCaaStore) row(host string) *testCaaHostRow {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row, ok := self.rows[host]
	if !ok {
		return nil
	}
	copied := *row
	return &copied
}

func (self *testCaaStore) list(filter func(row *testCaaHostRow) bool, afterHost string, count int) []*certsservice.CertsCaaHost {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	hosts := []*certsservice.CertsCaaHost{}
	for _, row := range self.rows {
		if row.strong && afterHost < row.host.Host && filter(row) {
			host := row.host
			hosts = append(hosts, &host)
		}
	}
	slices.SortFunc(hosts, func(a *certsservice.CertsCaaHost, b *certsservice.CertsCaaHost) int {
		return strings.Compare(a.Host, b.Host)
	})
	return hosts[:min(count, len(hosts))]
}

func (self *testCaaStore) ListCaaPending(ctx context.Context, afterHost string, count int) ([]*certsservice.CertsCaaHost, error) {
	return self.list(func(row *testCaaHostRow) bool { return row.state == sidecar.DnsCustomHostStatePending }, afterHost, count), nil
}

func (self *testCaaStore) ListCaaDue(ctx context.Context, lifetimeFraction float64, since time.Time, until time.Time, afterHost string, count int) ([]*certsservice.CertsCaaHost, error) {
	return self.list(func(row *testCaaHostRow) bool {
		return row.state == sidecar.DnsCustomHostStateActive && !row.recheck.IsZero() && row.recheck.After(since) && !row.recheck.After(until)
	}, afterHost, count), nil
}

func (self *testCaaStore) GetCaaHost(ctx context.Context, host string) (*certsservice.CertsCaaHost, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	row, ok := self.rows[host]
	if !ok || !row.strong || (row.state != sidecar.DnsCustomHostStatePending && row.state != sidecar.DnsCustomHostStateActive) {
		return nil, nil
	}
	copied := row.host
	return &copied, nil
}

func (self *testCaaStore) ApplyCaaVerdict(ctx context.Context, host string, pass bool) (certsservice.CertsCaaOutcome, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.applied = append(self.applied, host)
	row, ok := self.rows[host]
	if !ok || !row.strong || (row.state != sidecar.DnsCustomHostStatePending && row.state != sidecar.DnsCustomHostStateActive) {
		return certsservice.CertsCaaOutcomeGone, nil
	}
	switch {
	case row.state == sidecar.DnsCustomHostStatePending && pass:
		row.state = sidecar.DnsCustomHostStateActive
		row.host.Pending = false
		row.chainOk = true
		return certsservice.CertsCaaOutcomeActivated, nil
	case row.state == sidecar.DnsCustomHostStatePending:
		delete(self.rows, host)
		return certsservice.CertsCaaOutcomeRefused, nil
	case pass:
		row.chainOk = true
		return certsservice.CertsCaaOutcomeChecked, nil
	}
	row.chainOk = false
	return certsservice.CertsCaaOutcomeExposed, nil
}

// The checks and every scripted part behind them.
type testCaaWorld struct {
	t        *testing.T
	certs    *testCerts
	dns      *testCaaDns
	network  *testCaaNetwork
	store    *testCaaStore
	settings *certsservice.CertsCaaSettings
	deps     *certsservice.CertsCaaDeps
}

func newTestCaaWorld(t *testing.T) *testCaaWorld {
	t.Helper()
	certs := newTestCerts(t, nil)
	dns := newTestCaaDns()
	network := newTestCaaNetwork(dns)
	store := newTestCaaStore()
	settings := certsservice.DefaultCertsCaaSettings()
	settings.OperatorZones = []string{testRoot}
	// the pin at the customer's domain
	network.records["customer.example"] = []string{testCaaPin}
	return &testCaaWorld{
		t:        t,
		certs:    certs,
		dns:      dns,
		network:  network,
		store:    store,
		settings: settings,
		deps:     &certsservice.CertsCaaDeps{Resolver: network, Dns: dns, Store: store, Settings: settings},
	}
}

// A strong-mode host of network 1 mapped to owner under root.example, in state, with its recheck time.
func (self *testCaaWorld) addHost(host string, ownerLabel string, state string, recheck time.Time) {
	self.store.add(&testCaaHostRow{
		host: certsservice.CertsCaaHost{
			Host:      host,
			Owner:     ownerLabel + ".net1." + testRoot,
			NetworkId: sidecar.Id{1},
		},
		strong:  true,
		state:   state,
		chainOk: state == sidecar.DnsCustomHostStateActive,
		recheck: recheck,
	})
}

// One pass from cursor, driven through the fake clock.
func (self *testCaaWorld) run(cursor *certsservice.CertsCaaCursor) *certsservice.CertsCaaReport {
	self.t.Helper()
	type outcome struct {
		report *certsservice.CertsCaaReport
		err    error
	}
	result := testCaaDrive(self.certs.clock, func() outcome {
		report, err := self.certs.service.RunCaaChecks(self.certs.ctx, self.deps, cursor)
		return outcome{report: report, err: err}
	})
	if result.err != nil {
		self.t.Fatal(result.err)
	}
	return result.report
}

// The verdict a report holds for host, failing the test when it holds none.
func testCaaVerdict(t *testing.T, report *certsservice.CertsCaaReport, host string) *certsservice.CertsCaaVerdict {
	t.Helper()
	for _, verdict := range report.Verdicts {
		if verdict.Host == host {
			return verdict
		}
	}
	t.Fatalf("no verdict for %s among %d, %d with none", host, len(report.Verdicts), report.InconclusiveCount)
	return nil
}

func TestCertsCaaChecksSettingsRefuseWhatLeavesARuleUnenforced(t *testing.T) {
	settings := certsservice.DefaultCertsCaaSettings()
	if err := settings.Validate(); err == nil {
		t.Errorf("no operator zones passed")
	}
	settings.OperatorZones = []string{testRoot}
	if err := settings.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(settings *certsservice.CertsCaaSettings){
		func(settings *certsservice.CertsCaaSettings) { settings.ProbeInterval = 0 },
		func(settings *certsservice.CertsCaaSettings) { settings.ProbeTimeout = settings.ProbeWindow },
		func(settings *certsservice.CertsCaaSettings) { settings.ProbeConcurrency = 0 },
		func(settings *certsservice.CertsCaaSettings) { settings.RecheckLifetimeFraction = 1 },
		func(settings *certsservice.CertsCaaSettings) { settings.Walk = nil },
	} {
		changed := certsservice.DefaultCertsCaaSettings()
		changed.OperatorZones = []string{testRoot}
		change(changed)
		if err := changed.Validate(); err == nil {
			t.Errorf("a refused value passed: %+v", changed)
		}
	}
}

func TestCertsCaaChecksRunNothingWithoutTheirParts(t *testing.T) {
	world := newTestCaaWorld(t)
	cursor := &certsservice.CertsCaaCursor{AfterPendingHost: "kept.example"}
	report, err := world.certs.service.RunCaaChecks(world.certs.ctx, &certsservice.CertsCaaDeps{Settings: world.settings}, cursor)
	if err == nil || report.Next != cursor || len(report.Verdicts) != 0 {
		t.Fatalf("%v, %+v", err, report)
	}
}

func TestCertsCaaChecksScanDueHostsByWindow(t *testing.T) {
	world := newTestCaaWorld(t)
	now := world.certs.clock.Now()
	// app's newest chain reaches half its life in an hour; www's has passed it, open below on the first scan
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStateActive, now.Add(1*time.Hour))
	world.addHost("www.customer.example", "www", sidecar.DnsCustomHostStateActive, now.Add(-1*time.Hour))
	first := world.run(nil)
	if len(first.Verdicts) != 1 || first.Verdicts[0].Host != "www.customer.example" {
		t.Fatalf("first scan %+v", first.Verdicts)
	}
	world.certs.clock.Advance(2 * time.Hour)
	second := world.run(first.Next)
	if len(second.Verdicts) != 1 || second.Verdicts[0].Host != "app.customer.example" || second.Verdicts[0].Outcome != certsservice.CertsCaaOutcomeChecked {
		t.Fatalf("second scan %+v", second.Verdicts)
	}
	// each chain's recheck is judged once
	world.certs.clock.Advance(2 * time.Hour)
	if third := world.run(second.Next); len(third.Verdicts) != 0 {
		t.Fatalf("third scan judged again: %+v", third.Verdicts)
	}
}

func TestCertsCaaChecksCarryADueHostWithNoVerdictThenDropIt(t *testing.T) {
	world := newTestCaaWorld(t)
	world.settings.RetryMaxTryCount = 2
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStateActive, world.certs.clock.Now())
	// neither of the provider's servers answers a query
	world.network.silent["ns1.provider.example"] = true
	world.network.silent["ns2.provider.example"] = true
	first := world.run(nil)
	if first.InconclusiveCount != 1 || len(first.Next.Retries) != 1 || first.Next.Retries[0].TryCount != 1 {
		t.Fatalf("first pass %+v, retries %+v", first, first.Next.Retries)
	}
	second := world.run(first.Next)
	if second.InconclusiveCount != 1 || len(second.Next.Retries) != 0 || second.DroppedCount != 1 {
		t.Fatalf("second pass %+v, retries %+v", second, second.Next.Retries)
	}
	// its standing is untouched, and every canary was deleted
	if row := world.store.row("app.customer.example"); row.state != sidecar.DnsCustomHostStateActive || !row.chainOk {
		t.Errorf("row %+v", row)
	}
	publishes, deletes, _ := world.dns.log()
	if len(publishes) != 2 || len(deletes) != 2 {
		t.Errorf("%d publishes, %d deletes", len(publishes), len(deletes))
	}
}

func TestCertsCaaChecksPageThePendingHosts(t *testing.T) {
	world := newTestCaaWorld(t)
	world.settings.PendingBatchCount = 2
	for _, label := range []string{"a", "b", "c"} {
		world.addHost(label+".customer.example", label, sidecar.DnsCustomHostStatePending, time.Time{})
	}
	first := world.run(nil)
	if len(first.Verdicts) != 2 || !first.More || first.Next.AfterPendingHost != "b.customer.example" {
		t.Fatalf("first pass %+v, next %+v", first.Verdicts, first.Next)
	}
	second := world.run(first.Next)
	if len(second.Verdicts) != 1 || second.Verdicts[0].Host != "c.customer.example" || second.Next.AfterPendingHost != "" {
		t.Fatalf("second pass %+v, next %+v", second.Verdicts, second.Next)
	}
	for _, label := range []string{"a", "b", "c"} {
		if row := world.store.row(label + ".customer.example"); row == nil || row.state != sidecar.DnsCustomHostStateActive {
			t.Errorf("%s: %+v", label, row)
		}
	}
}

func TestCertsCaaChecksProbeOneOwnerAtATime(t *testing.T) {
	world := newTestCaaWorld(t)
	// two hosts behind one ALIAS target, and a third behind another
	world.addHost("app.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addHost("www.customer.example", "web", sidecar.DnsCustomHostStatePending, time.Time{})
	world.addHost("api.customer.example", "api", sidecar.DnsCustomHostStatePending, time.Time{})
	report := world.run(nil)
	if len(report.Verdicts) != 3 || report.InconclusiveCount != 0 {
		t.Fatalf("%+v, %d with none", report.Verdicts, report.InconclusiveCount)
	}
	publishes, deletes, busyCount := world.dns.log()
	if busyCount != 0 || len(publishes) != 3 || len(deletes) != 3 {
		t.Errorf("%d publishes, %d deletes, %d refused busy", len(publishes), len(deletes), busyCount)
	}
}
