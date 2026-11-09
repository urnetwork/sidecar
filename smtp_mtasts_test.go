//go:build !sidecar_http

// TL2's policies held to RFC 8461: the policy and TXT grammars, mx patterns matching only the left-most
// label, and SmtpMtaSts's §5.1 flow on a fake clock, the device's own DoH (FakeMailZone) and
// MxWorld's policy host, with a transport that counts what it was asked: fetched once and cached to
// max_age, fetched again for a new id, kept through a missing record or a failed fetch, a failed id
// left alone for MtaStsFetchRetryTimeout, and the cache kept across a restart.

package sidecar_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	testMtaStsDomain = "mail.example"
	testMtaStsHost   = "mx.mail.example"
	testMtaStsPolicy = "version: STSv1\r\nmode: enforce\r\nmx: mx.mail.example\r\nmx: *.backup.example\r\nmax_age: 86400\r\n"
)

var testMtaStsStart = time.Date(2026, time.November, 8, 12, 0, 0, 0, time.UTC)

// A transport in front of another that records each request's URL and can answer for it instead.
type testCountingTransport struct {
	next http.RoundTripper

	stateLock sync.Mutex
	urls      []string
	answer    func(request *http.Request) *http.Response
}

func (self *testCountingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	answer := func() func(request *http.Request) *http.Response {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.urls = append(self.urls, request.URL.String())
		return self.answer
	}()
	if answer != nil {
		return answer(request), nil
	}
	return self.next.RoundTrip(request)
}

func (self *testCountingTransport) fetches() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string(nil), self.urls...)
}

func (self *testCountingTransport) setAnswer(answer func(request *http.Request) *http.Response) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.answer = answer
}

// One recipient domain with a policy host in an MxWorld, its _mta-sts record in the device's DoH, and
// the cache on a fake store and clock.
type testMtaStsWorld struct {
	clock     *sidecartest.FakeClock
	world     *sidecartest.MxWorld
	zone      *sidecartest.FakeMailZone
	transport *testCountingTransport
	store     *sidecartest.FakeStore
	settings  *sidecar.SmtpSenderSettings
	mtaSts    *sidecar.SmtpMtaSts
}

func newTestMtaStsWorld(t *testing.T) *testMtaStsWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(testMtaStsStart)
	worldSettings := sidecartest.DefaultMxWorldSettings()
	worldSettings.Clock = clock
	world, err := sidecartest.NewMxWorld(worldSettings)
	if err != nil {
		t.Fatal(err)
	}
	if err := world.AddZone(testMtaStsDomain, nil); err != nil {
		t.Fatal(err)
	}
	self := &testMtaStsWorld{
		clock:     clock,
		world:     world,
		zone:      sidecartest.NewFakeMailZone(clock),
		transport: &testCountingTransport{next: world.MtaStsTransport()},
		store:     sidecartest.NewFakeStore(),
		settings:  sidecar.DefaultSmtpSenderSettings(),
	}
	self.restart()
	return self
}

// A new cache over the same store, as after a restart.
func (self *testMtaStsWorld) restart() {
	self.mtaSts = sidecar.NewSmtpMtaSts(self.zone, self.transport, self.store.Root(), self.settings, self.clock)
}

// Publishes policy under id, at the policy host and as the only _mta-sts record in the device's DoH,
// whose new zone the cache is restarted onto, its store kept.
func (self *testMtaStsWorld) publish(t *testing.T, id string, policy string) {
	t.Helper()
	if err := self.world.SetMtaStsPolicy(testMtaStsDomain, id, policy); err != nil {
		t.Fatal(err)
	}
	self.zone = sidecartest.NewFakeMailZone(self.clock)
	self.zone.AddTxt("_mta-sts."+testMtaStsDomain, "v=STSv1; id="+id)
	self.restart()
}

// Returns once clock has a timer pending at at: how a test knows a wait it is about to move past has
// begun. The real-time guard only fails a test that would otherwise hang.
func awaitTestTimerAt(t *testing.T, clock *sidecartest.FakeClock, at time.Time) {
	t.Helper()
	for {
		pending, added := clock.WatchTimers()
		if slices.ContainsFunc(pending, func(pendingAt time.Time) bool { return pendingAt.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-time.After(10 * time.Second):
			t.Fatalf("no timer at %v: %v", at, pending)
		}
	}
}

func (self *testMtaStsWorld) policy(t *testing.T) *sidecar.SmtpMtaStsPolicy {
	t.Helper()
	policy, err := self.mtaSts.Policy(context.Background(), testMtaStsDomain)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

// §3.2's example, CRLF or LF, unknown fields ignored, the first of a repeated field taken, and max_age
// past its maximum held to it.
func TestSmtpMtaStsPolicyParses(t *testing.T) {
	policy, err := sidecar.ParseSmtpMtaStsPolicy([]byte(testMtaStsPolicy))
	if err != nil || policy.Mode != sidecar.SmtpMtaStsModeEnforce || policy.MaxAge != 24*time.Hour ||
		strings.Join(policy.MxPatterns, ",") != "mx.mail.example,*.backup.example" || !policy.Enforced() {
		t.Errorf("%+v %v", policy, err)
	}
	policy, err = sidecar.ParseSmtpMtaStsPolicy([]byte("version: STSv1\nmode:testing\nextension_1: anything at all\nmode: enforce\n" +
		"mx: MX.Mail.Example.\nmax_age: 9999999999\nmax_age: 1\n\n"))
	if err != nil || policy.Mode != sidecar.SmtpMtaStsModeTesting || policy.MaxAge != 31557600*time.Second ||
		strings.Join(policy.MxPatterns, ",") != "mx.mail.example" || policy.Enforced() {
		t.Errorf("%+v %v", policy, err)
	}
	policy, err = sidecar.ParseSmtpMtaStsPolicy([]byte("version: STSv1\r\nmode: none\r\nmax_age: 0\r\n"))
	if err != nil || policy.Mode != sidecar.SmtpMtaStsModeNone || len(policy.MxPatterns) != 0 {
		t.Errorf("mode none needs no mx: %+v %v", policy, err)
	}
}

// Anything §3.2 does not allow is ErrSmtpMtaStsPolicyInvalid, which the cache reads as no policy fetched.
func TestSmtpMtaStsPolicyRefusesWhatIsNotOne(t *testing.T) {
	for _, body := range []string{
		"",
		"mode: enforce\nmx: mx.mail.example\nmax_age: 86400\n",
		"version: STSv2\nmode: enforce\nmx: mx.mail.example\nmax_age: 86400\n",
		"version: STSv1\nmode: strict\nmx: mx.mail.example\nmax_age: 86400\n",
		"version: STSv1\nmode: enforce\nmax_age: 86400\n",
		"version: STSv1\nmode: enforce\nmx: mx.mail.example\n",
		"version: STSv1\nmode: enforce\nmx: mx.mail.example\nmax_age: -1\n",
		"version: STSv1\nmode: enforce\nmx: mx.mail.example\nmax_age: 12345678901\n",
		"version: STSv1\nmode: enforce\nmx: *.*.mail.example\nmax_age: 86400\n",
		"version: STSv1\nmode: enforce\nmx: mx_1.mail.example\nmax_age: 86400\n",
		"version: STSv1\nmode: enforce\nmx: mx.mail.example\nmax_age: 86400\nno field here\n",
		"version: STSv1\nmode: enforce\nmx: mx.mail.example\nmax_age: 86400\n\xff\n",
		"Version: STSv1\nmode: enforce\nmx: mx.mail.example\nmax_age: 86400\n",
	} {
		if policy, err := sidecar.ParseSmtpMtaStsPolicy([]byte(body)); !errors.Is(err, sidecar.ErrSmtpMtaStsPolicyInvalid) {
			t.Errorf("%q: %+v %v", body, policy, err)
		}
	}
}

// §4.1: a * stands for the whole left-most label and nothing else, and names compare in any case.
func TestSmtpMtaStsMxPatternsMatchTheLeftMostLabelOnly(t *testing.T) {
	policy, err := sidecar.ParseSmtpMtaStsPolicy([]byte(testMtaStsPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for host, want := range map[string]bool{
		"mx.mail.example":         true,
		"MX.mail.example.":        true,
		"mail.backup.example":     true,
		"backup.example":          false,
		"a.b.backup.example":      false,
		"mailbackup.example":      false,
		"mx2.mail.example":        false,
		"mail.example":            false,
		"mx.mail.example.example": false,
	} {
		if got := policy.MatchesMx(host); got != want {
			t.Errorf("%s: %v", host, got)
		}
	}
}

// The policy is found by its TXT record over the device's DoH, fetched once from
// https://mta-sts.<domain>/.well-known/mta-sts.txt, cached to its max_age, then fetched again.
func TestSmtpMtaStsPolicyIsCachedToItsMaxAge(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	policy := world.policy(t)
	if policy == nil || policy.Id != "id1" || !policy.FetchTime.Equal(testMtaStsStart) || !policy.Enforced() {
		t.Fatalf("%+v", policy)
	}
	if fetches := world.transport.fetches(); len(fetches) != 1 || fetches[0] != "https://mta-sts.mail.example/.well-known/mta-sts.txt" {
		t.Fatalf("%q", fetches)
	}
	world.clock.Advance(24*time.Hour - time.Second)
	if policy := world.policy(t); policy == nil || policy.Id != "id1" || len(world.transport.fetches()) != 1 {
		t.Errorf("inside max_age: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
	world.clock.Advance(time.Second)
	if policy := world.policy(t); policy == nil || !policy.FetchTime.Equal(world.clock.Now()) || len(world.transport.fetches()) != 2 {
		t.Errorf("at max_age: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
}

// A TXT record naming a new id fetches the new policy, whose mode replaces the old: none clears an
// enforce policy (§8.3).
func TestSmtpMtaStsNewIdFetchesAgain(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	if policy := world.policy(t); policy == nil || !policy.Enforced() {
		t.Fatalf("%+v", policy)
	}
	world.publish(t, "id2", "version: STSv1\nmode: none\nmax_age: 86400\n")
	policy := world.policy(t)
	if policy == nil || policy.Id != "id2" || policy.Mode != sidecar.SmtpMtaStsModeNone || policy.Enforced() || len(world.transport.fetches()) != 2 {
		t.Errorf("%+v, %d fetches", policy, len(world.transport.fetches()))
	}
}

// A missing or unparseable TXT record does not drop a cached policy (§3.1, §5.1), and with nothing
// cached it is no policy at all, with nothing fetched.
func TestSmtpMtaStsRecordGoneKeepsTheCachedPolicy(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	world.policy(t)
	for _, records := range [][]string{
		nil,
		{"v=STSv1; id=id1", "v=STSv1; id=id2"},
		{"v=STSv1; id=an-id-with-hyphens"},
		{"v=STSv1 id=id1"},
		{"v=STSv10; id=id1"},
	} {
		world.zone = sidecartest.NewFakeMailZone(world.clock)
		for _, record := range records {
			world.zone.AddTxt("_mta-sts."+testMtaStsDomain, record)
		}
		world.mtaSts = sidecar.NewSmtpMtaSts(world.zone, world.transport, world.store.Root(), world.settings, world.clock)
		if policy := world.policy(t); policy == nil || policy.Id != "id1" {
			t.Errorf("%q: %+v", records, policy)
		}
	}
	if fetches := len(world.transport.fetches()); fetches != 1 {
		t.Errorf("%d fetches", fetches)
	}

	fresh := newTestMtaStsWorld(t)
	fresh.zone.AddTxt("_mta-sts."+testMtaStsDomain, "v=STSv1; id=id1; id=id2")
	fresh.restart()
	if policy := fresh.policy(t); policy != nil {
		t.Errorf("a record with nothing at its host: %+v", policy)
	}
	fresh.zone.Fail("_mta-sts."+testMtaStsDomain, dnsmessage.TypeTXT, sidecartest.FakeMailZoneServFail)
	if policy := fresh.policy(t); policy != nil {
		t.Errorf("no answer and nothing cached: %+v", policy)
	}
}

// A TXT record's fields: v=STSv1 first, then ;-separated name=value fields with the id among them, a
// final ; allowed, and the strings of one record joined.
func TestSmtpMtaStsTxtRecordGrammar(t *testing.T) {
	for record, want := range map[string]bool{
		"v=STSv1; id=20160831085700Z;":                  true,
		"v=STSv1;id=abc":                                true,
		"v=STSv1 ; id=abc ; ext.x=a:b":                  true,
		"v=STSv1; ext=1; id=abc":                        true,
		"v=STSv1;":                                      false,
		"v=STSv1; id=":                                  false,
		"v=STSv1; id=abc;;":                             false,
		"v=STSv1; id=abcdefghijklmnopqrstuvwxyz0123456": false,
		"v=STSv1; =abc; id=abc":                         false,
		"v=STSv1; id=abc; ext=a=b":                      false,
		"id=abc; v=STSv1":                               false,
	} {
		world := newTestMtaStsWorld(t)
		if err := world.world.SetMtaStsPolicy(testMtaStsDomain, "unused", testMtaStsPolicy); err != nil {
			t.Fatal(err)
		}
		world.zone.AddTxt("_mta-sts."+testMtaStsDomain, record)
		world.restart()
		if policy := world.policy(t); (policy != nil) != want {
			t.Errorf("%q: %+v", record, policy)
		}
	}
}

// A fetch that fails leaves the cached policy, or none; its id is not fetched again for
// MtaStsFetchRetryTimeout, and then is.
func TestSmtpMtaStsFailedFetchWaitsBeforeTheNext(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	world.policy(t)
	world.publish(t, "id2", testMtaStsPolicy)
	world.transport.setAnswer(func(request *http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}
	})
	if policy := world.policy(t); policy == nil || policy.Id != "id1" {
		t.Errorf("the failed fetch: %+v", policy)
	}
	world.clock.Advance(5*time.Minute - time.Second)
	if policy := world.policy(t); policy == nil || policy.Id != "id1" || len(world.transport.fetches()) != 2 {
		t.Errorf("inside the retry timeout: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
	world.transport.setAnswer(nil)
	world.clock.Advance(time.Second)
	if policy := world.policy(t); policy == nil || policy.Id != "id2" || len(world.transport.fetches()) != 3 {
		t.Errorf("after it: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
}

// §3.3: a redirect is not followed, a policy not served as text/plain or past MtaStsPolicyMaxByteCount
// is refused, and a fetch that does not answer ends at MtaStsFetchTimeout on the clock.
func TestSmtpMtaStsFetchRefusesWhatSection33Refuses(t *testing.T) {
	answers := map[string]func(request *http.Request) *http.Response{
		"redirect": func(request *http.Request) *http.Response {
			return &http.Response{StatusCode: http.StatusMovedPermanently, Header: http.Header{"Location": {"https://mta-sts.other.example/.well-known/mta-sts.txt"}}, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}
		},
		"html": func(request *http.Request) *http.Response {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/html"}}, Body: io.NopCloser(strings.NewReader(testMtaStsPolicy)), Request: request}
		},
		"large": func(request *http.Request) *http.Response {
			body := testMtaStsPolicy + "extension: " + strings.Repeat("x", 64*1024) + "\n"
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"text/plain; charset=utf-8"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}
		},
	}
	for name, answer := range answers {
		world := newTestMtaStsWorld(t)
		world.publish(t, "id1", testMtaStsPolicy)
		world.transport.setAnswer(answer)
		if policy := world.policy(t); policy != nil {
			t.Errorf("%s: %+v", name, policy)
		}
		if fetches := world.transport.fetches(); len(fetches) != 1 {
			t.Errorf("%s: %q", name, fetches)
		}
	}

	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	world.transport.setAnswer(func(request *http.Request) *http.Response {
		<-request.Context().Done()
		return &http.Response{StatusCode: http.StatusGatewayTimeout, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}
	})
	done := make(chan *sidecar.SmtpMtaStsPolicy, 1)
	go func() {
		policy, _ := world.mtaSts.Policy(context.Background(), testMtaStsDomain)
		done <- policy
	}()
	// the TXT lookup's 15 s timer has gone once the fetch's minute is set
	awaitTestTimerAt(t, world.clock, testMtaStsStart.Add(time.Minute))
	world.clock.Advance(time.Minute)
	if policy := <-done; policy != nil {
		t.Errorf("a fetch past its timeout: %+v", policy)
	}
}

// The cache is kept in the sealed store: a restart with the policy host gone still applies it until
// its max_age, and a cache file that does not parse is a failed store, never an empty cache.
func TestSmtpMtaStsCacheSurvivesARestart(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	world.policy(t)
	world.transport.setAnswer(func(request *http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}
	})
	world.restart()
	world.clock.Advance(time.Hour)
	if policy := world.policy(t); policy == nil || policy.Id != "id1" || !policy.Enforced() || len(world.transport.fetches()) != 1 {
		t.Errorf("after a restart: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
	if paths := world.store.Paths(); len(paths) != 1 || paths[0] != "mta-sts" {
		t.Errorf("%q", paths)
	}

	writer, err := world.store.Root().Create("mta-sts")
	if err != nil {
		t.Fatal(err)
	}
	writer.Write([]byte(`{"version":1,"policies":[{"domain":"mail.example","id":"id1","mode":1,"max_age_s":86400,"fetch_time_ms":1}]}`))
	if err := writer.Commit(); err != nil {
		t.Fatal(err)
	}
	world.restart()
	if _, err := world.mtaSts.Policy(context.Background(), testMtaStsDomain); !errors.Is(err, sidecar.ErrSidecarStoreFailed) {
		t.Errorf("an enforce policy with no mx: %v", err)
	}
}

// A fetch the caller's context ends is no failure of the policy host, so it holds the next fetch back
// for nothing: the next send fetches at once.
func TestSmtpMtaStsCancelledFetchHoldsNothingBack(t *testing.T) {
	world := newTestMtaStsWorld(t)
	world.publish(t, "id1", testMtaStsPolicy)
	ctx, cancel := context.WithCancel(context.Background())
	world.transport.setAnswer(func(request *http.Request) *http.Response {
		cancel()
		<-request.Context().Done()
		return &http.Response{StatusCode: http.StatusGatewayTimeout, Header: http.Header{}, Body: io.NopCloser(bytes.NewReader(nil)), Request: request}
	})
	if policy, err := world.mtaSts.Policy(ctx, testMtaStsDomain); err != nil || policy != nil {
		t.Fatalf("the cancelled fetch: %+v %v", policy, err)
	}
	world.transport.setAnswer(nil)
	if policy := world.policy(t); policy == nil || policy.Id != "id1" || len(world.transport.fetches()) != 2 {
		t.Errorf("the next fetch: %+v, %d fetches", policy, len(world.transport.fetches()))
	}
}

// §22.6's rule for what the network sends: no policy body panics the parser, and what parses holds to
// §3.2's forms, each mx pattern naming a host it matches.
func FuzzSmtpMtaStsPolicy(f *testing.F) {
	for _, seed := range []string{
		testMtaStsPolicy,
		"version: STSv1\nmode: none\nmax_age: 0\n",
		"version: STSv1\nmode: testing\nmx: *.mail.example\nmax_age: 31557600\n",
		"version: STSv1\r\nmode: enforce\r\nmx: *.\r\nmax_age: 1\r\n",
		"",
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		policy, err := sidecar.ParseSmtpMtaStsPolicy(body)
		if err != nil {
			if !errors.Is(err, sidecar.ErrSmtpMtaStsPolicyInvalid) {
				t.Fatalf("an error that is not invalid: %v", err)
			}
			return
		}
		if policy.Mode < sidecar.SmtpMtaStsModeEnforce || sidecar.SmtpMtaStsModeNone < policy.Mode ||
			policy.MaxAge < 0 || 31557600*time.Second < policy.MaxAge {
			t.Fatalf("%+v", policy)
		}
		if policy.Mode != sidecar.SmtpMtaStsModeNone && len(policy.MxPatterns) == 0 {
			t.Fatalf("no mx: %+v", policy)
		}
		for _, pattern := range policy.MxPatterns {
			host, wildcard := strings.CutPrefix(pattern, "*.")
			if wildcard {
				host = "a." + host
			}
			if len(host) <= 255 && !policy.MatchesMx(host) {
				t.Fatalf("pattern %q does not match %q", pattern, host)
			}
		}
	})
}
