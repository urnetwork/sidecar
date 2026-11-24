//go:build !ios_extension && !sidecar_http && !js

// Fetching (ATTEST-M12-01): the fetcher against a local TLS test server serving ur.io's paths, and tickets taken from
// any source, verified the same whichever it came from.

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ur.io's serving path on a local TLS server: files by path, changed by a test as the ticket host and the pipeline
// publish.
type testAttestPolicyServer struct {
	server *httptest.Server

	stateLock sync.Mutex
	files     map[string][]byte
	requests  []string
}

const testAttestPolicyBasePath = "/compute/policy/v1"

func newTestAttestPolicyServer(t *testing.T) *testAttestPolicyServer {
	t.Helper()
	self := &testAttestPolicyServer{files: map[string][]byte{}}
	self.server = httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		self.stateLock.Lock()
		self.requests = append(self.requests, request.URL.Path)
		file, ok := self.files[request.URL.Path]
		self.stateLock.Unlock()
		if strings.HasPrefix(request.URL.Path, "/redirect/") {
			http.Redirect(writer, request, testAttestPolicyBasePath+"/3.json", http.StatusFound)
			return
		}
		if !ok {
			http.NotFound(writer, request)
			return
		}
		writer.Write(file)
	}))
	t.Cleanup(self.server.Close)
	return self
}

// Serves data at name under the base.
func (self *testAttestPolicyServer) put(name string, data []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.files[testAttestPolicyBasePath+"/"+name] = data
}

// Stops serving name.
func (self *testAttestPolicyServer) remove(name string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, testAttestPolicyBasePath+"/"+name)
}

// A source over the server, through its client, which trusts its certificate and follows no redirect.
func (self *testAttestPolicyServer) source(t *testing.T, base string) ComputePolicySource {
	t.Helper()
	client := self.server.Client()
	client.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	source, err := NewComputePolicyHttpSource(self.server.URL+base, client, DefaultAttestSettings())
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// A fetcher over the gate world and sources.
func (self *testAttestGateWorld) fetcher(t *testing.T, sources ...ComputePolicySource) *ComputePolicyFetcher {
	t.Helper()
	fetcher, err := NewComputePolicyFetcher(&ComputePolicyFetcherArgs{
		Store:    self.policyStore,
		Gate:     self.gate,
		Sources:  sources,
		Settings: DefaultAttestSettings(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return fetcher
}

// Against ur.io's paths: a device holding no policy takes today's ticket and the policy it names, then a revocation's
// ticket and policy once they are published, and through RemoteWork's refresh too.
func TestComputePolicyFetcherAgainstATestServer(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	server := newTestAttestPolicyServer(t)
	batch := world.batch(t, testAttestSitting, 3, false)
	today := time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)
	document, signature := world.policy(t, 3)
	server.put("3.json", document)
	server.put("3.json.sig", signature)
	server.put("tickets/2026-12-03.bin", testAttestTicketAt(t, batch, today).file)
	server.put("tickets/2026-12-02.bin", testAttestTicketAt(t, batch, today.AddDate(0, 0, -1)).file)

	empty := newTestAttestStoreWorld(t)
	empty.keys = world.keys
	empty.verifier = world.verifier
	empty.clock = world.clock
	fresh := &testAttestGateWorld{testAttestStoreWorld: empty}
	fresh.reopen(t)
	world.clock.Set(today.Add(2 * time.Hour))
	fetcher := fresh.fetcher(t, server.source(t, testAttestPolicyBasePath))
	if err := fetcher.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if newest := fresh.policyStore.Newest(); newest == nil || newest.Version != 3 || fresh.policyStore.heldTicket() == nil {
		t.Fatalf("after a fetch: %v, ticket %v", newest, fresh.policyStore.heldTicket())
	}
	fresh.wantRemoteWork(t, today.Add(2*time.Hour))

	// the revocation, published: policy 4 and its batch's first ticket, today's file replaced
	revocationAt := today.Add(15 * time.Hour)
	revocation := world.batch(t, revocationAt, 4, true)
	document, signature = world.policy(t, 4)
	server.put("4.json", document)
	server.put("4.json.sig", signature)
	server.put("tickets/2026-12-03.bin", revocation[0].file)
	world.clock.Set(revocationAt.Add(time.Minute))
	if err := fetcher.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	if newest := fresh.policyStore.Newest(); newest.Version != 4 || fresh.policyStore.heldTicket().PolicyVersion != 4 {
		t.Fatalf("after the revocation's fetch: version %d", newest.Version)
	}

	// a withheld policy: version 5 named by a ticket and not served, so remote work stops, saying why
	tomorrow := world.batch(t, revocationAt.Add(time.Hour), 5, true)
	server.put("tickets/2026-12-03.bin", tomorrow[0].file)
	world.clock.Set(revocationAt.Add(time.Hour + time.Minute))
	if err := fetcher.Fetch(context.Background()); err != nil {
		t.Fatal(err)
	}
	fresh.wantLapsed(t, revocationAt.Add(time.Hour+time.Minute), ComputeRemoteLapsePolicyNewerSeen)
	server.put("5.json", testAttestPolicyVersion(t, 5))
	server.put("5.json.sig", testAttestSign(t, world.keys.policy, ComputePolicyNamespace, testAttestPolicyVersion(t, 5)))
	gate, err := NewComputePolicyGate(&ComputePolicyGateArgs{
		Store: fresh.policyStore, Verifier: world.verifier, Settings: DefaultAttestSettings(), Refresh: fetcher.Fetch,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := gate.RemoteWork(context.Background(), ComputeRemoteModelCallTee); err != nil {
		t.Errorf("RemoteWork's refresh fetching the policy named: %v", err)
	}
}

// A source's failures: a redirect is not followed, a body past its bound is refused, a base not https is refused,
// and nothing served is absent, not an error.
func TestComputePolicyHttpSourceRefuses(t *testing.T) {
	server := newTestAttestPolicyServer(t)
	source := server.source(t, testAttestPolicyBasePath)
	if _, _, err := source.Policy(context.Background(), 3); !errors.Is(err, ErrComputePolicySourceAbsent) {
		t.Errorf("nothing served: %v", err)
	}
	if _, err := source.Ticket(context.Background(), time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)); !errors.Is(err, ErrComputePolicySourceAbsent) {
		t.Errorf("no ticket served: %v", err)
	}
	if _, _, err := server.source(t, "/redirect").Policy(context.Background(), 3); err == nil || errors.Is(err, ErrComputePolicySourceAbsent) {
		t.Errorf("a redirect: %v", err)
	}
	server.put("3.json", make([]byte, DefaultAttestSettings().PolicyMaxByteCount+1))
	server.put("3.json.sig", []byte("signature"))
	if _, _, err := source.Policy(context.Background(), 3); err == nil || errors.Is(err, ErrComputePolicySourceAbsent) {
		t.Errorf("a body past its bound: %v", err)
	}
	for _, base := range []string{"http://ur.example/compute/policy/v1", "https://ur.example/v1?x=1", "ur.example/v1", "https://user@ur.example/v1"} {
		if _, err := NewComputePolicyHttpSource(base, nil, DefaultAttestSettings()); err == nil {
			t.Errorf("%s was taken as a base", base)
		}
	}
}

// A source in memory, as another device of the network passing on its newest current ticket would be.
type testAttestMemorySource struct {
	tickets  map[string][]byte
	policies map[uint64][2][]byte
	failure  error
}

func (self *testAttestMemorySource) Policy(ctx context.Context, version uint64) ([]byte, []byte, error) {
	if self.failure != nil {
		return nil, nil, self.failure
	}
	policy, ok := self.policies[version]
	if !ok {
		return nil, nil, ErrComputePolicySourceAbsent
	}
	return policy[0], policy[1], nil
}

func (self *testAttestMemorySource) Ticket(ctx context.Context, day time.Time) ([]byte, error) {
	if self.failure != nil {
		return nil, self.failure
	}
	file, ok := self.tickets[day.Format(computePolicyTicketDayLayout)]
	if !ok {
		return nil, ErrComputePolicySourceAbsent
	}
	return file, nil
}

// The signature is what is trusted, never the source: a ticket another device passes on verifies as ur.io's would,
// past a source that fails; a tampered ticket, or one the staging key signed, is refused from any source and the
// next is asked.
func TestTicketFromAnySourceVerifies(t *testing.T) {
	world := newTestAttestGateWorld(t, false)
	batch := world.batch(t, testAttestSitting, 3, false)
	today := time.Date(2026, time.December, 3, 0, 0, 0, 0, time.UTC)
	good := testAttestTicketAt(t, batch, today)
	tampered := append([]byte{}, good.file...)
	tampered[len(tampered)/3] ^= 0x01
	staging := testAttestSignTicket(t, world.keys.staging, ComputePolicyStagingNamespace, good.ticket)
	failing := &testAttestMemorySource{failure: errors.New("unreachable")}
	forged := &testAttestMemorySource{tickets: map[string][]byte{"2026-12-03": tampered}}
	stagingSource := &testAttestMemorySource{tickets: map[string][]byte{"2026-12-03": staging}}
	device := &testAttestMemorySource{tickets: map[string][]byte{"2026-12-03": good.file}}
	world.clock.Set(today.Add(time.Hour))
	fetcher := world.fetcher(t, failing, forged, stagingSource)
	if err := fetcher.Fetch(context.Background()); err == nil || world.policyStore.heldTicket() != nil {
		t.Fatalf("only refused tickets: %v, held %v", err, world.policyStore.heldTicket())
	}
	fetcher = world.fetcher(t, failing, forged, stagingSource, device)
	fetcher.Fetch(context.Background())
	if held := world.policyStore.heldTicket(); held == nil || string(held.File()) != string(good.file) {
		t.Fatalf("the device's ticket: %v", held)
	}
	world.wantRemoteWork(t, today.Add(time.Hour))
}
