package computeservice

// SRCH-M13-07: the limits' scripts (search_limits.go) through the admission, on FakeRedis's twins and a fake clock: a
// network's burst and rate, its UTC day and its rebuild after a loss, and the global limiter's refund. The catalog's
// search section as the device reads it.

import (
	"context"
	"net/http"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// Settings with room in the global limiter, so a network's own rate is what refuses.
func testComputeSearchRoomySettings() *ComputeEngineSettings {
	settings := DefaultComputeEngineSettings()
	settings.Search.ReportPollInterval = 0
	settings.Search.GlobalWindowCount = 1000
	return settings
}

// A burst of 20 at once, then 2 a second: the 21st waits half a second, and takes its place once it has passed.
func TestSearchLimitsNetworkRateBurst(t *testing.T) {
	fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{settings: testComputeSearchRoomySettings()})
	for i := 0; i < 20; i += 1 {
		if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("burst "+strconv.Itoa(i)), 1)); recorder.Code != http.StatusOK {
			t.Fatalf("search %d of the burst: %d %s", i, recorder.Code, recorder.Body.String())
		}
	}
	recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("burst 20"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalRateLimited, ComputeSearchRateLimitedReasonRate)
	if retry := recorder.Header().Get("Retry-After"); retry != "1" {
		t.Fatalf("Retry-After %q, want half a second rounded up", retry)
	}
	fixture.clock.Advance(500 * time.Millisecond)
	if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("burst 21"), 1)); recorder.Code != http.StatusOK {
		t.Fatalf("after the emission interval: %d %s", recorder.Code, recorder.Body.String())
	}
}

// A network's day ends at UTC midnight: past day_max its searches wait until then, and the next day counts afresh.
func TestSearchLimitsDayRolls(t *testing.T) {
	fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{settings: testComputeSearchRoomySettings()})
	fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{rows: &protocol.AclComputeRows{SearchEnabled: true, SearchDayMax: 2}, allowed: true})
	for i := 0; i < 2; i += 1 {
		if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("day "+strconv.Itoa(i)), 1)); recorder.Code != http.StatusOK {
			t.Fatalf("search %d: %d", i, recorder.Code)
		}
	}
	recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("day 2"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalRateLimited, ComputeSearchRateLimitedReasonDay)
	now := fixture.clock.Now()
	midnight := now.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
	if want := strconv.Itoa(int((midnight.Sub(now) + time.Second - 1) / time.Second)); recorder.Header().Get("Retry-After") != want {
		t.Fatalf("Retry-After %s, want %s, the next UTC midnight", recorder.Header().Get("Retry-After"), want)
	}
	fixture.clock.AdvanceTo(midnight)
	if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("next day"), 1)); recorder.Code != http.StatusOK {
		t.Fatalf("the next day: %d %s", recorder.Code, recorder.Body.String())
	}
}

// A {cmpr_<network_id>} lost mid-day is rebuilt from the day's search rows, so day_max still holds.
func TestSearchLimitsAbsentKeyRebuilt(t *testing.T) {
	fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{settings: testComputeSearchRoomySettings()})
	fixture.setAcl(fixture.networkId, &fakeComputeSearchAcl{rows: &protocol.AclComputeRows{SearchEnabled: true, SearchDayMax: 3}, allowed: true})
	for i := 0; i < 3; i += 1 {
		if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("rebuilt "+strconv.Itoa(i)), 1)); recorder.Code != http.StatusOK {
			t.Fatalf("search %d: %d", i, recorder.Code)
		}
	}
	fixture.redis.LoseKeys(ComputeSearchRateRedisKey(fixture.networkId))
	recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("rebuilt 3"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalRateLimited, ComputeSearchRateLimitedReasonDay)
	if open := fixture.ledger.openCount(); open != 3 {
		t.Fatalf("%d holds after the refusal, want 3", open)
	}
}

// A search the global limiter refuses gives back what the network's rate and day took.
func TestSearchLimitsGlobalRefundsRate(t *testing.T) {
	settings := DefaultComputeEngineSettings()
	settings.Search.ReportPollInterval = 0
	settings.Search.GlobalWindowCount = 1
	fixture := newComputeSearchFixture(t, &computeSearchFixtureOptions{settings: settings})
	if recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("global 0"), 1)); recorder.Code != http.StatusOK {
		t.Fatalf("the first: %d", recorder.Code)
	}
	recorder, _ := fixture.authorize(fixture.request(testSearchRequestId("global 1"), 1))
	requireComputeSearchRefusal(t, recorder, ComputeRefusalRateLimited, ComputeSearchRateLimitedReasonGlobal)
	count, found, err := fixture.redis.HashGet(context.Background(), ComputeSearchRateRedisKey(fixture.networkId), "c")
	if err != nil || !found || string(count) != "1" {
		t.Fatalf("the day counts %q after the refund, want 1", count)
	}
}

// The catalog's search section is what the device's reader takes (websearch_policy.go's, under the name "search"):
// search/parallel/<mode> in every mode, each id in INFER's search grammar, at $0.012, the gateway's $0.01 times the
// markup; and the admission prices a search at the section's lowest entry, refusing a version with none.
func TestSearchCatalogSectionReadsOnDevice(t *testing.T) {
	body, err := computeSearchCatalogSection(model.DefaultComputeLedgerSettings(), DefaultComputeSearchSettings())
	if err != nil {
		t.Fatal(err)
	}
	section := &protocol.WebSearchCatalogSection{}
	if err := proto.Unmarshal(body, section); err != nil {
		t.Fatal(err)
	}
	modes := map[string]bool{}
	for _, entry := range section.GetEntries() {
		id := (&sidecar.InferSearchId{Engine: entry.GetEngine(), Kind: entry.GetMode()}).String()
		if _, err := sidecar.InferParseSearchId(id, sidecar.DefaultInferSettings()); err != nil {
			t.Fatalf("%s is no search id the device takes: %v", id, err)
		}
		if entry.GetEngine() != sidecar.WebSearchEngineParallel || entry.GetNanoUsdPerSearch() != 12*1000*1000 {
			t.Fatalf("a search entry: %v", entry)
		}
		modes[entry.GetMode()] = true
	}
	for _, mode := range sidecar.WebSearchModes {
		if !modes[mode] {
			t.Fatalf("the catalog lists no search/parallel/%s", mode)
		}
	}
	answer := &protocol.InferCatalogAnswer{
		PublishedMs: 1,
		Models:      []*protocol.InferCatalogModel{},
		Sections:    []*protocol.InferCatalogSection{{Name: ComputeSearchCatalogSectionName, Body: body}},
	}
	price, err := computeSearchCatalogPrice(answer)
	if err != nil || price != 12*1000*1000 {
		t.Fatalf("the admission reads %d, %v", price, err)
	}
	empty := proto.Clone(answer).(*protocol.InferCatalogAnswer)
	empty.Sections = nil
	if _, err := computeSearchCatalogPrice(empty); err == nil {
		t.Fatal("a version with no search section priced a search")
	}
}
