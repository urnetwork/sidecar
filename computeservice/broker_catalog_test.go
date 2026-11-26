package computeservice

// The remote catalog at the broker (INFER-M12-01; DESIGN-COMPUTE §6.3, §4.5, §9.6): the build on BAL's price function,
// the hourly prune, the version rule, the sections, the direct exposures and the route. compute_catalog_version's SQL
// runs against the private test stack with server's migrations; these hold the rules that need no database, on a store
// a test keeps.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The versions a test keeps, oldest first. Safe for concurrent use.
type fakeComputeCatalogStore struct {
	stateLock sync.Mutex
	versions  []*ComputeCatalogVersion
	reads     int
}

func (self *fakeComputeCatalogStore) Newest(ctx context.Context, count int) ([]*ComputeCatalogVersion, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads += 1
	newest := []*ComputeCatalogVersion{}
	for i := len(self.versions) - 1; 0 <= i && len(newest) < count; i -= 1 {
		copied := *self.versions[i]
		copied.Answer = proto.Clone(self.versions[i].Answer).(*protocol.InferCatalogAnswer)
		copied.Exposures = slices.Clone(self.versions[i].Exposures)
		newest = append(newest, &copied)
	}
	return newest, nil
}

func (self *fakeComputeCatalogStore) Publish(ctx context.Context, version *ComputeCatalogVersion) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if version.Version != uint64(len(self.versions))+1 {
		return errComputeCatalogRace
	}
	if _, err := computeCatalogAnswerBytes(version.Answer); err != nil {
		return err
	}
	copied := *version
	copied.Answer = proto.Clone(version.Answer).(*protocol.InferCatalogAnswer)
	copied.Exposures = slices.Clone(version.Exposures)
	self.versions = append(self.versions, &copied)
	return nil
}

func (self *fakeComputeCatalogStore) SetExposure(ctx context.Context, version uint64, exposures []*ComputeDirectExposure, at time.Time) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, stored := range self.versions {
		if stored.Version == version {
			stored.Exposures = slices.Clone(exposures)
			stored.ExposureTime = at
			return nil
		}
	}
	return errors.New("no such version")
}

// The newest version the store holds.
func (self *fakeComputeCatalogStore) newest(t testing.TB) *ComputeCatalogVersion {
	t.Helper()
	versions, err := self.Newest(context.Background(), 1)
	if err != nil || len(versions) != 1 {
		t.Fatalf("no version: %v", err)
	}
	return versions[0]
}

// A model of a provider's catalog, priced in nano-gamma per million tokens.
func testCatalogProviderModel(modelId string, label sidecar.ComputeLabel, input int64, output int64, cached int64) *ComputeProviderModel {
	return &ComputeProviderModel{
		ModelId:                        modelId,
		Label:                          label,
		Efforts:                        []sidecar.InferEffort{sidecar.InferEffortOff, sidecar.InferEffortLow, sidecar.InferEffortHigh},
		ContextWindow:                  128 * 1024,
		MaxOutput:                      16 * 1024,
		Tools:                          true,
		StructuredOutput:               true,
		Modalities:                     []sidecar.InferModality{sidecar.InferModalityText},
		License:                        "mit",
		InputNanoGammaPerMillion:       input,
		OutputNanoGammaPerMillion:      output,
		CachedInputNanoGammaPerMillion: cached,
	}
}

// One provider's checked read.
func testCatalogRead(provider ComputeProviderId, gammaNanoUsd int64, models ...*ComputeProviderModel) *computeProviderCatalogRead {
	return &computeProviderCatalogRead{
		Provider: provider,
		Catalog:  &ComputeProviderCatalog{Provider: provider, GammaNanoUsd: gammaNanoUsd, Models: models},
	}
}

// A job over a test's reads and store, on a fake clock.
type testCatalogJob struct {
	t       testing.TB
	clock   *sidecartest.FakeClock
	store   *fakeComputeCatalogStore
	metrics *sidecartest.FakeMetrics
	log     *testComputeLog
	job     *ComputeProviderPricesJob

	readsLock sync.Mutex
	reads     []*computeProviderCatalogRead
}

func newTestCatalogJob(t testing.TB, policy *sidecar.ComputePolicy, sections []*computeCatalogSection) *testCatalogJob {
	self := &testCatalogJob{
		t:       t,
		clock:   sidecartest.NewFakeClock(sidecartest.DefaultClockStart()),
		store:   &fakeComputeCatalogStore{},
		metrics: sidecartest.NewFakeMetrics(nil),
		log:     &testComputeLog{},
	}
	if sections == nil {
		sections = []*computeCatalogSection{}
	}
	job, err := NewComputeProviderPricesJob(&ComputeProviderPricesJobArgs{
		Policy:  func() *sidecar.ComputePolicy { return policy },
		Metrics: self.metrics,
		Clock:   self.clock,
		Log:     self.log,
		testReadPrices: func(ctx context.Context, now time.Time) ([]*computeProviderCatalogRead, error) {
			self.readsLock.Lock()
			defer self.readsLock.Unlock()
			return self.reads, nil
		},
		testStore:    self.store,
		testSections: sections,
	})
	if err != nil {
		t.Fatal(err)
	}
	self.job = job
	return self
}

// Runs the job over reads.
func (self *testCatalogJob) run(reads ...*computeProviderCatalogRead) {
	self.t.Helper()
	self.readsLock.Lock()
	self.reads = reads
	self.readsLock.Unlock()
	if err := self.job.Run(context.Background()); err != nil {
		self.t.Fatal(err)
	}
}

// The model of answer named provider-model, or nil.
func testCatalogModel(answer *protocol.InferCatalogAnswer, provider string, part string) *protocol.InferCatalogModel {
	for _, catalogModel := range answer.GetModels() {
		if catalogModel.GetProvider() == provider && catalogModel.GetModel() == part {
			return catalogModel
		}
	}
	return nil
}

// A logger that keeps every line, safe for concurrent use.
type testComputeLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *testComputeLog) add(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *testComputeLog) Info(args ...any)                 { self.add(fmt.Sprint(args...)) }
func (self *testComputeLog) Infof(format string, args ...any) { self.add(fmt.Sprintf(format, args...)) }
func (self *testComputeLog) Warningf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testComputeLog) Errorf(format string, args ...any) {
	self.add(fmt.Sprintf(format, args...))
}
func (self *testComputeLog) V(level int32) sidecar.Verbose { return testComputeVerbose{log: self} }

func (self *testComputeLog) text() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return strings.Join(self.lines, "\n")
}

type testComputeVerbose struct {
	log *testComputeLog
}

func (self testComputeVerbose) Enabled() bool                    { return true }
func (self testComputeVerbose) Info(args ...any)                 { self.log.Info(args...) }
func (self testComputeVerbose) Infof(format string, args ...any) { self.log.Infof(format, args...) }

// Each price is the provider's gamma price at the read's gamma value, times 1.20, rounded up to $0.001 a million: BAL's
// price function over the cost the broker pays.
func TestCatalogBuildPricesAtMarkupRoundedUp(t *testing.T) {
	job := newTestCatalogJob(t, nil, nil)
	// engy's gamma at $1.05; $1.00, $2.000000007 and $0.10 a million tokens in gamma
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_050_000_000,
		testCatalogProviderModel("DeepSeek-V4.1-Flash", sidecar.ComputeLabelNone, 1_000_000_000, 2_000_000_007, 100_000_000)))
	answer := job.store.newest(t).Answer
	catalogModel := testCatalogModel(answer, "engy", "deepseek-v4.1-flash")
	if catalogModel == nil {
		t.Fatalf("no model: %v", answer)
	}
	// $1.05 a million at the read, $1.26 at 1.20: exact, no rounding
	if catalogModel.GetInputNanoUsdPerMillion() != 1_260_000_000 {
		t.Errorf("input %d", catalogModel.GetInputNanoUsdPerMillion())
	}
	ledger := model.DefaultComputeLedgerSettings()
	for _, c := range []struct {
		nanoGamma int64
		got       int64
	}{
		{nanoGamma: 2_000_000_007, got: catalogModel.GetOutputNanoUsdPerMillion()},
		{nanoGamma: 100_000_000, got: catalogModel.GetCachedInputNanoUsdPerMillion()},
	} {
		cost, err := computeNanoGammaToNanoUsd(c.nanoGamma, 1_050_000_000)
		if err != nil {
			t.Fatal(err)
		}
		want, err := model.ComputeRetailPrice(ledger, model.ComputePriceClassTokens, cost)
		if err != nil {
			t.Fatal(err)
		}
		if c.got != want || c.got%ledger.TokenPriceStepNanoUsd != 0 || c.got*5 < cost*6 {
			t.Errorf("%d nano-gamma priced %d, BAL's function %d", c.nanoGamma, c.got, want)
		}
	}
	// 2,000,000,007 nano-gamma at 1.05 costs 2,100,000,008 nano-USD, rounded up, and 1.20 of it rounds up to $2.521
	if catalogModel.GetOutputNanoUsdPerMillion() != 2_521_000_000 {
		t.Errorf("output %d", catalogModel.GetOutputNanoUsdPerMillion())
	}
	if catalogModel.GetKind() != protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT || catalogModel.GetLabel() != "none" ||
		catalogModel.GetDefaultEffort() != "low" || catalogModel.GetProviderModelId() != "DeepSeek-V4.1-Flash" {
		t.Errorf("the model: %v", catalogModel)
	}
}

// A provider whose price varies by request is listed at the most it charges, which its adapter reads as its price.
func TestCatalogVaryingPriceListedAtMax(t *testing.T) {
	job := newTestCatalogJob(t, nil, nil)
	varying := testCatalogProviderModel("gm-router-large", sidecar.ComputeLabelNone, 3_000_000_000, 9_000_000_000, 0)
	varying.PriceVaries = true
	job.run(testCatalogRead(ComputeProviderIdSaygm, 1_000_000_000, varying))
	catalogModel := testCatalogModel(job.store.newest(t).Answer, "saygm", "gm-router-large")
	if catalogModel == nil || !catalogModel.GetPriceVaries() {
		t.Fatalf("the model: %v", catalogModel)
	}
	if catalogModel.GetInputNanoUsdPerMillion() != 3_600_000_000 || catalogModel.GetOutputNanoUsdPerMillion() != 10_800_000_000 {
		t.Errorf("listed at %d and %d, not the most it charges times 1.20", catalogModel.GetInputNanoUsdPerMillion(), catalogModel.GetOutputNanoUsdPerMillion())
	}
}

// An hourly read takes out at once a model whose cost passed its price and one its provider stopped offering, keeps a
// failed provider's models, adds no new one until the day's rebuild, and publishes nothing when nothing changed.
func TestCatalogDropsModelWhoseCostPassesPrice(t *testing.T) {
	job := newTestCatalogJob(t, nil, nil)
	gamma := int64(1_000_000_000)
	rising := testCatalogProviderModel("rising", sidecar.ComputeLabelNone, 1_000_000_000, 1_000_000_000, 0)
	leaving := testCatalogProviderModel("leaving", sidecar.ComputeLabelNone, 1_000_000_000, 1_000_000_000, 0)
	steady := testCatalogProviderModel("steady", sidecar.ComputeLabelNone, 1_000_000_000, 1_000_000_000, 0)
	failing := testCatalogProviderModel("kept", sidecar.ComputeLabelNone, 1_000_000_000, 1_000_000_000, 0)
	job.run(testCatalogRead(ComputeProviderIdEngy, gamma, rising, leaving, steady), testCatalogRead(ComputeProviderIdSaygm, gamma, failing))
	if version := job.store.newest(t); version.Version != 1 || len(version.Answer.GetModels()) != 4 {
		t.Fatalf("the first version: %d with %d models", version.Version, len(version.Answer.GetModels()))
	}
	job.clock.Advance(time.Hour)
	// rising's cost passes its price ($1.20 at 1.20) once it costs $1.25; leaving is gone; saygm's read failed; a new
	// model waits for the rebuild
	risen := testCatalogProviderModel("rising", sidecar.ComputeLabelNone, 1_250_000_000, 1_000_000_000, 0)
	added := testCatalogProviderModel("added", sidecar.ComputeLabelNone, 1_000_000_000, 1_000_000_000, 0)
	job.run(testCatalogRead(ComputeProviderIdEngy, gamma, risen, steady, added),
		&computeProviderCatalogRead{Provider: ComputeProviderIdSaygm, Err: errors.New("planted: timed out")})
	version := job.store.newest(t)
	if version.Version != 2 {
		t.Fatalf("no version for the prune: %d", version.Version)
	}
	for part, want := range map[string]bool{"rising": false, "leaving": false, "steady": true, "added": false} {
		if (testCatalogModel(version.Answer, "engy", part) != nil) != want {
			t.Errorf("engy-%s listed %t", part, !want)
		}
	}
	if testCatalogModel(version.Answer, "saygm", "kept") == nil {
		t.Error("a failed read's model was taken out")
	}
	// steady's price is the first version's, not repriced before the rebuild
	if steady := testCatalogModel(version.Answer, "engy", "steady"); steady.GetInputNanoUsdPerMillion() != 1_200_000_000 {
		t.Errorf("steady repriced: %d", steady.GetInputNanoUsdPerMillion())
	}
	job.clock.Advance(time.Hour)
	job.run(testCatalogRead(ComputeProviderIdEngy, gamma, steady), testCatalogRead(ComputeProviderIdSaygm, gamma, failing))
	if version := job.store.newest(t); version.Version != 2 {
		t.Errorf("an unchanged read published version %d", version.Version)
	}
	// a provider no longer enabled loses its models at once
	job.clock.Advance(time.Hour)
	job.run(testCatalogRead(ComputeProviderIdEngy, gamma, steady))
	if version := job.store.newest(t); version.Version != 3 || testCatalogModel(version.Answer, "saygm", "kept") != nil {
		t.Errorf("a disabled provider's model stayed: version %d", version.Version)
	}
	// the day's rebuild adds and reprices
	job.clock.Advance(DefaultComputeBrokerSettings().CatalogRebuildInterval)
	job.run(testCatalogRead(ComputeProviderIdEngy, gamma, steady, added))
	if version := job.store.newest(t); version.Version != 4 || testCatalogModel(version.Answer, "engy", "added") == nil {
		t.Errorf("the rebuild did not add the new model: version %d", version.Version)
	}
}

// A request's version is taken while it is current, and the one before it for 24 hours after a newer one; any other is
// catalog_stale, and a version newer than the one an engine holds is read again.
func TestCatalogVersionCurrentAndPreviousWithin24Hours(t *testing.T) {
	store := &fakeComputeCatalogStore{}
	fixture := newComputeFixture(t, &computeFixtureOptions{catalogStore: store})
	publish := func(version uint64) {
		answer := &protocol.InferCatalogAnswer{Version: version, PublishedMs: fixture.clock.Now().UnixMilli()}
		if err := store.Publish(context.Background(), &ComputeCatalogVersion{Version: version, PublishedTime: fixture.clock.Now(), Answer: answer}); err != nil {
			t.Fatal(err)
		}
	}
	at := func(version uint64) ComputeRefusalCode {
		found, refusal := fixture.engine.computeCatalogAt(context.Background(), version)
		if refusal != nil {
			return refusal.Code
		}
		if found.Version != version {
			t.Fatalf("asked %d, answered %d", version, found.Version)
		}
		return ""
	}
	if code := at(1); code != ComputeRefusalUnavailable {
		t.Errorf("before any version: %q", code)
	}
	publish(1)
	fixture.clock.Advance(time.Hour)
	publish(2)
	// the engine read version 1 alone a moment ago; a request naming 2 reads again
	if code := at(2); code != "" {
		t.Errorf("the current version: %q", code)
	}
	fixture.clock.Advance(24*time.Hour - time.Second)
	if code := at(1); code != "" {
		t.Errorf("the previous version within 24 hours: %q", code)
	}
	fixture.clock.Advance(time.Second)
	if code := at(1); code != ComputeRefusalCatalogStale {
		t.Errorf("the previous version at 24 hours: %q", code)
	}
	if code := at(0); code != ComputeRefusalCatalogStale {
		t.Errorf("version 0: %q", code)
	}
	if code := at(3); code != ComputeRefusalCatalogStale {
		t.Errorf("a version no one published: %q", code)
	}
	publish(3)
	if code := at(3); code != "" {
		t.Errorf("a version published since the engine read: %q", code)
	}
	// 1 is two versions back now, whatever the time
	if code := at(1); code != ComputeRefusalCatalogStale {
		t.Errorf("two versions back: %q", code)
	}
}

// ENC's shapes and SRCH's search ids join a version as sections from their own builders, in name order, and a builder
// that fails leaves its section out and the models in.
func TestCatalogSectionsJoin(t *testing.T) {
	sections := []*computeCatalogSection{
		{name: "search", build: func(ctx context.Context, args *ComputeCatalogSectionArgs) ([]byte, error) {
			return []byte("search ids"), nil
		}},
		{name: "enclave", build: func(ctx context.Context, args *ComputeCatalogSectionArgs) ([]byte, error) {
			if len(args.Catalogs) != 1 || args.Ledger == nil {
				return nil, errors.New("planted: no catalogs")
			}
			return []byte("shapes"), nil
		}},
		{name: "broken", build: func(ctx context.Context, args *ComputeCatalogSectionArgs) ([]byte, error) {
			return nil, errors.New("planted: a failed section")
		}},
	}
	job := newTestCatalogJob(t, nil, sections)
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_000_000_000, testCatalogProviderModel("m", sidecar.ComputeLabelNone, 1, 1, 1)))
	answer := job.store.newest(t).Answer
	names := []string{}
	for _, section := range answer.GetSections() {
		names = append(names, section.GetName())
	}
	if !slices.Equal(names, []string{"enclave", "search"}) || string(answer.GetSections()[0].GetBody()) != "shapes" {
		t.Errorf("sections %v", names)
	}
	if len(answer.GetModels()) != 1 {
		t.Errorf("a failed section took the models with it: %d", len(answer.GetModels()))
	}
	if !strings.Contains(job.log.text(), "broken") {
		t.Error("the failed section was not logged")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("a second registration of one section did not panic")
			}
		}()
		registered := computeCatalogSections
		t.Cleanup(func() { computeCatalogSections = registered })
		computeCatalogRegisterSection("planted", sections[0].build)
		computeCatalogRegisterSection("planted", sections[0].build)
	}()
}

// Each direct provider's costliest worst case, over its whole list at the network's prices, is recomputed at each read,
// published with the version that stands and gauged, and a rise is logged for the page.
func TestDirectExposureRecomputedAndRiseSignalled(t *testing.T) {
	job := newTestCatalogJob(t, nil, nil)
	cheap := testCatalogProviderModel("cheap", sidecar.ComputeLabelNone, 100_000_000, 400_000_000, 0)
	costly := testCatalogProviderModel("costly", sidecar.ComputeLabelNone, 1_000_000_000, 4_000_000_000, 0)
	tee := testCatalogProviderModel("tee-model", sidecar.ComputeLabelAp, 9_000_000_000, 9_000_000_000, 0)
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_000_000_000, cheap, costly), testCatalogRead(ComputeProviderIdChutes, 1_000_000_000, tee))
	version := job.store.newest(t)
	exposure := version.Exposure(ComputeProviderIdEngy)
	want, err := model.ComputeWorstCase(costly.ContextWindow, costly.MaxOutput, 1_200_000_000, 4_800_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if exposure == nil || exposure.WorstCaseNanoUsd != want || exposure.ModelId != "costly" {
		t.Fatalf("engy's exposure %+v, want %d", exposure, want)
	}
	if version.Exposure(ComputeProviderIdChutes) != nil {
		t.Error("a TEE provider has a direct exposure")
	}
	if got := job.metrics.Value(computeDirectWorstCaseMetric, "engy"); got != float64(want) {
		t.Errorf("the gauge reads %v", got)
	}
	// a model the provider adds above its costliest raises it at the next read, before any rebuild lists the model
	job.clock.Advance(time.Hour)
	costlier := testCatalogProviderModel("costlier", sidecar.ComputeLabelNone, 2_000_000_000, 8_000_000_000, 0)
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_000_000_000, cheap, costly, costlier), testCatalogRead(ComputeProviderIdChutes, 1_000_000_000, tee))
	version = job.store.newest(t)
	if version.Version != 1 {
		t.Fatalf("the read published version %d", version.Version)
	}
	raised := version.Exposure(ComputeProviderIdEngy)
	if raised == nil || raised.WorstCaseNanoUsd <= want || raised.ModelId != "costlier" || !version.ExposureTime.Equal(job.clock.Now()) {
		t.Errorf("the exposure after the rise: %+v at %v", raised, version.ExposureTime)
	}
	if got := job.metrics.Value(computeDirectWorstCaseMetric, "engy"); got != float64(raised.WorstCaseNanoUsd) {
		t.Errorf("the gauge reads %v after the rise", got)
	}
	if !strings.Contains(job.log.text(), "rose") {
		t.Error("the rise was not signalled")
	}
}

// Two of a provider's ids that normalize to one name keep the one the policy names, and with no policy neither.
func TestCatalogCollisionKeepsThePolicysId(t *testing.T) {
	first := testCatalogProviderModel("deepseek:v4", sidecar.ComputeLabelNone, 1, 1, 1)
	second := testCatalogProviderModel("DeepSeek_V4", sidecar.ComputeLabelNone, 1, 1, 1)
	job := newTestCatalogJob(t, nil, nil)
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_000_000_000, first, second))
	if models := job.store.newest(t).Answer.GetModels(); len(models) != 0 {
		t.Errorf("with no policy %d colliding ids were listed", len(models))
	}
	policy := &sidecar.ComputePolicy{Direct: sidecar.ComputePolicyDirectLine{Providers: []*sidecar.ComputePolicyDirect{{
		Slug:   "engy",
		Models: []*sidecar.ComputePolicyDirectModel{{Model: "deepseek-v4", ProviderModelId: "DeepSeek_V4"}},
	}}}}
	job = newTestCatalogJob(t, policy, nil)
	job.run(testCatalogRead(ComputeProviderIdEngy, 1_000_000_000, first, second))
	models := job.store.newest(t).Answer.GetModels()
	if len(models) != 1 || models[0].GetProviderModelId() != "DeepSeek_V4" {
		t.Errorf("the policy's id did not win: %v", models)
	}
}

// GET /v1/catalog answers the current version with the broker's clock through the guard, and 503 before any version
// is published.
func TestCatalogRouteAnswersTheCurrentVersion(t *testing.T) {
	store := &fakeComputeCatalogStore{}
	fixture := newComputeFixture(t, &computeFixtureOptions{
		handlers:     map[string]ComputeHandler{ComputeRouteCatalog: serveComputeCatalog},
		catalogStore: store,
	})
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil); recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("before any version: %d", recorder.Code)
	}
	answer := &protocol.InferCatalogAnswer{Version: 1, Models: []*protocol.InferCatalogModel{{Provider: "engy", Model: "m"}}}
	if err := store.Publish(context.Background(), &ComputeCatalogVersion{Version: 1, PublishedTime: fixture.clock.Now(), Answer: answer}); err != nil {
		t.Fatal(err)
	}
	fixture.clock.Advance(DefaultComputeBrokerSettings().CatalogCacheMaxAge)
	recorder := fixture.serve(http.MethodGet, "/v1/catalog", fixture.token(), "", nil)
	if recorder.Code != http.StatusOK || recorder.Header().Get("Content-Type") != computeContentTypeProtobuf {
		t.Fatalf("answered %d %s", recorder.Code, recorder.Header().Get("Content-Type"))
	}
	got := &protocol.InferCatalogAnswer{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), got); err != nil {
		t.Fatal(err)
	}
	if got.GetVersion() != 1 || got.GetBrokerTimeMs() != fixture.clock.Now().UnixMilli() || len(got.GetModels()) != 1 {
		t.Errorf("the answer: %v", got)
	}
	if recorder.Header().Get(sidecar.ComputeServiceTimeHeader) == "" {
		t.Error("the answer carries no broker clock")
	}
	// a refusal carries the clock too, and the route has no caller without a token
	refused := fixture.serve(http.MethodGet, "/v1/catalog", "", "", nil)
	if refused.Code != http.StatusUnauthorized || refused.Header().Get(sidecar.ComputeServiceTimeHeader) == "" {
		t.Errorf("without a token: %d, clock %q", refused.Code, refused.Header().Get(sidecar.ComputeServiceTimeHeader))
	}
}
