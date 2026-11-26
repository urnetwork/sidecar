//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A fetcher that answers its script in turn, the last again once the script runs out.
type testInferCatalogFetcher struct {
	stateLock sync.Mutex
	answers   []*protocol.InferCatalogAnswer
	errs      []error
	fetches   int
}

func (self *testInferCatalogFetcher) FetchCatalog(ctx context.Context) (*protocol.InferCatalogAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	index := min(self.fetches, len(self.answers)-1)
	self.fetches += 1
	if index < len(self.errs) && self.errs[index] != nil {
		return nil, self.errs[index]
	}
	return self.answers[index], nil
}

// A policy with one TEE provider and one direct one, each covering one model.
func testInferCatalogPolicy() *ComputePolicy {
	return &ComputePolicy{
		Providers: []*ComputePolicyProvider{{
			Id:       "chutes",
			Label:    ComputeLabelAp,
			Models:   []*ComputePolicyModel{{Model: "qwen3.8-27b-tee", ProviderModelId: "chute-0001"}},
			Profiles: []*ComputePolicyProfile{{Id: "profile-a"}, {Id: "profile-revoked"}},
		}},
		Direct: ComputePolicyDirectLine{Providers: []*ComputePolicyDirect{{
			Slug:           "engy",
			ApiHost:        "api.engy.example",
			ReceiverHotkey: "5ReceiverEngy",
			Targets:        []*ComputePolicyDirectTarget{{Method: http.MethodPost, Path: "/v1/chat/completions"}},
			Models: []*ComputePolicyDirectModel{{
				Model: "deepseek-v4.1-flash", ProviderModelId: "deepseek-v4.1-flash-1017", ZeroRetention: true,
			}},
		}}},
		Revoked: ComputePolicyRevoked{Profiles: []string{"profile-revoked"}},
	}
}

// A catalog model of provider, the broker's reading.
func testInferCatalogAnswerModel(provider string, part string, kind protocol.InferCatalogModelKind, label string) *protocol.InferCatalogModel {
	return &protocol.InferCatalogModel{
		Provider:                     provider,
		Model:                        part,
		Kind:                         kind,
		Label:                        label,
		Efforts:                      []string{"off", "high"},
		DefaultEffort:                "off",
		ContextWindow:                128 * 1024,
		MaxOutput:                    8 * 1024,
		Tools:                        true,
		Modalities:                   []string{"text"},
		ProviderModelId:              "broker-says-" + part,
		InputNanoUsdPerMillion:       1_200_000_000,
		OutputNanoUsdPerMillion:      2_400_000_000,
		CachedInputNanoUsdPerMillion: 120_000_000,
	}
}

// A remote catalog over fetcher and policy, on clock.
func newTestInferRemoteCatalog(t *testing.T, fetcher *testInferCatalogFetcher, policy *ComputePolicy, clock Clock) *inferRemoteCatalog {
	t.Helper()
	catalog, err := newInferRemoteCatalog(&inferRemoteCatalogArgs{
		Ctx:     context.Background(),
		Fetcher: fetcher,
		Policy: func() (*ComputePolicy, error) {
			if policy == nil {
				return nil, errors.New("planted: no policy is current")
			}
			return policy, nil
		},
		Settings: DefaultInferSettings(),
		Clock:    clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	return catalog
}

// The entry of entries named provider-model, or nil.
func testInferJoinedEntry(entries []*InferCatalogEntry, provider string, part string) *InferCatalogEntry {
	index := slices.IndexFunc(entries, func(entry *InferCatalogEntry) bool {
		return entry.Provider == provider && entry.Model == part
	})
	if index < 0 {
		return nil
	}
	return entries[index]
}

// A model the policy does not cover, in a TEE or not, is listed unusable and never resolves to run; a covered one takes
// its label and its provider's id from the policy, and with no current policy none is usable.
func TestRemoteCatalogUncoveredEntryUnusable(t *testing.T) {
	answer := &protocol.InferCatalogAnswer{Version: 1, Models: []*protocol.InferCatalogModel{
		testInferCatalogAnswerModel("chutes", "qwen3.8-27b-tee", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_TEE, "A1"),
		testInferCatalogAnswerModel("chutes", "uncovered-tee", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_TEE, "AP"),
		testInferCatalogAnswerModel("saygm", "unlisted", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
		testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
	}}
	catalog := newTestInferRemoteCatalog(t, &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{answer}}, testInferCatalogPolicy(), newTestEnvelopeClock())
	entries, err := catalog.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	covered := testInferJoinedEntry(entries, "chutes", "qwen3.8-27b-tee")
	if covered == nil || covered.Unavailable != "" {
		t.Fatalf("the covered TEE model: %+v", covered)
	}
	// the policy's label, never the catalog's A1, and the policy's id and profiles
	if covered.Label != ComputeLabelAp || covered.Remote.ProviderModelId != "chute-0001" || !slices.Equal(covered.Remote.Profiles, []string{"profile-a"}) {
		t.Errorf("the covered TEE model's fields: %s %q %v", covered.Label, covered.Remote.ProviderModelId, covered.Remote.Profiles)
	}
	for _, part := range []string{"uncovered-tee", "unlisted"} {
		provider := "chutes"
		if part == "unlisted" {
			provider = "saygm"
		}
		entry := testInferJoinedEntry(entries, provider, part)
		if entry == nil || entry.Unavailable == "" {
			t.Errorf("%s-%s is listed usable: %+v", provider, part, entry)
		}
	}
	local, err := newInferCatalog(nil, nil, "", DefaultInferSettings())
	if err != nil {
		t.Fatal(err)
	}
	joined, err := local.Join(entries)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := joined.Resolve("chutes-uncovered-tee-high", ""); !errors.Is(err, ErrInferModelUnavailable) {
		t.Errorf("an uncovered model resolved to run: %v", err)
	}
	if resolution, err := joined.Resolve("chutes-qwen3.8-27b-tee-high", ""); err != nil || resolution.Entry.Remote.ProviderModelId != "chute-0001" {
		t.Errorf("the covered model: %v, %v", resolution, err)
	}
	// no current policy: nothing usable, each saying why
	unpoliced := newTestInferRemoteCatalog(t, &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{answer}}, nil, newTestEnvelopeClock())
	entries, err = unpoliced.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Unavailable == "" {
			t.Errorf("%s-%s is usable with no policy", entry.Provider, entry.Model)
		}
	}
}

// A direct model's provider id, its zero-retention rule and upstreams come from the policy's models map alone, and a
// catalog that names another host, receiver or target than the policy pins loses: the model is listed unusable.
func TestRemoteCatalogDirectFieldsFromPolicyOnly(t *testing.T) {
	direct := func(change func(model *protocol.InferCatalogModel)) *InferCatalogEntry {
		model := testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none")
		model.Host = "api.engy.example"
		model.ReceiverHotkey = "5ReceiverEngy"
		model.Targets = []*protocol.InferCatalogTarget{{Method: http.MethodPost, Path: "/v1/chat/completions"}}
		change(model)
		answer := &protocol.InferCatalogAnswer{Version: 1, Models: []*protocol.InferCatalogModel{model}}
		catalog := newTestInferRemoteCatalog(t, &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{answer}}, testInferCatalogPolicy(), newTestEnvelopeClock())
		entries, err := catalog.Entries(context.Background())
		if err != nil || len(entries) != 1 {
			t.Fatalf("%d entries: %v", len(entries), err)
		}
		return entries[0]
	}
	entry := direct(func(model *protocol.InferCatalogModel) {
		model.ProviderModelId = "another-model-entirely"
		model.ServingCodeUnmeasured = true
	})
	if entry.Unavailable != "" || entry.Remote.ProviderModelId != "deepseek-v4.1-flash-1017" || entry.Label != ComputeLabelNone ||
		entry.Remote.ServingCodeUnmeasured {
		t.Errorf("the catalog's words won: %+v %+v", entry, entry.Remote)
	}
	if entry := direct(func(model *protocol.InferCatalogModel) {
		model.Host, model.ReceiverHotkey, model.Targets = "", "", nil
	}); entry.Unavailable != "" {
		t.Errorf("a catalog naming no target refused: %q", entry.Unavailable)
	}
	for name, change := range map[string]func(model *protocol.InferCatalogModel){
		"another host":     func(model *protocol.InferCatalogModel) { model.Host = "api.elsewhere.example" },
		"another receiver": func(model *protocol.InferCatalogModel) { model.ReceiverHotkey = "5ReceiverElsewhere" },
		"another target": func(model *protocol.InferCatalogModel) {
			model.Targets = append(model.Targets, &protocol.InferCatalogTarget{Method: http.MethodPost, Path: "/v1/elsewhere"})
		},
	} {
		if entry := direct(change); entry.Unavailable == "" || !strings.Contains(entry.Unavailable, "policy") {
			t.Errorf("a catalog naming %s left the model usable: %q", name, entry.Unavailable)
		}
	}
}

// A catalog in which two entries share a name is refused whole and the last good one kept, and so is one older than
// the version kept.
func TestRemoteCatalogCollisionKeepsLastGood(t *testing.T) {
	good := &protocol.InferCatalogAnswer{Version: 1, Models: []*protocol.InferCatalogModel{
		testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
	}}
	colliding := &protocol.InferCatalogAnswer{Version: 2, Models: []*protocol.InferCatalogModel{
		testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
		testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
	}}
	older := &protocol.InferCatalogAnswer{Version: 0}
	clock := newTestEnvelopeClock()
	fetcher := &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{good, colliding, older}}
	catalog := newTestInferRemoteCatalog(t, fetcher, testInferCatalogPolicy(), clock)
	if version, err := catalog.Version(context.Background()); err != nil || version != 1 {
		t.Fatalf("the first fetch: %d, %v", version, err)
	}
	if _, _, err := InferCatalogAnswerEntries(colliding, DefaultInferSettings()); !errors.Is(err, ErrInferCatalogAnswer) {
		t.Errorf("a colliding catalog read: %v", err)
	}
	for range 2 {
		clock.Advance(DefaultInferSettings().RemoteCatalogMaxAge)
		if err := catalog.fetchNow(context.Background()); err == nil {
			t.Error("a refused catalog was taken")
		}
		entries, err := catalog.Entries(context.Background())
		version, versionErr := catalog.Version(context.Background())
		if err != nil || versionErr != nil || version != 1 || len(entries) != 1 {
			t.Errorf("after a refused fetch: version %d, %d entries, %v %v", version, len(entries), err, versionErr)
		}
	}
	// an entry that is not whole is left out, the rest kept
	partial := &protocol.InferCatalogAnswer{Version: 3, Models: []*protocol.InferCatalogModel{
		testInferCatalogAnswerModel("engy", "deepseek-v4.1-flash", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
		testInferCatalogAnswerModel("engy", "glm-tee", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_DIRECT, "none"),
		testInferCatalogAnswerModel("local", "gemma", protocol.InferCatalogModelKind_INFER_CATALOG_MODEL_KIND_TEE, "AP"),
	}}
	entries, faults, err := InferCatalogAnswerEntries(partial, DefaultInferSettings())
	if err != nil || len(entries) != 1 || len(faults) != 2 {
		t.Errorf("a partial catalog: %d entries, faults %v, %v", len(entries), faults, err)
	}
}

// A request the broker refuses catalog_stale fetches the catalog and asks once more with the new version; refused
// again, it is ErrInferCatalogStale, having asked twice.
func TestRemoteCatalogStaleRetriesOnce(t *testing.T) {
	stale := &ComputeServiceError{Route: "POST /v1/infer/authorize", Status: http.StatusConflict, Code: "catalog_stale"}
	first := &protocol.InferCatalogAnswer{Version: 4}
	second := &protocol.InferCatalogAnswer{Version: 5}
	fetcher := &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{first, second}}
	catalog := newTestInferRemoteCatalog(t, fetcher, testInferCatalogPolicy(), newTestEnvelopeClock())
	asked := []uint64{}
	err := catalog.WithVersion(context.Background(), func(version uint64) error {
		asked = append(asked, version)
		if version == 4 {
			return stale
		}
		return nil
	})
	if err != nil || !slices.Equal(asked, []uint64{4, 5}) || fetcher.fetches != 2 {
		t.Errorf("asked %v, fetched %d: %v", asked, fetcher.fetches, err)
	}
	asked = asked[:0]
	third := &protocol.InferCatalogAnswer{Version: 6}
	fetcher.answers = append(fetcher.answers, third)
	err = catalog.WithVersion(context.Background(), func(version uint64) error {
		asked = append(asked, version)
		return stale
	})
	if !errors.Is(err, ErrInferCatalogStale) || !slices.Equal(asked, []uint64{5, 6}) {
		t.Errorf("refused stale twice: asked %v: %v", asked, err)
	}
	// any other answer is ask's own, asked once
	asked = asked[:0]
	capacity := &ComputeServiceError{Code: "capacity"}
	err = catalog.WithVersion(context.Background(), func(version uint64) error {
		asked = append(asked, version)
		return capacity
	})
	if !errors.Is(err, capacity) || len(asked) != 1 {
		t.Errorf("another refusal: asked %v: %v", asked, err)
	}
}

// A section reader an area registers joins its entries, search endpoints alone; a section no reader reads is passed
// over.
func TestRemoteCatalogSectionsJoin(t *testing.T) {
	readers := inferCatalogSectionReaders
	t.Cleanup(func() { inferCatalogSectionReaders = readers })
	inferCatalogSectionReaders = map[string]InferCatalogSectionReader{}
	registerInferCatalogSection("search", func(body []byte, settings *InferSettings) ([]*InferCatalogEntry, error) {
		return []*InferCatalogEntry{
			{Provider: "parallel", Kind: InferCatalogKindSearch, Label: ComputeLabelNone, Search: &InferSearchEndpoint{Kind: string(body), NanoUsdPerSearch: 5_000_000}},
			{Provider: "local", Model: "sneaky", Kind: InferCatalogKindLocal, Label: ComputeLabelLocal, Local: &InferLocalModel{}},
		}, nil
	})
	answer := &protocol.InferCatalogAnswer{Version: 1, Sections: []*protocol.InferCatalogSection{
		{Name: "search", Body: []byte("fast")},
		{Name: "enclave", Body: []byte("no reader on the device")},
	}}
	catalog := newTestInferRemoteCatalog(t, &testInferCatalogFetcher{answers: []*protocol.InferCatalogAnswer{answer}}, testInferCatalogPolicy(), newTestEnvelopeClock())
	entries, err := catalog.Entries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SearchId() != "search/parallel/fast" {
		t.Errorf("the joined sections: %+v", entries)
	}
	defer func() {
		if recover() == nil {
			t.Error("a second reader of one section did not panic")
		}
	}()
	registerInferCatalogSection("search", func(body []byte, settings *InferSettings) ([]*InferCatalogEntry, error) { return nil, nil })
}

// A fetch that fails keeps the last good catalog, and with none says why; past RemoteCatalogMaxAge the kept catalog is
// listed at once while it is fetched again in the background, and a failure is not tried again within
// RemoteCatalogFailureRetryInterval.
func TestRemoteCatalogFetchFailureKeepsLastGood(t *testing.T) {
	clock := newTestEnvelopeClock()
	failure := errors.New("planted: the broker did not answer")
	fetcher := &testInferCatalogFetcher{
		answers: []*protocol.InferCatalogAnswer{nil, {Version: 1}, nil},
		errs:    []error{failure, nil, failure},
	}
	catalog := newTestInferRemoteCatalog(t, fetcher, testInferCatalogPolicy(), clock)
	if _, err := catalog.Entries(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("with no catalog: %v", err)
	}
	// within the failure's interval nothing is fetched again
	catalog.Entries(context.Background())
	if fetcher.fetches != 1 {
		t.Errorf("%d fetches within the failure's interval", fetcher.fetches)
	}
	clock.Advance(DefaultInferSettings().RemoteCatalogFailureRetryInterval)
	if version, err := catalog.Version(context.Background()); err != nil || version != 1 {
		t.Fatalf("after the interval: %d, %v", version, err)
	}
	clock.Advance(DefaultInferSettings().RemoteCatalogMaxAge + time.Second)
	if version, err := catalog.Version(context.Background()); err != nil || version != 1 {
		t.Errorf("past its age: %d, %v", version, err)
	}
	<-catalog.idle()
	if version, err := catalog.Version(context.Background()); err != nil || version != 1 || fetcher.fetches != 3 {
		t.Errorf("a failed fetch past its age: %d, %v, %d fetches", version, err, fetcher.fetches)
	}
	<-catalog.idle()
	if fetcher.fetches != 3 {
		t.Errorf("a failure was fetched again within its interval: %d fetches", fetcher.fetches)
	}
}
