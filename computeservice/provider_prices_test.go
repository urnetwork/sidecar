package computeservice

// The hourly price read (PROV-M12-01; DESIGN-COMPUTE §9.6, §4.7): each serving provider's catalog read and stored as
// one row a model or shape for the hour, one provider's failure stopping no other's, and a catalog that does not check
// refused whole. The rows' SQL runs on the private test stack in server's cmd_compute_provider_server_test.go.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A test adapter whose catalog a test sets.
type catalogComputeProvider struct {
	ComputeProviderBase
	catalog func(ctx context.Context) (*ComputeProviderCatalog, error)
}

func (self *catalogComputeProvider) Catalog(ctx context.Context) (*ComputeProviderCatalog, error) {
	return self.catalog(ctx)
}

// A registration of an adapter answering catalog.
func testCatalogRegistration(id ComputeProviderId, catalog func(ctx context.Context) (*ComputeProviderCatalog, error)) *computeProviderRegistration {
	return &computeProviderRegistration{
		id: id,
		construct: func(args *ComputeProviderArgs) (ComputeProvider, error) {
			return &catalogComputeProvider{ComputeProviderBase: ComputeProviderBase{ProviderId: id}, catalog: catalog}, nil
		},
	}
}

// engy's catalog of two models at $1.05 a gamma.
func testEngyCatalog() *ComputeProviderCatalog {
	return &ComputeProviderCatalog{
		Provider:     ComputeProviderIdEngy,
		GammaNanoUsd: 1_050_000_000,
		Models: []*ComputeProviderModel{
			{
				ModelId: "deepseek-ai/DeepSeek-V4.1-Flash-1017", Label: sidecar.ComputeLabelNone,
				Efforts:                  []sidecar.InferEffort{sidecar.InferEffortOff, sidecar.InferEffortHigh},
				InputNanoGammaPerMillion: 150_000_000, OutputNanoGammaPerMillion: 600_000_000, CachedInputNanoGammaPerMillion: 15_000_000,
				Capacity: 4, CapacityKnown: true,
			},
			{
				ModelId: "Qwen/Qwen3.6-35B-A3B", Label: sidecar.ComputeLabelNone,
				Efforts:                  []sidecar.InferEffort{sidecar.InferEffortOff},
				InputNanoGammaPerMillion: 90_000_000, OutputNanoGammaPerMillion: 300_000_000,
			},
		},
	}
}

// hippius' catalog of one shape.
func testHippiusCatalog() *ComputeProviderCatalog {
	return &ComputeProviderCatalog{
		Provider:     ComputeProviderIdHippius,
		GammaNanoUsd: 1_000_000_000,
		Shapes: []*ComputeProviderShape{
			{ShapeId: "cpu-2", Label: sidecar.ComputeLabelAp, VcpuCount: 2, MemoryByteCount: 8 * 1024 * 1024 * 1024,
				DiskByteCount: 64 * 1024 * 1024 * 1024, HourNanoGamma: 40_000_000, EgressNanoGammaPerGib: 10_000_000},
		},
	}
}

// Every serving provider's catalog becomes one row a model or shape, at the hour of the read, in one transaction;
// a provider that fails, answers slowly past the bound or answers a catalog that does not check is reported and
// stores nothing, and the others store theirs; a provider that does not serve is never read.
func TestComputeProviderReadPricesStoresOneReadPerModelAndHour(t *testing.T) {
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	saygmCatalogRead := false
	settings := testComputeProviderSettings("main", ComputeDeploymentProduction,
		ComputeProviderIdEngy, ComputeProviderIdSaygm, ComputeProviderIdHippius, ComputeProviderIdLium, ComputeProviderIdCathedral)
	// no read waits: the slow provider's bound has passed when it looks
	settings.CatalogReadTimeout = time.Nanosecond
	statuses := &fakeComputeProviderStatuses{}
	statuses.set(map[ComputeProviderId]ComputeProviderStatus{
		ComputeProviderIdEngy:      ComputeProviderStatusGated,
		ComputeProviderIdSaygm:     ComputeProviderStatusSuspended,
		ComputeProviderIdHippius:   ComputeProviderStatusGated,
		ComputeProviderIdLium:      ComputeProviderStatusGated,
		ComputeProviderIdCathedral: ComputeProviderStatusGated,
	}, nil)
	registry, err := NewComputeProviderRegistry(&ComputeProviderRegistryArgs{
		Settings: settings,
		Clock:    clock,
		testRegistrations: []*computeProviderRegistration{
			testCatalogRegistration(ComputeProviderIdEngy, func(ctx context.Context) (*ComputeProviderCatalog, error) {
				return testEngyCatalog(), nil
			}),
			testCatalogRegistration(ComputeProviderIdSaygm, func(ctx context.Context) (*ComputeProviderCatalog, error) {
				saygmCatalogRead = true
				return &ComputeProviderCatalog{Provider: ComputeProviderIdSaygm}, nil
			}),
			testCatalogRegistration(ComputeProviderIdHippius, func(ctx context.Context) (*ComputeProviderCatalog, error) {
				return testHippiusCatalog(), nil
			}),
			testCatalogRegistration(ComputeProviderIdLium, func(ctx context.Context) (*ComputeProviderCatalog, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			}),
			testCatalogRegistration(ComputeProviderIdCathedral, func(ctx context.Context) (*ComputeProviderCatalog, error) {
				catalog := testHippiusCatalog()
				catalog.Provider = ComputeProviderIdCathedral
				catalog.Shapes[0].Label = sidecar.ComputeLabelNone
				return catalog, nil
			}),
		},
		testStatuses: statuses,
	})
	if err != nil {
		t.Fatal(err)
	}
	db := &recordingComputeDb{}
	store := NewComputeProviderStore(db, settings)
	now := time.Date(2026, 11, 24, 13, 47, 12, 0, time.UTC)
	reads, err := computeProviderReadPrices(ctx, registry, store, now)
	if err != nil {
		t.Fatal(err)
	}
	if saygmCatalogRead {
		t.Fatal("a suspended provider's catalog was read")
	}
	outcomes := map[ComputeProviderId]*computeProviderCatalogRead{}
	for _, read := range reads {
		outcomes[read.Provider] = read
	}
	if len(reads) != 4 || outcomes[ComputeProviderIdEngy].Err != nil || outcomes[ComputeProviderIdHippius].Err != nil ||
		outcomes[ComputeProviderIdLium].Err == nil || outcomes[ComputeProviderIdCathedral].Err == nil {
		for _, read := range reads {
			t.Logf("%s: %v", read.Provider, read.Err)
		}
		t.Fatalf("%d providers read", len(reads))
	}
	if !errors.Is(outcomes[ComputeProviderIdCathedral].Err, errComputeProviderCatalog) {
		t.Fatalf("a shape outside a TEE: %v", outcomes[ComputeProviderIdCathedral].Err)
	}
	statements := db.recorded()
	if len(statements) != 3 {
		t.Fatalf("%d rows written, want engy's two models and hippius' shape", len(statements))
	}
	hour := time.Date(2026, 11, 24, 13, 0, 0, 0, time.UTC)
	want := map[string]bool{"deepseek-ai/DeepSeek-V4.1-Flash-1017": true, "Qwen/Qwen3.6-35B-A3B": true, "cpu-2": true}
	for _, statement := range statements {
		if !strings.Contains(statement.sql, "INSERT INTO compute_provider_price") {
			t.Fatalf("wrote %s", statement.sql)
		}
		itemId := statement.args[2].(string)
		readHour := statement.args[3].(time.Time)
		readTime := statement.args[4].(time.Time)
		if !want[itemId] || !readHour.Equal(hour) || !readTime.Equal(now) {
			t.Errorf("a row for %q at %s read %s", itemId, readHour, readTime)
		}
		delete(want, itemId)
		if itemId == "deepseek-ai/DeepSeek-V4.1-Flash-1017" &&
			(statement.args[5].(int64) != 1_050_000_000 || statement.args[6].(int64) != 150_000_000 || *statement.args[12].(*int64) != 4) {
			t.Errorf("engy's model stored %v", statement.args)
		}
		if itemId == "Qwen/Qwen3.6-35B-A3B" && statement.args[12].(*int64) != nil {
			t.Errorf("a capacity the provider gave none of stored %v", *statement.args[12].(*int64))
		}
		if itemId == "cpu-2" && (statement.args[9].(int64) != 40_000_000 || statement.args[6].(int64) != 0) {
			t.Errorf("hippius' shape stored %v", statement.args)
		}
	}

	// a store that fails stores nothing and says so, the reads still answered
	failing := &recordingComputeDb{err: errors.New("the database is gone")}
	if reads, err := computeProviderReadPrices(ctx, registry, NewComputeProviderStore(failing, settings), now); err == nil || len(reads) != 4 {
		t.Fatalf("a failing store: %d reads, %v", len(reads), err)
	}
	// statuses that do not read read no provider
	statuses.set(nil, errors.New("compute_provider does not read"))
	clock.Advance(settings.StatusMaxAge)
	if reads, err := computeProviderReadPrices(ctx, registry, store, now); err == nil || reads != nil {
		t.Fatalf("unread statuses read %d providers", len(reads))
	}
}

// What a catalog read refuses: another provider's catalog, too many entries, an entry of a kind the provider does not
// serve, an id empty, long or twice, a model under the local or A2 label or with an effort none of §6.3's, a shape
// outside a TEE, a price or count below zero, and prices in a gamma of no value.
func TestComputeProviderCatalogChecks(t *testing.T) {
	settings := DefaultComputeProviderSettings()
	if err := computeProviderCheckCatalog(ComputeProviderIdEngy, testEngyCatalog(), settings); err != nil {
		t.Fatal(err)
	}
	if err := computeProviderCheckCatalog(ComputeProviderIdHippius, testHippiusCatalog(), settings); err != nil {
		t.Fatal(err)
	}
	engy := func(change func(catalog *ComputeProviderCatalog)) *ComputeProviderCatalog {
		catalog := testEngyCatalog()
		change(catalog)
		return catalog
	}
	hippius := func(change func(catalog *ComputeProviderCatalog)) *ComputeProviderCatalog {
		catalog := testHippiusCatalog()
		change(catalog)
		return catalog
	}
	cases := map[string]struct {
		id      ComputeProviderId
		catalog *ComputeProviderCatalog
	}{
		"none":               {id: ComputeProviderIdEngy, catalog: nil},
		"another's":          {id: ComputeProviderIdSaygm, catalog: testEngyCatalog()},
		"shapes for engy":    {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Shapes = testHippiusCatalog().Shapes })},
		"models for hippius": {id: ComputeProviderIdHippius, catalog: hippius(func(c *ComputeProviderCatalog) { c.Models = testEngyCatalog().Models })},
		"a worthless gamma":  {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.GammaNanoUsd = 0 })},
		"an empty id":        {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].ModelId = "" })},
		"a long id": {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) {
			c.Models[0].ModelId = strings.Repeat("m", settings.CatalogIdMaxByteCount+1)
		})},
		"an id twice":      {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[1].ModelId = c.Models[0].ModelId })},
		"a local model":    {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].Label = sidecar.ComputeLabelLocal })},
		"an A2 model":      {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].Label = sidecar.ComputeLabelA2 })},
		"no effort":        {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].Efforts = nil })},
		"a strange effort": {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].Efforts = []sidecar.InferEffort{"turbo"} })},
		"a negative price": {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) { c.Models[0].OutputNanoGammaPerMillion = -1 })},
		"a negative capacity": {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) {
			c.Models[0].Capacity = -1
		})},
		"a shape outside a TEE": {id: ComputeProviderIdHippius, catalog: hippius(func(c *ComputeProviderCatalog) { c.Shapes[0].Label = sidecar.ComputeLabelNone })},
		"a negative hour":       {id: ComputeProviderIdHippius, catalog: hippius(func(c *ComputeProviderCatalog) { c.Shapes[0].HourNanoGamma = -1 })},
		"too many": {id: ComputeProviderIdEngy, catalog: engy(func(c *ComputeProviderCatalog) {
			for i := range settings.CatalogMaxEntryCount {
				c.Models = append(c.Models, &ComputeProviderModel{ModelId: strings.Repeat("n", 1+i%200) + string(rune('a'+i%26)), Label: sidecar.ComputeLabelNone, Efforts: []sidecar.InferEffort{sidecar.InferEffortOff}})
			}
		})},
	}
	for label, c := range cases {
		if err := computeProviderCheckCatalog(c.id, c.catalog, settings); err == nil || !errors.Is(err, errComputeProviderCatalog) {
			t.Errorf("%s: %v", label, err)
		}
	}
}
