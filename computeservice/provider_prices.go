// The hourly price read (DESIGN-COMPUTE §9.6, §4.5, §14.5's compute_provider_prices): each enabled provider's catalog
// read through its adapter and stored as one compute_provider_price row a model or shape and hour, which INFER's
// catalog build (INFER-M12-01, whose job wrapper in sidecar/work calls this) and GAMMA's margin checks read. Prices stay
// in the provider's gamma as read, with the gamma's USD value of that read; the markup and rounding are BAL's (§9.6).
//
// A catalog is unsigned and decides nothing about who reads a prompt (R1-14): it adds prices and capacity alone, and
// the policy pins every host, model id and route (§5.4). So a read is checked only for what its rows hold, and one that
// does not check is refused whole, its provider's last read standing: one provider's failure, a slow answer among them,
// stops no other's (§4.7).
//
// The function holds no state, so it is safe for concurrent use as its registry and store are.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

// One provider's catalog at an hourly read.
type computeProviderCatalogRead struct {
	Provider ComputeProviderId
	// The catalog as read and checked; nil where the read failed.
	Catalog *ComputeProviderCatalog
	// What it stored: one read a model or shape, for the hour.
	PriceReads []*ComputeProviderPriceRead
	// Why the read failed, its provider's last stored read standing; nil where it did not.
	Err error
}

// Reads the catalog of every provider registry serves for new work now, each within the settings'
// CatalogReadTimeout and at once, and stores one price read a model or shape for now's hour in one transaction. Each
// provider's outcome is its own entry, in code order; the error is the statuses' read failing, which reads no
// provider, or the store's write failing, which stores none.
func computeProviderReadPrices(ctx context.Context, registry *ComputeProviderRegistry, store *ComputeProviderStore, now time.Time) ([]*computeProviderCatalogRead, error) {
	adapters, err := registry.EnabledProviders(ctx)
	if err != nil {
		return nil, err
	}
	settings := registry.Settings()
	catalogReads := make([]*computeProviderCatalogRead, len(adapters))
	var waitGroup sync.WaitGroup
	for i, adapter := range adapters {
		catalogReads[i] = &computeProviderCatalogRead{Provider: adapter.Id()}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			catalogRead := catalogReads[i]
			readCtx, cancel := context.WithTimeout(ctx, settings.CatalogReadTimeout)
			defer cancel()
			catalog, err := adapter.Catalog(readCtx)
			if err == nil {
				err = computeProviderCheckCatalog(adapter.Id(), catalog, settings)
			}
			if err != nil {
				catalogRead.Err = err
				return
			}
			catalogRead.Catalog = catalog
			catalogRead.PriceReads = computeProviderPriceReads(catalog, now)
		}()
	}
	waitGroup.Wait()
	priceReads := []*ComputeProviderPriceRead{}
	for _, catalogRead := range catalogReads {
		priceReads = append(priceReads, catalogRead.PriceReads...)
	}
	if err := store.WritePriceReads(ctx, priceReads); err != nil {
		return catalogReads, fmt.Errorf("compute providers: the hour's price reads were not stored: %w", err)
	}
	return catalogReads, nil
}

// A catalog's rows for now's hour: one a model, one a shape.
func computeProviderPriceReads(catalog *ComputeProviderCatalog, now time.Time) []*ComputeProviderPriceRead {
	priceReads := []*ComputeProviderPriceRead{}
	for _, model := range catalog.Models {
		priceReads = append(priceReads, &ComputeProviderPriceRead{
			Provider:                       catalog.Provider,
			Item:                           ComputeProviderPriceItemModel,
			ItemId:                         model.ModelId,
			ReadTime:                       now,
			GammaNanoUsd:                   catalog.GammaNanoUsd,
			InputNanoGammaPerMillion:       model.InputNanoGammaPerMillion,
			OutputNanoGammaPerMillion:      model.OutputNanoGammaPerMillion,
			CachedInputNanoGammaPerMillion: model.CachedInputNanoGammaPerMillion,
			PriceVaries:                    model.PriceVaries,
			Capacity:                       model.Capacity,
			CapacityKnown:                  model.CapacityKnown,
		})
	}
	for _, shape := range catalog.Shapes {
		priceReads = append(priceReads, &ComputeProviderPriceRead{
			Provider:              catalog.Provider,
			Item:                  ComputeProviderPriceItemShape,
			ItemId:                shape.ShapeId,
			ReadTime:              now,
			GammaNanoUsd:          catalog.GammaNanoUsd,
			HourNanoGamma:         shape.HourNanoGamma,
			EgressNanoGammaPerGib: shape.EgressNanoGammaPerGib,
			Capacity:              shape.Capacity,
			CapacityKnown:         shape.CapacityKnown,
		})
	}
	return priceReads
}

// What a catalog read refuses for.
var errComputeProviderCatalog = errors.New("catalog read refused")

// Why catalog cannot be stored as id's read, or nil: it is another provider's; it holds more entries than the settings
// allow, or an entry of the kind id does not serve; an id empty, past the bound or twice; a model's label unknown or
// local, a shape's not a TEE's (an enclave always runs in one, R-PROV-1); an effort none of §6.3's; or a price, count
// or capacity below zero, or a gamma of no value while it prices anything.
func computeProviderCheckCatalog(id ComputeProviderId, catalog *ComputeProviderCatalog, settings *ComputeProviderSettings) error {
	refuse := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s: %s", errComputeProviderCatalog, id, fmt.Sprintf(format, args...))
	}
	kind, _ := ComputeProviderKindOf(id)
	switch {
	case catalog == nil:
		return refuse("no catalog")
	case catalog.Provider != id:
		return refuse("the catalog is another provider's")
	case settings.CatalogMaxEntryCount < len(catalog.Models)+len(catalog.Shapes):
		return refuse("more than %d models and shapes", settings.CatalogMaxEntryCount)
	case kind != ComputeProviderKindInference && 0 < len(catalog.Models):
		return refuse("models from a provider that serves no inference")
	case kind != ComputeProviderKindEnclave && 0 < len(catalog.Shapes):
		return refuse("shapes from a provider that serves no enclaves")
	case 0 < len(catalog.Models)+len(catalog.Shapes) && catalog.GammaNanoUsd <= 0:
		return refuse("prices in a gamma of no value")
	}
	checkId := func(itemId string, seen map[string]bool) error {
		switch {
		case itemId == "":
			return refuse("an empty id")
		case settings.CatalogIdMaxByteCount < len(itemId):
			return refuse("an id longer than %d bytes", settings.CatalogIdMaxByteCount)
		case seen[itemId]:
			return refuse("an id twice")
		}
		seen[itemId] = true
		return nil
	}
	modelIds := map[string]bool{}
	for _, model := range catalog.Models {
		if model == nil {
			return refuse("an empty model")
		}
		if err := checkId(model.ModelId, modelIds); err != nil {
			return err
		}
		switch {
		case !model.Label.Valid() || model.Label == sidecar.ComputeLabelLocal || model.Label == sidecar.ComputeLabelA2:
			// A2 comes only from a custody registry the policy names, on the device (§4.3)
			return refuse("a model offered under no remote label a provider gives")
		case len(model.Efforts) == 0 || slices.ContainsFunc(model.Efforts, func(effort sidecar.InferEffort) bool { return !effort.Valid() }):
			return refuse("a model with an effort none of §6.3's, or none")
		case model.InputNanoGammaPerMillion < 0 || model.OutputNanoGammaPerMillion < 0 || model.CachedInputNanoGammaPerMillion < 0:
			return refuse("a price below zero")
		case model.ContextWindow < 0 || model.MaxOutput < 0 || (model.CapacityKnown && model.Capacity < 0):
			return refuse("a count below zero")
		}
	}
	shapeIds := map[string]bool{}
	for _, shape := range catalog.Shapes {
		if shape == nil {
			return refuse("an empty shape")
		}
		if err := checkId(shape.ShapeId, shapeIds); err != nil {
			return err
		}
		switch {
		case shape.Label != sidecar.ComputeLabelA1 && shape.Label != sidecar.ComputeLabelAp:
			return refuse("a shape not offered in a TEE")
		case shape.HourNanoGamma < 0 || shape.EgressNanoGammaPerGib < 0:
			return refuse("a price below zero")
		case shape.VcpuCount < 0 || shape.MemoryByteCount < 0 || shape.DiskByteCount < 0 || shape.GpuCount < 0 ||
			(shape.CapacityKnown && shape.Capacity < 0):
			return refuse("a count below zero")
		}
	}
	return nil
}
