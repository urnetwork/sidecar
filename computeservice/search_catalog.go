// The catalog's search section (DESIGN-COMPUTE §6.3's search ids, §21.8, D-SRCH-6; SRCH-M13-07): web search's part of
// each catalog version, built by INFER's section registry (computeCatalogRegisterSection) beside the models, under the
// name the device's reader takes (websearch_policy.go). One entry an engine and mode, search/parallel/<mode> for each of
// §21.6's four modes, each at the gateway's price times the compute markup, rounded up to the search step (§9.6):
// $0.012 at the gateway's $0.01, the same in every mode. The device holds an offer to its mode's price, and the broker's
// admission holds the authorization's amount to the version's lowest search price (search_admit.go), so the version a
// request names bounds what it may pay.
//
// The gateway's price is ComputeSearchSettings.GatewayAmount at its default: INFER's section builder takes the hour's
// catalogs and the ledger's price rule, and no search settings, so a price change within the policy's ceiling is a
// release until the section's arguments carry them (reported). Searches stay off until G-SRCH-parallel whatever the
// catalog lists: the signed policy carries no search line before it, and the device and the broker refuse without one.

package computeservice

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

// The section's name in a catalog version, the device reader's: an identifier.
const ComputeSearchCatalogSectionName = "search"

// The section joins every version's build.
func init() {
	computeCatalogRegisterSection(ComputeSearchCatalogSectionName, func(ctx context.Context, args *ComputeCatalogSectionArgs) ([]byte, error) {
		return computeSearchCatalogSection(args.Ledger, DefaultComputeSearchSettings())
	})
}

// A search's retail price for amount, the asset's units: amount at the asset's unit times the markup, rounded up to the
// search step (§21.8).
func computeSearchRetailNanoUsd(ledger *model.ComputeLedgerSettings, settings *ComputeSearchSettings, amount uint64) (int64, error) {
	unit := settings.webSearch().AssetUnitNanoUsd
	if amount == 0 || unit <= 0 || uint64(1<<62)/uint64(unit) < amount {
		return 0, fmt.Errorf("compute search: an amount of %d units does not price", amount)
	}
	return model.ComputeRetailPrice(ledger, model.ComputePriceClassSearch, int64(amount)*unit)
}

// The section's bytes: each mode at the gateway's price (see the file header).
func computeSearchCatalogSection(ledger *model.ComputeLedgerSettings, settings *ComputeSearchSettings) ([]byte, error) {
	if ledger == nil {
		ledger = model.DefaultComputeLedgerSettings()
	}
	price, err := computeSearchRetailNanoUsd(ledger, settings, settings.GatewayAmount)
	if err != nil {
		return nil, err
	}
	section := &protocol.WebSearchCatalogSection{}
	for _, mode := range sidecar.WebSearchModes {
		section.Entries = append(section.Entries, &protocol.WebSearchCatalogEntry{
			Engine:           sidecar.WebSearchEngineParallel,
			Mode:             mode,
			NanoUsdPerSearch: price,
		})
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(section)
}

// A version without a search section, or one that lists no priced entry.
var errComputeSearchCatalogNone = errors.New("compute search: the catalog version lists no search")

// The lowest search price the version's section lists, which an admission's amount times the markup may not pass.
func computeSearchCatalogPrice(answer *protocol.InferCatalogAnswer) (int64, error) {
	for _, section := range answer.GetSections() {
		if section.GetName() != ComputeSearchCatalogSectionName {
			continue
		}
		parsed := &protocol.WebSearchCatalogSection{}
		if err := proto.Unmarshal(section.GetBody(), parsed); err != nil {
			return 0, errComputeSearchCatalogNone
		}
		lowest := int64(0)
		for _, entry := range parsed.GetEntries() {
			if entry.GetEngine() != sidecar.WebSearchEngineParallel || entry.GetNanoUsdPerSearch() <= 0 {
				continue
			}
			if lowest == 0 || entry.GetNanoUsdPerSearch() < lowest {
				lowest = entry.GetNanoUsdPerSearch()
			}
		}
		if lowest == 0 {
			return 0, errComputeSearchCatalogNone
		}
		return lowest, nil
	}
	return 0, errComputeSearchCatalogNone
}
