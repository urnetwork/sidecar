// The broker's tunables (QD-702): every limit, interval and bound INFER's broker routes and jobs read, each a field set
// only by DefaultComputeBrokerSettings, which ComputeEngineSettings.Broker carries. The catalog's are INFER-M12-01's;
// the direct path's authorize, settle and dispute bounds join from their own tasks. Identifiers (route names, refusal
// codes, section names) stay constants in their files.

package computeservice

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/model"
)

// The broker's tunables.
type ComputeBrokerSettings struct {
	// §6.3's version rule. How long a published catalog stands before compute_provider_prices rebuilds it from the
	// newest prices, adding the models providers added and repricing every one: 24 hours. Between rebuilds an hourly
	// read only takes out, at once, a model whose cost passed its price or whose provider stopped offering it (§4.5).
	// Non-positive rebuilds at every read.
	CatalogRebuildInterval time.Duration
	// How long the version before the current one is still taken after a newer one is published: 24 hours (§6.3).
	// Past it a request naming it is refused catalog_stale, as one naming any older version is at once. Non-positive
	// takes the current version alone.
	CatalogPreviousGrace time.Duration
	// How long an engine answers from the newest versions it read before reading them again: 30 s, so a version the
	// hourly job publishes reaches every broker instance within it while a burst of devices reads Postgres once. A
	// request naming a version newer than the newest held reads again at once. Non-positive reads at every request.
	CatalogCacheMaxAge time.Duration
	// The largest version a build publishes, in bytes of its deterministic protobuf: 4 MiB, room for thousands of
	// models where the launch providers list under a hundred. A build past it publishes nothing, and the version that
	// stands keeps standing. A format limit the device's InferSettings.RemoteCatalogMaxByteCount reads at the same
	// default.
	CatalogAnswerMaxByteCount int
	// The most models one version lists: 4096, the bound InferSettings.ProviderModelIdMaxCount puts on one provider's
	// ids. A build past it publishes nothing.
	CatalogModelMaxCount int
	// The ledger's price rule (§9.6): the markup and the steps a retail price rounds up to, BAL's, so the catalog prices
	// at the markup the ledger charges. nil: model.DefaultComputeLedgerSettings.
	Ledger *model.ComputeLedgerSettings
}

// The defaults, the only place one is set.
func DefaultComputeBrokerSettings() *ComputeBrokerSettings {
	return &ComputeBrokerSettings{
		CatalogRebuildInterval:    24 * time.Hour,
		CatalogPreviousGrace:      24 * time.Hour,
		CatalogCacheMaxAge:        30 * time.Second,
		CatalogAnswerMaxByteCount: 4 * 1024 * 1024,
		CatalogModelMaxCount:      4096,
		Ledger:                    model.DefaultComputeLedgerSettings(),
	}
}

// The ledger's price rule, the defaults where none is set.
func (self *ComputeBrokerSettings) ledger() *model.ComputeLedgerSettings {
	if self.Ledger == nil {
		return model.DefaultComputeLedgerSettings()
	}
	return self.Ledger
}

// An error for settings no catalog could be published under.
func (self *ComputeBrokerSettings) Validate() error {
	switch {
	case self.CatalogAnswerMaxByteCount <= 0:
		return fmt.Errorf("compute broker: the catalog bound %d is not positive", self.CatalogAnswerMaxByteCount)
	case self.CatalogModelMaxCount <= 0:
		return fmt.Errorf("compute broker: the catalog's model bound %d is not positive", self.CatalogModelMaxCount)
	}
	ledger := self.ledger()
	if ledger.MarkupNumerator <= 0 || ledger.MarkupDenominator <= 0 || ledger.TokenPriceStepNanoUsd <= 0 {
		return fmt.Errorf("compute broker: the markup and the token price step are positive")
	}
	return nil
}
