// The providers' settings (DESIGN-COMPUTE §4.6, §4.7, QD-702): which adapters this deployment enables in which env,
// each provider's payment setup as read at its gate (D-PROV-4), and every bound the registry, the store and the
// hourly price read hold, each a field set only by DefaultComputeProviderSettings. The engine carries them as
// ComputeEngineSettings.Providers, so an engine whose settings would run the reference provider in production refuses
// to start (D-ENC-2, CO-21). Identifiers stay constants: the slugs, codes and gate names (provider.go) and the kinds of
// deployment below.
//
// A settings value is read, never changed, once a registry or engine holds it: a caller changes its own copy first.

package computeservice

import (
	"fmt"
	"slices"
	"time"
)

// What kind of deployment an env is, which decides where the reference provider may run (D-ENC-2).
type ComputeDeploymentKind string

// The design's words for them (§11.3, §19.2). Identifiers.
const (
	ComputeDeploymentDevelopment ComputeDeploymentKind = "development"
	ComputeDeploymentCi          ComputeDeploymentKind = "ci"
	ComputeDeploymentStaging     ComputeDeploymentKind = "staging"
	ComputeDeploymentProduction  ComputeDeploymentKind = "production"
)

// Every kind, and the kinds the reference provider may run in: development, CI and staging, never production, since it
// meets no gamma rule and serves no user (§11.3, CO-21).
var (
	computeDeploymentKinds          = []ComputeDeploymentKind{ComputeDeploymentDevelopment, ComputeDeploymentCi, ComputeDeploymentStaging, ComputeDeploymentProduction}
	computeReferenceDeploymentKinds = []ComputeDeploymentKind{ComputeDeploymentDevelopment, ComputeDeploymentCi, ComputeDeploymentStaging}
)

// The providers' tunables and switches.
type ComputeProviderSettings struct {
	// The env this engine or job serves, as WARP_ENV names it, which its host sets. Empty names no env, and so reads
	// as production and enables no adapter.
	Environment string
	// Each env's kind, by its WARP_ENV name: local is development, and the private test stack's CI runs as it; canary
	// is staging. An env the map does not name is production, so a new or misspelt env enables nothing production may
	// not run.
	EnvironmentKinds map[string]ComputeDeploymentKind
	// The envs each provider's adapter is enabled in, by slug. A provider the map does not name, or names with no env,
	// is enabled nowhere: every Bittensor provider by default, until its gate passes and a release enables it (§4.7,
	// compute-plan-adapters-before-commitment). The reference provider may name only envs of the development, CI and
	// staging kinds; by default it is enabled in local alone. Enabled is not serving: an adapter serves only while its
	// compute_provider row reads gated too.
	ProviderEnvironments map[ComputeProviderId][]string
	// Each provider's payment setup, by slug, as read at its gate (D-PROV-4) from the triples compute_gamma.yml lists
	// (§10.5). None by default, so an adapter reports no payment until a deployment sets one.
	Payments map[ComputeProviderId]*ComputeProviderPayment
	// How long the registry serves the statuses it read from compute_provider before it reads them again: 30 s, so a
	// suspension or a failed gate reaches every broker and job within half a minute. A read that fails past it refuses
	// every provider, never enables one (§4.7). Non-positive reads them for every question.
	StatusMaxAge time.Duration
	// How long one adapter's catalog read may take at the hourly read: 60 s. A provider slower than it is skipped for
	// the hour, its last read standing, and the others are read regardless (§4.7: one failing does not stop the rest).
	// Non-positive reads nothing.
	CatalogReadTimeout time.Duration
	// The most models and shapes one catalog read may hold: 1024, some fifteen times the largest provider catalog of
	// 2026-11-23 (67 models), so a hostile answer bounds the work and the rows it writes. A larger read is refused
	// whole.
	CatalogMaxEntryCount int
	// The longest model or shape id a catalog read may hold, in bytes: 256, as InferSettings bounds a provider's model
	// id on the device. A longer id refuses the read whole, never cut.
	CatalogIdMaxByteCount int
	// G-PROV-any's interval: 90 days (§4.7). `sidecarctl compute provider ls` shows a re-check due past it; a missed
	// re-check takes no provider out by itself, only a failed one does.
	GateRecheckInterval time.Duration
	// The most entries a provider's history keeps, newest last: 256, more than sixty years of 90-day re-checks. Older
	// ones are dropped at the next write.
	HistoryMaxCount int
	// The longest operator name, evidence reference, reason or note one history entry holds, in bytes: 1024. A longer
	// one is refused, never cut.
	HistoryTextMaxByteCount int
	// The largest compute-providers.yml the registry reads, in bytes: 1 MiB, room for many providers' keys. A larger
	// file hands no adapter its credentials.
	CredentialsFileMaxByteCount int
}

// The defaults, the only place one is set.
func DefaultComputeProviderSettings() *ComputeProviderSettings {
	return &ComputeProviderSettings{
		Environment: "",
		EnvironmentKinds: map[string]ComputeDeploymentKind{
			"local":  ComputeDeploymentDevelopment,
			"canary": ComputeDeploymentStaging,
		},
		ProviderEnvironments: map[ComputeProviderId][]string{
			ComputeProviderIdReference: {"local"},
		},
		Payments:                    map[ComputeProviderId]*ComputeProviderPayment{},
		StatusMaxAge:                30 * time.Second,
		CatalogReadTimeout:          60 * time.Second,
		CatalogMaxEntryCount:        1024,
		CatalogIdMaxByteCount:       256,
		GateRecheckInterval:         90 * 24 * time.Hour,
		HistoryMaxCount:             256,
		HistoryTextMaxByteCount:     1024,
		CredentialsFileMaxByteCount: 1024 * 1024,
	}
}

// The kind of env: the map's, else production.
func (self *ComputeProviderSettings) EnvironmentKind(env string) ComputeDeploymentKind {
	if kind, ok := self.EnvironmentKinds[env]; ok && env != "" {
		return kind
	}
	return ComputeDeploymentProduction
}

// Whether this deployment enables id's adapter in its env: the env named, the provider's envs holding it, and, for the
// reference provider, the env a development, CI or staging one.
func (self *ComputeProviderSettings) Enabled(id ComputeProviderId) bool {
	if self.Environment == "" || !slices.Contains(self.ProviderEnvironments[id], self.Environment) {
		return false
	}
	if id == ComputeProviderIdReference && !slices.Contains(computeReferenceDeploymentKinds, self.EnvironmentKind(self.Environment)) {
		return false
	}
	kind, known := ComputeProviderKindOf(id)
	return known && kind != ComputeProviderKindSearch
}

// id's payment setup, a copy, or none.
func (self *ComputeProviderSettings) Payment(id ComputeProviderId) ComputeProviderPayment {
	if payment := self.Payments[id]; payment != nil {
		return *payment
	}
	return ComputeProviderPayment{Method: ComputeProviderPaymentNone}
}

// An error for settings no registry may run under: an unknown kind or slug, an adapter enabled for web search, which
// has none, the reference provider enabled in an env that is not development, CI or staging, a payment of no known
// method, or a bound that is not positive.
func (self *ComputeProviderSettings) Validate() error {
	for env, kind := range self.EnvironmentKinds {
		if env == "" || !slices.Contains(computeDeploymentKinds, kind) {
			return fmt.Errorf("compute providers: the env %q has the kind %q, which is none of development, ci, staging and production", env, kind)
		}
	}
	for id, envs := range self.ProviderEnvironments {
		kind, known := ComputeProviderKindOf(id)
		if !known {
			return fmt.Errorf("compute providers: %q is no provider this build knows", id)
		}
		if kind == ComputeProviderKindSearch && 0 < len(envs) {
			return fmt.Errorf("compute providers: %s is reached by no adapter, so none is enabled", id)
		}
		if id != ComputeProviderIdReference {
			continue
		}
		for _, env := range envs {
			if !slices.Contains(computeReferenceDeploymentKinds, self.EnvironmentKind(env)) {
				return fmt.Errorf("compute providers: the reference provider is enabled in %q, a production env; it serves development, CI and staging alone (D-ENC-2, CO-21)", env)
			}
		}
	}
	for id, payment := range self.Payments {
		if _, known := ComputeProviderCodeOf(id); !known {
			return fmt.Errorf("compute providers: a payment for %q, which is no provider this build knows", id)
		}
		if payment == nil || !slices.Contains([]ComputeProviderPaymentMethod{ComputeProviderPaymentNone, ComputeProviderPaymentGamma, ComputeProviderPaymentApiKey}, payment.Method) {
			return fmt.Errorf("compute providers: %s's payment has no known method", id)
		}
	}
	if self.CatalogReadTimeout <= 0 || self.GateRecheckInterval <= 0 {
		return fmt.Errorf("compute providers: the catalog read's timeout and G-PROV-any's interval must be positive")
	}
	if self.CatalogMaxEntryCount <= 0 || self.CatalogIdMaxByteCount <= 0 || self.HistoryMaxCount <= 0 ||
		self.HistoryTextMaxByteCount <= 0 || self.CredentialsFileMaxByteCount <= 0 {
		return fmt.Errorf("compute providers: every count and size bound must be positive")
	}
	return nil
}
