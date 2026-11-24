//go:build !ios_extension && !sidecar_http

// The router's checks (DESIGN-COMPUTE §6.4), which INFER-M11-03 builds. Until they land, every remote call is refused,
// so no remote model is reached before the policy, the floor, the providers, allow, the budgets, a none model's
// disclosure and a run's limited_use mark are checked; a local call, which sends nothing anywhere (CO-9), runs.

package sidecar

import (
	"context"
)

// What the router checks with until INFER-M11-03's checks land: remote refused, local let through.
type inferRemoteRefused struct{}

// The checks for sidecar's router.
func newInferSidecarChecker(sidecar *Sidecar, settings *InferSettings) inferChecker {
	return &inferRemoteRefused{}
}

// The reason every remote model is refused.
const inferRemoteUncheckedReason = "remote models are refused until the router's checks of them are built"

// See inferChecker.
func (self *inferRemoteRefused) check(ctx context.Context, call *InferCall) error {
	if call.Entry.Kind == InferCatalogKindLocal {
		return nil
	}
	return &InferError{Code: InferErrorModelRefused, Model: call.Name, Message: inferRemoteUncheckedReason}
}

// See inferChecker.
func (self *inferRemoteRefused) limit(ctx context.Context, catalog *InferCatalog) *InferCatalog {
	return catalog.Refuse(func(entry *InferCatalogEntry) string {
		if entry.remote() {
			return inferRemoteUncheckedReason
		}
		return ""
	}, inferRemoteUncheckedReason)
}
