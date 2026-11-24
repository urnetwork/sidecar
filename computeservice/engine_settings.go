// The compute engine's tunables (QD-702): every limit, size, interval and bound the engine and its guard read, each a
// field set only by DefaultComputeEngineSettings. Protocol identifiers (route names, refusal codes, header names, the
// feature bits) stay constants in their own files.

package computeservice

import (
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// The engine's tunables.
type ComputeEngineSettings struct {
	// How long a stream may go with nothing written before it writes an SSE comment: 15 s, under the lb's stall
	// timeouts (§14.2's Host row; DESIGN CONVENTIONS §8's 15 s and 60 s). Non-positive writes no comment, which only
	// a test that drives frames itself may want.
	StreamCommentInterval time.Duration
	// How long Drain lets requests in flight, streams and hijacked tunnels included, finish on their own before it ends
	// what is left: 45 s, inside the block's 60 s shutdown (sidecarhost's ShutdownTimeout), so a stream ends under the
	// engine's bound and not at the status server's close. Non-positive ends them at once.
	DrainTimeout time.Duration
	// After the drain's bound has ended every request's context, how long Drain waits for their handlers to return
	// before it gives up on them: 5 s. A handler that ignores its context is the handler's fault, and Close follows.
	DrainEndTimeout time.Duration
	// Retry-After on a 503 whose cause the design gives no retry time for, such as a network whose state is not
	// loaded or an auth state that could not answer: 1 s, as D-BAL-13's lost cache asks devices to wait. Values under
	// a second round up to one.
	UnavailableRetryAfter time.Duration
	// How often a long request rereads rev/ for its token (RecheckRevocation): 60 s, §11.8's stream rule, which the
	// compute routes take as evs's streams do.
	RevocationStreamInterval time.Duration
	// The body a route reads at most, by route name, for the routes the default does not fit. A route the map does not
	// name reads at most RequestBodyMaxByteCount.
	RouteBodyMaxByteCounts map[string]int64
	// The body any other route reads at most: 64 KiB, enough for every other protobuf body §14.3 lists.
	RequestBodyMaxByteCount int64
	// The rev/ reader's settings, which the host builds the RevocationChecker from: each answer cached at most 5 s
	// (§7.8's check row). nil: sidecar.DefaultRevocationSettings.
	Revocation *sidecar.RevocationSettings
	// The projection cache's settings, which the host builds the process's AclGateCache from (§8.9, C-09). nil:
	// sidecar.DefaultAclGateSettings.
	AclGate *sidecar.AclGateSettings
}

// The defaults.
func DefaultComputeEngineSettings() *ComputeEngineSettings {
	return &ComputeEngineSettings{
		StreamCommentInterval:    15 * time.Second,
		DrainTimeout:             45 * time.Second,
		DrainEndTimeout:          5 * time.Second,
		UnavailableRetryAfter:    1 * time.Second,
		RevocationStreamInterval: 60 * time.Second,
		RouteBodyMaxByteCounts: map[string]int64{
			// ComputeInferHeader and the sealed envelope: a long context with its images, compressed (§6.6)
			ComputeRouteInfer: 32 * 1024 * 1024,
			// a TEE's evidence, which the VM posts once per nonce (§11.7)
			ComputeRouteEnclaveEvidencePost: 1 * 1024 * 1024,
			// the sealed provisioning bundle, relayed once and never stored (§11.7)
			ComputeRouteEnclaveProvision: 4 * 1024 * 1024,
		},
		RequestBodyMaxByteCount: 64 * 1024,
		Revocation:              sidecar.DefaultRevocationSettings(),
		AclGate:                 sidecar.DefaultAclGateSettings(),
	}
}

// The body route reads at most.
func (self *ComputeEngineSettings) bodyMaxByteCount(route string) int64 {
	if maxByteCount, ok := self.RouteBodyMaxByteCounts[route]; ok {
		return maxByteCount
	}
	return self.RequestBodyMaxByteCount
}

// An error for settings no engine could serve under: a body bound that is not positive, or one naming no route of
// the design.
func (self *ComputeEngineSettings) Validate() error {
	if self.RequestBodyMaxByteCount <= 0 {
		return fmt.Errorf("compute engine: the request body bound %d is not positive", self.RequestBodyMaxByteCount)
	}
	designNames := map[string]bool{}
	for _, route := range computeRouteDesign() {
		designNames[route.Name] = true
	}
	for route, maxByteCount := range self.RouteBodyMaxByteCounts {
		if !designNames[route] {
			return fmt.Errorf("compute engine: a body bound for %q, which is no compute route", route)
		}
		if maxByteCount <= 0 {
			return fmt.Errorf("compute engine: the body bound of %s is not positive", route)
		}
	}
	return nil
}
