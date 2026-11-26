// compute_provider_prices' run (DESIGN-COMPUTE §14.5, §6.3, §6.6, §9.6; INFER-M12-01): hourly, each enabled provider's
// catalog read and stored, the remote catalog rebuilt or pruned and published where it changed, and each direct
// provider's costliest worst case recomputed for the exposure rule. The logic is computeservice's
// ComputeProviderPricesJob, which sidecar/work may not import, an engine being no client package's to import (§4.4): the
// process that runs taskworker builds the job over its providers' settings and credentials, the newest verified compute
// policy and its Postgres, and installs its Run here (InstallComputeProviderPrices). A process that installed none fails
// each run with ErrComputeJobDepsNotInstalled, which waits on server/task's backoff, so nothing is read or published from
// a process that cannot reach the providers.
//
// The install is read at each run, so it is safe for concurrent use.

package work

import (
	"context"
	"fmt"
	"sync/atomic"
)

// One run of compute_provider_prices: computeservice's ComputeProviderPricesJob.Run.
type ComputeProviderPricesRun func(ctx context.Context) error

// What the newest install gave.
var computeProviderPricesRun atomic.Pointer[ComputeProviderPricesRun]

// Installs what compute_provider_prices runs in this process. Answers what removes it, which leaves a later install in
// place.
func InstallComputeProviderPrices(run ComputeProviderPricesRun) func() {
	installed := &run
	computeProviderPricesRun.Store(installed)
	return func() {
		computeProviderPricesRun.CompareAndSwap(installed, nil)
	}
}

func init() {
	RegisterJob(&Job{Name: ComputeJobProviderPrices, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		installed := computeProviderPricesRun.Load()
		if installed == nil || *installed == nil {
			return nil, fmt.Errorf("%w: no provider prices run", ErrComputeJobDepsNotInstalled)
		}
		return nil, (*installed)(ctx)
	}})
}
