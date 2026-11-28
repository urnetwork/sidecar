// compute_search_tickets' and compute_search_purge's runs (DESIGN-COMPUTE §14.5, §21.5; SRCH-M13-08): every minute,
// the holds of the search admissions no report reached an hour past their window released; every 5 minutes, each web
// search's rows deleted once their minute is 71 h 55 min old, and a row past 72 hours paged. The logic is
// computeservice's ComputeSearchJobs (Tickets and Purge), which sidecar/work may not import, an engine being no client
// package's to import (§4.4): the process that runs taskworker builds them over its Env and installs their runs here
// (InstallComputeSearchJobs), as compute_provider_prices' is. A process that installed none fails each run with
// ErrComputeJobDepsNotInstalled, which waits on server/task's backoff, so nothing is released or deleted from a
// process that cannot reach the ledger.
//
// The install is read at each run, so it is safe for concurrent use.

package work

import (
	"context"
	"fmt"
	"sync/atomic"
)

// The search jobs' runs, each computeservice's.
type ComputeSearchJobRuns struct {
	// One compute_search_tickets run: ComputeSearchJobs.Tickets.
	Tickets func(ctx context.Context) error
	// One compute_search_purge run: ComputeSearchJobs.Purge.
	Purge func(ctx context.Context) error
}

// What the newest install gave.
var computeSearchJobRuns atomic.Pointer[ComputeSearchJobRuns]

// Installs the search jobs' runs in this process. Answers what removes them, which leaves a later install in place.
func InstallComputeSearchJobs(runs *ComputeSearchJobRuns) func() {
	installed := &ComputeSearchJobRuns{}
	if runs != nil {
		copied := *runs
		installed = &copied
	}
	computeSearchJobRuns.Store(installed)
	return func() {
		computeSearchJobRuns.CompareAndSwap(installed, nil)
	}
}

func init() {
	RegisterJob(&Job{Name: ComputeJobSearchTickets, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		runs := computeSearchJobRuns.Load()
		if runs == nil || runs.Tickets == nil {
			return nil, fmt.Errorf("%w: no search tickets run", ErrComputeJobDepsNotInstalled)
		}
		return nil, runs.Tickets(ctx)
	}})
	RegisterJob(&Job{Name: ComputeJobSearchPurge, Run: func(ctx context.Context, args []byte) ([]byte, error) {
		runs := computeSearchJobRuns.Load()
		if runs == nil || runs.Purge == nil {
			return nil, fmt.Errorf("%w: no search purge run", ErrComputeJobDepsNotInstalled)
		}
		return nil, runs.Purge(ctx)
	}})
}
