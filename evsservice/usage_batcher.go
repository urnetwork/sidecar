// evs's usage producer (§20.6, §11.13's transfer row; EVSB-M2-15): one per evs process over the root's
// QuotaUsageBatcher under producer evs, which EVS1-M2-12's step 8 and EVSB-M2-09's uploads feed with stored bytes
// and the router's meter with transfer (transfer_meter.go). Stored-byte deltas go to the repo's network and
// transfer to the caller's, on meter evs. Every 60 s window goes out as
// batches whose id is the first 16 B of SHA-256(producerInstanceId || windowSeq), retried under that id for at
// most 10 min and then dropped, counted and alerted, so api applies each once: under-billing, never
// double-billing (FI-13 (a)). Drain sends the open window at once, as SIGTERM asks. The index rows land with
// M10's tasks. Safe for concurrent use.

package evsservice

import (
	"context"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// See the file header.
type UsageBatcher struct {
	batcher *sidecar.QuotaUsageBatcher
}

// The process's producer, started. host.Quota receives the batches and host.Clock times the windows. settings
// may be nil for §20.6's. Close ends it.
func NewUsageBatcher(ctx context.Context, host *sidecar.ServiceHost, settings *sidecar.QuotaUsageBatcherSettings) (*UsageBatcher, error) {
	batcher, err := sidecar.NewQuotaUsageBatcher(ctx, host, sidecar.QuotaProducerEvs, settings)
	if err != nil {
		return nil, err
	}
	return &UsageBatcher{batcher: batcher}, nil
}

// byteDelta of stored bytes for a repo of repoNetworkId: an upload's size, a commit's payload, or a freed
// object's as a negative.
func (self *UsageBatcher) AddStored(repoNetworkId connect.Id, byteDelta int64) error {
	return self.batcher.AddStoredDelta(repoNetworkId, byteDelta)
}

// byteCount of transfer the caller's network moved through evs.
func (self *UsageBatcher) AddTransfer(callerNetworkId connect.Id, byteCount int64) error {
	return self.batcher.AddTransfer(callerNetworkId, sidecar.QuotaMeterEvs, byteCount)
}

// Sends the open window and waits for every batch to be answered or dropped, or ctx to end.
func (self *UsageBatcher) Drain(ctx context.Context) error {
	return self.batcher.Drain(ctx)
}

// Ends it. A window not drained is lost, at most a minute of this process's bytes.
func (self *UsageBatcher) Close() {
	self.batcher.Close()
}
