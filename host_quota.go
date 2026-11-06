//go:build !sidecar_http

// ServiceHost.Quota (§20.7), implemented by server: limits, rates, edge leases and usage. api_quota.go
// holds the types every leg decodes.

package sidecar

import (
	"context"
	"time"

	"github.com/urnetwork/connect"
)

// One producer's window of usage, sent every 60 s and flushed on SIGTERM. A producer retries an
// unanswered batch for at most 10 min, then drops it, counted and alerting: under-billing, never
// double-billing (§20.6).
type UsageBatch struct {
	// The retry identity: the first 16 B of SHA-256(producerInstanceId || windowSeq), where
	// producerInstanceId is 16 random bytes drawn at process start. A drop job's batch takes the first
	// 16 B of SHA-256(scanId || cursor range) instead (§20.6).
	BatchId connect.Id
	// "evs", "tlsedge", "mxedge", "smtpedge"; "taskworker" for evacuation's staged frees and the drop
	// job's deletes and holds.
	Producer string
	// 60 s windows.
	WindowStart time.Time
	Events      []*UsageEvent
}

// One network's usage on one meter in a batch. It names no repo, host or peer: §2.8's evs-9 lists
// transfer bytes per caller network and stored-byte deltas per repo network, and no more (I-18).
type UsageEvent struct {
	// Transfer: the caller's network. A stored-byte delta: the repo's network.
	NetworkId connect.Id
	// The meter it counts on, such as "tls" (§13.6).
	Meter string
	// Bytes to debit from the network's transfer balance.
	TransferByteCount int64
	// Moves the nightly stored count between passes (§20.7); negative when content is freed.
	StoredByteDelta int64
}

// Quota.OverLimit's answer, which evs and sockets re-read every 5 s, so writes overshoot by about a
// minute (§20.6). Each map holds the refusal to answer, keyed by network.
type QuotaOverLimit struct {
	// Over their storage limit: evs refuses their payload-adding uploads and pushes (§11.13).
	StorageNetworkIdRefusals map[connect.Id]*QuotaRefusal
	// Spent, with no balance left: new streams get quota and a Find names no ticket (§9.6), and evs
	// refuses as above (§20.6).
	SpentNetworkIdRefusals map[connect.Id]*QuotaRefusal
}

// §20.7. Producers cache limits 5 s. A zero network, debit or batch id is the caller's bug and an
// error, never a lookup: it names no one's limits or balance, and two calls sharing a zero id would
// read as one retried, the second counting nothing.
type Quota interface {
	// The network's effective limits.
	Limits(ctx context.Context, networkId connect.Id) (*QuotaLimits, error)
	// Counts keyAmounts against the network's rates in one all-or-none script on {sq_<network_id>},
	// once per debitId, so a retry counts nothing twice. A non-nil refusal counted nothing. Fails
	// open for one window if Redis is lost (§20.7).
	CountRate(ctx context.Context, networkId connect.Id, keyAmounts map[string]int64, debitId connect.Id) (*QuotaRefusal, error)
	// A lease for one edge process on one network and meter, drawing on escrow's per-balance
	// reservations, 64 MiB at a time and 16 MiB on Community (§20.6). A non-nil refusal holds no
	// lease and marks the network spent.
	Lease(ctx context.Context, networkId connect.Id, meter string) (QuotaLease, *QuotaRefusal, error)
	// Every 60 s per producer; idempotent per BatchId (§20.6).
	ReportUsage(ctx context.Context, batch *UsageBatch) error
	// evs and sockets, every 5 s: networks over their storage limit, or spent.
	OverLimit(ctx context.Context) (*QuotaOverLimit, error)
}

// One lease, safe for concurrent use. It renews itself at 75% used (§20.6).
type QuotaLease interface {
	// Atomic, with no I/O, so it runs inline on a stream. False: the lease has run out, and the
	// network is spent until a new Lease says otherwise.
	Spend(byteCount int64) bool
	// Settles and releases, returning the unused rest in reverse draw order.
	Close()
}
