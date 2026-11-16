//go:build !sidecar_http && !ios_extension

// ServiceHost.Quota (§20.7), implemented by server: limits, rates, edge leases and usage, whose types
// are operator-core's (owner decision 251). api_quota.go aliases the ones every leg decodes.

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// One producer's window of usage, sent every 60 s and flushed on SIGTERM.
type UsageBatch = operator.UsageBatch

// One network's usage on one meter in a batch.
type UsageEvent = operator.UsageEvent

// Quota.OverLimit's answer, keyed by network.
type QuotaOverLimit = operator.QuotaOverLimit

// §20.7's quota.
type Quota = operator.Quota

// One edge lease, which renews itself at 75% used (§20.6).
type QuotaLease = operator.QuotaLease
