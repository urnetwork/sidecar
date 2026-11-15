// The quota types every leg decodes (§20.7): SidecarApi reads them in the page Worker too, so they
// name no connect type. They are operator-core's (owner decision 251), aliased here; host_quota.go
// holds what only hosted engines use.

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// A refusal maps to 402 with x402 terms when a purchase lifts the limit, 429 with Retry-After when a
// window resets, else Error{RESOURCE_EXHAUSTED} (§6.5) or stream quota.
type QuotaRefusal = operator.QuotaRefusal

// A network's effective limits after its network_sidecar_limit rows (NetworkSidecarLimits, §20.5):
// Quota.Limits's result and GET /sidecar/limits's body. A key absent from Limits reads 0, so a limit
// this build does not know fails closed.
type QuotaLimits = operator.QuotaLimits
