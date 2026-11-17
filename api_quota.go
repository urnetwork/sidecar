//go:build !sidecar_http

// The quota types every leg decodes (§20.7). They are operator-core's (owner decision 251), aliased
// here on every leg but sidecar_http: SidecarApi reads them in the page Worker too, which links no
// operator-core (QD-856), so api_quota_http.go declares the same structs there, and
// TestQuotaTwinEncodesAsOperatorCoresDoes holds their JSON equal on both legs. They name no connect
// type. host_quota.go holds what only hosted engines use.

package sidecar

import (
	operator "github.com/urnetwork/operator-core"
)

// A refusal maps to 402 with x402 terms when a purchase lifts the limit, 429 with Retry-After when a
// window resets, else Error{RESOURCE_EXHAUSTED} (§6.5) or stream quota.
type QuotaRefusal = operator.QuotaRefusal

// A network's effective limits after its network_sidecar_limit rows (NetworkSidecarLimits, §20.5):
// Quota.Limits's result and GET /sidecar/limits's body. A key absent from Limits reads 0, so a limit
// this build does not know fails closed. Enforced is enforce_sidecar_limits's state, which a local
// pre-check follows through quotaLocalLimit (api_limits.go).
type QuotaLimits = operator.QuotaLimits
