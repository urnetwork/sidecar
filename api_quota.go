// The quota types every leg decodes (§20.7): SidecarApi reads them in the page Worker too, so they
// name no connect type. host_quota.go holds what only hosted engines use.

package sidecar

// A refusal maps to 402 with x402 terms when a purchase lifts the limit, 429 with Retry-After when a
// window resets (server/controller/x402_controller.go:849; server/router/handler_utils.go:604-609),
// else Error{RESOURCE_EXHAUSTED} (§6.5) or stream quota.
type QuotaRefusal struct {
	LimitKey     string `json:"limit_key"`
	Limit        int64  `json:"limit"`
	Used         int64  `json:"used"`
	RetryAfterMs uint32 `json:"retry_after_ms"`
	// A purchase or a higher tier lifts it.
	Upgrade bool `json:"upgrade"`
}

// A network's effective limits after its network_sidecar_limit rows (NetworkSidecarLimits, §20.5):
// Quota.Limits's result and GET /sidecar/limits's body. Producers cache it 5 s (§20.7).
type QuotaLimits struct {
	// "free" (Community), "pro" or "team" (§20.5).
	Tier string `json:"tier"`
	// By §20.4's keys, the same limit_key QuotaRefusal and network_sidecar_limit carry: its sidecar:
	// block's and its sidecar_abuse: block's, the directory_* keys among them, which §16.11's daemons
	// and readers apply (D-QUOTA-11). Bytes count as bytes, a true is 1 and a false 0, and -1 means
	// none, as `none` does in §20.4. A key absent here reads 0, which §20.5 defines as not included,
	// so a limit this build does not know fails closed.
	Limits map[string]int64 `json:"limits"`
}
