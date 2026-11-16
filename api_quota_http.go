//go:build sidecar_http

// The quota types the page Worker decodes (§20.7), on the sidecar_http leg: the twin of api_quota.go,
// whose types are operator-core's. This leg links no operator-core (QD-856), so it declares the same
// structs, field for field and with the same JSON names, which TestQuotaTwinEncodesAsOperatorCoresDoes
// holds on both legs.

package sidecar

// A refusal maps to 402 with x402 terms when a purchase lifts the limit, 429 with Retry-After when a
// window resets, else Error{RESOURCE_EXHAUSTED} (§6.5) or stream quota.
type QuotaRefusal struct {
	LimitKey     string `json:"limit_key"`
	Limit        int64  `json:"limit"`
	Used         int64  `json:"used"`
	RetryAfterMs uint32 `json:"retry_after_ms"`
	// A purchase or a higher tier lifts it.
	Upgrade bool `json:"upgrade"`
}

// A network's effective limits after its network_sidecar_limit rows (NetworkSidecarLimits, §20.5):
// GET /sidecar/limits's body.
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
