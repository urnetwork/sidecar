// ComputeRefusal: every answer the broker gives but a route's own success. A refusal is its status and a JSON body
// naming its code, {"code":"…"}, with a reason from the code's own closed set where it has one and retry_after_ms
// where the design gives a retry time, which Retry-After repeats. The code decides the status from one fixed table,
// so a device's compute client reads one shape whichever route refused it; a code the table does not have is a
// handler's fault, which alarms and answers 503 unavailable in its place, refusing nothing.
//
// The codes are evs's not_found, unauthenticated, scope and unavailable; §16.6's upgrade_required; this plan's
// not_built, idempotency_key_required and invalid, which the design does not name; and the areas' own: capacity, held,
// insufficient_quota, tee_unverified, disclosure_required, catalog_stale, rate_limited and suspended, §17.2's
// region_refused (451, CARCH-M12-01, which the design names no code for), and kind 21's approval_refused and spent
// (§16.6's gate: refused writing nothing, and 409 SPENT; BAL-M12-16). The route bodies
// are protobuf (QD-1246); a refusal is JSON, so a client reads it before it knows which message a route answers with.

package computeservice

import (
	"encoding/json"
	"net/http"
	"time"
)

// A refusal's code, as its body spells it.
type ComputeRefusalCode string

const (
	// No route takes the method and path.
	ComputeRefusalNotFound ComputeRefusalCode = "not_found"
	// No token, or one that does not authenticate for the compute audience, or one a rev/ object voids: the device
	// mints a new token and asks again (§7.8).
	ComputeRefusalUnauthenticated ComputeRefusalCode = "unauthenticated"
	// A token that is no admitted sidecar's of its network.
	ComputeRefusalScope ComputeRefusalCode = "scope"
	// The broker cannot tell or cannot serve now: a state not loaded, a closed gate, a group this binary does not
	// link, a seam not installed, a store that did not answer. Retryable.
	ComputeRefusalUnavailable ComputeRefusalCode = "unavailable"
	// The network's newest base turns on an authorization feature this broker's release does not implement (§16.6's
	// hold): the network waits for the broker's update.
	ComputeRefusalUpgradeRequired ComputeRefusalCode = "upgrade_required"
	// A design route whose area has not landed its handler.
	ComputeRefusalNotBuilt ComputeRefusalCode = "not_built"
	// A route that takes Idempotency-Key was asked without one.
	ComputeRefusalIdempotencyKeyRequired ComputeRefusalCode = "idempotency_key_required"
	// A body over its route's bound, or one its handler cannot read.
	ComputeRefusalInvalid ComputeRefusalCode = "invalid"
	// No passing instance or provider account can take the call now (§6.6, §10.4).
	ComputeRefusalCapacity ComputeRefusalCode = "capacity"
	// The balance would pay but open holds stand in the way (§9.7), or a lost projection is being rebuilt (D-BAL-13).
	ComputeRefusalHeld ComputeRefusalCode = "held"
	// A hold refused for the balance or a budget (§6.6, §9.9, §16.4), its reason naming which.
	ComputeRefusalInsufficientQuota ComputeRefusalCode = "insufficient_quota"
	// No instance's evidence verified (§5, §6.6).
	ComputeRefusalTeeUnverified ComputeRefusalCode = "tee_unverified"
	// A disclosure the caller has not acknowledged (§2.8).
	ComputeRefusalDisclosureRequired ComputeRefusalCode = "disclosure_required"
	// A catalog version older than the newest by more than §6.3 allows.
	ComputeRefusalCatalogStale ComputeRefusalCode = "catalog_stale"
	// A rate the broker holds the caller to: a network's searches, failed promotion codes.
	ComputeRefusalRateLimited ComputeRefusalCode = "rate_limited"
	// The network's compute is suspended (§9.9, §17.2): by §21's standing or an operator's hold (abuse_hold.go), the
	// reason saying which.
	ComputeRefusalSuspended ComputeRefusalCode = "suspended"
	// The request's address is in a region the broker refuses compute to (§17.2's sanctioned users; abuse_region.go).
	ComputeRefusalRegionRefused ComputeRefusalCode = "region_refused"
	// An approval route's decisions do not spend, or ask what no decision of the kind may (§16.6's gate step 1), its
	// reason the spend check's code; nothing was written.
	ComputeRefusalApprovalRefused ComputeRefusalCode = "approval_refused"
	// Every use of the approval is taken (§16.6's gate step 2, 409 SPENT).
	ComputeRefusalSpent ComputeRefusalCode = "spent"
)

// Each code's status.
var computeRefusalStatuses = map[ComputeRefusalCode]int{
	ComputeRefusalNotFound:               http.StatusNotFound,
	ComputeRefusalUnauthenticated:        http.StatusUnauthorized,
	ComputeRefusalScope:                  http.StatusForbidden,
	ComputeRefusalUnavailable:            http.StatusServiceUnavailable,
	ComputeRefusalUpgradeRequired:        http.StatusServiceUnavailable,
	ComputeRefusalNotBuilt:               http.StatusServiceUnavailable,
	ComputeRefusalIdempotencyKeyRequired: http.StatusBadRequest,
	ComputeRefusalInvalid:                http.StatusBadRequest,
	ComputeRefusalCapacity:               http.StatusServiceUnavailable,
	ComputeRefusalHeld:                   http.StatusTooManyRequests,
	ComputeRefusalInsufficientQuota:      http.StatusPaymentRequired,
	ComputeRefusalTeeUnverified:          http.StatusServiceUnavailable,
	ComputeRefusalDisclosureRequired:     http.StatusForbidden,
	ComputeRefusalCatalogStale:           http.StatusConflict,
	ComputeRefusalRateLimited:            http.StatusTooManyRequests,
	ComputeRefusalSuspended:              http.StatusForbidden,
	ComputeRefusalRegionRefused:          http.StatusUnavailableForLegalReasons,
	ComputeRefusalApprovalRefused:        http.StatusForbidden,
	ComputeRefusalSpent:                  http.StatusConflict,
}

// The status a code answers with, false for a code the table does not have.
func ComputeRefusalStatus(code ComputeRefusalCode) (int, bool) {
	status, ok := computeRefusalStatuses[code]
	return status, ok
}

// One refusal.
type ComputeRefusal struct {
	Code ComputeRefusalCode
	// A word from the code's own closed set, such as insufficient_quota's balance or budget (§6.6), never anything a
	// caller sent. Empty for none.
	Reason string
	// When the caller may ask again, where the design gives a retry time; zero for none. Rounded up to whole seconds
	// in Retry-After and to milliseconds in the body.
	RetryAfter time.Duration
}

// A refusal with its code alone.
func NewComputeRefusal(code ComputeRefusalCode) *ComputeRefusal {
	return &ComputeRefusal{Code: code}
}

// What a refusal's body holds.
type computeRefusalBody struct {
	Code         ComputeRefusalCode `json:"code"`
	Reason       string             `json:"reason,omitempty"`
	RetryAfterMs int64              `json:"retry_after_ms,omitempty"`
}

// The refusal's body: its JSON, which marshals for every value a refusal can hold.
func (self *ComputeRefusal) body() []byte {
	body := &computeRefusalBody{Code: self.Code, Reason: self.Reason}
	if 0 < self.RetryAfter {
		body.RetryAfterMs = (self.RetryAfter + time.Millisecond - 1).Milliseconds()
	}
	data, err := json.Marshal(body)
	if err != nil {
		// a string and two numbers always marshal; the code alone says why if they ever do not
		data = []byte(`{"code":"` + string(ComputeRefusalUnavailable) + `"}`)
	}
	return data
}
