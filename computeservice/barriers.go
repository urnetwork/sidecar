// Every barrier computeservice calls (§22.4, §22.8): the names a fault schedule holds, listed once here so a schedule
// and the code agree, each area appending its own. A name is compute.<part>.<point>, with .before and .after around a
// linearization point. A key says which instance is held: a request's engine id in sidecar.EvsKeyId's form, or
// computeBarrierEngineKey for the engine's own step. Keys are opaque ids, never a path, a route or a name (I-13).
//
// Each hook may block for as long as a schedule holds it, so none is called with a state lock held.

package computeservice

// The engine's own steps (CSRV-M12-01).
const (
	// Around a request's entry into the in-flight count, the point Drain's count is taken against: a request past
	// .after is one Drain waits for, and one held at .before arrives after the drain began and is refused.
	BarrierComputeRequestAdmitBefore = "compute.request.admit.before"
	BarrierComputeRequestAdmitAfter  = "compute.request.admit.after"
	// Around the drain's bound, where every request's context ends.
	BarrierComputeDrainEndBefore = "compute.drain.end.before"
	BarrierComputeDrainEndAfter  = "compute.drain.end.after"
	// Around a stream's keep-alive comment.
	BarrierComputeStreamCommentBefore = "compute.stream.comment.before"
	BarrierComputeStreamCommentAfter  = "compute.stream.comment.after"
)

// The key of a step that belongs to the engine and no one request.
const computeBarrierEngineKey = "engine"

// The provider store's steps (PROV-M12-01), keyed by the provider's code in decimal.
const (
	// Around a status change's transaction, whose commit is its linearization point: a gate result, a suspension or a
	// resumption (provider_store.go).
	BarrierComputeProviderStatusBefore = "compute.provider.status.before"
	BarrierComputeProviderStatusAfter  = "compute.provider.status.after"
)

// The remote catalog's steps (INFER-M12-01), keyed by the version in decimal.
const (
	// Around a version's publish, whose insert is its linearization point: of two publishers of one version, the one
	// that inserts second loses there (broker_catalog.go).
	BarrierComputeCatalogPublishBefore = "compute.catalog.publish.before"
	BarrierComputeCatalogPublishAfter  = "compute.catalog.publish.after"
)

// The abuse hold's steps (CARCH-M12-01), keyed by the network's id in sidecar.EvsKeyId's form.
const (
	// Around an admission's fill of a network's hold from Postgres, between the row's read and its projection: a staff
	// act that commits and projects in between leaves a newer version the fill's write never replaces (abuse_hold.go).
	BarrierComputeAbuseHoldFillBefore = "compute.abuse_hold.fill.before"
	BarrierComputeAbuseHoldFillAfter  = "compute.abuse_hold.fill.after"
)

// Web search's steps (SRCH-M13-07, SRCH-M13-08), keyed by the search's operation key in sidecar.EvsKeyId's form, which
// names no ticket, nonce or payee (D-BAL-14).
const (
	// Around an admission's claim of its request id and attempt in {cmpa}: of two admissions of one, the one that
	// claims second meets the first's ticket there (search_tickets.go).
	BarrierComputeSearchClaimBefore = "compute.search.claim.before"
	BarrierComputeSearchClaimAfter  = "compute.search.claim.after"
	// Around the ledger's hold, whose row's commit is the admission's liability: nothing reaches the signer before it.
	BarrierComputeSearchHoldBefore = "compute.search.hold.before"
	BarrierComputeSearchHoldAfter  = "compute.search.hold.after"
	// Around the sign request's relay to searchsigner.
	BarrierComputeSearchSignBefore = "compute.search.sign.before"
	BarrierComputeSearchSignAfter  = "compute.search.sign.after"
	// Around a report's answer, whose ledger move (the charge, or the release) is its linearization point: a report
	// answered twice books one charge (search_settle.go).
	BarrierComputeSearchAnswerBefore = "compute.search.answer.before"
	BarrierComputeSearchAnswerAfter  = "compute.search.answer.after"
)
