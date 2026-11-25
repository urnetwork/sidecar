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
