// An operator's suspension of a network's compute and its resume (DESIGN-COMPUTE §17.2, D-CABUSE-1, D-CABUSE-2;
// CARCH-M12-01): what api's staff kinds compute_suspend and compute_resume run (server's
// abuse_compute_hold_controller.go) for `sidecarctl compute suspend` and `sidecarctl compute resume`, the abuse hold
// every broker admission reads (computeservice's abuse_hold.go).
//
//	ComputeAbuseHoldSuspend  the hold committed in one transaction (model's compute_abuse_hold), then projected for
//	                         every broker instance, then the network's enclaves stopped through ENC's
//	                         ComputeAbuseHoldListener, the indexer's among them
//	ComputeAbuseHoldResume   the hold ended and projected; nothing restarts: an enclave the hold stopped waits for its
//	                         keeper or its sponsor, whose start the broker admits again (§17.2's trap)
//
// Neither touches the ledger: a held network keeps its balance, its lots, its charges and its records (D-CABUSE-1),
// and §9.9's state goes on as the balance moves it. A projection that fails after the commit is said in the answer:
// every broker reads the row once the stale projection expires, within ComputeAbuseHoldSettings.ProjectionMaxAge, and
// a retry of the same act projects again. A listener that fails is alarmed and said; a retry asks it again, as it
// does whenever the hold stands after the act.

package controller

import (
	"context"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar/model"
)

// What an operator's hold stops: ENC's (C§11.11), which registers it. None registered stops nothing, since no enclave
// runs before M14. Each call is idempotent: a network held twice is stopped once.
type ComputeAbuseHoldListener interface {
	// Stops every enclave of networkId, the network's indexer enclave among them, each stop's cause the operator's
	// hold, so a keeper starts none of them again while it stands.
	Held(env operator.Env, ctx context.Context, networkId operator.Id) error
}

var (
	computeAbuseHoldLock     sync.Mutex
	computeAbuseHoldListener ComputeAbuseHoldListener
)

// Registers ENC's abuse hold listener from its own file. A second registration, or a nil one, panics.
func RegisterComputeAbuseHoldListener(listener ComputeAbuseHoldListener) {
	if listener == nil {
		panic("compute abuse hold: nil listener")
	}
	computeAbuseHoldLock.Lock()
	defer computeAbuseHoldLock.Unlock()
	if computeAbuseHoldListener != nil {
		panic("compute abuse hold: the listener is registered once")
	}
	computeAbuseHoldListener = listener
}

func computeRegisteredAbuseHoldListener() ComputeAbuseHoldListener {
	computeAbuseHoldLock.Lock()
	defer computeAbuseHoldLock.Unlock()
	return computeAbuseHoldListener
}

// The alarm kind of a hold whose enclaves the listener did not stop: a retry of the act, or a person, makes it good.
const ComputeAlarmAbuseHoldListener = "abuse_hold_listener"

// The alarm kind of a hold committed whose projection did not take: every broker reads it once the projection expires.
const ComputeAlarmAbuseHoldProjection = "abuse_hold_projection"

// What one act asks.
type ComputeAbuseHoldRequest struct {
	NetworkId operator.Id
	// The class a suspension is for; a resume reads none.
	Reason model.ComputeAbuseHoldReason
	// The staff member's opaque reviewer id (abuse-staff.yml), which the row keeps.
	StaffId operator.Id
}

// What the enclaves' stop came to.
type ComputeAbuseHoldEnclaves string

const (
	// No listener is registered: no enclave runs before ENC's M14, so nothing was there to stop.
	ComputeAbuseHoldEnclavesNone ComputeAbuseHoldEnclaves = "none"
	// The listener stopped the network's enclaves, or found none running.
	ComputeAbuseHoldEnclavesStopped ComputeAbuseHoldEnclaves = "stopped"
	// The listener failed: alarmed, and asked again by a retry of the suspension.
	ComputeAbuseHoldEnclavesFailed ComputeAbuseHoldEnclaves = "failed"
	// A resume restarts nothing (§17.2's trap).
	ComputeAbuseHoldEnclavesUntouched ComputeAbuseHoldEnclaves = "untouched"
)

// What one act came to.
type ComputeAbuseHoldAnswer struct {
	// The row as it stands after; nil for a resume of a network never held.
	Hold *model.ComputeAbuseHold
	// Whether this act changed the row; false for a retry, or a resume of a hold that does not stand.
	Changed bool
	// Whether every broker reads the row's state at once: false where the projection failed after the commit, so
	// brokers read it once the stale projection expires.
	Projected bool
	Enclaves  ComputeAbuseHoldEnclaves
}

// Holds request's network for its reason (see the file header).
func ComputeAbuseHoldSuspend(env operator.Env, ctx context.Context, settings *model.ComputeAbuseHoldSettings, request *ComputeAbuseHoldRequest) (*ComputeAbuseHoldAnswer, error) {
	if !request.Reason.Valid() {
		return nil, model.ErrComputeAbuseHoldArgs
	}
	answer, err := computeAbuseHoldChange(env, ctx, settings, request.NetworkId, func(tx operator.DbTx, now time.Time) (*model.ComputeAbuseHold, bool, error) {
		return model.ComputeAbuseHoldSuspendInTx(env, ctx, tx, request.NetworkId, request.Reason, request.StaffId, now)
	})
	if err != nil {
		return nil, err
	}
	answer.Enclaves = ComputeAbuseHoldEnclavesNone
	if listener := computeRegisteredAbuseHoldListener(); listener != nil {
		answer.Enclaves = ComputeAbuseHoldEnclavesStopped
		if err := listener.Held(env, ctx, request.NetworkId); err != nil {
			computeAlarm(env)(ComputeAlarmAbuseHoldListener)
			answer.Enclaves = ComputeAbuseHoldEnclavesFailed
		}
	}
	return answer, nil
}

// Ends request's network's hold (see the file header); its reason is not read.
func ComputeAbuseHoldResume(env operator.Env, ctx context.Context, settings *model.ComputeAbuseHoldSettings, request *ComputeAbuseHoldRequest) (*ComputeAbuseHoldAnswer, error) {
	answer, err := computeAbuseHoldChange(env, ctx, settings, request.NetworkId, func(tx operator.DbTx, now time.Time) (*model.ComputeAbuseHold, bool, error) {
		return model.ComputeAbuseHoldResumeInTx(env, ctx, tx, request.NetworkId, request.StaffId, now)
	})
	if err != nil {
		return nil, err
	}
	answer.Enclaves = ComputeAbuseHoldEnclavesUntouched
	return answer, nil
}

// Runs change in one transaction, its commit the hold's linearization point, then projects the row it answered.
func computeAbuseHoldChange(env operator.Env, ctx context.Context, settings *model.ComputeAbuseHoldSettings, networkId operator.Id, change func(tx operator.DbTx, now time.Time) (*model.ComputeAbuseHold, bool, error)) (*ComputeAbuseHoldAnswer, error) {
	clock, err := env.Clock()
	if err != nil {
		return nil, err
	}
	db, err := env.Db()
	if err != nil {
		return nil, err
	}
	answer := &ComputeAbuseHoldAnswer{}
	err = db.Tx(ctx, func(tx operator.DbTx) error {
		*answer = ComputeAbuseHoldAnswer{}
		hold, changed, err := change(tx, clock.Now())
		if err != nil {
			return err
		}
		answer.Hold, answer.Changed = hold, changed
		testHookBarrier("compute_abuse_hold.commit.before", networkId.String())
		return nil
	}, operator.DbIsolationReadCommitted)
	if err != nil {
		return nil, err
	}
	testHookBarrier("compute_abuse_hold.commit.after", networkId.String())
	answer.Projected = computeAbuseHoldProject(env, ctx, settings, networkId, model.ComputeAbuseHoldStateOf(answer.Hold))
	return answer, nil
}

// Writes state as networkId's projection, true where it took; a failure is alarmed, never an error, since the row is
// committed and the stale projection expires within its max age.
func computeAbuseHoldProject(env operator.Env, ctx context.Context, settings *model.ComputeAbuseHoldSettings, networkId operator.Id, state *model.ComputeAbuseHoldState) bool {
	redis, err := env.Redis()
	if err == nil {
		var projected bool
		projected, err = model.ComputeAbuseHoldProject(ctx, redis, settings, networkId, state)
		if err == nil && projected {
			return true
		}
	}
	computeAlarm(env)(ComputeAlarmAbuseHoldProjection)
	return false
}
