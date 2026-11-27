// The abuse hold every broker admission reads (DESIGN-COMPUTE §17.2, D-CABUSE-1, D-CABUSE-2; CARCH-M12-01):
// computeAbuseHold, an admission check on remote calls, searches and enclave creates and starts, which refuses a
// network whose compute is suspended, 403 suspended, after the gate, the groups and Idempotency-Key and before any
// handler holds a cent (engine.go's step 6). It reads, in this order:
//
//  1. DESIGN §21.7's standing, from the host's AbuseGate memory (ServiceHost.Abuse): a network §21 suspends, or one
//     in a standing this build does not know, gets no compute either, reason standing; one the gate has not loaded
//     answers unavailable while the gate loads it off the path, as every §21 gate does;
//  2. the operator's hold (model's compute_abuse_hold), placed by `sidecarctl compute suspend` through api's staff
//     route and ended by `sidecarctl compute resume`: the projection {cmp_<network_id>}:a on the host's Redis, which
//     every broker instance shares, or on a miss the row in Postgres, which it then projects; reason hold. A held
//     network keeps its balance and its records; this only refuses;
//  3. the flags other areas keep on a network for some of its admissions, read into the one hold through
//     registerComputeAbuseFlag: INFER's and BAL's second direct-call mismatch in 30 days, refusing the network's
//     direct calls (§6.6, §9.11); SRCH's suspension of a network's search (§21.5, §21.10); ENC's failed starts
//     (§11.6, §11.13). None is registered until its area lands it.
//
// An admission that cannot read what it needs refuses, unavailable: no gate loaded, no Redis, a row that did not read,
// a flag that cannot tell. The refusal's reason says which part held the network, never its class: the class is the
// record's and the runbook's, and a takedown under a sealed order must not say so (§17.3; DESIGN §21.9).
//
// The projection is soft state: a lost or expired one is filled again from the row, a lower version never replacing
// a higher, so a fill that read Postgres before a staff act committed loses to the act's own write.

package computeservice

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/urnetwork/connect"
	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// Every admission's abuse hold, registered before the region check.
func init() {
	registerComputeAdmissionCheck("abuse_hold", computeAbuseHold)
}

// A suspended refusal's reasons: which part held the network.
const (
	// DESIGN §21.7's standing: a §21 suspension, or a standing this build does not know.
	ComputeSuspendedReasonStanding = "standing"
	// An operator's hold (compute_abuse_hold).
	ComputeSuspendedReasonHold = "hold"
)

// The admission check (see the file header): nil admits, a refusal answers.
func computeAbuseHold(request *ComputeRequest) *ComputeRefusal {
	caller := request.Caller
	if caller == nil {
		// an admission route takes a sidecar, so one with no caller is a fault, which refuses
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	standing, loaded := request.engine.host.AbuseOrUnloaded().Standing(connect.Id(caller.NetworkId))
	if !loaded {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if standing == sidecar.AbuseStandingSuspended || !standing.Known() {
		return &ComputeRefusal{Code: ComputeRefusalSuspended, Reason: ComputeSuspendedReasonStanding}
	}
	state, err := request.engine.abuseHoldState(request.Ctx, caller.NetworkId)
	if err != nil {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if state.Held() {
		return &ComputeRefusal{Code: ComputeRefusalSuspended, Reason: ComputeSuspendedReasonHold}
	}
	for _, flag := range computeAbuseFlags {
		if !slices.Contains(flag.Routes, request.route.Name) {
			continue
		}
		if refusal := flag.Check(request); refusal != nil {
			return refusal
		}
	}
	return nil
}

// Where a broker reads a network's hold when its projection is absent: compute_abuse_hold, over the engine's Env.
type computeAbuseHoldStore interface {
	// The network's row, nil for a network never held.
	Hold(ctx context.Context, networkId sidecar.Id) (*model.ComputeAbuseHold, error)
}

// The real store: model's, over the engine's Env (owner decision 594).
type envComputeAbuseHoldStore struct {
	env operator.Env
}

// See computeAbuseHoldStore.
func (self *envComputeAbuseHoldStore) Hold(ctx context.Context, networkId sidecar.Id) (*model.ComputeAbuseHold, error) {
	return model.ComputeAbuseHoldGet(self.env, ctx, networkId)
}

// The engine's abuse settings: its settings' Abuse, or the defaults.
func (self *ComputeEngine) abuseSettings() *ComputeAbuseSettings {
	if self.settings.Abuse == nil {
		return DefaultComputeAbuseSettings()
	}
	return self.settings.Abuse
}

// The store a miss reads: the deps' test store, else compute_abuse_hold over the engine's Env.
func (self *ComputeEngine) abuseHoldStore() computeAbuseHoldStore {
	if self.deps.testAbuseHoldStore != nil {
		return self.deps.testAbuseHoldStore
	}
	return &envComputeAbuseHoldStore{env: self.Env()}
}

// networkId's hold as an admission reads it (see the file header): the projection, or on a miss the row, then
// projected. An error where neither could be read.
func (self *ComputeEngine) abuseHoldState(ctx context.Context, networkId sidecar.Id) (*model.ComputeAbuseHoldState, error) {
	settings := self.abuseSettings().holdSettings()
	key := model.ComputeAbuseHoldRedisKey(networkId)
	var redis sidecar.Redis
	if 0 < settings.ProjectionMaxAge {
		var err error
		redis, err = self.MainRedis(key)
		if err != nil {
			return nil, err
		}
		state, err := model.ComputeAbuseHoldProjected(ctx, redis, networkId)
		if err != nil {
			return nil, err
		}
		if state != nil {
			return state, nil
		}
	}
	barrierKey := sidecar.EvsKeyId(networkId)
	testHookBarrier(BarrierComputeAbuseHoldFillBefore, barrierKey)
	hold, err := self.abuseHoldStore().Hold(ctx, networkId)
	if err != nil {
		return nil, err
	}
	state := model.ComputeAbuseHoldStateOf(hold)
	testHookBarrier(BarrierComputeAbuseHoldFillAfter, barrierKey)
	if redis != nil {
		// a fill that does not take is no refusal: the row was read, and the next admission reads it again
		model.ComputeAbuseHoldProject(ctx, redis, settings, networkId, state)
	}
	return state, nil
}

// A flag another area keeps on a network, read into the one hold for the admission routes it names (see the file
// header).
type ComputeAbuseFlag struct {
	// The registry's name for it, held once.
	Name string
	// The admission routes it refuses, by route name: a direct-call flag names POST /v1/infer/authorize alone.
	Routes []string
	// nil admits; a refusal answers, and a flag that cannot tell refuses, unavailable. Runs after the hold, on the
	// request's goroutine, with request.Caller set.
	Check ComputeAdmissionCheck
}

// The flags areas registered, in registration order.
var computeAbuseFlags = []*ComputeAbuseFlag{}

// Registers a flag from an area's file at init. An empty name, a name taken, a nil check, no route, and a route that
// is no admission route of the design each panic: a build that registers wrongly does not start.
func registerComputeAbuseFlag(flag *ComputeAbuseFlag) {
	if flag == nil || flag.Name == "" || flag.Check == nil || len(flag.Routes) == 0 {
		panic(errors.New("a compute abuse flag needs a name, its routes and a check"))
	}
	admissionRoutes := []string{}
	for _, route := range computeRouteDesign() {
		if route.Admission {
			admissionRoutes = append(admissionRoutes, route.Name)
		}
	}
	for _, routeName := range flag.Routes {
		if !slices.Contains(admissionRoutes, routeName) {
			panic(fmt.Errorf("compute abuse flag %q names %q, which is no admission route", flag.Name, routeName))
		}
	}
	for _, registered := range computeAbuseFlags {
		if registered.Name == flag.Name {
			panic(fmt.Errorf("compute abuse flag %q registered twice", flag.Name))
		}
	}
	copied := *flag
	copied.Routes = slices.Clone(flag.Routes)
	computeAbuseFlags = append(computeAbuseFlags, &copied)
}
