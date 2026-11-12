// A store fault is a plan: the next matching operation on any fake gets its result (§22.8's FaultPlan).
// A schedule arms plans; a fake takes them. The types live here and not in sidecartest/fault, whose
// Step carries them, because a parent never imports its child (connect/CODESTYLE.md:26) and every fake
// here needs them. package fault re-exports them under the design's names.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// What an operation does instead of its normal result.
type FaultResult int

const (
	// Applies a write and shows the caller a transport error (§22.8's unknown rule): a lost response.
	// A read answers normally at the store and the caller gets the same transport error.
	ApplyThenDrop FaultResult = iota + 1
	// The request dies before the store takes it: nothing applies, and the caller gets a transport
	// error, the same one a lost response gives.
	FailBeforeApply
	// A PUT's condition fails, whatever the key holds, and nothing applies.
	Precondition
	// The request is parked. FaultPlan.Delay says what becomes of it, and its caller waits as a client
	// does: until it lands, its ctx ends, or the request's timeout passes on the clock.
	Delay
	// §19.6's settle holds the key: nothing applies and the caller gets ErrBlobHeld.
	Held
	// The caller's process dies as the request leaves, so nothing applies and the call never returns.
	CrashBeforeApply
	// The store applies the write, and the caller's process dies before the answer reaches it: a
	// crash point after a commit, so the call never returns.
	CrashAfterApply
	// A real store loses its read or write quorum (T3 only: FS-1, FS-40).
	QuorumLoss
	// A write misses a drive (T3 only: FS-40).
	DriveMiss
)

func (self FaultResult) String() string {
	switch self {
	case ApplyThenDrop:
		return "ApplyThenDrop"
	case FailBeforeApply:
		return "FailBeforeApply"
	case Precondition:
		return "Precondition"
	case Delay:
		return "Delay"
	case Held:
		return "Held"
	case CrashBeforeApply:
		return "CrashBeforeApply"
	case CrashAfterApply:
		return "CrashAfterApply"
	case QuorumLoss:
		return "QuorumLoss"
	case DriveMiss:
		return "DriveMiss"
	}
	return fmt.Sprintf("FaultResult(%d)", int(self))
}

// What becomes of a Delay. The first two are the settle rule's two fates for a write the store took
// (D-OPS-20): it takes effect before the next request on its key, or never.
type FaultDelay int

const (
	// Takes effect just before the next request on its key, by the checks of that moment, its
	// deadline and its condition among them.
	DelayLandsBeforeNext FaultDelay = iota
	// Never takes effect: the next request on its key finds it gone.
	DelayNeverLands
	// Has not reached the store: other requests on its key pass it, and it arrives when a test calls
	// FakeBlobs.DeliverDelayed, judged then, by its deadline first (§19.6's a request delayed in the
	// network).
	DelayInNetwork
)

// Operation names a plan matches. A fake with no such operation never takes the plan, and the plan
// stays unfired, which fails the schedule.
const (
	// PutIfNoneMatch, PutIfMatch and PutStream.
	FaultOpPut = "put"
	// Get, GetRange and Head.
	FaultOpGet    = "get"
	FaultOpList   = "list"
	FaultOpDelete = "delete"
	// Every Redis call but AddKeyEventCallback.
	FaultOpRedis = "redis"
	// A server's commit, at T3.
	FaultOpPgCommit = "pg-commit"
	// An api route, on FakeApi.
	FaultOpHttp = "http"
	// Every call of a Quota, Tasks or Push fake, which have no key: KeyPrefix then matches the
	// method's name.
	FaultOpHost = "host"
)

var faultOps = []string{
	FaultOpPut, FaultOpGet, FaultOpList, FaultOpDelete, FaultOpRedis, FaultOpPgCommit, FaultOpHttp, FaultOpHost,
}

// The result the next matching operation gets. See §22.8.
type FaultPlan struct {
	Op        string
	KeyPrefix string
	// Which match gets it, counting from 1. Zero means the first.
	Nth    int
	Result FaultResult
	// With Delay: what becomes of the request.
	Delay FaultDelay
	// How many further matches after Nth get the same result, so a store can stay down for a while.
	// Negative: every further one, until the test ends. An unbounded plan counts as fired at its first.
	Repeat int
	// Only this actor's calls match. Empty: anyone's.
	Actor string
	// Only this cluster's calls match. Empty: any.
	ClusterId string
	// Takes the operation it fires at even from an older plan that fires there too, which then counts
	// as fired there without its result. How §22.8's unknown rule loses the response of a write the
	// schedule's own FailBeforeApply fails, which a caller cannot tell apart from a lost response.
	Displaces bool
	// Only operations that write match and count toward Nth, so a Redis plan can name the nth Redis
	// write whatever reads come between, as §22.8's unknown rule needs. A PUT and a DELETE always write.
	WritesOnly bool
}

func (self *FaultPlan) String() string {
	return fmt.Sprintf("%s %s nth=%d %s", self.Op, self.KeyPrefix, self.Nth, self.Result)
}

// Whether a fake at T2 can do what this plan asks: T3's results need real drives.
func (self *FaultPlan) validate() error {
	if !slices.Contains(faultOps, self.Op) {
		return fmt.Errorf("fault plan %s: no such operation", self)
	}
	if self.Nth < 0 {
		return fmt.Errorf("fault plan %s: a negative Nth", self)
	}
	switch self.Result {
	case ApplyThenDrop, FailBeforeApply, CrashBeforeApply, CrashAfterApply:
	case Delay:
		if self.Op == FaultOpHost {
			return fmt.Errorf("fault plan %s: a host fake parks no call", self)
		}
	case Precondition:
		if self.Op != FaultOpPut {
			return fmt.Errorf("fault plan %s: only a PUT has a condition", self)
		}
	case Held:
		if self.Op != FaultOpPut && self.Op != FaultOpGet && self.Op != FaultOpDelete {
			return fmt.Errorf("fault plan %s: only a request on a key is held", self)
		}
	case QuorumLoss:
		if self.Op != FaultOpPut && self.Op != FaultOpGet && self.Op != FaultOpList && self.Op != FaultOpDelete {
			return fmt.Errorf("fault plan %s: only a store request loses a quorum", self)
		}
		return fmt.Errorf("fault plan %s: %w", self, ErrFaultNeedsRealStore)
	case DriveMiss:
		if self.Op != FaultOpPut {
			return fmt.Errorf("fault plan %s: only a PUT misses a drive", self)
		}
		return fmt.Errorf("fault plan %s: %w", self, ErrFaultNeedsRealStore)
	default:
		return fmt.Errorf("fault plan %s: no such result", self)
	}
	return nil
}

// A plan only T3's stores can carry out: a fake refuses it rather than pretend (§22.8).
var ErrFaultNeedsRealStore = errors.New("this result needs a real store (T3)")

type armedFault struct {
	plan      *FaultPlan
	matches   int
	fireCount int
	fired     chan struct{}
}

// One queue of armed plans, shared by every fake of a test, so a schedule's plan reaches whichever
// fake the operation goes to. Safe for concurrent use.
type FaultQueue struct {
	stateLock sync.Mutex
	armed     []*armedFault
	onFire    func(plan *FaultPlan)
	// what the stores behind the queue cannot carry out, beside validate's rules: nil on T2
	check func(plan *FaultPlan) error
	// whether the stores behind the queue carry out a result only a real store can: nil on T2, where every
	// such plan is ErrFaultNeedsRealStore
	realStore func(plan *FaultPlan) error
	// By operation, each one that reached the queue in order, with the result it was given, zero for
	// none.
	opResults map[string][]FaultResult
	// The same, for the operations that write alone.
	writeResults map[string][]FaultResult
}

func NewFaultQueue() *FaultQueue {
	return &FaultQueue{}
}

// Called with each plan as it fires, on the goroutine of the operation it hit, and with no lock held.
func (self *FaultQueue) SetOnFire(onFire func(plan *FaultPlan)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.onFire = onFire
}

// Refuses, at Add, each plan check returns an error for: what the stores behind this queue cannot
// carry out beyond what validate already refuses. Server's T3 sets it (sidecart3), since a real store
// parks no request on a schedule's word, so a schedule asking for that fails where it was written, as
// it does on a fake. nil checks nothing more.
func (self *FaultQueue) SetCheck(check func(plan *FaultPlan) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.check = check
}

// Lets the stores behind this queue take QuorumLoss and DriveMiss, which a fake refuses as
// ErrFaultNeedsRealStore: admit says whether they can carry out one such plan, and its error refuses the plan
// at Add. Server's T3 sets it on a Net over its 4-host file-cluster layouts (sidecart3/cluster_faults.go),
// where a host goes down for real, and one MinIO process refuses both, having no host to lose. nil, as on
// T2, refuses every such plan.
func (self *FaultQueue) SetRealStore(admit func(plan *FaultPlan) error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.realStore = admit
}

// Arms plan. A plan a fake cannot carry out is an error here, so a schedule fails where it was
// written. The returned channel closes when the plan first fires.
func (self *FaultQueue) Add(plan *FaultPlan) (fired <-chan struct{}, err error) {
	validateErr := plan.validate()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if validateErr != nil {
		// a result only a real store carries out is the real store's to take or refuse
		if !errors.Is(validateErr, ErrFaultNeedsRealStore) || self.realStore == nil {
			return nil, validateErr
		}
		if err := self.realStore(plan); err != nil {
			return nil, fmt.Errorf("fault plan %s: %w", plan, err)
		}
	}
	if self.check != nil {
		if err := self.check(plan); err != nil {
			return nil, fmt.Errorf("fault plan %s: %w", plan, err)
		}
	}
	armed := &armedFault{plan: plan, fired: make(chan struct{})}
	self.armed = append(self.armed, armed)
	return armed.fired, nil
}

// For a store, Redis or api wrapper outside this package, such as server's T3 wrappers (sidecart3):
// the plan one operation gets, or nil, exactly as a fake here takes one. op is a FaultOp, clusterId the
// operation's cluster or empty, key its key or what stands for one, and write whether it writes. Under
// InspectContext nothing is taken or counted.
func (self *FaultQueue) Take(ctx context.Context, op string, clusterId string, key string, write bool) *FaultPlan {
	return self.take(ctx, op, clusterId, key, write)
}

// For one operation, the plan it gets, or nil. Reading counts a match on every armed plan the
// operation fits, so Nth means the same whatever else is armed. The oldest plan that fires wins,
// unless a plan that Displaces fires too. write says whether the operation writes.
func (self *FaultQueue) take(ctx context.Context, op string, clusterId string, key string, write bool) *FaultPlan {
	if isInspecting(ctx) {
		return nil
	}
	actorName := ActorName(ctx)
	var taken *FaultPlan
	var onFire func(plan *FaultPlan)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		firing := []*armedFault{}
		for _, armed := range self.armed {
			plan := armed.plan
			if plan.Op != op || !strings.HasPrefix(key, plan.KeyPrefix) {
				continue
			}
			if plan.Actor != "" && plan.Actor != actorName {
				continue
			}
			if plan.ClusterId != "" && plan.ClusterId != clusterId {
				continue
			}
			if plan.WritesOnly && !write {
				continue
			}
			armed.matches += 1
			first := max(plan.Nth, 1)
			if armed.matches < first {
				continue
			}
			if 0 <= plan.Repeat && first+plan.Repeat < armed.matches {
				continue
			}
			firing = append(firing, armed)
		}
		fire := func(armed *armedFault) {
			armed.fireCount += 1
			if armed.fireCount == 1 {
				close(armed.fired)
			}
		}
		winner := slices.IndexFunc(firing, func(armed *armedFault) bool { return armed.plan.Displaces })
		if winner < 0 && 0 < len(firing) {
			winner = 0
		}
		result := FaultResult(0)
		if 0 <= winner {
			taken = firing[winner].plan
			result = taken.Result
			fire(firing[winner])
			if taken.Displaces {
				// what it displaced fired here as its schedule armed it to, only without its result
				for index, armed := range firing {
					if index != winner {
						fire(armed)
					}
				}
			}
		}
		if self.opResults == nil {
			self.opResults = map[string][]FaultResult{}
			self.writeResults = map[string][]FaultResult{}
		}
		self.opResults[op] = append(self.opResults[op], result)
		if write {
			self.writeResults[op] = append(self.writeResults[op], result)
		}
		onFire = self.onFire
	}()
	if taken != nil && onFire != nil {
		onFire(taken)
	}
	return taken
}

// Each operation of op that reached the queue, in order, with the result its plan gave, zero for none.
// What a sweep over a schedule's writes counts from, since a fake counts only what it served.
func (self *FaultQueue) OpResults(op string) []FaultResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opResults[op])
}

// As OpResults, for the operations of op that write alone: what §22.8's unknown rule loses the response
// of, one write at a time.
func (self *FaultQueue) WriteResults(op string) []FaultResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.writeResults[op])
}

// Plans armed and never fired: a schedule ending with one proved nothing about it.
func (self *FaultQueue) Unfired() []*FaultPlan {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	plans := []*FaultPlan{}
	for _, armed := range self.armed {
		if armed.fireCount == 0 {
			plans = append(plans, armed.plan)
		}
	}
	return plans
}

// Drops every armed plan.
func (self *FaultQueue) Clear() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.armed = nil
}

type inspectContextKey struct{}

// ctx for an oracle: a fake serves a call under it directly from its state, with no fault, delay,
// count, deadline or history, so reading after every step changes nothing a schedule counts. A real
// store ignores it.
func InspectContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, inspectContextKey{}, true)
}

func isInspecting(ctx context.Context) bool {
	inspecting, _ := ctx.Value(inspectContextKey{}).(bool)
	return inspecting
}
