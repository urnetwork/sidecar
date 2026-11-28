// ComputeSearchSuspend: the sanctions records and the search suspension they bring (DESIGN-COMPUTE §21.5, §21.10,
// compute-10; SRCH-M13-07, SRCH-M13-08), over compute_search_flag (sidecar/model's compute_search.go):
//
//	payee_refused  the signer's screen refused the payee a device relayed: never paid. The record keeps the payee with
//	               the network, sidecar and time, the network's search is suspended until an operator reviews it
//	               (an honest device only relays the gateway's payee), and the record pages
//	out_of_band    an authorization settled by a sender outside the facilitator's addresses: charged as settled. The
//	               record keeps its payee and transaction with the network and sidecar, flags the network for review
//	               (§21.10) and pages; the network's search goes on until the review decides
//
// The suspension is read at every search admission as one of CARCH-M12-01's abuse flags (abuse_hold.go's
// registerComputeAbuseFlag), on POST /v1/search/authorize alone, and answers search_off naming review, the network's
// other compute untouched. A broker instance answers it from what it last read for SuspensionCacheMaxAge, and the
// instance that records a refusal answers it at once. An operator's review clears it: `sidecarctl compute resume
// <network> --search --review <reference>` (QD-1374, CARCH's command, which reviews the records through
// model.ComputeSearchFlagReview); until that lands, a suspended network stays suspended.
//
// Each record pages through urnetwork_compute_alarms_total{kind="search_sanctions_record"}, whose line names no
// network (IC-13): the record is where the network is, for the review and for counsel. Safe for concurrent use.

package computeservice

import (
	"context"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/model"
)

// The suspension, as every search admission reads it.
func init() {
	registerComputeAbuseFlag(&ComputeAbuseFlag{
		Name:   "search_suspension",
		Routes: []string{ComputeRouteSearchAuthorize},
		Check:  computeSearchSuspensionCheck,
	})
}

// search_off's reasons: which switch is off, so the device can name the fix.
const (
	// The compute terms' web search clause is not accepted: an Owner or Admin accepts it (§21.9).
	ComputeSearchOffReasonClause = "clause"
	// The compute block's search.enabled is false.
	ComputeSearchOffReasonPolicy = "policy"
	// No compute:search query rule names the caller.
	ComputeSearchOffReasonQuery = "query"
	// A sanctions record suspends the network's search until reviewed.
	ComputeSearchOffReasonReview = "review"
	// The signed policy carries no search line, or the catalog version lists no search: before G-SRCH-parallel.
	ComputeSearchOffReasonPolicyLine = "policy_line"
)

// The alarm a sanctions record raises: the monitor's compute-search-sanctions-record page (§14.7).
const ComputeAlarmSearchSanctionsRecord = "search_sanctions_record"

// Where the records live: compute_search_flag, over the engine's Env, or a test's.
type computeSearchFlagStore interface {
	Insert(ctx context.Context, flag *model.ComputeSearchFlag) (bool, error)
	Suspended(ctx context.Context, networkId sidecar.Id) (bool, error)
}

// The real store.
type envComputeSearchFlagStore struct {
	env operator.Env
}

// See computeSearchFlagStore.
func (self *envComputeSearchFlagStore) Insert(ctx context.Context, flag *model.ComputeSearchFlag) (bool, error) {
	return model.ComputeSearchFlagInsert(self.env, ctx, flag)
}

// See computeSearchFlagStore.
func (self *envComputeSearchFlagStore) Suspended(ctx context.Context, networkId sidecar.Id) (bool, error) {
	return model.ComputeSearchSuspended(self.env, ctx, networkId)
}

// One network's suspension as this instance last read it.
type computeSearchSuspensionEntry struct {
	suspended bool
	readTime  time.Time
}

// The records and the suspension for one engine. See the file header.
type ComputeSearchSuspend struct {
	engine   *ComputeEngine
	settings *ComputeSearchSettings
	store    func() computeSearchFlagStore

	stateLock          sync.Mutex
	networkIdSuspended map[sidecar.Id]*computeSearchSuspensionEntry
}

// The suspension for engine, its records in store's.
func newComputeSearchSuspend(engine *ComputeEngine, settings *ComputeSearchSettings, store func() computeSearchFlagStore) *ComputeSearchSuspend {
	return &ComputeSearchSuspend{
		engine:             engine,
		settings:           settings,
		store:              store,
		networkIdSuspended: map[sidecar.Id]*computeSearchSuspensionEntry{},
	}
}

// Remembers networkId's suspension as read at now, the cache emptied past its bound.
func (self *ComputeSearchSuspend) remember(networkId sidecar.Id, suspended bool, now time.Time) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.CacheMaxCount <= len(self.networkIdSuspended) {
		self.networkIdSuspended = map[sidecar.Id]*computeSearchSuspensionEntry{}
	}
	self.networkIdSuspended[networkId] = &computeSearchSuspensionEntry{suspended: suspended, readTime: now}
}

// Whether networkId's search is suspended for review: from the cache while it is fresh, else the store's.
func (self *ComputeSearchSuspend) Suspended(ctx context.Context, networkId sidecar.Id) (bool, error) {
	now := self.engine.clock.Now()
	maxAge := self.settings.SuspensionCacheMaxAge
	cached := func() (bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry := self.networkIdSuspended[networkId]
		if entry == nil || maxAge <= 0 || maxAge <= now.Sub(entry.readTime) {
			return false, false
		}
		return entry.suspended, true
	}
	if suspended, ok := cached(); ok {
		return suspended, nil
	}
	suspended, err := self.store().Suspended(ctx, networkId)
	if err != nil {
		return false, err
	}
	self.remember(networkId, suspended, now)
	return suspended, nil
}

// Keeps a sanctions record of reason for networkId and sidecarId: payee for both, transaction for an out-of-band
// settlement. A refused payee suspends the network's search at once on this instance, and within
// SuspensionCacheMaxAge on the others. Every record pages; one already standing open writes nothing new.
func (self *ComputeSearchSuspend) Record(ctx context.Context, networkId sidecar.Id, sidecarId sidecar.Id, reason model.ComputeSearchFlagReason, payee []byte, transaction []byte) error {
	now := self.engine.clock.Now()
	flag := &model.ComputeSearchFlag{
		FlagId:      sidecar.NewId(),
		NetworkId:   networkId,
		SidecarId:   sidecarId,
		Reason:      reason,
		Payee:       append([]byte{}, payee...),
		Transaction: transaction,
		FlagTime:    now.UTC(),
	}
	if reason == model.ComputeSearchFlagReasonPayeeRefused {
		flag.Transaction = nil
		// the suspension stands at once here, whatever the write does: a write that failed is asked again by the
		// caller, and the next read of the store answers what it holds
		self.remember(networkId, true, now)
	}
	self.engine.alarm(ComputeAlarmSearchSanctionsRecord, "a web search sanctions record (%s) was kept for review", reason)
	_, err := self.store().Insert(ctx, flag)
	return err
}

// The admission check: search_off naming review while a refused payee's record stands unreviewed; unavailable where
// the suspension cannot be read.
func computeSearchSuspensionCheck(request *ComputeRequest) *ComputeRefusal {
	if request.Caller == nil || request.engine.search == nil {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	suspended, err := request.engine.search.suspend.Suspended(request.Ctx, request.Caller.NetworkId)
	if err != nil {
		return NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if suspended {
		return &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonReview}
	}
	return nil
}
