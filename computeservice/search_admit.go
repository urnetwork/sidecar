// POST compute/v1/search/authorize (DESIGN-COMPUTE §14.3, §21.5, §21.8, §21.9, §21.10, R-SRCH-2, R-SRCH-3, D-SRCH-2,
// D-SRCH-6, D-SRCH-10, D-SRCH-11, D-SRCH-12, IC-13, IC-15, CF-13, compute-10, compute-11; SRCH-M13-07): one search's
// admission, registered by route name behind the engine's whole guard, which has by then authenticated a sidecar of
// the network, held the compute gate, and run the admission checks: CARCH-M12-01's abuse hold and region refusal, and
// the search suspension a sanctions record brings (search_flag.go). In order, each refusal answered before anything is
// held:
//
//  1. the request: ComputeSearchAuthorizeRequest, its sizes the shared format's (a 16-byte request id, attempts 1 to
//     3, a 20-byte asset, a sealed payee within its bound), else invalid
//  2. {cmpa}'s instance sure to keep nothing, else capacity (§14.4)
//  3. the broker's newest verified policy's search line (§5.4): none, before G-SRCH-parallel, answers search_off; the
//     asset, network and amount must be its USDC on its CAIP-2 network within its ceiling, else invalid
//  4. the catalog version the request names (computeCatalogAt): one the broker no longer takes answers catalog_stale;
//     the amount times the markup, rounded up, may not pass the version's search price, else invalid (an honest
//     device pays no challenge above it), and a version listing no search answers search_off
//  5. search_off, naming the fix, unless the network's compute block leaves search on, a compute:search query rule
//     names the caller (§16.2, CACL's ComputeAllows over the projection's rows), and the network accepted the compute
//     terms' web search clause (BAL-M13-03, read through ComputeSearchLedger)
//  6. the request id and attempt claimed in {cmpa} for a fresh 32-byte ticket. One already admitted is a retry: the
//     signer is asked again with its ticket, the sealed payee the retry sent and the admission's own amount and minute,
//     and re-signs to the same bytes, so a retry neither holds nor signs anew; one in flight answers capacity. A retry
//     names its admission's amount, device and agent, else it is none and answers invalid
//  7. the hold, by the ledger's search script on {cmp_<network_id>} under D-BAL-14's key, its row committed before the
//     answer admits: insufficient_quota for the balance (grace, suspended, below zero, promotional credit paying none,
//     §9.9, §9.11), a budget (§16.4, §16.5) or open holds, capacity where the ledger cannot take it
//  8. the limits' second script (search_limits.go): the network's rate and its day under day_max (DefaultDayMaxCount
//     where the policy sets none), never above the search cap, then the payer's global rate with each active network's
//     equal share; a refusal releases the hold, rate_limited with a retry time
//  9. the ticket admitted in {cmpa}, and the sign request relayed to searchsigner over mTLS: the ticket, the amount,
//     the minute and the sealed payee, unread
//  10. the signer's answer: the sealed authorization, relayed unread, and the request's outcome counts added at once to
//     {cmpo}'s hour across all networks (a total past the network's searches today is dropped whole); or its refusal,
//     which releases the hold and drops the ticket, payee_refused also keeping the returned payee as a sanctions
//     record with the network, sidecar and time, suspending the network's search until reviewed and paging; a signer
//     unreachable answers capacity, the hold released. Outcomes count only beside an authorization, since the device
//     marks them reported only on one (websearch_client.go): a refused request's come again with its next, and a
//     retry's were counted with the authorization it repeats
//
// The broker never sees a payee, a nonce, a query, a mode or a result: the sealed payee and the sealed authorization
// pass through as bytes. No line is written per authorization (the route is NoLog): urnetwork_compute_search_
// authorizations_total{outcome} and the guard's per-route counters count them (§14.2's Logs, IC-13).
//
// Until their parts land, each seam fails closed: the ledger's search hold path (BAL-M13-02) refuses, so every search
// answers capacity; the clause's projection flag (BAL-M13-03) reads not accepted, so every search answers search_off;
// with no signer client (SRCH-M13-03's signer and the block's vault file) or no {cmpa} instance and its persistence
// reader (CSRV's host), every search answers capacity.

package computeservice

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/controller"
	"github.com/urnetwork/sidecar/model"
	"github.com/urnetwork/sidecar/protocol"
)

func init() {
	registerComputeRoutes(map[string]ComputeHandler{
		ComputeRouteSearchAuthorize: computeSearchAuthorizeHandler,
	})
}

// invalid's and capacity's reasons at the search route: which part did not read or could not serve.
const (
	ComputeSearchInvalidReasonRequest = "request"
	ComputeSearchInvalidReasonAsset   = "asset"
	ComputeSearchInvalidReasonNetwork = "network"
	ComputeSearchInvalidReasonCeiling = "ceiling"
	ComputeSearchInvalidReasonPrice   = "price"
	ComputeSearchInvalidReasonRetry   = "retry"

	ComputeSearchCapacityReasonAdmissions = "admissions"
	ComputeSearchCapacityReasonLedger     = "ledger"
	ComputeSearchCapacityReasonInFlight   = "in_flight"
	ComputeSearchCapacityReasonSigner     = "signer"
)

// What the search route reads of the caller's verified state (§16.2, §16.4): *sidecar.AclState's.
type computeSearchAcl interface {
	ComputeRows() *protocol.AclComputeRows
	ComputeAllows(subject sidecar.AclSubject, target sidecar.AclComputeTarget, action protocol.AclAction, now time.Time) sidecar.AclDecision
}

// {cmpa}'s instance's persistence, as its host reads it (Redis's CONFIG GET save and appendonly).
type ComputeRedisPersistence struct {
	// Any RDB save rule set.
	Snapshots bool
	// The append-only file on.
	AppendOnly bool
}

// Whether the instance keeps nothing: no snapshot and no append-only file.
func (self *ComputeRedisPersistence) Off() bool {
	return !self.Snapshots && !self.AppendOnly
}

// The test seams of one engine's search, each nil taking the real one.
type computeSearchTestDeps struct {
	// The caller's verified state, in place of its snapshot's rows.
	acl func(caller *ComputeCaller) computeSearchAcl
	// compute_search_flag, in place of the Env's.
	flags computeSearchFlagStore
}

// One engine's web search: the admission, its stores, the suspension and the report loop. Safe for concurrent use.
type ComputeSearchAdmission struct {
	engine   *ComputeEngine
	settings *ComputeSearchSettings
	signer   SearchSignerClient
	tickets  *computeSearchTickets
	limits   *computeSearchLimits
	outcomes *computeSearchOutcomeCounts
	suspend  *ComputeSearchSuspend
	reports  *ComputeSearchReportLoop

	authorizations sidecar.MetricsCounter

	persistenceLock sync.Mutex
	// sure, from a check, that the instance keeps nothing
	persistenceOff bool
	// a check found persistence on: every search refused until the engine restarts
	persistenceOn        bool
	persistenceCheckedAt time.Time
}

// The search outcomes urnetwork_compute_search_authorizations_total counts (§14.7).
const (
	computeSearchAuthorizationAuthorized = "authorized"
	computeSearchAuthorizationSettled    = "settled"
	computeSearchAuthorizationLapsed     = "lapsed"
)

// The engine's search settings: its settings' Search, or the defaults.
func (self *ComputeEngine) searchSettings() *ComputeSearchSettings {
	if self.settings.Search == nil {
		return DefaultComputeSearchSettings()
	}
	return self.settings.Search
}

// The engine's web search.
func (self *ComputeEngine) SearchAdmission() *ComputeSearchAdmission {
	return self.search
}

// The search for engine, from its deps: the signer client from the block's vault file where the deps give none, and
// {cmpa}'s persistence asked at once. The report loop starts where a signer, {cmpa} and a poll interval all stand.
func newComputeSearchAdmission(engine *ComputeEngine) *ComputeSearchAdmission {
	settings := engine.searchSettings()
	self := &ComputeSearchAdmission{
		engine:         engine,
		settings:       settings,
		tickets:        &computeSearchTickets{engine: engine, settings: settings},
		outcomes:       newComputeSearchOutcomeCounts(engine, settings),
		authorizations: engine.host.Metrics.Counter("urnetwork_compute_search_authorizations_total", "search authorizations by outcome, across all networks", "outcome"),
	}
	self.limits = &computeSearchLimits{engine: engine, settings: settings, ledger: self.ledger}
	self.suspend = newComputeSearchSuspend(engine, settings, self.flagStore)
	self.signer = engine.deps.SearchSigner
	if self.signer == nil {
		signer, err := newSearchSignerClientFromSecretFile(engine.deps.SecretFile, settings)
		if err != nil {
			// no client: every search answers capacity; the error names the file alone
			if engine.log.V(1).Enabled() {
				engine.log.Infof("[compute] web search holds no signer client: %v", err)
			}
		} else {
			self.signer = signer
		}
	}
	self.checkPersistence(engine.ctx)
	self.reports = newComputeSearchReportLoop(self)
	return self
}

// The ledger: the deps', else BAL's over the engine's Env, read at use since the Env may be the process's global one.
func (self *ComputeSearchAdmission) ledger() ComputeSearchLedger {
	if self.engine.deps.SearchLedger != nil {
		return self.engine.deps.SearchLedger
	}
	return NewComputeSearchLedger(self.engine.Env(), self.engine.brokerSettings().ledger())
}

// The sanctions records' store: the test's, else compute_search_flag over the engine's Env.
func (self *ComputeSearchAdmission) flagStore() computeSearchFlagStore {
	if test := self.engine.deps.testSearch; test != nil && test.flags != nil {
		return test.flags
	}
	return &envComputeSearchFlagStore{env: self.engine.Env()}
}

// The caller's verified state: the test's, else its snapshot's, nil where it keeps none.
func (self *ComputeSearchAdmission) acl(caller *ComputeCaller) computeSearchAcl {
	if test := self.engine.deps.testSearch; test != nil && test.acl != nil {
		return test.acl(caller)
	}
	if caller.Snapshot == nil || caller.Snapshot.Acl == nil {
		return nil
	}
	return caller.Snapshot.Acl
}

// The suspension a sanctions record brings.
func (self *ComputeSearchAdmission) Suspend() *ComputeSearchSuspend {
	return self.suspend
}

// The report loop.
func (self *ComputeSearchAdmission) Reports() *ComputeSearchReportLoop {
	return self.reports
}

// Asks {cmpa}'s instance whether it keeps anything, within PersistenceCheckTimeout: sure off, found on (sticky), or
// left unsure where no reader is given or it did not answer.
func (self *ComputeSearchAdmission) checkPersistence(ctx context.Context) {
	reader := self.engine.deps.AdmissionsPersistence
	now := self.engine.clock.Now()
	func() {
		self.persistenceLock.Lock()
		defer self.persistenceLock.Unlock()
		self.persistenceCheckedAt = now
	}()
	if reader == nil || self.engine.deps.AdmissionsRedis == nil {
		return
	}
	checkCtx, cancel := context.WithTimeout(ctx, self.settings.PersistenceCheckTimeout)
	defer cancel()
	persistence, err := reader(checkCtx)
	if err != nil || persistence == nil {
		return
	}
	on := !persistence.Off()
	func() {
		self.persistenceLock.Lock()
		defer self.persistenceLock.Unlock()
		if on {
			self.persistenceOn = true
			self.persistenceOff = false
		} else if !self.persistenceOn {
			self.persistenceOff = true
		}
	}()
	if on {
		self.engine.alarm("search_admissions_persistent", "the {cmpa} instance keeps snapshots or an append-only file: every web search is refused")
	}
}

// Whether {cmpa}'s instance is sure to keep nothing, asking again past PersistenceRecheckInterval while unsure.
func (self *ComputeSearchAdmission) admissionsSafe(ctx context.Context) bool {
	off, on, checkedAt := func() (bool, bool, time.Time) {
		self.persistenceLock.Lock()
		defer self.persistenceLock.Unlock()
		return self.persistenceOff, self.persistenceOn, self.persistenceCheckedAt
	}()
	if on {
		return false
	}
	if off {
		return true
	}
	if self.settings.PersistenceRecheckInterval <= self.engine.clock.Now().Sub(checkedAt) {
		self.checkPersistence(ctx)
		return func() bool {
			self.persistenceLock.Lock()
			defer self.persistenceLock.Unlock()
			return self.persistenceOff && !self.persistenceOn
		}()
	}
	return false
}

// A request read and held to the format.
type computeSearchParsed struct {
	requestId      sidecar.Id
	attempt        uint16
	agentId        *sidecar.Id
	amount         uint64
	catalogVersion uint64
	sealedPayee    []byte
}

// body held to the shared format (step 1).
func (self *ComputeSearchAdmission) parse(body *protocol.ComputeSearchAuthorizeRequest) (*computeSearchParsed, *ComputeRefusal) {
	format := self.settings.webSearch()
	invalid := &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonRequest}
	if len(body.GetRequestId()) != format.RequestIdByteCount || len(body.GetRequestId()) != len(sidecar.Id{}) {
		return nil, invalid
	}
	if body.GetAttempt() < 1 || uint32(format.AttemptMaxCount) < body.GetAttempt() {
		return nil, invalid
	}
	if len(body.GetSealedPayee()) == 0 || self.settings.SealedPayeeMaxByteCount < len(body.GetSealedPayee()) {
		return nil, invalid
	}
	if body.GetAmount() == 0 || body.GetCatalogVersion() == 0 || len(body.GetAsset()) != len(sidecar.WebSearchAddress{}) ||
		body.GetNetwork() == "" || format.NetworkMaxByteCount < len(body.GetNetwork()) {
		return nil, invalid
	}
	parsed := &computeSearchParsed{
		requestId:      sidecar.Id(body.GetRequestId()),
		attempt:        uint16(body.GetAttempt()),
		amount:         body.GetAmount(),
		catalogVersion: body.GetCatalogVersion(),
		sealedPayee:    body.GetSealedPayee(),
	}
	if agentId := body.GetAgentId(); len(agentId) != 0 {
		id, err := sidecar.IdFromBytes(agentId)
		if err != nil {
			return nil, invalid
		}
		parsed.agentId = &id
	}
	return parsed, nil
}

// The policy's search line and the catalog's price, held against parsed (steps 3 and 4).
func (self *ComputeSearchAdmission) checkOffer(request *ComputeRequest, body *protocol.ComputeSearchAuthorizeRequest, parsed *computeSearchParsed) *ComputeRefusal {
	var policy *sidecar.ComputePolicy
	if self.engine.deps.Policy != nil {
		policy = self.engine.deps.Policy()
	}
	if policy == nil || len(policy.Search) == 0 {
		return &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonPolicyLine}
	}
	line, err := sidecar.ParseWebSearchPolicyLine(policy.Search, self.settings.webSearch())
	if err != nil {
		return &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonPolicyLine}
	}
	if !bytes.Equal(body.GetAsset(), line.Asset[:]) {
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonAsset}
	}
	if body.GetNetwork() != line.Network {
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonNetwork}
	}
	if line.CeilingAmount < parsed.amount {
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonCeiling}
	}
	version, refusal := self.engine.computeCatalogAt(request.Ctx, parsed.catalogVersion)
	if refusal != nil {
		return refusal
	}
	price, err := computeSearchCatalogPrice(version.Answer)
	if err != nil {
		return &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonPolicyLine}
	}
	retail, err := computeSearchRetailNanoUsd(self.engine.brokerSettings().ledger(), self.settings, parsed.amount)
	if err != nil || price < retail {
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonPrice}
	}
	return nil
}

// What the caller's state allows (step 5): search_off naming the switch that is off, or the day cap and whether the
// policy names budgets of its own.
func (self *ComputeSearchAdmission) checkCaller(ctx context.Context, caller *ComputeCaller, now time.Time) (dayMax uint32, policyBudgets bool, refusal *ComputeRefusal) {
	acl := self.acl(caller)
	if acl == nil {
		return 0, false, NewComputeRefusal(ComputeRefusalUnavailable)
	}
	rows := acl.ComputeRows()
	if rows != nil && !rows.GetSearchEnabled() {
		return 0, false, &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonPolicy}
	}
	decision := acl.ComputeAllows(sidecar.AclSidecarSubject(caller.SidecarId),
		sidecar.AclComputeTarget{Resource: protocol.AclComputeResource_ACL_COMPUTE_RESOURCE_SEARCH},
		protocol.AclAction_ACL_ACTION_QUERY, now)
	if !decision.Allowed {
		return 0, false, &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonQuery}
	}
	accepted, err := self.ledger().ClauseAccepted(ctx, caller.NetworkId)
	if err != nil {
		return 0, false, NewComputeRefusal(ComputeRefusalUnavailable)
	}
	if !accepted {
		return 0, false, &ComputeRefusal{Code: ComputeRefusalSearchOff, Reason: ComputeSearchOffReasonClause}
	}
	return rows.GetSearchDayMax(), 0 < len(rows.GetBudgets()), nil
}

// A capacity refusal of the broker's own, with its retry.
func (self *ComputeSearchAdmission) capacity(reason string) *ComputeRefusal {
	return &ComputeRefusal{Code: ComputeRefusalCapacity, Reason: reason, RetryAfter: self.settings.CapacityRetryAfter}
}

// The signer's refusal as the device reads it: payee_refused as itself, its rates rate_limited with a retry, a
// stopped or stale signer capacity, a request the signer cannot take invalid, each naming the signer's word.
func (self *ComputeSearchAdmission) signerRefusal(refusal protocol.SearchSignRefusal, clock *computeSearchClock) *ComputeRefusal {
	retry := self.settings.SignerRefusalRetryAfter
	switch refusal {
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_PAYEE_REFUSED:
		return NewComputeRefusal(ComputeRefusalPayeeRefused)
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_RATE_LIMITED:
		return &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: "signer_rate", RetryAfter: retry}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSETTLED_CAP:
		return &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: "unsettled_cap", RetryAfter: retry}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_DAY_CAP:
		return &ComputeRefusal{Code: ComputeRefusalRateLimited, Reason: "day_cap", RetryAfter: clock.nextDay.Sub(clock.now)}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_NONCE_REUSED:
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: "nonce_reused"}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_CEILING:
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonCeiling}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_SEAL_INVALID:
		return &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: "seal"}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_LISTS_STALE:
		return &ComputeRefusal{Code: ComputeRefusalCapacity, Reason: "lists_stale", RetryAfter: self.settings.CapacityRetryAfter}
	case protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_STOPPED:
		return &ComputeRefusal{Code: ComputeRefusalCapacity, Reason: "stopped", RetryAfter: self.settings.CapacityRetryAfter}
	}
	return self.capacity(ComputeSearchCapacityReasonSigner)
}

// The sign request for ticket: its amount, its minute and the sealed payee, unread.
func computeSearchSignRequest(ticket []byte, record *computeSearchTicketRecord, sealedPayee []byte) *protocol.SearchSignRequest {
	return &protocol.SearchSignRequest{
		Ticket:      ticket,
		Amount:      record.amount,
		MinuteS:     record.minuteUnix,
		SealedPayee: sealedPayee,
	}
}

// A retry of an admission that stands (step 6): the signer asked again with its ticket, its amount and minute and the
// sealed payee the retry sent. Nothing is held, released or dropped: the first admission's authorization stands, and a
// payee the signer refuses now is kept as a sanctions record, suspending the network's search, as at a first request. A
// request naming another amount, another of the network's devices or another agent under the same request id and
// attempt is no retry of it, and is refused before the signer is asked.
func (self *ComputeSearchAdmission) retry(ctx context.Context, caller *ComputeCaller, claim *computeSearchClaim, parsed *computeSearchParsed, clock *computeSearchClock) (*protocol.ComputeSearchAuthorizeResponse, *ComputeRefusal) {
	switch claim.record.state {
	case computeSearchTicketAdmitted:
	case computeSearchTicketPending:
		return nil, self.capacity(ComputeSearchCapacityReasonInFlight)
	default:
		// reported: its authorization is final, and the signer holds its ticket no more
		return nil, self.capacity(ComputeSearchCapacityReasonInFlight)
	}
	sameAgent := claim.record.agentId == nil && parsed.agentId == nil ||
		claim.record.agentId != nil && parsed.agentId != nil && *claim.record.agentId == *parsed.agentId
	if claim.record.amount != parsed.amount || claim.record.sidecarId != caller.SidecarId || !sameAgent {
		return nil, &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonRetry}
	}
	if self.signer == nil {
		return nil, self.capacity(ComputeSearchCapacityReasonSigner)
	}
	response, err := self.signer.Sign(ctx, computeSearchSignRequest(claim.ticket, claim.record, parsed.sealedPayee))
	if err != nil {
		return nil, self.capacity(ComputeSearchCapacityReasonSigner)
	}
	if response.GetRefusal() != protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSPECIFIED || len(response.GetSealedAuthorization()) == 0 {
		if response.GetRefusal() == protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_PAYEE_REFUSED {
			// a payee the screen refuses on a retry is a sanctions record as on a first request, though the first
			// admission's authorization, signed to a payee the screen passed then, stands and keeps its hold
			if err := self.suspend.Record(ctx, caller.NetworkId, caller.SidecarId, model.ComputeSearchFlagReasonPayeeRefused, response.GetPayee(), nil); err != nil {
				self.engine.alarm("search_sanctions_record_write", "a web search sanctions record was not written")
			}
		}
		return nil, self.signerRefusal(response.GetRefusal(), clock)
	}
	return &protocol.ComputeSearchAuthorizeResponse{SealedAuthorization: response.GetSealedAuthorization()}, nil
}

// One admission (see the file header): the sealed authorization, or the refusal it answers.
func (self *ComputeSearchAdmission) authorize(request *ComputeRequest, body *protocol.ComputeSearchAuthorizeRequest) (*protocol.ComputeSearchAuthorizeResponse, *ComputeRefusal) {
	ctx := request.Ctx
	caller := request.Caller
	if caller == nil {
		return nil, NewComputeRefusal(ComputeRefusalUnavailable)
	}
	parsed, refusal := self.parse(body)
	if refusal != nil {
		return nil, refusal
	}
	if !self.admissionsSafe(ctx) {
		return nil, self.capacity(ComputeSearchCapacityReasonAdmissions)
	}
	if refusal := self.checkOffer(request, body, parsed); refusal != nil {
		return nil, refusal
	}
	now := self.engine.clock.Now()
	dayMax, policyBudgets, refusal := self.checkCaller(ctx, caller, now)
	if refusal != nil {
		return nil, refusal
	}
	ledgerSettings := self.engine.brokerSettings().ledger()
	retail, err := computeSearchRetailNanoUsd(ledgerSettings, self.settings, parsed.amount)
	if err != nil {
		return nil, &ComputeRefusal{Code: ComputeRefusalInvalid, Reason: ComputeSearchInvalidReasonPrice}
	}
	opKey, minute, err := controller.ComputeOpKeyForSearch(ledgerSettings, caller.NetworkId, parsed.requestId, int16(parsed.attempt), now)
	if err != nil {
		return nil, self.capacity(ComputeSearchCapacityReasonLedger)
	}
	clock := self.settings.clockAt(now)
	record := &computeSearchTicketRecord{
		networkId:  caller.NetworkId,
		sidecarId:  caller.SidecarId,
		agentId:    parsed.agentId,
		requestId:  parsed.requestId,
		attempt:    parsed.attempt,
		opKey:      opKey,
		hold:       retail,
		amount:     parsed.amount,
		minuteUnix: minute.Unix(),
	}

	// step 6: the claim, or the retry of the admission that holds it
	testHookBarrier(BarrierComputeSearchClaimBefore, sidecar.EvsKeyId(opKey))
	claim, err := self.tickets.claim(ctx, record)
	testHookBarrier(BarrierComputeSearchClaimAfter, sidecar.EvsKeyId(opKey))
	if err != nil {
		return nil, self.capacity(ComputeSearchCapacityReasonAdmissions)
	}
	if !claim.claimed {
		if claim.record == nil {
			return nil, self.capacity(ComputeSearchCapacityReasonInFlight)
		}
		return self.retry(ctx, caller, claim, parsed, clock)
	}
	ticket := claim.ticket
	dropClaim := func() {
		if err := self.tickets.drop(ctx, ticket, record); err != nil {
			// the claim lapses at its own ttl
			self.engine.alarm("search_claim_drop", "a refused web search's claim was not dropped")
		}
	}
	releaseHold := func() {
		if _, err := self.ledger().Release(ctx, caller.NetworkId, opKey); err != nil {
			// the row stays open, and compute_search_tickets releases it an hour past its window
			self.engine.alarm("search_release", "a refused web search's hold was not released")
		}
	}

	// step 7: the hold, its row committed first
	var memberId *sidecar.Id
	if caller.MemberId != (sidecar.Id{}) {
		member := caller.MemberId
		memberId = &member
	}
	testHookBarrier(BarrierComputeSearchHoldBefore, sidecar.EvsKeyId(opKey))
	hold, err := self.ledger().Hold(ctx, &ComputeSearchHoldRequest{
		NetworkId:          caller.NetworkId,
		RequestId:          parsed.requestId,
		Attempt:            int16(parsed.attempt),
		OpKey:              opKey,
		Minute:             minute,
		SidecarId:          caller.SidecarId,
		AgentId:            parsed.agentId,
		MemberId:           memberId,
		Tagged:             caller.Tagged(),
		PolicyNamesBudgets: policyBudgets,
		CatalogVersion:     int64(parsed.catalogVersion),
		HoldNanoUsd:        retail,
	})
	testHookBarrier(BarrierComputeSearchHoldAfter, sidecar.EvsKeyId(opKey))
	switch {
	case err != nil:
		dropClaim()
		return nil, self.capacity(ComputeSearchCapacityReasonLedger)
	case hold.Refusal != nil:
		dropClaim()
		return nil, hold.Refusal
	case !hold.Admitted:
		// a key whose operation finished before: nothing is held for it again
		dropClaim()
		return nil, self.capacity(ComputeSearchCapacityReasonLedger)
	}

	// step 8: the network's rate and day, then the payer's global rate
	limits, err := self.limits.take(ctx, caller.NetworkId, clock, dayMax)
	if err != nil || limits.refusal != nil {
		releaseHold()
		dropClaim()
		if err != nil {
			return nil, self.capacity(ComputeSearchCapacityReasonAdmissions)
		}
		return nil, limits.refusal
	}

	// step 9: admitted, the ticket to the signer
	admitted, err := self.tickets.admit(ctx, ticket, record, self.engine.clock.Now())
	if err != nil || !admitted {
		releaseHold()
		dropClaim()
		return nil, self.capacity(ComputeSearchCapacityReasonAdmissions)
	}
	dropTicket := func() {
		releaseHold()
		admittedRecord := record.in(computeSearchTicketAdmitted)
		if err := self.tickets.drop(ctx, ticket, admittedRecord); err != nil {
			self.engine.alarm("search_claim_drop", "a refused web search's ticket was not dropped")
		}
	}
	if self.signer == nil {
		dropTicket()
		return nil, self.capacity(ComputeSearchCapacityReasonSigner)
	}
	testHookBarrier(BarrierComputeSearchSignBefore, sidecar.EvsKeyId(opKey))
	response, err := self.signer.Sign(ctx, computeSearchSignRequest(ticket, record, parsed.sealedPayee))
	testHookBarrier(BarrierComputeSearchSignAfter, sidecar.EvsKeyId(opKey))
	if err != nil {
		dropTicket()
		return nil, self.capacity(ComputeSearchCapacityReasonSigner)
	}

	// step 10: the signer's answer, and with an authorization the request's outcomes
	if response.GetRefusal() == protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_UNSPECIFIED && 0 < len(response.GetSealedAuthorization()) {
		self.authorizations.Add(1, computeSearchAuthorizationAuthorized)
		if outcomes := body.GetOutcomes(); outcomes != nil {
			if computeSearchOutcomesTotal(outcomes) <= limits.dayCount {
				if err := self.outcomes.add(ctx, outcomes, now); err != nil {
					self.engine.alarm("search_outcomes", "a web search's outcome counts were not added")
				}
			} else {
				// more outcomes than the network's searches today: a modified client's counts, dropped whole
				self.engine.alarm("search_outcomes_dropped", "a web search's outcome counts passed the network's searches today")
			}
		}
		return &protocol.ComputeSearchAuthorizeResponse{SealedAuthorization: response.GetSealedAuthorization()}, nil
	}
	dropTicket()
	if response.GetRefusal() == protocol.SearchSignRefusal_SEARCH_SIGN_REFUSAL_PAYEE_REFUSED {
		if err := self.suspend.Record(ctx, caller.NetworkId, caller.SidecarId, model.ComputeSearchFlagReasonPayeeRefused, response.GetPayee(), nil); err != nil {
			self.engine.alarm("search_sanctions_record_write", "a web search sanctions record was not written")
		}
	}
	return nil, self.signerRefusal(response.GetRefusal(), clock)
}

// The route's handler (see the file header).
func computeSearchAuthorizeHandler(request *ComputeRequest) {
	admission := request.engine.search
	if admission == nil {
		request.Unavailable()
		return
	}
	body := &protocol.ComputeSearchAuthorizeRequest{}
	if !request.ReadMessage(body) {
		return
	}
	response, refusal := admission.authorize(request, body)
	if refusal != nil {
		request.Refuse(refusal)
		return
	}
	request.Reply(response)
}
