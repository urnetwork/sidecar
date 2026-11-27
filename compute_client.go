//go:build !ios_extension && !sidecar_http && !js

// The device's compute client (DESIGN-COMPUTE §3.2, §9; BAL-M12-17): one per Sidecar, a compute component on every leg
// but the VPN component and the page Worker (§15.4), which `ur compute` (through DaemonComputeMethods), the sdk's
// Compute() and the compute tools call. It holds no credential of its own: every call goes through the Sidecar's
// SidecarApi (compute_client_api.go), which keeps the token in this process (I-7), and nothing it answers holds a card,
// a token, a store receipt or a promotion code.
//
//	Balance       the network's balance as the caller may see it; a person's surface's, never an agent's (§7.5's
//	              compute_balance reads AccountState: the state alone)
//	Packs         §9.5's Stripe packs and §9.8's monthly plans, and the stores' compute.* products as
//	              ComputeStoreProducts registers them (BAL-M12-09), each store's with its product id
//	Checkout      a Stripe Checkout url for a pack or the monthly plan, with the auto-renew mode its payer turns on
//	Redeem        a promotion code; a Confirm method in the daemon (D-CORE-13)
//	AutoRenew     §9.8's modes, and SetAutoRenew's change of one, a Confirm method in the daemon
//	Charges, Statement, Spend
//	              the read routes' answers, every id named on the device (compute_labels.go)
//	Refund        a Stripe lot's unspent part (§9.12)
//	RaiseBudget   kind 21 (§16.3), filed through Sidecar.Authorize with BAL-M12-16's effect, which sends the approved
//	              raise to the broker's POST compute/v1/budget/raise; refused until that effect registers
//
// The client also raises compute_low (compute_events.go). Its loop reads the balance when asked: by a hint or a resync
// on the compute push topic, which a small SidecarComponent subscribes to in each client generation (QD-1238); by a
// hold the broker refused (HoldRefused, which INFER's and SRCH's remote paths call); and every BalancePollInterval
// while no generation holds the topic. Asks coalesce, at most one read a BalanceReadMinInterval, and a failed read
// retries with backoff a bounded number of times.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The compute component's name (compute_sidecar.go), and the client generations' part's (sidecar_component.go).
const (
	computeClientComponentName = "compute"
	computeHintComponentName   = "compute-balance"
)

var (
	// A surface of a client that has closed.
	ErrComputeClientClosed = errors.New("compute client closed")
	// No store products are registered: ComputeStoreProducts (BAL-M12-09) has not landed in this build, so the apps
	// sell no store product yet.
	ErrComputeStoreProductsUnavailable = errors.New("the stores' compute products are not in this build")
	// Kind 21's effect, which sends an approved raise to the broker, is not in this build (BAL-M12-16): nothing is
	// filed.
	ErrComputeBudgetRaiseUnavailable = errors.New("budget raises are not in this build")
	// A raise the client cannot file: no subject, both an agent and a grant, an unknown period, or an amount not
	// above the current one.
	ErrComputeBudgetRaiseInvalid = errors.New("budget raise refused")
)

// Registers the client, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(computeClientComponentName, newSidecarComputeClient, func(client *ComputeClient) { client.Close() })
}

// What a ComputeClient is built on: the parts of its Sidecar it uses, which a test may fake.
type computeClientHost interface {
	// The Sidecar's api client, holding its token.
	computeApi() *SidecarApi
	// Raises one event to the host's listeners.
	emitEvent(event SidecarEvent)
	// This sidecar's ids, nil before it holds an identity.
	currentIdentity() *SidecarIdentity
	// §5.4's gate.
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
	// Seals a version-5 action's detail (approval_compute_detail.go).
	SealActionDetail5(ctx context.Context, clear *protocol.CanonicalAction, detail *protocol.CanonicalActionDetail5) (*StoredCanonicalAction, error)
}

// The Sidecar's api client.
func (self *Sidecar) computeApi() *SidecarApi {
	return self.sidecarApi
}

// What a ComputeClient is made with.
type ComputeClientArgs struct {
	Host     computeClientHost
	Settings *ComputeClientSettings
	// What the labeler holds catalog ids to (§6.3's grammar); nil reads the defaults.
	InferSettings *InferSettings
	// What names the views' ids; nil names none, every id unknown.
	Sources *ComputeLabelSources
	// Nil reads real time.
	Clock Clock
	Log   Logger
	// No loop: a test drives each read itself.
	manual bool
}

// A Sidecar's compute client. Construct with NewComputeClient.
type ComputeClient struct {
	ctx           context.Context
	cancel        context.CancelFunc
	host          computeClientHost
	settings      *ComputeClientSettings
	inferSettings *InferSettings
	sources       *ComputeLabelSources
	clock         Clock
	log           Logger
	low           computeLowTracker
	lowListeners  *CallbackList[ComputeLowListener]
	// A read asked for by a hint, a resync or a refused hold: one waits at most, so a burst asks once.
	asks chan struct{}
	// Closed when the loop has returned; closed at once for a manual client.
	done chan struct{}

	stateLock sync.Mutex
	// How many client generations hold the compute push topic now.
	pushHolders int
	closed      bool
}

// The client on sidecar: its settings, its sources and its clock, and its part of each client generation, which
// holds the compute push topic.
func newSidecarComputeClient(sidecar *Sidecar) (*ComputeClient, error) {
	client, err := NewComputeClient(&ComputeClientArgs{
		Host:          sidecar,
		Settings:      sidecar.settings.Compute,
		InferSettings: sidecar.settings.Infer,
		Sources:       newComputeLabelSources(sidecar, computeLabelSourcesRegistrations),
		Clock:         sidecar.clock,
		Log:           sidecar.log,
	})
	if err != nil {
		return nil, err
	}
	// listed as AddComponent lists one, but without its wake: the client constructs before the run loop starts
	// (compute_sidecar.go), whose first pass attaches every listed component, so a wake would only add a pass. The leg
	// closes it with the rest as the Sidecar ends, after this client.
	leg, ok := sidecar.leg.(*sidecarConnectLeg)
	if !ok {
		// no client generations, so no push: the poll stands in
		return client, nil
	}
	if err := leg.addComponent(&computeHintComponent{client: client}); err != nil && sidecar.log.V(1).Enabled() {
		sidecar.log.Infof("[compute]the balance hint is not subscribed: %s", err)
	}
	return client, nil
}

// This Sidecar's compute client, or why it has none.
func (self *Sidecar) ComputeClient() (*ComputeClient, error) {
	return sidecarComputeComponent[ComputeClient](self, computeClientComponentName)
}

// A client over args, its loop started unless args is a test's manual one.
func NewComputeClient(args *ComputeClientArgs) (*ComputeClient, error) {
	if args == nil || args.Host == nil {
		return nil, fmt.Errorf("%w: a compute client needs its host", errInvalidSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultComputeClientSettings()
	}
	inferSettings := args.InferSettings
	if inferSettings == nil {
		inferSettings = DefaultInferSettings()
	}
	sources := args.Sources
	if sources == nil {
		sources = &ComputeLabelSources{}
	}
	clock := args.Clock
	if clock == nil {
		clock = RealClock{}
	}
	log := loggerOrDefault(args.Log)
	ctx, cancel := context.WithCancel(context.Background())
	client := &ComputeClient{
		ctx:           ctx,
		cancel:        cancel,
		host:          args.Host,
		settings:      settings,
		inferSettings: inferSettings,
		sources:       sources,
		clock:         clock,
		log:           log,
		lowListeners:  NewCallbackList[ComputeLowListener](),
		asks:          make(chan struct{}, 1),
		done:          make(chan struct{}),
	}
	if args.manual {
		close(client.done)
	} else {
		go client.run()
	}
	return client, nil
}

// Ends the loop and waits for it. Later calls answer ErrComputeClientClosed. The client generations' part ends with the
// Sidecar's components, and a hint it takes after this asks nothing of the ended loop.
func (self *ComputeClient) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
	}()
	self.cancel()
	<-self.done
}

// Whether Close has run.
func (self *ComputeClient) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// The api, or ErrComputeClientClosed.
func (self *ComputeClient) api() (*SidecarApi, error) {
	if self.isClosed() {
		return nil, ErrComputeClientClosed
	}
	api := self.host.computeApi()
	if api == nil {
		return nil, fmt.Errorf("%w: no api client", ErrComputeClientClosed)
	}
	return api, nil
}

// ctx bounded by RequestTimeout, where it is positive.
func (self *ComputeClient) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if self.settings.RequestTimeout <= 0 {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, self.settings.RequestTimeout)
}

// The network's balance as the caller may see it (GET /compute/balance), which also moves compute_low. A person's
// surface's: an agent-facing path reads AccountState, never this (§7.5).
func (self *ComputeClient) Balance(ctx context.Context) (*ComputeBalance, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	balance, err := api.ComputeBalance(ctx)
	if err != nil {
		return nil, err
	}
	self.observe(balance)
	return balance, nil
}

// The network's compute state alone (§9.9), what §7.5's compute_balance says of the network beside the agent's budget:
// never the balance, the holds or auto-renew, which only §9.10's roles see.
func (self *ComputeClient) AccountState(ctx context.Context) (ComputeAccountState, error) {
	balance, err := self.Balance(ctx)
	if err != nil {
		return "", err
	}
	return balance.State, nil
}

// One product a market sells for compute credit (§9.5): Stripe's packs and monthly plans, and the stores' compute.*
// products, each with its product id.
type ComputePack struct {
	Market ComputeMarket `json:"market"`
	// A subscription granting Credits each month (§9.8's monthly plan); else a pack bought once.
	Monthly bool  `json:"monthly"`
	Credits int64 `json:"credits"`
	// The store's product id; empty for Stripe's, which Checkout sells by credits.
	ProductId string `json:"product_id,omitempty"`
}

// The store products' source, which ComputeStoreProducts (BAL-M12-09) registers; nil until then.
var computeStoreProductsSource func(market ComputeMarket) []*ComputePack

// Registers the stores' compute.* products from an init function in their own file (BAL-M12-09). A second
// registration, or a nil one, is a build error, which panics.
func registerComputeStoreProducts(products func(market ComputeMarket) []*ComputePack) {
	if products == nil || computeStoreProductsSource != nil {
		panic("compute store products registered twice or as nil")
	}
	computeStoreProductsSource = products
}

// What market sells (§9.5, §9.8): Stripe's packs and monthly plans from the settings; a store's products as
// ComputeStoreProducts names them, ErrComputeStoreProductsUnavailable until it registers. Whether the caller may buy,
// and whether sales are open, is Balance's to say (Q-BAL-13); a surface offers these only where both hold.
func (self *ComputeClient) Packs(market ComputeMarket) ([]*ComputePack, error) {
	switch market {
	case ComputeMarketStripe:
		packs := []*ComputePack{}
		for _, credits := range self.settings.StripePackCredits {
			packs = append(packs, &ComputePack{Market: market, Credits: credits})
		}
		for _, credits := range self.settings.MonthlyPlanCredits {
			packs = append(packs, &ComputePack{Market: market, Monthly: true, Credits: credits})
		}
		return packs, nil
	case ComputeMarketAppStore, ComputeMarketGooglePlay:
		if computeStoreProductsSource == nil {
			return nil, ErrComputeStoreProductsUnavailable
		}
		packs := []*ComputePack{}
		for _, pack := range computeStoreProductsSource(market) {
			if pack != nil && pack.Market == market {
				copied := *pack
				packs = append(packs, &copied)
			}
		}
		return packs, nil
	}
	return nil, fmt.Errorf("%w: not a market that sells compute credit", ErrSidecarApiArgs)
}

// A Stripe Checkout url for args (§9.5), which the surface opens in the person's browser; the person pays there.
func (self *ComputeClient) Checkout(ctx context.Context, args *ComputeCheckoutArgs) (*ComputeCheckout, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	return api.ComputeCheckout(ctx, args)
}

// Redeems a promotion code for the network (§9.11): the person's own act, never an agent's, which the daemon takes
// only confirmed (D-CORE-13). The balance is read again after a redemption.
func (self *ComputeClient) Redeem(ctx context.Context, code string) (*ComputeRedemption, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	redemption, err := api.ComputePromoRedeem(ctx, code)
	if err != nil {
		return nil, err
	}
	self.ask()
	return redemption, nil
}

// §9.8's two modes as they stand.
func (self *ComputeClient) AutoRenew(ctx context.Context) (*ComputeAutoRenew, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	return api.ComputeAutoRenew(ctx)
}

// Changes one mode (§9.8): the person's own act, which the daemon takes only confirmed (D-CORE-13). A mode turned on
// names a card the person turning it on saved for it, else api answers card_required and the person checks out a
// pack with the mode on.
func (self *ComputeClient) SetAutoRenew(ctx context.Context, change *ComputeAutoRenewChange) (*ComputeAutoRenew, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	return api.ComputeSetAutoRenew(ctx, change)
}

// A labeler over one read of the client's sources.
func (self *ComputeClient) labeler(ctx context.Context) *ComputeLabeler {
	return NewComputeLabeler(ctx, self.sources, self.settings, self.inferSettings, self.log)
}

// One page of the charges the caller may see, from cursor ("" for the first), each id named on the device.
func (self *ComputeClient) Charges(ctx context.Context, cursor string) (*ComputeChargesView, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	charges, err := api.ComputeCharges(ctx, cursor)
	if err != nil {
		return nil, err
	}
	return self.labeler(ctx).ChargesView(charges), nil
}

// A month's statement (YYYY-MM, UTC), each id named on the device (§9.13).
func (self *ComputeClient) Statement(ctx context.Context, month string) (*ComputeStatementView, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	statement, err := api.ComputeStatement(ctx, month)
	if err != nil {
		return nil, err
	}
	return self.labeler(ctx).StatementView(statement), nil
}

// §9.13's spend view by by, its ids named on the device: a person's surface's, and `compute_spend`'s on the person's
// consented device, which BAL-M12-20's tool checks before it calls.
func (self *ComputeClient) Spend(ctx context.Context, by ComputeSpendBy) (*ComputeSpendView, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	spend, err := api.ComputeSpend(ctx, by)
	if err != nil {
		return nil, err
	}
	return self.labeler(ctx).SpendView(spend), nil
}

// Refunds a Stripe lot's unspent part (§9.12): an Owner's or a Billing admin's act, which the daemon takes only
// confirmed. The balance is read again after it.
func (self *ComputeClient) Refund(ctx context.Context, lotId Id) (*ComputeRefund, error) {
	api, err := self.api()
	if err != nil {
		return nil, err
	}
	ctx, cancel := self.bounded(ctx)
	defer cancel()
	refund, err := api.ComputeRefund(ctx, lotId)
	if err != nil {
		return nil, err
	}
	self.ask()
	return refund, nil
}

// §16.3's kind 21 periods, by the words the surfaces take.
var computeBudgetPeriods = map[string]uint32{
	"day":   approvalComputeBudgetPeriodDay,
	"month": approvalComputeBudgetPeriodMonth,
	"run":   approvalComputeBudgetPeriodRun,
}

// A raise of one budget past its default (§16.3's kind 21, §16.4): an agent's, or a gateway grant's, for a day, a
// month or a run.
type ComputeBudgetRaiseArgs struct {
	// The agent whose budget passes; nil where GrantId names a gateway grant's instead.
	AgentId *Id `json:"agent_id,omitempty"`
	// A gateway grant the raise passes (§8.6), sealed in the action's detail.
	GrantId *Id `json:"grant_id,omitempty"`
	// day, month or run.
	Period string `json:"period"`
	// The new amount and the current one, in nano-USD.
	AmountNanoUsd  int64 `json:"amount_nano_usd"`
	CurrentNanoUsd int64 `json:"current_nano_usd"`
	// The asker's words, shown to the approver as untrusted text (D-MCP-17).
	Summary string `json:"summary,omitempty"`
	// The asking run and agent, which the decision binds; nil for a person's own ask.
	RunId      *Id `json:"run_id,omitempty"`
	RunAgentId *Id `json:"run_agent_id,omitempty"`
}

// What a filed raise came to: done once the approved raise reached the broker, or pending on the approval a person
// decides.
type ComputeBudgetRaiseResult struct {
	// done or approval_pending.
	Outcome    string `json:"outcome"`
	ApprovalId *Id    `json:"approval_id,omitempty"`
}

// A filed raise's outcomes.
const (
	ComputeBudgetRaiseDone    = "done"
	ComputeBudgetRaisePending = "approval_pending"
)

// Kind 21's effect for one stored action, BAL-M12-16's ComputeBudgetRaiseEffect, which sends the approved raise to
// POST compute/v1/budget/raise under Idempotency-Key: <effect_key>; nil until it registers.
var computeBudgetRaiseEffectSource func(client *ComputeClient, action *StoredCanonicalAction) SidecarEffect

// Registers kind 21's effect from an init function in its own file (BAL-M12-16). A second registration, or a nil
// one, is a build error, which panics.
func registerComputeBudgetRaiseEffect(effect func(client *ComputeClient, action *StoredCanonicalAction) SidecarEffect) {
	if effect == nil || computeBudgetRaiseEffectSource != nil {
		panic("compute budget raise effect registered twice or as nil")
	}
	computeBudgetRaiseEffectSource = effect
}

// Files kind 21 (§16.3) for args through §5.4's gate: a version-5 compute_budget_raise action, its BudgetFields in
// field 43 and its sealed detail naming a gateway grant where args does, which a person approves on an
// approval-capable device, never an agent's own (§27.4: the classifier never decides kind 21). Answers
// approval_pending with the approval's id while the person decides, and done once the approved raise reached the
// broker; a retry after the decision spends it. Refused before anything is filed while BAL-M12-16's effect is not in
// this build (ErrComputeBudgetRaiseUnavailable).
func (self *ComputeClient) RaiseBudget(ctx context.Context, args *ComputeBudgetRaiseArgs) (*ComputeBudgetRaiseResult, error) {
	if self.isClosed() {
		return nil, ErrComputeClientClosed
	}
	if args == nil {
		return nil, fmt.Errorf("%w: no raise", ErrComputeBudgetRaiseInvalid)
	}
	period, ok := computeBudgetPeriods[args.Period]
	if !ok {
		return nil, fmt.Errorf("%w: a period is day, month or run", ErrComputeBudgetRaiseInvalid)
	}
	if (args.AgentId == nil) == (args.GrantId == nil) {
		return nil, fmt.Errorf("%w: a raise names an agent or a gateway grant, one of them", ErrComputeBudgetRaiseInvalid)
	}
	if args.CurrentNanoUsd < 0 || args.AmountNanoUsd <= args.CurrentNanoUsd {
		return nil, fmt.Errorf("%w: the new amount is above the current one", ErrComputeBudgetRaiseInvalid)
	}
	effectSource := computeBudgetRaiseEffectSource
	if effectSource == nil {
		return nil, ErrComputeBudgetRaiseUnavailable
	}
	budget := &protocol.BudgetFields{
		Period:  period,
		Amount:  uint64(args.AmountNanoUsd),
		Current: uint64(args.CurrentNanoUsd),
	}
	detail := &protocol.CanonicalActionDetail5{}
	if args.AgentId != nil {
		budget.AgentId = args.AgentId.Bytes()
	} else {
		detail.GrantId = args.GrantId.Bytes()
	}
	clear := &protocol.CanonicalAction{
		Kind:    uint32(SidecarActionComputeBudgetRaise),
		Version: canonicalActionVersionCompute,
		Budget:  budget,
	}
	stored, err := self.host.SealActionDetail5(ctx, clear, detail)
	if err != nil {
		return nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskNormal, args.RunId, args.RunAgentId)
	if err != nil {
		return nil, err
	}
	action.Summary = args.Summary
	action.Effect = effectSource(self, stored)
	if action.Effect == nil {
		return nil, ErrComputeBudgetRaiseUnavailable
	}
	err = self.host.Authorize(ctx, action, nil)
	var pending *ApprovalPendingError
	if errors.As(err, &pending) {
		approvalId := pending.ApprovalId
		return &ComputeBudgetRaiseResult{Outcome: ComputeBudgetRaisePending, ApprovalId: &approvalId}, nil
	}
	if err != nil {
		return nil, err
	}
	return &ComputeBudgetRaiseResult{Outcome: ComputeBudgetRaiseDone}, nil
}

// A hold the broker refused for the balance (insufficient_quota's balance, 402 COMPUTE_BALANCE): asks a read of the
// balance, which raises compute_low where the state moved. INFER's and SRCH's remote paths call it; it never blocks.
func (self *ComputeClient) HoldRefused() {
	self.ask()
}

// A hint or a resync on the compute push topic: asks a read of the balance. Never blocks.
func (self *ComputeClient) Refresh() {
	self.ask()
}

// Calls listener with each compute_low notice, in full; the answer removes it.
func (self *ComputeClient) AddLowListener(listener ComputeLowListener) func() {
	callbackId := self.lowListeners.Add(listener)
	var once sync.Once
	return func() {
		once.Do(func() {
			self.lowListeners.Remove(callbackId)
		})
	}
}

// The newest compute_low notice, refreshed by every later read at its state; nil before any.
func (self *ComputeClient) LowNotice() *ComputeLowNotice {
	return self.low.latest()
}

// Asks the loop for a read, without waiting: a read asked already covers this ask.
func (self *ComputeClient) ask() {
	select {
	case self.asks <- struct{}{}:
	default:
	}
}

// Moves compute_low by a read of the balance: the state applied in version order, its notice raised once a change,
// to the host's listeners as compute_low and to the client's in full.
func (self *ComputeClient) observe(balance *ComputeBalance) {
	testHookBarrier("compute_client.low.before", "")
	notice := self.low.apply(balance, self.clock.Now())
	testHookBarrier("compute_client.low.after", "")
	if notice == nil {
		return
	}
	self.host.emitEvent(computeLowEvent(notice))
	for _, listener := range self.lowListeners.Get() {
		listener(notice.clone())
	}
}

// One read for the loop, bounded by RequestTimeout: nothing while this sidecar holds no identity, since api would
// refuse it unsent.
func (self *ComputeClient) readBalance(ctx context.Context) error {
	if self.host.currentIdentity() == nil {
		return nil
	}
	_, err := self.Balance(ctx)
	return err
}

// One client generation holds the compute push topic (+1), or let it go (-1).
func (self *ComputeClient) holdPush(delta int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.pushHolders += delta
}

// Whether a client generation holds the compute push topic now, so its hints stand in for the poll.
func (self *ComputeClient) pushHeld() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return 0 < self.pushHolders
}

// The poll's next tick, or nil, which never fires, where the poll is off.
func (self *ComputeClient) pollAfter() <-chan time.Time {
	if self.settings.BalancePollInterval <= 0 {
		return nil
	}
	return self.clock.After(self.settings.BalancePollInterval)
}

// The wait before retry number attempt, from 0: BalanceRetryFirstInterval doubled each time up to
// BalanceRetryMaxInterval.
func (self *ComputeClient) retryWait(attempt int) time.Duration {
	wait := self.settings.BalanceRetryFirstInterval
	for i := 0; i < attempt && wait < self.settings.BalanceRetryMaxInterval; i += 1 {
		wait *= 2
	}
	return min(wait, self.settings.BalanceRetryMaxInterval)
}

// The loop: waits for an ask, a retry or the poll, keeps BalanceReadMinInterval between reads, takes every ask that
// came meanwhile into the read it makes, and retries a failed one with backoff, until Close.
func (self *ComputeClient) run() {
	defer close(self.done)
	poll := self.pollAfter()
	var retry <-chan time.Time
	retryCount := 0
	var lastRead time.Time
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-self.asks:
		case <-retry:
		case <-poll:
			poll = self.pollAfter()
			if self.pushHeld() {
				continue
			}
		}
		retry = nil
		if !lastRead.IsZero() {
			// the next read may go BalanceReadMinInterval after the last, a wait for that time itself (QD-1425)
			if readAt := lastRead.Add(self.settings.BalanceReadMinInterval); self.clock.Now().Before(readAt) {
				select {
				case <-self.ctx.Done():
					return
				case <-ClockAfterAt(self.clock, readAt):
				}
			}
		}
		// every ask before this read is answered by it
		select {
		case <-self.asks:
		default:
		}
		lastRead = self.clock.Now()
		err := self.readBalance(self.ctx)
		if err == nil || self.ctx.Err() != nil {
			retryCount = 0
			continue
		}
		if self.log.V(1).Enabled() {
			self.log.Infof("[compute]the balance did not read: %s", err)
		}
		if retryCount < self.settings.BalanceRetryMaxCount {
			retry = self.clock.After(self.retryWait(retryCount))
			retryCount += 1
		} else {
			retryCount = 0
		}
	}
}

// The client's part of each client generation (§5.4's components): it subscribes to the compute push topic, whose
// hints and resyncs ask a read (QD-1238), and holds it while the generation runs, so the poll stops meanwhile.
type computeHintComponent struct {
	client *ComputeClient
}

// The component's name, a seal class of its own: it keeps nothing in it.
func (self *computeHintComponent) Name() string {
	return computeHintComponentName
}

// Subscribes to the compute topic for the generation's life. A generation without push holds nothing, and the poll
// stands in.
func (self *computeHintComponent) Attach(env *SidecarEnv) error {
	if env.Subprotocol == nil {
		return nil
	}
	remove, err := env.Subprotocol.Subscribe(PushTopicCompute, func(notice PushNotice) {
		self.client.Refresh()
	})
	if err != nil {
		return nil
	}
	self.client.holdPush(1)
	context.AfterFunc(env.Ctx, func() {
		remove()
		self.client.holdPush(-1)
	})
	return nil
}

// Nothing: the client closes itself.
func (self *computeHintComponent) Close() {}
