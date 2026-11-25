// The ledger's identifiers (DESIGN-COMPUTE §9.4, §9.6, §9.9; BAL-M12-01): what compute_charge.kind, compute_lot.kind,
// compute_lot.market, compute_account.state and compute_op.state hold, as smallints, and ComputeUnits, a charge's typed
// units as compute_charge.units holds them in JSON and the rollups in typed columns.
//
// The device's compute client keeps its own view of the same numbers (the root's compute_client_api.go, which the
// js and extension legs this package also builds on do not link), and the account state there is §9.9's word, not
// its number: compute_kinds_client_test.go holds the two to one table.
//
// These are identifiers, so they stay constants (QD-702).

package model

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// What a charge is for (§9.6).
type ComputeChargeKind int16

const (
	// One remote inference request: input, output and cached-input tokens at the catalog model's prices.
	ComputeChargeKindInference ComputeChargeKind = 1
	// One enclave's running time, per second, written every 10 minutes and at stop.
	ComputeChargeKindEnclaveRun ComputeChargeKind = 2
	// Reserved for persistent enclave volumes, which are Later (§11.9): declared and never written.
	ComputeChargeKindEnclaveDisk ComputeChargeKind = 3
	// Bytes an enclave sends through its provider's own network under default egress off (§11.8), hourly.
	ComputeChargeKindEnclaveHostEgress ComputeChargeKind = 4
	// A support credit or debit naming no charge; a refund is a charge of the kind it returns.
	ComputeChargeKindAdjustment ComputeChargeKind = 5
	// One web search (§21).
	ComputeChargeKindWebSearch ComputeChargeKind = 6
)

// Every kind §9.6 names, in its order.
var computeChargeKinds = []ComputeChargeKind{
	ComputeChargeKindInference,
	ComputeChargeKindEnclaveRun,
	ComputeChargeKindEnclaveDisk,
	ComputeChargeKindEnclaveHostEgress,
	ComputeChargeKindAdjustment,
	ComputeChargeKindWebSearch,
}

// Every kind §9.6 names.
func ComputeChargeKinds() []ComputeChargeKind {
	return append([]ComputeChargeKind{}, computeChargeKinds...)
}

// §9.6's name, or kind<n> for a number it does not name.
func (self ComputeChargeKind) String() string {
	switch self {
	case ComputeChargeKindInference:
		return "inference"
	case ComputeChargeKindEnclaveRun:
		return "enclave_run"
	case ComputeChargeKindEnclaveDisk:
		return "enclave_disk"
	case ComputeChargeKindEnclaveHostEgress:
		return "enclave_host_egress"
	case ComputeChargeKindAdjustment:
		return "adjustment"
	case ComputeChargeKindWebSearch:
		return "web_search"
	}
	return "kind" + strconv.Itoa(int(self))
}

// Whether §9.6 names the kind.
func (self ComputeChargeKind) Valid() bool {
	for _, kind := range computeChargeKinds {
		if kind == self {
			return true
		}
	}
	return false
}

// Whether a charge may carry the kind at launch: every kind but enclave_disk, which is reserved (§11.9).
func (self ComputeChargeKind) Written() bool {
	return self.Valid() && self != ComputeChargeKindEnclaveDisk
}

// Whether the kind is an enclave's: its holds reach into the floor and budgets never bound it (§9.7, §16.4).
func (self ComputeChargeKind) Enclave() bool {
	return self == ComputeChargeKindEnclaveRun || self == ComputeChargeKindEnclaveDisk || self == ComputeChargeKindEnclaveHostEgress
}

// What a lot is (§9.4).
type ComputeLotKind int16

const (
	// Credits bought once: a Stripe pack or a store consumable.
	ComputeLotKindPurchase ComputeLotKind = 1
	// A subscription period's credits: the Stripe monthly plan or a store subscription.
	ComputeLotKindSubscription ComputeLotKind = 2
	// A promotion code's credit, which lapses (§9.11).
	ComputeLotKindPromotion ComputeLotKind = 3
	// An operator's support credit.
	ComputeLotKindAdjustment ComputeLotKind = 4
)

// §9.4's name, or lot<n> for a number it does not name.
func (self ComputeLotKind) String() string {
	switch self {
	case ComputeLotKindPurchase:
		return "purchase"
	case ComputeLotKindSubscription:
		return "subscription"
	case ComputeLotKindPromotion:
		return "promotion"
	case ComputeLotKindAdjustment:
		return "adjustment"
	}
	return "lot" + strconv.Itoa(int(self))
}

// Whether §9.4 names the kind.
func (self ComputeLotKind) Valid() bool {
	return ComputeLotKindPurchase <= self && self <= ComputeLotKindAdjustment
}

// Where a lot came from (§9.4, §9.11).
type ComputeMarket int16

const (
	ComputeMarketStripe     ComputeMarket = 1
	ComputeMarketAppStore   ComputeMarket = 2
	ComputeMarketGooglePlay ComputeMarket = 3
	// An operator's adjustment.
	ComputeMarketManual ComputeMarket = 4
	// A promotion code's redemption, whose market_ref is the redemption's id.
	ComputeMarketPromotion ComputeMarket = 5
)

// §9.4's word, or market<n> for a number it does not name.
func (self ComputeMarket) String() string {
	switch self {
	case ComputeMarketStripe:
		return "stripe"
	case ComputeMarketAppStore:
		return "app_store"
	case ComputeMarketGooglePlay:
		return "google_play"
	case ComputeMarketManual:
		return "manual"
	case ComputeMarketPromotion:
		return "promotion"
	}
	return "market" + strconv.Itoa(int(self))
}

// Whether §9.4 names the market.
func (self ComputeMarket) Valid() bool {
	return ComputeMarketStripe <= self && self <= ComputeMarketPromotion
}

// A network's compute account's state (§9.9), as compute_account.state holds it.
type ComputeAccountState int16

const (
	// The balance holds at least 24 hours of the network's burn.
	ComputeAccountStateActive ComputeAccountState = 1
	// Under 24 hours of burn, or under the threshold T.
	ComputeAccountStateLow ComputeAccountState = 2
	// At or under zero: new remote inference and searches refused, running enclaves running down to the floor.
	ComputeAccountStateGrace ComputeAccountState = 3
	// At or under minus the floor, or grace past its hour: enclaves stopped, remote inference refused.
	ComputeAccountStateSuspended ComputeAccountState = 4
	// The network was deleted.
	ComputeAccountStateClosed ComputeAccountState = 5
)

// §9.9's word, the one the balance route and compute_low carry, or state<n> for a number it does not name.
func (self ComputeAccountState) String() string {
	switch self {
	case ComputeAccountStateActive:
		return "active"
	case ComputeAccountStateLow:
		return "low"
	case ComputeAccountStateGrace:
		return "grace"
	case ComputeAccountStateSuspended:
		return "suspended"
	case ComputeAccountStateClosed:
		return "closed"
	}
	return "state" + strconv.Itoa(int(self))
}

// Whether §9.9 names the state.
func (self ComputeAccountState) Valid() bool {
	return ComputeAccountStateActive <= self && self <= ComputeAccountStateClosed
}

// Whether a new remote call or search may hold in this state: active or low (§9.9).
func (self ComputeAccountState) CanPay() bool {
	return self == ComputeAccountStateActive || self == ComputeAccountStateLow
}

// The state §9.9's word names.
func ParseComputeAccountState(word string) (ComputeAccountState, error) {
	for state := ComputeAccountStateActive; state <= ComputeAccountStateClosed; state += 1 {
		if state.String() == word {
			return state, nil
		}
	}
	return 0, fmt.Errorf("compute: %q is no account state", word)
}

// A billable operation's state (§9.7): each move is conditional on the one before, open to settled or void, settled
// to applied.
type ComputeOpState int16

const (
	// Admitted, its hold taken: liable until settled or released.
	ComputeOpStateOpen ComputeOpState = 1
	// Its outcome committed: units, amount, cost, absorbed and times.
	ComputeOpStateSettled ComputeOpState = 2
	// Booked by compute_settle: its charge, draws and rollups committed.
	ComputeOpStateApplied ComputeOpState = 3
	// Released at no charge.
	ComputeOpStateVoid ComputeOpState = 4
)

// The state's word, or op<n> for a number §9.7 does not name.
func (self ComputeOpState) String() string {
	switch self {
	case ComputeOpStateOpen:
		return "open"
	case ComputeOpStateSettled:
		return "settled"
	case ComputeOpStateApplied:
		return "applied"
	case ComputeOpStateVoid:
		return "void"
	}
	return "op" + strconv.Itoa(int(self))
}

// Whether §9.7 names the state.
func (self ComputeOpState) Valid() bool {
	return ComputeOpStateOpen <= self && self <= ComputeOpStateVoid
}

// Whether a row in this state may move to next: open to settled or void, settled to applied, and nothing else.
func (self ComputeOpState) MayMoveTo(next ComputeOpState) bool {
	switch self {
	case ComputeOpStateOpen:
		return next == ComputeOpStateSettled || next == ComputeOpStateVoid
	case ComputeOpStateSettled:
		return next == ComputeOpStateApplied
	}
	return false
}

// A charge's units (§9.4): counts alone, each a typed column of the rollups, so an upsert adds them exactly. Inference
// fills the tokens, an enclave's running time its seconds, host egress its bytes and a search its searches; an
// adjustment has none.
type ComputeUnits struct {
	// Input tokens, reasoning excluded.
	InputTokens int64 `json:"input_tokens"`
	// Output tokens, reasoning included.
	OutputTokens int64 `json:"output_tokens"`
	// Cached-input tokens.
	CachedTokens int64 `json:"cached_tokens"`
	// Seconds in running.
	Seconds int64 `json:"seconds"`
	// Bytes out through the provider's own network.
	EgressBytes int64 `json:"egress_bytes"`
	// One per search authorization Base shows used.
	Searches int64 `json:"searches"`
}

// The sum of two units.
func (self ComputeUnits) Add(other ComputeUnits) ComputeUnits {
	return ComputeUnits{
		InputTokens:  self.InputTokens + other.InputTokens,
		OutputTokens: self.OutputTokens + other.OutputTokens,
		CachedTokens: self.CachedTokens + other.CachedTokens,
		Seconds:      self.Seconds + other.Seconds,
		EgressBytes:  self.EgressBytes + other.EgressBytes,
		Searches:     self.Searches + other.Searches,
	}
}

// Whether every count is zero or more: a refund changes no units (§9.13), so no row ever holds a negative one.
func (self ComputeUnits) Valid() bool {
	return 0 <= self.InputTokens && 0 <= self.OutputTokens && 0 <= self.CachedTokens &&
		0 <= self.Seconds && 0 <= self.EgressBytes && 0 <= self.Searches
}

// The units as compute_charge.units holds them.
func (self ComputeUnits) Json() ([]byte, error) {
	return json.Marshal(self)
}

// Units from compute_charge.units: every field a count, an unknown field or a negative count refused, so a row that
// is not §9.4's never reads as one.
func ParseComputeUnits(data []byte) (ComputeUnits, error) {
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &fields); err != nil {
		return ComputeUnits{}, fmt.Errorf("compute units: %w", err)
	}
	units := ComputeUnits{}
	targets := map[string]*int64{
		"input_tokens":  &units.InputTokens,
		"output_tokens": &units.OutputTokens,
		"cached_tokens": &units.CachedTokens,
		"seconds":       &units.Seconds,
		"egress_bytes":  &units.EgressBytes,
		"searches":      &units.Searches,
	}
	for name, raw := range fields {
		target, ok := targets[name]
		if !ok {
			return ComputeUnits{}, fmt.Errorf("compute units: no field %q", name)
		}
		if err := json.Unmarshal(raw, target); err != nil {
			return ComputeUnits{}, fmt.Errorf("compute units: %s: %w", name, err)
		}
	}
	if !units.Valid() {
		return ComputeUnits{}, fmt.Errorf("compute units: a negative count")
	}
	return units, nil
}
