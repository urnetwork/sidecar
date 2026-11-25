// The {cmp_<network_id>} projection (DESIGN-COMPUTE §9.7, §14.4, D-BAL-13; BAL-M12-02): Redis's side of the compute
// balance, a cache of Postgres's ledger, rebuilt from it before a lost or failed-over shard admits again, and never
// the only record of a debt. Every key of a network shares its hash tag, declared here and nowhere else
// (computeservice's helpers name the same strings), so each call is one script on one slot:
//
//	{cmp_<network_id>}                 settled, the unsettled charges' sum, the open holds' sum, promo, the floor,
//	                                   the running enclaves' accrued time, the state, the account version as a
//	                                   decimal string and a rebuild mark; each hold and each unsettled charge
//	                                   under its operation key (compute_projection_scripts.go has the fields)
//	{cmp_<network_id>}:u               the unconfirmed holds by the Redis TIME each was taken
//	{cmp_<network_id>}:b:<subject_id>  a subject's budget counters for the UTC day and month
//
// The calls, each acting once per operation key, a repeat answering its first outcome:
//
//	ComputeProjectionHold     a TEE call's hold and its budget reservations, unconfirmed; held while the projection
//	                          is absent or marked, or while open holds or reservations stand in the way; balance or
//	                          budget where the room is not there. The direct, search and interval branches are
//	                          scripts of their own over computeHoldPrelude (BAL-M12-21, BAL-M13-02, BAL-M14-01):
//	                          until they land, their paths are refused
//	ComputeProjectionConfirm  the hold confirmed once its operation row committed
//	ComputeProjectionSettle   the hold turned into an unsettled charge of the outcome's amount
//	ComputeProjectionVoid     the hold and its reservations released at no charge
//	ComputeProjectionDrop     a booked batch's unsettled charges dropped, settled taken from the committed account
//	                          when its version is newer
//	ComputeProjectionRebuild  the whole projection written from a snapshot, the mark cleared
//	ComputeProjectionRead     available for admission alone, and the balance the states and auto-renew read
//
// Budgets (§16.4): each hold names its ComputeBudgetLines, a subject, a budget, a period and a cap, from CACL's
// resolver (C§16.4) once it lands; until then ComputeDefaultBudgetLines gives §16.5's defaults by sidecar and agent
// from settings, and a network whose policy names budgets the ledger cannot read is refused budget.
//
// Each function takes the Env first (owner decision 594) and reaches Redis only through it. Safe for concurrent use:
// the scripts are the serialization, one network's at a time.

package model

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// Lua holds numbers as doubles, exact up to here: every amount, cap and time a script takes stays at or below it.
const computeLuaMaxExactInteger int64 = 1<<53 - 1

var (
	// A call the projection cannot take: an amount out of range, a malformed line, a kind that is not written.
	ErrComputeProjectionArgs = errors.New("compute projection: arguments refused")
	// A hold path whose script has not landed: the direct call's (BAL-M12-21), the search's (BAL-M13-02) and the
	// enclave interval's (BAL-M14-01). Refused, never held some other way.
	ErrComputeHoldPathUnbuilt = errors.New("compute projection: this hold path is not built")
	// The network's policy names budgets the ledger cannot read until CACL's resolver lands (C§16.4): the broker
	// answers budget.
	ErrComputeBudgetsUnread = errors.New("compute projection: the network's budgets cannot be read yet")
	// A script's reply this package does not know: the Redis it reached runs other code.
	ErrComputeProjectionReply = errors.New("compute projection: an unknown reply")
)

// The network's projection: {cmp_<network_id>}.
func ComputeProjectionKey(networkId operator.Id) string {
	return "{cmp_" + hex.EncodeToString(networkId[:]) + "}"
}

// A subject's budget counters, in its network's slot: {cmp_<network_id>}:b:<subject_id>.
func ComputeBudgetKey(networkId operator.Id, subjectId operator.Id) string {
	return ComputeProjectionKey(networkId) + ":b:" + hex.EncodeToString(subjectId[:])
}

// The network's unconfirmed holds by the Redis TIME each was taken: {cmp_<network_id>}:u.
func computeUnconfirmedKey(networkId operator.Id) string {
	return ComputeProjectionKey(networkId) + ":u"
}

// How a hold is taken (§9.7): which script, and so which of the prelude's classes.
type ComputeHoldPath int

const (
	// A remote call through a provider's TEE: its model's worst case, down to zero.
	ComputeHoldPathTee ComputeHoldPath = 1
	// A direct call: the declared model's worst case and a budget reservation, under the exposure rule (BAL-M12-21).
	ComputeHoldPathDirect ComputeHoldPath = 2
	// One web search's price, past promotional credit (BAL-M13-02).
	ComputeHoldPathSearch ComputeHoldPath = 3
	// An enclave's next 10 minutes, down to minus the floor (BAL-M14-01).
	ComputeHoldPathInterval ComputeHoldPath = 4
)

// One budget a hold is checked and reserved against (§16.4): a subject's budget for a UTC day or month, capped at what
// its subjects may be charged in that period.
type ComputeBudgetLine struct {
	// The agent, the sidecar, the member or the network the budget binds.
	SubjectId operator.Id
	// Which of the subject's budgets: a short name, [a-z0-9_] up to 24, so two budgets of one subject count apart,
	// as a device's ceiling across all its calls does beside its budget for calls naming no agent.
	Budget string
	// Day or month; a run's budget is the device's to keep, never the broker's.
	Period ComputeBudgetPeriod
	// What the subject may be charged in the period, in nano-USD.
	CapNanoUsd int64
}

// The default budgets' names (§16.5).
const (
	// An agent id's, or a tagged subject's own: $5 a day and $50 a month.
	ComputeBudgetAgent  = "agent"
	ComputeBudgetTagged = "tagged"
	// An untagged device's, for its calls naming no agent: $20 a day and $200 a month.
	ComputeBudgetDevice = "device"
	// An untagged device's ceiling across all its agents and calls: $50 a day (CO-41).
	ComputeBudgetCeiling = "ceiling"
)

// Who a call is for, as the broker read it from the signed projection, for §16.5's default budgets.
type ComputeBudgetCaller struct {
	SidecarId operator.Id
	// The agent the call names, nil for none.
	AgentId *operator.Id
	// A tagged sidecar, an enclave among them.
	Tagged bool
	// The network's policy names budgets of its own, which only CACL's resolver reads.
	PolicyNamesBudgets bool
}

// §16.5's budgets for caller, from settings, until CACL's resolver gives the policy's (C§16.4): a call naming an agent
// counts to the agent's budget; an untagged device's call naming none to the device's own; every untagged device's
// call to its ceiling; a tagged sidecar's call to its own as a tagged subject. A caller whose policy names budgets is
// refused with ErrComputeBudgetsUnread, so no call passes a budget the ledger has not read.
func ComputeDefaultBudgetLines(settings *ComputeLedgerSettings, caller *ComputeBudgetCaller) ([]*ComputeBudgetLine, error) {
	if caller.PolicyNamesBudgets {
		return nil, ErrComputeBudgetsUnread
	}
	lines := []*ComputeBudgetLine{}
	add := func(subjectId operator.Id, budget string, dayNanoUsd int64, monthNanoUsd int64) {
		lines = append(lines, &ComputeBudgetLine{SubjectId: subjectId, Budget: budget, Period: ComputeBudgetPeriodDay, CapNanoUsd: dayNanoUsd})
		if 0 <= monthNanoUsd {
			lines = append(lines, &ComputeBudgetLine{SubjectId: subjectId, Budget: budget, Period: ComputeBudgetPeriodMonth, CapNanoUsd: monthNanoUsd})
		}
	}
	if caller.AgentId != nil {
		add(*caller.AgentId, ComputeBudgetAgent, settings.DefaultAgentDayNanoUsd, settings.DefaultAgentMonthNanoUsd)
	}
	if caller.Tagged {
		add(caller.SidecarId, ComputeBudgetTagged, settings.DefaultAgentDayNanoUsd, settings.DefaultAgentMonthNanoUsd)
		return lines, nil
	}
	if caller.AgentId == nil {
		add(caller.SidecarId, ComputeBudgetDevice, settings.DefaultDeviceDayNanoUsd, settings.DefaultDeviceMonthNanoUsd)
	}
	// a day's ceiling, no month's
	add(caller.SidecarId, ComputeBudgetCeiling, settings.DefaultDeviceCeilingDayNanoUsd, -1)
	return lines, nil
}

// A budget's name: lowercase letters, digits and _, so it sits in a counter's field between colons.
var computeBudgetNamePattern = regexp.MustCompile(`^[a-z0-9_]{1,24}$`)

// The period's letter in a script's line: d or m.
func (self ComputeBudgetPeriod) letter() (string, error) {
	switch self {
	case ComputeBudgetPeriodDay:
		return "d", nil
	case ComputeBudgetPeriodMonth:
		return "m", nil
	}
	return "", fmt.Errorf("%w: a budget's period is a day or a month at the broker, not %s", ErrComputeProjectionArgs, self)
}

// A counter's period field for the UTC day or month t falls in: d:YYYYMMDD or m:YYYYMM, as the scripts write them.
func ComputeBudgetPeriodField(period ComputeBudgetPeriod, t time.Time) (string, error) {
	switch period {
	case ComputeBudgetPeriodDay:
		return "d:" + t.UTC().Format("20060102"), nil
	case ComputeBudgetPeriodMonth:
		return "m:" + t.UTC().Format("200601"), nil
	}
	return "", fmt.Errorf("%w: a budget's period is a day or a month at the broker, not %s", ErrComputeProjectionArgs, period)
}

// Checks an amount a script takes: zero or more, and exact in Lua.
func computeProjectionAmount(what string, amount int64) error {
	if amount < 0 || computeLuaMaxExactInteger < amount {
		return fmt.Errorf("%w: %s %d is out of range", ErrComputeProjectionArgs, what, amount)
	}
	return nil
}

// The subjects' counters' keys for network, each once, in order: what a call declares after the projection and the
// unconfirmed set.
func computeBudgetKeys(networkId operator.Id, subjectIds []operator.Id) []string {
	keys := []string{}
	for _, subjectId := range subjectIds {
		key := ComputeBudgetKey(networkId, subjectId)
		if !slices.Contains(keys, key) {
			keys = append(keys, key)
		}
	}
	return keys
}

// A line's ARGV, subject, budget, period letter and cap, checked.
func computeLineArgs(line *ComputeBudgetLine) ([]string, error) {
	if !computeBudgetNamePattern.MatchString(line.Budget) {
		return nil, fmt.Errorf("%w: the budget name %q", ErrComputeProjectionArgs, line.Budget)
	}
	letter, err := line.Period.letter()
	if err != nil {
		return nil, err
	}
	if err := computeProjectionAmount("a budget's cap", line.CapNanoUsd); err != nil {
		return nil, err
	}
	return []string{hex.EncodeToString(line.SubjectId[:]), line.Budget, letter, strconv.FormatInt(line.CapNanoUsd, 10)}, nil
}

// The lines' ARGV, their count first, and their subjects.
func computeLinesArgs(settings *ComputeLedgerSettings, lines []*ComputeBudgetLine) ([]string, []operator.Id, error) {
	if settings.ProjectionHoldMaxLineCount < len(lines) {
		return nil, nil, fmt.Errorf("%w: %d budget lines, past %d", ErrComputeProjectionArgs, len(lines), settings.ProjectionHoldMaxLineCount)
	}
	args := []string{strconv.Itoa(len(lines))}
	subjectIds := []operator.Id{}
	for _, line := range lines {
		lineArgs, err := computeLineArgs(line)
		if err != nil {
			return nil, nil, err
		}
		args = append(args, lineArgs...)
		subjectIds = append(subjectIds, line.SubjectId)
	}
	return args, subjectIds, nil
}

// A duration in whole milliseconds, at least one, as a script's ttl or age takes it.
func computeMillis(duration time.Duration) string {
	return strconv.FormatInt(max(1, duration.Milliseconds()), 10)
}

// The env's Redis, which a ledger call needs.
func computeProjectionRedis(env operator.Env) (operator.Redis, error) {
	return env.Redis()
}

// The reply's strings, in order: an array of bulk strings or integers, nil elements read as "".
func computeReplyStrings(reply *operator.RedisReply) ([]string, error) {
	if reply == nil || reply.Kind != operator.RedisReplyArray {
		return nil, fmt.Errorf("%w: not an array", ErrComputeProjectionReply)
	}
	values := []string{}
	for _, element := range reply.Replies {
		switch {
		case element == nil || element.Kind == operator.RedisReplyNil:
			values = append(values, "")
		case element.Kind == operator.RedisReplyBulk:
			values = append(values, string(element.Bulk))
		case element.Kind == operator.RedisReplyInteger:
			values = append(values, strconv.FormatInt(element.Integer, 10))
		default:
			return nil, fmt.Errorf("%w: a nested array", ErrComputeProjectionReply)
		}
	}
	return values, nil
}

// What a hold came to.
type ComputeHoldOutcome string

const (
	// The hold is taken, unconfirmed until the operation's row commits.
	ComputeHoldTaken ComputeHoldOutcome = "taken"
	// Refused for now: the projection is absent or marked, or open holds or reservations, not the balance or a
	// budget, stand in the way. RetryAfter says when to ask again (§6.6's held).
	ComputeHoldHeld ComputeHoldOutcome = "held"
	// Refused: the balance cannot cover it, or the account is in grace or worse (402 COMPUTE_BALANCE).
	ComputeHoldBalance ComputeHoldOutcome = "balance"
	// Refused: a budget line's charges and the reservation would pass its cap.
	ComputeHoldBudget ComputeHoldOutcome = "budget"
	// A repeat of an operation that was released at no charge, or whose unconfirmed hold was dropped past its age.
	ComputeHoldVoid ComputeHoldOutcome = "void"
	// A repeat of an operation already booked.
	ComputeHoldDropped ComputeHoldOutcome = "dropped"
)

// One hold to take.
type ComputeHoldRequest struct {
	NetworkId operator.Id
	// The operation key: its charge's charge_id.
	OpKey operator.Id
	Kind  ComputeChargeKind
	Path  ComputeHoldPath
	// The balance hold: a TEE call's worst case.
	HoldNanoUsd int64
	// The budget reservation: a TEE call's is its hold.
	ReserveNanoUsd int64
	Lines          []*ComputeBudgetLine
}

// What a hold came to.
type ComputeHoldResult struct {
	Outcome ComputeHoldOutcome
	// When to ask again, for held.
	RetryAfter time.Duration
	// The Redis TIME of the hold, the operation's start; for a refusal, when it was refused; zero for a repeat whose
	// hold has settled.
	Time time.Time
}

// Takes request's hold (see the file header). Only the TEE path is built; the others are refused with
// ErrComputeHoldPathUnbuilt.
func ComputeProjectionHold(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, request *ComputeHoldRequest) (*ComputeHoldResult, error) {
	if request.Path != ComputeHoldPathTee {
		return nil, ErrComputeHoldPathUnbuilt
	}
	if request.Kind != ComputeChargeKindInference {
		return nil, fmt.Errorf("%w: a TEE call holds as inference, not %s", ErrComputeProjectionArgs, request.Kind)
	}
	if err := computeProjectionAmount("the hold", request.HoldNanoUsd); err != nil {
		return nil, err
	}
	if err := computeProjectionAmount("the reservation", request.ReserveNanoUsd); err != nil {
		return nil, err
	}
	linesArgs, subjectIds, err := computeLinesArgs(settings, request.Lines)
	if err != nil {
		return nil, err
	}
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return nil, err
	}
	keys := append([]string{ComputeProjectionKey(request.NetworkId), computeUnconfirmedKey(request.NetworkId)},
		computeBudgetKeys(request.NetworkId, subjectIds)...)
	args := append([]string{
		hex.EncodeToString(request.OpKey[:]),
		strconv.Itoa(int(request.Kind)),
		strconv.FormatInt(request.HoldNanoUsd, 10),
		strconv.FormatInt(request.ReserveNanoUsd, 10),
		computeMillis(settings.UnconfirmedHoldMaxAge),
		computeMillis(settings.ProjectionMemoTtl),
		computeMillis(settings.HeldRetry),
		computeMillis(settings.ProjectionRebuildRetry),
	}, linesArgs...)
	reply, err := redis.RunScript(ctx, computeProjectionHoldScript, keys, args)
	if err != nil {
		return nil, err
	}
	values, err := computeReplyStrings(reply)
	if err != nil {
		return nil, err
	}
	if len(values) != 3 {
		return nil, fmt.Errorf("%w: a hold answers 3 values", ErrComputeProjectionReply)
	}
	outcome := ComputeHoldOutcome(values[0])
	if !slices.Contains([]ComputeHoldOutcome{ComputeHoldTaken, ComputeHoldHeld, ComputeHoldBalance, ComputeHoldBudget, ComputeHoldVoid, ComputeHoldDropped}, outcome) {
		return nil, fmt.Errorf("%w: the hold outcome %q", ErrComputeProjectionReply, values[0])
	}
	retryMs, err1 := strconv.ParseInt(values[1], 10, 64)
	timeMs, err2 := strconv.ParseInt(values[2], 10, 64)
	if err1 != nil || err2 != nil {
		return nil, fmt.Errorf("%w: a hold's retry or time", ErrComputeProjectionReply)
	}
	result := &ComputeHoldResult{Outcome: outcome, RetryAfter: time.Duration(retryMs) * time.Millisecond}
	if 0 < timeMs {
		result.Time = time.UnixMilli(timeMs).UTC()
	}
	return result, nil
}

// What a confirm, settle or void came to.
type ComputeScriptOutcome string

const (
	ComputeScriptConfirmed ComputeScriptOutcome = "confirmed"
	ComputeScriptSettled   ComputeScriptOutcome = "settled"
	ComputeScriptVoid      ComputeScriptOutcome = "void"
	ComputeScriptDropped   ComputeScriptOutcome = "dropped"
	// No projection, or, for a confirm, no hold of this key: a rebuild from the rows restores what is due.
	ComputeScriptAbsent ComputeScriptOutcome = "absent"
)

// One outcome a script answered, among those it may.
func computeScriptOutcome(reply *operator.RedisReply, allowed ...ComputeScriptOutcome) (ComputeScriptOutcome, error) {
	values, err := computeReplyStrings(reply)
	if err != nil {
		return "", err
	}
	if len(values) != 1 || !slices.Contains(allowed, ComputeScriptOutcome(values[0])) {
		return "", fmt.Errorf("%w: %v", ErrComputeProjectionReply, values)
	}
	return ComputeScriptOutcome(values[0]), nil
}

// Confirms opKey's hold once its operation row committed (D-BAL-13). subjectIds holds every subject the hold may
// name, a superset of its lines' subjects (the row's sidecar, agent, member and network): their counters are where
// its reservations move.
func ComputeProjectionConfirm(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, networkId operator.Id, opKey operator.Id, subjectIds []operator.Id) (ComputeScriptOutcome, error) {
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return "", err
	}
	keys := append([]string{ComputeProjectionKey(networkId), computeUnconfirmedKey(networkId)}, computeBudgetKeys(networkId, subjectIds)...)
	reply, err := redis.RunScript(ctx, computeProjectionConfirmScript, keys, []string{
		hex.EncodeToString(opKey[:]),
		computeMillis(settings.UnconfirmedHoldMaxAge),
		computeMillis(settings.ProjectionMemoTtl),
		computeMillis(settings.BudgetCounterTtl),
	})
	if err != nil {
		return "", err
	}
	return computeScriptOutcome(reply, ComputeScriptConfirmed, ComputeScriptVoid, ComputeScriptDropped, ComputeScriptAbsent)
}

// One settlement's first script.
type ComputeSettleRequest struct {
	NetworkId operator.Id
	OpKey     operator.Id
	Kind      ComputeChargeKind
	Path      ComputeHoldPath
	// The outcome's amount, committed to the row first.
	AmountNanoUsd int64
	// The row's reservation, which caps what each counter is charged where the hold is gone.
	ReserveNanoUsd int64
	// The row's start time, whose UTC day and month a charge with no hold counts to.
	StartTime time.Time
	// The lines the hold was reserved under, as the resolver gives them again; read only where the hold is gone.
	Lines []*ComputeBudgetLine
	// Every subject the operation names, the lines' among them.
	SubjectIds []operator.Id
}

// Turns request's hold into an unsettled charge of its amount (§9.7). A TEE call, a search and an interval are held at
// their worst case, so the charge is never above the hold; the direct path's settlement is BAL-M12-21's and refused
// here.
func ComputeProjectionSettle(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, request *ComputeSettleRequest) (ComputeScriptOutcome, error) {
	if request.Path == ComputeHoldPathDirect {
		return "", ErrComputeHoldPathUnbuilt
	}
	if !request.Kind.Written() || request.Kind == ComputeChargeKindAdjustment {
		return "", fmt.Errorf("%w: an operation of kind %s settles no hold", ErrComputeProjectionArgs, request.Kind)
	}
	if err := computeProjectionAmount("the charge", request.AmountNanoUsd); err != nil {
		return "", err
	}
	if err := computeProjectionAmount("the reservation", request.ReserveNanoUsd); err != nil {
		return "", err
	}
	startMs := request.StartTime.UnixMilli()
	if err := computeProjectionAmount("the start", startMs); err != nil {
		return "", err
	}
	linesArgs, lineSubjectIds, err := computeLinesArgs(settings, request.Lines)
	if err != nil {
		return "", err
	}
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return "", err
	}
	keys := append([]string{ComputeProjectionKey(request.NetworkId), computeUnconfirmedKey(request.NetworkId)},
		computeBudgetKeys(request.NetworkId, append(slices.Clone(request.SubjectIds), lineSubjectIds...))...)
	args := append([]string{
		hex.EncodeToString(request.OpKey[:]),
		strconv.Itoa(int(request.Kind)),
		strconv.FormatInt(request.AmountNanoUsd, 10),
		"1",
		strconv.FormatInt(request.ReserveNanoUsd, 10),
		strconv.FormatInt(startMs, 10),
		computeMillis(settings.UnconfirmedHoldMaxAge),
		computeMillis(settings.ProjectionMemoTtl),
		computeMillis(settings.BudgetCounterTtl),
	}, linesArgs...)
	reply, err := redis.RunScript(ctx, computeProjectionSettleScript, keys, args)
	if err != nil {
		return "", err
	}
	return computeScriptOutcome(reply, ComputeScriptSettled, ComputeScriptVoid, ComputeScriptDropped, ComputeScriptAbsent)
}

// Releases opKey's hold at no charge (§9.7); subjectIds as for ComputeProjectionConfirm.
func ComputeProjectionVoid(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, networkId operator.Id, opKey operator.Id, subjectIds []operator.Id) (ComputeScriptOutcome, error) {
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return "", err
	}
	keys := append([]string{ComputeProjectionKey(networkId), computeUnconfirmedKey(networkId)}, computeBudgetKeys(networkId, subjectIds)...)
	reply, err := redis.RunScript(ctx, computeProjectionVoidScript, keys, []string{
		hex.EncodeToString(opKey[:]),
		computeMillis(settings.UnconfirmedHoldMaxAge),
		computeMillis(settings.ProjectionMemoTtl),
	})
	if err != nil {
		return "", err
	}
	return computeScriptOutcome(reply, ComputeScriptVoid, ComputeScriptSettled, ComputeScriptDropped, ComputeScriptAbsent)
}

// The committed account a booked batch leaves (§9.7): what the drop takes when its version is newer.
type ComputeProjectionAccount struct {
	Version        int64
	SettledNanoUsd int64
	PromoNanoUsd   int64
	FloorNanoUsd   int64
	State          ComputeAccountState
}

// Checks an account's values for a script.
func (self *ComputeProjectionAccount) args() ([]string, error) {
	if self.Version < 0 {
		return nil, fmt.Errorf("%w: a negative version", ErrComputeProjectionArgs)
	}
	if self.SettledNanoUsd < -computeLuaMaxExactInteger || computeLuaMaxExactInteger < self.SettledNanoUsd {
		return nil, fmt.Errorf("%w: settled is out of range", ErrComputeProjectionArgs)
	}
	if err := computeProjectionAmount("promo", self.PromoNanoUsd); err != nil {
		return nil, err
	}
	if err := computeProjectionAmount("the floor", self.FloorNanoUsd); err != nil {
		return nil, err
	}
	if !self.State.Valid() {
		return nil, fmt.Errorf("%w: no account state %d", ErrComputeProjectionArgs, self.State)
	}
	return []string{
		strconv.FormatInt(self.Version, 10),
		strconv.FormatInt(self.SettledNanoUsd, 10),
		strconv.FormatInt(self.PromoNanoUsd, 10),
		strconv.FormatInt(self.FloorNanoUsd, 10),
		strconv.Itoa(int(self.State)),
	}, nil
}

// One booked operation of a batch: its key and the amount booked.
type ComputeDropOp struct {
	OpKey         operator.Id
	AmountNanoUsd int64
}

// A booked batch's drop for one network.
type ComputeDropRequest struct {
	NetworkId operator.Id
	// The account as the booking committed it.
	Account *ComputeProjectionAccount
	Ops     []*ComputeDropOp
	// Every subject the batch's operations name.
	SubjectIds []operator.Id
}

// What a drop did.
type ComputeDropResult struct {
	// No projection: nothing was written, and a rebuild makes it.
	Absent bool
	// How many unsettled charges it dropped.
	DroppedCount int
	// Whether the account's values were newer than the projection's and taken.
	Applied bool
}

// Drops a booked batch's unsettled charges and sets settled from the committed account when its version is newer
// (§9.7).
func ComputeProjectionDrop(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, request *ComputeDropRequest) (*ComputeDropResult, error) {
	accountArgs, err := request.Account.args()
	if err != nil {
		return nil, err
	}
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return nil, err
	}
	args := append(accountArgs,
		computeMillis(settings.UnconfirmedHoldMaxAge),
		computeMillis(settings.ProjectionMemoTtl),
		computeMillis(settings.BudgetCounterTtl),
		strconv.Itoa(len(request.Ops)),
	)
	for _, op := range request.Ops {
		if err := computeProjectionAmount("a booked amount", op.AmountNanoUsd); err != nil {
			return nil, err
		}
		args = append(args, hex.EncodeToString(op.OpKey[:]), strconv.FormatInt(op.AmountNanoUsd, 10))
	}
	keys := append([]string{ComputeProjectionKey(request.NetworkId), computeUnconfirmedKey(request.NetworkId)},
		computeBudgetKeys(request.NetworkId, request.SubjectIds)...)
	reply, err := redis.RunScript(ctx, computeProjectionDropScript, keys, args)
	if err != nil {
		return nil, err
	}
	values, err := computeReplyStrings(reply)
	if err != nil {
		return nil, err
	}
	if len(values) != 3 || (values[0] != "dropped" && values[0] != "absent") {
		return nil, fmt.Errorf("%w: %v", ErrComputeProjectionReply, values)
	}
	droppedCount, err := strconv.Atoi(values[1])
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrComputeProjectionReply, values)
	}
	return &ComputeDropResult{Absent: values[0] == "absent", DroppedCount: droppedCount, Applied: values[2] == "1"}, nil
}

// One open operation's hold in a rebuild's snapshot: its row's key, kind, hold, reservation, start and the lines it
// was reserved under (their caps unread).
type ComputeProjectionHoldRow struct {
	OpKey          operator.Id
	Kind           ComputeChargeKind
	HoldNanoUsd    int64
	ReserveNanoUsd int64
	StartTime      time.Time
	Lines          []*ComputeBudgetLine
}

// One settled, unbooked operation's charge in a rebuild's snapshot.
type ComputeProjectionChargeRow struct {
	OpKey         operator.Id
	Kind          ComputeChargeKind
	AmountNanoUsd int64
}

// One booked counter in a rebuild's snapshot: what a subject's budget was charged in the UTC period of At.
type ComputeProjectionCounter struct {
	SubjectId      operator.Id
	Budget         string
	Period         ComputeBudgetPeriod
	At             time.Time
	ChargedNanoUsd int64
}

// What a rebuild writes: the account's settled balance and version, each open row's hold and reservation, each
// settled row's charge, and the day's and month's booked charges by subject, read in one REPEATABLE READ snapshot
// under the network's fence (BAL-M12-04).
type ComputeProjectionSnapshot struct {
	NetworkId operator.Id
	Account   *ComputeProjectionAccount
	// The running enclaves' time accrued in their current interval (BAL-M14-01); zero before.
	AccruedNanoUsd int64
	Holds          []*ComputeProjectionHoldRow
	Charges        []*ComputeProjectionChargeRow
	Counters       []*ComputeProjectionCounter
}

// Writes snapshot's projection whole and clears the mark (§9.7): every counter the projection listed is deleted with
// it, so nothing of the lost state stays.
func ComputeProjectionRebuild(env operator.Env, ctx context.Context, settings *ComputeLedgerSettings, snapshot *ComputeProjectionSnapshot) error {
	accountArgs, err := snapshot.Account.args()
	if err != nil {
		return err
	}
	if snapshot.AccruedNanoUsd < 0 || computeLuaMaxExactInteger < snapshot.AccruedNanoUsd {
		return fmt.Errorf("%w: accrued is out of range", ErrComputeProjectionArgs)
	}
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return err
	}
	subjectIds := []operator.Id{}
	args := append(accountArgs, strconv.FormatInt(snapshot.AccruedNanoUsd, 10), computeMillis(settings.BudgetCounterTtl), strconv.Itoa(len(snapshot.Holds)))
	for _, hold := range snapshot.Holds {
		if err := computeProjectionAmount("a hold", hold.HoldNanoUsd); err != nil {
			return err
		}
		if err := computeProjectionAmount("a reservation", hold.ReserveNanoUsd); err != nil {
			return err
		}
		startMs := hold.StartTime.UnixMilli()
		if err := computeProjectionAmount("a hold's start", startMs); err != nil {
			return err
		}
		args = append(args, hex.EncodeToString(hold.OpKey[:]), strconv.Itoa(int(hold.Kind)), strconv.FormatInt(hold.HoldNanoUsd, 10),
			strconv.FormatInt(hold.ReserveNanoUsd, 10), strconv.FormatInt(startMs, 10), strconv.Itoa(len(hold.Lines)))
		for _, line := range hold.Lines {
			lineArgs, err := computeLineArgs(line)
			if err != nil {
				return err
			}
			args = append(args, lineArgs[:3]...)
			subjectIds = append(subjectIds, line.SubjectId)
		}
	}
	args = append(args, strconv.Itoa(len(snapshot.Charges)))
	for _, charge := range snapshot.Charges {
		if err := computeProjectionAmount("a charge", charge.AmountNanoUsd); err != nil {
			return err
		}
		args = append(args, hex.EncodeToString(charge.OpKey[:]), strconv.Itoa(int(charge.Kind)), strconv.FormatInt(charge.AmountNanoUsd, 10))
	}
	args = append(args, strconv.Itoa(len(snapshot.Counters)))
	for _, counter := range snapshot.Counters {
		if !computeBudgetNamePattern.MatchString(counter.Budget) {
			return fmt.Errorf("%w: the budget name %q", ErrComputeProjectionArgs, counter.Budget)
		}
		field, err := ComputeBudgetPeriodField(counter.Period, counter.At)
		if err != nil {
			return err
		}
		if err := computeProjectionAmount("a counter", counter.ChargedNanoUsd); err != nil {
			return err
		}
		args = append(args, hex.EncodeToString(counter.SubjectId[:]), counter.Budget, field, strconv.FormatInt(counter.ChargedNanoUsd, 10))
		subjectIds = append(subjectIds, counter.SubjectId)
	}
	// the subjects the projection listed, whose counters go with it
	key := ComputeProjectionKey(snapshot.NetworkId)
	fieldValues, err := redis.HashGetAll(ctx, key)
	if err != nil {
		return err
	}
	for field := range fieldValues {
		if len(field) == 2+32 && field[:2] == "s:" {
			subjectBytes, err := hex.DecodeString(field[2:])
			if err == nil && len(subjectBytes) == 16 {
				subjectIds = append(subjectIds, operator.Id(subjectBytes))
			}
		}
	}
	slices.SortFunc(subjectIds, operator.Id.Cmp)
	keys := append([]string{key, computeUnconfirmedKey(snapshot.NetworkId)}, computeBudgetKeys(snapshot.NetworkId, slices.Compact(subjectIds))...)
	reply, err := redis.RunScript(ctx, computeProjectionRebuildScript, keys, args)
	if err != nil {
		return err
	}
	values, err := computeReplyStrings(reply)
	if err != nil {
		return err
	}
	if len(values) != 1 || values[0] != "rebuilt" {
		return fmt.Errorf("%w: %v", ErrComputeProjectionReply, values)
	}
	return nil
}

// Marks networkId's projection as possibly lost, as after its shard's master changed: it admits nothing until a
// rebuild clears the mark (§9.7).
func ComputeProjectionMarkRebuild(env operator.Env, ctx context.Context, networkId operator.Id) error {
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return err
	}
	reply, err := redis.RunScript(ctx, computeProjectionMarkScript, []string{ComputeProjectionKey(networkId)}, nil)
	if err != nil {
		return err
	}
	values, err := computeReplyStrings(reply)
	if err != nil {
		return err
	}
	if len(values) != 1 || values[0] != "marked" {
		return fmt.Errorf("%w: %v", ErrComputeProjectionReply, values)
	}
	return nil
}

// A network's projection as it stands: admission reads AvailableNanoUsd alone, and the states and auto-renew read
// BalanceNanoUsd (§9.7, D-BAL-9).
type ComputeProjection struct {
	// The projection exists: a rebuild wrote it.
	Present bool
	// A rebuild is due: it admits nothing.
	Marked           bool
	SettledNanoUsd   int64
	UnsettledNanoUsd int64
	HoldsNanoUsd     int64
	PromoNanoUsd     int64
	FloorNanoUsd     int64
	AccruedNanoUsd   int64
	State            ComputeAccountState
	// The account version, a decimal string.
	Version string
}

// settled - unsettled charges - open holds: what admission reads.
func (self *ComputeProjection) AvailableNanoUsd() int64 {
	return self.SettledNanoUsd - self.UnsettledNanoUsd - self.HoldsNanoUsd
}

// settled - unsettled charges - the running enclaves' accrued time, holds left out: what the states and auto-renew
// read, since a hold is a worst case, not spend.
func (self *ComputeProjection) BalanceNanoUsd() int64 {
	return self.SettledNanoUsd - self.UnsettledNanoUsd - self.AccruedNanoUsd
}

// networkId's projection as it stands. An absent one reads Present false and every figure zero.
func ComputeProjectionRead(env operator.Env, ctx context.Context, networkId operator.Id) (*ComputeProjection, error) {
	redis, err := computeProjectionRedis(env)
	if err != nil {
		return nil, err
	}
	reply, err := redis.RunScript(ctx, computeProjectionReadScript, []string{ComputeProjectionKey(networkId)}, nil)
	if err != nil {
		return nil, err
	}
	values, err := computeReplyStrings(reply)
	if err != nil {
		return nil, err
	}
	if len(values) != 9 {
		return nil, fmt.Errorf("%w: a read answers 9 values", ErrComputeProjectionReply)
	}
	projection := &ComputeProjection{Present: values[0] != "", Marked: values[1] != "", Version: values[0]}
	for i, target := range []*int64{
		&projection.SettledNanoUsd, &projection.UnsettledNanoUsd, &projection.HoldsNanoUsd, &projection.PromoNanoUsd,
		&projection.FloorNanoUsd, &projection.AccruedNanoUsd,
	} {
		value := values[2+i]
		if value == "" {
			continue
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("%w: %q", ErrComputeProjectionReply, value)
		}
		*target = parsed
	}
	if values[8] != "" {
		state, err := strconv.Atoi(values[8])
		if err != nil {
			return nil, fmt.Errorf("%w: the state %q", ErrComputeProjectionReply, values[8])
		}
		projection.State = ComputeAccountState(state)
	}
	return projection, nil
}
