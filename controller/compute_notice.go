// The compute balance's billing notices (DESIGN-COMPUTE §9.8, §9.9, §9.12, DESIGN §7.4; BAL-M12-11): what auto-renew,
// §9.9's states and a network's closure owe its billing contacts, the network's Owners and Billing admins, and the hint
// §9.9's states owe every member device.
//
//	ComputeNotifier       the host's half (server's ComputeServerNotifier): owes a notice in the transaction of the
//	                      change that owes it, on its account message outbox, so the notice exists exactly when the
//	                      change commits and a change run again owes it once, by its key; and hints the network's
//	                      devices on the compute topic once a state change committed (QD-1238), a hint naming no state,
//	                      on which each device reads the balance route
//	RegisterComputeNotifier  the host's registration, once a process
//
// A notice names its kind and figures, never a charge's content: amounts, a count, a time, opaque enclave ids. Where no
// notifier is registered, as in a process that holds no outbox, a notice is owed to no one and its alarm counts it: a
// notice never holds back the change that owes it, since a state change is what refuses spending.

package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	operator "github.com/urnetwork/operator-core"
)

// What a notice is about (§9.8, §9.9, §9.12): identifiers, the template family's kinds.
type ComputeNoticeKind string

const (
	// A threshold top-up failed: it retries at RetryTime (§9.8).
	ComputeNoticeTopUpFailed ComputeNoticeKind = "top_up_failed"
	// The third failure in a row turned threshold off until it is turned on again (§9.8).
	ComputeNoticeTopUpOff ComputeNoticeKind = "top_up_off"
	// The card's bank asked for authentication: threshold is off until its holder buys again with it on (§9.8).
	ComputeNoticeAuthenticationRequired ComputeNoticeKind = "authentication_required"
	// The card's holder left the network or lost the role that let them buy: the card was detached and threshold
	// stopped until another is saved (§9.5).
	ComputeNoticeCardDetached ComputeNoticeKind = "card_detached"
	// A monthly plan's invoice was not paid: Stripe's billing retry follows (§9.8).
	ComputeNoticeMonthlyFailed ComputeNoticeKind = "monthly_failed"
	// §9.9's states, each change into one of them.
	ComputeNoticeLow       ComputeNoticeKind = "low"
	ComputeNoticeGrace     ComputeNoticeKind = "grace"
	ComputeNoticeSuspended ComputeNoticeKind = "suspended"
	// The network was deleted: its unspent purchased credit refunded where the market allows, the rest forfeited
	// (§9.12).
	ComputeNoticeClosed ComputeNoticeKind = "closed"
)

// Every kind, in this file's order.
var computeNoticeKinds = []ComputeNoticeKind{
	ComputeNoticeTopUpFailed, ComputeNoticeTopUpOff, ComputeNoticeAuthenticationRequired, ComputeNoticeCardDetached,
	ComputeNoticeMonthlyFailed, ComputeNoticeLow, ComputeNoticeGrace, ComputeNoticeSuspended, ComputeNoticeClosed,
}

// Every kind a notice may be.
func ComputeNoticeKinds() []ComputeNoticeKind {
	return append([]ComputeNoticeKind{}, computeNoticeKinds...)
}

// One notice to a network's billing contacts.
type ComputeNotice struct {
	NetworkId operator.Id
	Kind      ComputeNoticeKind
	// What owes it, unique to the change across every network, its network's id within it: a change run again owes the
	// notice once. Ids and numbers, never content.
	Key string
	// A top-up's: the pack's amount, the failures in a row, and when it retries (nil where it does not).
	AmountNanoUsd int64
	FailureCount  int
	RetryTime     *time.Time
	// A state's: the balance it read, holds left out; from low on, the enclaves a suspension would stop and the days
	// the network's indexer enclave's reserve and grace leave, nil where it has none (§9.9).
	BalanceNanoUsd   int64
	AtRiskEnclaveIds []operator.Id
	IndexerDaysLeft  *int64
	// A closure's: what went back to the card, and what was forfeited.
	RefundedNanoUsd  int64
	ForfeitedNanoUsd int64
}

// The host's notices and hints (see the file header). Implementations are safe for concurrent use.
type ComputeNotifier interface {
	// Owes notice to its network's billing contacts in tx, the transaction of the change that owes it; a key owed
	// before owes nothing more. An error is the transaction's: a failure the host can keep from the change it keeps
	// there itself.
	NoticeInTx(env operator.Env, ctx context.Context, tx operator.DbTx, notice *ComputeNotice) error
	// Hints every member device of networkId on the compute topic, after the change committed. Lossy: a device that
	// misses one reads the state from the balance route at its next poll.
	HintDevices(env operator.Env, ctx context.Context, networkId operator.Id) error
}

var (
	computeNoticeLock sync.Mutex
	computeNotifier   ComputeNotifier
)

// Registers the host's notifier, once a process, from the host's own install. A second registration, or a nil one,
// is a build error, which panics.
func RegisterComputeNotifier(notifier ComputeNotifier) {
	if notifier == nil {
		panic("compute notice: nil notifier")
	}
	computeNoticeLock.Lock()
	defer computeNoticeLock.Unlock()
	if computeNotifier != nil {
		panic("compute notice: the notifier is registered once")
	}
	computeNotifier = notifier
}

// The registered notifier, nil until one registers.
func ComputeRegisteredNotifier() ComputeNotifier {
	computeNoticeLock.Lock()
	defer computeNoticeLock.Unlock()
	return computeNotifier
}

// The alarm kind of a notice owed to no one, where no notifier is registered.
const ComputeAlarmNoticeUnowed = "notice_unowed"

// A notice that names no network, kind or key.
var errComputeNoticeArgs = errors.New("compute notice: a notice names its network, kind and key")

// Owes notice in tx through the registered notifier (see the file header); with none registered, nothing is owed and
// the unowed alarm counts it.
func computeNoticeInTx(env operator.Env, ctx context.Context, tx operator.DbTx, notice *ComputeNotice) error {
	var zero operator.Id
	if notice.NetworkId == zero || notice.Kind == "" || notice.Key == "" {
		return errComputeNoticeArgs
	}
	notifier := ComputeRegisteredNotifier()
	if notifier == nil {
		computeAlarm(env)(ComputeAlarmNoticeUnowed)
		return nil
	}
	return notifier.NoticeInTx(env, ctx, tx, notice)
}

// Hints networkId's devices through the registered notifier after a state change committed; lossy, so a failure or no
// notifier is no error.
func computeHintDevices(env operator.Env, ctx context.Context, networkId operator.Id) {
	if notifier := ComputeRegisteredNotifier(); notifier != nil {
		notifier.HintDevices(env, ctx, networkId)
	}
}
