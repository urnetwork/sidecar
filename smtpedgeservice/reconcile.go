// §14.8's RUA check (D-SMTP-23, D-SMTP-10; SMTP-M9-17): per network and UTC day, the DMARC aggregate message
// counts reporters gave for mail from URnetwork's sending addresses against the recipients the edge proved it
// sent that day (smtp_send). A day whose reported messages run above its proven recipients by more than
// ExcessPercent of them plus ExcessFloor is mail sent from the shared addresses under the network's name that
// no proven send carried, which §21 reviews as an investigation signal: a case, never a halt (§14.8's table).
//
// Messages are compared with recipients, not connections, because one connection's message counts once per
// recipient in a receiver's report (RFC 9990 §3.1.1.8): a one-connection send to ten recipients is ten proven
// recipients, which its ten reported messages meet.
//
// A day is judged once it has settled, SettleTimeout after its end, so its reports have landed, and only while
// its sends are all still kept: a day past MaxDayAge, whose smtp_send rows may have gone at 30 days, would read
// every reported message as unproven, so it is never judged. A report that lands after its day was judged
// counts for nothing here. TLS-RPT counts sessions, not messages, and takes no part.
//
// A pass reads one day's networks a page at a time from a cursor, oldest day first, so it bounds the work it
// examines, and a pass cut short resumes at its cursor. Judging a network again, as a pass retried from its
// cursor does, asks §21 again, and §21's case for the network coalesces it. Nothing here logs a network, a
// domain or a count (I-13).

package smtpedgeservice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
)

// Tunables of the RUA check.
type SmtpReconcileSettings struct {
	// How far a day's reported messages may run above its proven recipients, in percent of them, before the
	// day is a signal: §14.8's 20%. Not negative.
	ExcessPercent int64
	// And by how many messages more: §14.8's 5. Not negative.
	ExcessFloor int64
	// How long after a UTC day ends before it is judged: reporters send a day's aggregate within a day or two
	// of its end, so 3 days lets them land. Positive.
	SettleTimeout time.Duration
	// The oldest day a pass judges, counted from its end back to now: 25 days, inside smtp_send's 30, so every
	// judged day still has its sends. More than SettleTimeout.
	MaxDayAge time.Duration
	// Networks read in one page. Positive.
	PageNetworkCount int
	// Pages one pass reads before it leaves the rest to the next. Positive.
	PassPageCount int
}

func DefaultSmtpReconcileSettings() *SmtpReconcileSettings {
	return &SmtpReconcileSettings{
		ExcessPercent:    20,
		ExcessFloor:      5,
		SettleTimeout:    3 * 24 * time.Hour,
		MaxDayAge:        25 * 24 * time.Hour,
		PageNetworkCount: 500,
		PassPageCount:    20,
	}
}

// Settings the check cannot run on.
var ErrSmtpReconcileSettingsRefused = errors.New("smtp reconcile settings refused")

// Refuses settings outside their documented bounds, naming the field.
func (self *SmtpReconcileSettings) Validate() error {
	switch {
	case self == nil:
		return fmt.Errorf("%w: none", ErrSmtpReconcileSettingsRefused)
	case self.ExcessPercent < 0:
		return fmt.Errorf("%w: ExcessPercent", ErrSmtpReconcileSettingsRefused)
	case self.ExcessFloor < 0:
		return fmt.Errorf("%w: ExcessFloor", ErrSmtpReconcileSettingsRefused)
	case self.SettleTimeout <= 0:
		return fmt.Errorf("%w: SettleTimeout", ErrSmtpReconcileSettingsRefused)
	case self.MaxDayAge <= self.SettleTimeout:
		return fmt.Errorf("%w: MaxDayAge", ErrSmtpReconcileSettingsRefused)
	case self.PageNetworkCount <= 0:
		return fmt.Errorf("%w: PageNetworkCount", ErrSmtpReconcileSettingsRefused)
	case self.PassPageCount <= 0:
		return fmt.Errorf("%w: PassPageCount", ErrSmtpReconcileSettingsRefused)
	}
	return nil
}

// One network's UTC day as the check reads it.
type SmtpReconcileDay struct {
	NetworkId sidecar.Id
	// The UTC midnight starting the day.
	Day time.Time
	// The day's DMARC aggregate message counts, every reporter's, for mail from the sending addresses
	// (smtp_dmarc_daily keeps no other).
	ReportedMessageCount uint64
	// The recipients of the network's sends that started that day, as Z4 proved them (smtp_send).
	ProvenRecipientCount uint64
}

// Whether the day's reported messages run above its proven recipients by more than ExcessPercent of them
// plus ExcessFloor (§14.8's ">20% + 5 a day"), saturating rather than wrapping.
func (self *SmtpReconcileSettings) Exceeds(day *SmtpReconcileDay) bool {
	if day == nil {
		return false
	}
	allowance := smtpReconcileSaturatingAdd(
		smtpReconcileSaturatingMultiply(day.ProvenRecipientCount, uint64(self.ExcessPercent))/100,
		uint64(self.ExcessFloor),
	)
	return smtpReconcileSaturatingAdd(day.ProvenRecipientCount, allowance) < day.ReportedMessageCount
}

func smtpReconcileSaturatingAdd(a uint64, b uint64) uint64 {
	if sum := a + b; a <= sum {
		return sum
	}
	return ^uint64(0)
}

func smtpReconcileSaturatingMultiply(a uint64, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if product := a * b; product/b == a {
		return product
	}
	return ^uint64(0)
}

// What the check reads, off any connection path. server implements it on smtp_dmarc_daily and smtp_send.
// Safe for concurrent use.
type SmtpReconcileStore interface {
	// The networks with DMARC aggregate counts for day, in id order after afterNetworkId (the zero id
	// before every network), at most limit, each with the day's reported messages and proven recipients.
	ReconcileDays(ctx context.Context, day time.Time, afterNetworkId sidecar.Id, limit int) ([]*SmtpReconcileDay, error)
}

// Where a day that exceeds goes: §21, as a case with no halt. Safe for concurrent use.
type SmtpReconcileSink interface {
	// Opens or adds to the network's investigation case for the day. A day asked again adds to the open case.
	OpenSmtpReconcileCase(ctx context.Context, day *SmtpReconcileDay) error
}

// Where a pass starts, and where the next resumes.
type SmtpReconcileCursor struct {
	// The UTC midnight of the day in progress. Zero, or a day older than MaxDayAge, starts at the oldest day
	// still judged.
	Day time.Time
	// The last network judged on Day; the zero id for none yet.
	AfterNetworkId sidecar.Id
}

// What one pass did.
type SmtpReconcileResult struct {
	// Where the next pass resumes.
	Next SmtpReconcileCursor
	// Network days judged, and those §21 was asked to review.
	JudgedCount   int
	ExceededCount int
	// A read or a case that failed: the pass stopped there, and Next resumes at that network.
	Err error
	// Work remains for an immediate next pass: the page budget ran out on a settled day.
	More bool
}

// The RUA check. NewSmtpReconcile makes one. Safe for concurrent use.
type SmtpReconcile struct {
	store    SmtpReconcileStore
	sink     SmtpReconcileSink
	settings *SmtpReconcileSettings
}

func NewSmtpReconcile(store SmtpReconcileStore, sink SmtpReconcileSink, settings *SmtpReconcileSettings) (*SmtpReconcile, error) {
	if store == nil || sink == nil {
		return nil, errors.New("smtp reconcile needs its store and its sink")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	return &SmtpReconcile{
		store:    store,
		sink:     sink,
		settings: settings,
	}, nil
}

// The newest day settled at now: the UTC day that ended SettleTimeout or more before it.
func (self *SmtpReconcile) newestSettledDay(now time.Time) time.Time {
	return smtpUtcDay(now.Add(-self.settings.SettleTimeout)).Add(-24 * time.Hour)
}

// Where a chain with no cursor starts at now: the newest settled day, so a first pass judges from then on and
// asks §21 about no older day.
func (self *SmtpReconcile) StartCursor(now time.Time) SmtpReconcileCursor {
	return SmtpReconcileCursor{Day: self.newestSettledDay(now)}
}

// The oldest day still judged at now: the UTC day that ended less than MaxDayAge before it.
func (self *SmtpReconcile) oldestJudgedDay(now time.Time) time.Time {
	return smtpUtcDay(now.Add(-self.settings.MaxDayAge))
}

// Runs one bounded pass from cursor at now: each settled day from the cursor's, a page of its networks at a
// time, judging each and asking §21 to review each that exceeds, until PassPageCount pages or a day not yet
// settled. A day finished moves the cursor to the next. A failed read or case stops the pass with Err set and
// Next at the last network finished, so the next pass resumes there.
func (self *SmtpReconcile) Pass(ctx context.Context, cursor SmtpReconcileCursor, now time.Time) *SmtpReconcileResult {
	result := &SmtpReconcileResult{Next: cursor}
	day := smtpUtcDay(cursor.Day)
	afterNetworkId := cursor.AfterNetworkId
	if oldest := self.oldestJudgedDay(now); cursor.Day.IsZero() || day.Before(oldest) {
		// a day whose sends may be gone is never judged, and what it held is skipped
		day = oldest
		afterNetworkId = sidecar.Id{}
	}
	newest := self.newestSettledDay(now)
	result.Next = SmtpReconcileCursor{Day: day, AfterNetworkId: afterNetworkId}
	for pageCount := 0; !day.After(newest); {
		if pageCount == self.settings.PassPageCount {
			result.More = true
			return result
		}
		if err := ctx.Err(); err != nil {
			result.Err = err
			return result
		}
		pageCount += 1
		days, err := self.store.ReconcileDays(ctx, day, afterNetworkId, self.settings.PageNetworkCount)
		if err != nil {
			result.Err = err
			return result
		}
		for _, networkDay := range days {
			if networkDay == nil {
				continue
			}
			if self.settings.Exceeds(networkDay) {
				if err := self.sink.OpenSmtpReconcileCase(ctx, networkDay); err != nil {
					result.Err = err
					return result
				}
				result.ExceededCount += 1
			}
			result.JudgedCount += 1
			afterNetworkId = networkDay.NetworkId
			result.Next = SmtpReconcileCursor{Day: day, AfterNetworkId: afterNetworkId}
		}
		if len(days) < self.settings.PageNetworkCount {
			// the day is done
			day = day.Add(24 * time.Hour)
			afterNetworkId = sidecar.Id{}
			result.Next = SmtpReconcileCursor{Day: day, AfterNetworkId: afterNetworkId}
		}
	}
	return result
}
