// §14.8's RUA check (SMTP-M9-17; D-SMTP-23): the threshold with its twin just below, a one-connection send to ten
// recipients raising nothing, settled days alone and only while their sends are kept, and a pass bounded by its
// pages that resumes at its cursor after a failure.

package smtpedgeservice_test

import (
	"context"
	"errors"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// The days a store holds, by day, each day's networks in id order, with a read that can fail once.
type reconcileStore struct {
	dayNetworks map[time.Time][]*smtpedgeservice.SmtpReconcileDay
	reads       []time.Time
	// the read of this index fails, once
	failRead int
}

func newReconcileStore() *reconcileStore {
	return &reconcileStore{dayNetworks: map[time.Time][]*smtpedgeservice.SmtpReconcileDay{}, failRead: -1}
}

func (self *reconcileStore) add(day time.Time, networkId sidecar.Id, reported uint64, proven uint64) {
	self.dayNetworks[day] = append(self.dayNetworks[day], &smtpedgeservice.SmtpReconcileDay{
		NetworkId:            networkId,
		Day:                  day,
		ReportedMessageCount: reported,
		ProvenRecipientCount: proven,
	})
	slices.SortFunc(self.dayNetworks[day], func(a *smtpedgeservice.SmtpReconcileDay, b *smtpedgeservice.SmtpReconcileDay) int {
		return a.NetworkId.Cmp(b.NetworkId)
	})
}

func (self *reconcileStore) ReconcileDays(ctx context.Context, day time.Time, afterNetworkId sidecar.Id, limit int) ([]*smtpedgeservice.SmtpReconcileDay, error) {
	read := len(self.reads)
	self.reads = append(self.reads, day)
	if read == self.failRead {
		self.failRead = -1
		return nil, errors.New("the store did not answer")
	}
	page := []*smtpedgeservice.SmtpReconcileDay{}
	for _, networkDay := range self.dayNetworks[day] {
		if afterNetworkId.Cmp(networkDay.NetworkId) < 0 && len(page) < limit {
			page = append(page, networkDay)
		}
	}
	return page, nil
}

// The days §21 was asked to review.
type reconcileSink struct {
	opened []*smtpedgeservice.SmtpReconcileDay
}

func (self *reconcileSink) OpenSmtpReconcileCase(ctx context.Context, day *smtpedgeservice.SmtpReconcileDay) error {
	self.opened = append(self.opened, day)
	return nil
}

func reconcileNetworkId(n byte) sidecar.Id {
	return sidecar.Id{0x01, n}
}

// A check over the store, at now, its days settled from 2031-03-01 to 2031-03-10.
func newReconcileWorld(t *testing.T, settings *smtpedgeservice.SmtpReconcileSettings) (*smtpedgeservice.SmtpReconcile, *reconcileStore, *reconcileSink, time.Time) {
	store := newReconcileStore()
	sink := &reconcileSink{}
	if settings == nil {
		settings = smtpedgeservice.DefaultSmtpReconcileSettings()
	}
	reconcile, err := smtpedgeservice.NewSmtpReconcile(store, sink, settings)
	if err != nil {
		t.Fatal(err)
	}
	// 2031-03-10 ended 3 days before
	now := time.Date(2031, 3, 14, 6, 0, 0, 0, time.UTC)
	return reconcile, store, sink, now
}

func TestSmtpReconcileOpensACaseAboveTwentyPercentAndFive(t *testing.T) {
	reconcile, store, sink, now := newReconcileWorld(t, nil)
	day := time.Date(2031, 3, 10, 0, 0, 0, 0, time.UTC)
	// 100 proven recipients: 21% + 5 above them is 126 messages, a signal
	store.add(day, reconcileNetworkId(1), 126, 100)
	// 20% + 5 above them is not more than the allowance
	store.add(day, reconcileNetworkId(2), 125, 100)
	// and 20% alone is not either
	store.add(day, reconcileNetworkId(3), 120, 100)
	result := reconcile.Pass(context.Background(), smtpedgeservice.SmtpReconcileCursor{Day: day}, now)
	if result.Err != nil {
		t.Fatal(result.Err)
	}
	if len(sink.opened) != 1 || sink.opened[0].NetworkId != reconcileNetworkId(1) || result.ExceededCount != 1 || result.JudgedCount != 3 {
		t.Fatalf("opened %d cases, judged %d", len(sink.opened), result.JudgedCount)
	}
	if sink.opened[0].ReportedMessageCount != 126 || sink.opened[0].ProvenRecipientCount != 100 || !sink.opened[0].Day.Equal(day) {
		t.Fatalf("the case's day %+v", sink.opened[0])
	}
}

// One connection's message to ten recipients is ten reported messages, which its ten proven recipients meet, and
// a reporter that counts a few more stays inside the allowance (RFC 9990 §3.1.1.8).
func TestSmtpReconcileOneConnectionTenRecipientsRaisesNothing(t *testing.T) {
	reconcile, store, sink, now := newReconcileWorld(t, nil)
	day := time.Date(2031, 3, 10, 0, 0, 0, 0, time.UTC)
	store.add(day, reconcileNetworkId(1), 10, 10)
	store.add(day, reconcileNetworkId(2), 17, 10)
	// a connection count of one would have flagged both
	result := reconcile.Pass(context.Background(), smtpedgeservice.SmtpReconcileCursor{Day: day}, now)
	if result.Err != nil || len(sink.opened) != 0 || result.JudgedCount != 2 {
		t.Fatalf("opened %d cases, judged %d, %v", len(sink.opened), result.JudgedCount, result.Err)
	}
	// with no proven send at all, the floor still allows 5
	settings := smtpedgeservice.DefaultSmtpReconcileSettings()
	if settings.Exceeds(&smtpedgeservice.SmtpReconcileDay{ReportedMessageCount: 5}) || !settings.Exceeds(&smtpedgeservice.SmtpReconcileDay{ReportedMessageCount: 6}) {
		t.Fatal("the floor over no sends")
	}
}

// Counts near the largest neither wrap nor make a signal of a day that does not exceed.
func TestSmtpReconcileThresholdSaturates(t *testing.T) {
	settings := smtpedgeservice.DefaultSmtpReconcileSettings()
	if settings.Exceeds(&smtpedgeservice.SmtpReconcileDay{ReportedMessageCount: math.MaxUint64, ProvenRecipientCount: math.MaxUint64 - 1}) {
		t.Fatal("a wrapped allowance")
	}
	if !settings.Exceeds(&smtpedgeservice.SmtpReconcileDay{ReportedMessageCount: math.MaxUint64, ProvenRecipientCount: 1}) {
		t.Fatal("a large count over a small one")
	}
}

// A day not yet settled is not read; one past MaxDayAge, whose sends may be gone, is skipped, its networks read as
// nothing; and a caught-up cursor waits at the next day to settle.
func TestSmtpReconcileJudgesOnlySettledDaysWithTheirSends(t *testing.T) {
	settings := smtpedgeservice.DefaultSmtpReconcileSettings()
	// the 22 days from the oldest judged to the newest settled in one pass
	settings.PassPageCount = 30
	reconcile, store, sink, now := newReconcileWorld(t, settings)
	settled := time.Date(2031, 3, 10, 0, 0, 0, 0, time.UTC)
	unsettled := time.Date(2031, 3, 11, 0, 0, 0, 0, time.UTC)
	tooOld := time.Date(2031, 2, 15, 0, 0, 0, 0, time.UTC)
	store.add(settled, reconcileNetworkId(1), 100, 0)
	store.add(unsettled, reconcileNetworkId(2), 100, 0)
	store.add(tooOld, reconcileNetworkId(3), 100, 0)
	result := reconcile.Pass(context.Background(), smtpedgeservice.SmtpReconcileCursor{Day: tooOld}, now)
	if result.Err != nil || result.More {
		t.Fatalf("%v, more %t", result.Err, result.More)
	}
	if len(sink.opened) != 1 || sink.opened[0].NetworkId != reconcileNetworkId(1) {
		t.Fatalf("opened %d cases", len(sink.opened))
	}
	for _, read := range store.reads {
		if read.Before(time.Date(2031, 2, 17, 0, 0, 0, 0, time.UTC)) || read.After(settled) {
			t.Fatalf("read %v", read)
		}
	}
	if !result.Next.Day.Equal(unsettled) || result.Next.AfterNetworkId != (sidecar.Id{}) {
		t.Fatalf("next %+v", result.Next)
	}
	// nothing is read again until the next day settles
	readCount := len(store.reads)
	again := reconcile.Pass(context.Background(), result.Next, now)
	if len(store.reads) != readCount || again.JudgedCount != 0 || !again.Next.Day.Equal(unsettled) {
		t.Fatalf("a caught-up pass read %d", len(store.reads)-readCount)
	}
	later := reconcile.Pass(context.Background(), result.Next, now.Add(24*time.Hour))
	if later.Err != nil || len(sink.opened) != 2 || sink.opened[1].NetworkId != reconcileNetworkId(2) {
		t.Fatalf("the next day: %d cases, %v", len(sink.opened), later.Err)
	}
}

// A pass reads at most PassPageCount pages and says more remains; a read that fails stops the pass at the last
// network finished, and the next pass resumes there, judging no network twice.
func TestSmtpReconcilePassIsBoundedAndResumesAtItsCursor(t *testing.T) {
	settings := smtpedgeservice.DefaultSmtpReconcileSettings()
	settings.PageNetworkCount = 2
	settings.PassPageCount = 2
	reconcile, store, sink, now := newReconcileWorld(t, settings)
	day := time.Date(2031, 3, 10, 0, 0, 0, 0, time.UTC)
	for n := byte(1); n <= 7; n++ {
		store.add(day, reconcileNetworkId(n), 1000, 0)
	}
	first := reconcile.Pass(context.Background(), smtpedgeservice.SmtpReconcileCursor{Day: day}, now)
	if first.Err != nil || !first.More || first.JudgedCount != 4 || first.Next.AfterNetworkId != reconcileNetworkId(4) {
		t.Fatalf("first %+v", first)
	}
	// the second page of the next pass fails
	store.failRead = len(store.reads) + 1
	second := reconcile.Pass(context.Background(), first.Next, now)
	if second.Err == nil || second.JudgedCount != 2 || second.Next.AfterNetworkId != reconcileNetworkId(6) || !second.Next.Day.Equal(day) {
		t.Fatalf("second %+v", second)
	}
	third := reconcile.Pass(context.Background(), second.Next, now)
	if third.Err != nil || third.JudgedCount != 1 || !third.Next.Day.Equal(day.Add(24*time.Hour)) {
		t.Fatalf("third %+v", third)
	}
	if len(sink.opened) != 7 {
		t.Fatalf("opened %d", len(sink.opened))
	}
	for i, opened := range sink.opened {
		if opened.NetworkId != reconcileNetworkId(byte(i+1)) {
			t.Fatalf("case %d names %v", i, opened.NetworkId)
		}
	}
}

// A sink that fails stops the pass before the network counts as judged, so the next pass asks again.
func TestSmtpReconcileFailedCaseIsAskedAgain(t *testing.T) {
	store := newReconcileStore()
	day := time.Date(2031, 3, 10, 0, 0, 0, 0, time.UTC)
	store.add(day, reconcileNetworkId(1), 1000, 0)
	failing := &failingReconcileSink{failCount: 1}
	reconcile, err := smtpedgeservice.NewSmtpReconcile(store, failing, smtpedgeservice.DefaultSmtpReconcileSettings())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2031, 3, 14, 6, 0, 0, 0, time.UTC)
	first := reconcile.Pass(context.Background(), smtpedgeservice.SmtpReconcileCursor{Day: day}, now)
	if first.Err == nil || first.Next.AfterNetworkId != (sidecar.Id{}) || !first.Next.Day.Equal(day) {
		t.Fatalf("first %+v", first)
	}
	second := reconcile.Pass(context.Background(), first.Next, now)
	if second.Err != nil || failing.openedCount != 1 {
		t.Fatalf("second %+v, opened %d", second, failing.openedCount)
	}
}

type failingReconcileSink struct {
	failCount   int
	openedCount int
}

func (self *failingReconcileSink) OpenSmtpReconcileCase(ctx context.Context, day *smtpedgeservice.SmtpReconcileDay) error {
	if 0 < self.failCount {
		self.failCount -= 1
		return errors.New("§21 did not answer")
	}
	self.openedCount += 1
	return nil
}

func TestSmtpReconcileSettingsRefuseWhatCannotRun(t *testing.T) {
	for _, change := range []func(settings *smtpedgeservice.SmtpReconcileSettings){
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.ExcessPercent = -1 },
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.ExcessFloor = -1 },
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.SettleTimeout = 0 },
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.MaxDayAge = settings.SettleTimeout },
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.PageNetworkCount = 0 },
		func(settings *smtpedgeservice.SmtpReconcileSettings) { settings.PassPageCount = 0 },
	} {
		settings := smtpedgeservice.DefaultSmtpReconcileSettings()
		change(settings)
		if _, err := smtpedgeservice.NewSmtpReconcile(newReconcileStore(), &reconcileSink{}, settings); !errors.Is(err, smtpedgeservice.ErrSmtpReconcileSettingsRefused) {
			t.Fatalf("settings %+v: %v", settings, err)
		}
	}
	if _, err := smtpedgeservice.NewSmtpReconcile(nil, &reconcileSink{}, smtpedgeservice.DefaultSmtpReconcileSettings()); err == nil {
		t.Fatal("no store")
	}
}
