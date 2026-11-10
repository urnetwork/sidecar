//go:build !sidecar_http && !ios_extension

// The one usage producer (§20.6): evs, tlsedge, mxedge, smtpedge and taskworker each run one, adding
// metered bytes as they move and stored-byte deltas as they land. Every WindowTimeout it closes its
// window into batches of at most QuotaUsageBatchMaxEventCount events, each with the id
// NewUsageBatchId(this process's instance, its sequence), and sends them through Quota.ReportUsage. A
// batch without an answer is retried under its own id, so api applies it once however many times it
// arrives, until RetryHorizon after its window closed; then it is dropped, counted in
// urnetwork_quota_usage_batches_dropped_total and urnetwork_quota_usage_dropped_bytes_total, which alert:
// under-billing, never double-billing. Drain sends the open window at once, as SIGTERM asks; a kill loses
// the open window and whatever is still unanswered, at most a minute of this process's metered bytes
// while api answers (FI-13(a)).
//
// evsservice.UsageBatcher and the edges' lease files wrap this rather than repeat it. Safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/connect"
)

// Tunables of a QuotaUsageBatcher.
type QuotaUsageBatcherSettings struct {
	// How long a window gathers usage before it is sent: §20.6's 60 s. Must be positive.
	WindowTimeout time.Duration
	// How long after its window closed a batch is still retried before it is dropped: §20.6's 10 min.
	// Non-positive drops a batch at its first failure.
	RetryHorizon time.Duration
	// The wait after a failed send before the next, which every batch then due shares, so an api that is
	// down sees one attempt per wait. Must be positive.
	RetryTimeout time.Duration
	// Bounds one ReportUsage call on the batcher's clock, so a hung call counts as a failure. Non-positive
	// leaves the call to the batcher's context.
	ReportTimeout time.Duration
}

// §20.6's 60 s windows and 10 min horizon.
func DefaultQuotaUsageBatcherSettings() *QuotaUsageBatcherSettings {
	return &QuotaUsageBatcherSettings{
		WindowTimeout: 60 * time.Second,
		RetryHorizon:  10 * time.Minute,
		RetryTimeout:  5 * time.Second,
		ReportTimeout: 30 * time.Second,
	}
}

// What the batcher counts, by producer.
const (
	quotaUsageBatchesDroppedMetricName = "urnetwork_quota_usage_batches_dropped_total"
	quotaUsageDroppedBytesMetricName   = "urnetwork_quota_usage_dropped_bytes_total"
	quotaUsageSendFailuresMetricName   = "urnetwork_quota_usage_send_failures_total"
)

// What an add answers once Close has run: the bytes would never be sent.
var ErrQuotaUsageBatcherClosed = errors.New("the usage batcher is closed")

// One event of the open window: a network's usage on a meter.
type quotaUsageEventKey struct {
	networkId connect.Id
	meter     string
}

// One batch cut from a window, until api answers it or it is dropped.
type quotaUsageSend struct {
	batch *UsageBatch
	// when its window closed: the retry horizon runs from here
	cutTime      time.Time
	nextSendTime time.Time
	attemptCount int
	// what dropping it loses, for the metric
	transferByteCount int64
}

// See the file header.
type QuotaUsageBatcher struct {
	ctx      context.Context
	cancel   context.CancelFunc
	quota    Quota
	clock    Clock
	producer string
	settings *QuotaUsageBatcherSettings
	// 16 random bytes drawn at construction, which every batch id of this process hashes
	instanceId          [16]byte
	droppedBatchCounter MetricsCounter
	droppedByteCounter  MetricsCounter
	failedSendCounter   MetricsCounter
	// wakes run before its timer: a drain asking for the open window
	wake chan struct{}
	done chan struct{}

	stateLock   sync.Mutex
	windowStart time.Time
	keyEvents   map[quotaUsageEventKey]*UsageEvent
	windowSeq   uint64
	// cut and unanswered, oldest first but for a failed send, which goes to the back
	sends      []*quotaUsageSend
	drainCount int
	// closed and replaced at the end of each of run's rounds, for Drain
	roundDone chan struct{}
}

// A running batcher for producer, one of the QuotaProducer names, sending through host.Quota, counting
// in host.Metrics and timing its windows on host.Clock. settings nil takes the defaults. It runs until
// ctx ends or Close.
func NewQuotaUsageBatcher(ctx context.Context, host *ServiceHost, producer string, settings *QuotaUsageBatcherSettings) (*QuotaUsageBatcher, error) {
	if settings == nil {
		settings = DefaultQuotaUsageBatcherSettings()
	}
	if host == nil || host.Quota == nil {
		return nil, errors.New("the usage batcher needs ServiceHost.Quota")
	}
	if !IsQuotaProducer(producer) {
		return nil, fmt.Errorf("no producer %q", producer)
	}
	if settings.WindowTimeout <= 0 || settings.RetryTimeout <= 0 {
		return nil, errors.New("the usage batcher needs a positive window and retry timeout")
	}
	var instanceId [16]byte
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(instanceId[:])
	clock := host.ClockOrReal()
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &QuotaUsageBatcher{
		ctx:         cancelCtx,
		cancel:      cancel,
		quota:       host.Quota,
		clock:       clock,
		producer:    producer,
		settings:    settings,
		instanceId:  instanceId,
		wake:        make(chan struct{}, 1),
		done:        make(chan struct{}),
		windowStart: clock.Now(),
		keyEvents:   map[quotaUsageEventKey]*UsageEvent{},
		roundDone:   make(chan struct{}),
	}
	if host.Metrics != nil {
		self.droppedBatchCounter = host.Metrics.Counter(
			quotaUsageBatchesDroppedMetricName,
			"Usage batches dropped unanswered past the retry horizon, which nothing bills.",
			"producer",
		)
		self.droppedByteCounter = host.Metrics.Counter(
			quotaUsageDroppedBytesMetricName,
			"Transfer bytes in usage batches dropped unanswered, which nothing bills.",
			"producer",
		)
		self.failedSendCounter = host.Metrics.Counter(
			quotaUsageSendFailuresMetricName,
			"Usage batch sends that failed and will be retried under the same id.",
			"producer",
		)
	}
	go self.run()
	return self, nil
}

// The open window's event for a network and meter.
func (self *QuotaUsageBatcher) eventWithLock(networkId connect.Id, meter string) *UsageEvent {
	key := quotaUsageEventKey{networkId: networkId, meter: meter}
	event, ok := self.keyEvents[key]
	if !ok {
		event = &UsageEvent{NetworkId: networkId, Meter: meter}
		self.keyEvents[key] = event
	}
	return event
}

// Counts byteCount on meter for networkId, the caller's network for transfer (§20.6). A zero network, an
// unknown meter or a negative count is the caller's bug, and counts nothing.
func (self *QuotaUsageBatcher) AddTransfer(networkId connect.Id, meter string, byteCount int64) error {
	if networkId == (connect.Id{}) {
		return errors.New("a zero network id")
	}
	if !IsQuotaMeter(meter) {
		return fmt.Errorf("no meter %q", meter)
	}
	if byteCount < 0 {
		return fmt.Errorf("a negative transfer %d", byteCount)
	}
	if self.ctx.Err() != nil {
		return ErrQuotaUsageBatcherClosed
	}
	if byteCount == 0 {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.eventWithLock(networkId, meter).TransferByteCount += byteCount
	return nil
}

// Moves networkId's stored count, the repo's network, by byteDelta, negative when content is freed
// (§20.7). It rides evs's meter, which storage counts on.
func (self *QuotaUsageBatcher) AddStoredDelta(networkId connect.Id, byteDelta int64) error {
	if networkId == (connect.Id{}) {
		return errors.New("a zero network id")
	}
	if self.ctx.Err() != nil {
		return ErrQuotaUsageBatcherClosed
	}
	if byteDelta == 0 {
		return nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.eventWithLock(networkId, QuotaMeterEvs).StoredByteDelta += byteDelta
	return nil
}

// Sends the open window now and returns once every batch is answered or dropped, or ctx ends first. For
// SIGTERM: an engine's Drain calls it, then Close. Adds that arrive meanwhile are sent too.
func (self *QuotaUsageBatcher) Drain(ctx context.Context) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drainCount += 1
	}()
	defer func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.drainCount -= 1
	}()
	for {
		var open bool
		var unanswered bool
		var roundDone chan struct{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			open = 0 < len(self.keyEvents)
			unanswered = 0 < len(self.sends)
			roundDone = self.roundDone
		}()
		if !open && !unanswered {
			return nil
		}
		if open {
			self.signalWake()
		}
		select {
		case <-roundDone:
		case <-ctx.Done():
			return ctx.Err()
		case <-self.done:
			return ErrQuotaUsageBatcherClosed
		}
	}
}

// Stops at once, as a kill would: the open window and every unanswered batch are lost. Returns once run
// has. Safe more than once.
func (self *QuotaUsageBatcher) Close() {
	self.cancel()
	<-self.done
}

// Wakes run for a round, unless a wake already waits.
func (self *QuotaUsageBatcher) signalWake() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Each round cuts a window that is due, sends what is due, and waits for the next of the two.
func (self *QuotaUsageBatcher) run() {
	defer close(self.done)
	for {
		self.cutDue()
		self.sendDue()
		timeout := self.finishRound()
		stop := self.clock.AfterFunc(timeout, self.signalWake)
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-self.wake:
			stop()
		}
	}
}

// Closes the window into batches when it is due or a drain waits, and restarts an empty one.
func (self *QuotaUsageBatcher) cutDue() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	now := self.clock.Now()
	due := !now.Before(self.windowStart.Add(self.settings.WindowTimeout))
	if len(self.keyEvents) == 0 {
		if due {
			self.windowStart = now
		}
		return
	}
	if !due && self.drainCount == 0 {
		return
	}
	events := []*UsageEvent{}
	for _, event := range self.keyEvents {
		if event.TransferByteCount != 0 || event.StoredByteDelta != 0 {
			events = append(events, event)
		}
	}
	// a fixed order, so a window's batches read the same in every trace
	slices.SortFunc(events, func(a *UsageEvent, b *UsageEvent) int {
		if c := bytes.Compare(a.NetworkId[:], b.NetworkId[:]); c != 0 {
			return c
		}
		return cmp.Compare(a.Meter, b.Meter)
	})
	for from := 0; from < len(events); from += QuotaUsageBatchMaxEventCount {
		chunk := events[from:min(from+QuotaUsageBatchMaxEventCount, len(events))]
		self.windowSeq += 1
		transferByteCount := int64(0)
		for _, event := range chunk {
			transferByteCount += event.TransferByteCount
		}
		self.sends = append(self.sends, &quotaUsageSend{
			batch: &UsageBatch{
				BatchId:     NewUsageBatchId(self.instanceId, self.windowSeq),
				Producer:    self.producer,
				WindowStart: self.windowStart,
				Events:      chunk,
			},
			cutTime:           now,
			nextSendTime:      now,
			transferByteCount: transferByteCount,
		})
	}
	self.keyEvents = map[quotaUsageEventKey]*UsageEvent{}
	self.windowStart = now
}

// Sends each batch that is due, oldest first, dropping one past its horizon. One failure ends the round:
// every batch then due waits RetryTimeout, and the failed one goes to the back, so a batch api keeps
// refusing holds no other up.
func (self *QuotaUsageBatcher) sendDue() {
	for {
		var send *quotaUsageSend
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			now := self.clock.Now()
			for {
				index := slices.IndexFunc(self.sends, func(send *quotaUsageSend) bool {
					return !now.Before(send.nextSendTime)
				})
				if index < 0 {
					return
				}
				candidate := self.sends[index]
				if 0 < candidate.attemptCount && self.settings.RetryHorizon <= now.Sub(candidate.cutTime) {
					self.sends = slices.Delete(self.sends, index, index+1)
					self.countDroppedWithLock(candidate)
					continue
				}
				candidate.attemptCount += 1
				send = candidate
				return
			}
		}()
		if send == nil {
			return
		}
		err := self.report(send.batch)
		failed := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			index := slices.Index(self.sends, send)
			if err == nil {
				self.sends = slices.Delete(self.sends, index, index+1)
				return
			}
			failed = true
			if self.failedSendCounter != nil {
				self.failedSendCounter.Add(1, self.producer)
			}
			now := self.clock.Now()
			retryTime := now.Add(self.settings.RetryTimeout)
			for _, other := range self.sends {
				if !now.Before(other.nextSendTime) {
					other.nextSendTime = retryTime
				}
			}
			send.nextSendTime = retryTime
			self.sends = append(slices.Delete(self.sends, index, index+1), send)
		}()
		if failed || self.ctx.Err() != nil {
			return
		}
	}
}

// Counts a batch dropped past its horizon, and the bytes nothing will bill.
func (self *QuotaUsageBatcher) countDroppedWithLock(send *quotaUsageSend) {
	if self.droppedBatchCounter != nil {
		self.droppedBatchCounter.Add(1, self.producer)
		self.droppedByteCounter.Add(float64(send.transferByteCount), self.producer)
	}
}

// One ReportUsage call, bounded by ReportTimeout on the batcher's clock. No lock is held.
func (self *QuotaUsageBatcher) report(batch *UsageBatch) error {
	testHookBarrier("quota.usage_report.before", self.producer)
	ctx := self.ctx
	if 0 < self.settings.ReportTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithCancel(self.ctx)
		defer cancel()
		stop := self.clock.AfterFunc(self.settings.ReportTimeout, cancel)
		defer stop()
	}
	err := self.quota.ReportUsage(ctx, batch)
	testHookBarrier("quota.usage_report.after", self.producer)
	return err
}

// Ends a round: tells Drain, and answers how long until the window is due or a batch is, zero when a
// drain waits on an open window.
func (self *QuotaUsageBatcher) finishRound() time.Duration {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	close(self.roundDone)
	self.roundDone = make(chan struct{})
	now := self.clock.Now()
	if 0 < self.drainCount && 0 < len(self.keyEvents) {
		return 0
	}
	timeout := self.windowStart.Add(self.settings.WindowTimeout).Sub(now)
	for _, send := range self.sends {
		timeout = min(timeout, send.nextSendTime.Sub(now))
	}
	return max(timeout, 0)
}
