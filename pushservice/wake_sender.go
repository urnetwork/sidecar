// §18.7's step 4 and §19.4's push sender (SDK-M8-10; D-SDK-10, D-SDK-16, WK2 to WK4): a continuous loop in
// taskworker, not a job, that reads every {wakeq_<shard>} stream through one consumer group, so an entry has
// one sender, holds what it read in a heap by due time, and at each entry's due settles it:
//
//	age       an entry over MaxAge (60 s) from its hint is dropped: the client resyncs at its next start
//	read      one GetMany of {scp_<C>}ack, tok and tokrev, three keys of one slot (WK1)
//	acked     ack at or past the entry's hint id: the client's stack has the hint, so no wake
//	token     no tok, or one that does not parse: nothing to wake
//	window    {wake_<C>}w SET NX for ClientWindow (10 s), its value the window's start, before any vendor call,
//	          so a sender killed after the send still holds the window (FS-36). A window already held from at
//	          or after the hint folds the entry into that wake (coalesced); one held from before the hint puts
//	          the entry off to the window's end, the one wake at a window's end a hint inside it earns
//	caps      APNs ApnsWindowMaxCount (3) an ApnsWindow (1 h) per device, FCM FcmWindowMaxCount (1) an
//	          FcmWindow (1 min) per device and topic: INCR under {wake_<C>}, expiring within the hour
//	send      the vendor, retried after a 429, a 5xx or no answer at most RetryCount (3) times, backing off from
//	          RetryBackoff, doubling; APNs' 410 or FCM's UNREGISTERED tombstones the client's row only while
//	          its revision is the tokrev read with that token (WakeTokenStore), so a newer registration
//	          survives, and the store applies the tombstone by §18.7's script
//	ack       XACK, whatever came of it; a sender killed before it leaves the entry pending, which a sender
//	          claims (XAUTOCLAIM) once it has idled ClaimMinIdle (30 s), its window still keeping it to one
//	          wake per 10 s
//
// Every key a command names shares one tag: a client's {scp_<C>} or {wake_<C>}, or a shard's {wakeq_<n>},
// so no command or script spans two slots (WK1). Nothing here touches hint state (WK3): only the queue's
// entries are acknowledged, and only {wake_<C>} is written. A wake carries a topic class and a version only
// (WK4, wake_vendor.go). The sender logs no token, and metrics carry platform, topic and result only (I-13).
//
// sidecar.yml's wake switch is asked before each read and each send: while it is off nothing is read, and a
// held entry is acknowledged unsent, so entries age out rather than wake later (§19.11). A process holds
// at most HeldMaxCount entries; past it its readers wait, and a burst stays in the streams, whose MAXLEN
// bounds it. pushservice takes the host's Redis and Metrics and never imports server: WakeTokenStore is
// what server injects (model.TombstonePushTokenIfRevision).
//
// Safe for concurrent use. NewWakeSender starts its goroutines; Close ends them and waits.

package pushservice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
)

// What the sender needs of Redis: ServiceHost.Redis satisfies it. Safe for concurrent use.
type WakeSenderRedis interface {
	// See sidecar.Redis.
	Get(ctx context.Context, key string) (value []byte, found bool, err error)
	// See sidecar.Redis.
	GetMany(ctx context.Context, keys []string) (values [][]byte, err error)
	// See sidecar.Redis.
	SetIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (set bool, err error)
	// See sidecar.Redis.
	Increment(ctx context.Context, key string, ttl time.Duration) (value int64, err error)
	// See sidecar.Redis.
	StreamGroupCreate(ctx context.Context, key string, group string) error
	// See sidecar.Redis.
	StreamGroupRead(ctx context.Context, key string, group string, consumer string, count int64, block time.Duration) (entries []*sidecar.RedisStreamEntry, err error)
	// See sidecar.Redis.
	StreamGroupAck(ctx context.Context, key string, group string, entryIds []string) error
	// See sidecar.Redis.
	StreamGroupClaim(ctx context.Context, key string, group string, consumer string, minIdle time.Duration, cursor string, count int64) (entries []*sidecar.RedisStreamEntry, nextCursor string, err error)
}

// The token rows' store a vendor's rejection writes through: server's model, which the sender cannot import.
// Safe for concurrent use.
type WakeTokenStore interface {
	// Tombstones clientId's sidecar_push_token row only while its rev is revision, the tokrev read with the
	// rejected token, then applies the tombstone by WakeTokenApplyScript (§18.7's steps 0 and 4). Answers
	// whether it tombstoned: false for a row at another revision, already a tombstone, or absent.
	TombstoneIfRevision(ctx context.Context, clientId connect.Id, revision int64) (bool, error)
}

// How one entry settled, as metrics' result label names it.
type WakeSettledResult string

const (
	// The vendor accepted the wake.
	WakeSettledSent WakeSettledResult = "sent"
	// The vendor said the token is gone; the row was tombstoned if still at the revision read with it.
	WakeSettledUnregistered WakeSettledResult = "unregistered"
	// The vendor refused it for good.
	WakeSettledRefused WakeSettledResult = "refused"
	// The vendor still failed after every retry.
	WakeSettledGivenUp WakeSettledResult = "given_up"
	// The client's stack acked the hint first.
	WakeSettledAcked WakeSettledResult = "acked"
	// No token, or one this sender cannot parse.
	WakeSettledNoToken WakeSettledResult = "no_token"
	// No vendor for the token's platform in this process.
	WakeSettledNoVendor WakeSettledResult = "no_vendor"
	// A wake at or after the hint covers it (§19.4's per-client window).
	WakeSettledCoalesced WakeSettledResult = "coalesced"
	// A vendor cap held it (§19.4's rate row).
	WakeSettledCapped WakeSettledResult = "capped"
	// Older than MaxAge.
	WakeSettledExpired WakeSettledResult = "expired"
	// An entry this package did not write.
	WakeSettledMalformed WakeSettledResult = "malformed"
	// sidecar.yml's wake switch was off.
	WakeSettledGated WakeSettledResult = "gated"
)

// One entry's settlement, as WakeSenderArgs.Settled hears it. Carries no token.
type WakeSettled struct {
	StreamKey string
	EntryId   string
	ClientId  connect.Id
	// apns, fcm, or empty where the token was never read.
	Platform   string
	TopicClass string
	Result     WakeSettledResult
	// The vendor's last status, 0 for none.
	Status int
	// Whether the entry was acknowledged: false where the ack failed, as when the sender is killed.
	Acked bool
}

// What NewWakeSender takes.
type WakeSenderArgs struct {
	Redis WakeSenderRedis
	// Server's token rows. Nil tombstones nothing on a vendor's rejection, which then only counts.
	Tokens WakeTokenStore
	// One vendor per platform, as the process holds keys for: none sends nothing, every entry settling
	// no_vendor once read.
	Vendors []WakeVendor
	// This process's consumer name in the group, unique among the senders running.
	Consumer string
	// sidecar.yml's wake switch, asked before each read and send. Nil is always off, the closed default.
	Enabled func() bool
	// Nil is real time.
	Clock sidecar.Clock
	// Nil counts nothing.
	Metrics sidecar.Metrics
	// Nil logs nothing.
	Log sidecar.Logger
	// Nil takes DefaultWakeSenderSettings.
	Settings *WakeSenderSettings
	// Told each settlement on the worker that made it, nil for none. It must not block: what FS-36's
	// schedules and the tests watch.
	Settled func(settled *WakeSettled)
}

// What a sender has counted, by result.
type WakeSenderStats struct {
	Settled map[WakeSettledResult]uint64
	// Entries read and claimed, and those a claim found already held.
	ReadCount      uint64
	ClaimedCount   uint64
	VendorAttempts uint64
	// Held now.
	HeldCount int
}

// The push sender. NewWakeSender makes one.
type WakeSender struct {
	ctx      context.Context
	cancel   context.CancelFunc
	redis    WakeSenderRedis
	tokens   WakeTokenStore
	vendors  map[string]WakeVendor
	consumer string
	enabled  func() bool
	clock    sidecar.Clock
	log      sidecar.Logger
	settings *WakeSenderSettings
	settled  func(settled *WakeSettled)
	// nil when the host gave no Metrics
	settledCounter sidecar.MetricsCounter
	heldGauge      sidecar.MetricsGauge
	work           chan *wakeHeldEntry
	// wakes the dispatcher, buffered by one so a wake never blocks and two read as one
	dispatchWake chan struct{}
	lifetime     sync.WaitGroup

	stateLock sync.Mutex
	held      *wakeHeap
	// closed and replaced each time an entry is let go, so a reader waiting for room hears it
	roomChanged    chan struct{}
	settledCounts  map[WakeSettledResult]uint64
	readCount      uint64
	claimedCount   uint64
	vendorAttempts atomic.Uint64
}

// A sender on args, its readers, claimer, dispatcher and workers running until ctx ends or Close. Refuses
// args missing Redis or a consumer, and settings out of range.
func NewWakeSender(ctx context.Context, args *WakeSenderArgs) (*WakeSender, error) {
	if args == nil || args.Redis == nil || args.Consumer == "" {
		return nil, fmt.Errorf("%w: a sender needs Redis and a consumer name", ErrWakeSenderSettings)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultWakeSenderSettings()
	}
	if err := settings.validate(); err != nil {
		return nil, err
	}
	vendors := map[string]WakeVendor{}
	for _, vendor := range args.Vendors {
		platform := vendor.Platform()
		if platform != WakePlatformApns && platform != WakePlatformFcm || vendors[platform] != nil {
			return nil, fmt.Errorf("%w: one vendor a platform, apns or fcm", ErrWakeSenderSettings)
		}
		vendors[platform] = vendor
	}
	clock := args.Clock
	if clock == nil {
		clock = sidecar.RealClock{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	enabled := args.Enabled
	if enabled == nil {
		enabled = func() bool { return false }
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &WakeSender{
		ctx:           cancelCtx,
		cancel:        cancel,
		redis:         args.Redis,
		tokens:        args.Tokens,
		vendors:       vendors,
		consumer:      args.Consumer,
		enabled:       enabled,
		clock:         clock,
		log:           log,
		settings:      settings,
		settled:       args.Settled,
		work:          make(chan *wakeHeldEntry),
		dispatchWake:  make(chan struct{}, 1),
		held:          newWakeHeap(),
		roomChanged:   make(chan struct{}),
		settledCounts: map[WakeSettledResult]uint64{},
	}
	if args.Metrics != nil {
		self.settledCounter = args.Metrics.Counter("urnetwork_wake_settled_total", "wake-queue entries the push sender settled (§19.4)", "platform", "topic", "result")
		self.heldGauge = args.Metrics.Gauge("urnetwork_wake_held", "wake-queue entries the push sender holds (§19.4)")
	}
	for shard := range settings.Queue.ShardCount {
		self.lifetime.Go(func() { self.runReader(WakeQueueKey(shard)) })
	}
	// the first claim's timer is set here, so the claims fall at whole ClaimIntervals from the sender's start
	firstClaim := clock.After(settings.ClaimInterval)
	self.lifetime.Go(func() { self.runClaimer(firstClaim) })
	self.lifetime.Go(self.runDispatcher)
	for range settings.SendConcurrency {
		self.lifetime.Go(self.runWorker)
	}
	return self, nil
}

// Ends the sender and waits for its goroutines. An entry held and not acknowledged stays pending in its
// group, for a sender to claim.
func (self *WakeSender) Close() {
	self.cancel()
	self.lifetime.Wait()
}

// What the sender has counted.
func (self *WakeSender) Stats() WakeSenderStats {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	settled := make(map[WakeSettledResult]uint64, len(self.settledCounts))
	for result, count := range self.settledCounts {
		settled[result] = count
	}
	return WakeSenderStats{
		Settled:        settled,
		ReadCount:      self.readCount,
		ClaimedCount:   self.claimedCount,
		VendorAttempts: self.vendorAttempts.Load(),
		HeldCount:      self.held.heldCount(),
	}
}

// Waits timeout on the sender's clock, false once the sender ended first.
func (self *WakeSender) wait(timeout time.Duration) bool {
	select {
	case <-self.ctx.Done():
		return false
	case <-self.clock.After(timeout):
		return true
	}
}

// Wakes the dispatcher without waiting.
func (self *WakeSender) wakeDispatcher() {
	select {
	case self.dispatchWake <- struct{}{}:
	default:
	}
}

// One shard's reads until the sender ends: the group made, then XREADGROUP while the switch is on and the
// process has room, each entry held until due.
func (self *WakeSender) runReader(streamKey string) {
	groupReady := false
	for self.ctx.Err() == nil {
		if !self.enabled() {
			if !self.wait(self.settings.GateInterval) {
				return
			}
			continue
		}
		if !groupReady {
			if err := self.redis.StreamGroupCreate(self.ctx, streamKey, self.settings.ConsumerGroup); err != nil {
				if !self.wait(self.settings.ErrorBackoff) {
					return
				}
				continue
			}
			groupReady = true
		}
		room, roomChanged := func() (int, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.settings.HeldMaxCount - self.held.heldCount(), self.roomChanged
		}()
		if room <= 0 {
			select {
			case <-self.ctx.Done():
				return
			case <-roomChanged:
			}
			continue
		}
		entries, err := self.redis.StreamGroupRead(self.ctx, streamKey, self.settings.ConsumerGroup, self.consumer, min(self.settings.ReadCount, int64(room)), self.settings.ReadBlock)
		if err != nil {
			if self.ctx.Err() != nil {
				return
			}
			// the group may be gone with its stream: made again before the next read
			groupReady = false
			if !self.wait(self.settings.ErrorBackoff) {
				return
			}
			continue
		}
		testHookBarrier("pushservice.wake_sender.read", streamKey)
		self.hold(streamKey, entries, false)
	}
}

// Holds entries read or claimed from streamKey until due; one malformed is acknowledged and dropped, and
// one already held is held once.
func (self *WakeSender) hold(streamKey string, entries []*sidecar.RedisStreamEntry, claimed bool) {
	malformed := []*wakeHeldEntry{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, streamEntry := range entries {
			if claimed {
				self.claimedCount += 1
			} else {
				self.readCount += 1
			}
			entry, err := ParseWakeEntry(streamEntry)
			if err != nil {
				malformed = append(malformed, &wakeHeldEntry{streamKey: streamKey, entryId: streamEntry.Id, index: -1})
				continue
			}
			self.held.add(&wakeHeldEntry{streamKey: streamKey, entryId: streamEntry.Id, entry: entry, dueMs: entry.DueMs, index: -1})
		}
		self.publishHeldWithLock()
	}()
	for _, held := range malformed {
		self.finish(held, &WakeSettled{Result: WakeSettledMalformed})
	}
	if 0 < len(entries) {
		self.wakeDispatcher()
	}
}

// The held gauge, under stateLock.
func (self *WakeSender) publishHeldWithLock() {
	if self.heldGauge != nil {
		self.heldGauge.Set(float64(self.held.heldCount()))
	}
}

// Claims each shard's entries idle ClaimMinIdle every ClaimInterval until the sender ends, from next, the
// first: a sender killed before its XACK left them pending (§19.4's input row). Each pass's next timer is set
// before the pass, so a slow pass moves no later one.
func (self *WakeSender) runClaimer(next <-chan time.Time) {
	for {
		select {
		case <-self.ctx.Done():
			return
		case <-next:
		}
		next = self.clock.After(self.settings.ClaimInterval)
		if !self.enabled() {
			continue
		}
		for shard := range self.settings.Queue.ShardCount {
			self.claimShard(WakeQueueKey(shard))
		}
	}
}

// One pass of XAUTOCLAIM over streamKey's pending list, to its end.
func (self *WakeSender) claimShard(streamKey string) {
	cursor := ""
	for self.ctx.Err() == nil {
		entries, nextCursor, err := self.redis.StreamGroupClaim(self.ctx, streamKey, self.settings.ConsumerGroup, self.consumer, self.settings.ClaimMinIdle, cursor, self.settings.ReadCount)
		if err != nil {
			// the next pass tries again; a missing group is the reader's to make
			return
		}
		if 0 < len(entries) {
			testHookBarrier("pushservice.wake_sender.claim", streamKey)
			self.hold(streamKey, entries, true)
		}
		if nextCursor == "" || nextCursor == "0-0" {
			return
		}
		cursor = nextCursor
	}
}

// Hands each due entry to a worker, waiting for the next due on the sender's clock or for a new entry.
func (self *WakeSender) runDispatcher() {
	for self.ctx.Err() == nil {
		nowMs := self.clock.Now().UnixMilli()
		held, nextDueMs, waiting := func() (*wakeHeldEntry, int64, bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if held := self.held.popDue(nowMs); held != nil {
				return held, 0, false
			}
			nextDueMs, waiting := self.held.nextDueMs()
			return nil, nextDueMs, waiting
		}()
		if held != nil {
			select {
			case <-self.ctx.Done():
				return
			case self.work <- held:
			}
			continue
		}
		stop := func() bool { return false }
		if waiting {
			stop = self.clock.AfterFunc(time.Duration(nextDueMs-nowMs)*time.Millisecond, self.wakeDispatcher)
		}
		select {
		case <-self.ctx.Done():
			stop()
			return
		case <-self.dispatchWake:
			stop()
		}
	}
}

// Settles due entries until the sender ends.
func (self *WakeSender) runWorker() {
	for {
		select {
		case <-self.ctx.Done():
			return
		case held := <-self.work:
			self.settle(held)
		}
	}
}

// Puts held off to atMs, or past MaxAge settles it expired. A time not after now, as a window's end another
// host's clock set, waits ErrorBackoff, so a key that outlives its end on this clock never spins a worker.
func (self *WakeSender) requeue(held *wakeHeldEntry, atMs int64) {
	if nowMs := self.clock.Now().UnixMilli(); atMs <= nowMs {
		atMs = nowMs + self.settings.ErrorBackoff.Milliseconds()
	}
	if self.settings.MaxAge.Milliseconds() < atMs-held.entry.HintMs {
		self.finish(held, &WakeSettled{ClientId: held.entry.ClientId, TopicClass: held.entry.TopicClass, Result: WakeSettledExpired})
		return
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.held.requeue(held, atMs)
	}()
	self.wakeDispatcher()
}

// One due entry: see the file's comment.
func (self *WakeSender) settle(held *wakeHeldEntry) {
	entry := held.entry
	clientId := entry.ClientId
	now := self.clock.Now()
	settled := &WakeSettled{ClientId: clientId, TopicClass: entry.TopicClass}
	if self.settings.MaxAge.Milliseconds() < now.UnixMilli()-entry.HintMs {
		settled.Result = WakeSettledExpired
		self.finish(held, settled)
		return
	}
	if !self.enabled() {
		settled.Result = WakeSettledGated
		self.finish(held, settled)
		return
	}
	retryLater := func() {
		self.requeue(held, now.Add(self.settings.ErrorBackoff).UnixMilli())
	}
	values, err := self.redis.GetMany(self.ctx, []string{HintAckKey(clientId), HintTokenKey(clientId), WakeTokenRevisionKey(clientId)})
	if err != nil || len(values) != 3 {
		retryLater()
		return
	}
	if ack := values[0]; ack != nil {
		if order, err := CompareStreamId(string(ack), entry.StreamId); err == nil && 0 <= order {
			settled.Result = WakeSettledAcked
			self.finish(held, settled)
			return
		}
	}
	platform, token, ok := ParseWakeTokenValue(values[1])
	if !ok {
		settled.Result = WakeSettledNoToken
		self.finish(held, settled)
		return
	}
	settled.Platform = platform
	// the revision the token was read at, 0 when tokrev does not parse, which tombstones nothing
	revision, err := strconv.ParseInt(string(values[2]), 10, 64)
	if err != nil || revision < 1 || WakeTokenMaxRevision < revision {
		revision = 0
	}
	vendor := self.vendors[platform]
	if vendor == nil {
		settled.Result = WakeSettledNoVendor
		self.finish(held, settled)
		return
	}

	// one wake a client a window, the window set before the vendor call (FS-36)
	windowStartMs, acquired, err := self.acquireWindow(clientId, now)
	if err != nil {
		retryLater()
		return
	}
	if !acquired {
		if entry.HintMs <= windowStartMs {
			settled.Result = WakeSettledCoalesced
			self.finish(held, settled)
			return
		}
		held.windowDeferred = true
		self.requeue(held, windowStartMs+self.settings.ClientWindow.Milliseconds())
		return
	}

	capped, err := self.capped(clientId, platform, entry.TopicClass)
	if err != nil {
		// the window is taken and the cap unknown: no wake, since a cap that cannot be read cannot be kept
		settled.Result = WakeSettledCapped
		self.finish(held, settled)
		return
	}
	if capped {
		settled.Result = WakeSettledCapped
		self.finish(held, settled)
		return
	}

	payload := &WakePayload{TopicClass: entry.TopicClass, Version: entry.Version}
	result := self.submit(vendor, token, payload, clientId)
	settled.Status = result.Status
	switch result.Outcome {
	case WakeVendorSent:
		settled.Result = WakeSettledSent
	case WakeVendorUnregistered:
		settled.Result = WakeSettledUnregistered
		if self.tokens != nil && revision != 0 {
			if _, err := self.tokens.TombstoneIfRevision(self.ctx, clientId, revision); err != nil {
				self.log.Warningf("[wake]a vendor's rejection was not tombstoned: %v", err)
			}
		}
	case WakeVendorRetry:
		settled.Result = WakeSettledGivenUp
	default:
		settled.Result = WakeSettledRefused
	}
	self.finish(held, settled)
}

// Takes clientId's window at now, answering its start: now's when taken, else the start the holder wrote.
func (self *WakeSender) acquireWindow(clientId connect.Id, now time.Time) (int64, bool, error) {
	key := WakeWindowKey(clientId)
	nowMs := now.UnixMilli()
	for range 2 {
		testHookBarrier("pushservice.wake_sender.window", clientId.String())
		set, err := self.redis.SetIfAbsent(self.ctx, key, []byte(strconv.FormatInt(nowMs, 10)), self.settings.ClientWindow)
		testHookBarrier("pushservice.wake_sender.window_set", clientId.String())
		if err != nil {
			return 0, false, err
		}
		if set {
			return nowMs, true, nil
		}
		value, found, err := self.redis.Get(self.ctx, key)
		if err != nil {
			return 0, false, err
		}
		if !found {
			// it lapsed between the two: take it again
			continue
		}
		startMs, err := strconv.ParseInt(string(value), 10, 64)
		if err != nil {
			// a window this package did not write: as held from now, which puts the entry off
			return nowMs, false, nil
		}
		return startMs, false, nil
	}
	return 0, false, errors.New("wake sender: the window lapsed twice while read")
}

// Whether a vendor cap holds the wake: APNs' per device, FCM's per device and topic, each an INCR under
// {wake_<C>} with its window's ttl.
func (self *WakeSender) capped(clientId connect.Id, platform string, topicClass string) (bool, error) {
	key, window, maxCount := WakeApnsCapKey(clientId), self.settings.ApnsWindow, self.settings.ApnsWindowMaxCount
	if platform == WakePlatformFcm {
		key, window, maxCount = WakeFcmCapKey(clientId, topicClass), self.settings.FcmWindow, self.settings.FcmWindowMaxCount
	}
	count, err := self.redis.Increment(self.ctx, key, window)
	if err != nil {
		return false, err
	}
	return maxCount < count, nil
}

// The vendor's answer to one wake, after at most RetryCount retries of a 429, a 5xx or no answer, the
// n-th after RetryBackoff times 2^(n-1), or the vendor's Retry-After where that is longer.
func (self *WakeSender) submit(vendor WakeVendor, token string, payload *WakePayload, clientId connect.Id) *WakeVendorResult {
	backoff := self.settings.RetryBackoff
	var result *WakeVendorResult
	for attempt := 0; ; attempt += 1 {
		self.vendorAttempts.Add(1)
		testHookBarrier("pushservice.wake_sender.send", clientId.String())
		result = vendor.Send(self.ctx, token, payload)
		testHookBarrier("pushservice.wake_sender.sent", clientId.String())
		if result == nil {
			result = &WakeVendorResult{Outcome: WakeVendorRetry}
		}
		if result.Outcome != WakeVendorRetry || self.settings.RetryCount <= attempt {
			return result
		}
		wait := max(backoff, result.RetryAfter)
		backoff *= 2
		if !self.wait(wait) {
			return result
		}
	}
}

// Acknowledges held, lets it go and tells what came of it. An ack that fails, as at a kill, leaves the entry
// pending for a claim.
func (self *WakeSender) finish(held *wakeHeldEntry, settled *WakeSettled) {
	testHookBarrier("pushservice.wake_sender.ack", held.entryId)
	err := self.redis.StreamGroupAck(self.ctx, held.streamKey, self.settings.ConsumerGroup, []string{held.entryId})
	settled.StreamKey, settled.EntryId, settled.Acked = held.streamKey, held.entryId, err == nil
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.held.release(held)
		self.settledCounts[settled.Result] += 1
		self.publishHeldWithLock()
		close(self.roomChanged)
		self.roomChanged = make(chan struct{})
	}()
	if self.settledCounter != nil {
		platform := settled.Platform
		if platform == "" {
			platform = "none"
		}
		topicClass := settled.TopicClass
		if topicClass == "" {
			topicClass = "none"
		}
		self.settledCounter.Add(1, platform, topicClass, string(settled.Result))
	}
	if self.settled != nil {
		self.settled(settled)
	}
}

// {wake_<C>}w: the client's window, its value the window's start in unix milliseconds (§19.4's rate row).
func WakeWindowKey(clientId connect.Id) string {
	return "{wake_" + clientId.String() + "}w"
}

// {wake_<C>}apns: the client's APNs wakes in the current ApnsWindow.
func WakeApnsCapKey(clientId connect.Id) string {
	return "{wake_" + clientId.String() + "}apns"
}

// {wake_<C>}fcm_<topic class>: the client's FCM wakes of one topic class in the current FcmWindow.
func WakeFcmCapKey(clientId connect.Id, topicClass string) string {
	return "{wake_" + clientId.String() + "}fcm_" + topicClass
}
