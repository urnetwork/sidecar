// GkmHint intake (§10.14, D-KEYS-19, §6.8), on every leg: what gkm's hints wake in this sidecar. A hint is only a
// wake, carrying ids, kinds and versions and no authority: whatever it names is refetched over HTTPS and verified,
// and a hint lost, coalesced or forged costs latency at most, since every handler also runs at each resync, at
// least once a ResyncInterval (§6.8's hourly resync).
//
// Hints arrive as push notices on two topics, from a connect leg's Subprotocol.Subscribe or the sidecar_http leg's
// PushPollClient.Subscribe, whichever the host passes:
//
//   - gkm:<group_id>, commit, whose version is epoch × 2^24 + generation (D-KEYS-19), so a rotation with no commit
//     wakes too;
//   - gkm, per client, the work hints: pending, welcome, key-packages-low and wrap-pending.
//
// Receive never blocks: it records the wake under a lock and signals the intake's own goroutine, which runs the
// handlers, so the push's goroutine, which serves every topic, never waits on gkm (connect/CODESTYLE.md's receive
// rule). Wakes coalesce by kind, group and recipient until a handler takes them, a commit's keeping its highest
// epoch and generation, so a burst of hints costs one fetch. Past HintPendingCount pending wakes, a new one is
// dropped and a resync asked for instead. A notice that does not decode, or one the push marks as a resync, asks for
// a resync.
//
// Each kind's handler is its flow's: KEYS-M2-18's upkeep takes key-packages-low, and KEYS-M2-19 to KEYS-M2-23 the
// rest as they land; a kind with no handler yet is passed over, which the resync covers once one is set.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// What one wake names: a hint's kind and the group, epoch, generation and recipient it carries. A commit's epoch and
// generation come from its topic's version; a work hint's generation is zero.
type GkmHintWake struct {
	Kind protocol.GkmHintKind
	// nil for a hint about no group, as key-packages-low is.
	GroupId    *Id
	Epoch      uint64
	Generation uint64
	// A late wrap's ask: s:<sidecar_id> or d:<delegation_id>, as its wrap path writes it.
	Recipient string
}

// Takes one coalesced wake, on the intake's goroutine. It refetches what the wake names and verifies it, and returns
// once done; the next wake waits for it.
type GkmHintHandler func(ctx context.Context, wake *GkmHintWake)

// Runs at each resync: what a handler's hints would have told it, refetched whole.
type GkmResyncHandler func(ctx context.Context)

// Subprotocol.Subscribe's or PushPollClient.Subscribe's shape.
type GkmSubscribeFunction func(topic string, callback PushNoticeFunction) (remove func(), err error)

// The key wakes coalesce by.
type gkmHintKey struct {
	kind      protocol.GkmHintKind
	groupId   Id
	hasGroup  bool
	recipient string
}

// The intake. See the file header.
type GkmHints struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *GkmSettings
	clock    Clock
	log      Logger
	removes  []func()
	// closed when the run loop has returned
	done chan struct{}

	stateLock      sync.Mutex
	kindHandlers   map[protocol.GkmHintKind]GkmHintHandler
	resyncHandlers []GkmResyncHandler
	keyWakes       map[gkmHintKey]*GkmHintWake
	keyOrder       []gkmHintKey
	resyncAsked    bool
	droppedCount   int
	// signals the run loop that a wake or a resync is waiting
	waiting *MonitorValue[int]
	// passes the run loop has finished, each a drain of the wakes and any resync
	passCount *MonitorValue[int]
}

// What NewGkmHints takes.
type GkmHintsArgs struct {
	// The push feed's Subscribe; nil subscribes to nothing, and only Receive and the resync wake the handlers.
	Subscribe GkmSubscribeFunction
	// nil takes the defaults.
	Settings *GkmSettings
	// nil is real time.
	Clock Clock
	Log   Logger
}

// A running intake, subscribed to gkm and the gkm: family when args.Subscribe is set. It runs until ctx ends or
// Close.
func NewGkmHints(ctx context.Context, args *GkmHintsArgs) (*GkmHints, error) {
	if args == nil {
		args = &GkmHintsArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultGkmSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &GkmHints{
		ctx:          cancelCtx,
		cancel:       cancel,
		settings:     settings,
		clock:        clockOrReal(args.Clock),
		log:          loggerOrDefault(args.Log),
		done:         make(chan struct{}),
		kindHandlers: map[protocol.GkmHintKind]GkmHintHandler{},
		keyWakes:     map[gkmHintKey]*GkmHintWake{},
		waiting:      NewMonitorValue(0),
		passCount:    NewMonitorValue(0),
	}
	if args.Subscribe != nil {
		for _, topic := range []string{PushTopicGkm, PushTopicGkmGroupPrefix} {
			remove, err := args.Subscribe(topic, self.Receive)
			if err != nil {
				for _, remove := range self.removes {
					remove()
				}
				cancel()
				return nil, fmt.Errorf("gkm hints: subscribe %s: %w", topic, err)
			}
			self.removes = append(self.removes, remove)
		}
	}
	go self.run()
	return self, nil
}

// Sets the handler of one kind, replacing an earlier one; nil removes it.
func (self *GkmHints) SetHandler(kind protocol.GkmHintKind, handler GkmHintHandler) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if handler == nil {
		delete(self.kindHandlers, kind)
		return
	}
	self.kindHandlers[kind] = handler
}

// Adds a handler every resync runs.
func (self *GkmHints) AddResync(handler GkmResyncHandler) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resyncHandlers = append(self.resyncHandlers, handler)
}

// Asks for a resync now, as a reconnect does.
func (self *GkmHints) Resync() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.resyncAsked = true
	self.signalWithLock()
}

// A push notice on gkm or a gkm:<group_id> topic. Never blocks, so it may be the push feed's callback.
func (self *GkmHints) Receive(notice PushNotice) {
	wake, err := gkmHintWakeOf(notice)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if err != nil || wake == nil {
		// a resync notice, or a hint lost in its decoding: the handlers refetch everything
		self.resyncAsked = true
		self.signalWithLock()
		return
	}
	key := gkmHintKey{kind: wake.Kind, recipient: wake.Recipient}
	if wake.GroupId != nil {
		key.groupId = *wake.GroupId
		key.hasGroup = true
	}
	if pending, ok := self.keyWakes[key]; ok {
		// coalesced: a commit keeps its newest epoch and generation
		if pending.Epoch < wake.Epoch || pending.Epoch == wake.Epoch && pending.Generation < wake.Generation {
			pending.Epoch = wake.Epoch
			pending.Generation = wake.Generation
		}
		return
	}
	if self.settings.HintPendingCount <= len(self.keyWakes) {
		self.droppedCount += 1
		self.resyncAsked = true
		self.signalWithLock()
		return
	}
	self.keyWakes[key] = wake
	self.keyOrder = append(self.keyOrder, key)
	self.signalWithLock()
}

// The wake a notice names, nil for a resync notice, or an error for a hint that does not decode or does not hold
// its topic's form.
func gkmHintWakeOf(notice PushNotice) (*GkmHintWake, error) {
	if notice.Resync {
		return nil, nil
	}
	if notice.Kind != uint32(protocol.MessageType_GKM_HINT) {
		return nil, errors.New("gkm hints: another message type")
	}
	hint := &protocol.GkmHint{}
	if err := proto.Unmarshal(notice.Hint, hint); err != nil {
		return nil, err
	}
	wake := &GkmHintWake{Kind: hint.GetKind(), Epoch: hint.GetEpoch(), Recipient: string(hint.GetRecipient())}
	if len(hint.GetGroupId()) != 0 {
		groupId, err := IdFromBytes(hint.GetGroupId())
		if err != nil {
			return nil, err
		}
		wake.GroupId = &groupId
	}
	if idText, ok := strings.CutPrefix(notice.Topic, PushTopicGkmGroupPrefix); ok {
		// commit on gkm:<group_id>: the topic names the group, and the version its epoch and generation
		groupId, err := ParseId(idText)
		if err != nil || groupId.String() != idText || wake.Kind != protocol.GkmHintKind_GKM_HINT_COMMIT {
			return nil, errors.New("gkm hints: a group topic out of form")
		}
		wake.GroupId = &groupId
		wake.Epoch = notice.Version >> gkmGroupGenerationBitCount
		wake.Generation = notice.Version & (1<<gkmGroupGenerationBitCount - 1)
		return wake, nil
	}
	if notice.Topic != PushTopicGkm {
		return nil, errors.New("gkm hints: another topic")
	}
	switch wake.Kind {
	case protocol.GkmHintKind_GKM_HINT_PENDING, protocol.GkmHintKind_GKM_HINT_WELCOME,
		protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, protocol.GkmHintKind_GKM_HINT_WRAP_PENDING:
		return wake, nil
	}
	return nil, errors.New("gkm hints: a kind the gkm topic does not carry")
}

// Wakes the run loop, which a change of waiting's value does.
func (self *GkmHints) signalWithLock() {
	self.waiting.Update(func(count int) int { return count + 1 })
}

// Takes the pending wakes and whether a resync was asked for, leaving none.
func (self *GkmHints) takePending() ([]*GkmHintWake, bool, map[protocol.GkmHintKind]GkmHintHandler, []GkmResyncHandler) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	wakes := make([]*GkmHintWake, 0, len(self.keyOrder))
	for _, key := range self.keyOrder {
		wakes = append(wakes, self.keyWakes[key])
	}
	self.keyWakes = map[gkmHintKey]*GkmHintWake{}
	self.keyOrder = nil
	resync := self.resyncAsked
	self.resyncAsked = false
	kindHandlers := make(map[protocol.GkmHintKind]GkmHintHandler, len(self.kindHandlers))
	for kind, handler := range self.kindHandlers {
		kindHandlers[kind] = handler
	}
	return wakes, resync, kindHandlers, append([]GkmResyncHandler(nil), self.resyncHandlers...)
}

// The loop: at each signal it drains the wakes into their handlers and runs a resync asked for, and at each
// ResyncInterval it runs a resync anyway. Handlers run with no lock held, one at a time.
func (self *GkmHints) run() {
	defer close(self.done)
	resyncAt := self.clock.After(self.settings.ResyncInterval)
	for {
		_, signal := self.waiting.Get()
		wakes, resync, kindHandlers, resyncHandlers := self.takePending()
		for _, wake := range wakes {
			if handler, ok := kindHandlers[wake.Kind]; ok {
				handler(self.ctx, wake)
			}
		}
		if resync {
			for _, handler := range resyncHandlers {
				handler(self.ctx)
			}
		}
		self.passCount.Update(func(count int) int { return count + 1 })
		select {
		case <-self.ctx.Done():
			return
		case <-signal:
		case <-resyncAt:
			resyncAt = self.clock.After(self.settings.ResyncInterval)
			func() {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				self.resyncAsked = true
			}()
		}
	}
}

// How many passes the loop has finished, and a channel that closes at the next: what a test waits on instead of
// sleeping.
func (self *GkmHints) Passes() (count int, changed chan struct{}) {
	return self.passCount.Get()
}

// Wakes dropped past HintPendingCount, each covered by a resync.
func (self *GkmHints) DroppedCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.droppedCount
}

// Stops the intake: unsubscribes, ends the loop and waits for it.
func (self *GkmHints) Close() {
	for _, remove := range self.removes {
		remove()
	}
	self.cancel()
	<-self.done
}
