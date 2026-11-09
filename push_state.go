// §6.8's client side, on every leg: the state a client keeps of its topics and the machine that moves
// it, fed from the resident's ControlId frames (push_client.go) or from the long-poll (push_poll.go). It
// names no connect type, so §18.10's sidecar_http leg links it.
//
// The machine's rules (D-PROTO-5, D-PROTO-20, I-16):
//
//   - A reset is a run of PushReset parts with one epoch, and their union applies only once a part says
//     complete, so a partial reset advances no applied version. A part with a new epoch, or a hint while
//     a run is open, abandons the run and sends the client to GET /sidecar/sync/versions.
//   - A hint's seq must be the last plus one: any other, a lower one included, since n restarts when its
//     hour ends (reading 5), sends the client to versions. A reset clears the baseline, and the next
//     hint sets it.
//   - A version at or below the client's is ignored; a newer one calls the topic's subscribers, who fetch
//     its state over HTTPS: a hint is a prompt and carries no content (R-PROTO-8).
//   - A reset never lowers a durable version (team, dns, gkm:<group_id>): a lower one raises head_alarm
//     and Consistent() turns false until the topic's owner reconciles it, which is what §8's inbound
//     state reads to fail closed. A clock version's fall (sock, gkm, evs:, core, mail, tls) is a gap:
//     the subscribers refetch, check what they fetch against their pins, and the fall is adopted.
//   - A topic a reset omits keeps the client's version.
//
// Every version is a uint64 on every leg. What the machine applied is kept in the store, so a restart
// neither re-fetches what it has nor forgets a durable floor.

package sidecar

import (
	"context"
	"errors"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A versions page this client did not ask for: another epoch inside one run, or a run past
	// MaxTopicCount.
	errPushVersionsRun = errors.New("push: a versions run that does not hold together")
)

// The client's push bounds.
type PushClientSettings struct {
	// How often the client resyncs its topics, so correctness never rests on a hint's delivery: 1 h,
	// SidecarProtocolSettings.SyncRefetchInterval's value (§6.8).
	SyncRefetchInterval time.Duration
	// The most topics the client tracks, and the most a reset run may name, so a run that never
	// completes costs a bound: 65,536, past every repo and group a member reads. A run past it is
	// abandoned for versions, and a topic past it is not tracked.
	MaxTopicCount int
	// The first wait after a versions refetch fails, doubling to the next: 1 s.
	RetryMinInterval time.Duration
	// The longest wait between failed refetches: 5 min.
	RetryMaxInterval time.Duration
}

// The defaults.
func DefaultPushClientSettings() *PushClientSettings {
	return &PushClientSettings{
		SyncRefetchInterval: 1 * time.Hour,
		MaxTopicCount:       64 * 1024,
		RetryMinInterval:    1 * time.Second,
		RetryMaxInterval:    5 * time.Minute,
	}
}

// What a subscriber is told: a hint that raised a topic, or a resync notice that its state may have
// moved without one.
type PushNotice struct {
	Topic   string
	Version uint64
	// The hint's owner MessageType and bytes, when a hint raised the topic: ids, kinds and versions,
	// never content. Empty on a resync notice.
	Kind uint32
	Hint []byte
	// The topic's state may have moved with no hint: after a reset, a versions refetch or a clock's
	// fall. Fetch it.
	Resync bool
}

// Called for each notice of a topic subscribed to, on whatever goroutine fed the state. It must not
// block, and copies what it keeps.
type PushNoticeFunction func(notice PushNotice)

// What one input asks of the feed beyond the notices it gave.
type pushAction struct {
	// GET /sidecar/sync/versions
	refetchVersions bool
	// the applied versions changed and are to be kept
	changed bool
	// durable topics a reset tried to lower: head_alarm for each
	alarms []pushAlarm
	// notices for the subscribers, in order
	notices []PushNotice
}

// A durable topic a reset presented lower than the client holds.
type pushAlarm struct {
	topic   string
	held    uint64
	offered uint64
}

// The machine of the file header. Not safe for concurrent use: pushFeed holds it under its lock.
type pushMachine struct {
	settings *PushClientSettings
	// what has been applied, by topic
	topicVersions map[string]uint64
	// durable topics held in alarm until reconciled
	alarmTopics map[string]bool
	// the open reset run, if any
	runOpen     bool
	runEpoch    uint64
	runVersions map[string]uint64
	// the last hint's seq, once one has set the baseline since the last reset
	lastSeq uint64
	hasSeq  bool
}

// A machine starting from topicVersions, what a client applied before, nil for none.
func newPushMachine(settings *PushClientSettings, topicVersions map[string]uint64) *pushMachine {
	if topicVersions == nil {
		topicVersions = map[string]uint64{}
	}
	return &pushMachine{
		settings:      settings,
		topicVersions: topicVersions,
		alarmTopics:   map[string]bool{},
	}
}

// Ends any open run unapplied.
func (self *pushMachine) abandonRun() {
	self.runOpen = false
	self.runEpoch = 0
	self.runVersions = nil
}

// One part of a resident's reset: opens or extends the run, and applies the union once complete.
func (self *pushMachine) resetPart(part *protocol.PushReset) *pushAction {
	action := &pushAction{}
	if part == nil {
		return action
	}
	if self.runOpen && part.Epoch != self.runEpoch {
		self.abandonRun()
		action.refetchVersions = true
		return action
	}
	if !self.runOpen {
		self.runOpen = true
		self.runEpoch = part.Epoch
		self.runVersions = map[string]uint64{}
	}
	for _, topicVersion := range part.Versions {
		if PushTopicClassOf(topicVersion.Topic) == PushTopicUnknown {
			continue
		}
		if _, seen := self.runVersions[topicVersion.Topic]; !seen && self.settings.MaxTopicCount <= len(self.runVersions) {
			// a run past every topic a client could hold: abandoned, and versions puts it right
			self.abandonRun()
			action.refetchVersions = true
			return action
		}
		self.runVersions[topicVersion.Topic] = topicVersion.Version
	}
	if !part.Complete {
		return action
	}
	union := self.runVersions
	self.abandonRun()
	self.applyReset(union, action)
	return action
}

// A whole reset at once, every part's versions together: a versions refetch, or a poll's complete part.
func (self *pushMachine) reset(topicVersions map[string]uint64) *pushAction {
	action := &pushAction{}
	self.abandonRun()
	self.applyReset(topicVersions, action)
	return action
}

// Applies a complete reset's union by the file header's rules, into action. Every topic named gets its
// subscribers' resync notice when it moves, and core gets one whatever it shows, since a client fetches
// core at every resync (plan-CORE-core-hint-body #3).
func (self *pushMachine) applyReset(topicVersions map[string]uint64, action *pushAction) {
	topics := slices.Sorted(func(yield func(string) bool) {
		for topic := range topicVersions {
			if !yield(topic) {
				return
			}
		}
	})
	coreNoticed := false
	for _, topic := range topics {
		version := topicVersions[topic]
		class := PushTopicClassOf(topic)
		if class == PushTopicUnknown {
			continue
		}
		held, holds := self.topicVersions[topic]
		switch {
		case holds && version == held:
		case !holds || held < version:
			if !holds && self.settings.MaxTopicCount <= len(self.topicVersions) {
				continue
			}
			self.topicVersions[topic] = version
			action.changed = true
			if class == PushTopicDurable {
				delete(self.alarmTopics, topic)
			}
			action.notices = append(action.notices, PushNotice{Topic: topic, Version: version, Resync: true})
			coreNoticed = coreNoticed || topic == PushTopicCore
		case class == PushTopicDurable:
			// never lowered: an alarm, and the topic fails closed until its owner reconciles it
			self.alarmTopics[topic] = true
			action.alarms = append(action.alarms, pushAlarm{topic: topic, held: held, offered: version})
		default:
			// a clock's fall is a gap: refetch, and adopt what verifies
			self.topicVersions[topic] = version
			action.changed = true
			action.notices = append(action.notices, PushNotice{Topic: topic, Version: version, Resync: true})
			coreNoticed = coreNoticed || topic == PushTopicCore
		}
	}
	if !coreNoticed {
		action.notices = append(action.notices, PushNotice{Topic: PushTopicCore, Version: self.topicVersions[PushTopicCore], Resync: true})
	}
	// a reset is the new baseline: the next hint's seq sets it
	self.hasSeq = false
}

// One hint by the file header's rules.
func (self *pushMachine) hint(hint *protocol.PushHint) *pushAction {
	action := &pushAction{}
	if hint == nil {
		return action
	}
	if self.runOpen {
		self.abandonRun()
		action.refetchVersions = true
	}
	if self.hasSeq && hint.Seq != self.lastSeq+1 {
		action.refetchVersions = true
	}
	self.lastSeq = hint.Seq
	self.hasSeq = true
	if PushTopicClassOf(hint.Topic) == PushTopicUnknown {
		return action
	}
	held, holds := self.topicVersions[hint.Topic]
	if holds && hint.Version <= held {
		return action
	}
	if !holds && self.settings.MaxTopicCount <= len(self.topicVersions) {
		return action
	}
	self.topicVersions[hint.Topic] = hint.Version
	action.changed = true
	action.notices = append(action.notices, PushNotice{
		Topic:   hint.Topic,
		Version: hint.Version,
		Kind:    hint.Kind,
		Hint:    slices.Clone(hint.Hint),
	})
	return action
}

// The topic's owner fetched and verified its state at version: it is applied, even below what was
// held, and the topic's alarm ends.
func (self *pushMachine) reconcile(topic string, version uint64) bool {
	if PushTopicClassOf(topic) == PushTopicUnknown {
		return false
	}
	held, holds := self.topicVersions[topic]
	delete(self.alarmTopics, topic)
	if holds && held == version {
		return false
	}
	if !holds && self.settings.MaxTopicCount <= len(self.topicVersions) {
		// past the bound a reconcile tracks nothing new, as a hint or a reset would not
		return false
	}
	self.topicVersions[topic] = version
	return true
}

// The file a client's applied versions are kept in, as a complete PushReset.
const pushVersionsFileName = "push-versions"

// The applied versions store holds, an empty map when it holds none. A file that does not decode is
// an error, never an empty map: a durable floor is never forgotten by a fault.
func loadPushVersions(store SidecarStore) (map[string]uint64, error) {
	reader, err := store.Open(pushVersionsFileName)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return map[string]uint64{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	kept := &protocol.PushReset{}
	if err := proto.Unmarshal(encoded, kept); err != nil {
		return nil, ErrSidecarStoreFailed
	}
	topicVersions := map[string]uint64{}
	for _, topicVersion := range kept.Versions {
		if PushTopicClassOf(topicVersion.Topic) != PushTopicUnknown {
			topicVersions[topicVersion.Topic] = topicVersion.Version
		}
	}
	return topicVersions, nil
}

// Keeps topicVersions in store, whole.
func storePushVersions(store SidecarStore, topicVersions map[string]uint64) error {
	kept := &protocol.PushReset{Complete: true}
	for _, topic := range slices.Sorted(func(yield func(string) bool) {
		for topic := range topicVersions {
			if !yield(topic) {
				return
			}
		}
	}) {
		kept.Versions = append(kept.Versions, &protocol.TopicVersion{Topic: topic, Version: topicVersions[topic]})
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(kept)
	if err != nil {
		return err
	}
	writer, err := store.Create(pushVersionsFileName)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// GET /sidecar/sync/versions, one page at a time: SidecarApi.SyncVersions, or a test's.
type pushVersionsFunction func(ctx context.Context, cursor []byte) (*protocol.PollResponse, error)

// The machine with what feeds it and what it tells: the subscribers, the store, the head_alarm sink
// and the resync loop, on every leg. The resident's frames and the long-poll both feed one. Safe for
// concurrent use; a subscriber's callback runs on the goroutine that fed the input, with no lock held.
type pushFeed struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *PushClientSettings
	store    SidecarStore
	clock    Clock
	log      Logger
	event    SidecarEventFunction
	versions pushVersionsFunction

	stateLock sync.Mutex
	machine   *pushMachine
	// subscribers by exact topic, and by family prefix (gkm:, evs:)
	topicSubscribers  map[string]map[*pushSubscriber]bool
	familySubscribers map[string]map[*pushSubscriber]bool
	// raised for every resync asked for, which run coalesces
	resyncs *MonitorValue[uint64]
	done    chan struct{}
}

// One Subscribe.
type pushSubscriber struct {
	callback PushNoticeFunction
}

// A feed over store's kept versions, starting its resync loop, which fetches versions at once, at
// each resync asked for and each SyncRefetchInterval. Ends with ctx or close.
func newPushFeed(ctx context.Context, settings *PushClientSettings, store SidecarStore, clock Clock, log Logger, event SidecarEventFunction, versions pushVersionsFunction) (*pushFeed, error) {
	topicVersions, err := loadPushVersions(store)
	if err != nil {
		return nil, err
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &pushFeed{
		ctx:               cancelCtx,
		cancel:            cancel,
		settings:          settings,
		store:             store,
		clock:             clockOrReal(clock),
		log:               loggerOrDefault(log),
		event:             event,
		versions:          versions,
		machine:           newPushMachine(settings, topicVersions),
		topicSubscribers:  map[string]map[*pushSubscriber]bool{},
		familySubscribers: map[string]map[*pushSubscriber]bool{},
		resyncs:           NewMonitorValue[uint64](0),
		done:              make(chan struct{}),
	}
	go self.run()
	return self, nil
}

// Stops the resync loop and waits for it.
func (self *pushFeed) close() {
	self.cancel()
	<-self.done
}

// Asks the loop for a versions refetch now: at reconnect, a gap, an abandoned run.
func (self *pushFeed) resync() {
	self.resyncs.Update(func(count uint64) uint64 {
		return count + 1
	})
}

// Whether no durable topic is held in alarm: what §8's inbound state reads, failing closed while false
// (I-16).
func (self *pushFeed) consistent() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.machine.alarmTopics) == 0
}

// The version applied for topic, 0 when none.
func (self *pushFeed) version(topic string) uint64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.machine.topicVersions[topic]
}

// Subscribes callback to topic: an exact topic, or the family gkm: or evs:, every member of which it
// hears. remove ends it.
func (self *pushFeed) subscribe(topic string, callback PushNoticeFunction) (func(), error) {
	family := topic == PushTopicGkmGroupPrefix || topic == PushTopicEvsPrefix
	if callback == nil || (!family && PushTopicClassOf(topic) == PushTopicUnknown) {
		return nil, ErrSidecarPushTopic
	}
	subscriber := &pushSubscriber{callback: callback}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	subscribers := self.topicSubscribers
	if family {
		subscribers = self.familySubscribers
	}
	if subscribers[topic] == nil {
		subscribers[topic] = map[*pushSubscriber]bool{}
	}
	subscribers[topic][subscriber] = true
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(subscribers[topic], subscriber)
		if len(subscribers[topic]) == 0 {
			delete(subscribers, topic)
		}
	}, nil
}

// Every subscriber notice reaches, snapshot under the lock.
func (self *pushFeed) subscribersOfWithLock(topic string) []*pushSubscriber {
	subscribers := []*pushSubscriber{}
	for subscriber := range self.topicSubscribers[topic] {
		subscribers = append(subscribers, subscriber)
	}
	for _, prefix := range []string{PushTopicGkmGroupPrefix, PushTopicEvsPrefix} {
		if len(prefix) < len(topic) && topic[:len(prefix)] == prefix {
			for subscriber := range self.familySubscribers[prefix] {
				subscribers = append(subscribers, subscriber)
			}
		}
	}
	return subscribers
}

// Runs one input through the machine and acts on what it asked: keeps the versions, raises each alarm,
// tells the subscribers and asks for versions. Store and callbacks run with no lock held.
func (self *pushFeed) apply(input func(machine *pushMachine) *pushAction) {
	var action *pushAction
	var topicVersions map[string]uint64
	deliveries := []func(){}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		action = input(self.machine)
		if action.changed {
			topicVersions = make(map[string]uint64, len(self.machine.topicVersions))
			for topic, version := range self.machine.topicVersions {
				topicVersions[topic] = version
			}
		}
		for _, notice := range action.notices {
			for _, subscriber := range self.subscribersOfWithLock(notice.Topic) {
				deliveries = append(deliveries, func() {
					subscriber.callback(notice)
				})
			}
		}
	}()
	if topicVersions != nil {
		if err := storePushVersions(self.store, topicVersions); err != nil {
			self.log.Warningf("[push]versions not kept: %s\n", err)
		}
	}
	for _, alarm := range action.alarms {
		self.raiseAlarm(alarm)
	}
	for _, delivery := range deliveries {
		delivery()
	}
	if action.refetchVersions {
		self.resync()
	}
}

// head_alarm for a durable topic a reset presented lower than the client holds, with both versions
// as evidence, the client's first.
func (self *pushFeed) raiseAlarm(alarm pushAlarm) {
	self.log.Warningf("[push]a reset presented a durable topic below the version held\n")
	if self.event == nil {
		return
	}
	held, _ := proto.Marshal(&protocol.TopicVersion{Topic: alarm.topic, Version: alarm.held})
	offered, _ := proto.Marshal(&protocol.TopicVersion{Topic: alarm.topic, Version: alarm.offered})
	self.event(SidecarEvent{
		Kind:      SidecarEventHeadAlarm,
		HeadAlarm: SidecarHeadAlarmFork,
		Evidence:  [2][]byte{held, offered},
	})
}

// A resident's reset part.
func (self *pushFeed) applyResetPart(part *protocol.PushReset) {
	self.apply(func(machine *pushMachine) *pushAction {
		return machine.resetPart(part)
	})
}

// A hint.
func (self *pushFeed) applyHint(hint *protocol.PushHint) {
	self.apply(func(machine *pushMachine) *pushAction {
		return machine.hint(hint)
	})
}

// A long-poll's answer: its reset first, applied only when complete, else versions, then its hints.
func (self *pushFeed) applyPoll(response *protocol.PollResponse) {
	if reset := response.GetReset_(); reset != nil {
		if reset.Complete {
			topicVersions := map[string]uint64{}
			for _, topicVersion := range reset.Versions {
				topicVersions[topicVersion.Topic] = topicVersion.Version
			}
			self.apply(func(machine *pushMachine) *pushAction {
				return machine.reset(topicVersions)
			})
		} else {
			// a part of a run the poll never finishes: applies nothing, and versions puts it right
			self.resync()
		}
	}
	for _, hint := range response.GetHints() {
		self.applyHint(hint)
	}
}

// The topic's owner verified its state at version (§6.8): applied, and its alarm ended.
func (self *pushFeed) reconcile(topic string, version uint64) {
	changed := false
	var topicVersions map[string]uint64
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		changed = self.machine.reconcile(topic, version)
		if changed {
			topicVersions = make(map[string]uint64, len(self.machine.topicVersions))
			for topic, version := range self.machine.topicVersions {
				topicVersions[topic] = version
			}
		}
	}()
	if changed {
		if err := storePushVersions(self.store, topicVersions); err != nil {
			self.log.Warningf("[push]versions not kept: %s\n", err)
		}
	}
}

// Fetches every page of one versions run and applies it whole, or applies nothing.
func (self *pushFeed) refetchVersions() error {
	topicVersions := map[string]uint64{}
	cursor := []byte(nil)
	epoch := uint64(0)
	for page := 0; ; page += 1 {
		response, err := self.versions(self.ctx, cursor)
		if err != nil {
			return err
		}
		reset := response.GetReset_()
		if reset == nil || len(response.GetHints()) != 0 || (0 < page && reset.Epoch != epoch) {
			return errPushVersionsRun
		}
		epoch = reset.Epoch
		for _, topicVersion := range reset.Versions {
			if _, seen := topicVersions[topicVersion.Topic]; !seen && self.settings.MaxTopicCount <= len(topicVersions) {
				return errPushVersionsRun
			}
			topicVersions[topicVersion.Topic] = topicVersion.Version
		}
		if reset.Complete {
			break
		}
		if len(response.Cursor) == 0 {
			return errPushVersionsRun
		}
		cursor = response.Cursor
	}
	self.apply(func(machine *pushMachine) *pushAction {
		return machine.reset(topicVersions)
	})
	return nil
}

// The resync loop: a versions refetch at start, at each resync asked for and each SyncRefetchInterval,
// a failed one tried again after a wait that doubles from RetryMinInterval to RetryMaxInterval.
func (self *pushFeed) run() {
	defer close(self.done)
	retryInterval := time.Duration(0)
	for {
		// read before the refetch, so a resync asked for while it runs is the next one
		_, notify := self.resyncs.Get()
		if err := self.refetchVersions(); err != nil {
			if self.ctx.Err() != nil {
				return
			}
			if retryInterval == 0 {
				retryInterval = self.settings.RetryMinInterval
			} else {
				retryInterval = min(2*retryInterval, self.settings.RetryMaxInterval)
			}
			if self.log.V(1).Enabled() {
				self.log.Infof("[push]versions refetch = %s\n", err)
			}
			select {
			case <-self.ctx.Done():
				return
			case <-self.clock.After(retryInterval):
			}
			continue
		}
		retryInterval = 0
		select {
		case <-self.ctx.Done():
			return
		case <-notify:
		case <-self.clock.After(self.settings.SyncRefetchInterval):
		}
	}
}

// A topic Subscribe does not know: neither in §6.8's registry nor one of its two families.
var ErrSidecarPushTopic = errors.New("push: no such topic")
