// The driver behind testHookBarrier (§22.4, §22.8): where a fault schedule holds a goroutine and
// releases it in the order the schedule chooses. A site is <name> or <name>@<key>: a name alone
// matches every key, and a key holds one instance of the step and not another's.
//
// A site an arm names holds its next arrival until Release. Any other site records the arrival and
// passes, so a schedule pays only for the barriers it names.
//
// Actors run one at a time, handing a baton at each hold, each block and each end, so what an actor
// does between barriers never races another actor's. With no seed the baton moves only then, in
// arrival order. With a seed, each barrier an actor passes is also a choice of who runs next, which is
// §22.8's explorer. A goroutine the driver did not start for an actor takes no baton: it runs free,
// and it holds at an armed site like any other. An actor blocked on something this file cannot see
// loses the baton after settings.StallTimeout, and the trace says so. An actor still working then, or
// waiting on a goroutine that is, is slow and not blocked: it keeps the baton, so the order stays the
// schedule's, until a wait's settings.AwaitTimeout fails the schedule (barrier_stall.go).
//
// A script makes the driver follow a recorded trace instead: each baton choice and each yield the trace
// shows, as long as the run keeps to it, which is how a failing seed becomes a fixed schedule (§22.8).
// The trace names who ran, so it repeats an order a seed alone may not, since what a goroutine no actor
// owns does between barriers can change whom a seed's draw lands on. Where the run leaves the trace,
// the fixed order takes over and ScriptDeparture says where.
//
// Every hook call is checked against the naming rule, and a violation fails the schedule. Waits here
// bound real time only to fail with a trace (§22.8's 10 s); nothing here sleeps. Safe for concurrent
// use.

package sidecartest

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// <file prefix>.<step>, with .before and .after for the steps around a point. A step may have parts of
// its own, as evs.step7.put does.
var barrierNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9][a-z0-9_]*)+$`)

// Ids and tokens: a ULID, a UUID, hex, base32, base64url, or a pair of them. A slash, a space or an
// @ means a path, a name or a site, and none of those is an opaque id (I-13).
var barrierKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_:=+.-]{1,128}$`)

// Why a hook call breaks the rule in testhook.go, or empty.
func barrierViolation(name string, key string) string {
	if !barrierNamePattern.MatchString(name) {
		return fmt.Sprintf("barrier %q: not <file prefix>.<step>", name)
	}
	if key != "" && !barrierKeyPattern.MatchString(key) {
		return fmt.Sprintf("barrier %q: key %q is not an opaque id", name, key)
	}
	return ""
}

// A site for a schedule to name: Await and Release take this form.
func BarrierSite(name string, key string) string {
	if key == "" {
		return name
	}
	return name + "@" + key
}

type BarrierEventKind string

const (
	// Reached a site nothing holds.
	BarrierPassed BarrierEventKind = "passed"
	// Reached an armed site and stopped there.
	BarrierHeld     BarrierEventKind = "held"
	BarrierReleased BarrierEventKind = "released"
	// A held goroutine's actor was killed there.
	BarrierKilled BarrierEventKind = "killed"
	// An actor took the baton.
	BarrierRan BarrierEventKind = "ran"
	// An actor lost the baton: past settings.StallTimeout it was found blocked where no barrier sees.
	BarrierStalled BarrierEventKind = "stalled"
)

// One line of a schedule's trace.
type BarrierEvent struct {
	Kind BarrierEventKind
	Name string
	Key  string
	// Empty for a goroutine no actor owns.
	Actor string
}

func (self *BarrierEvent) String() string {
	actor := self.Actor
	if actor == "" {
		actor = "-"
	}
	return fmt.Sprintf("%-8s %-10s %s", self.Kind, actor, BarrierSite(self.Name, self.Key))
}

type BarrierDriverSettings struct {
	// §22.8: a schedule waiting this long in real time for a barrier fails with its trace.
	AwaitTimeout time.Duration
	// How long in real time an actor may keep the baton while others wait or a schedule wants to
	// settle, before the driver asks whether it is blocked on something it cannot see. A holder found
	// blocked loses the baton, which costs determinism, so fault.Run fails a run in which an actor
	// stalled. A holder found working keeps it, however slow the machine, until AwaitTimeout.
	// Non-positive disables it, so a blocked actor fails the schedule at AwaitTimeout too.
	StallTimeout time.Duration
	// Past StallTimeout, how long between two readings of the holder's goroutines. Non-positive:
	// StallTimeout again.
	StallSampleInterval time.Duration
	// How many readings in a row must find the holder blocked before it loses the baton, so one that
	// catches a working actor between two steps takes nothing from it. Under one counts as one.
	StallSampleCount int
	// The first size of the buffer a reading's goroutine dump goes into, doubled until the dump fits.
	StallDumpByteCount int
}

func DefaultBarrierDriverSettings() *BarrierDriverSettings {
	return &BarrierDriverSettings{
		AwaitTimeout:        10 * time.Second,
		StallTimeout:        2 * time.Second,
		StallSampleInterval: 200 * time.Millisecond,
		StallSampleCount:    3,
		StallDumpByteCount:  1 << 20,
	}
}

type barrierArm struct {
	site string
	// Empty: any arrival. Otherwise an arrival known to be another actor's passes.
	actor string
	// Arrivals this arm lets pass before it holds one.
	skip int
}

type heldBarrier struct {
	site  string
	name  string
	key   string
	actor string
	run   *actorRun
	// closed to end the hold
	release chan struct{}
	// set before release closes: the goroutine parks dead instead of going on
	dead bool
}

// One Action on its own goroutine: what the baton passes between.
type actorRun struct {
	actor       *Actor
	goroutineId uint64
	// closes when function has returned or its goroutine has left
	done chan struct{}
	// closes at done or at its actor's death, whichever comes first
	ended   chan struct{}
	endOnce sync.Once
	err     error
	// closed and replaced each time it is handed the baton
	granted chan struct{}
}

func (self *actorRun) end() {
	self.endOnce.Do(func() {
		close(self.ended)
	})
}

type BarrierDriver struct {
	settings *BarrierDriverSettings
	// closes at Reap, when parked goroutines leave
	reaped   chan struct{}
	reapOnce sync.Once

	stateLock sync.Mutex
	arms      []*barrierArm
	held      []*heldBarrier
	trace     []*BarrierEvent
	// the rule breaks seen, each once
	violations []string
	// closed and replaced at every change a waiter might want
	changed chan struct{}

	goroutineRuns map[uint64]*actorRun
	batonHolder   *actorRun
	batonWaiters  []*actorRun
	batonSince    time.Time
	// counts the batons given, so a reading of the holder's goroutines knows the hold it read
	batonGrantCount uint64
	// the holder's readings past StallTimeout: when the last began, how many in a row found it
	// blocked, and what the last one saw
	stallSampleTime   time.Time
	stallBlockedCount int
	stallSeen         string
	// the actors a reading found working past StallTimeout, each once
	slowActors []string
	// no waiter takes the baton while set, so a step queues its actors together
	batonPaused bool
	// set by Close: an actor's goroutine stops at the next thing it does here
	closed bool
	// the explorer's choices; nil: none
	random *rand.Rand
	// a recorded trace's events that actors own, to follow; nil: none, or left
	script       []*BarrierEvent
	scriptCursor int
	// where and why the run left its script; empty while it follows
	scriptDeparture string
}

func NewBarrierDriver(settings *BarrierDriverSettings) *BarrierDriver {
	if settings == nil {
		settings = DefaultBarrierDriverSettings()
	}
	return &BarrierDriver{
		settings:      settings,
		reaped:        make(chan struct{}),
		changed:       make(chan struct{}),
		goroutineRuns: map[uint64]*actorRun{},
	}
}

// Lets every goroutine parked dead run its deferred calls and leave. Call it once a schedule's checks
// are done: what those calls do then no check will read.
func (self *BarrierDriver) Reap() {
	self.reapOnce.Do(func() {
		close(self.reaped)
	})
}

// Makes each barrier a passing actor reaches a seeded choice of who runs next (§22.8's explorer). One
// seed gives one order, as long as no actor stalls.
func (self *BarrierDriver) SetSeed(seed int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.random = rand.New(rand.NewPCG(uint64(seed), 0x5eed))
}

func (self *BarrierDriver) notifyWithLock() {
	close(self.changed)
	self.changed = make(chan struct{})
}

func (self *BarrierDriver) recordWithLock(kind BarrierEventKind, name string, key string, actor string) {
	event := &BarrierEvent{Kind: kind, Name: name, Key: key, Actor: actor}
	self.trace = append(self.trace, event)
	self.followScriptWithLock(event)
	self.notifyWithLock()
}

// Makes the driver follow events, a recorded run's trace: each baton goes to the actor the trace says
// ran next, and an actor passing a barrier yields where the trace shows another ran. Only the events
// actors own are followed; a goroutine no actor owns runs free here as it did there. Set it before the
// run starts, and not with a seed.
func (self *BarrierDriver) SetScript(events []*BarrierEvent) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.script = []*BarrierEvent{}
	for _, event := range events {
		if event.Actor != "" {
			eventCopy := *event
			self.script = append(self.script, &eventCopy)
		}
	}
	self.scriptCursor = 0
	self.scriptDeparture = ""
	self.leaveAtStallWithLock()
}

// Where the run left its script and why, or empty while it follows it or has none. A run of the same
// code as the recording keeps to it to the recording's end; a fixed one leaves it where it differs, or
// stops short of the recording's end, which read after the run reads as a departure too.
func (self *BarrierDriver) ScriptDeparture() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.script != nil && self.scriptCursor < len(self.script) {
		return fmt.Sprintf("the run stopped at event %d of the trace's %d, before %s", self.scriptCursor, len(self.script), self.script[self.scriptCursor])
	}
	return self.scriptDeparture
}

func (self *BarrierDriver) followScriptWithLock(event *BarrierEvent) {
	if self.script == nil || event.Actor == "" {
		return
	}
	if len(self.script) <= self.scriptCursor {
		self.leaveScriptWithLock(fmt.Sprintf("after the trace's last event, the run went on with %s", event))
		return
	}
	want := self.script[self.scriptCursor]
	if *want != *event {
		self.leaveScriptWithLock(fmt.Sprintf("at event %d the run did %s where the trace did %s", self.scriptCursor, event, want))
		return
	}
	self.scriptCursor += 1
	self.leaveAtStallWithLock()
}

// A stall in the recording is an order no replay can repeat: the fixed order goes on from there.
func (self *BarrierDriver) leaveAtStallWithLock() {
	if self.script != nil && self.scriptCursor < len(self.script) && self.script[self.scriptCursor].Kind == BarrierStalled {
		self.leaveScriptWithLock(fmt.Sprintf("at event %d the recorded run stalled, which no replay repeats", self.scriptCursor))
	}
}

func (self *BarrierDriver) leaveScriptWithLock(departure string) {
	self.script = nil
	self.scriptDeparture = departure
}

// The actor the script says takes the baton next, or empty when its next event is something else.
func (self *BarrierDriver) scriptNextRunWithLock() string {
	if self.script == nil || len(self.script) <= self.scriptCursor {
		return ""
	}
	if next := self.script[self.scriptCursor]; next.Kind == BarrierRan {
		return next.Actor
	}
	return ""
}

// sites, a step's Release list, in the order the script releases them: what a replay releases in, where
// a seed shuffled the list. Sites the script releases nowhere ahead keep their order, after the rest.
func (self *BarrierDriver) ScriptReleaseOrder(sites []string) []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.script == nil {
		return sites
	}
	position := func(site string) int {
		actorName := ""
		if before, after, found := strings.Cut(site, "/"); found {
			actorName, site = before, after
		}
		for index := self.scriptCursor; index < len(self.script); index += 1 {
			event := self.script[index]
			if event.Kind != BarrierReleased || (actorName != "" && event.Actor != actorName) {
				continue
			}
			if site == event.Name || site == BarrierSite(event.Name, event.Key) {
				return index
			}
		}
		return len(self.script)
	}
	ordered := slices.Clone(sites)
	slices.SortStableFunc(ordered, func(a string, b string) int {
		return position(a) - position(b)
	})
	return ordered
}

// The calling goroutine's id, from its stack header. The only way to tell which actor a hook call
// came from, since a call site names no instance.
func currentGoroutineId() uint64 {
	var buffer [32]byte
	header := buffer[:runtime.Stack(buffer[:], false)]
	header, _ = bytes.CutPrefix(header, []byte("goroutine "))
	if end := bytes.IndexByte(header, ' '); 0 <= end {
		header = header[:end]
	}
	id, err := strconv.ParseUint(string(header), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("goroutine header %q: %v", header, err))
	}
	return id
}

func (self *BarrierDriver) currentRunWithLock() *actorRun {
	return self.goroutineRuns[currentGoroutineId()]
}

// The actor whose goroutine calls this, or "" for a goroutine no actor runs: a test's own, or one an actor's
// code started, which the driver does not follow.
func (self *BarrierDriver) CurrentActor() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if run := self.currentRunWithLock(); run != nil {
		return run.actor.Name()
	}
	return ""
}

// Makes the next arrival at site hold, after skip arrivals pass. actor limits that to one actor's
// arrivals; an arrival from a goroutine with no known actor still matches. Arms for one site take
// arrivals in the order armed.
func (self *BarrierDriver) Arm(site string, actor string, skip int) error {
	name, key, _ := strings.Cut(site, "@")
	if violation := barrierViolation(name, key); violation != "" {
		return errors.New(violation)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.arms = append(self.arms, &barrierArm{site: site, actor: actor, skip: skip})
	return nil
}

// The arm this arrival takes, removed, or nil. Exact key matches first: a schedule's narrower site
// wins over its wider one.
func (self *BarrierDriver) takeArmWithLock(name string, key string, actorName string) *barrierArm {
	matchSite := func(site string) *barrierArm {
		for index, arm := range self.arms {
			if arm.site != site {
				continue
			}
			if arm.actor != "" && actorName != "" && arm.actor != actorName {
				continue
			}
			if 0 < arm.skip {
				arm.skip -= 1
				return nil
			}
			self.arms = slices.Delete(self.arms, index, index+1)
			return arm
		}
		return nil
	}
	if key != "" {
		if arm := matchSite(BarrierSite(name, key)); arm != nil {
			return arm
		}
	}
	return matchSite(name)
}

// The hook. Runs on the goroutine at the barrier and returns when it may go on. A dead actor's
// goroutine never returns: it stays parked until Reap and leaves without running further.
func (self *BarrierDriver) Hit(name string, key string) {
	var hold *heldBarrier
	var dead bool
	var yielded *actorRun
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if violation := barrierViolation(name, key); violation != "" && !slices.Contains(self.violations, violation) {
			self.violations = append(self.violations, violation)
			self.notifyWithLock()
		}
		run := self.currentRunWithLock()
		actorName := ""
		if run != nil {
			actorName = run.actor.name
			if self.closed || run.actor.Killed() {
				self.abandonRunWithLock(run)
				dead = true
				return
			}
		}
		if arm := self.takeArmWithLock(name, key, actorName); arm != nil {
			if actorName == "" {
				// a goroutine the driver did not start, taken as the arm's actor's
				actorName = arm.actor
			}
			hold = &heldBarrier{
				site:    arm.site,
				name:    name,
				key:     key,
				actor:   actorName,
				run:     run,
				release: make(chan struct{}),
			}
			self.held = append(self.held, hold)
			self.recordWithLock(BarrierHeld, name, key, actorName)
			if run != nil {
				self.handBatonWithLock(run)
			}
			return
		}
		self.recordWithLock(BarrierPassed, name, key, actorName)
		if run != nil && (self.random != nil || self.script != nil) && self.yieldWithLock(run) {
			yielded = run
		}
	}()
	switch {
	case dead:
		self.parkDead()
	case hold != nil:
		self.waitHeld(hold)
	case yielded != nil:
		self.awaitBaton(yielded)
	}
}

// Parks until Reap, then ends the goroutine.
func (self *BarrierDriver) parkDead() {
	<-self.reaped
	runtime.Goexit()
}

func (self *BarrierDriver) waitHeld(hold *heldBarrier) {
	<-hold.release
	if hold.dead {
		self.parkDead()
	}
	if hold.run != nil {
		self.awaitBaton(hold.run)
	}
}

// run's actor died: it holds nothing, and whoever waits on it stops waiting.
func (self *BarrierDriver) abandonRunWithLock(run *actorRun) {
	run.end()
	self.batonWaiters = slices.DeleteFunc(self.batonWaiters, func(waiter *actorRun) bool { return waiter == run })
	self.handBatonWithLock(run)
	self.notifyWithLock()
}

// Keeps every actor from taking the baton until Resume, so what a step starts and releases all queues
// before any of it runs. An actor already running runs on.
func (self *BarrierDriver) Pause() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.batonPaused = true
}

func (self *BarrierDriver) Resume() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.batonPaused = false
	self.nextBatonWithLock(nil)
	self.notifyWithLock()
}

// Whether the seed or the script sends the baton elsewhere, and if so hands it over, leaving run among
// the waiters.
func (self *BarrierDriver) yieldWithLock(run *actorRun) bool {
	if self.batonHolder != run || len(self.batonWaiters) == 0 {
		return false
	}
	if self.script != nil {
		if next := self.scriptNextRunWithLock(); next == "" || next == run.actor.name {
			return false
		}
		// another ran next either because this actor yielded or because it ended, and only an actor
		// that yielded shows up in the trace again
		if !slices.ContainsFunc(self.script[self.scriptCursor+1:], func(event *BarrierEvent) bool { return event.Actor == run.actor.name }) {
			return false
		}
	} else if self.random.IntN(len(self.batonWaiters)+1) == 0 {
		return false
	}
	self.batonWaiters = append(self.batonWaiters, run)
	self.batonHolder = nil
	self.nextBatonWithLock(run)
	return true
}

// Gives the free baton to a waiter, the first, the script's or the seed's choice, never except. A script
// naming an actor that is not waiting is a run that left it, which the ran event then records.
func (self *BarrierDriver) nextBatonWithLock(except *actorRun) {
	if self.batonHolder != nil || self.batonPaused {
		return
	}
	candidates := []int{}
	for index, waiter := range self.batonWaiters {
		if waiter != except {
			candidates = append(candidates, index)
		}
	}
	if len(candidates) == 0 {
		return
	}
	chosen := candidates[0]
	if next := self.scriptNextRunWithLock(); next != "" {
		if index := slices.IndexFunc(candidates, func(index int) bool { return self.batonWaiters[index].actor.name == next }); 0 <= index {
			chosen = candidates[index]
		}
	} else if self.random != nil {
		chosen = candidates[self.random.IntN(len(candidates))]
	}
	next := self.batonWaiters[chosen]
	self.batonWaiters = slices.Delete(self.batonWaiters, chosen, chosen+1)
	self.giveBatonWithLock(next)
}

func (self *BarrierDriver) giveBatonWithLock(run *actorRun) {
	self.batonHolder = run
	self.batonSince = time.Now()
	self.batonGrantCount += 1
	self.stallSampleTime = time.Time{}
	self.stallBlockedCount = 0
	self.stallSeen = ""
	self.recordWithLock(BarrierRan, "", "", run.actor.name)
	close(run.granted)
	run.granted = make(chan struct{})
}

// run stops running: it gives up the baton if it has it.
func (self *BarrierDriver) handBatonWithLock(run *actorRun) {
	if self.batonHolder == run {
		self.batonHolder = nil
		self.nextBatonWithLock(nil)
	}
	self.notifyWithLock()
}

// Waits for the baton: run queues for it, and returns holding it, or never, if the driver closes first.
func (self *BarrierDriver) awaitBaton(run *actorRun) {
	var granted chan struct{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.batonHolder == run {
			return
		}
		granted = run.granted
		if !slices.Contains(self.batonWaiters, run) {
			self.batonWaiters = append(self.batonWaiters, run)
		}
		self.nextBatonWithLock(nil)
		if self.batonHolder == run {
			granted = nil
		}
		self.notifyWithLock()
	}()
	if granted != nil {
		select {
		case <-granted:
		case <-self.reaped:
			self.parkDead()
		}
	}
}

// The calling goroutine stops running for good, as at a crash, and parks. Never returns.
func (self *BarrierDriver) crashCurrent() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if run := self.currentRunWithLock(); run != nil {
			self.abandonRunWithLock(run)
		}
	}()
	self.parkDead()
}

// Runs wait with the baton given up, for a fake that parks a caller: the caller's actor does not stall
// the others while it waits.
func (self *BarrierDriver) Blocking(wait func()) {
	var run *actorRun
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		run = self.currentRunWithLock()
		if run != nil {
			self.handBatonWithLock(run)
		}
	}()
	wait()
	if run != nil {
		if run.actor.Killed() {
			self.crashCurrent()
		}
		self.awaitBaton(run)
	}
}

// Starts function as actor's Action on its own goroutine, under the baton, so a Settle after this
// waits for it. A crash or a kill ends the run with no error, and its goroutine parks.
func (self *BarrierDriver) Start(actor *Actor, function func() error) *ActorRun {
	run := &actorRun{
		actor:   actor,
		done:    make(chan struct{}),
		ended:   make(chan struct{}),
		granted: make(chan struct{}),
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.batonWaiters = append(self.batonWaiters, run)
		self.nextBatonWithLock(nil)
	}()
	go func() {
		defer close(run.done)
		defer run.end()
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			run.goroutineId = currentGoroutineId()
			self.goroutineRuns[run.goroutineId] = run
		}()
		defer func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.goroutineRuns, run.goroutineId)
			self.abandonRunWithLock(run)
		}()
		self.awaitBaton(run)
		run.err = function()
	}()
	return &ActorRun{run: run}
}

// An Action in flight.
type ActorRun struct {
	run *actorRun
}

func (self *ActorRun) Actor() *Actor {
	return self.run.actor
}

// Closes at the end of function or at its actor's death, whichever comes first.
func (self *ActorRun) Ended() <-chan struct{} {
	return self.run.ended
}

// Its error, once Ended closes. nil for a run its actor's death ended.
func (self *ActorRun) Err() error {
	return self.run.err
}

// Whether a hold matches a site and, when actorName is not empty, is that actor's.
func (self *heldBarrier) matches(site string, actorName string) bool {
	return self.site == site && (actorName == "" || self.actor == actorName)
}

// Waits for an arrival held at site, as armed, by actorName unless that is empty.
func (self *BarrierDriver) AwaitHeld(ctx context.Context, site string, actorName string) error {
	return self.awaitCondition(ctx, fmt.Sprintf("barrier %s", site), func() bool {
		return slices.ContainsFunc(self.held, func(hold *heldBarrier) bool {
			return hold.matches(site, actorName)
		})
	})
}

// As AwaitHeld, and fails at once if run ends without getting there. run may be nil.
func (self *BarrierDriver) AwaitHeldOrEnded(ctx context.Context, site string, actorName string, run *ActorRun) error {
	ended := false
	err := self.awaitCondition(ctx, fmt.Sprintf("barrier %s", site), func() bool {
		if slices.ContainsFunc(self.held, func(hold *heldBarrier) bool { return hold.matches(site, actorName) }) {
			return true
		}
		if run != nil {
			select {
			case <-run.run.ended:
				ended = true
				return true
			default:
			}
		}
		return false
	})
	if err != nil {
		return err
	}
	if ended {
		if err := run.Err(); err != nil {
			return fmt.Errorf("ended before barrier %s: %w", site, err)
		}
		return fmt.Errorf("ended without reaching barrier %s", site)
	}
	return nil
}

// Waits for channel to close, with the same bound and the same care for a stalled baton as a barrier
// has, so a schedule's other waits fail with its trace too.
func (self *BarrierDriver) AwaitChannel(ctx context.Context, what string, channel <-chan struct{}) error {
	timeout := time.After(self.settings.AwaitTimeout)
	for {
		stallIn := self.checkStall()
		var changed chan struct{}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			changed = self.changed
		}()
		var stalled <-chan time.Time
		if 0 < stallIn {
			stalled = time.After(stallIn)
		}
		select {
		case <-channel:
			return nil
		case <-changed:
		case <-stalled:
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return self.awaitTimeoutError(what)
		}
	}
}

// Waits for done to become true under the state lock, for at most settings.AwaitTimeout. While it
// waits, an actor blocked with the baton past settings.StallTimeout loses it, or the one waiting for
// the baton behind it would run into this timeout. Behind an actor still working it does.
func (self *BarrierDriver) awaitCondition(ctx context.Context, what string, done func() bool) error {
	timeout := time.After(self.settings.AwaitTimeout)
	for {
		// before done is read, which then sees a baton this took
		stallIn := self.checkStall()
		var changed chan struct{}
		var finished bool
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			changed = self.changed
			finished = done()
		}()
		if finished {
			return nil
		}
		var stalled <-chan time.Time
		if 0 < stallIn {
			stalled = time.After(stallIn)
		}
		select {
		case <-changed:
		case <-stalled:
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return self.awaitTimeoutError(what)
		}
	}
}

// §22.8's failed wait, naming the actor that kept the baton through it and what it was last seen doing.
func (self *BarrierDriver) awaitTimeoutError(what string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.batonHolder == nil {
		return fmt.Errorf("waited %s for %s", self.settings.AwaitTimeout, what)
	}
	seen := self.stallSeen
	if seen == "" {
		seen = "its goroutines not read yet"
	}
	return fmt.Errorf(
		"waited %s for %s, with %s holding the baton for %s, %s",
		self.settings.AwaitTimeout,
		what,
		self.batonHolder.actor.name,
		time.Since(self.batonSince).Round(time.Millisecond),
		seen,
	)
}

// What a wait does about the baton each time it wakes. Past settings.StallTimeout it reads the
// holder's goroutines, and takes the baton from a holder that settings.StallSampleCount readings in a
// row found blocked, which runs on regardless once whatever blocks it lets go. Returns how long until
// it should look again, zero when no holder can stall.
func (self *BarrierDriver) checkStall() time.Duration {
	holder, holderGoroutineId, grantCount, runGoroutineIds, checkIn := self.stallSampleDue()
	if holder == nil {
		return checkIn
	}
	// read with the state lock free: a goroutine waiting for that lock would read as blocked
	blocked, seen := goroutinesBlocked(dumpGoroutines(self.settings.StallDumpByteCount), holderGoroutineId, runGoroutineIds)

	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.batonHolder != holder || self.batonGrantCount != grantCount {
		// the hold the reading saw is over
		return self.nextStallCheckWithLock()
	}
	// the interval runs from a reading's end, so readings that take long leave the actors the time between
	self.stallSampleTime = time.Now()
	self.stallSeen = seen
	if !blocked {
		self.stallBlockedCount = 0
		if !slices.Contains(self.slowActors, holder.actor.name) {
			self.slowActors = append(self.slowActors, holder.actor.name)
		}
		return self.nextStallCheckWithLock()
	}
	self.stallBlockedCount += 1
	if self.stallBlockedCount < self.settings.StallSampleCount {
		return self.nextStallCheckWithLock()
	}
	self.recordWithLock(BarrierStalled, "", "", holder.actor.name)
	self.batonHolder = nil
	self.nextBatonWithLock(nil)
	return self.nextStallCheckWithLock()
}

// The holder to read now, with its goroutine, zero until that has started, the hold's count and every
// run's goroutine, or nil and checkStall's answer while no reading is due. A reading due is taken here,
// so two waits do not both count it.
func (self *BarrierDriver) stallSampleDue() (
	holder *actorRun,
	holderGoroutineId uint64,
	grantCount uint64,
	runGoroutineIds map[uint64]bool,
	checkIn time.Duration,
) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if sampleIn, canStall := self.stallSampleInWithLock(); !canStall || 0 < sampleIn {
		return nil, 0, 0, nil, self.nextStallCheckWithLock()
	}
	self.stallSampleTime = time.Now()
	runGoroutineIds = map[uint64]bool{}
	for goroutineId := range self.goroutineRuns {
		runGoroutineIds[goroutineId] = true
	}
	return self.batonHolder, self.batonHolder.goroutineId, self.batonGrantCount, runGoroutineIds, 0
}

// How long until the holder's goroutines are next read, zero or less for now, and whether there is a
// holder that can stall at all.
func (self *BarrierDriver) stallSampleInWithLock() (sampleIn time.Duration, canStall bool) {
	if self.batonHolder == nil || self.settings.StallTimeout <= 0 {
		return 0, false
	}
	if stallIn := self.settings.StallTimeout - time.Since(self.batonSince); 0 < stallIn {
		return stallIn, true
	}
	if self.stallSampleTime.IsZero() {
		return 0, true
	}
	interval := self.settings.StallSampleInterval
	if interval <= 0 {
		interval = self.settings.StallTimeout
	}
	return interval - time.Since(self.stallSampleTime), true
}

// What checkStall returns: positive while a holder can stall, so the wait looks again, at once when a
// reading is already due.
func (self *BarrierDriver) nextStallCheckWithLock() time.Duration {
	sampleIn, canStall := self.stallSampleInWithLock()
	if !canStall {
		return 0
	}
	return max(sampleIn, time.Nanosecond)
}

// The actors found still working with the baton past settings.StallTimeout, each once, in the order
// found. They kept it, so the order stayed the schedule's: this says where a slow machine's time went.
func (self *BarrierDriver) SlowActors() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.slowActors)
}

// A site with an actor in front, as in writerB/evs.head_cas.before: that actor's hold there, for a
// schedule with two actors held at one site.
func ActorBarrierSite(actorName string, site string) string {
	return actorName + "/" + site
}

// Releases the oldest arrival held at site, which then queues for the baton. Site may name an actor,
// as ActorBarrierSite writes. A site nobody is held at is an error: a schedule that thinks otherwise
// has lost its place.
func (self *BarrierDriver) Release(site string) error {
	actorName := ""
	if before, after, found := strings.Cut(site, "/"); found {
		actorName, site = before, after
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for index, hold := range self.held {
		if !hold.matches(site, actorName) {
			continue
		}
		self.held = slices.Delete(self.held, index, index+1)
		self.recordWithLock(BarrierReleased, hold.name, hold.key, hold.actor)
		close(hold.release)
		if hold.run != nil {
			// queued here, in release order, and not when its goroutine wakes: the step's next baton
			// choice then has every actor it released to choose from, so a seed or a script picks the
			// same one every time
			if self.batonHolder != hold.run && !slices.Contains(self.batonWaiters, hold.run) {
				self.batonWaiters = append(self.batonWaiters, hold.run)
			}
			self.nextBatonWithLock(nil)
		}
		return nil
	}
	return fmt.Errorf("nothing is held at %s", site)
}

// A dead actor's held goroutines stay parked rather than go on. The Kill itself is the actor's.
func (self *BarrierDriver) AbandonHeld(actorName string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kept := []*heldBarrier{}
	for _, hold := range self.held {
		if hold.actor != actorName {
			kept = append(kept, hold)
			continue
		}
		hold.dead = true
		if hold.run != nil {
			hold.run.end()
		}
		self.recordWithLock(BarrierKilled, hold.name, hold.key, hold.actor)
		close(hold.release)
	}
	self.held = kept
}

// Sites still holding a goroutine, oldest first.
func (self *BarrierDriver) HeldSites() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sites := make([]string, 0, len(self.held))
	for _, hold := range self.held {
		sites = append(sites, hold.site)
	}
	return sites
}

// Sites armed and never reached.
func (self *BarrierDriver) ArmedSites() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	sites := make([]string, 0, len(self.arms))
	for _, arm := range self.arms {
		sites = append(sites, arm.site)
	}
	return sites
}

// Returns once no actor is running: each is held, blocked in a fake, or done, or found blocked out of
// sight past settings.StallTimeout. What a schedule calls so that the step after a Release starts from
// one state.
func (self *BarrierDriver) Settle(ctx context.Context) error {
	return self.awaitCondition(ctx, "the actors to settle", func() bool {
		self.nextBatonWithLock(nil)
		return self.batonHolder == nil && len(self.batonWaiters) == 0
	})
}

// The trace so far.
func (self *BarrierDriver) Trace() []*BarrierEvent {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.trace)
}

// Each hook call that broke testhook.go's rule, once.
func (self *BarrierDriver) Violations() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.violations)
}

// Ends a test: whatever is held or waiting for the baton parks dead, no site holds any more, and Reap
// lets them all leave. What a dead goroutine's deferred calls then do, no check reads.
func (self *BarrierDriver) Close() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.closed = true
		for _, hold := range self.held {
			hold.dead = true
			if hold.run != nil {
				hold.run.end()
			}
			close(hold.release)
		}
		self.held = nil
		self.arms = nil
		for _, waiter := range self.batonWaiters {
			waiter.end()
		}
		self.batonWaiters = nil
		self.notifyWithLock()
	}()
	self.Reap()
}
