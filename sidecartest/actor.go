// The actors of a schedule (§22.8): writerA, evs1, gc. An actor is a process as far as a test can make
// one: its context carries its name to every fake and ends when it dies, and its memory is whatever
// its builder made, dropped by Kill.
//
// A crash runs no more of the actor's code. The goroutine that crashes, and each goroutine held at a
// barrier when its actor is killed, stays parked until BarrierDriver.Reap, which a schedule's end calls
// after its last check, so a deferred cleanup cannot do at the crash what a dead process never would.
// An actor's goroutine that is running when the actor is killed stops at its next barrier or fake.

package sidecartest

import (
	"context"
	"runtime"
	"sync"
	"time"
)

type actorContextKey struct{}

// One running incarnation of a named process. Safe for concurrent use.
type Actor struct {
	name      string
	table     *ActorTable
	clock     Clock
	ctx       context.Context
	cancel    context.CancelFunc
	stateLock sync.Mutex
	killed    bool
}

func (self *Actor) Name() string {
	return self.name
}

// Carries the actor to every fake a call reaches, and ends with it. A schedule's Action gets this.
func (self *Actor) Context() context.Context {
	return self.ctx
}

// Its view of time, offset where a schedule sets one.
func (self *Actor) Clock() Clock {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.clock
}

// Offsets its clock from the shared one (FS-1's fast evs2).
func (self *Actor) SetClockOffset(clock *FakeClock, offset time.Duration) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.clock = clock.WithOffset(offset)
}

func (self *Actor) Killed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.killed
}

// Ends the actor: its context cancels, and any of its goroutines reaching a barrier or a fake from now
// on parks there. Safe more than once.
func (self *Actor) Kill() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.killed = true
	}()
	self.cancel()
}

// Dies here, on one of the actor's goroutines: called at a crash point, and never returns. The
// goroutine parks as a dead process's would, and leaves at Reap.
func (self *Actor) crash() {
	self.Kill()
	self.table.barriers.crashCurrent()
}

// Every actor of a test, by name. Names are unique among running actors, and a Restart makes a new
// incarnation. Safe for concurrent use.
type ActorTable struct {
	clock    *FakeClock
	barriers *BarrierDriver

	stateLock sync.Mutex
	actors    map[string]*Actor
}

func NewActorTable(clock *FakeClock, barriers *BarrierDriver) *ActorTable {
	return &ActorTable{
		clock:    clock,
		barriers: barriers,
		actors:   map[string]*Actor{},
	}
}

// The running incarnation of name, started if it has none or the last one was killed, so an Action
// under a killed actor's name, which a schedule writes only after Restart, runs on a fresh one.
func (self *ActorTable) Actor(parent context.Context, name string) *Actor {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if actor, ok := self.actors[name]; ok && !actor.Killed() {
		return actor
	}
	actor := &Actor{name: name, table: self, clock: self.clock}
	actor.ctx, actor.cancel = context.WithCancel(context.WithValue(parent, actorContextKey{}, actor))
	self.actors[name] = actor
	return actor
}

// The incarnation of name now, or nil. Unlike Actor, this starts nothing.
func (self *ActorTable) Lookup(name string) *Actor {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.actors[name]
}

// The actor ctx belongs to, or nil for a caller outside any schedule.
func ActorFromContext(ctx context.Context) *Actor {
	actor, _ := ctx.Value(actorContextKey{}).(*Actor)
	return actor
}

// Its name, or empty.
func ActorName(ctx context.Context) string {
	if actor := ActorFromContext(ctx); actor != nil {
		return actor.name
	}
	return ""
}

// The caller's clock: its actor's, or fallback outside a schedule.
func clockOf(ctx context.Context, fallback Clock) Clock {
	if actor := ActorFromContext(ctx); actor != nil {
		return actor.Clock()
	}
	return fallback
}

// What a wrapper outside this package does first, as every fake here does: a dead actor's goroutine
// stops here, and any other caller goes on. Server's T3 store wrappers call it (sidecart3).
func StopIfDead(ctx context.Context) {
	stopIfDead(ctx)
}

// A crash point in a wrapper outside this package, as CrashBeforeApply and CrashAfterApply take one
// here: the calling actor dies and the call never returns (sidecart3).
func CrashCaller(ctx context.Context) {
	crashCaller(ctx)
}

// What every fake does first: a dead actor's goroutine stops here.
func stopIfDead(ctx context.Context) {
	if actor := ActorFromContext(ctx); actor != nil && actor.Killed() {
		actor.crash()
	}
}

// Dies at a crash point: the calling actor's crash, or, outside a schedule, this goroutine's end, so
// a unit test sees the call never return.
func crashCaller(ctx context.Context) {
	if actor := ActorFromContext(ctx); actor != nil {
		actor.crash()
	}
	runtime.Goexit()
}
