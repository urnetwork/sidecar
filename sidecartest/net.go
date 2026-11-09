// T2's world in one process (§22.4): one clock, one fault queue, one barrier driver, the actors of a
// schedule, and a ServiceHost, fake unless a test gives another. net_connect.go adds connect clients on
// an in-process exchange. A Net is built per test and closed at its end.
//
// NewNet installs the process-wide hooks under sidecar_testhooks, so two Nets cannot be open at once,
// and tests using one are not parallel. Methods are safe for concurrent use.

package sidecartest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
)

type NetSettings struct {
	// Where the injected clock starts.
	ClockStart time.Time
	Barriers   *BarrierDriverSettings
	// The fakes behind the default host.
	Host *FakeHostSettings
	// The exchange's seed for packet loss, so a lossy link repeats.
	LinkSeed int64
	// How long, in real time, NetClient.Send and the exchange give a connect client to take a frame.
	SendTimeout time.Duration
}

func DefaultNetSettings() *NetSettings {
	return &NetSettings{
		ClockStart:  DefaultClockStart(),
		Barriers:    DefaultBarrierDriverSettings(),
		Host:        DefaultFakeHostSettings(),
		LinkSeed:    1,
		SendTimeout: 30 * time.Second,
	}
}

// Builds a process's memory, on the instance named, from durable state alone: what AddProcess runs
// first and Restart runs again. ctx ends with the process.
type ProcessBuilder func(ctx context.Context, instance string) (any, error)

// A process's clusters' fake drive counters (§19.6's counters row, FS-61).
type DriveCounters struct {
	ClusterId string
	Drives    []*DriveCounter
}

// One metadata drive, as /sys/block/<dev>/stat gives it.
type DriveCounter struct {
	DriveId string
	// Field 7.
	SectorsWritten uint64
	// Field 5.
	WritesCompleted uint64
	// The governor skips a drive under heal (§19.6).
	Healing bool
}

type Net struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *NetSettings
	clock    *FakeClock
	faults   *FaultQueue
	barriers *BarrierDriver
	actors   *ActorTable
	capture  *PrivacyCapture

	fakes       *FakeHost
	blobs       *BlobRecorder
	removeHooks func()

	stateLock     sync.Mutex
	host          *sidecar.ServiceHost
	builders      map[string]ProcessBuilder
	processes     map[string]any
	engines       map[string]sidecar.Engine
	driveCounters map[string]*DriveCounters

	exchange *netExchange

	// the api AddSidecar enrolls through and the network it enrolls in, made at first use (core_enroll.go), and
	// every sidecar started, which Close ends
	api              *FakeApi
	defaultNetworkId sidecar.Id
	testSidecars     []*TestSidecar

	// what the world's searches are judged against (search_oracle.go), made at first use
	searchLedger *SearchLedger
	searchOracle *SearchOracle
}

// A fresh world. settings may be nil for the defaults. The caller closes it. Under sidecar_testhooks
// this installs the hooks, and a second open Net is a test bug that panics here.
func NewNet(ctx context.Context, settings *NetSettings) *Net {
	if settings == nil {
		settings = DefaultNetSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	clock := NewFakeClock(settings.ClockStart)
	faults := NewFaultQueue()
	barriers := NewBarrierDriver(settings.Barriers)
	self := &Net{
		ctx:           cancelCtx,
		cancel:        cancel,
		settings:      settings,
		clock:         clock,
		faults:        faults,
		barriers:      barriers,
		actors:        NewActorTable(clock, barriers),
		capture:       NewPrivacyCapture(),
		builders:      map[string]ProcessBuilder{},
		processes:     map[string]any{},
		engines:       map[string]sidecar.Engine{},
		driveCounters: map[string]*DriveCounters{},
	}
	self.fakes = NewFakeHost(cancelCtx, clock, faults, barriers, settings.Host)
	self.AddEngines(self.fakes.ServiceHost())
	self.exchange = newNetExchange(cancelCtx, self)
	self.capture.AddSource(self.fakes.privacyItems)
	self.capture.AddSource(processEnvironmentItems)
	if HooksLinked {
		remove, err := InstallTestHooks(self.capture.AddSecret, barriers.Hit)
		if err != nil {
			panic(err)
		}
		self.removeHooks = remove
	}
	return self
}

// Ends everything: sidecars and engines close, held and parked goroutines leave, and the hooks come off.
func (self *Net) Close() {
	self.closeTestSidecars()
	var engines []sidecar.Engine
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		engines = slices.Collect(maps.Values(self.engines))
		clear(self.engines)
	}()
	for _, engine := range engines {
		engine.Close()
	}
	self.exchange.close()
	self.barriers.Close()
	self.fakes.Redis.Close()
	self.cancel()
	if self.removeHooks != nil {
		self.removeHooks()
		self.removeHooks = nil
	}
}

func (self *Net) Context() context.Context {
	return self.ctx
}

func (self *Net) Clock() *FakeClock {
	return self.clock
}

func (self *Net) Faults() *FaultQueue {
	return self.faults
}

func (self *Net) Barriers() *BarrierDriver {
	return self.barriers
}

func (self *Net) Actors() *ActorTable {
	return self.actors
}

// The fakes by their types. On T3 these exist and nothing talks to them.
func (self *Net) Fakes() *FakeHost {
	return self.fakes
}

// Where engines run on: fakes on T2, server's stores on T3 (§22.4). Blobs goes through a recorder, so
// FI-30 reads every request either way, and a real host's stores are real.
func (self *Net) AddEngines(host *sidecar.ServiceHost) {
	hostCopy := *host
	blobs := NewBlobRecorder(host.Blobs, self.clock, nil)
	hostCopy.Blobs = blobs
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.host = &hostCopy
	self.blobs = blobs
}

// The host engines take, as AddEngines last set it.
func (self *Net) Host() *sidecar.ServiceHost {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.host
}

// Every store request so far, across clusters.
func (self *Net) BlobHistory() []*BlobHistoryEntry {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.blobs.History()
}

// Starts a process under name, and keeps builder for its Restart. Returns its memory.
func (self *Net) AddProcess(name string, builder ProcessBuilder) (any, error) {
	actor := self.actors.Actor(self.ctx, name)
	process, err := builder(actor.Context(), name)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.builders[name] = builder
	self.processes[name] = process
	return process, nil
}

// Starts an engine under name on Host(). Kill drops it with no Drain or Close, as a dead process's
// memory goes; Close closes what is alive.
func (self *Net) AddEngine(name string, build func(ctx context.Context, host *sidecar.ServiceHost) (sidecar.Engine, error)) (sidecar.Engine, error) {
	process, err := self.AddProcess(name, func(ctx context.Context, instance string) (any, error) {
		engine, err := build(ctx, self.Host())
		if err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.engines[instance] = engine
		return engine, nil
	})
	if err != nil {
		return nil, err
	}
	return process.(sidecar.Engine), nil
}

// What a running process built, or nil.
func (self *Net) Process(name string) any {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.processes[name]
}

// Kills an actor: its context ends, its memory goes, and any goroutine of it held at a barrier or
// reaching one stays parked until the end of the test (§22.8's Kill).
func (self *Net) Kill(name string) error {
	actor := self.actors.Lookup(name)
	if actor == nil {
		return fmt.Errorf("no actor %q to kill", name)
	}
	actor.Kill()
	self.barriers.AbandonHeld(name)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.processes, name)
	delete(self.engines, name)
	return nil
}

// Rebuilds a killed process on instance from durable state alone (§22.8's Restart): instance may be
// the old name or a new host's, such as evs2 for evs1. An actor with no builder restarts with empty
// memory, which suits an Action whose state is all in its stores.
func (self *Net) Restart(name string, instance string) error {
	var builder ProcessBuilder
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		builder = self.builders[name]
	}()
	actor := self.actors.Actor(self.ctx, instance)
	if builder == nil {
		return nil
	}
	process, err := builder(actor.Context(), instance)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.builders[instance] = builder
	self.processes[instance] = process
	return nil
}

// Sets what a metadata cluster's drives report (FS-61).
func (self *Net) SetDriveCounters(counters *DriveCounters) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.driveCounters[counters.ClusterId] = counters
}

// What a cluster's drives report, or nil.
func (self *Net) DriveCounters(clusterId string) *DriveCounters {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.driveCounters[clusterId]
}
