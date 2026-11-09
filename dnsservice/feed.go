// The edge's feed loop (§12.6, D-DNS-3, I-12, FS-42). For each root it long-polls GET /dns/journal with
// the serial it has applied, applies the rows in serial order into a new ZoneView, self-checks it with
// the key window the feed last named and the ZSK from secret_files, and only then swaps it in whole; a
// view or window that fails keeps the previous one serving. A reload fetches GET /dns/snapshot, builds
// and checks the new view and swaps it in whole, keeping the replaced view only when it is older than
// restore_serial, until POST /dns/reload-diff takes its diff, at most feed.replaced_keep_s (dns-1); any
// other replaced view is gone at once.
//
// The feed never lowers a view: a row at or below the applied serial without a reload is refused and
// counted, a reload's snapshot that is not above it likewise, and a row of a format this release does
// not read stops applying while the last good view keeps serving. Everything served is written to the
// local snapshot (snapshot_file.go) by a writer of its own, which coalesces a burst of rows into one
// write, so an edge restarted with the core down serves the last view it had. --require-reload, §19.10's
// rule for a stopped NS, serves again only from a reload, its local snapshot taken as the replaced one.
//
// An edge reaches the block only through DnsFeed, so it has no way to reach Postgres (I-12). Each root's
// loop takes the context, rate-limits itself and backs off a failing block on the clock.

package dnsservice

import (
	"cmp"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/urnetwork/sidecar"
)

// What one poll came to, the values of the feed_polls metric's result label.
const (
	dnsFeedPollRows   = "rows"
	dnsFeedPollReload = "reload"
	dnsFeedPollEmpty  = "empty"
	dnsFeedPollError  = "error"
)

// The values of the self_checks metric's result label.
const (
	dnsSelfCheckPass = "pass"
	dnsSelfCheckFail = "fail"
)

// What became of a replaced snapshot's diff, the values of the reload_diffs metric's result label.
const (
	dnsReloadDiffPosted  = "posted"
	dnsReloadDiffFailed  = "failed"
	dnsReloadDiffExpired = "expired"
)

// The values of the snapshot_writes metric's result label.
const (
	dnsSnapshotWriteOk     = "ok"
	dnsSnapshotWriteFailed = "failed"
)

// The RRsets that differ between replaced, the view a reload replaced, and current, its new one: in one
// and not the other, or in both with another TTL, kind or rdata. Sorted by owner, then type, so two
// edges with the same views post the same diff, each with its kind, current's where it holds the RRset.
func RrsetDiff(replaced *ZoneView, current *ZoneView) *DnsReloadDiff {
	before := map[DnsRecordKey]*DnsRecordSet{}
	for set := range replaced.Rows() {
		before[set.Key()] = set
	}
	keyKinds := map[DnsRecordKey]DnsRecordKind{}
	for set := range current.Rows() {
		key := set.Key()
		if old, ok := before[key]; !ok || !reflect.DeepEqual(old, set) {
			keyKinds[key] = set.Kind
		}
		delete(before, key)
	}
	for key, set := range before {
		keyKinds[key] = set.Kind
	}
	keys := slices.SortedFunc(maps.Keys(keyKinds), func(a DnsRecordKey, b DnsRecordKey) int {
		return cmp.Or(cmp.Compare(a.Owner, b.Owner), cmp.Compare(a.Type, b.Type))
	})
	kinds := make([]DnsRecordKind, 0, len(keys))
	for _, key := range keys {
		kinds = append(kinds, keyKinds[key])
	}
	return &DnsReloadDiff{Root: current.root, ReplacedSerial: replaced.serial, Serial: current.serial, Rrsets: keys, Kinds: kinds}
}

// Whether two windows are one. nil is a window of its own.
func dnsKeyWindowsEqual(a *DnsKeyWindow, b *DnsKeyWindow) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Root == b.Root && a.NotBefore.Equal(b.NotBefore) && a.NotAfter.Equal(b.NotAfter) &&
		slices.Equal(a.Dnskeys, b.Dnskeys) && slices.Equal(a.Rrsigs, b.Rrsigs)
}

// What a feed loop takes beyond its host and settings.
type FeedLoopDeps struct {
	// The block, over HTTP (NewDnsFeedHttp) or a fake. Required.
	Feed DnsFeed
	// Where each checked view is served. Required.
	Edge *DnsEdge
	// The current ZSK, from LoadZsk. Required.
	Zsk crypto.Signer
	// Each root's KSK DNSKEYs, the trust anchors SelfCheck holds a window to (ParseDnsTrustAnchors).
	// Every root needs at least one.
	Anchors map[string][]*dns.DNSKEY
	// Where each root keeps its local snapshot, in a directory named for the root. Required.
	SnapshotDirectory string
	// §19.10's start for a stopped NS: serve nothing until a reload, the local snapshot being the
	// replaced one.
	RequireReload bool
	// Told each interface list the feed names that differs from the last, the prober's SetInterfaces.
	// nil ignores them.
	OnInterfaces func(interfaces []DnsLbInterface)
	// Lifecycle only. nil discards.
	Log sidecar.Logger
}

// The feed loop. Safe for concurrent use: each root's state belongs to its loop's goroutine.
type FeedLoop struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *DnsSettings
	clock    sidecar.Clock
	log      sidecar.Logger
	metrics  *dnsMetrics
	deps     *FeedLoopDeps
	roots    []*dnsFeedRoot
	group    sync.WaitGroup
}

// Starts a loop for each of settings' roots, which first serves its local snapshot, unless
// RequireReload, and then follows the feed until ctx ends or Close. host needs Metrics; its Clock is
// every wait's.
func NewFeedLoop(ctx context.Context, host *sidecar.ServiceHost, settings *DnsSettings, deps *FeedLoopDeps) (*FeedLoop, error) {
	if host == nil || host.Metrics == nil {
		return nil, errors.New("feed loop needs a host with Metrics")
	}
	if deps == nil || deps.Feed == nil || deps.Edge == nil || deps.Zsk == nil || deps.SnapshotDirectory == "" {
		return nil, errors.New("feed loop needs a feed, an edge, a zsk and a snapshot directory")
	}
	if err := settings.Validate(); err != nil {
		return nil, err
	}
	log := deps.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &FeedLoop{
		ctx:      cancelCtx,
		cancel:   cancel,
		settings: settings,
		clock:    host.ClockOrReal(),
		log:      log,
		metrics:  newDnsMetrics(host.Metrics),
		deps:     deps,
	}
	for _, root := range settings.Roots {
		anchors := deps.Anchors[root]
		if len(anchors) == 0 {
			cancel()
			return nil, fmt.Errorf("no trust anchor for %s", root)
		}
		file, err := NewSnapshotFile(filepath.Join(deps.SnapshotDirectory, strings.TrimSuffix(root, ".")), root)
		if err != nil {
			cancel()
			return nil, err
		}
		empty, err := NewZoneView(settings, NewDnsSnapshotRows(DnsSnapshot{Format: DnsFormat, Root: root}, nil))
		if err != nil {
			cancel()
			return nil, err
		}
		self.roots = append(self.roots, &dnsFeedRoot{
			loop:          self,
			root:          root,
			file:          file,
			anchors:       anchors,
			writer:        newDnsSnapshotWriter(file, self.clock, dnsSeconds(settings.Feed.SnapshotWriteSeconds), self.metrics),
			view:          empty,
			requireReload: deps.RequireReload,
			park:          sidecar.NewMonitorValue(dnsFeedPark{}),
		})
	}
	for _, root := range self.roots {
		self.group.Add(2)
		go func() {
			defer self.group.Done()
			root.run()
		}()
		go func() {
			defer self.group.Done()
			root.writer.run(cancelCtx)
		}()
	}
	return self, nil
}

// Stops every loop, then writes what each serves to its local snapshot, so a restart serves from the
// newest view. Safe more than once.
func (self *FeedLoop) Close() {
	self.cancel()
	self.group.Wait()
	for _, root := range self.roots {
		root.writer.flush()
	}
}

// One root's loop. Everything here but the writer belongs to run's goroutine.
type dnsFeedRoot struct {
	loop    *FeedLoop
	root    string
	file    *SnapshotFile
	anchors []*dns.DNSKEY
	writer  *dnsSnapshotWriter

	// The newest view applied and checked, or the view a restart read, or an empty one at serial
	// zero: what the next poll continues from.
	view *ZoneView
	// What the served view was checked with. nil while nothing serves.
	keys *DnsSigningKeys
	// The newest window the feed or the local snapshot named, checked or not.
	window        *DnsKeyWindow
	interfaces    []DnsLbInterface
	restoreSerial uint64
	requireReload bool
	// Under requireReload, the local snapshot, which the first reload replaces.
	replaced *ZoneView
	// Replaced snapshots whose diffs wait for POST /dns/reload-diff.
	pending []*DnsReplacedSnapshot
	backoff time.Duration
	// Where the loop is parked: in a poll, or in a wait on the clock until a time.
	park *sidecar.MonitorValue[dnsFeedPark]
}

// Where one of a root's goroutines is parked, with nothing of its own in hand: what a test reads
// before it moves a fake clock, so time moves only while the loop and its writer wait on it. The zero
// value is not parked.
type dnsFeedPark struct {
	parked bool
	// When the wait parked in ends, set with its timer: a goroutine whose until the clock has reached
	// has been woken, though it reads parked until it runs again. Zero for a poll, or for the writer's
	// wait for a change, whose wakes come from elsewhere.
	until time.Time
}

// Waits timeout on the clock. False once the loop has ended.
func (self *dnsFeedRoot) wait(timeout time.Duration) bool {
	timer := self.loop.clock.After(timeout)
	// the clock is read after the timer is set, so a move in between leaves until no earlier than it
	self.park.Set(dnsFeedPark{parked: true, until: self.loop.clock.Now().Add(timeout)})
	defer self.park.Set(dnsFeedPark{})
	testHookBarrier("dnsservice.feed_wait", "")
	select {
	case <-self.loop.ctx.Done():
		return false
	case <-timer:
		return true
	}
}

// The next backoff after a failure: feed.retry_min_s, doubling to feed.retry_max_s.
func (self *dnsFeedRoot) nextBackoff() time.Duration {
	feed := &self.loop.settings.Feed
	self.backoff = min(max(self.backoff*2, dnsSeconds(feed.RetryMinSeconds)), dnsSeconds(feed.RetryMaxSeconds))
	return self.backoff
}

// Polls until the loop ends.
func (self *dnsFeedRoot) run() {
	self.start()
	metrics := self.loop.metrics
	for self.loop.ctx.Err() == nil {
		self.postReplaced()
		pollStart := self.loop.clock.Now()
		after := self.view.serial
		if self.requireReload {
			// a reload comes next whatever the journal holds, so nothing need hold
			after = 0
		}
		self.park.Set(dnsFeedPark{parked: true})
		answer, err := self.loop.deps.Feed.Journal(self.loop.ctx, self.root, after)
		self.park.Set(dnsFeedPark{})
		if err == nil {
			err = self.checkAnswer(answer)
		}
		if err != nil {
			if self.loop.ctx.Err() != nil {
				return
			}
			if errors.Is(err, ErrDnsRowMalformed) || errors.Is(err, ErrDnsFormatTooNew) {
				metrics.feedRefusals.Add(1, dnsFeedRefusedLabel(err))
			} else {
				metrics.feedPolls.Add(1, dnsFeedPollError)
			}
			if !self.wait(self.nextBackoff()) {
				return
			}
			continue
		}
		self.takeInterfaces(answer.Interfaces)
		self.restoreSerial = max(self.restoreSerial, answer.RestoreSerial)
		if answer.KeyWindow != nil {
			self.takeWindow(answer.KeyWindow)
		}
		succeeded := true
		switch {
		case answer.Reload || self.requireReload:
			metrics.feedPolls.Add(1, dnsFeedPollReload)
			succeeded = self.reload()
		case len(answer.Rows) != 0:
			metrics.feedPolls.Add(1, dnsFeedPollRows)
			succeeded = self.apply(answer.Rows)
		default:
			metrics.feedPolls.Add(1, dnsFeedPollEmpty)
			// a block that answers at once with nothing cannot make the loop spin
			if elapsed := self.loop.clock.Now().Sub(pollStart); elapsed < dnsSeconds(self.loop.settings.Feed.EmptyPollSeconds) {
				if !self.wait(dnsSeconds(self.loop.settings.Feed.EmptyPollSeconds) - elapsed) {
					return
				}
			}
		}
		if !succeeded {
			if !self.wait(self.nextBackoff()) {
				return
			}
			continue
		}
		self.backoff = 0
	}
}

// Whether an answer is this root's and reads whole.
func (self *dnsFeedRoot) checkAnswer(answer *DnsFeedAnswer) error {
	if answer == nil {
		return fmt.Errorf("%w: no answer", ErrDnsRowMalformed)
	}
	if err := answer.Validate(); err != nil {
		return err
	}
	if answer.Root != self.root {
		return fmt.Errorf("%w: an answer for %s to %s's poll", ErrDnsRowMalformed, answer.Root, self.root)
	}
	return nil
}

// Reads the local snapshot and the replaced ones waiting on diffs, and serves the snapshot if it
// checks, unless requireReload, when it is the replaced one. A snapshot that does not read whole is
// discarded, and the root stays not ready until the feed gives it a view.
func (self *dnsFeedRoot) start() {
	if pending, err := self.file.Replaced(); err == nil {
		self.pending = pending
	}
	saved, err := self.file.Load(self.loop.settings)
	if errors.Is(err, fs.ErrNotExist) {
		return
	}
	if err != nil {
		self.loop.metrics.feedRefusals.Add(1, dnsFeedRefusedLabel(err))
		self.loop.log.Infof("[dnsedge] the local snapshot does not read whole; discarding it")
		self.file.Discard()
		return
	}
	self.takeInterfaces(saved.Interfaces)
	self.window = saved.KeyWindow
	self.restoreSerial = saved.RestoreSerial
	if self.requireReload {
		self.replaced = saved.View
		return
	}
	self.view = saved.View
	if keys, err := self.check(saved.View); err == nil {
		self.swap(saved.View, keys)
	}
}

// Passes interfaces on when they differ from the last, and keeps them for the local snapshot.
func (self *dnsFeedRoot) takeInterfaces(interfaces []DnsLbInterface) {
	if reflect.DeepEqual(interfaces, self.interfaces) {
		return
	}
	self.interfaces = slices.Clone(interfaces)
	if self.loop.deps.OnInterfaces != nil {
		self.loop.deps.OnInterfaces(slices.Clone(interfaces))
	}
	self.markChanged()
}

// Takes a window the feed names. One that differs from the last is checked against what serves, and
// swapped in with it when it passes; one that fails leaves the keys that serve as they are.
func (self *dnsFeedRoot) takeWindow(window *DnsKeyWindow) {
	if dnsKeyWindowsEqual(window, self.window) {
		return
	}
	self.window = window
	if self.requireReload || self.view.soa == nil {
		return
	}
	if keys, err := self.check(self.view); err == nil && !dnsKeyWindowsEqual(keys.Window(), self.keysWindow()) {
		self.swap(self.view, keys)
	}
	self.markChanged()
}

// The window what serves was checked with, or nil.
func (self *dnsFeedRoot) keysWindow() *DnsKeyWindow {
	if self.keys == nil {
		return nil
	}
	return self.keys.Window()
}

// SelfCheck of view with the newest window, or the window that serves if the newest fails.
func (self *dnsFeedRoot) check(view *ZoneView) (*DnsSigningKeys, error) {
	windows := []*DnsKeyWindow{}
	if self.window != nil {
		windows = append(windows, self.window)
	}
	if serving := self.keysWindow(); serving != nil && !dnsKeyWindowsEqual(serving, self.window) {
		windows = append(windows, serving)
	}
	err := fmt.Errorf("%w: no key window", ErrDnsSelfCheck)
	for _, window := range windows {
		var keys *DnsSigningKeys
		keys, err = SelfCheck(view, &DnsKeySet{Window: window, Zsk: self.loop.deps.Zsk}, self.anchors, self.loop.clock.Now())
		if err == nil {
			self.loop.metrics.selfChecks.Add(1, dnsSelfCheckPass)
			return keys, nil
		}
	}
	self.loop.metrics.selfChecks.Add(1, dnsSelfCheckFail)
	return nil, err
}

// Applies rows onto the view, checks the result and swaps it in, or leaves the last good view serving
// and says why not.
func (self *dnsFeedRoot) apply(rows []DnsJournalRow) bool {
	testHookBarrier("dnsservice.feed_apply.before", "")
	next, err := self.view.Apply(rows)
	if err != nil {
		self.loop.metrics.feedRefusals.Add(1, dnsFeedRefusedLabel(err))
		return false
	}
	keys, err := self.check(next)
	if err != nil {
		return false
	}
	testHookBarrier("dnsservice.feed_apply", "")
	testHookBarrier("dnsservice.feed_apply.after", "")
	self.swap(next, keys)
	return true
}

// Serves view under keys and hands it to the writer.
func (self *dnsFeedRoot) swap(view *ZoneView, keys *DnsSigningKeys) {
	testHookBarrier("dnsservice.feed_swap.before", "")
	self.loop.deps.Edge.publish(view, keys)
	testHookBarrier("dnsservice.feed_swap", "")
	self.view = view
	self.keys = keys
	self.markChanged()
	testHookBarrier("dnsservice.feed_swap.after", "")
}

// Hands what serves to the writer, which writes it once its interval passes.
func (self *dnsFeedRoot) markChanged() {
	if self.keys == nil {
		return
	}
	self.writer.set(self.savedState())
}

// What the local snapshot holds now.
func (self *dnsFeedRoot) savedState() *dnsSavedState {
	return &dnsSavedState{
		view:          self.view,
		restoreSerial: self.restoreSerial,
		window:        self.keysWindow(),
		interfaces:    slices.Clone(self.interfaces),
	}
}

// Fetches a snapshot, checks it and swaps it in whole. A view it replaces that is older than
// restore_serial is kept with its diff until the block takes the diff; any other is gone at once. The
// new view is written to the local snapshot before this returns, so a crash cannot bring back what it
// replaced.
func (self *dnsFeedRoot) reload() bool {
	rows, err := self.loop.deps.Feed.Snapshot(self.loop.ctx, self.root)
	if err != nil {
		self.loop.metrics.feedPolls.Add(1, dnsFeedPollError)
		return false
	}
	defer rows.Close()
	next, err := NewZoneView(self.loop.settings, rows)
	if err != nil {
		self.loop.metrics.feedRefusals.Add(1, dnsFeedRefusedLabel(err))
		return false
	}
	if next.root != self.root {
		self.loop.metrics.feedRefusals.Add(1, dnsFeedRefusedMalformed)
		return false
	}
	replaced := self.view
	if self.requireReload {
		replaced = self.replaced
	} else if next.serial <= self.view.serial {
		// a reload never lowers a view
		self.loop.metrics.feedRefusals.Add(1, dnsFeedRefusedLower)
		return false
	}
	keys, err := self.check(next)
	if err != nil {
		return false
	}
	restoreSerial := max(self.restoreSerial, rows.Snapshot().RestoreSerial)
	now := self.loop.clock.Now()
	if replaced != nil && 0 < replaced.serial && replaced.serial < restoreSerial {
		diff := RrsetDiff(replaced, next)
		kept, err := self.file.KeepReplaced(replaced, diff, now)
		if err != nil {
			// the diff still goes from memory; only a crash before it lands loses it
			kept = &DnsReplacedSnapshot{Diff: diff, ReloadTime: now}
		}
		self.pending = append(self.pending, kept)
	}
	self.restoreSerial = restoreSerial
	self.requireReload = false
	self.replaced = nil
	self.swap(next, keys)
	self.writer.saveNow(self.savedState())
	self.postReplaced()
	return true
}

// Posts each waiting diff, removing its replaced snapshot once the block takes it or once
// feed.replaced_keep_s has passed since its reload.
func (self *dnsFeedRoot) postReplaced() {
	if len(self.pending) == 0 {
		return
	}
	now := self.loop.clock.Now()
	keep := dnsSeconds(self.loop.settings.Feed.ReplacedKeepSeconds)
	remaining := []*DnsReplacedSnapshot{}
	for _, replaced := range self.pending {
		if keep <= now.Sub(replaced.ReloadTime) {
			self.loop.metrics.reloadDiffs.Add(1, dnsReloadDiffExpired)
			self.deleteReplaced(replaced)
			continue
		}
		if err := self.loop.deps.Feed.ReloadDiff(self.loop.ctx, replaced.Diff); err != nil {
			self.loop.metrics.reloadDiffs.Add(1, dnsReloadDiffFailed)
			remaining = append(remaining, replaced)
			continue
		}
		self.loop.metrics.reloadDiffs.Add(1, dnsReloadDiffPosted)
		self.deleteReplaced(replaced)
	}
	self.pending = remaining
}

// Removes a replaced snapshot's file, if it has one.
func (self *dnsFeedRoot) deleteReplaced(replaced *DnsReplacedSnapshot) {
	if replaced.path != "" {
		self.file.DeleteReplaced(replaced)
	}
}

// What one write of the local snapshot holds.
type dnsSavedState struct {
	view          *ZoneView
	restoreSerial uint64
	window        *DnsKeyWindow
	interfaces    []DnsLbInterface
}

// Writes a root's local snapshot off the loop, at most once each feed.snapshot_write_s, so a burst of
// rows costs one write. Generations order the writes: none older than what is on disk is written. Safe
// for concurrent use.
type dnsSnapshotWriter struct {
	file     *SnapshotFile
	clock    sidecar.Clock
	interval time.Duration
	metrics  *dnsMetrics
	// The generation last set, and the one on disk, each with its channel.
	wake    *sidecar.MonitorValue[uint64]
	written *sidecar.MonitorValue[uint64]
	// The serial of the view on disk, zero before the first write.
	writtenSerial *sidecar.MonitorValue[uint64]
	// Where run is parked: waiting for a change, which a generation newer than the one written has
	// woken, or for its interval, until a time.
	park *sidecar.MonitorValue[dnsFeedPark]

	stateLock  sync.Mutex
	state      *dnsSavedState
	generation uint64
	// Held across a write, so two writes never interleave and the generation check holds.
	writeLock sync.Mutex
}

func newDnsSnapshotWriter(file *SnapshotFile, clock sidecar.Clock, interval time.Duration, metrics *dnsMetrics) *dnsSnapshotWriter {
	return &dnsSnapshotWriter{
		file:          file,
		clock:         clock,
		interval:      interval,
		metrics:       metrics,
		wake:          sidecar.NewMonitorValue[uint64](0),
		written:       sidecar.NewMonitorValue[uint64](0),
		writtenSerial: sidecar.NewMonitorValue[uint64](0),
		park:          sidecar.NewMonitorValue(dnsFeedPark{}),
	}
}

// Hands state over as the next to write, returning its generation.
func (self *dnsSnapshotWriter) set(state *dnsSavedState) uint64 {
	generation := func() uint64 {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.generation += 1
		self.state = state
		return self.generation
	}()
	self.wake.Set(generation)
	return generation
}

// The newest state and its generation.
func (self *dnsSnapshotWriter) current() (*dnsSavedState, uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state, self.generation
}

// Writes state, unless something newer is already on disk.
func (self *dnsSnapshotWriter) save(state *dnsSavedState, generation uint64) {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if state == nil || generation <= self.written.Value() {
		return
	}
	if err := self.file.Save(state.view, state.restoreSerial, state.window, state.interfaces); err != nil {
		self.metrics.snapshotWrites.Add(1, dnsSnapshotWriteFailed)
		return
	}
	self.metrics.snapshotWrites.Add(1, dnsSnapshotWriteOk)
	self.written.Set(generation)
	self.writtenSerial.Set(state.view.serial)
}

// Hands state over and writes it now, on the caller's goroutine.
func (self *dnsSnapshotWriter) saveNow(state *dnsSavedState) {
	self.save(state, self.set(state))
}

// Writes the newest state, if it is not on disk yet.
func (self *dnsSnapshotWriter) flush() {
	self.save(self.current())
}

// Writes each change once feed.snapshot_write_s has passed since it came, until ctx ends. A failed
// write is tried again an interval later.
func (self *dnsSnapshotWriter) run(ctx context.Context) {
	for {
		generation, woken := self.wake.Get()
		if self.written.Value() < generation {
			timer := self.clock.After(self.interval)
			// the clock is read after the timer is set, as the loop's wait does
			self.park.Set(dnsFeedPark{parked: true, until: self.clock.Now().Add(self.interval)})
			testHookBarrier("dnsservice.feed_writer_interval", "")
			select {
			case <-ctx.Done():
				return
			case <-timer:
			}
			self.park.Set(dnsFeedPark{})
			self.flush()
			continue
		}
		self.park.Set(dnsFeedPark{parked: true})
		testHookBarrier("dnsservice.feed_writer_change", "")
		select {
		case <-ctx.Done():
			return
		case <-woken:
		}
		self.park.Set(dnsFeedPark{})
	}
}
