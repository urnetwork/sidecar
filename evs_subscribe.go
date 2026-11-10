// EvsRepo.Subscribe and the client's catch-up (§11.10's lease, renew, epochs, gap and loss rows; R-EVS-2, D-EVS-14,
// FS-12; EVS1-M2-27): what keeps a device's view of the repos it follows current while hints are lossy.
//
//	subscribe  Subscribe takes a ref, or every ref, and up to 16 directories or subpaths, tokenizes them in the ref's
//	           current path epoch, keeps the subscription in the evs component's sealed store, and POSTs
//	           /evs/v1/subscriptions until 200, any answer that refuses nothing tried again; a kill before the 200
//	           leaves the record, which the next start leases again. 5 s after each 200 it rereads the head fresh,
//	           which covers a commit whose evs process read the leases before this lease's write (§11.10's match row)
//	renew      a lease over 24 h old is renewed at a random time within the next hour, never because of a reconnect
//	hints      (evs_hint.go) a hint one past the repo's push sequence names the only commit between, and only its ref
//	           is read; a skip, or a sequence that fell, reads every subscribed ref of the repo, a gap and never an
//	           alarm. A hint carries no authority: it only sends a read, which verifies whatever it finds
//	resync     a reset that moved a repo's topic catches the repo up at once; every subscribed ref is read fresh
//	           hourly at a random offset, its leases listed and a lost one re-created; the first sync of a repo each
//	           UTC day lists its refs whole (GET .../refs, M6's listing); and a background daemon told of an
//	           incomplete reset first waits a random 0-10 min
//	epochs     a read showing the ref's current path epoch past a subscription's re-tokenizes its paths and leases them
//	           in the new epoch, then deletes the old epoch's leases (§11.6's leases row)
//	changes    each verified statement a read brings raises a change (ref, version, the subscribed paths it touched,
//	           signer) to the subscription's own callback and to the client's listeners: MCP sessions and §18's
//	           SidecarRepoChangeListener (AddRepoChangeListener)
//
// The subscriber's work runs in rounds (runDue) on one goroutine (run), which Start begins and Close ends; every input
// only queues work and wakes it, so a hint's path never waits. A round's I/O holds no lock. Paths are this device's
// plaintext, kept only in the sealed store and never logged (I-13).
//
// On every leg. Safe for concurrent use.

package sidecar

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.10's lease row: the prefixes one lease request names.
const evsSubscriptionMaxPrefixCount = 16

// The store's directory: subscriptions/<repo_id>, each the repo's subscriptions as JSON, rewritten whole.
const evsSubscriptionDirectory = "subscriptions/"

// A subscription Subscribe refuses before anything is sent: more than 16 paths, a path that does not split into
// names, or none of its own refs.
var ErrEvsSubscriptionInvalid = errors.New("evs: subscription invalid")

// One change a subscribed ref saw: a verified statement past this device's pin, or a gap past the catch-up budget.
type EvsRepoChange struct {
	RepoId Id
	RefId  Id
	// The ref version the statement committed at; on a gap, the head's version.
	Version         uint64
	PushId          Id
	SignerSidecarId Id
	// The subscribed directories and subpaths the change touched, as the subscriptions named them, sorted.
	Paths []string
	// A subscription of the whole ref matched.
	WholeRef bool
	// The read re-pinned past §11.9's catch-up budget, so which paths changed between is not known: every subscribed
	// path is named.
	Gap bool
	// The push moved the ref's path epoch.
	PathEpoch bool
}

// Called with each change, on the subscriber's goroutine. It must not block, and copies what it keeps.
type EvsRepoChangeFunction func(change *EvsRepoChange)

// A subscription's stored form.
type evsSubscriptionRecord struct {
	Id string `json:"id"`
	// Empty for every ref.
	RefId string   `json:"ref_id,omitempty"`
	Paths []string `json:"paths,omitempty"`
	// The epoch its prefixes are in, and each path's prefix in it, by KeyString, "" for the whole ref.
	PathEpoch uint64   `json:"path_epoch"`
	Prefixes  []string `json:"prefixes,omitempty"`
	// When its lease last answered 200; 0 while one is still owed.
	LeasedAtMs int64 `json:"leased_at_ms,omitempty"`
}

// One subscription as the subscriber holds it.
type evsSubscriptionState struct {
	id     Id
	repoId Id
	// nil: every ref
	refId *Id
	paths []string
	// the epoch the lease is in, and each path's token prefix there
	pathEpoch uint64
	prefixes  []EvsTokenPath
	// zero while a lease is owed: a new subscription, a lost lease, a new epoch
	leasedAt time.Time
	// the renewal's random time once the lease passed SubscribeRenewAge, zero before
	renewAt time.Time
	// when an owed lease may be tried next, and how many tries in a row failed
	leaseDueAt        time.Time
	leaseFailureCount int
	// a previous epoch's prefixes to delete once the new epoch's lease lands
	staleEpoch    uint64
	stalePrefixes []EvsTokenPath
	callback      EvsRepoChangeFunction
}

// What a round reads of one repo: some refs, or every subscribed ref.
type evsSyncRequest struct {
	refIds map[Id]bool
	all    bool
	fresh  bool
	// not before this, zero for now
	dueAt time.Time
}

// A client's subscriptions and catch-up. See the file header.
type evsSubscriber struct {
	client *EvsClient
	// a random duration in [0, limit), which a test fixes
	random func(limit time.Duration) time.Duration

	// serializes store writes, outside stateLock
	writeLock sync.Mutex

	stateLock     sync.Mutex
	loaded        bool
	subscriptions map[Id]*evsSubscriptionState
	syncs         map[Id]*evsSyncRequest
	// each repo's push sequence as the last hint or listing gave it
	repoSequences map[Id]uint64
	// the UTC day of each repo's last whole listing
	repoListedDays map[Id]string
	nextResyncAt   time.Time
	// a full resync owed after an incomplete reset, not before this
	resetResyncAt time.Time
	listeners     map[int]*evsRepoChangeListener
	listenerSeq   int
	// leases of ended subscriptions, which the next round deletes
	pendingDeletes []*evsSubscriptionView
	// the run loop's lifetime, and its end
	runCancel context.CancelFunc
	runDone   chan struct{}
	wake      chan struct{}
	// rounds done, for a test to wait on
	roundCount *MonitorValue[int]
}

// A listener of one repo's changes, or every repo's.
type evsRepoChangeListener struct {
	repoId   *Id
	listener EvsRepoChangeFunction
}

// A subscriber of client, with nothing loaded until a call needs it.
func newEvsSubscriber(client *EvsClient) *evsSubscriber {
	return &evsSubscriber{
		client:         client,
		random:         evsRandomDuration,
		subscriptions:  map[Id]*evsSubscriptionState{},
		syncs:          map[Id]*evsSyncRequest{},
		repoSequences:  map[Id]uint64{},
		repoListedDays: map[Id]string{},
		listeners:      map[int]*evsRepoChangeListener{},
		wake:           make(chan struct{}, 1),
		roundCount:     NewMonitorValue(0),
	}
}

// A uniform random duration in [0, limit), 0 for a limit that is not positive.
func evsRandomDuration(limit time.Duration) time.Duration {
	if limit <= 0 {
		return 0
	}
	var randomBytes [8]byte
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(randomBytes[:])
	return time.Duration(binary.BigEndian.Uint64(randomBytes[:]) % uint64(limit))
}

// A live subscription, which Close ends.
type EvsSubscription struct {
	cancel func()
}

// Ends the subscription: its record goes, and its leases are deleted on the subscriber's next round.
func (self *EvsSubscription) Close() {
	if self != nil && self.cancel != nil {
		self.cancel()
	}
}

// What Subscribe leases (§11.10; EVS1-M2-27).
type EvsSubscribeArgs struct {
	// The ref's name bytes; nil with no RefId: every ref of the repo.
	RefName []byte
	// The ref's id, for a ref whose name is not a named ref's. Overrides RefName.
	RefId *Id
	// Directories and subpaths, raw names joined by /, at most 16; empty: the whole ref. "" names the whole ref too.
	Paths []string
	// The subscription's own changes, beside the client's listeners. nil for none.
	Changes EvsRepoChangeFunction
}

// Leases a subscription (see the file header) and answers once its lease answered 200, or once the caller's ctx ended
// with the lease still owed, which the subscriber's rounds keep trying. A refusal that is final (a scope, a cap, an
// invalid request) drops the subscription and is the answer.
func (self *EvsRepo) Subscribe(ctx context.Context, args *EvsSubscribeArgs) (*EvsSubscription, error) {
	return self.client.subscriber.subscribe(ctx, self, args)
}

// Calls listener with every change of repoId's subscribed refs, or of every repo's with nil, until remove.
func (self *EvsClient) AddRepoChangeListener(repoId *Id, listener EvsRepoChangeFunction) (remove func()) {
	subscriber := self.subscriber
	subscriber.stateLock.Lock()
	defer subscriber.stateLock.Unlock()
	subscriber.listenerSeq += 1
	listenerId := subscriber.listenerSeq
	var repoIdCopy *Id
	if repoId != nil {
		copied := *repoId
		repoIdCopy = &copied
	}
	subscriber.listeners[listenerId] = &evsRepoChangeListener{repoId: repoIdCopy, listener: listener}
	return func() {
		subscriber.stateLock.Lock()
		defer subscriber.stateLock.Unlock()
		delete(subscriber.listeners, listenerId)
	}
}

// Begins the subscriber's rounds: the stored subscriptions load, every one owed a lease is leased, and the hourly
// resync starts at a random offset. Rounds run until Close. Calling it again does nothing.
func (self *EvsClient) StartSubscriptions() error {
	return self.subscriber.start()
}

// Ends the subscriber's rounds and returns once the round in progress, if any, has. Subscriptions stay in the store
// for the next start.
func (self *EvsClient) Close() {
	self.subscriber.stateLock.Lock()
	cancel, done := self.subscriber.runCancel, self.subscriber.runDone
	self.subscriber.runCancel, self.subscriber.runDone = nil, nil
	self.subscriber.stateLock.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

// See StartSubscriptions.
func (self *evsSubscriber) start() error {
	if err := self.load(); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.runCancel != nil {
			return false
		}
		self.runCancel, self.runDone = cancel, done
		return true
	}()
	if !started {
		cancel()
		return nil
	}
	go self.run(ctx, done)
	return nil
}

// The rounds, each at the next due time or a wake, until ctx ends; done closes then.
func (self *evsSubscriber) run(ctx context.Context, done chan struct{}) {
	defer close(done)
	for {
		next := self.runDue(ctx)
		var timer <-chan time.Time
		if !next.IsZero() {
			timer = self.client.clock.After(max(0, next.Sub(self.client.clock.Now())))
		}
		select {
		case <-ctx.Done():
			return
		case <-self.wake:
		case <-timer:
		}
	}
}

// Wakes the rounds without waiting.
func (self *evsSubscriber) wakeRounds() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Reads the stored subscriptions once. A file that does not decode is an error, never an empty set.
func (self *evsSubscriber) load() error {
	self.stateLock.Lock()
	loaded := self.loaded
	self.stateLock.Unlock()
	if loaded {
		return nil
	}
	entries, err := self.client.args.Store.List(evsSubscriptionDirectory)
	if err != nil {
		return err
	}
	states := []*evsSubscriptionState{}
	for _, entry := range entries {
		repoId, err := ParseId(strings.TrimPrefix(entry.Name, evsSubscriptionDirectory))
		if err != nil {
			continue
		}
		data, err := self.readFile(entry.Name)
		if err != nil {
			return err
		}
		records := []*evsSubscriptionRecord{}
		if err := json.Unmarshal(data, &records); err != nil {
			return fmt.Errorf("%w: evs subscriptions", ErrSidecarStoreFailed)
		}
		for _, record := range records {
			state, err := evsSubscriptionStateOf(repoId, record)
			if err != nil {
				return err
			}
			states = append(states, state)
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.loaded {
		return nil
	}
	for _, state := range states {
		self.subscriptions[state.id] = state
	}
	self.loaded = true
	return nil
}

// A stored record's state.
func evsSubscriptionStateOf(repoId Id, record *evsSubscriptionRecord) (*evsSubscriptionState, error) {
	refused := fmt.Errorf("%w: an evs subscription", ErrSidecarStoreFailed)
	id, err := ParseId(record.Id)
	if err != nil {
		return nil, refused
	}
	state := &evsSubscriptionState{id: id, repoId: repoId, paths: record.Paths, pathEpoch: record.PathEpoch}
	if record.RefId != "" {
		refId, err := ParseId(record.RefId)
		if err != nil {
			return nil, refused
		}
		state.refId = &refId
	}
	for _, prefixText := range record.Prefixes {
		prefix, err := parseEvsTokenPathKey(prefixText)
		if err != nil {
			return nil, refused
		}
		state.prefixes = append(state.prefixes, prefix)
	}
	if 0 < record.LeasedAtMs {
		state.leasedAt = time.UnixMilli(record.LeasedAtMs)
	}
	return state, nil
}

// A token path from its KeyString, the empty path from "".
func parseEvsTokenPathKey(text string) (EvsTokenPath, error) {
	if text == "" {
		return EvsTokenPath{}, nil
	}
	tokenPath := EvsTokenPath{}
	for _, component := range strings.Split(text, "/") {
		token, err := ParseEvsToken(component)
		if err != nil {
			return nil, err
		}
		tokenPath = append(tokenPath, token)
	}
	return tokenPath, nil
}

// One file's bytes.
func (self *evsSubscriber) readFile(name string) ([]byte, error) {
	reader, err := self.client.args.Store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// Rewrites repoId's subscriptions file from memory, or removes it when none is left.
func (self *evsSubscriber) persist(repoId Id) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	records := func() []*evsSubscriptionRecord {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		records := []*evsSubscriptionRecord{}
		for _, state := range self.subscriptions {
			if state.repoId != repoId {
				continue
			}
			record := &evsSubscriptionRecord{Id: state.id.String(), Paths: state.paths, PathEpoch: state.pathEpoch}
			if state.refId != nil {
				record.RefId = state.refId.String()
			}
			for _, prefix := range state.prefixes {
				record.Prefixes = append(record.Prefixes, prefix.KeyString())
			}
			if !state.leasedAt.IsZero() {
				record.LeasedAtMs = state.leasedAt.UnixMilli()
			}
			records = append(records, record)
		}
		slices.SortFunc(records, func(a *evsSubscriptionRecord, b *evsSubscriptionRecord) int { return strings.Compare(a.Id, b.Id) })
		return records
	}()
	name := evsSubscriptionDirectory + repoId.String()
	if len(records) == 0 {
		return self.client.args.Store.Remove(name)
	}
	data, err := json.Marshal(records)
	if err != nil {
		return err
	}
	writer, err := self.client.args.Store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// See EvsRepo.Subscribe.
func (self *evsSubscriber) subscribe(ctx context.Context, repo *EvsRepo, args *EvsSubscribeArgs) (*EvsSubscription, error) {
	if args == nil || evsSubscriptionMaxPrefixCount < len(args.Paths) {
		return nil, fmt.Errorf("%w: more than %d paths", ErrEvsSubscriptionInvalid, evsSubscriptionMaxPrefixCount)
	}
	for _, path := range args.Paths {
		if path == "" {
			continue
		}
		if _, err := evsPathNames(path); err != nil {
			return nil, fmt.Errorf("%w: a path that does not split into names", ErrEvsSubscriptionInvalid)
		}
	}
	if err := self.load(); err != nil {
		return nil, err
	}
	state := &evsSubscriptionState{id: NewEvsRepoId(), repoId: repo.repoId, paths: slices.Clone(args.Paths), callback: args.Changes}
	epochRefId := Id{}
	if args.RefId != nil || args.RefName != nil {
		refId, err := repo.resolveRefId(ctx, args.RefName, args.RefId)
		if err != nil {
			return nil, err
		}
		state.refId = &refId
		epochRefId = refId
	} else {
		// every ref: leased in main's current epoch, which a PATH_EPOCH on main moves
		mainRefId, err := repo.resolveRefId(ctx, nil, nil)
		if err != nil {
			return nil, err
		}
		epochRefId = mainRefId
	}
	pathEpoch, err := self.currentEpoch(ctx, repo, epochRefId)
	if err != nil {
		return nil, err
	}
	if err := self.tokenizeState(ctx, repo, state, pathEpoch); err != nil {
		return nil, err
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.subscriptions[state.id] = state
	}()
	if err := self.persist(repo.repoId); err != nil {
		self.drop(state.id)
		return nil, err
	}
	subscription := &EvsSubscription{cancel: func() { self.unsubscribe(state.id) }}
	for attempt := 0; ; attempt += 1 {
		err := self.lease(ctx, state.id)
		if err == nil {
			return subscription, nil
		}
		if !evsLeaseRetries(err) {
			self.drop(state.id)
			self.persist(repo.repoId)
			return nil, err
		}
		if self.client.settings.SubscribeRetryCount <= attempt {
			// owed: the rounds keep trying until 200
			self.wakeRounds()
			return subscription, nil
		}
		wait := func() time.Duration {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return max(0, state.leaseDueAt.Sub(self.client.clock.Now()))
		}()
		select {
		case <-ctx.Done():
			self.wakeRounds()
			return subscription, nil
		case <-self.client.clock.After(wait):
		}
	}
}

// Whether a lease's error is one to try again: an answer that refuses nothing, no answer at all, or a lost token. A
// refusal that settles (a scope, a cap, an invalid request) is final.
func evsLeaseRetries(err error) bool {
	if evsError, ok := EvsErrorOf(err); ok {
		return evsError.RefusesNothing()
	}
	return !errors.Is(err, ErrEvsSubscriptionInvalid) && !errors.Is(err, context.Canceled)
}

// The ref's current path epoch: from the last verified head, else one head read, which verifies and pins.
func (self *evsSubscriber) currentEpoch(ctx context.Context, repo *EvsRepo, refId Id) (uint64, error) {
	if epoch := self.client.refEpoch(repo.repoId, refId); epoch != nil {
		return max(1, epoch.GetCurrent()), nil
	}
	result, err := repo.read(ctx, refId, nil, 0, false)
	if err != nil {
		return 0, err
	}
	result.objects.close()
	return max(1, result.head.Head.GetPathEpoch().GetCurrent()), nil
}

// Each path's token prefix in epoch, written into state.
func (self *evsSubscriber) tokenizeState(ctx context.Context, repo *EvsRepo, state *evsSubscriptionState, epoch uint64) error {
	prefixes, err := self.tokenizePaths(ctx, repo, state.paths, epoch)
	if err != nil {
		return err
	}
	state.pathEpoch = epoch
	state.prefixes = prefixes
	return nil
}

// Each path's token prefix in epoch, the empty path for "".
func (self *evsSubscriber) tokenizePaths(ctx context.Context, repo *EvsRepo, paths []string, epoch uint64) ([]EvsTokenPath, error) {
	keys := newEvsReadKeys(repo)
	prefixes := []EvsTokenPath{}
	for _, path := range paths {
		if path == "" {
			prefixes = append(prefixes, EvsTokenPath{})
			continue
		}
		names, err := evsPathNames(path)
		if err != nil {
			return nil, err
		}
		pathKey, err := keys.path(ctx, epoch)
		if err != nil {
			return nil, err
		}
		tokenPath, err := EvsPathTokens(pathKey, names)
		if err != nil {
			return nil, err
		}
		prefixes = append(prefixes, tokenPath)
	}
	return prefixes, nil
}

// Drops a subscription from memory.
func (self *evsSubscriber) drop(id Id) *evsSubscriptionState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	state := self.subscriptions[id]
	delete(self.subscriptions, id)
	return state
}

// Ends a subscription: its record goes now, and its leases, those no other subscription still leases, at the next
// round, a delete that fails being left to the leases' 7-day life.
func (self *evsSubscriber) unsubscribe(id Id) {
	state := self.drop(id)
	if state == nil {
		return
	}
	self.persist(state.repoId)
	if state.leasedAt.IsZero() {
		return
	}
	prefixes := state.prefixes
	if len(prefixes) == 0 {
		prefixes = []EvsTokenPath{{}}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.pendingDeletes = append(self.pendingDeletes, &evsSubscriptionView{
			id: state.id, refId: state.refId, paths: state.paths, pathEpoch: state.pathEpoch, prefixes: prefixes,
			repoId: state.repoId,
		})
	}()
	self.wakeRounds()
}

// The prefixes no other subscription of the same repo, ref and epoch leases: what a delete of an ended one's may take.
func (self *evsSubscriber) unsharedPrefixes(ended *evsSubscriptionView) []EvsTokenPath {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	unshared := []EvsTokenPath{}
	for _, prefix := range ended.prefixes {
		shared := false
		for _, other := range self.subscriptions {
			if other.id == ended.id || other.repoId != ended.repoId || other.pathEpoch != ended.pathEpoch || !evsSameRef(other.refId, ended.refId) {
				continue
			}
			otherPrefixes := other.prefixes
			if len(otherPrefixes) == 0 {
				otherPrefixes = []EvsTokenPath{{}}
			}
			shared = shared || slices.ContainsFunc(otherPrefixes, prefix.Equal)
		}
		if !shared {
			unshared = append(unshared, prefix)
		}
	}
	return unshared
}

// Whether two subscriptions name the same ref, every ref included.
func evsSameRef(a *Id, b *Id) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// One POST /evs/v1/subscriptions of a subscription's lease. On 200 the lease's time is kept, its reread queued for
// SubscribeRereadDelay on, and an older epoch's leases deleted; on any other answer the next try waits, doubling.
func (self *evsSubscriber) lease(ctx context.Context, id Id) error {
	request, repoId, refId, ok := func() (*protocol.EvsSubscriptionRequest, Id, *Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.subscriptions[id]
		if state == nil {
			return nil, Id{}, nil, false
		}
		return evsSubscriptionRequestOf(state.repoId, state.refId, state.pathEpoch, state.prefixes), state.repoId, state.refId, true
	}()
	if !ok {
		return nil
	}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "POST /evs/v1/subscriptions",
		method: http.MethodPost,
		path:   "/evs/v1/subscriptions",
		repoId: repoId,
		role:   evsScopeRead,
		body:   request,
	}, nil)
	now := self.client.clock.Now()
	var stale *evsSubscriptionState
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state := self.subscriptions[id]
		if state == nil {
			return
		}
		if err != nil {
			state.leaseFailureCount += 1
			wait := self.client.settings.SubscribeRetryMinWait << min(16, state.leaseFailureCount-1)
			if !evsLeaseRetries(err) {
				// final for now: asked again at the hourly resync's pace
				wait = self.client.settings.SubscribeResyncInterval
			}
			state.leaseDueAt = now.Add(min(wait, self.client.settings.SubscribeRetryMaxWait))
			return
		}
		state.leasedAt = now
		state.renewAt = time.Time{}
		state.leaseDueAt = time.Time{}
		state.leaseFailureCount = 0
		if 0 < state.staleEpoch {
			stale = &evsSubscriptionState{id: state.id, repoId: state.repoId, refId: state.refId, pathEpoch: state.staleEpoch, prefixes: state.stalePrefixes}
			state.staleEpoch = 0
			state.stalePrefixes = nil
		}
		self.queueSyncWithLock(state.repoId, state.refId, true, now.Add(self.client.settings.SubscribeRereadDelay))
	}()
	if err != nil {
		return err
	}
	if perr := self.persist(repoId); perr != nil {
		return perr
	}
	if stale != nil {
		self.deleteLeases(ctx, stale.repoId, refId, stale.pathEpoch, stale.prefixes)
	}
	return nil
}

// A lease request's body: no prefix for a subscription of the whole ref, else its prefixes, an empty one standing
// for the whole ref.
func evsSubscriptionRequestOf(repoId Id, refId *Id, pathEpoch uint64, prefixes []EvsTokenPath) *protocol.EvsSubscriptionRequest {
	request := &protocol.EvsSubscriptionRequest{RepoId: repoId.Bytes(), PathEpoch: pathEpoch}
	if refId != nil {
		request.RefId = refId.Bytes()
	}
	for _, prefix := range prefixes {
		request.Prefixes = append(request.Prefixes, prefix.Proto())
	}
	return request
}

// DELETE /evs/v1/subscriptions of the caller's leases on a ref in epoch: the prefixes named, nothing when none is.
// A failure is left to the leases' 7-day life.
func (self *evsSubscriber) deleteLeases(ctx context.Context, repoId Id, refId *Id, epoch uint64, prefixes []EvsTokenPath) {
	if len(prefixes) == 0 {
		return
	}
	request := evsSubscriptionRequestOf(repoId, refId, epoch, prefixes)
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "DELETE /evs/v1/subscriptions",
		method: http.MethodDelete,
		path:   "/evs/v1/subscriptions",
		repoId: repoId,
		role:   evsScopeRead,
		body:   request,
	}, nil)
	if err != nil {
		self.client.log.Infof("[evs]a lease delete went unanswered; the lease lapses in 7 d")
	}
}

// Queues a read of refId of repoId, or of every subscribed ref with nil, at dueAt (zero for now). An earlier due
// time, a wider set or fresh wins over what is queued.
func (self *evsSubscriber) queueSyncWithLock(repoId Id, refId *Id, fresh bool, dueAt time.Time) {
	request := self.syncs[repoId]
	if request == nil {
		request = &evsSyncRequest{refIds: map[Id]bool{}, dueAt: dueAt}
		self.syncs[repoId] = request
	} else if dueAt.Before(request.dueAt) {
		request.dueAt = dueAt
	}
	if refId == nil {
		request.all = true
	} else {
		request.refIds[*refId] = true
	}
	request.fresh = request.fresh || fresh
}

// Whether repoId has a subscription.
func (self *evsSubscriber) followsWithLock(repoId Id) bool {
	for _, state := range self.subscriptions {
		if state.repoId == repoId {
			return true
		}
	}
	return false
}

// One round at the clock's now: owed leases, renewals, the hourly resync and an incomplete reset's, then the reads
// due. Answers when the next work is due, zero for none.
func (self *evsSubscriber) runDue(ctx context.Context) time.Time {
	defer self.roundCount.Update(func(count int) int { return count + 1 })
	if self.load() != nil {
		return self.client.clock.Now().Add(self.client.settings.SubscribeRetryMaxWait)
	}
	now := self.client.clock.Now()
	settings := self.client.settings
	leaseIds := []Id{}
	resyncRepoIds := []Id{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, state := range self.subscriptions {
			if state.leasedAt.IsZero() {
				if !now.Before(state.leaseDueAt) {
					leaseIds = append(leaseIds, state.id)
				}
				continue
			}
			if state.renewAt.IsZero() && !now.Before(state.leasedAt.Add(settings.SubscribeRenewAge)) {
				// once over 24 h old, at a random time within the next hour (§11.10's renew row)
				state.renewAt = now.Add(self.random(settings.SubscribeRenewWindow))
			}
			if !state.renewAt.IsZero() && !now.Before(state.renewAt) {
				leaseIds = append(leaseIds, state.id)
			}
		}
		if len(self.subscriptions) == 0 {
			// nothing to resync, and no timer: the rounds wait for a subscription's wake
			self.nextResyncAt = time.Time{}
			return
		}
		if self.nextResyncAt.IsZero() {
			// hourly at a random offset (§11.10's gap row)
			self.nextResyncAt = now.Add(self.random(settings.SubscribeResyncInterval))
		}
		resetDue := !self.resetResyncAt.IsZero() && !now.Before(self.resetResyncAt)
		if !now.Before(self.nextResyncAt) || resetDue {
			if !now.Before(self.nextResyncAt) {
				self.nextResyncAt = now.Add(settings.SubscribeResyncInterval)
			}
			self.resetResyncAt = time.Time{}
			for _, state := range self.subscriptions {
				if !slices.Contains(resyncRepoIds, state.repoId) {
					resyncRepoIds = append(resyncRepoIds, state.repoId)
				}
			}
		}
	}()
	for _, id := range leaseIds {
		self.lease(ctx, id)
	}
	pendingDeletes := func() []*evsSubscriptionView {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pendingDeletes := self.pendingDeletes
		self.pendingDeletes = nil
		return pendingDeletes
	}()
	for _, ended := range pendingDeletes {
		self.deleteLeases(ctx, ended.repoId, ended.refId, ended.pathEpoch, self.unsharedPrefixes(ended))
	}
	for _, repoId := range resyncRepoIds {
		self.resyncLeases(ctx, repoId)
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.queueSyncWithLock(repoId, nil, true, time.Time{})
		}()
	}
	for _, repoId := range self.dueSyncs(now) {
		self.syncRepo(ctx, repoId)
	}
	return self.nextDue()
}

// The repos whose queued reads are due at now, their requests kept until the read takes them.
func (self *evsSubscriber) dueSyncs(now time.Time) []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoIds := []Id{}
	for repoId, request := range self.syncs {
		if !now.Before(request.dueAt) {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, func(a Id, b Id) int { return strings.Compare(a.String(), b.String()) })
	return repoIds
}

// When the next work is due: a lease, a renewal, a queued read, the resyncs. Zero for none, with no subscription.
func (self *evsSubscriber) nextDue() time.Time {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if 0 < len(self.pendingDeletes) {
		return self.client.clock.Now()
	}
	if len(self.subscriptions) == 0 {
		return time.Time{}
	}
	next := self.nextResyncAt
	earlier := func(at time.Time) {
		if !at.IsZero() && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}
	earlier(self.resetResyncAt)
	for _, state := range self.subscriptions {
		switch {
		case state.leasedAt.IsZero():
			earlier(state.leaseDueAt)
			if state.leaseDueAt.IsZero() {
				earlier(self.client.clock.Now())
			}
		case !state.renewAt.IsZero():
			earlier(state.renewAt)
		default:
			earlier(state.leasedAt.Add(self.client.settings.SubscribeRenewAge))
		}
	}
	for _, request := range self.syncs {
		earlier(request.dueAt)
		if request.dueAt.IsZero() {
			earlier(self.client.clock.Now())
		}
	}
	return next
}

// The hourly resync's lease half (§11.10's loss row): the caller's live leases on the repo, and every subscription
// whose lease is not among them owed one again. A listing that does not answer re-creates nothing: the reads still
// run, and the next resync tries again.
func (self *evsSubscriber) resyncLeases(ctx context.Context, repoId Id) {
	reply := &protocol.EvsSubscriptionsReply{}
	err := self.client.http.callMessage(ctx, &evsCall{
		route:  "GET /evs/v1/subscriptions",
		method: http.MethodGet,
		path:   "/evs/v1/subscriptions?repo_id=" + evsUrlId(repoId),
		repoId: repoId,
		role:   evsScopeRead,
		retry:  true,
	}, reply)
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, subscription := range reply.GetSubscriptions() {
		prefix, err := ParseEvsTokenPath(subscription.GetPrefix().GetToken())
		if err != nil {
			continue
		}
		live[evsLeaseKey(subscription.GetRefId(), subscription.GetPathEpoch(), prefix)] = true
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, state := range self.subscriptions {
		if state.repoId != repoId || state.leasedAt.IsZero() {
			continue
		}
		var refBytes []byte
		if state.refId != nil {
			refBytes = state.refId.Bytes()
		}
		prefixes := state.prefixes
		if len(prefixes) == 0 {
			prefixes = []EvsTokenPath{{}}
		}
		for _, prefix := range prefixes {
			if !live[evsLeaseKey(refBytes, state.pathEpoch, prefix)] {
				state.leasedAt = time.Time{}
				state.leaseDueAt = time.Time{}
				break
			}
		}
	}
}

// One lease's identity as a listing names it.
func evsLeaseKey(refId []byte, epoch uint64, prefix EvsTokenPath) string {
	return fmt.Sprintf("%x|%d|%s", refId, epoch, prefix.KeyString())
}

// The reads queued for repoId: each ref asked, or every subscribed ref (a whole repo's subscription listing the repo's
// refs), each verified and pinned, its new statements raised as changes; a ref whose current epoch moved past a
// subscription's re-tokenizes it. A read that fails is queued again after ReadRetryWait.
func (self *evsSubscriber) syncRepo(ctx context.Context, repoId Id) {
	request := func() *evsSyncRequest {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		request := self.syncs[repoId]
		delete(self.syncs, repoId)
		return request
	}()
	if request == nil {
		return
	}
	repo := self.client.Repo(repoId)
	refIds, err := self.refsToRead(ctx, repo, request)
	if err != nil {
		self.requeue(repoId, request)
		return
	}
	for _, refId := range refIds {
		result, err := repo.read(ctx, refId, nil, 0, request.fresh)
		if err != nil {
			self.requeue(repoId, &evsSyncRequest{refIds: map[Id]bool{refId: true}, fresh: request.fresh})
			continue
		}
		result.objects.close()
		self.raiseChanges(ctx, repo, refId, result.head)
	}
}

// Queues request again after ReadRetryWait.
func (self *evsSubscriber) requeue(repoId Id, request *evsSyncRequest) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dueAt := self.client.clock.Now().Add(self.client.settings.ReadRetryWait)
	if request.all {
		self.queueSyncWithLock(repoId, nil, request.fresh, dueAt)
	}
	for refId := range request.refIds {
		self.queueSyncWithLock(repoId, &refId, request.fresh, dueAt)
	}
}

// The refs a sync reads: the ones asked that a subscription follows, and with all every subscribed ref, a whole repo's
// subscription adding the repo's refs as the day's listing (GET .../refs) gives them, else as this device's pins and
// main do.
func (self *evsSubscriber) refsToRead(ctx context.Context, repo *EvsRepo, request *evsSyncRequest) ([]Id, error) {
	refIdSet := map[Id]bool{}
	everyRef := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, state := range self.subscriptions {
			if state.repoId != repo.repoId {
				continue
			}
			if state.refId == nil {
				everyRef = true
				continue
			}
			if request.all || request.refIds[*state.refId] {
				refIdSet[*state.refId] = true
			}
		}
	}()
	if everyRef {
		if request.all {
			listed, err := self.listRefs(ctx, repo)
			if err != nil {
				return nil, err
			}
			for _, refId := range listed {
				refIdSet[refId] = true
			}
		} else {
			for refId := range request.refIds {
				refIdSet[refId] = true
			}
		}
	}
	refIds := []Id{}
	for refId := range refIdSet {
		refIds = append(refIds, refId)
	}
	slices.SortFunc(refIds, func(a Id, b Id) int { return strings.Compare(a.String(), b.String()) })
	return refIds, nil
}

// Every ref of a repo for a whole repo's subscription: the first listing each UTC day is GET .../refs with no
// moved_after (M6's listing), later ones and a listing that does not answer fall back to the refs this device holds
// pins of, and main.
func (self *evsSubscriber) listRefs(ctx context.Context, repo *EvsRepo) ([]Id, error) {
	refIdSet := map[Id]bool{}
	mainRefId, err := repo.resolveRefId(ctx, nil, nil)
	if err != nil {
		return nil, err
	}
	refIdSet[mainRefId] = true
	pins, err := self.client.pins.Pins(&repo.repoId)
	if err != nil {
		return nil, err
	}
	for _, pin := range pins {
		refIdSet[pin.RefId] = true
	}
	day := self.client.clock.Now().UTC().Format(time.DateOnly)
	listed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.repoListedDays[repo.repoId] == day
	}()
	if !listed {
		reply := &protocol.EvsRefsReply{}
		err := self.client.http.callMessage(ctx, &evsCall{
			route:  "GET /evs/v1/repos/{repo_id}/refs",
			method: http.MethodGet,
			path:   "/evs/v1/repos/" + evsUrlId(repo.repoId) + "/refs",
			repoId: repo.repoId,
			role:   evsScopeRead,
			retry:  true,
		}, reply)
		if err == nil {
			for _, head := range reply.GetRefs() {
				if refId, err := IdFromBytes(head.GetRefId()); err == nil {
					refIdSet[refId] = true
				}
			}
			self.stateLock.Lock()
			self.repoListedDays[repo.repoId] = day
			if self.repoSequences[repo.repoId] < reply.GetPushSequence() {
				self.repoSequences[repo.repoId] = reply.GetPushSequence()
			}
			self.stateLock.Unlock()
		}
	}
	refIds := []Id{}
	for refId := range refIdSet {
		refIds = append(refIds, refId)
	}
	slices.SortFunc(refIds, func(a Id, b Id) int { return strings.Compare(a.String(), b.String()) })
	return refIds, nil
}

// A subscription as one round's read sees it, copied under the lock.
type evsSubscriptionView struct {
	id        Id
	repoId    Id
	refId     *Id
	paths     []string
	pathEpoch uint64
	prefixes  []EvsTokenPath
	callback  EvsRepoChangeFunction
}

// The changes a verified read of refId brought: each statement after the read's pin against each subscription of the
// ref, then an epoch past a subscription's re-tokenized and owed a lease.
func (self *evsSubscriber) raiseChanges(ctx context.Context, repo *EvsRepo, refId Id, head *EvsVerifiedHead) {
	views := func() []*evsSubscriptionView {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		views := []*evsSubscriptionView{}
		for _, state := range self.subscriptions {
			if state.repoId == repo.repoId && (state.refId == nil || *state.refId == refId) {
				views = append(views, &evsSubscriptionView{
					id: state.id, refId: state.refId, paths: state.paths, pathEpoch: state.pathEpoch,
					prefixes: state.prefixes, callback: state.callback,
				})
			}
		}
		slices.SortFunc(views, func(a *evsSubscriptionView, b *evsSubscriptionView) int {
			return strings.Compare(a.id.String(), b.id.String())
		})
		return views
	}()
	if len(views) == 0 {
		return
	}
	// each subscription's prefixes in each epoch a statement is in, derived once a read
	epochPrefixes := map[Id]map[uint64][]EvsTokenPath{}
	prefixesIn := func(view *evsSubscriptionView, epoch uint64) []EvsTokenPath {
		if epoch == view.pathEpoch {
			return view.prefixes
		}
		byEpoch := epochPrefixes[view.id]
		if byEpoch == nil {
			byEpoch = map[uint64][]EvsTokenPath{}
			epochPrefixes[view.id] = byEpoch
		}
		prefixes, ok := byEpoch[epoch]
		if !ok {
			var err error
			if prefixes, err = self.tokenizePaths(ctx, repo, view.paths, epoch); err != nil {
				// no key for that epoch: every path counts as touched, never as untouched
				prefixes = nil
			}
			byEpoch[epoch] = prefixes
		}
		return prefixes
	}
	changes := []*EvsRepoChange{}
	viewChanges := map[Id][]*EvsRepoChange{}
	if head.Gap {
		change := &EvsRepoChange{RepoId: repo.repoId, RefId: refId, Version: head.Version, Gap: true}
		for _, view := range views {
			change.WholeRef = change.WholeRef || len(view.paths) == 0
			change.Paths = append(change.Paths, view.paths...)
			viewChanges[view.id] = append(viewChanges[view.id], &EvsRepoChange{
				RepoId: repo.repoId, RefId: refId, Version: head.Version, Gap: true, Paths: evsSortedPaths(view.paths), WholeRef: len(view.paths) == 0,
			})
		}
		change.Paths = evsSortedPaths(change.Paths)
		changes = append(changes, change)
	}
	for _, verified := range head.Statements {
		push := verified.Statement.Push
		touched := evsStatementTokenPaths(verified.Statement)
		change := &EvsRepoChange{
			RepoId:    repo.repoId,
			RefId:     refId,
			Version:   verified.Version,
			PathEpoch: push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0,
		}
		change.PushId, _ = IdFromBytes(push.GetPushId())
		change.SignerSidecarId, _ = IdFromBytes(push.GetSignerSidecarId())
		matched := false
		for _, view := range views {
			own := &EvsRepoChange{RepoId: change.RepoId, RefId: refId, Version: change.Version, PushId: change.PushId,
				SignerSidecarId: change.SignerSidecarId, PathEpoch: change.PathEpoch}
			if len(view.paths) == 0 {
				own.WholeRef = true
			} else {
				prefixes := prefixesIn(view, max(1, push.GetPathEpoch()))
				for i, path := range view.paths {
					if prefixes == nil || len(prefixes[i]) == 0 || evsTokenPathsTouch(prefixes[i], touched) {
						own.Paths = append(own.Paths, path)
					}
				}
			}
			if !own.WholeRef && len(own.Paths) == 0 {
				continue
			}
			matched = true
			change.WholeRef = change.WholeRef || own.WholeRef
			change.Paths = append(change.Paths, own.Paths...)
			own.Paths = evsSortedPaths(own.Paths)
			viewChanges[view.id] = append(viewChanges[view.id], own)
		}
		if matched {
			change.Paths = evsSortedPaths(change.Paths)
			changes = append(changes, change)
		}
	}
	self.deliver(repo.repoId, views, changes, viewChanges)
	self.followEpoch(ctx, repo, refId, head, views)
}

// Every token path a statement names: its changes, or with its list not inline, its covering prefixes.
func evsStatementTokenPaths(statement *EvsStatement) []EvsTokenPath {
	tokenPaths := []EvsTokenPath{}
	for _, change := range statement.Changes {
		tokenPaths = append(tokenPaths, change.TokenPath)
	}
	return append(tokenPaths, statement.ChangedPrefixes...)
}

// Whether prefix and any of tokenPaths are on one branch of the tree: one a prefix of the other (§11.10's match row).
func evsTokenPathsTouch(prefix EvsTokenPath, tokenPaths []EvsTokenPath) bool {
	for _, tokenPath := range tokenPaths {
		if tokenPath.HasPrefix(prefix) || prefix.HasPrefix(tokenPath) {
			return true
		}
	}
	return false
}

// Paths deduplicated and sorted.
func evsSortedPaths(paths []string) []string {
	sorted := slices.Clone(paths)
	slices.Sort(sorted)
	return slices.Compact(sorted)
}

// Calls each subscription's callback with its own changes and each listener of the repo with the union, in order.
func (self *evsSubscriber) deliver(repoId Id, views []*evsSubscriptionView, changes []*EvsRepoChange, viewChanges map[Id][]*EvsRepoChange) {
	listeners := func() []EvsRepoChangeFunction {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listenerIds := []int{}
		for listenerId := range self.listeners {
			listenerIds = append(listenerIds, listenerId)
		}
		slices.Sort(listenerIds)
		listeners := []EvsRepoChangeFunction{}
		for _, listenerId := range listenerIds {
			listener := self.listeners[listenerId]
			if listener.repoId == nil || *listener.repoId == repoId {
				listeners = append(listeners, listener.listener)
			}
		}
		return listeners
	}()
	for _, view := range views {
		if view.callback == nil {
			continue
		}
		for _, change := range viewChanges[view.id] {
			view.callback(change)
		}
	}
	for _, change := range changes {
		for _, listener := range listeners {
			listener(change)
		}
	}
}

// §11.6's leases row on the client: a subscription whose lease is in an epoch below the ref's current one (main's for
// a whole repo's subscription) is re-tokenized in the current epoch and owed a lease, its old prefixes kept to delete
// once the new lease lands.
func (self *evsSubscriber) followEpoch(ctx context.Context, repo *EvsRepo, refId Id, head *EvsVerifiedHead, views []*evsSubscriptionView) {
	current := max(1, head.Head.GetPathEpoch().GetCurrent())
	mainRefId, err := repo.resolveRefId(ctx, nil, nil)
	if err != nil {
		return
	}
	moved := false
	for _, view := range views {
		if (view.refId == nil && refId != mainRefId) || current <= view.pathEpoch {
			continue
		}
		prefixes, err := self.tokenizePaths(ctx, repo, view.paths, current)
		if err != nil {
			continue
		}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			state := self.subscriptions[view.id]
			if state == nil || current <= state.pathEpoch {
				return
			}
			if !state.leasedAt.IsZero() {
				state.staleEpoch = state.pathEpoch
				state.stalePrefixes = state.prefixes
			}
			state.pathEpoch = current
			state.prefixes = prefixes
			state.leasedAt = time.Time{}
			state.leaseDueAt = time.Time{}
			state.renewAt = time.Time{}
			moved = true
		}()
	}
	if moved {
		self.persist(repo.repoId)
		self.wakeRounds()
	}
}
