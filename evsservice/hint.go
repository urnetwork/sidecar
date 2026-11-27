// Step 8's sequence and hints (§11.10's match, epochs, sequence and hint rows; EVS1-M2-15): the engine's
// EvsCommitNotifier.
//
//	sequence  {evsq_<repo_id>} raised first, by sequence.go's script, so the head cache entry step 8 writes next records
//	          the value this commit raised
//	match     the commit's changes, or its covering prefixes when its list is not inline, against the repo's leases,
//	          from a copy this process keeps until a GET of {evsl_<repo_id>}v after the commit shows a new value; a lease
//	          on the commit's ref, or on every ref, in the ref's current path epoch matches when its prefix and a
//	          changed path are on one branch of the tree; a lease on every ref with no prefix, the whole repo, names no
//	          token, so its epoch carries no meaning and it matches a commit on any ref whatever that ref's epoch
//	          (§11.10's epochs row; QD-953, owner decision 409), the expiry and reader skips still applying; a
//	          PATH_EPOCH commit matches every lease holder of the ref, whatever its epoch, which then re-creates its
//	          leases in the new epoch (§11.6's leases row)
//	skip      holders the newest projection no longer lists as the repo's readers are skipped, and so is everyone
//	          while that state is not loaded: a hint missed costs only latency
//	hint      §6.8's PushHint per matching client: topic evs:<repo_id>, version the push sequence, kind EVS_HEAD_CHANGED
//	          (0x1401) and the delta EvsHeadChanged{ref_id, version, chain, push_id}, coalesced to HintPerRepoInterval
//	          a repo (10 a second): a commit inside the interval waits for its end, and the newest commit's hint goes
//	          then to every client the coalesced commits matched; newest is by push sequence, since step 8s of
//	          consecutive commits overlap and their hints can arrive here in another order than they raised it
//	unsent    a hint counts as unsent from the moment send takes it until Push.Hint has returned for it or for the
//	          waiting hint it joined, so the engine's Drain, which waits for the count to reach zero, never returns
//	          with a hint still waiting out its interval
//
// Every family touched is soft state: a failure is logged and is a gap, which clients' hourly resync covers, never an
// alarm. Each script touches one hash tag. Not built: the rev/ check of each holder (§11.10's "holders a rev/ object
// names"), which the projection check stands in for once a revocation reaches the projection, within §8.9's 5 s.
//
// Safe for concurrent use. No lock is held across I/O.

package evsservice

import (
	"context"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// What tunes the notifier.
type EvsHintSettings struct {
	// §19.8's head-to-hint deadline, from the acknowledged head CAS through the push handoff.
	HeadHintTarget time.Duration
	// The least time between two hints of one repo: 100 ms, §11.10's hint row's 10 hints a second a repo. A hint
	// inside it waits for its end. Non-positive sends every hint at once.
	HintPerRepoInterval time.Duration
	// How many repos' lease copies, and how many repos' hint states, a process keeps: 100,000 each, about one
	// process's busy repos. Past it an entry goes for each one added, a lease copy to be read again and a hint state
	// only while no hint waits in it. Non-positive keeps one.
	RepoStateCount int
}

func DefaultEvsHintSettings() *EvsHintSettings {
	return &EvsHintSettings{
		HeadHintTarget:      2 * time.Second,
		HintPerRepoInterval: 100 * time.Millisecond,
		RepoStateCount:      100 * 1000,
	}
}

// A repo's leases as this process last read them, with the version they were read at.
type evsLeaseCopy struct {
	version string
	leases  []*EvsLease
}

// A repo's coalescing: when its last hint went, and the hint waiting for its interval to end.
type evsRepoHintState struct {
	lastSent time.Time
	pending  *sidecar.ClientHint
	// A coalesced hint covers each of these heads, which retain their own latency deadlines.
	pendingHeads []time.Time
	clients      map[sidecar.Id]bool
}

// See the file header.
type EvsHintNotifier struct {
	ctx      context.Context
	clock    sidecar.Clock
	redis    sidecar.Redis
	push     sidecar.Push
	views    EvsGateViews
	settings *EvsHintSettings
	log      sidecar.Logger
	outcomes sidecar.MetricsCounter

	stateLock   sync.Mutex
	leaseCopies map[sidecar.Id]*evsLeaseCopy
	repoHints   map[sidecar.Id]*evsRepoHintState
	// hints sent, for a test to wait on
	sentCount *sidecar.MonitorValue[int]
	// hints taken and not yet handed to push (the file header's unsent row), for the engine's Drain
	unsentCount *sidecar.MonitorValue[int]
}

// The notifier over a host's Redis and Push and the gate views, until ctx ends, with the default settings. A nil
// redis raises nothing; a nil push or views hints no one.
func NewEvsHintNotifier(ctx context.Context, clock sidecar.Clock, redis sidecar.Redis, push sidecar.Push, views EvsGateViews, log sidecar.Logger) *EvsHintNotifier {
	return NewEvsHintNotifierWithSettings(ctx, clock, redis, push, views, nil, log)
}

// As NewEvsHintNotifier, with settings, which may be nil for the defaults.
func NewEvsHintNotifierWithSettings(ctx context.Context, clock sidecar.Clock, redis sidecar.Redis, push sidecar.Push, views EvsGateViews, settings *EvsHintSettings, log sidecar.Logger) *EvsHintNotifier {
	if settings == nil {
		settings = DefaultEvsHintSettings()
	}
	return &EvsHintNotifier{
		ctx:         ctx,
		clock:       clock,
		redis:       redis,
		push:        push,
		views:       views,
		settings:    settings,
		log:         log,
		leaseCopies: map[sidecar.Id]*evsLeaseCopy{},
		repoHints:   map[sidecar.Id]*evsRepoHintState{},
		sentCount:   sidecar.NewMonitorValue(0),
		unsentCount: sidecar.NewMonitorValue(0),
	}
}

// Hints sent so far, and a channel that closes at the next.
func (self *EvsHintNotifier) Sent() (int, chan struct{}) {
	return self.sentCount.Get()
}

// See EvsCommitNotifier.
func (self *EvsHintNotifier) Unsent() (int, chan struct{}) {
	return self.unsentCount.Get()
}

// See EvsCommitNotifier.
func (self *EvsHintNotifier) Notify(ctx context.Context, committed *EvsCommitted) (sequence uint64, err error) {
	defer func() {
		if err != nil && self.outcomes != nil && !committed.SeenAt.IsZero() {
			self.outcomes.Add(1, "failed")
		}
	}()
	if self.redis == nil {
		return 0, nil
	}
	sequence, err = RaisePushSequence(ctx, self.redis, committed.RepoId)
	if err != nil {
		return 0, err
	}
	if self.push == nil || self.views == nil {
		return sequence, nil
	}
	leases, err := self.leases(ctx, committed.RepoId)
	if err != nil {
		return sequence, err
	}
	clientIds := self.match(committed, leases)
	if len(clientIds) == 0 {
		return sequence, nil
	}
	head := committed.Head.Head
	delta, err := marshalDeterministic(&protocol.EvsHeadChanged{
		RefId:   committed.RefId.Bytes(),
		Version: head.GetVersion(),
		Chain:   head.GetChain(),
		PushId:  head.GetPushId(),
	})
	if err != nil {
		return sequence, err
	}
	self.send(committed.RepoId, &sidecar.ClientHint{
		Topic:   sidecar.PushTopicEvs(committed.RepoId),
		Version: sequence,
		Kind:    uint32(protocol.MessageType_EVS_HEAD_CHANGED),
		Body:    delta,
	}, clientIds, committed.SeenAt)
	return sequence, nil
}

// The repo's leases: this process's copy while {evsl_<repo_id>}v still shows the version it was read at, else the
// hash read again.
func (self *EvsHintNotifier) leases(ctx context.Context, repoId sidecar.Id) ([]*EvsLease, error) {
	versionBytes, _, err := self.redis.Get(ctx, LeaseVersionKey(repoId))
	if err != nil {
		return nil, err
	}
	version := string(versionBytes)
	self.stateLock.Lock()
	copied, ok := self.leaseCopies[repoId]
	self.stateLock.Unlock()
	if ok && copied.version == version {
		return copied.leases, nil
	}
	leases, err := ReadLeases(ctx, self.redis, repoId)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.RepoStateCount <= len(self.leaseCopies) {
		for evicted := range self.leaseCopies {
			delete(self.leaseCopies, evicted)
			break
		}
	}
	self.leaseCopies[repoId] = &evsLeaseCopy{version: version, leases: leases}
	return leases, nil
}

// The clients whose leases committed matches. See the file header.
func (self *EvsHintNotifier) match(committed *EvsCommitted, leases []*EvsLease) []sidecar.Id {
	view, answer := self.views.View(committed.RepoNetworkId)
	now := self.clock.Now()
	if answer != EvsAuthAllowed || view == nil {
		// A missing projection prevents dispatch to potentially eligible live leases. It cannot
		// silently remove these heads from the delivery budget. A known denial owes no hint.
		if self.outcomes != nil && !committed.SeenAt.IsZero() && answer != EvsAuthDenied {
			for _, lease := range leases {
				if now.Before(lease.ExpiresAt) && (lease.EveryRef || lease.RefId == committed.RefId) {
					self.outcomes.Add(1, "failed")
					break
				}
			}
		}
		return nil
	}
	readers := map[sidecar.Id]bool{}
	for _, reader := range view.RepoReaders(committed.RepoId) {
		readers[reader] = true
	}
	push := committed.Statement.Push
	pathEpochCommit := push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0
	epoch := EvsHeadCurrentEpoch(committed.Head.Head)
	changed := []sidecar.EvsTokenPath{}
	if committed.Payload != nil {
		changed = committed.Payload.ChangedPaths()
	}
	if len(push.GetChangesRoot()) != 0 && len(changed) == 0 {
		changed = committed.Statement.ChangedPrefixes
	}
	clients := map[sidecar.Id]bool{}
	for _, lease := range leases {
		if !now.Before(lease.ExpiresAt) || (!lease.EveryRef && lease.RefId != committed.RefId) || !readers[lease.SidecarId] {
			continue
		}
		// the whole repo names no token, so it matches in every epoch (QD-953); every other lease's tokens are its
		// epoch's
		wholeRepo := lease.EveryRef && len(lease.Prefix) == 0
		if wholeRepo || pathEpochCommit || (lease.PathEpoch == epoch && evsLeaseMatches(lease.Prefix, changed)) {
			clients[lease.ClientId] = true
		}
	}
	clientIds := make([]sidecar.Id, 0, len(clients))
	for clientId := range clients {
		clientIds = append(clientIds, clientId)
	}
	return clientIds
}

// Whether a lease's prefix and a changed path are on one branch of the tree: one a prefix of the other. The empty
// prefix is the whole ref.
func evsLeaseMatches(prefix sidecar.EvsTokenPath, changed []sidecar.EvsTokenPath) bool {
	if len(prefix) == 0 {
		return true
	}
	for _, path := range changed {
		if path.HasPrefix(prefix) || prefix.HasPrefix(path) {
			return true
		}
	}
	return false
}

// Sends hint to clientIds now, or, inside the repo's interval, at its end: then the waiting hint with the highest
// push sequence goes, to the clients of every hint that waited. Hints reach here in any order, since each commit's
// step 8 runs on its own, so a hint that arrives after one with a higher sequence adds its clients and no more:
// were it to take the waiting hint's place, the higher sequence would not be hinted before the repo's next push or
// the clients' hourly resync. The hint counts as unsent before the waiting hint can see it, and one that joins a
// waiting hint stops counting only once it has joined, so the count never reads zero while either waits.
func (self *EvsHintNotifier) send(repoId sidecar.Id, hint *sidecar.ClientHint, clientIds []sidecar.Id, seenAt time.Time) {
	self.unsentCount.Update(func(count int) int { return count + 1 })
	now := self.clock.Now()
	sendNow := false
	joined := false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, ok := self.repoHints[repoId]
		if !ok {
			if self.settings.RepoStateCount <= len(self.repoHints) {
				for evictedRepoId, evicted := range self.repoHints {
					if evicted.pending == nil {
						delete(self.repoHints, evictedRepoId)
						break
					}
				}
			}
			state = &evsRepoHintState{}
			self.repoHints[repoId] = state
		}
		if state.pending == nil {
			state.clients = map[sidecar.Id]bool{}
		}
		for _, clientId := range clientIds {
			state.clients[clientId] = true
		}
		switch {
		case state.pending != nil:
			joined = true
			state.pendingHeads = append(state.pendingHeads, seenAt)
			// a hint already waits: the one of the higher push sequence stays, for the clients of both
			if state.pending.Version < hint.Version {
				state.pending = hint
			}
		case now.Sub(state.lastSent) < self.settings.HintPerRepoInterval:
			state.pending = hint
			state.pendingHeads = []time.Time{seenAt}
			// for the interval's end itself (QD-1425); the flush runs on its own goroutine, so an end already reached may
			// start it here
			sidecar.ClockAfterFuncAt(self.clock, state.lastSent.Add(self.settings.HintPerRepoInterval), func() {
				go self.flush(repoId)
			})
		default:
			state.lastSent = now
			sendNow = true
		}
	}()
	if joined {
		// the waiting hint carries it to push, and counts until then
		self.unsentCount.Update(func(count int) int { return count - 1 })
	}
	if sendNow {
		self.deliver(hint, clientIds, []time.Time{seenAt})
	}
}

// Sends the repo's waiting hint, its interval ended.
func (self *EvsHintNotifier) flush(repoId sidecar.Id) {
	var hint *sidecar.ClientHint
	var pendingHeads []time.Time
	var clientIds []sidecar.Id
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		state, ok := self.repoHints[repoId]
		if !ok || state.pending == nil {
			return
		}
		hint = state.pending
		pendingHeads = state.pendingHeads
		state.pendingHeads = nil
		for clientId := range state.clients {
			clientIds = append(clientIds, clientId)
		}
		state.pending = nil
		state.clients = nil
		state.lastSent = self.clock.Now()
	}()
	if hint != nil {
		self.deliver(hint, clientIds, pendingHeads)
	}
}

// One Push.Hint, whose failure is a gap, for one hint send counted unsent: a hint sent at once, or a repo's waiting
// hint with every hint that joined it.
func (self *EvsHintNotifier) deliver(hint *sidecar.ClientHint, clientIds []sidecar.Id, heads []time.Time) {
	connectClientIds := make([]connect.Id, len(clientIds))
	for i, clientId := range clientIds {
		connectClientIds[i] = connect.Id(clientId)
	}
	err := self.push.Hint(self.ctx, connectClientIds, hint)
	if err != nil {
		self.log.Infof("[evs] hints for %s not all sent: %v", hint.Topic, err)
	}
	if self.outcomes != nil {
		now := self.clock.Now()
		for _, seenAt := range heads {
			if seenAt.IsZero() {
				continue
			}
			result := "on_time"
			if err != nil {
				result = "failed"
			} else if self.settings.HeadHintTarget < now.Sub(seenAt) {
				result = "late"
			}
			self.outcomes.Add(1, result)
		}
	}
	self.sentCount.Update(func(count int) int { return count + 1 })
	self.unsentCount.Update(func(count int) int { return count - 1 })
}
