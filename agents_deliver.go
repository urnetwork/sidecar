//go:build !ios_extension && !sidecar_http

// Delivery (DESIGN-COMPUTE §20.7's notify, where agents wait and loops rows, §20.5's step 4, R-SKILL-4, R-SKILL-9,
// D-SKILL-8, D-SKILL-11, CF-10; SKILL-M11-05): how a message written into an inbox reaches the agent it names.
//
//	watch     AgentsClient.Watch leases inbox/ of the member's agents repo (agents:inbox/) and of each watched agent's
//	          inbox repo (agent/<name>:inbox/; a child with no repo of its own through its nearest ancestor's lease,
//	          delivering what names it), DESIGN §11.10, and at each change, at most once a WatchPassMinInterval, reads the
//	          new messages, each verified (agents_thread.go, agents_trust.go), and hands each to AgentInboxDelivery,
//	          which the Harness implements: queued for the agent's next turn, or a wake of an idle agent in an open run
//	address   a message wakes only the agent whose member, name and, where set, own agent repo its to names, never one
//	          that matches by label alone; a message to "*" in the agents repo goes to every watched agent; an agent is
//	          never handed its own message (its verified agent)
//	closed    a message to an agent whose run is closed, or whose host is down, waits in the inbox: AgentsClient.Untaken
//	          answers every message of each thread its runs have not taken, by the thread and message ids the taken
//	          record holds, a late one whose seq falls below the last taken included, so none is lost or taken twice
//	taken     the taken record (AgentTakenRecord) is CTXH's session entries in the design (§24.4), which a run's
//	          context records as it takes each message; until that seam is wired, the device's sealed store keeps one
//	          (agentsStoreTaken), per agent and thread, so taking is idempotent by message id on the device
//	wakes     within AgentWakeLimiter's limits (agents_wake.go): past them the delivery stops queuing, the agent's
//	          status says so (AgentWatchArgs.Limited), and the message waits for the person's turn; a message from
//	          outside the member never wakes (SKILL-M13-01 brings those senders) and is queued for the next turn its
//	          person drives
//	close     a thread with a close stops queuing after it
//	me        the person's me: every device of the member watches the threads that name it and hands each message to
//	          the person's view as an AgentThreadMessage, never to a model, so a report to me shows on each device
//	          without waking a bot (the thread_message event's payload, §7.6)
//
// Nothing here reads a message into a model's context: the Harness does, between untrusted-data markers, its run
// tainted first where AgentDelivery.Taints says so.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"
)

// Where a watched inbox's messages go for an agent (§20.7's notify row): the Harness's. Safe for concurrent use.
type AgentInboxDelivery interface {
	// Whether name's run is open on this host: a closed run's messages wait in the inbox until it reopens.
	RunOpen(name AgentName) bool
	// Hands one message to name's run: queued for its next turn, and with Wake an idle agent woken. A nil error takes
	// the message: the watch records it taken.
	Deliver(ctx context.Context, delivery *AgentDelivery) error
}

// One message for one agent.
type AgentDelivery struct {
	Agent   AgentName
	Message *AgentMessageRead
	// The delivery may wake an idle agent: within the wake limits, from inside the member.
	Wake bool
	// Taking the message taints the run that takes it (AgentMessageTrust.Taints): the Harness taints first.
	Taints bool
}

// The thread_message event's payload (§7.6, §20.7's person in a thread): one message as the person's view shows it,
// on every device of the member, never to a model.
type AgentThreadMessage struct {
	RepoId    Id               `json:"repo_id"`
	Thread    AgentThreadId    `json:"-"`
	ThreadHex string           `json:"thread"`
	MessageId AgentMessageId   `json:"-"`
	IdHex     string           `json:"id"`
	Seq       uint64           `json:"seq"`
	Kind      AgentMessageKind `json:"kind"`
	Subject   string           `json:"subject,omitempty"`
	Body      string           `json:"body,omitempty"`
	// Who the provenance shows wrote it, and how its trust reads.
	SenderSidecarId Id                     `json:"sender_sidecar_id"`
	SenderName      AgentName              `json:"sender_name,omitempty"`
	SenderPerson    bool                   `json:"sender_person,omitempty"`
	Trust           AgentMessageTrustClass `json:"trust"`
	// To every agent, else the agent named.
	ToAll   bool      `json:"to_all,omitempty"`
	ToName  AgentName `json:"to_name,omitempty"`
	Created time.Time `json:"created"`
	// A support notice's enumerated fields, rendered from their values.
	Support *AgentMessageSupport `json:"support,omitempty"`
}

// The payload of read in repoId.
func agentThreadMessageOf(read *AgentMessageRead) *AgentThreadMessage {
	message := read.Message
	view := &AgentThreadMessage{
		RepoId: read.RepoId, Thread: message.Thread, ThreadHex: message.Thread.String(), MessageId: message.Id,
		IdHex: message.Id.String(), Seq: message.Seq, Kind: message.Kind, Subject: message.Subject, Body: message.Body,
		SenderSidecarId: read.Trust.Sender.SidecarId, SenderName: read.Trust.Sender.Name, Trust: read.Trust.Class,
		ToAll: message.ToAll(), Created: message.Created, Support: message.Support,
	}
	view.SenderPerson = read.Trust.Class == AgentMessageTrustPerson
	if message.To != nil {
		view.ToName = message.To.Name
	}
	return view
}

// Which thread and message ids each agent's runs took (§24.4's session entries). Safe for concurrent use.
type AgentTakenRecord interface {
	Taken(agent AgentName, thread AgentThreadId, id AgentMessageId) (bool, error)
	Take(agent AgentName, thread AgentThreadId, id AgentMessageId) error
}

// The taken directory of the agents store: taken/<name>/<thread>.json, the ids taken in the thread.
const agentsTakenDirectory = "taken"

// The device's own taken record, in its sealed store, until CTXH's session entries are wired (see the file header).
// Every record over one client serializes on the client's takenLock, so two of them never lose each other's takes.
type agentsStoreTaken struct {
	client *AgentsClient
}

// The record's file of agent's thread.
func (self *agentsStoreTaken) file(agent AgentName) (SidecarStore, error) {
	if self.client.args.Store == nil {
		return nil, ErrAgentsOutboxUnavailable
	}
	store, err := self.client.args.Store()
	if err != nil {
		return nil, err
	}
	return store.Directory(agentsTakenDirectory+"/"+string(agent), "")
}

// The ids taken in a thread.
func (self *agentsStoreTaken) readWithLock(agent AgentName, thread AgentThreadId) (map[string]bool, error) {
	store, err := self.file(agent)
	if err != nil {
		return nil, err
	}
	reader, err := store.Open(thread.String() + ".json")
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return map[string]bool{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	if err := json.Unmarshal(data, &ids); err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	for _, id := range ids {
		taken[id] = true
	}
	return taken, nil
}

// Whether agent took the message id of thread, as the record holds it.
func (self *agentsStoreTaken) Taken(agent AgentName, thread AgentThreadId, id AgentMessageId) (bool, error) {
	self.client.takenLock.Lock()
	defer self.client.takenLock.Unlock()
	taken, err := self.readWithLock(agent, thread)
	if err != nil {
		return false, err
	}
	return taken[id.String()], nil
}

// Records agent's take of the message id of thread, its thread's file rewritten whole.
func (self *agentsStoreTaken) Take(agent AgentName, thread AgentThreadId, id AgentMessageId) error {
	self.client.takenLock.Lock()
	defer self.client.takenLock.Unlock()
	taken, err := self.readWithLock(agent, thread)
	if err != nil {
		return err
	}
	if taken[id.String()] {
		return nil
	}
	taken[id.String()] = true
	ids := []string{}
	for taken := range taken {
		ids = append(ids, taken)
	}
	slices.Sort(ids)
	encoded, err := json.Marshal(ids)
	if err != nil {
		return err
	}
	store, err := self.file(agent)
	if err != nil {
		return err
	}
	writer, err := store.Create(thread.String() + ".json")
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(encoded); err != nil {
		return err
	}
	return writer.Commit()
}

// What a watch watches and where it hands what it finds.
type AgentWatchArgs struct {
	// The agents this host runs, by name: their own inboxes and the agents repo's threads to every agent.
	Agents   []AgentName
	Delivery AgentInboxDelivery
	// The person's me on this device, by its name, "" for none: its inbox's and the agents repo's threads go to Person.
	Me     AgentName
	Person func(message *AgentThreadMessage)
	// Which ids each agent took; nil keeps the device's own record in its sealed store.
	Taken AgentTakenRecord
	// Told when an agent's delivery stops queuing past a wake limit, for its status line. Nil for none.
	Limited func(agent AgentName, refusal AgentWakeRefusal)
	// The limits' counts, shared with what else wakes the host's agents; nil makes one.
	Limiter *AgentWakeLimiter
	// Called after each pass with its error, nil for one that read everything: a test's. Nil for none.
	Passed func(err error)
}

// One watch: see the file header. Close ends it.
type AgentInboxWatch struct {
	client   *AgentsClient
	args     *AgentWatchArgs
	taken    AgentTakenRecord
	limiter  *AgentWakeLimiter
	ctx      context.Context
	cancel   context.CancelFunc
	wake     chan struct{}
	done     chan struct{}
	settings *SkillSettings
	clock    Clock

	stateLock     sync.Mutex
	subscriptions map[Id]*EvsSubscription
}

// What a repo is leased through: EvsRepo.Subscribe. A repo access without it is read at each pass alone.
type agentsRepoSubscriber interface {
	Subscribe(ctx context.Context, args *EvsSubscribeArgs) (*EvsSubscription, error)
}

// Starts a watch over args (see the file header), its first pass at once.
func (self *AgentsClient) Watch(ctx context.Context, args *AgentWatchArgs) (*AgentInboxWatch, error) {
	if args == nil || (0 < len(args.Agents) && args.Delivery == nil) || (args.Me != "" && args.Person == nil) {
		return nil, fmt.Errorf("%w: a watch's delivery", errInvalidSettings)
	}
	if _, err := self.placeWithRepo(); err != nil {
		return nil, err
	}
	watchCtx, cancel := context.WithCancel(context.Background())
	watch := &AgentInboxWatch{
		client: self, args: args, taken: args.Taken, limiter: args.Limiter, ctx: watchCtx, cancel: cancel,
		wake: make(chan struct{}, 1), done: make(chan struct{}), settings: self.settings, clock: self.clock,
		subscriptions: map[Id]*EvsSubscription{},
	}
	if watch.taken == nil {
		watch.taken = &agentsStoreTaken{client: self}
	}
	if watch.limiter == nil {
		watch.limiter = NewAgentWakeLimiter(self.settings)
	}
	watch.signal()
	go watch.run()
	return watch, nil
}

// Ends the watch, its leases with it, waiting for its goroutine.
func (self *AgentInboxWatch) Close() {
	self.cancel()
	<-self.done
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for repoId, subscription := range self.subscriptions {
		subscription.Close()
		delete(self.subscriptions, repoId)
	}
}

// Wakes the watch's goroutine without waiting.
func (self *AgentInboxWatch) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// A person's input to agent: its wake counts start again, and the next pass delivers what waited.
func (self *AgentInboxWatch) PersonInput(agent AgentName) {
	self.limiter.PersonInput(agent)
	self.signal()
}

// Reads again now: a run reopened, or the Harness asks.
func (self *AgentInboxWatch) Poke() {
	self.signal()
}

// The watch's rounds: a pass at each signal, at most once a WatchPassMinInterval, WatchRetryWait after a failure. No
// pass starts once the watch has ended, a signal or a pause's end taken as it ended included, so nothing is handed to
// an agent or taken past the end, and an ended watch asks the clock for nothing.
func (self *AgentInboxWatch) run() {
	defer close(self.done)
	// select takes either of its ready cases at random: a signal or a pause's end taken as the watch ended reads as the
	// end
	for self.ctx.Err() == nil {
		select {
		case <-self.ctx.Done():
		case <-self.wake:
		}
		if self.ctx.Err() != nil {
			return
		}
		err := self.pass()
		if self.args.Passed != nil {
			self.args.Passed(err)
		}
		if self.ctx.Err() != nil {
			// a watch that ended as the pass ran asks the clock for nothing
			return
		}
		wait := self.settings.WatchPassMinInterval
		if err != nil {
			// the next pass tries again, after the retry wait
			wait = self.settings.WatchRetryWait
			self.signal()
		}
		if 0 < wait {
			paused := make(chan struct{})
			stop := self.clock.AfterFunc(wait, func() { close(paused) })
			select {
			case <-self.ctx.Done():
			case <-paused:
			}
			stop()
		}
	}
}

// One watched recipient: an agent with its card and the repo its inbox is in, or the person's me.
type agentWatchTarget struct {
	name    AgentName
	card    *AgentCard
	inboxId Id
	person  bool
}

// Leases repoId's inbox/ once (§11.10), each change signalling the watch.
func (self *AgentInboxWatch) lease(repoId Id, repo AgentsRepoAccess) {
	self.stateLock.Lock()
	_, leased := self.subscriptions[repoId]
	self.stateLock.Unlock()
	if leased {
		return
	}
	subscriber, ok := repo.(agentsRepoSubscriber)
	if !ok {
		return
	}
	subscription, err := subscriber.Subscribe(self.ctx, &EvsSubscribeArgs{
		Paths:   []string{agentInboxDirectory},
		Changes: func(change *EvsRepoChange) { self.signal() },
	})
	if err != nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.subscriptions[repoId] != nil || self.ctx.Err() != nil {
		subscription.Close()
		return
	}
	self.subscriptions[repoId] = subscription
}

// The watched recipients at place: each agent's card and inbox repo, a child's its ancestor's, and the person's me.
func (self *AgentInboxWatch) targets(ctx context.Context, place *agentsPlace) ([]*agentWatchTarget, error) {
	targets := []*agentWatchTarget{}
	add := func(name AgentName, person bool) error {
		read, err := self.client.readCard(ctx, place, name)
		if err != nil {
			return err
		}
		if read.Card == nil || read.Card.IsRetired() || read.Card.Person() != person {
			return nil
		}
		inboxId, err := self.client.AgentRepo(ctx, name)
		if errors.Is(err, ErrAgentCardAbsent) {
			inboxId = Id{}
		} else if err != nil {
			return err
		}
		targets = append(targets, &agentWatchTarget{name: name, card: read.Card, inboxId: inboxId, person: person})
		return nil
	}
	for _, name := range self.args.Agents {
		if err := add(name, false); err != nil {
			return nil, err
		}
	}
	if self.args.Me != "" {
		if err := add(self.args.Me, true); err != nil {
			return nil, err
		}
	}
	return targets, nil
}

// Whether message, in the repo repoId, is target's: see the file header's address row.
func (self *AgentInboxWatch) addressed(place *agentsPlace, target *agentWatchTarget, repoId Id, message *AgentMessageRead) bool {
	if sender := message.Trust.Sender.AgentId; sender != nil && !target.person && *sender == target.card.AgentId {
		// its own message
		return false
	}
	if target.person && message.Trust.Class == AgentMessageTrustPerson {
		// the person's own words, which every device of the member wrote or shows already
		return false
	}
	to := message.Message.To
	if to == nil {
		return repoId == place.agentsRepoId
	}
	if to.MemberId != place.memberId || to.Name != target.name {
		return false
	}
	if to.RepoId != (Id{}) && to.RepoId != target.card.AgentRepo {
		return false
	}
	return repoId == target.inboxId || repoId == place.agentsRepoId
}

// One pass: every watched repo's threads read, each message for a watched recipient that it has not taken delivered.
func (self *AgentInboxWatch) pass() error {
	ctx := self.ctx
	place, err := self.client.placeWithRepo()
	if err != nil {
		return err
	}
	targets, err := self.targets(ctx, place)
	if err != nil {
		return err
	}
	repoIds := []Id{place.agentsRepoId}
	for _, target := range targets {
		if target.inboxId != (Id{}) && !slices.Contains(repoIds, target.inboxId) {
			repoIds = append(repoIds, target.inboxId)
		}
	}
	var firstErr error
	for _, repoId := range repoIds {
		repo := self.client.args.Repo(repoId)
		if repo == nil {
			continue
		}
		self.lease(repoId, repo)
		threads, err := self.client.threadIds(ctx, repo)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, threadId := range threads {
			thread, err := self.client.readThread(ctx, place, repoId, repo, threadId)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			if err := self.deliverThread(ctx, place, targets, repoId, thread); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Hands a thread's untaken messages to the recipients they are for, in (seq, id) order.
func (self *AgentInboxWatch) deliverThread(ctx context.Context, place *agentsPlace, targets []*agentWatchTarget, repoId Id, thread *AgentThreadRead) error {
	for _, target := range targets {
		closed := false
		for i, message := range thread.Messages {
			if closed {
				break
			}
			if message.Message.Kind == AgentMessageKindClose {
				closed = true
			}
			if !self.addressed(place, target, repoId, message) {
				continue
			}
			taken, err := self.taken.Taken(target.name, thread.Thread, message.Message.Id)
			if err != nil {
				return err
			}
			if taken {
				continue
			}
			if target.person {
				self.args.Person(agentThreadMessageOf(message))
				if err := self.taken.Take(target.name, thread.Thread, message.Message.Id); err != nil {
					return err
				}
				continue
			}
			if !self.args.Delivery.RunOpen(target.name) {
				// waits in the inbox for the run to reopen (Untaken)
				continue
			}
			wake := message.Trust.Sender.MemberId == place.memberId
			if wake {
				allowed, refusal := self.limiter.Allow(target.name, agentWakeSender(message), i+1, self.clock.Now())
				if !allowed {
					// the delivery stops queuing, the status says so, and the message waits for the person's turn
					if self.args.Limited != nil {
						self.args.Limited(target.name, refusal)
					}
					break
				}
			}
			err = self.args.Delivery.Deliver(ctx, &AgentDelivery{Agent: target.name, Message: message, Wake: wake, Taints: message.Trust.Taints()})
			if err != nil {
				return err
			}
			if err := self.taken.Take(target.name, thread.Thread, message.Message.Id); err != nil {
				return err
			}
		}
	}
	return nil
}

// What a reopened run asks of its inboxes.
type AgentUntakenArgs struct {
	Agent AgentName
	// Which ids the agent's runs took; nil reads the device's own record.
	Taken AgentTakenRecord
}

// Every message for agent that its runs have not taken (§20.7's where agents wait row): each thread of its inbox repo
// and the agents repo's threads to every agent or naming it, by thread and then (seq, id), a late one whose seq falls
// below the last taken included; at most SkillSettings.UntakenMaxCount, the rest at the next ask. A thread past its
// close stops there. Nothing is marked taken here: the run records what it takes.
func (self *AgentsClient) Untaken(ctx context.Context, args *AgentUntakenArgs) ([]*AgentMessageRead, error) {
	if args == nil || args.Agent == "" {
		return nil, fmt.Errorf("%w: an untaken read names its agent", errInvalidSettings)
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	taken := args.Taken
	if taken == nil {
		taken = &agentsStoreTaken{client: self}
	}
	watch := &AgentInboxWatch{client: self, args: &AgentWatchArgs{Agents: []AgentName{args.Agent}}, settings: self.settings}
	targets, err := watch.targets(ctx, place)
	if err != nil {
		return nil, err
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, args.Agent)
	}
	target := targets[0]
	repoIds := []Id{place.agentsRepoId}
	if target.inboxId != (Id{}) && target.inboxId != place.agentsRepoId {
		repoIds = append(repoIds, target.inboxId)
	}
	untaken := []*AgentMessageRead{}
	for _, repoId := range repoIds {
		repo := self.args.Repo(repoId)
		if repo == nil {
			continue
		}
		threads, err := self.threadIds(ctx, repo)
		if err != nil {
			return nil, err
		}
		for _, threadId := range threads {
			thread, err := self.readThread(ctx, place, repoId, repo, threadId)
			if err != nil {
				return nil, err
			}
			for _, message := range thread.Messages {
				if !watch.addressed(place, target, repoId, message) {
					if message.Message.Kind == AgentMessageKindClose {
						break
					}
					continue
				}
				isTaken, err := taken.Taken(args.Agent, thread.Thread, message.Message.Id)
				if err != nil {
					return nil, err
				}
				if !isTaken {
					untaken = append(untaken, message)
					if self.settings.UntakenMaxCount <= len(untaken) {
						return untaken, nil
					}
				}
				if message.Message.Kind == AgentMessageKindClose {
					break
				}
			}
		}
	}
	return untaken, nil
}

// Records message taken by agent in the device's own record, as a run takes it from Untaken.
func (self *AgentsClient) Take(agent AgentName, message *AgentMessageRead) error {
	return (&agentsStoreTaken{client: self}).Take(agent, message.Message.Thread, message.Message.Id)
}

// The state agent_send answers its recipient in (§20.7's where agents wait row): its status's, offline where it has
// none or it is older than OfflineAfter. Empty for a message to every agent.
func (self *AgentsClient) recipientState(ctx context.Context, place *agentsPlace, name AgentName) AgentState {
	read, err := self.readCard(ctx, place, name)
	if err != nil || read.Card == nil || read.Card.Person() {
		return ""
	}
	status, err := agentsReadStatus(ctx, place.agentsRepo, place.authority, place.memberId, read.Card, self.settings, self.clock.Now(),
		func(version *EvsHistoryVersion) { self.alarm(place.agentsRepoId, version) })
	if err != nil || status.Status == nil {
		return AgentStateOffline
	}
	return status.State
}
