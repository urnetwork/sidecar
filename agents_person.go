//go:build !ios_extension && !sidecar_http

// The person's live view of the member's agents (DESIGN-COMPUTE §20.7's person in a thread and where agents wait rows,
// §20.8's graph, §15.3's Agents().AddListener; SKILL-M11-08): what the apps' recURd view, threads view and agents' feed
// hear as it happens, on every device of the member.
//
//	leases    inbox/ of the member's agents repo and of each card's agent repo, me's among them, since a reply to the
//	          person lands in the thread the person opened, in the recipient's repo (§20.7's open row: the sender
//	          listens on the dir it created); and the agents repo's cards/, status/ and summary/ (DESIGN §11.10)
//	messages  each message that lands, once (a device's own seen record in its sealed store, as the taken record is),
//	          as the thread_message payload (AgentThreadMessage), never to a model: the person's view shows it all
//	notify    for a message another sender wrote to the person's me, to one of the member's agents or to every agent,
//	          a notification's payload whose sender and subject this device read from the message and its push's
//	          provenance (AgentNotification), never from a wake push (§20.7: "never carried in the push"); the person's
//	          own words and support's notices notify nothing here
//	changed   a card, status or summary changed: the view reads the list and the graph again
//	baseline  a device's first view takes what stands as seen, telling none of it, so a new phone is not flooded
//
// Passes run at most once a SkillSettings.WatchPassMinInterval, and again after WatchRetryWait where one fails.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// The record name a device keeps the person's view's seen messages under: no agent's name, so no agent's record.
const agentsPersonSeenName = AgentName("_person")

// The file whose presence says a device's person view has taken its baseline.
const agentsPersonBaselineFile = "baseline"

// The agents repo's paths besides inbox/ whose changes the person's view hears.
var agentsPersonChangePaths = []string{agentCardDirectory, "status", agentSummaryDirectory}

// A local notification's payload (§20.7's where agents wait row): who wrote a message and its subject as this device
// read them, never as a push carried them.
type AgentNotification struct {
	Thread string `json:"thread"`
	Repo   string `json:"repo"`
	Id     string `json:"id"`
	// The verified sender: an agent's name, or the signing sidecar's id where from does not hold.
	Sender string `json:"sender"`
	// The agent it is to, "*" for every agent.
	To      string `json:"to"`
	Subject string `json:"subject,omitempty"`
	// person, member_run or untrusted (§20.7's trust).
	Trust string `json:"trust"`
	// The message is to the person's me.
	ToPerson bool `json:"to_person,omitempty"`
}

// What a person's watch tells and where.
type AgentPersonWatchArgs struct {
	// Each new message of the member's threads, in order, with its notification where it gives one. Nil for none.
	Message func(message *AgentThreadMessage, notification *AgentNotification)
	// A card, a status or a summary changed. Nil for none.
	Changed func()
	// Called after each pass with its error: a test's. Nil for none.
	Passed func(err error)
}

// One person's watch: see the file header. Close ends it.
type AgentPersonWatch struct {
	client *AgentsClient
	args   *AgentPersonWatchArgs
	ctx    context.Context
	cancel context.CancelFunc
	wake   chan struct{}
	done   chan struct{}

	stateLock     sync.Mutex
	subscriptions map[Id]*EvsSubscription
	changed       bool
}

// Starts the person's watch (see the file header), its first pass at once.
func (self *AgentsClient) WatchPerson(ctx context.Context, args *AgentPersonWatchArgs) (*AgentPersonWatch, error) {
	if args == nil {
		return nil, fmt.Errorf("%w: a person's watch", errInvalidSettings)
	}
	if _, err := self.placeWithRepo(); err != nil {
		return nil, err
	}
	watchCtx, cancel := context.WithCancel(context.Background())
	watch := &AgentPersonWatch{client: self, args: args, ctx: watchCtx, cancel: cancel, wake: make(chan struct{}, 1),
		done: make(chan struct{}), subscriptions: map[Id]*EvsSubscription{}}
	watch.signal()
	go watch.run()
	return watch, nil
}

// Ends the watch and its leases, waiting for its goroutine.
func (self *AgentPersonWatch) Close() {
	self.cancel()
	<-self.done
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for repoId, subscription := range self.subscriptions {
		subscription.Close()
		delete(self.subscriptions, repoId)
	}
}

// Reads again now.
func (self *AgentPersonWatch) Poke() {
	self.signal()
}

// Wakes the goroutine without waiting.
func (self *AgentPersonWatch) signal() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// The watch's rounds: a pass at each signal, at most once a WatchPassMinInterval, WatchRetryWait after a failure. No
// pass starts once the watch has ended, a signal or a pause's end taken as it ended included, so nothing is told to the
// person's view or recorded seen past the end, and an ended watch asks the clock for nothing.
func (self *AgentPersonWatch) run() {
	defer close(self.done)
	settings := self.client.settings
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
		wait := settings.WatchPassMinInterval
		if err != nil {
			// the next pass tries again, after the retry wait
			wait = settings.WatchRetryWait
			self.signal()
		}
		if 0 < wait {
			paused := make(chan struct{})
			stop := self.client.clock.AfterFunc(wait, func() { close(paused) })
			select {
			case <-self.ctx.Done():
			case <-paused:
			}
			stop()
		}
	}
}

// Leases repoId's paths once, each change signalling the watch, a change to the agents repo's cards, status or
// summary marking the view changed.
func (self *AgentPersonWatch) lease(repoId Id, repo AgentsRepoAccess, agentsRepo bool) {
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
	paths := []string{agentInboxDirectory}
	if agentsRepo {
		paths = append(paths, agentsPersonChangePaths...)
	}
	subscription, err := subscriber.Subscribe(self.ctx, &EvsSubscribeArgs{
		Paths: paths,
		Changes: func(change *EvsRepoChange) {
			if agentsRepo && (change.Gap || change.WholeRef || slices.ContainsFunc(change.Paths, func(path string) bool {
				return slices.Contains(agentsPersonChangePaths, path)
			})) {
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.changed = true
				}()
			}
			self.signal()
		},
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

// Whether this device's person view has taken its baseline.
func (self *AgentPersonWatch) baselined() (bool, SidecarStore, error) {
	if self.client.args.Store == nil {
		return false, nil, ErrAgentsOutboxUnavailable
	}
	store, err := self.client.args.Store()
	if err != nil {
		return false, nil, err
	}
	directory, err := store.Directory(agentsTakenDirectory+"/"+string(agentsPersonSeenName), "")
	if err != nil {
		return false, nil, err
	}
	reader, err := directory.Open(agentsPersonBaselineFile)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, directory, nil
	}
	if err != nil {
		return false, nil, err
	}
	reader.Close()
	return true, directory, nil
}

// One pass: every thread of the member's repos read, each message not seen yet told (or, at the baseline, only taken
// as seen), then the view's change told where one landed.
func (self *AgentPersonWatch) pass() error {
	ctx := self.ctx
	client := self.client
	place, err := client.placeWithRepo()
	if err != nil {
		return err
	}
	baselined, directory, err := self.baselined()
	if err != nil {
		return err
	}
	repoIds, err := agentsMemberRepos(ctx, client, place)
	if err != nil {
		return err
	}
	person := agentsPersonName(ctx, client)
	seen := &agentsStoreTaken{client: client}
	var firstErr error
	for _, repoId := range repoIds {
		repo := client.args.Repo(repoId)
		if repo == nil {
			continue
		}
		self.lease(repoId, repo, repoId == place.agentsRepoId)
		threads, err := client.threadIds(ctx, repo)
		if err != nil {
			firstErr = errors.Join(firstErr, err)
			continue
		}
		for _, threadId := range threads {
			thread, err := client.readThread(ctx, place, repoId, repo, threadId)
			if err != nil {
				firstErr = errors.Join(firstErr, err)
				continue
			}
			for _, message := range thread.Messages {
				isSeen, err := seen.Taken(agentsPersonSeenName, message.Message.Thread, message.Message.Id)
				if err != nil {
					return err
				}
				if isSeen {
					continue
				}
				if baselined && self.args.Message != nil {
					self.args.Message(agentThreadMessageOf(message), agentsNotificationOf(message, person))
				}
				if err := seen.Take(agentsPersonSeenName, message.Message.Thread, message.Message.Id); err != nil {
					return err
				}
			}
		}
	}
	if !baselined && firstErr == nil {
		writer, err := directory.Create(agentsPersonBaselineFile)
		if err != nil {
			return err
		}
		if _, err := writer.Write([]byte("1")); err != nil {
			writer.Close()
			return err
		}
		if err := writer.Commit(); err != nil {
			writer.Close()
			return err
		}
		writer.Close()
	}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		changed := self.changed
		self.changed = false
		return changed
	}()
	if changed && self.args.Changed != nil {
		self.args.Changed()
	}
	return firstErr
}

// The notification a message gives: another sender's message to the person's me, to one of the member's agents or to
// every agent; nil for the person's own words and support's notices.
func agentsNotificationOf(read *AgentMessageRead, person AgentName) *AgentNotification {
	trust := read.Trust
	if trust.Class == AgentMessageTrustPerson || trust.Class == AgentMessageTrustSupport || read.Message.Kind == AgentMessageKindSupport {
		return nil
	}
	message := read.Message
	notification := &AgentNotification{
		Thread: message.Thread.String(), Repo: agentCardIdText(read.RepoId), Id: message.Id.String(), To: agentMessageToAll,
		Subject: message.Subject, Trust: string(trust.Class),
	}
	if trust.FromVerified && trust.Sender.Name != "" {
		notification.Sender = string(trust.Sender.Name)
	} else {
		notification.Sender = "sidecar " + trust.Sender.SidecarId.String()
	}
	if message.To != nil {
		notification.To = string(message.To.Name)
		notification.ToPerson = message.To.Name == person
	}
	return notification
}

// What the person sends (§20.7's kind (a)): a message, a broadcast, a reply or a close.
type AgentPersonSendArgs struct {
	// The recipient's name, "*" in a thread to all; "" for a broadcast, or for a reply to the thread's last sender.
	To      string
	Subject string
	Body    string
	// The thread to continue or close.
	Thread string
	// Opens a thread to every agent.
	Broadcast bool
	// Writes kind close in Thread.
	Close bool
	Refs  []*AgentToolRef
}

// Writes the person's own message (§20.7's kind (a)): a push bound to no run, from an untagged consented device of the
// member, the person's me registered first so replies have its repo to land in. Only the device's input path calls it:
// the sdk's Agents().Send, Broadcast and a remote app's agents.send, and ur agents send, broadcast and reply confirmed
// on /dev/tty with no harness among the caller's ancestors (agents_daemon.go); never a tool. A reply with no to answers
// the thread's last other sender by its verified provenance, a thread to all's opener first.
func (self *AgentsClient) SendAsPerson(ctx context.Context, args *AgentPersonSendArgs) (*AgentSendToolResult, error) {
	if args == nil || (!args.Close && args.Body == "") {
		return nil, fmt.Errorf("%w: a message's body", ErrAgentToolArguments)
	}
	refs, err := agentToolRefs(args.Refs)
	if err != nil {
		return nil, err
	}
	if _, err := self.RegisterMe(ctx, &AgentRegisterMeArgs{}); err != nil {
		return nil, err
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	send := &AgentSendArgs{Person: true, Subject: args.Subject, Body: args.Body, Refs: refs}
	toAll := args.To == agentMessageToAll
	var sent *AgentSendResult
	switch {
	case args.Thread == "" && (args.Close || toAll):
		return nil, fmt.Errorf("%w: a close or a message to all continues a thread", ErrAgentToolArguments)
	case args.Thread == "" && args.Broadcast:
		sent, err = self.Broadcast(ctx, send)
	case args.Thread == "":
		if send.To, err = ParseAgentName(args.To, self.settings); err != nil {
			return nil, fmt.Errorf("%w: to is an agent's name", ErrAgentToolArguments)
		}
		sent, err = self.Send(ctx, send)
	default:
		sent, err = self.personContinue(ctx, place, args, send, toAll)
	}
	if err != nil {
		return nil, agentToolSendError(err)
	}
	return agentSendToolResultOf(sent), nil
}

// The person's reply, answer to all or close in args.Thread: the thread found in the member's repos, its recipient
// named, or taken from the replied message's provenance (agentsReplyRecipient), and written as the person's.
func (self *AgentsClient) personContinue(ctx context.Context, place *agentsPlace, args *AgentPersonSendArgs, send *AgentSendArgs,
	toAll bool) (*AgentSendResult, error) {
	thread, err := ParseAgentThreadId(args.Thread)
	if err != nil {
		return nil, fmt.Errorf("%w: the thread", ErrAgentToolArguments)
	}
	repoId, read, err := agentsThreadRepo(ctx, self, "", thread)
	if err != nil {
		return nil, err
	}
	inAgentsRepo := repoId == place.agentsRepoId
	if toAll && !inAgentsRepo {
		return nil, fmt.Errorf("%w: to \"*\" continues a thread to every agent", ErrAgentToolArguments)
	}
	var to AgentName
	switch {
	case toAll:
	case args.To != "":
		if to, err = ParseAgentName(args.To, self.settings); err != nil {
			return nil, fmt.Errorf("%w: to is an agent's name", ErrAgentToolArguments)
		}
	case !args.Close || !inAgentsRepo:
		// a close in a thread to all goes to all; any other answer goes to the thread's other side
		if to, err = agentsReplyRecipient(ctx, self, "", true, read, inAgentsRepo); err != nil {
			return nil, err
		}
	}
	if args.Close {
		return self.Close(ctx, &AgentCloseArgs{Person: true, Thread: thread, RepoId: repoId, To: to})
	}
	send.Thread, send.ThreadRepoId, send.To = thread, repoId, to
	if toAll {
		return self.Broadcast(ctx, send)
	}
	return self.Send(ctx, send)
}

// What the person's inbox reads.
type AgentPersonInboxArgs struct {
	// One thread; empty for the person's threads.
	Thread string
	// The answer may feed a model: a message that taints has its text withheld unless Include, which taints first.
	ForModel   bool
	Include    bool
	TaintFirst func(ctx context.Context) error
}

// One thread of the person's inbox.
type AgentPersonThread struct {
	Thread string `json:"thread"`
	Repo   string `json:"repo"`
	Closed bool   `json:"closed,omitempty"`
	// A thread to every agent.
	ToAll    bool                 `json:"to_all,omitempty"`
	Messages []*AgentInboxMessage `json:"messages"`
	// The newest message's time, which the threads are ordered by, newest first.
	Latest string `json:"latest"`
	latest time.Time
}

// The person's inbox.
type AgentPersonInbox struct {
	Threads []*AgentPersonThread `json:"threads"`
	// Messages past the answer's bounds, counted and not listed.
	More int `json:"more,omitempty"`
	// Messages whose text was withheld from a caller that may feed a model.
	Withheld int `json:"withheld,omitempty"`
	// The answer holds a message that taints: the caller's runs were tainted first.
	Untrusted bool `json:"untrusted,omitempty"`
}

// The person's threads (§20.7's person in a thread): each thread of the member's repos the person wrote in, one to the
// person's me, or one to every agent, every message of it, newest thread first, within SkillSettings'
// InboxResultMessageCount and InboxResultByteCount; or the one thread asked for. The person's view shows every text; a
// caller that may feed a model (ForModel) gets a message that taints withheld, or its text once TaintFirst tainted its
// runs (Include).
func (self *AgentsClient) PersonInbox(ctx context.Context, args *AgentPersonInboxArgs) (*AgentPersonInbox, error) {
	if args == nil {
		args = &AgentPersonInboxArgs{}
	}
	if args.ForModel && args.Include && args.TaintFirst == nil {
		return nil, ErrAgentsTaintFirst
	}
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	person := agentsPersonName(ctx, self)
	threads := []*AgentThreadRead{}
	if args.Thread != "" {
		thread, err := ParseAgentThreadId(args.Thread)
		if err != nil {
			return nil, fmt.Errorf("%w: the thread", ErrAgentToolArguments)
		}
		_, read, err := agentsThreadRepo(ctx, self, "", thread)
		if err != nil {
			return nil, err
		}
		threads = append(threads, read)
	} else {
		repoIds, err := agentsMemberRepos(ctx, self, place)
		if err != nil {
			return nil, err
		}
		for _, repoId := range repoIds {
			repo := self.args.Repo(repoId)
			if repo == nil {
				continue
			}
			threadIds, err := self.threadIds(ctx, repo)
			if err != nil {
				return nil, err
			}
			for _, threadId := range threadIds {
				read, err := self.readThread(ctx, place, repoId, repo, threadId)
				if err != nil {
					return nil, err
				}
				if slices.ContainsFunc(read.Messages, func(message *AgentMessageRead) bool {
					to := message.Message.To
					return message.Trust.Class == AgentMessageTrustPerson || (to == nil && repoId == place.agentsRepoId) ||
						(to != nil && to.MemberId == place.memberId && to.Name == person)
				}) {
					threads = append(threads, read)
				}
			}
		}
	}
	inbox := &AgentPersonInbox{Threads: []*AgentPersonThread{}}
	type pair struct {
		thread *AgentPersonThread
		read   *AgentThreadRead
	}
	pairs := []*pair{}
	for _, read := range threads {
		thread := &AgentPersonThread{Thread: read.Thread.String(), Repo: agentCardIdText(read.RepoId), Closed: read.Closed,
			ToAll: read.RepoId == place.agentsRepoId, Messages: []*AgentInboxMessage{}}
		for _, message := range read.Messages {
			if message.Time.After(thread.latest) {
				thread.latest = message.Time
			}
		}
		thread.Latest = agentCardTimeText(thread.latest)
		pairs = append(pairs, &pair{thread: thread, read: read})
	}
	slices.SortFunc(pairs, func(a *pair, b *pair) int {
		if !a.thread.latest.Equal(b.thread.latest) {
			return b.thread.latest.Compare(a.thread.latest)
		}
		return strings.Compare(a.thread.Thread+a.thread.Repo, b.thread.Thread+b.thread.Repo)
	})
	// the bounds, newest threads first, one message always
	count, byteCount := 0, 0
	taints := false
	for _, pair := range pairs {
		thread, read := pair.thread, pair.read
		for _, message := range read.Messages {
			size := len(message.Message.Subject) + len(message.Message.Body)
			if 0 < count && (self.settings.InboxResultMessageCount <= count || self.settings.InboxResultByteCount < byteCount+size) {
				inbox.More += 1
				continue
			}
			count, byteCount = count+1, byteCount+size
			out := agentInboxMessageOf(message)
			if out.Taints {
				taints = true
				if args.ForModel && !args.Include {
					out.Subject, out.Body, out.Withheld = "", "", true
					inbox.Withheld += 1
				}
			}
			thread.Messages = append(thread.Messages, out)
		}
		if 0 < len(thread.Messages) {
			inbox.Threads = append(inbox.Threads, thread)
		}
	}
	if args.ForModel && args.Include && taints {
		// the taint goes first, write-ahead: a failure returns nothing
		if err := args.TaintFirst(ctx); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
		}
		inbox.Untrusted = true
	}
	return inbox, nil
}
