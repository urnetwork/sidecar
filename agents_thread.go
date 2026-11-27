//go:build !ios_extension && !sidecar_http

// Threads (DESIGN-COMPUTE §20.7's open, reply, all, again, to and close rows, R-SKILL-4, R-SKILL-9, D-SKILL-3,
// D-SKILL-12; SKILL-M11-04): a thread is a directory inbox/<thread>/ of the repo its recipient reads, each message a file
// <id>.json in it, written create-only and never changed:
//
//	open      Send to a name: the recipient's agent repo, which the member's cards give (§20.5), or for a child with
//	          none yet its nearest ancestor's, addressed to it; a new thread, seq 1, kind message
//	again     Send with a thread continues it in the repo it lives in, seq one past the highest the writer has seen, kind
//	          reply, for as long as neither side closes it
//	all       Broadcast opens a thread to "*" in the member's agents repo, every agent's lease firing (SKILL-M11-05)
//	close     Close writes kind close in the thread
//	write     a create-only write (EvsPathWrite.IfVersion 0) carrying the inbox guard's grant, the one write that
//	          passes AgentsInboxGuard; the message kept in the outbox from before its first write until it lands
//	          (agents_outbox.go). A retry that finds its path taken counts the message sent when the first version
//	          there holds its bytes under its own provenance (this sidecar, or for the person any device of the
//	          member), and otherwise alarms id_reuse and gives up the id: nothing is written over another's message
//	from      an agent's message names the sender's card (its member, name, agent, sidecar and repo), its push sealing
//	          the agent's id and the run's tainted bit; the person's names the member and person, its push bound to no
//	          run (SendAsPerson, the device's input path's alone)
//	read      Thread reads every message of a directory: each file's first version is the message, a later one
//	          passed over and alarmed (EVS does not stop one writer rewriting another's path); a file whose history
//	          does not reach its first version is withheld; each judged by its provenance (agents_trust.go); ordered by
//	          (seq, id), so every reader shows one order
//
// Traps: no path is built from a seq or a name, which two devices writing as me, or two members' agents of one name,
// would collide on (R2-05); from is never taken on its word.
//
// On the compute legs. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

var (
	// The thread is not one this member's repos hold, or the message to continue is not in it.
	ErrAgentThreadAbsent = errors.New("agents: no such thread")
	// The message's path holds another message's bytes: its id is given up, and nothing was written over it.
	ErrAgentMessageIdTaken = errors.New("agents: another message holds the id's path")
	// The thread holds SkillSettings.ThreadMessageMax messages already.
	ErrAgentThreadFull = errors.New("agents: the thread holds as many messages as a thread may")
)

// What a send asks.
type AgentSendArgs struct {
	// The sender: the session's agent by its name, this sidecar's own card. Empty with Person.
	From AgentName
	// The member's own person (§20.7's kind (a)): only the device's input path sets it, ur agents send confirmed on
	// /dev/tty with no harness among its ancestors or the sdk's Agents().Send (SKILL-M11-08); its push is bound to no
	// run. Never an agent's tool call.
	Person bool
	// The recipient by its name in this member; empty for Broadcast.
	To      AgentName
	Subject string
	Body    string
	Refs    []*AgentMessageRef
	// The thread to continue and the repo it lives in; zero opens one.
	Thread       AgentThreadId
	ThreadRepoId Id
	// Where a report goes, nil for none: the person's me for work the person asked for.
	ReplyTo *AgentAddress
	// The id's key: a kind-24 send's effect key; else a Harness run's run and tool call; else random.
	EffectKey  []byte
	RunId      Id
	ToolCallId string
	// The writing run's tainted bit, which the push seals.
	Tainted bool
}

// What a send did.
type AgentSendResult struct {
	Message *AgentMessage
	// The repo the message landed in and its path.
	RepoId Id
	Path   string
	// A retry found the message already landed.
	Duplicate bool
	// The recipient's state from its status (§20.7: agent_send answers it), offline among them, so a sender can say when
	// a reply may come; empty for a message to every agent.
	RecipientState AgentState
}

// The message's id, from its key (§20.7's ids row).
func agentSendMessageId(args *AgentSendArgs) (AgentMessageId, error) {
	switch {
	case len(args.EffectKey) != 0:
		return AgentMessageIdForEffect(args.EffectKey), nil
	case args.RunId != (Id{}) && args.ToolCallId != "":
		return AgentMessageIdForCall(args.RunId, args.ToolCallId), nil
	}
	return NewAgentMessageId()
}

// The sender's from and push: an agent's card on this sidecar, its repo made first where a child has none (§20.5's
// step 3, at its first send), or the person's.
func (self *AgentsClient) sendFrom(ctx context.Context, place *agentsPlace, args *AgentSendArgs) (AgentMessageFrom, *Id, bool, error) {
	if args.Person {
		if args.From != "" || !place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
			return AgentMessageFrom{}, nil, false, fmt.Errorf("%w: the person writes from an untagged consented device of the member", ErrAgentsNotWriter)
		}
		return AgentMessageFrom{MemberId: place.memberId, Person: true}, nil, false, nil
	}
	read, err := self.ownCard(ctx, place, args.From)
	if err != nil {
		return AgentMessageFrom{}, nil, false, err
	}
	card := read.Card
	if card.AgentRepo == (Id{}) && place.authority.UntaggedConsented(place.sidecarId, place.memberId) {
		registration := &AgentRegistration{Name: card.Name, AgentId: card.AgentId, Card: card, CardVersion: read.Newest}
		if err := self.ensureAgentRepo(ctx, place, registration); err != nil {
			return AgentMessageFrom{}, nil, false, err
		}
		card = registration.Card
	}
	agentId := card.AgentId
	from := AgentMessageFrom{MemberId: place.memberId, Name: card.Name, AgentId: card.AgentId, SidecarId: place.sidecarId, RepoId: card.AgentRepo}
	return from, &agentId, args.Tainted, nil
}

// The repo a thread to name lands in and the address it names: its own agent repo, or a child's nearest ancestor's.
func (self *AgentsClient) recipient(ctx context.Context, place *agentsPlace, name AgentName) (Id, *AgentAddress, error) {
	read, err := self.readCard(ctx, place, name)
	if err != nil {
		return Id{}, nil, err
	}
	if read.Card == nil || read.Card.IsRetired() {
		return Id{}, nil, fmt.Errorf("%w: %s", ErrAgentCardAbsent, name)
	}
	repoId, err := self.AgentRepo(ctx, name)
	if err != nil {
		return Id{}, nil, err
	}
	address := &AgentAddress{MemberId: place.memberId, Name: name, RepoId: read.Card.AgentRepo}
	if read.Card.AgentRepo != (Id{}) && !place.authority.MemberAgentRepo(place.memberId, read.Card.AgentRepo) {
		address.RepoId = Id{}
	}
	return repoId, address, nil
}

// Whether repoId is one this member's threads live in: its agents repo or one of its agent repos.
func (self *AgentsClient) threadRepo(place *agentsPlace, repoId Id) (AgentsRepoAccess, bool) {
	if repoId != place.agentsRepoId && !place.authority.MemberAgentRepo(place.memberId, repoId) {
		return nil, false
	}
	repo := self.args.Repo(repoId)
	return repo, repo != nil
}

// Opens or continues a thread to one agent (see the file header).
func (self *AgentsClient) Send(ctx context.Context, args *AgentSendArgs) (*AgentSendResult, error) {
	if args == nil || args.To == "" {
		return nil, fmt.Errorf("%w: a send names its recipient", errInvalidSettings)
	}
	return self.send(ctx, args, false)
}

// Opens a thread to every agent of the member in its agents repo (§20.7's all row), or continues one.
func (self *AgentsClient) Broadcast(ctx context.Context, args *AgentSendArgs) (*AgentSendResult, error) {
	if args == nil || args.To != "" {
		return nil, fmt.Errorf("%w: a broadcast names no recipient", errInvalidSettings)
	}
	return self.send(ctx, args, true)
}

// What closing a thread asks: its thread, its repo, its sender, and to whom the close goes.
type AgentCloseArgs struct {
	From     AgentName
	Person   bool
	Thread   AgentThreadId
	RepoId   Id
	To       AgentName
	RunId    Id
	ToolCall string
	Tainted  bool
}

// Writes kind close in a thread (§20.7's close row): the Harness stops queuing it.
func (self *AgentsClient) Close(ctx context.Context, args *AgentCloseArgs) (*AgentSendResult, error) {
	if args == nil || args.Thread == (AgentThreadId{}) {
		return nil, fmt.Errorf("%w: a close names its thread", errInvalidSettings)
	}
	send := &AgentSendArgs{From: args.From, Person: args.Person, To: args.To, Thread: args.Thread, ThreadRepoId: args.RepoId,
		RunId: args.RunId, ToolCallId: args.ToolCall, Tainted: args.Tainted}
	return self.sendKind(ctx, send, args.To == "", AgentMessageKindClose)
}

// Send and Broadcast.
func (self *AgentsClient) send(ctx context.Context, args *AgentSendArgs, all bool) (*AgentSendResult, error) {
	kind := AgentMessageKindMessage
	if args.Thread != (AgentThreadId{}) {
		kind = AgentMessageKindReply
	}
	return self.sendKind(ctx, args, all, kind)
}

// Composes the message whole, keeps it in the outbox and lands it (see the file header).
func (self *AgentsClient) sendKind(ctx context.Context, args *AgentSendArgs, all bool, kind AgentMessageKind) (*AgentSendResult, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	from, agentId, tainted, err := self.sendFrom(ctx, place, args)
	if err != nil {
		return nil, err
	}
	message := &AgentMessage{From: from, Kind: kind, Subject: args.Subject, Body: args.Body, Refs: args.Refs,
		ReplyTo: args.ReplyTo, Effect: args.EffectKey, Created: self.clock.Now(), Seq: 1}
	repoId := place.agentsRepoId
	if !all {
		landing, address, err := self.recipient(ctx, place, args.To)
		if err != nil {
			return nil, err
		}
		repoId, message.To = landing, address
	}
	if args.Thread != (AgentThreadId{}) {
		// again: in the repo the thread lives in, one past the highest seq the writer has seen
		repo, ok := self.threadRepo(place, args.ThreadRepoId)
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrAgentThreadAbsent, args.Thread)
		}
		thread, err := self.readThread(ctx, place, args.ThreadRepoId, repo, args.Thread)
		if err != nil {
			return nil, err
		}
		if len(thread.Messages) == 0 {
			return nil, fmt.Errorf("%w: %s", ErrAgentThreadAbsent, args.Thread)
		}
		if self.settings.ThreadMessageMax <= len(thread.Messages)+thread.Withheld {
			return nil, ErrAgentThreadFull
		}
		message.Thread, message.Seq, repoId = args.Thread, thread.HighestSeq+1, args.ThreadRepoId
	} else if message.Thread, err = NewAgentThreadId(); err != nil {
		return nil, err
	}
	if message.Id, err = agentSendMessageId(args); err != nil {
		return nil, err
	}
	data, err := EncodeAgentMessage(message, self.settings)
	if err != nil {
		return nil, err
	}
	repo := self.args.Repo(repoId)
	if repo == nil {
		return nil, ErrAgentsUnavailable
	}
	if err := self.outboxPut(repoId, message, data, agentId, tainted); err != nil {
		return nil, err
	}
	duplicate, err := self.landMessage(ctx, repoId, repo, message, data, agentId, tainted)
	if err != nil {
		return nil, err
	}
	result := &AgentSendResult{Message: message, RepoId: repoId, Path: message.Path(), Duplicate: duplicate}
	if !all {
		result.RecipientState = self.recipientState(ctx, place, args.To)
	}
	return result, nil
}

// A message path's first version as a reader takes it: its bytes, signer, time and provenance; withheld where the
// path's history does not reach it or runs past SkillSettings.MessageHistoryMaxCount.
type agentMessageFirst struct {
	data       []byte
	version    *EvsHistoryVersion
	provenance *EvsPushProvenance
	// the versions after the first, each another write over a message
	later []*EvsHistoryVersion
}

// A message file's path withheld from its reader.
var errAgentMessageWithheld = errors.New("agents: a message whose first version cannot be judged")

// The first version of path in repo: see agentMessageFirst. ErrEvsPathAbsent where evs shows nothing.
func (self *AgentsClient) readMessageFirst(ctx context.Context, repo AgentsRepoAccess, path string) (*agentMessageFirst, error) {
	history, err := repo.History(ctx, &EvsReadArgs{Path: path})
	if err != nil {
		return nil, err
	}
	if !history.Whole || len(history.Versions) == 0 || self.settings.MessageHistoryMaxCount < len(history.Versions) {
		return nil, errAgentMessageWithheld
	}
	first := history.Versions[len(history.Versions)-1]
	if first.Removed || first.Ignored {
		return nil, errAgentMessageWithheld
	}
	buffer := &agentCardBuffer{maxByteCount: self.settings.MessageMaxByteCount}
	info, err := repo.ReadHead(ctx, &EvsReadArgs{Path: path, Version: first.Version, Provenance: true}, buffer)
	if errors.Is(err, errAgentCardOversize) {
		return nil, errAgentMessageWithheld
	}
	if err != nil {
		return nil, err
	}
	read := &agentMessageFirst{data: buffer.data, version: first, later: history.Versions[:len(history.Versions)-1]}
	if info != nil {
		read.provenance = info.Provenance
	}
	return read, nil
}

// Writes message create-only, carrying the inbox guard's grant, and drops it from the outbox once it landed: a path
// found taken holds it already (true) when its first version is its bytes under its own provenance, else the id is
// given up, alarmed. A failure with no answer is tried again, reading the path first, at most MessageWriteAttemptCount
// times; the message stays in the outbox where none lands it.
func (self *AgentsClient) landMessage(ctx context.Context, repoId Id, repo AgentsRepoAccess, message *AgentMessage, data []byte,
	agentId *Id, tainted bool) (bool, error) {
	path := message.Path()
	sidecarId, err := self.args.Self()
	if err != nil {
		return false, err
	}
	landedAlready := func() (bool, error) {
		first, err := self.readMessageFirst(ctx, repo, path)
		if errors.Is(err, ErrEvsPathAbsent) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		own := first.version.SignerSidecarId == sidecarId
		if message.From.Person && !own {
			authority, err := self.args.Authority()
			own = err == nil && authority.UntaggedConsented(first.version.SignerSidecarId, message.From.MemberId)
		}
		if (own && bytes.Equal(first.data, data)) || self.sameSupportNotice(first, message) {
			return true, nil
		}
		self.alarmReason(repoId, first.version, SidecarRecordAlarmIdReuse)
		return false, fmt.Errorf("%w: %s", ErrAgentMessageIdTaken, message.Id)
	}
	var lastErr error
	for attempt := 0; attempt < max(self.settings.MessageWriteAttemptCount, 1); attempt += 1 {
		if 0 < attempt {
			landed, err := landedAlready()
			if landed || errors.Is(err, ErrAgentMessageIdTaken) {
				if landed {
					return true, self.outboxRemove(message.Id)
				}
				self.outboxRemove(message.Id)
				return false, err
			}
		}
		zero := uint64(0)
		_, err := repo.WritePaths(ctx, &EvsWritePathsArgs{
			Writes: []*EvsPathWrite{{
				Path:         path,
				Content:      bytes.NewReader(data),
				IfVersion:    &zero,
				inboxMessage: &evsInboxMessageGrant{path: path},
			}},
			AgentId: agentId,
			Tainted: tainted,
		})
		if err == nil {
			return false, self.outboxRemove(message.Id)
		}
		lastErr = err
		if agentsWriteConflict(err) {
			landed, err := landedAlready()
			if landed {
				return true, self.outboxRemove(message.Id)
			}
			if errors.Is(err, ErrAgentMessageIdTaken) {
				self.outboxRemove(message.Id)
			}
			return false, err
		}
		if errors.Is(err, ErrEvsInboxMessagesOnly) {
			// refused for good: never retried from the outbox
			self.outboxRemove(message.Id)
			return false, err
		}
		if ctx.Err() != nil {
			return false, err
		}
	}
	return false, lastErr
}

// Raises record_alarm reason for a version, once a push.
func (self *AgentsClient) alarmReason(repoId Id, version *EvsHistoryVersion, reason SidecarRecordAlarm) {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.alarmedPushIds[version.PushId] {
			return false
		}
		self.alarmedPushIds[version.PushId] = true
		return true
	}()
	if !first || self.args.Alarm == nil {
		return
	}
	signerId := version.SignerSidecarId
	self.args.Alarm(&RecordAlarm{Reason: reason, LogId: repoId, SidecarId: &signerId})
}

// One message as a reader took it.
type AgentMessageRead struct {
	Message *AgentMessage
	Trust   *AgentMessageTrust
	RepoId  Id
	// Its first version, that version's push and signer and time.
	Version         uint64
	PushId          Id
	SignerSidecarId Id
	Time            time.Time
	// Later versions of the file, each another write over the message, alarmed.
	Rewritten []uint64
}

// One thread as a reader took it.
type AgentThreadRead struct {
	RepoId Id
	Thread AgentThreadId
	// By (seq, id).
	Messages []*AgentMessageRead
	// The highest seq among them, the next message's base.
	HighestSeq uint64
	// A close stands in it.
	Closed bool
	// Files that are no message a reader takes: withheld, unreadable or refused, each alarmed.
	Withheld int
}

// The cards of this member a judge confirms from's name and repo by, read once a name.
func (self *AgentsClient) cardLookup(ctx context.Context, place *agentsPlace) func(name AgentName) *AgentCard {
	cards := map[AgentName]*AgentCard{}
	return func(name AgentName) *AgentCard {
		if card, found := cards[name]; found {
			return card
		}
		var card *AgentCard
		if place.agentsRepo != nil {
			if read, err := self.readCard(ctx, place, name); err == nil {
				card = read.Card
			}
		}
		cards[name] = card
		return card
	}
}

// One message file as a reader takes it, nil where it is none a reader takes.
func (self *AgentsClient) readMessage(ctx context.Context, place *agentsPlace, repoId Id, repo AgentsRepoAccess, judge *agentMessageJudge,
	path string) (*AgentMessageRead, error) {
	thread, id, ok := ParseAgentMessagePath(path)
	if !ok {
		return nil, nil
	}
	first, err := self.readMessageFirst(ctx, repo, path)
	if errors.Is(err, errAgentMessageWithheld) || errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	message, err := ParseAgentMessage(first.data, self.settings)
	if err != nil || message.Id != id || message.Thread != thread {
		self.alarmReason(repoId, first.version, SidecarRecordAlarmBadEntry)
		return nil, nil
	}
	read := &AgentMessageRead{
		Message: message, RepoId: repoId, Version: first.version.Version, PushId: first.version.PushId,
		SignerSidecarId: first.version.SignerSidecarId, Time: first.version.Time,
	}
	for _, later := range first.later {
		read.Rewritten = append(read.Rewritten, later.Version)
		self.alarmReason(repoId, later, SidecarRecordAlarmPathRule)
	}
	read.Trust = judge.judge(message, first.version.SignerSidecarId, first.provenance)
	if read.Trust.Class == AgentMessageTrustRefused {
		self.alarmReason(repoId, first.version, SidecarRecordAlarmBadEntry)
		return nil, nil
	}
	if !read.Trust.FromVerified {
		// shown by its provenance alone
		self.alarmReason(repoId, first.version, SidecarRecordAlarmBadEntry)
	}
	return read, nil
}

// Reads one thread of repo at place (see the file header).
func (self *AgentsClient) readThread(ctx context.Context, place *agentsPlace, repoId Id, repo AgentsRepoAccess, thread AgentThreadId) (*AgentThreadRead, error) {
	read := &AgentThreadRead{RepoId: repoId, Thread: thread, Messages: []*AgentMessageRead{}}
	listing, err := repo.List(ctx, &EvsReadArgs{Path: AgentThreadPath(thread)})
	if errors.Is(err, ErrEvsPathAbsent) {
		return read, nil
	}
	if err != nil {
		return nil, err
	}
	judge := &agentMessageJudge{authority: place.authority, memberId: place.memberId, card: self.cardLookup(ctx, place)}
	for i, entry := range listing.Entries {
		if self.settings.ThreadListMaxCount <= i {
			break
		}
		path := AgentThreadPath(thread) + "/" + string(entry.Name)
		message, err := self.readMessage(ctx, place, repoId, repo, judge, path)
		if err != nil {
			return nil, err
		}
		if message == nil {
			read.Withheld += 1
			continue
		}
		read.Messages = append(read.Messages, message)
	}
	slices.SortFunc(read.Messages, func(a *AgentMessageRead, b *AgentMessageRead) int {
		if a.Message.Seq != b.Message.Seq {
			if a.Message.Seq < b.Message.Seq {
				return -1
			}
			return 1
		}
		return bytes.Compare(a.Message.Id[:], b.Message.Id[:])
	})
	for _, message := range read.Messages {
		read.HighestSeq = max(read.HighestSeq, message.Message.Seq)
		read.Closed = read.Closed || message.Message.Kind == AgentMessageKindClose
	}
	return read, nil
}

// One thread of this member's repo repoId, its agents repo or an agent repo: every message of it, held to the rules in
// the file header, by (seq, id).
func (self *AgentsClient) Thread(ctx context.Context, repoId Id, thread AgentThreadId) (*AgentThreadRead, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	repo, ok := self.threadRepo(place, repoId)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrAgentThreadAbsent, thread)
	}
	return self.readThread(ctx, place, repoId, repo, thread)
}

// The threads repoId's inbox/ holds, at most ThreadListMaxCount, sorted.
func (self *AgentsClient) Threads(ctx context.Context, repoId Id) ([]AgentThreadId, error) {
	place, err := self.placeWithRepo()
	if err != nil {
		return nil, err
	}
	repo, ok := self.threadRepo(place, repoId)
	if !ok {
		return nil, ErrAgentThreadAbsent
	}
	return self.threadIds(ctx, repo)
}

// The thread directories of repo's inbox/.
func (self *AgentsClient) threadIds(ctx context.Context, repo AgentsRepoAccess) ([]AgentThreadId, error) {
	listing, err := repo.List(ctx, &EvsReadArgs{Path: agentInboxDirectory})
	if errors.Is(err, ErrEvsPathAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	threads := []AgentThreadId{}
	for _, entry := range listing.Entries {
		thread, err := ParseAgentThreadId(strings.TrimSpace(string(entry.Name)))
		if err != nil || string(entry.Name) != thread.String() {
			continue
		}
		threads = append(threads, thread)
		if self.settings.ThreadListMaxCount <= len(threads) {
			break
		}
	}
	slices.SortFunc(threads, func(a AgentThreadId, b AgentThreadId) int { return bytes.Compare(a[:], b[:]) })
	return threads, nil
}
