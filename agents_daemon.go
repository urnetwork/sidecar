//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// ur daemon's agents methods (DESIGN-COMPUTE §15.1's ur agents rows, §15.3's Agents() in remote mode, §20.7's person in
// a thread, §20.8; SKILL-M11-08): what ur agents ls, send, broadcast, inbox and reply call, and a remote-mode app's
// Agents(), each over the network's agents client. The cli registers them with urDaemonMethodExtensions, giving them
// the caller's ancestry (Sidecar.HarnessAncestor) and its runs' taint (Sidecar.TaintAncestorRuns), read from the peer's
// pid, which the caller cannot set.
//
//	agents.list   the member's agents as the person's view shows them: with untrusted include, every agent's text,
//	              each run the caller's ancestry binds tainted first; with withhold, the default off a terminal, an
//	              untrusted writer's agent as its stub (§16.10's cli rule)
//	agents.send   a message, a broadcast, a reply or a close. The person's input path (§20.7's kind (a)): a call
//	              confirmed on /dev/tty or in an app's UI (D-CORE-13) from a caller with no harness process among its
//	              ancestors is written as the person's, bound to no run (AgentsClient.SendAsPerson). From under a harness
//	              it is that run's message, untrusted: written as the session's agent, its push's taint bit set, through
//	              agent_send's rules, kind 24's refusals among them (from M13b a tainted ancestor's send to another
//	              member files kind 24, SKILL-M13-01). A call neither confirmed nor under a harness is refused, never
//	              written down as an unknown run's: the person's input path is refused when no terminal answers
//	agents.inbox  the person's threads, or one, with untrusted as agents.list's
//	agents.graph  the agent graph (agents_graph.go), with untrusted as agents.list's
//	agents.watch  a long poll of the person's view (agents_person.go): the messages after the caller's cursor, and
//	              whether the cards, statuses or summaries changed, waiting up to SkillSettings.DaemonWatchWait; one
//	              person's watch a network runs while any caller polls, closed once none has for twice that wait
//
// A caller the daemon cannot read the ancestry of is under a harness, the closed reading. ur native-host relays none of
// these.
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"
)

// The methods' names.
const (
	DaemonMethodAgentsList  = "agents.list"
	DaemonMethodAgentsSend  = "agents.send"
	DaemonMethodAgentsInbox = "agents.inbox"
	DaemonMethodAgentsGraph = "agents.graph"
	DaemonMethodAgentsWatch = "agents.watch"
)

var (
	// A call's params that do not decode, or break a method's rules; the text names nothing they held.
	ErrDaemonAgentsParams = errors.New("agents: the params do not fit the method")
	// The person's message was not confirmed on /dev/tty or in an app, and no harness is the caller's ancestor.
	ErrDaemonAgentsUnconfirmed = errors.New("agents: the person's message is confirmed on the terminal (/dev/tty) or in an app, " +
		"and none answered: nothing was sent")
	// From under a harness, a message is its run's agent's, and the session names no agent.
	ErrDaemonAgentsNoAgent = errors.New("agents: under a harness, a message is its agent's: name the agent with --agent or " +
		"the project's .ur")
)

// agents.list's params.
type DaemonAgentsListParams struct {
	Network string `json:"network,omitempty"`
	Retired bool   `json:"retired,omitempty"`
	// withhold or include; "" reads withhold.
	Untrusted string `json:"untrusted,omitempty"`
}

// agents.send's params.
type DaemonAgentsSendParams struct {
	Network string `json:"network,omitempty"`
	// The recipient's name, "*" in a thread to all; "" for a broadcast or a reply to the thread's last sender.
	To      string `json:"to,omitempty"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body,omitempty"`
	// The thread to continue or close.
	Thread string `json:"thread,omitempty"`
	// Opens a thread to every agent.
	Broadcast bool `json:"broadcast,omitempty"`
	// Writes kind close in Thread.
	Close bool `json:"close,omitempty"`
}

// agents.send's answer: what was written, and whether as the person's own words or as a run's.
type DaemonAgentsSendReply struct {
	*AgentSendToolResult
	// Written as the person's (§20.7's kind (a)); false for a harness run's message, which reads untrusted.
	Person bool `json:"person"`
}

// agents.inbox's params.
type DaemonAgentsInboxParams struct {
	Network   string `json:"network,omitempty"`
	Thread    string `json:"thread,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
}

// agents.graph's params.
type DaemonAgentsGraphParams struct {
	Network   string `json:"network,omitempty"`
	Retired   bool   `json:"retired,omitempty"`
	Agent     string `json:"agent,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
}

// agents.watch's params: the cursor the last answer gave, "" for the first call, which answers the cursor alone.
type DaemonAgentsWatchParams struct {
	Network   string `json:"network,omitempty"`
	Cursor    string `json:"cursor,omitempty"`
	Untrusted string `json:"untrusted,omitempty"`
}

// One message of agents.watch's answer, with its notification where it gives one.
type DaemonAgentsWatchMessage struct {
	Message      *AgentThreadMessage `json:"message"`
	Notification *AgentNotification  `json:"notification,omitempty"`
}

// agents.watch's answer.
type DaemonAgentsWatchReply struct {
	Messages []*DaemonAgentsWatchMessage `json:"messages"`
	// The cursor to send next.
	Cursor string `json:"cursor"`
	// The cards, statuses or summaries changed since the cursor: read the list and the graph again.
	Changed bool `json:"changed,omitempty"`
	// Messages past the cursor that the daemon no longer holds: read the inbox again.
	Gap bool `json:"gap,omitempty"`
	// Untrusted writers' messages whose text was withheld.
	Withheld int `json:"withheld,omitempty"`
}

// What the methods read of the caller and the network: the cli's, from the peer's pid.
type DaemonAgentsBackends struct {
	// Whether the caller has a harness process of the network's runs among its ancestors; true where it cannot say.
	UnderHarness func(ctx context.Context, call *DaemonCall) bool
	// Taints each run the caller's ancestry binds, fsynced, before untrusted text returns to it.
	TaintAncestors func(ctx context.Context, call *DaemonCall) error
	// The network's agents client; nil reads the call's Sidecar's.
	Client func(sidecar *Sidecar) (*AgentsClient, error)
}

// The params of call, strictly.
func decodeDaemonAgentsParams(call *DaemonCall, params any) error {
	if err := decodeDaemonSocketParams(call, params); err != nil {
		return fmt.Errorf("%w: %w", ErrDaemonAgentsParams, err)
	}
	return nil
}

// Whether untrusted asks for the text: "" and withhold keep stubs.
func daemonAgentsInclude(untrusted string) (bool, error) {
	include, err := agentToolInclude(untrusted)
	if err != nil {
		return false, ErrDaemonAgentsParams
	}
	return include, nil
}

// The methods over backends (see the file header).
func DaemonAgentsMethods(backends *DaemonAgentsBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonAgentsBackends{}
	}
	underHarness := backends.UnderHarness
	if underHarness == nil {
		underHarness = func(ctx context.Context, call *DaemonCall) bool { return true }
	}
	taintAncestors := backends.TaintAncestors
	if taintAncestors == nil {
		taintAncestors = func(ctx context.Context, call *DaemonCall) error {
			return errors.New("agents: this daemon cannot taint its caller's runs, so it returns no untrusted text")
		}
	}
	clientOf := backends.Client
	if clientOf == nil {
		clientOf = func(sidecar *Sidecar) (*AgentsClient, error) { return sidecar.AgentsClient() }
	}
	open := func(call *DaemonCall, params any) (*AgentsClient, error) {
		if err := decodeDaemonAgentsParams(call, params); err != nil {
			return nil, err
		}
		if call.Sidecar == nil {
			return nil, fmt.Errorf("%w: no network's sidecar", ErrDaemonAgentsParams)
		}
		return clientOf(call.Sidecar)
	}
	// the taint the include of untrusted text runs first, as the caller's ancestry binds it
	taintFirst := func(call *DaemonCall) func(ctx context.Context) error {
		return func(ctx context.Context) error { return taintAncestors(ctx, call) }
	}
	hub := newDaemonAgentsHub()
	return []*DaemonMethod{
		{
			Name:    DaemonMethodAgentsList,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonAgentsListParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				include, err := daemonAgentsInclude(params.Untrusted)
				if err != nil {
					return nil, err
				}
				if include {
					// the person's view, every text, its readers' runs tainted first
					if err := taintAncestors(ctx, call); err != nil {
						return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
					}
					return client.List(ctx, &AgentListArgs{IncludeRetired: params.Retired})
				}
				return client.List(ctx, &AgentListArgs{IncludeRetired: params.Retired, ForModel: true})
			},
		},
		{
			Name:    DaemonMethodAgentsSend,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonAgentsSendParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				person := &AgentPersonSendArgs{To: params.To, Subject: params.Subject, Body: params.Body, Thread: params.Thread,
					Broadcast: params.Broadcast, Close: params.Close}
				switch {
				case underHarness(ctx, call):
					// that run's message, untrusted, never the person's
					if call.Agent == nil || call.Agent.Label == "" {
						return nil, ErrDaemonAgentsNoAgent
					}
					result, err := daemonAgentsRunSend(ctx, client, call.Agent.Label, person)
					if err != nil {
						return nil, err
					}
					return &DaemonAgentsSendReply{AgentSendToolResult: result}, nil
				case call.Confirmed:
					result, err := client.SendAsPerson(ctx, person)
					if err != nil {
						return nil, err
					}
					return &DaemonAgentsSendReply{AgentSendToolResult: result, Person: true}, nil
				}
				return nil, ErrDaemonAgentsUnconfirmed
			},
		},
		{
			Name:    DaemonMethodAgentsInbox,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonAgentsInboxParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				include, err := daemonAgentsInclude(params.Untrusted)
				if err != nil {
					return nil, err
				}
				// the caller may feed a model: withheld, or its runs tainted first for the text
				return client.PersonInbox(ctx, &AgentPersonInboxArgs{Thread: params.Thread, ForModel: true, Include: include,
					TaintFirst: taintFirst(call)})
			},
		},
		{
			Name:    DaemonMethodAgentsGraph,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonAgentsGraphParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				include, err := daemonAgentsInclude(params.Untrusted)
				if err != nil {
					return nil, err
				}
				if include {
					if err := taintAncestors(ctx, call); err != nil {
						return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
					}
					return client.Graph(ctx, &AgentsGraphArgs{Retired: params.Retired, Agent: params.Agent})
				}
				return client.Graph(ctx, &AgentsGraphArgs{Retired: params.Retired, Agent: params.Agent, ForModel: true})
			},
		},
		{
			Name:    DaemonMethodAgentsWatch,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &DaemonAgentsWatchParams{}
				client, err := open(call, params)
				if err != nil {
					return nil, err
				}
				include, err := daemonAgentsInclude(params.Untrusted)
				if err != nil {
					return nil, err
				}
				if include {
					if err := taintAncestors(ctx, call); err != nil {
						return nil, fmt.Errorf("%w: %w", ErrAgentsTaintFirst, err)
					}
				}
				return hub.wait(ctx, client, call.SessionDone, params.Cursor, include)
			},
		},
	}
}

// A message from under a harness: the session agent's, through agent_send's rules, its push tainted.
func daemonAgentsRunSend(ctx context.Context, client *AgentsClient, agent string, args *AgentPersonSendArgs) (*AgentSendToolResult, error) {
	tools, err := NewAgentsTools(&AgentsToolsArgs{Client: func() (*AgentsClient, error) { return client, nil }})
	if err != nil {
		return nil, err
	}
	caller := &AgentsToolCaller{Agent: agent, NameFixed: true, Tainted: func() bool { return true }}
	var answer *AgentsToolAnswer
	switch {
	case args.Close:
		answer, err = tools.Close(ctx, caller, &AgentCloseToolArgs{Thread: args.Thread})
	case args.Broadcast:
		answer, err = tools.Broadcast(ctx, caller, &AgentBroadcastToolArgs{Subject: args.Subject, Body: args.Body})
	default:
		answer, err = tools.Send(ctx, caller, &AgentSendToolArgs{To: args.To, Subject: args.Subject, Body: args.Body, Thread: args.Thread})
	}
	if err != nil {
		return nil, err
	}
	return answer.Data.(*AgentSendToolResult), nil
}

// The person's watches agents.watch polls, one a network's client while any caller polls. Safe for concurrent use.
type daemonAgentsHub struct {
	stateLock sync.Mutex
	watches   map[*AgentsClient]*daemonAgentsHubWatch
}

// An empty hub.
func newDaemonAgentsHub() *daemonAgentsHub {
	return &daemonAgentsHub{watches: map[*AgentsClient]*daemonAgentsHubWatch{}}
}

// One network's person watch as the hub keeps it: its messages in order, each numbered, the last
// DaemonWatchMessageCount held, and a channel closed at each change.
type daemonAgentsHubWatch struct {
	hub    *daemonAgentsHub
	client *AgentsClient
	watch  *AgentPersonWatch

	stateLock sync.Mutex
	// the number of the newest message told, and the held ones, oldest first
	seq      uint64
	messages []*daemonAgentsHubMessage
	// the number the view last changed at
	changedSeq uint64
	updated    chan struct{}
	// callers waiting now, and when the last one left
	waiting  int
	lastUsed time.Time
}

// One held message.
type daemonAgentsHubMessage struct {
	seq     uint64
	message *DaemonAgentsWatchMessage
	// whether its text taints a reader, withheld from a caller that did not include it
	taints bool
}

// The watch of client, started where none runs, counted waiting under the hub's lock, so an idle close, which takes the
// same lock, never closes a watch a caller holds.
func (self *daemonAgentsHub) watchOf(client *AgentsClient) (*daemonAgentsHubWatch, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if watch := self.watches[client]; watch != nil {
		func() {
			watch.stateLock.Lock()
			defer watch.stateLock.Unlock()
			watch.waiting += 1
		}()
		return watch, nil
	}
	watch := &daemonAgentsHubWatch{hub: self, client: client, updated: make(chan struct{}), lastUsed: client.clock.Now()}
	personWatch, err := client.WatchPerson(context.Background(), &AgentPersonWatchArgs{
		Message: watch.told,
		Changed: watch.changed,
	})
	if err != nil {
		return nil, err
	}
	watch.watch = personWatch
	watch.waiting = 1
	self.watches[client] = watch
	return watch, nil
}

// Takes one message the person's watch told.
func (self *daemonAgentsHubWatch) told(message *AgentThreadMessage, notification *AgentNotification) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.seq += 1
	self.messages = append(self.messages, &daemonAgentsHubMessage{seq: self.seq, taints: message.Trust != AgentMessageTrustPerson &&
		message.Trust != AgentMessageTrustMemberRun && message.Trust != AgentMessageTrustSupport,
		message: &DaemonAgentsWatchMessage{Message: message, Notification: notification}})
	if limit := max(self.client.settings.DaemonWatchMessageCount, 1); limit < len(self.messages) {
		self.messages = self.messages[len(self.messages)-limit:]
	}
	close(self.updated)
	self.updated = make(chan struct{})
}

// Notes the view changed.
func (self *daemonAgentsHubWatch) changed() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.seq += 1
	self.changedSeq = self.seq
	close(self.updated)
	self.updated = make(chan struct{})
}

// The answer for cursor now, and the channel the next change closes; empty where nothing is past the cursor.
func (self *daemonAgentsHubWatch) answer(cursor uint64, include bool) (*DaemonAgentsWatchReply, <-chan struct{}) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	reply := &DaemonAgentsWatchReply{Messages: []*DaemonAgentsWatchMessage{}, Cursor: strconv.FormatUint(self.seq, 10)}
	reply.Changed = cursor < self.changedSeq
	if 0 < len(self.messages) && cursor+1 < self.messages[0].seq && cursor < self.seq {
		reply.Gap = true
	}
	for _, held := range self.messages {
		if held.seq <= cursor {
			continue
		}
		message := held.message
		if held.taints && !include {
			// the text of a message that taints reaches only a caller that tainted its runs for it
			withheld := *message.Message
			withheld.Subject, withheld.Body = "", ""
			message = &DaemonAgentsWatchMessage{Message: &withheld, Notification: message.Notification}
			if message.Notification != nil {
				notification := *message.Notification
				notification.Subject = ""
				message.Notification = &notification
			}
			reply.Withheld += 1
		}
		reply.Messages = append(reply.Messages, message)
	}
	return reply, self.updated
}

// Waits for what follows cursor: at once where something does, else until a change, SkillSettings.DaemonWatchWait,
// the caller leaving or ctx's end. A first call, with no cursor, answers the cursor alone.
func (self *daemonAgentsHub) wait(ctx context.Context, client *AgentsClient, sessionDone <-chan struct{}, cursorText string, include bool) (*DaemonAgentsWatchReply, error) {
	watch, err := self.watchOf(client)
	if err != nil {
		return nil, err
	}
	defer self.leave(watch)
	if cursorText == "" {
		reply, _ := watch.answer(^uint64(0)>>1, include)
		reply.Changed, reply.Gap = false, false
		return reply, nil
	}
	cursor, err := strconv.ParseUint(cursorText, 10, 64)
	if err != nil {
		return nil, ErrDaemonAgentsParams
	}
	reply, updated := watch.answer(cursor, include)
	if 0 < len(reply.Messages) || reply.Changed || reply.Gap || client.settings.DaemonWatchWait <= 0 {
		return reply, nil
	}
	elapsed := make(chan struct{})
	stop := client.clock.AfterFunc(client.settings.DaemonWatchWait, func() { close(elapsed) })
	defer stop()
	select {
	case <-updated:
	case <-elapsed:
	case <-sessionDone:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	reply, _ = watch.answer(cursor, include)
	return reply, nil
}

// One caller left: once none has polled for twice DaemonWatchWait, the watch closes.
func (self *daemonAgentsHub) leave(watch *daemonAgentsHubWatch) {
	idle := 2 * max(watch.client.settings.DaemonWatchWait, watch.client.settings.WatchPassMinInterval)
	func() {
		watch.stateLock.Lock()
		defer watch.stateLock.Unlock()
		watch.waiting -= 1
		watch.lastUsed = watch.client.clock.Now()
	}()
	watch.client.clock.AfterFunc(idle, func() {
		closing := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			watch.stateLock.Lock()
			defer watch.stateLock.Unlock()
			if watch.waiting != 0 || watch.client.clock.Now().Sub(watch.lastUsed) < idle || self.watches[watch.client] != watch {
				return false
			}
			delete(self.watches, watch.client)
			return true
		}()
		if closing {
			watch.watch.Close()
		}
	})
}
