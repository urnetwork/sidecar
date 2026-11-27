//go:build !js && !ios && !android && !sdk_mobile_bind

// The recURd skill's tools over MCP (DESIGN-COMPUTE §15.2, §20.10; SKILL-M11-07): agent_register, agent_summary,
// agent_list, agent_find, agent_send, agent_broadcast, agent_inbox and agent_close, answered by the network's
// AgentsTools (the root's agents_tools.go), the one implementation the Harness registers too, so a Claude Code, Codex or
// Cursor session reads the same arguments, tiers, refusals and data as a Harness agent.
//
//	agent     the session's agent is its hello's label, else its project's .ur default (McpSession.Agent); a session
//	          with none registers one first, agent_register's name or one derived from its harness, and acts as it
//	          for the session's life (mcpAgentsSessions), never past it
//	taint     an MCP session's run is its harness process's (hook_bind.go): untrusted: include and an inbox message
//	          that taints call McpResult.Untrusted first, write-ahead, and each untrusted text then sits between §16.6's
//	          markers (McpResult.Fence); a trusted writer's text is the member's data, unfenced; a stub's identifier
//	          fields go as data, never fenced, since they taint nothing
//	ids       an MCP caller's message takes a random id (§20.7's ids row)
//	tiers     §20.10's: register, summary, send, broadcast and close W, list, find and inbox R. A tainted run's send
//	          that kind 24 makes outward is refused at the call (ErrAgentSendOutward) until SKILL-M13-01 files it
//
// §16.5's design table names these once CSURF-M11-02's compute rows land in catalog.go (CONTRACTS C-29, which this
// task does not edit): until then the catalog test refuses a name the table lacks, so the tools join the daemon's
// catalog only once the table names every one, as tools_compute.go's do (mcpAgentsToolsDesigned), each held to its row.

package mcp

import (
	"context"
	"errors"
	"runtime"
	"slices"
	"sync"
	"weak"

	"github.com/urnetwork/sidecar"
)

// What the tools reach the network's agents through: *sidecar.Sidecar's AgentsTools.
type mcpAgentsNetwork interface {
	AgentsTools() (*sidecar.AgentsTools, error)
}

var (
	errMcpAgentsUnavailable = NewMcpError(McpCodeUnavailable,
		"your member's agents cannot be reached from this network now: run ur status in your own terminal", true)
	errMcpAgentsArguments = NewMcpError(McpCodeInvalidArguments,
		"the arguments do not fit the tool: names are a-z, 0-9 and '-'; a subject is one line of at most 120 characters "+
			"and a body at most 32 KiB; a thread is the id agent_inbox gives", false)
	errMcpAgentsReposOff = NewMcpError(McpCodeRefused,
		"your network's agent_repos feature is off: an Owner or Admin turns it on (the bot tab's first run, or ur admin "+
			"settings --feature agent_repos)", false)
	errMcpAgentsRepoAbsent = NewMcpError(McpCodeRefused,
		"your member has no agents repo yet: your member's first device that runs the recURd skill creates it", true)
	errMcpAgentsNameTaken = NewMcpError(McpCodeRefused,
		"every name tried is another agent's: pick another name", false)
	errMcpAgentsRegisterOther = NewMcpError(McpCodeRefused,
		"your agent's name is this session's label: agent_register answers it", false)
	errMcpAgentsNoAgent = NewMcpError(McpCodeInvalidArguments,
		"no agent of that name in your member's agents repo: agent_list shows them", false)
	errMcpAgentsNoThread = NewMcpError(McpCodeInvalidArguments,
		"no such thread in your member's inboxes: agent_inbox shows yours", false)
	errMcpAgentsThreadFull = NewMcpError(McpCodeRefused,
		"the thread holds as many messages as a thread may: open another", false)
	errMcpAgentsOutward = NewMcpError(McpCodeRefused,
		"this send leaves your member's own agents from a run that read untrusted content, an outward action this daemon "+
			"does not file yet: ask your person to send it", false)
	errMcpAgentsRecipient = NewMcpError(McpCodeInvalidArguments,
		"name to: the thread's last sender cannot be verified", false)
	errMcpAgentsScope = NewMcpError(McpCodeRefused,
		"scope team is not built yet: use scope mine", false)
	errMcpAgentsTaint = NewMcpError(McpCodeFailed,
		"the run's taint could not be written, so nothing untrusted is returned", true)
)

// Registers the eight tools, once §16.5's design table names them all.
func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		if !mcpAgentsToolsDesigned() {
			return
		}
		addAgentsTools(catalog)
	})
}

// Whether §16.5's design table names every agent_* tool (CSURF-M11-02's compute rows).
func mcpAgentsToolsDesigned() bool {
	for _, spec := range sidecar.AgentToolSpecs() {
		if _, found := mcpAgentsDesignRow(spec.Name); !found {
			return false
		}
	}
	return true
}

// The design table's row of name.
func mcpAgentsDesignRow(name string) (mcpCatalogDesignTool, bool) {
	index := slices.IndexFunc(mcpCatalogDesign, func(design mcpCatalogDesignTool) bool { return design.name == name })
	if index < 0 {
		return mcpCatalogDesignTool{}, false
	}
	return mcpCatalogDesign[index], true
}

// The names sessions with no agent registered, each kept while its session lives: a session is held weakly, and its
// entry goes when the session is collected. Safe for concurrent use.
type mcpAgentsSessions struct {
	stateLock sync.Mutex
	names     map[weak.Pointer[McpSession]]sidecar.AgentName
}

func newMcpAgentsSessions() *mcpAgentsSessions {
	return &mcpAgentsSessions{names: map[weak.Pointer[McpSession]]sidecar.AgentName{}}
}

// The name session registered, "" for none.
func (self *mcpAgentsSessions) name(session *McpSession) sidecar.AgentName {
	if session == nil {
		return ""
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.names[weak.Make(session)]
}

// Keeps name as session's agent for its later calls.
func (self *mcpAgentsSessions) set(session *McpSession, name sidecar.AgentName) {
	if session == nil {
		return
	}
	key := weak.Make(session)
	added := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		_, had := self.names[key]
		self.names[key] = name
		return !had
	}()
	if added {
		runtime.AddCleanup(session, func(key weak.Pointer[McpSession]) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.names, key)
		}, key)
	}
}

// The call's network's tools and its caller: the session's agent, its run's taint through result, and a session with
// no agent's registered name kept in sessions.
func mcpAgentsOf(call *McpCall, result *McpResult, sessions *mcpAgentsSessions) (*sidecar.AgentsTools, *sidecar.AgentsToolCaller, error) {
	if call == nil || call.Network == nil {
		return nil, nil, errMcpAgentsUnavailable
	}
	network, ok := call.Network.(mcpAgentsNetwork)
	if !ok {
		return nil, nil, errMcpAgentsUnavailable
	}
	tools, err := network.AgentsTools()
	if err != nil || tools == nil {
		return nil, nil, errMcpAgentsUnavailable
	}
	caller := &sidecar.AgentsToolCaller{Tainted: call.Tainted, Taint: result.Untrusted}
	session := call.Session
	if session != nil {
		hello := session.Hello()
		caller.Harness = hello.Harness
		if hello.Harness != "" {
			caller.DefaultName = string(sidecar.DeriveAgentName(hello.Harness, sidecar.DefaultSkillSettings()))
		}
		if agent := session.Agent(); agent != nil {
			caller.Agent, caller.NameFixed = agent.Label, true
		} else if name := sessions.name(session); name != "" {
			caller.Agent = string(name)
		}
		caller.Registered = func(name sidecar.AgentName) { sessions.set(session, name) }
	}
	return tools, caller, nil
}

// A root refusal as the tool answers it: constant text, never a name or an argument.
func mcpAgentsError(err error) error {
	var mcpErr *McpError
	switch {
	case errors.As(err, &mcpErr):
		return mcpErr
	case errors.Is(err, sidecar.ErrAgentsTaintFirst):
		return errMcpAgentsTaint
	case errors.Is(err, sidecar.ErrAgentReposOff):
		return errMcpAgentsReposOff
	case errors.Is(err, sidecar.ErrAgentsRepoAbsent):
		return errMcpAgentsRepoAbsent
	case errors.Is(err, sidecar.ErrAgentNameTaken):
		return errMcpAgentsNameTaken
	case errors.Is(err, sidecar.ErrAgentToolRegisterOther):
		return errMcpAgentsRegisterOther
	case errors.Is(err, sidecar.ErrAgentSendOutward):
		return errMcpAgentsOutward
	case errors.Is(err, sidecar.ErrAgentSendRecipient):
		return errMcpAgentsRecipient
	case errors.Is(err, sidecar.ErrAgentFindScope), errors.Is(err, sidecar.ErrAgentBroadcastScope):
		return errMcpAgentsScope
	case errors.Is(err, sidecar.ErrAgentCardAbsent):
		return errMcpAgentsNoAgent
	case errors.Is(err, sidecar.ErrAgentThreadAbsent):
		return errMcpAgentsNoThread
	case errors.Is(err, sidecar.ErrAgentThreadFull):
		return errMcpAgentsThreadFull
	case errors.Is(err, sidecar.ErrAgentToolArguments), errors.Is(err, sidecar.ErrAgentNameInvalid),
		errors.Is(err, sidecar.ErrAgentFindTask), errors.Is(err, sidecar.ErrAgentMessageInvalid):
		return errMcpAgentsArguments
	}
	return errMcpAgentsUnavailable
}

// The untrusted text of a list's entry, fenced once the run was tainted for it; a stub's fields go as data.
func mcpAgentsFenceEntry(result *McpResult, entry *sidecar.AgentListEntry) {
	if entry == nil {
		return
	}
	if entry.Stub != nil {
		// identifier fields held to their grammars, which taint nothing: data, with no markers in it
		entry.Stub.Text = ""
		return
	}
	if entry.Trusted {
		return
	}
	for _, text := range []*string{&entry.Harness, &entry.Model, &entry.Activity, &entry.Task, &entry.Summary} {
		if *text != "" {
			*text = result.Fence(*text)
		}
	}
}

// Registers the tools on catalog.
func addAgentsTools(catalog *McpCatalog) {
	sessions := newMcpAgentsSessions()
	mayAct := func(name string) bool {
		row, _ := mcpAgentsDesignRow(name)
		return row.mayAct
	}
	none := func(call *McpCall) ([]McpAccess, error) { return nil, nil }

	AddTool(catalog, &McpToolSpec[sidecar.AgentRegisterToolArgs]{
		Name: sidecar.AgentToolRegister, Tier: McpTierWrite, Description: sidecar.AgentToolRegisterDescription,
		MayAct: mayAct(sidecar.AgentToolRegister),
		Access: func(call *McpCall, in *sidecar.AgentRegisterToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentRegisterToolArgs, result *McpResult) (*sidecar.AgentRegisterToolResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		answer, err := tools.Register(ctx, caller, in)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		return answer.Data.(*sidecar.AgentRegisterToolResult), nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentSummaryToolArgs]{
		Name: sidecar.AgentToolSummary, Tier: McpTierWrite, Description: sidecar.AgentToolSummaryDescription,
		MayAct: mayAct(sidecar.AgentToolSummary),
		Access: func(call *McpCall, in *sidecar.AgentSummaryToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentSummaryToolArgs, result *McpResult) (*sidecar.AgentSummaryToolResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		answer, err := tools.Summary(ctx, caller, in)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		return answer.Data.(*sidecar.AgentSummaryToolResult), nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentListToolArgs]{
		Name: sidecar.AgentToolList, Tier: McpTierRead, Description: sidecar.AgentToolListDescription,
		MayAct: mayAct(sidecar.AgentToolList),
		Access: func(call *McpCall, in *sidecar.AgentListToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentListToolArgs, result *McpResult) (*sidecar.AgentList, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		result.Member()
		answer, err := tools.List(ctx, caller, in, nil)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		list := answer.Data.(*sidecar.AgentList)
		for _, entry := range list.Agents {
			mcpAgentsFenceEntry(result, entry)
		}
		return list, nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentFindToolArgs]{
		Name: sidecar.AgentToolFind, Tier: McpTierRead, Description: sidecar.AgentToolFindDescription,
		MayAct: mayAct(sidecar.AgentToolFind),
		Access: func(call *McpCall, in *sidecar.AgentFindToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentFindToolArgs, result *McpResult) (*sidecar.AgentFindResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		result.Member()
		answer, err := tools.Find(ctx, caller, in, nil)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		found := answer.Data.(*sidecar.AgentFindResult)
		for _, match := range found.Matches {
			mcpAgentsFenceEntry(result, match.Agent)
		}
		return found, nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentSendToolArgs]{
		Name: sidecar.AgentToolSend, Tier: McpTierWrite, Description: sidecar.AgentToolSendDescription,
		MayAct: mayAct(sidecar.AgentToolSend),
		Access: func(call *McpCall, in *sidecar.AgentSendToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentSendToolArgs, result *McpResult) (*sidecar.AgentSendToolResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		answer, err := tools.Send(ctx, caller, in)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		return answer.Data.(*sidecar.AgentSendToolResult), nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentBroadcastToolArgs]{
		Name: sidecar.AgentToolBroadcast, Tier: McpTierWrite, Description: sidecar.AgentToolBroadcastDescription,
		MayAct: mayAct(sidecar.AgentToolBroadcast),
		Access: func(call *McpCall, in *sidecar.AgentBroadcastToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentBroadcastToolArgs, result *McpResult) (*sidecar.AgentSendToolResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		answer, err := tools.Broadcast(ctx, caller, in)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		return answer.Data.(*sidecar.AgentSendToolResult), nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentInboxToolArgs]{
		Name: sidecar.AgentToolInbox, Tier: McpTierRead, Description: sidecar.AgentToolInboxDescription,
		MayAct: mayAct(sidecar.AgentToolInbox),
		Access: func(call *McpCall, in *sidecar.AgentInboxToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentInboxToolArgs, result *McpResult) (*sidecar.AgentInboxResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		result.Member()
		// Untrusted, the caller's Taint, runs before any message that taints is read into the answer
		answer, err := tools.Inbox(ctx, caller, in, nil)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		inbox := answer.Data.(*sidecar.AgentInboxResult)
		for _, message := range inbox.Messages {
			if !message.Taints {
				continue
			}
			if message.Subject != "" {
				message.Subject = result.Fence(message.Subject)
			}
			if message.Body != "" {
				message.Body = result.Fence(message.Body)
			}
		}
		return inbox, nil
	})

	AddTool(catalog, &McpToolSpec[sidecar.AgentCloseToolArgs]{
		Name: sidecar.AgentToolClose, Tier: McpTierWrite, Description: sidecar.AgentToolCloseDescription,
		MayAct: mayAct(sidecar.AgentToolClose),
		Access: func(call *McpCall, in *sidecar.AgentCloseToolArgs) ([]McpAccess, error) { return none(call) },
	}, func(ctx context.Context, call *McpCall, in *sidecar.AgentCloseToolArgs, result *McpResult) (*sidecar.AgentSendToolResult, error) {
		tools, caller, err := mcpAgentsOf(call, result, sessions)
		if err != nil {
			return nil, err
		}
		result.SetSource("agents")
		answer, err := tools.Close(ctx, caller, in)
		if err != nil {
			return nil, mcpAgentsError(err)
		}
		return answer.Data.(*sidecar.AgentSendToolResult), nil
	})
}
