//go:build !js && !ios && !android && !sdk_mobile_bind && !sidecar_http && !ios_extension

// §8.9's run handle (D-GW-7, R-GW-6, D-MCP-16, owner decision 448, I-9; GW-M12-02): a gateway call binds to its run by
// its token, before the router sees it, never by its time, since the binding sets the marks the router enforces (§6.4,
// §25.10) as well as where the call is recorded.
//
//	handle   a token is a run handle when the command that minted it, `ur gateway token` run as a harness's credential
//	         command (Codex's [model_providers.ur.auth] command, Claude Code's apiKeyHelper), runs under a harness
//	         process: the nearest of its ancestors that is no shell, found as a hook's is (DESIGN §16.7), taken as the
//	         grant's harness's where its name is one of GatewaySettings.HarnessProcessNames' for that harness or a run
//	         of the network names that process already. The handle is that process, by pid and start time, with the
//	         processes above it, kept beside the token's hash (gateway_grant.go). A command whose stdout is a terminal,
//	         a person at a prompt, mints an unbound token whatever its ancestry: the command's word, which any same-user
//	         process could give, so TB1's residual (DESIGN §2.4); minted any other way, a token is unbound too
//	run      a bound call records into the run of that process whose session its headers name (Codex's session-id,
//	         Claude Code's x-claude-code-session-id, which their hooks report as session ids), a session no run holds
//	         yet bound as a hook's first event would bind it (RECORD.md section 4.3); else into the process's newest
//	         run; else a new run of the process. An unbound call records into the grant's own run of unbound calls,
//	         by harness, agent and time, tainted from its start (D-CTXH-9, QD-1445)
//	marks    a bound call is checked against the union of the marks and taint of every run of its process and of each
//	         process above it, a nested harness's caller among them, ended runs included (owner decision 448); an
//	         unbound call against the union over every run of its grant's live harness processes, the processes of
//	         the grant's live run handles that still run. A run whose marks do not read fails the union, and with it
//	         the call, which the router then refuses (failing closed); InferRouter's check reads the same union again,
//	         as it stands then, through BindingMarks
//
// The root holds the interface alone: the index of harness processes and their runs is mcp's (RunBinder, hook_bind.go),
// which implements it in mcp/hook_bind_gateway.go, since the root cannot import mcp. With no binder set every token is
// unbound and every binding fails, so no call reaches the router. A same-user process that reads another's token joins
// that token's binding, its marks included, as TB1 accepts.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// No binder is set, so no call binds: every one is refused.
var ErrGatewayNoBinder = errors.New("the gateway binds no call: its run binder is not set")

// What a binder reads of a network: its run files. *Sidecar is one.
type GatewayRunNetwork interface {
	Runs() (*RunStore, error)
}

// A run handle: the harness process a token binds (§8.9), kept beside the token's hash.
type GatewayRunHandle struct {
	Process ProcessIdentity `json:"process"`
	// The processes above it when the token was minted, nearest first: each one's runs are in the union too.
	Above []ProcessIdentity `json:"above,omitempty"`
}

// The handle's key, InferBinding.Handle and SessionGatewayBinding.Handle: the process's pid and start time, which name
// nothing outside the device.
func (self *GatewayRunHandle) Key() string {
	return self.Process.String()
}

// A copy.
func (self *GatewayRunHandle) clone() *GatewayRunHandle {
	if self == nil {
		return nil
	}
	return &GatewayRunHandle{Process: self.Process, Above: slices.Clone(self.Above)}
}

// The harness process a minting command runs under, as a binder finds it.
type GatewayHarnessProcess struct {
	// The nearest of the command's ancestors that is no shell.
	Process *ProcessInfo
	// The processes above it, nearest first.
	Above []ProcessIdentity
	// A run of the network names it already: a hook, or an earlier call, bound it.
	Known bool
}

// The union a call is checked against.
type GatewayRunUnion struct {
	Tainted bool
	// Each mark once.
	Marks []string
}

// mcp's run index as the gateway binds through it (mcp/hook_bind_gateway.go). Safe for concurrent use.
type GatewayRunBinder interface {
	// The nearest of pid's ancestors that is no shell, as a hook's harness process is found, with the processes above
	// it; nil where pid's ancestry does not read or names none.
	HarnessProcess(ctx context.Context, network GatewayRunNetwork, pid int) (*GatewayHarnessProcess, error)
	// The run a call of handle records into: the run of handle's process holding sessionId where the call names one,
	// bound as a hook's first event would bind it where none holds it yet; else the process's newest run; else a new
	// run of the process, which starts with the taint of the runs above it, fsynced.
	BindRun(ctx context.Context, network GatewayRunNetwork, harness string, handle *GatewayRunHandle, sessionId string) (Id, error)
	// The union of the taint and marks of every run of each handle's process and of the processes above it, ended runs
	// included; an error where one's marks do not read.
	Union(ctx context.Context, network GatewayRunNetwork, handles []*GatewayRunHandle) (*GatewayRunUnion, error)
}

// A call's binding, as a front hands it to the router (InferBinding) and to the recorder (§24.8).
type GatewayBinding struct {
	// The run the call records into.
	RunId   Id
	AgentId Id
	GrantId Id
	// The run handle's key; empty for an unbound token, whose binding is inferred.
	Handle string
	// The union the router checks.
	Tainted bool
	Marks   []string
}

// The router's view: the grant and the handle, whose marks it reads again as they stand then (BindingMarks).
func (self *GatewayBinding) InferBinding() *InferBinding {
	return &InferBinding{GrantId: self.GrantId, Handle: self.Handle}
}

// Sets mcp's binder (mcp's RunBinder.GatewayRunBinder), which the daemon builds after the gateway.
func (self *GatewayServer) SetRunBinder(binder GatewayRunBinder) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.binder = binder
}

// The binder, nil while none is set.
func (self *GatewayServer) runBinder() GatewayRunBinder {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.binder
}

// Whether a process name reads as one of names: the name itself or the name followed by "-", lowercase, without .exe.
func gatewayHarnessNameMatches(names []string, processName string) bool {
	base := processBaseName(processName)
	return slices.ContainsFunc(names, func(name string) bool {
		name = processBaseName(name)
		return name != "" && (base == name || strings.HasPrefix(base, name+"-"))
	})
}

// The run handle a token minted by pid is, for harness: see the file header. Nil, an unbound token, where no binder is
// set, the ancestry names no harness process, or the one it names is not harness's.
func (self *GatewayServer) harnessHandle(ctx context.Context, network GatewayRunNetwork, harness string, pid int) *GatewayRunHandle {
	binder := self.runBinder()
	if binder == nil || pid <= 0 {
		return nil
	}
	found, err := binder.HarnessProcess(ctx, network, pid)
	if err != nil || found == nil || found.Process == nil || !found.Process.Identity.Known() {
		return nil
	}
	if !found.Known && !gatewayHarnessNameMatches(self.settings.HarnessProcessNames[harness], found.Process.Name) {
		return nil
	}
	return &GatewayRunHandle{Process: found.Process.Identity, Above: slices.Clone(found.Above)}
}

// The handles of grantId's live tokens whose processes still run: the grant's live harness processes.
func (self *GatewayServer) liveHandles(store *GatewayGrantStore, grantId Id) ([]*GatewayRunHandle, error) {
	handles, err := store.Handles(grantId)
	if err != nil {
		return nil, err
	}
	live := []*GatewayRunHandle{}
	for _, handle := range handles {
		process, err := self.processes.Process(handle.Process.Pid)
		if err != nil || process.Identity != handle.Process {
			continue
		}
		live = append(live, handle)
	}
	return live, nil
}

// Binds a call of caller before the router sees it (§8.9): the run it records into and the union the router checks it
// against. Refused, so the call goes nowhere, where no binder is set, a run cannot be bound or made, or the union does
// not read.
func (self *GatewayServer) BindCall(ctx context.Context, caller *GatewayCaller, sessionId string) (*GatewayBinding, error) {
	binder := self.runBinder()
	if binder == nil {
		return nil, ErrGatewayNoBinder
	}
	binding := &GatewayBinding{AgentId: caller.Grant.AgentId, GrantId: caller.Grant.GrantId}
	handles := []*GatewayRunHandle{}
	if handle := caller.Token.Handle; handle != nil {
		runId, err := binder.BindRun(ctx, caller.Network, caller.Grant.Harness, handle, sessionId)
		if err != nil {
			return nil, err
		}
		binding.RunId, binding.Handle = runId, handle.Key()
		handles = append(handles, handle)
	} else {
		runId, err := self.unboundRun(ctx, caller)
		if err != nil {
			return nil, err
		}
		binding.RunId = runId
		live, err := self.liveHandles(caller.Store, caller.Grant.GrantId)
		if err != nil {
			return nil, err
		}
		handles = live
	}
	union, err := binder.Union(ctx, caller.Network, handles)
	if err != nil {
		return nil, err
	}
	binding.Tainted, binding.Marks = union.Tainted, slices.Clone(union.Marks)
	return binding, nil
}

// The run an unbound call of caller's grant records into: the grant's own, made on its first call, tainted
// untrusted_data from its start, since no process vouches for what the call carries (QD-1445).
func (self *GatewayServer) unboundRun(ctx context.Context, caller *GatewayCaller) (Id, error) {
	self.unboundLock.Lock()
	defer self.unboundLock.Unlock()
	grant, err := caller.Store.Grant(caller.Grant.GrantId)
	if err != nil {
		return Id{}, err
	}
	if grant.UnboundRunId != nil {
		return *grant.UnboundRunId, nil
	}
	runs, err := caller.Network.Runs()
	if err != nil {
		return Id{}, err
	}
	run := &RunFile{
		RunId:        NewId(),
		Harness:      grant.Harness,
		Tainted:      true,
		TaintReasons: []RunTaintReason{RunTaintUntrustedData},
	}
	if err := runs.Create(ctx, run); err != nil {
		return Id{}, err
	}
	if err := caller.Store.SetUnboundRun(ctx, grant.GrantId, run.RunId); err != nil {
		return Id{}, err
	}
	return run.RunId, nil
}

// The router's binding marks (InferMarkSource.BindingMarks, §8.9): the union, as it stands now, over the run handle's
// process and those above it, or for an unbound token over the grant's live harness processes. An error, which the
// router reads as every mark, where the grant or the handle is not this gateway's, no binder is set, or a run's marks do
// not read.
func (self *GatewayServer) BindingMarks(ctx context.Context, binding *InferBinding) ([]string, error) {
	binder := self.runBinder()
	if binder == nil {
		return nil, ErrGatewayNoBinder
	}
	if binding == nil {
		return nil, errors.New("no binding")
	}
	network, store, err := self.grantNetwork(binding.GrantId)
	if err != nil {
		return nil, err
	}
	handles := []*GatewayRunHandle{}
	if binding.Handle != "" {
		handle, err := store.HandleOf(binding.GrantId, binding.Handle)
		if err != nil {
			return nil, err
		}
		handles = append(handles, handle)
	} else {
		handles, err = self.liveHandles(store, binding.GrantId)
		if err != nil {
			return nil, err
		}
	}
	union, err := binder.Union(ctx, network, handles)
	if err != nil {
		return nil, err
	}
	return slices.Clone(union.Marks), nil
}

// The network and store holding grantId among the hosted networks'. An error where none does, or where a store that
// does not read might.
func (self *GatewayServer) grantNetwork(grantId Id) (GatewayNetwork, *GatewayGrantStore, error) {
	hosts := self.gatewayHosts()
	if hosts == nil {
		return nil, nil, ErrGatewayGrantUnknown
	}
	unread := []error{}
	for _, hosted := range hosts.GatewayNetworks() {
		store, err := hosted.Network.GatewayGrants()
		if err != nil {
			unread = append(unread, err)
			continue
		}
		if _, err := store.Grant(grantId); err == nil {
			return hosted.Network, store, nil
		} else if !errors.Is(err, ErrGatewayGrantUnknown) {
			unread = append(unread, err)
		}
	}
	if 0 < len(unread) {
		return nil, nil, fmt.Errorf("%w: a network's grants do not read: %w", ErrGatewayGrantUnknown, errors.Join(unread...))
	}
	return nil, nil, ErrGatewayGrantUnknown
}
