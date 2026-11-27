//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension

// The daemon's control-mode search methods (§16.10's CLI and wire rows; §5.8's control mode; R-MCP-12, D-MCP-17,
// D-MCP-25, I-7, I-9, I-13; SEARCH-M10-29): search, search.agents and search.status take the search tools' arguments
// (search_tools.go) on the call's network, so `ur search` and an agent read the same results.
//
//	control   a search that asks for progress gets search.progress notifications on its session until it answers;
//	          include first taints, fsynced, each run whose harness process is the caller's ancestor, by the peer pid
//	          the system reports (§5.8; §16.7's pid ancestry), and a caller whose process cannot be read gets no
//	          untrusted text
//	sessions  each control session is a search session of its own, its cursors, limits and hit ids its own; once
//	          the session ends each engine it searched in ends what it held there, as an MCP session's close does
//	          (D-MCP-25)
//
// No control path sets a remote mode or writes index settings (D-MCP-17). Queries, hits and cursors are never logged
// (I-13).

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

// The control methods the search tools run as, and the notification a search streams (§16.10's wire row).
const (
	DaemonMethodSearch       = "search"
	DaemonMethodSearchAgents = "search.agents"
	DaemonMethodSearchStatus = "search.status"
	// A notification, never a method: a search's progress, sent on its session while the call runs.
	DaemonMethodSearchProgress = "search.progress"
)

// Each control session's search session: its cursors, limits and hit ids are its own. Once the session ends its id is
// forgotten, and each engine it searched in ends what it held there (SearchEngine.EndSession), as an MCP session's
// close does (D-MCP-25).
type daemonSearchSessions struct {
	// called once an ended session's engines ended it: a test's seam, nil otherwise
	endedHook func(session Id)

	stateLock  sync.Mutex
	sessionIds map[<-chan struct{}]Id
	// the engines each session searched in
	sessionIdEngines map[Id]map[*SearchEngine]bool
}

// The search session of call's control session, minted at its first search, which tools' engine ends at the
// session's end; a call no session reader watches is a session of its own.
func (self *daemonSearchSessions) of(call *DaemonCall, tools *SearchTools) Id {
	if call.SessionDone == nil {
		return NewId()
	}
	sessionId, added := func() (Id, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.sessionIds == nil {
			self.sessionIds = map[<-chan struct{}]Id{}
			self.sessionIdEngines = map[Id]map[*SearchEngine]bool{}
		}
		sessionId, ok := self.sessionIds[call.SessionDone]
		if !ok {
			sessionId = NewId()
			self.sessionIds[call.SessionDone] = sessionId
			self.sessionIdEngines[sessionId] = map[*SearchEngine]bool{}
		}
		if tools != nil {
			self.sessionIdEngines[sessionId][tools.engine] = true
		}
		return sessionId, !ok
	}()
	if added {
		// forgotten when the session ends, which ends this wait
		go func(done <-chan struct{}) {
			<-done
			engines := func() map[*SearchEngine]bool {
				self.stateLock.Lock()
				defer self.stateLock.Unlock()
				delete(self.sessionIds, done)
				engines := self.sessionIdEngines[sessionId]
				delete(self.sessionIdEngines, sessionId)
				return engines
			}()
			for engine := range engines {
				engine.EndSession(sessionId)
			}
			if self.endedHook != nil {
				self.endedHook(sessionId)
			}
		}(call.SessionDone)
	}
	return sessionId
}

// What the control methods act through, for the call's Sidecar. A nil Tools, TaintAncestors or Secret takes the
// Sidecar's own.
type DaemonSearchBackends struct {
	// The network's search tools: Sidecar.SearchTools.
	Tools func(sidecar *Sidecar) (*SearchTools, error)
	// Taints, fsynced, each run of the network whose harness process is an ancestor of pid: Sidecar.TaintAncestorRuns.
	TaintAncestors func(ctx context.Context, sidecar *Sidecar, pid int) error
	// The daemon's credentials as a matcher (I-7): Sidecar.SecretMatcher's, an error while it cannot be read.
	Secret func(sidecar *Sidecar) (func(text []byte) bool, error)
	// Called once an ended control session's engines ended what it held: a test's seam, nil otherwise.
	sessionEnded func(session Id)
}

// search's control params: the tool's arguments, the call's network, and whether to stream search.progress.
type daemonSearchParams struct {
	SearchToolArgs
	Network  string `json:"network,omitempty"`
	Progress bool   `json:"progress,omitempty"`
}

// search.agents' control params.
type daemonSearchAgentsParams struct {
	SearchAgentsToolArgs
	Network string `json:"network,omitempty"`
}

// search.status' control params.
type daemonSearchStatusParams struct {
	SearchStatusToolArgs
	Network string `json:"network,omitempty"`
	Scope   string `json:"scope,omitempty"`
}

// The daemon's control-mode search methods over backends: search, search.agents and search.status, each on its call's
// network with the MCP tools' arguments, none a Confirm one (they sign nothing). The daemon's composition registers
// them with RegisterMethod.
func DaemonSearchMethods(backends *DaemonSearchBackends) []*DaemonMethod {
	if backends == nil {
		backends = &DaemonSearchBackends{}
	}
	toolsOf := backends.Tools
	if toolsOf == nil {
		toolsOf = func(sidecar *Sidecar) (*SearchTools, error) {
			return sidecar.SearchTools()
		}
	}
	taintAncestors := backends.TaintAncestors
	if taintAncestors == nil {
		taintAncestors = func(ctx context.Context, sidecar *Sidecar, pid int) error {
			return sidecar.TaintAncestorRuns(ctx, pid)
		}
	}
	secretOf := backends.Secret
	if secretOf == nil {
		secretOf = func(sidecar *Sidecar) (func(text []byte) bool, error) {
			matcher, err := sidecar.SecretMatcher()
			if err != nil {
				return nil, err
			}
			return matcher.Matches, nil
		}
	}
	sessions := &daemonSearchSessions{endedHook: backends.sessionEnded}
	decode := func(call *DaemonCall, params any) error {
		if len(call.Params) == 0 {
			return nil
		}
		decoder := json.NewDecoder(strings.NewReader(string(call.Params)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(params); err != nil {
			return ErrSearchToolArguments
		}
		return nil
	}
	envOf := func(call *DaemonCall) (*SearchTools, *SearchToolEnv, error) {
		if call.Sidecar == nil {
			return nil, nil, ErrSidecarSearchUnavailable
		}
		tools, err := toolsOf(call.Sidecar)
		if err != nil {
			return nil, nil, err
		}
		env := &SearchToolEnv{
			Session: sessions.of(call, tools),
			// the caller's harness runs read untrusted text through this answer: they are tainted first, by the pid the
			// system reports for the socket's peer, never the hello's, which the caller writes (§5.8)
			Taint: func(ctx context.Context) error {
				pid := 0
				if call.Hello != nil {
					pid = int(call.Hello.PeerPid)
				}
				if pid <= 0 {
					return errors.New("the caller's process cannot be read, so no untrusted text is returned")
				}
				return taintAncestors(ctx, call.Sidecar, pid)
			},
		}
		return tools, env, nil
	}
	// the daemon's credentials, which a hit holding one is withheld for (I-7): a call whose result could carry text is
	// refused while they cannot be read, as MCP's tools are
	matcherOf := func(call *DaemonCall, env *SearchToolEnv) error {
		secret, err := secretOf(call.Sidecar)
		if err != nil {
			return fmt.Errorf("the daemon's credentials cannot be read to check the result: %w", err)
		}
		env.Secret = secret
		return nil
	}
	return []*DaemonMethod{
		{
			Name:        DaemonMethodSearch,
			Network:     true,
			allNetworks: daemonSearchAllScope,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				if params.Scope == "all" || strings.HasPrefix(params.Cursor, daemonSearchAllPrefix) {
					return daemonSearchAll(ctx, call, params, envOf, matcherOf)
				}
				tools, env, err := envOf(call)
				if err != nil {
					return nil, err
				}
				if err := matcherOf(call, env); err != nil {
					return nil, err
				}
				if params.Progress && call.Notify != nil {
					env.Report = func(progress *SearchToolProgress) {
						// a notification past the call's answer is dropped by the session
						call.Notify(DaemonMethodSearchProgress, progress)
					}
				}
				return tools.Search(ctx, env, &params.SearchToolArgs)
			},
		},
		{
			Name:    DaemonMethodSearchAgents,
			Network: true,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchAgentsParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				tools, env, err := envOf(call)
				if err != nil {
					return nil, err
				}
				if err := matcherOf(call, env); err != nil {
					return nil, err
				}
				return tools.Agents(ctx, env, &params.SearchAgentsToolArgs)
			},
		},
		{
			Name:        DaemonMethodSearchStatus,
			Network:     true,
			allNetworks: daemonSearchAllScope,
			Handler: func(ctx context.Context, call *DaemonCall) (any, error) {
				params := &daemonSearchStatusParams{}
				if err := decode(call, params); err != nil {
					return nil, err
				}
				if params.Scope == "all" {
					if params.Network != "" || len(params.Repos) > 0 {
						return nil, ErrSearchToolArguments
					}
					if len(call.Networks) == 0 {
						return nil, ErrSidecarSearchUnavailable
					}
					out := &SearchStatusToolResult{Repos: []*SearchToolRepoStatus{}}
					for _, network := range call.Networks {
						tools, err := toolsOf(network.Sidecar)
						if err != nil {
							return nil, err
						}
						status, err := tools.Status(&params.SearchStatusToolArgs)
						if err != nil {
							return nil, err
						}
						for _, repo := range status.Repos {
							repo.Network = network.NetworkId.String()
							out.Repos = append(out.Repos, repo)
						}
					}
					return out, nil
				}
				tools, _, err := envOf(call)
				if err != nil {
					return nil, err
				}
				return tools.Status(&params.SearchStatusToolArgs)
			},
		},
	}
}
