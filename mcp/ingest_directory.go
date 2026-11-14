//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's Run announcement row (MCP-M6-02; R-MCP-6, R-MCP-15, D-MCP-27, D-CORE-18, I-20): the ingest's RunLifecycle
// wired to the team directory's runs (RECORD-M6-16's DirectoryRuns). This is the one call site: a run's start, with
// its who, what and where, reaches DirectoryRuns.Started, a hook event of a started run Moved, and SessionEnd or the
// run's Coverage Ended. Nothing else of the ingest reaches the directory, and nothing else of a session reaches this
// file (I-20): RunLifecycleStart carries the harness, the agent label, the model, the title, the project and the
// branch, and no prompt past its first line, no tool body, no path and no diff.
//
// The session's claims value decides what is handed on. It is the value a session of the hook's caller starts under
// (Daemon.ResolveClaims, from the hello the hook arrived with), read once, when the run starts, and kept for the run:
// a later change of `.ur`, of the harness config or of the team's default leaves an open run as it was.
//
//   - auto and prompt hand the who, what and where to Started with the value, where DirectoryRuns announces an auto
//     run after its start delay and holds a prompt run for the person's first claim;
//   - off, and a start whose value cannot be read, hand on no title, project, branch, label or model: the run id, the
//     value and the project key alone, so DirectoryRuns can refuse a claim naming the setting. A start with no hello
//     or no directory hands on nothing at all.
//
// The title is the ingest's, already redacted: its first line, cut again here to DirectoryRunTitleByteCount at a
// rune's edge, since this file is what stands between a session and the directory.
//
// A run starts once: a resumed session's SessionStart restates nothing. The title a first prompt sets after the
// start, and a run that moves again after its Coverage ended it, come back through RunStarted with the same who and
// where, and reach Started again only as the content change or the new start they are, under the value first read.
//
// Safe for concurrent use: stateLock guards the open runs and is not held across a call to the directory.

package mcp

import (
	"context"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/urnetwork/sidecar"
)

// The hello a hook event arrived with, on the event's context.
type hookHelloContextKey struct{}

// ctx carrying the hello of the hook event it serves, which the directory lifecycle resolves the session's claims
// from.
func withHookHello(ctx context.Context, hello *sidecar.DaemonHello) context.Context {
	if hello == nil {
		return ctx
	}
	return context.WithValue(ctx, hookHelloContextKey{}, hello)
}

// The hello of the hook event ctx serves, nil for none.
func hookHelloOf(ctx context.Context) *sidecar.DaemonHello {
	hello, _ := ctx.Value(hookHelloContextKey{}).(*sidecar.DaemonHello)
	return hello
}

// The team directory's runs as the lifecycle writes them: *sidecar.DirectoryRuns' three calls.
type McpDirectoryRuns interface {
	Started(start *sidecar.DirectoryRunStart) error
	Moved(runId sidecar.Id)
	Ended(runId sidecar.Id) error
}

var _ McpDirectoryRuns = (*sidecar.DirectoryRuns)(nil)

// What the lifecycle needs.
type DirectoryLifecycleArgs struct {
	// A network's directory runs. Nil, a nil answer or an error, as a personal network's, announces nothing.
	Runs func(networkId sidecar.Id) (McpDirectoryRuns, error)
	// The value a session of hello's caller starts under in networkId: Daemon.ResolveClaims. Nil reads every
	// session as naming none, which hands on nothing.
	Claims func(ctx context.Context, hello *sidecar.DaemonHello, networkId sidecar.Id) *sidecar.SidecarClaimsResolution
	// Lifecycle only: a failure's class, never a title, a project or a branch. Nil discards.
	Log sidecar.Logger
}

// One open run.
type directoryLifecycleKey struct {
	networkId sidecar.Id
	runId     sidecar.Id
}

// What an open run was started with: the session's value, fixed, and the start last handed on.
type directoryLifecycleRun struct {
	claims       sidecar.SidecarClaims
	projectKey   string
	projectLabel string
	// nil where the start handed on nothing
	sent *sidecar.DirectoryRunStart
}

// The ingest's RunLifecycle over the team directory's runs. See the file's header.
type DirectoryLifecycle struct {
	runs   func(networkId sidecar.Id) (McpDirectoryRuns, error)
	claims func(ctx context.Context, hello *sidecar.DaemonHello, networkId sidecar.Id) *sidecar.SidecarClaimsResolution
	log    sidecar.Logger

	stateLock sync.Mutex
	openRuns  map[directoryLifecycleKey]*directoryLifecycleRun
}

var _ RunLifecycle = (*DirectoryLifecycle)(nil)

// The lifecycle over args, which IngestArgs.Lifecycle takes.
func NewDirectoryLifecycle(args *DirectoryLifecycleArgs) *DirectoryLifecycle {
	if args == nil {
		args = &DirectoryLifecycleArgs{}
	}
	log := args.Log
	if log == nil {
		log = sidecar.NewNoopLogger()
	}
	return &DirectoryLifecycle{
		runs:     args.Runs,
		claims:   args.Claims,
		log:      log,
		openRuns: map[directoryLifecycleKey]*directoryLifecycleRun{},
	}
}

// The network's directory runs, nil for none.
func (self *DirectoryLifecycle) runsOf(networkId sidecar.Id) McpDirectoryRuns {
	if self.runs == nil {
		return nil
	}
	runs, err := self.runs(networkId)
	if err != nil || runs == nil {
		return nil
	}
	return runs
}

// title as the directory takes it: its first line, cut to DirectoryRunTitleByteCount at a rune's edge.
func directoryLifecycleTitle(title string) string {
	line, _, _ := strings.Cut(strings.ReplaceAll(title, "\r", "\n"), "\n")
	line = strings.TrimSpace(line)
	if len(line) <= sidecar.DirectoryRunTitleByteCount {
		return line
	}
	cut := sidecar.DirectoryRunTitleByteCount
	for 0 < cut && !utf8.RuneStart(line[cut]) {
		cut -= 1
	}
	return strings.TrimSpace(line[:cut])
}

// Whether two starts hand the directory the same who, what and where.
func directoryLifecycleSame(a *sidecar.DirectoryRunStart, b *sidecar.DirectoryRunStart) bool {
	return a.Claims == b.Claims && a.ProjectKey == b.ProjectKey && a.AgentLabel == b.AgentLabel && a.Harness == b.Harness &&
		a.Model == b.Model && a.Title == b.Title && a.Project == b.Project && a.Branch == b.Branch
}

// RunLifecycle: a run's start, or a started run's who, what or where restated. The session's value is read at the
// first and kept.
func (self *DirectoryLifecycle) RunStarted(ctx context.Context, networkId sidecar.Id, start *RunLifecycleStart) {
	if start == nil {
		return
	}
	runs := self.runsOf(networkId)
	if runs == nil {
		return
	}
	key := directoryLifecycleKey{networkId: networkId, runId: start.RunId}
	open, known := func() (*directoryLifecycleRun, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		open, known := self.openRuns[key]
		return open, known
	}()
	if !known {
		hello := hookHelloOf(ctx)
		if hello == nil || self.claims == nil {
			// no caller to read a value for: nothing is handed on, the closed direction
			return
		}
		resolution := self.claims(ctx, hello, networkId)
		if resolution == nil {
			return
		}
		read := &directoryLifecycleRun{claims: resolution.Claims, projectKey: resolution.ProjectKey, projectLabel: resolution.ProjectLabel}
		open = func() *directoryLifecycleRun {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if raced, ok := self.openRuns[key]; ok {
				// another event of the run read its value first, which stands
				return raced
			}
			self.openRuns[key] = read
			return read
		}()
	}
	next := &sidecar.DirectoryRunStart{
		RunId:      start.RunId,
		Claims:     sidecar.DirectoryRunClaims(open.claims),
		ProjectKey: open.projectKey,
	}
	if open.claims == sidecar.SidecarClaimsAuto || open.claims == sidecar.SidecarClaimsPrompt {
		next.Harness = start.Harness
		next.AgentLabel = start.AgentLabel
		next.Model = start.Model
		next.Title = directoryLifecycleTitle(start.Title)
		next.Project = open.projectLabel
		if next.Project == "" {
			next.Project = start.Project
		}
		next.Branch = start.Branch
	} else {
		// off, and any value this build does not name: the setting alone
		next.Claims = sidecar.DirectoryRunClaimsOff
	}
	changed := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if open.sent != nil && directoryLifecycleSame(open.sent, next) {
			return false
		}
		open.sent = next
		return true
	}()
	if !changed {
		return
	}
	handed := *next
	if err := runs.Started(&handed); err != nil {
		self.log.Warningf("[ingest]a run's start did not reach the directory's runs")
	}
}

// RunLifecycle: a hook event of a started run.
func (self *DirectoryLifecycle) RunMoved(ctx context.Context, networkId sidecar.Id, runId sidecar.Id) {
	if runs := self.runsOf(networkId); runs != nil {
		runs.Moved(runId)
	}
}

// RunLifecycle: SessionEnd, or the run's Coverage after idling. The run's value is forgotten with it, so a run that
// moves again starts under the value its session would start under then.
func (self *DirectoryLifecycle) RunEnded(ctx context.Context, networkId sidecar.Id, runId sidecar.Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.openRuns, directoryLifecycleKey{networkId: networkId, runId: runId})
	}()
	runs := self.runsOf(networkId)
	if runs == nil {
		return
	}
	if err := runs.Ended(runId); err != nil {
		self.log.Warningf("[ingest]a run's end did not reach the directory's runs")
	}
}
