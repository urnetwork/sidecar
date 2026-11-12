//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind && !windows

// The twenty-agent test's load (§22.8's evs row; R-TEST-7; DESIGN-DETAILS 8.6's twenty agents; EVS1-M2-43), on an
// EvsGitWorld (sidecartest/evs_git_world.go): Agents agents, each a device of its own with a clone of the repo, commit
// to their owned refs ur/<sidecar_id>/work and push them at OwnedPushRate in all, and every MergeInterval each merges
// its ref into main, fetching and merging again on a non-fast-forward, open loop, so a slow system shows as queueing
// in the figures and never as a lower arrival rate. The run takes Duration; §22.8's is 20 agents for 1 h at 4.3
// pushes a second, which twenty-agents.sh runs apart, since this machine shares its CPU with a test campaign.
//
// At its end, the queues drained, a device that pushed nothing replays main and every agent's ref and the run
// checks, as §22.8 and 8.6 ask:
//
//	acked     no acknowledged commit lost: every commit an owned push answered ok reaches its ref's tip as evs holds
//	          it, and every merge main took is in main's history
//	conflicts no conflict branch on any device
//	fsck      git fsck --strict on the checking device's bare repository
//	export    export's tip of main equals the checking device's main
//
// The report is load's one shape (report.go): the owned pushes' figures, with the merges' in Notes beside the checks'
// outcomes. 8.6's check that a merge carries none of the commits it names is the checker's replay's own (8.2.3's
// rule refuses a push carrying another sidecar's commit, which stops the ref short of evs's head and fails the main
// check here); counting what each merge carried, §11.15's targets, the fold ratio, records per batch and removal
// markers (§22.8's fold row) are not read by this run yet. Not safe for concurrent use; one run a world.

package load

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/sidecartest/evsgit"
)

// The run's shape.
type EvsAgentsSettings struct {
	// The agents, each a device: 20 (§22.8).
	Agents int
	// The owned pushes a second over every agent: 4, beside the merges, near §22.8's 4.3 in all.
	OwnedPushRate float64
	// Each agent merges its ref into main this often: 60 s (§22.8).
	MergeInterval time.Duration
	// The steady phase, warm-up aside: 1 h for the published run.
	Duration time.Duration
	// The warm-up before it, left out of the figures.
	Warmup time.Duration
	// How long the end waits for the agents' queues to drain and the checker to replay: 2 min.
	DrainTimeout time.Duration
	// A merge's tries on non-fast-forward before it counts failed: 8.
	MergeTryCount int
	// How often the end looks again at a queue still draining: 100 ms.
	DrainPollInterval time.Duration
}

// §22.8's run.
func DefaultEvsAgentsSettings() *EvsAgentsSettings {
	return &EvsAgentsSettings{
		Agents:            20,
		OwnedPushRate:     4,
		MergeInterval:     60 * time.Second,
		Duration:          time.Hour,
		Warmup:            time.Minute,
		DrainTimeout:      2 * time.Minute,
		MergeTryCount:     8,
		DrainPollInterval: 100 * time.Millisecond,
	}
}

// What a run found beside the owned pushes' report.
type EvsAgentsResult struct {
	Owned  *Report
	Merges *Report
	// Commits an ok answered that the end could not find, each as ref and oid.
	Lost []string
	// Conflict branches the devices made.
	Conflicts int
	Fsck      error
	// Export's tip of main, and the checker's.
	ExportTip string
	MainTip   string
}

// Whether every check held.
func (self *EvsAgentsResult) Err() error {
	errs := []error{}
	if 0 < len(self.Lost) {
		errs = append(errs, fmt.Errorf("%d acknowledged commits lost: %v", len(self.Lost), self.Lost))
	}
	if 0 < self.Conflicts {
		errs = append(errs, fmt.Errorf("%d conflict branches", self.Conflicts))
	}
	if self.Fsck != nil {
		errs = append(errs, self.Fsck)
	}
	if self.ExportTip != self.MainTip {
		errs = append(errs, fmt.Errorf("export's main %s, the checker's %s", self.ExportTip, self.MainTip))
	}
	return errors.Join(errs...)
}

// One agent: its device and clone, and what it was answered.
type evsAgent struct {
	device *evsgit.Device
	clone  string
	ref    string
	// held across one agent's git work, which shares a clone
	workLock sync.Mutex
	count    int

	stateLock sync.Mutex
	ackedOwn  []string
	ackedMain []string
}

// Runs the agents on world: see the file header.
func RunEvsAgents(ctx context.Context, world *evsgit.World, settings *EvsAgentsSettings) (*EvsAgentsResult, error) {
	if settings == nil {
		settings = DefaultEvsAgentsSettings()
	}
	if settings.Agents <= 0 || settings.OwnedPushRate <= 0 || settings.MergeInterval <= 0 || settings.Duration <= 0 {
		return nil, fmt.Errorf("an agents run of %d agents, rate %f, merges every %s, for %s", settings.Agents, settings.OwnedPushRate, settings.MergeInterval, settings.Duration)
	}
	agents := []*evsAgent{}
	for i := range settings.Agents {
		device := world.Device(fmt.Sprintf("agent-%02d", i), nil)
		agent := &evsAgent{device: device, ref: "ur/" + device.SidecarId.String() + "/work"}
		agent.clone = device.Clone()
		agents = append(agents, agent)
	}
	// main's first commit, which every agent's ref starts from
	first := agents[0]
	first.device.Commit(first.clone, "the repo's first commit", map[string]*string{"README.md": evsgit.Text("twenty agents\n")})
	if out, ok := first.device.Push(first.clone, "origin", "HEAD:refs/heads/main"); !ok {
		return nil, fmt.Errorf("main's first push: %s", out)
	}
	for _, agent := range agents {
		if err := agent.device.Replay("main"); err != nil {
			return nil, err
		}
		if out, ok := agent.device.GitIn(agent.clone, nil, "fetch", "-q", "origin", "main"); !ok {
			return nil, fmt.Errorf("an agent's first fetch: %s", out)
		}
		agent.device.MustGit(agent.clone, "checkout", "-q", "-B", "work", "origin/main")
	}
	owned := NewDriver(&DriverSettings{
		Name: "evs twenty agents: owned pushes", Rate: settings.OwnedPushRate, Warmup: settings.Warmup,
		Steady: settings.Duration, MaxInFlight: settings.Agents, MaxFailureKinds: 16,
	}, func(ctx context.Context, arrival int64) error {
		return agents[arrival%int64(len(agents))].pushOwned()
	})
	merges := NewDriver(&DriverSettings{
		Name: "evs twenty agents: merges into main", Rate: float64(settings.Agents) / settings.MergeInterval.Seconds(),
		Warmup: settings.Warmup, Steady: settings.Duration, MaxInFlight: settings.Agents, MaxFailureKinds: 16,
	}, func(ctx context.Context, arrival int64) error {
		return agents[arrival%int64(len(agents))].merge(settings.MergeTryCount)
	})
	result := &EvsAgentsResult{}
	var waitGroup sync.WaitGroup
	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()
		result.Owned = owned.Run(ctx)
	}()
	go func() {
		defer waitGroup.Done()
		result.Merges = merges.Run(ctx)
	}()
	waitGroup.Wait()
	if err := ctx.Err(); err != nil {
		return result, err
	}
	if err := evsAgentsCheck(ctx, world, agents, settings, result); err != nil {
		return result, err
	}
	result.Owned.Settings = map[string]string{
		"agents": strconv.Itoa(settings.Agents), "owned_push_rate": strconv.FormatFloat(settings.OwnedPushRate, 'f', -1, 64),
		"merge_interval": settings.MergeInterval.String(), "duration": settings.Duration.String(),
	}
	result.Owned.Notes = append(result.Owned.Notes,
		fmt.Sprintf("merges: %d succeeded, %d failed", result.Merges.Succeeded, result.Merges.Failed),
		"§11.15's targets, the fold ratio, records per batch and removal markers are not read by this run")
	return result, nil
}

// One owned push: a commit of the agent's own file, pushed to its owned ref, which the queue takes to evs.
func (self *evsAgent) pushOwned() error {
	self.workLock.Lock()
	defer self.workLock.Unlock()
	self.count += 1
	path := "agents/" + self.device.Label + ".md"
	content := fmt.Sprintf("%s's note %d\n", self.device.Label, self.count)
	commit := self.device.Commit(self.clone, fmt.Sprintf("%s %d", self.device.Label, self.count), map[string]*string{path: &content})
	out, ok := self.device.Push(self.clone, "origin", "HEAD:refs/heads/"+self.ref)
	if !ok {
		return fmt.Errorf("an owned push: %s", evsAgentsReason(out))
	}
	self.stateLock.Lock()
	self.ackedOwn = append(self.ackedOwn, commit)
	self.stateLock.Unlock()
	return nil
}

// One merge into main: the mount's replay of main, as a hint would bring it, then fetch, merge the agent's work and
// push; a non-fast-forward replays, fetches and merges again.
func (self *evsAgent) merge(tryCount int) error {
	self.workLock.Lock()
	defer self.workLock.Unlock()
	for try := 0; try < max(1, tryCount); try += 1 {
		// the mount takes evs's newest main first, as a hint would have its sync engine do
		if err := self.device.Replay("main"); err != nil {
			return fmt.Errorf("a merge's replay of main: %w", err)
		}
		if out, ok := self.device.GitIn(self.clone, nil, "fetch", "-q", "origin", "main"); !ok {
			return fmt.Errorf("a merge's fetch: %s", evsAgentsReason(out))
		}
		if out, ok := self.device.GitIn(self.clone, nil, "merge", "-q", "--no-edit", "origin/main"); !ok {
			return fmt.Errorf("a merge: %s", evsAgentsReason(out))
		}
		commit := strings.TrimSpace(self.device.MustGit(self.clone, "rev-parse", "HEAD"))
		out, ok := self.device.Push(self.clone, "origin", "HEAD:refs/heads/main")
		if ok {
			self.stateLock.Lock()
			self.ackedMain = append(self.ackedMain, commit)
			self.stateLock.Unlock()
			return nil
		}
		if !strings.Contains(out, "non-fast-forward") {
			return fmt.Errorf("a merge's push: %s", evsAgentsReason(out))
		}
	}
	return fmt.Errorf("a merge refused non-fast-forward %d times", tryCount)
}

// The status line of git's porcelain output that names why, short.
func evsAgentsReason(out string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "!") || strings.Contains(line, "rejected") || strings.Contains(line, "fatal") {
			return strings.TrimSpace(line)
		}
	}
	return strings.TrimSpace(out)
}

// The end's checks: see the file header.
func evsAgentsCheck(ctx context.Context, world *evsgit.World, agents []*evsAgent, settings *EvsAgentsSettings, result *EvsAgentsResult) error {
	deadline := time.Now().Add(settings.DrainTimeout)
	for _, agent := range agents {
		for {
			statuses, err := agent.device.Mount.Receiver().JournalStatus()
			if err != nil {
				return err
			}
			if len(statuses) == 0 {
				break
			}
			if time.Now().After(deadline) {
				return fmt.Errorf("%s's queue did not drain: %+v", agent.device.Label, statuses)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(settings.DrainPollInterval):
			}
		}
		branches, err := agent.device.Mount.Sync().ConflictBranches(ctx)
		if err != nil {
			return err
		}
		result.Conflicts += len(branches)
	}
	checker := world.Device("checker", nil)
	if err := checker.Replay("main"); err != nil {
		return fmt.Errorf("the checker's replay of main: %w", err)
	}
	result.MainTip = checker.LocalRef("refs/heads/main")
	for _, agent := range agents {
		if err := checker.Replay(agent.ref); err != nil {
			return fmt.Errorf("the checker's replay of %s: %w", agent.ref, err)
		}
		tip := checker.LocalRef("refs/heads/" + agent.ref)
		agent.stateLock.Lock()
		ackedOwn, ackedMain := append([]string{}, agent.ackedOwn...), append([]string{}, agent.ackedMain...)
		agent.stateLock.Unlock()
		for _, commit := range ackedOwn {
			if _, ok := checker.GitIn(checker.Mount.BareDir, nil, "merge-base", "--is-ancestor", commit, tip); !ok {
				result.Lost = append(result.Lost, agent.ref+" "+commit)
			}
		}
		for _, commit := range ackedMain {
			if _, ok := checker.GitIn(checker.Mount.BareDir, nil, "merge-base", "--is-ancestor", commit, result.MainTip); !ok {
				result.Lost = append(result.Lost, "main "+commit)
			}
		}
	}
	result.Fsck = checker.Fsck()
	_, tips := checker.Export("main")
	result.ExportTip = tips["refs/heads/main"]
	return nil
}
