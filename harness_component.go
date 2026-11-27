//go:build !ios_extension && !sidecar_http

// The Harness on a Sidecar (DESIGN-COMPUTE §3.3, §20.7, Appendix D's §5.8 row): one Harness per sidecar host, built as
// a compute component (compute_sidecar.go) over the Sidecar's router, run store, gate and approvals, and the seams its
// owners fill through RegisterHarnessSources: the recURd skill (SKILL), the context journal (CTXH, wired by
// HARN-M11-08), the acknowledgment store (CTRUST), the purchase rights and kind 21's builder (BAL), SAFE's verdicts,
// and the host's foreground state (HARN-M11-10). A seam no owner fills leaves the Harness failing closed where it is
// needed (harness.go).
//
// HarnessComponent is the Harness as one of the Sidecar's components, named harness, Active while it holds an open
// run, so the daemon does not idle out while an agent waits for its inbox (§20.7), with no edit to daemon_idle.go.
// Sidecar.Harness adds it to the Sidecar at first use, as Sidecar.Mail adds mail's.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
)

// The name the Harness's compute component and its Sidecar component take.
const harnessComponentName = "harness"

// The seams a Sidecar's Harness is built on beside the Sidecar's own, each filled by its owner's installer.
type HarnessSources struct {
	Skill        HarnessSkill
	Journal      HarnessContextJournal
	Acks         HarnessDisclosureAcks
	Purchases    HarnessPurchases
	BudgetRaiser HarnessBudgetRaiser
	AutoVerdicts HarnessAutoVerdicts
	Foreground   HarnessForeground
	// SKILL's delivery of a reopened agent's untaken messages (harness_reopen.go).
	Untaken HarnessUntaken
}

// An owner's installer: sets its own sources, reading the Sidecar at use, never while it installs.
type HarnessSourcesInstaller func(sidecar *Sidecar, sources *HarnessSources) error

// One installer.
type harnessSourcesRegistration struct {
	name    string
	install HarnessSourcesInstaller
}

// Every installer, in the order the files' init functions registered them. Written only during the package's init.
var harnessSourcesRegistrations = []*harnessSourcesRegistration{}

// Registers an owner's installer of Harness sources under name, from an init function in its own file. An empty name,
// a nil installer or a name registered twice is a build error, which panics.
func RegisterHarnessSources(name string, install HarnessSourcesInstaller) {
	registered := slices.ContainsFunc(harnessSourcesRegistrations, func(registration *harnessSourcesRegistration) bool {
		return registration.name == name
	})
	if name == "" || install == nil || registered {
		panic(fmt.Sprintf("harness sources %q registered twice or without an installer", name))
	}
	harnessSourcesRegistrations = append(harnessSourcesRegistrations, &harnessSourcesRegistration{name: name, install: install})
}

// The sources each installer filled. An installer that fails, or one that replaces a source another set, leaves its
// sources out, logged, so what it would fill stays failing closed.
func installHarnessSources(sidecar *Sidecar, registrations []*harnessSourcesRegistration) *HarnessSources {
	sources := &HarnessSources{}
	for _, registration := range registrations {
		attempt := *sources
		if err := registration.install(sidecar, &attempt); err != nil {
			sidecar.log.Warningf("[harness]sources %s did not install: %v", registration.name, err)
			continue
		}
		replaced := []string{}
		for _, field := range []struct {
			name  string
			was   any
			isNow any
		}{
			{name: "Skill", was: sources.Skill, isNow: attempt.Skill},
			{name: "Journal", was: sources.Journal, isNow: attempt.Journal},
			{name: "Acks", was: sources.Acks, isNow: attempt.Acks},
			{name: "Purchases", was: sources.Purchases, isNow: attempt.Purchases},
			{name: "BudgetRaiser", was: sources.BudgetRaiser, isNow: attempt.BudgetRaiser},
			{name: "AutoVerdicts", was: sources.AutoVerdicts, isNow: attempt.AutoVerdicts},
			{name: "Foreground", was: sources.Foreground, isNow: attempt.Foreground},
			{name: "Untaken", was: sources.Untaken, isNow: attempt.Untaken},
		} {
			if field.was != nil && field.was != field.isNow {
				replaced = append(replaced, field.name)
			}
		}
		if 0 < len(replaced) {
			sidecar.log.Warningf("[harness]sources %s replaced %s, which another set", registration.name, strings.Join(replaced, ", "))
			continue
		}
		*sources = attempt
	}
	return sources
}

// Registers the Harness's component, which every Sidecar on a compute leg then constructs.
func init() {
	registerComputeComponent(harnessComponentName, newSidecarHarness, func(component *sidecarHarness) {
		component.close()
	})
}

// The router as the Harness reaches it on a Sidecar: the infer component's, read at use.
type harnessSidecarRouter struct {
	sidecar *Sidecar
}

// The infer component's router, or its error.
func (self *harnessSidecarRouter) router() (InferRouter, error) {
	return self.sidecar.InferRouter()
}

// The catalog, through the Sidecar's router.
func (self *harnessSidecarRouter) Catalog(ctx context.Context) (*InferCatalog, error) {
	router, err := self.router()
	if err != nil {
		return nil, err
	}
	return router.Catalog(ctx)
}

// A call, through the Sidecar's router.
func (self *harnessSidecarRouter) Infer(ctx context.Context, request *InferRequest) (<-chan *InferEvent, error) {
	router, err := self.router()
	if err != nil {
		return nil, err
	}
	return router.Infer(ctx, request)
}

// A check, through the Sidecar's router.
func (self *harnessSidecarRouter) Check(ctx context.Context, request *InferRequest) error {
	router, err := self.router()
	if err != nil {
		return err
	}
	return router.Check(ctx, request)
}

// The run store as the Harness reaches it on a Sidecar: Sidecar.Runs, read at use, failing every call before enrollment.
type harnessSidecarRuns struct {
	sidecar *Sidecar
}

// The store, or why there is none.
func (self *harnessSidecarRuns) store() (*RunStore, error) {
	return self.sidecar.Runs()
}

// Create, on the network's store.
func (self *harnessSidecarRuns) Create(ctx context.Context, run *RunFile) error {
	runs, err := self.store()
	if err != nil {
		return err
	}
	return runs.Create(ctx, run)
}

// Get, on the network's store.
func (self *harnessSidecarRuns) Get(runId Id) (*RunFile, error) {
	runs, err := self.store()
	if err != nil {
		return nil, err
	}
	return runs.Get(runId)
}

// Taint, on the network's store.
func (self *harnessSidecarRuns) Taint(ctx context.Context, runId Id, reason RunTaintReason) error {
	runs, err := self.store()
	if err != nil {
		return err
	}
	return runs.Taint(ctx, runId, reason)
}

// Tainted, true where there is no store.
func (self *harnessSidecarRuns) Tainted(runId Id) bool {
	runs, err := self.store()
	if err != nil {
		return true
	}
	return runs.Tainted(runId)
}

// TaintReasons, none where there is no store.
func (self *harnessSidecarRuns) TaintReasons(runId Id) []RunTaintReason {
	runs, err := self.store()
	if err != nil {
		return nil
	}
	return runs.TaintReasons(runId)
}

// Mark, on the network's store.
func (self *harnessSidecarRuns) Mark(ctx context.Context, runId Id, mark string) error {
	runs, err := self.store()
	if err != nil {
		return err
	}
	return runs.Mark(ctx, runId, mark)
}

// AddGap, on the network's store: a gap counted against the run's coverage.
func (self *harnessSidecarRuns) AddGap(ctx context.Context, runId Id, code string) error {
	runs, err := self.store()
	if err != nil {
		return err
	}
	return runs.AddGap(ctx, runId, code)
}

// Marks, unread where there is no store.
func (self *harnessSidecarRuns) Marks(runId Id) ([]string, error) {
	runs, err := self.store()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrRunMarksUnread, err)
	}
	return runs.Marks(runId)
}

// The approvals as the Harness reaches them on a Sidecar: the installed gate's, read at use.
type harnessSidecarApprovals struct {
	sidecar *Sidecar
}

// The installed gate's approvals, or why there are none.
func (self *harnessSidecarApprovals) approvals() (HarnessApprovals, error) {
	return newHarnessGateApprovals(self.sidecar)
}

// The installed gate's update callbacks; with none, a removal that removes nothing.
func (self *harnessSidecarApprovals) AddUpdateCallback(callback ApprovalUpdateFunction) func() {
	approvals, err := self.approvals()
	if err != nil {
		return func() {}
	}
	return approvals.AddUpdateCallback(callback)
}

// The installed gate's status of the approval.
func (self *harnessSidecarApprovals) Status(approvalId Id) (*ApprovalStatus, error) {
	approvals, err := self.approvals()
	if err != nil {
		return nil, err
	}
	return approvals.Status(approvalId)
}

// The installed gate's render of the approval.
func (self *harnessSidecarApprovals) Render(approvalId Id) (*ApprovalRender, error) {
	approvals, err := self.approvals()
	if err != nil {
		return nil, err
	}
	return approvals.Render(approvalId)
}

// The Harness's compute component on a Sidecar.
type sidecarHarness struct {
	sidecar   *Sidecar
	harness   *Harness
	component *HarnessComponent
	addOnce   sync.Once
	addErr    error
}

// The Harness over sidecar's settings, log, router, run store, gate and approvals, and the registered sources.
func newSidecarHarness(sidecar *Sidecar) (*sidecarHarness, error) {
	settings := sidecar.settings.Harness
	if settings == nil {
		settings = DefaultHarnessSettings()
	}
	sources := installHarnessSources(sidecar, harnessSourcesRegistrations)
	var support func() (*SupportClient, error)
	if sidecar.settings.Support != nil && sidecar.settings.Support.ServiceEnabled {
		// the release's support switch (§28.21): off, no agent lists the support tools or their skill
		support = sidecar.Support
	}
	// the session journal's recorder observes the Harness's events (harness_record.go)
	var observer func(agentId Id, event *HarnessEvent)
	observed, hasObserver := sources.Journal.(harnessObservedJournal)
	if hasObserver {
		observer = observed.observe
	}
	harness, err := NewHarness(&HarnessArgs{
		Settings:     settings,
		Log:          sidecar.log,
		Clock:        sidecar.settings.ClockOrReal(),
		Router:       &harnessSidecarRouter{sidecar: sidecar},
		Journal:      sources.Journal,
		Skill:        sources.Skill,
		Runs:         &harnessSidecarRuns{sidecar: sidecar},
		Gate:         sidecar,
		Approvals:    &harnessSidecarApprovals{sidecar: sidecar},
		AutoVerdicts: sources.AutoVerdicts,
		Acks:         sources.Acks,
		Purchases:    sources.Purchases,
		BudgetRaiser: sources.BudgetRaiser,
		Foreground:   sources.Foreground,
		Support:      support,
		Network:      &harnessSidecarNetwork{sidecar: sidecar},
		Observer:     observer,
		OpenRuns: &harnessStoreOpenRuns{store: func() (SidecarStore, error) {
			return sidecar.LocalStore().Directory(harnessComponentName, harnessComponentName)
		}},
		RunReader: &harnessSidecarRunReader{sidecar: sidecar},
		Untaken:   sources.Untaken,
	})
	if err != nil {
		return nil, err
	}
	if hasObserver {
		observed.bind(harness)
	}
	return &sidecarHarness{sidecar: sidecar, harness: harness, component: &HarnessComponent{harness: harness}}, nil
}

// Closes the Harness: every agent's run ends.
func (self *sidecarHarness) close() {
	self.harness.Close()
}

// This Sidecar's Harness, its component added to the Sidecar at first use so an open run keeps the daemon up; an
// error wrapping ErrComputeComponentUnavailable where there is none.
func (self *Sidecar) Harness() (*Harness, error) {
	component, err := sidecarComputeComponent[sidecarHarness](self, harnessComponentName)
	if err != nil {
		return nil, err
	}
	component.addOnce.Do(func() {
		_, component.addErr = self.AddComponent(component.component)
		if component.addErr == nil {
			// the runs a daemon held open when it stopped are taken up again (harness_reopen.go)
			go func() {
				if _, err := component.harness.Reopen(self.ctx); err != nil {
					self.log.Warningf("[harness]runs were not reopened: %v", err)
				}
			}()
		}
	})
	if component.addErr != nil {
		return nil, component.addErr
	}
	return component.harness, nil
}

// The Harness as one of a Sidecar's components (§5.4): it attaches nothing to a client generation, and keeps the
// daemon up while it holds an open run.
type HarnessComponent struct {
	harness *Harness
}

var _ SidecarComponent = (*HarnessComponent)(nil)
var _ SidecarActiveComponent = (*HarnessComponent)(nil)

// harness.
func (self *HarnessComponent) Name() string {
	return harnessComponentName
}

// Attaches nothing: the Harness reaches the network through its tools' own clients.
func (self *HarnessComponent) Attach(env *SidecarEnv) error {
	return nil
}

// Nothing to end here: the compute component closes the Harness with the Sidecar.
func (self *HarnessComponent) Close() {
}

// Whether the Harness holds an open run.
func (self *HarnessComponent) Active() bool {
	return self.harness.Active()
}
