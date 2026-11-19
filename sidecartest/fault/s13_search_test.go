//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// S13's search_agents step, from M10 (§22.4's S13, F13; FS-84 to FS-88; owner decisions 169, 171 and 181;
// RECORD-M10-06), on real engines: the directory world on evs at format 2 (fs_directory_evs.go), each daemon's runs
// riding its card through the run writer, and B's device searching the cards ref's index (sidecar's
// directory_search_testhooks.go) behind its folded view. The scenario's other steps, its requests, approvals, grants
// and removal, stay at M6's in sidecartest's s13_test.go, on that package's fakes; this package holds the step
// because the evs world is here.
//
//	find      B's agent finds member A's run within one sync by search_agents, grouped by A's agent on A's sidecar,
//	          its title withheld from B's agent and B's run untainted: the taint is never asked for. The run, in an
//	          announced general repo, shows its project and branch; A's run in a repo nothing announced shows neither
//	own       B's own run comes back the same way, a stub under its own agent and sidecar: the directory's prose is
//	          withheld whoever wrote it
//	revoked   P's admin revokes its announcement, A's daemon reads the marker and its next sync writes the run
//	          private, and a directory admin's erasure runner runs: B's next sync and search find the run with no
//	          project, and no card or index file B's device reads holds the repo's name or the project
//
// Not here: search_agents through the MCP tool and its session (mcp/session_search.go), and the search sync's adapter
// over EvsRepo, which no composition has yet: the hook answers each round by listing.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

const (
	s13SearchAdmin  = "daemonD"
	s13SearchOwner  = "ownerR"
	s13SearchA      = "daemonA"
	s13SearchB      = "daemonB"
	s13SearchRepo   = "P"
	s13SearchHidden = "Q"
	// what no readable copy may hold once the erasure ran: the repo's name and the project A's run named in it
	s13SearchRepoTitle = "pricing notes"
	s13SearchProject   = "example.org/team/pricing-notes"
	s13SearchRunTitle  = "draft the rollout checklist"
	s13SearchHiddenRun = "tune the importer"
	s13SearchOwnTitle  = "wire the limiter"
)

// S13's search_agents step: see the file header.
func s13SearchAgents(net *Net) *Schedule {
	devices := []string{s13SearchAdmin, s13SearchOwner, s13SearchA, s13SearchB}
	world := NewDirEvsWorld(net, &DirEvsWorldSettings{
		Devices:    []*DirEvsDeviceSettings{{Name: s13SearchAdmin, Admin: true}, {Name: s13SearchOwner}, {Name: s13SearchA}, {Name: s13SearchB}},
		RepoAdmins: map[string][]string{s13SearchRepo: {s13SearchOwner}, s13SearchHidden: {s13SearchOwner}},
	})
	var search *sidecar.SearchTestEvsDevice
	var revocation *sidecar.DirectoryRevocation
	startDelay := sidecar.DefaultDirectoryRunsSettings().StartDelay
	// B's one sync: its directory copy and its index
	sync := func(ctx context.Context) error {
		if err := world.Device(s13SearchB).Client.Sync(ctx); err != nil {
			return err
		}
		return search.Sync(ctx)
	}
	steps := []*Step{
		{Actor: s13SearchAdmin, Action: world.Setup},
		{Actor: s13SearchAdmin, Action: world.InstallIndexWriters(devices...)},
		{Actor: s13SearchOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(s13SearchOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			_, err := owner.Client.AnnounceRepo(ctx, &sidecar.DirectoryRepoAnnounceArgs{RepoId: world.Repo(s13SearchRepo), DisplayName: s13SearchRepoTitle, Confirmed: true})
			return err
		}},
		{Actor: s13SearchA, Action: func(ctx context.Context, net *Net) error {
			a := world.Device(s13SearchA)
			if err := a.Client.Sync(ctx); err != nil {
				return err
			}
			repoId, hiddenId := world.Repo(s13SearchRepo), world.Repo(s13SearchHidden)
			for _, start := range []*sidecar.DirectoryRunStart{
				{
					RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "pricing", AgentLabel: "planner", Harness: "codex",
					Title: s13SearchRunTitle + "\nand then everything else in the prompt", RepoId: &repoId, Project: s13SearchProject, Branch: "main",
				},
				{
					RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "importer", AgentLabel: "tuner", Harness: "codex",
					Title: s13SearchHiddenRun, RepoId: &hiddenId, Project: "example.org/team/importer", Branch: "tuning",
				},
			} {
				if err := a.Client.Runs().Started(start); err != nil {
					return err
				}
			}
			net.Clock().Advance(startDelay)
			return nil
		}},
		{Actor: s13SearchB, Action: func(ctx context.Context, net *Net) error {
			b := world.Device(s13SearchB)
			if err := b.Client.Sync(ctx); err != nil {
				return err
			}
			err := b.Client.Runs().Started(&sidecar.DirectoryRunStart{
				RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "app", AgentLabel: "wirer", Harness: "claude-code",
				Title: s13SearchOwnTitle, Project: "example.org/team/app", Branch: "main",
			})
			if err != nil {
				return err
			}
			net.Clock().Advance(startDelay)
			host := searchHostNamed("desktop")
			search, err = world.SearchDevice(ctx, s13SearchB, host.settings(), host.conditions)
			return err
		}},
		{Actor: s13SearchB, Action: func(ctx context.Context, net *Net) error {
			// within one sync
			if err := sync(ctx); err != nil {
				return err
			}
			a := world.Device(s13SearchA)
			taint := &dirEvsSearchTaint{}
			result, err := dirEvsSearchAgents(ctx, world, search, s13SearchB, "rollout checklist", false, taint)
			if err != nil {
				return fmt.Errorf("search_agents: %w", err)
			}
			if len(result.Groups) != 1 || taint.count != 0 || result.Untrusted || result.UntrustedWithheld == 0 {
				return fmt.Errorf("A's run: %d groups, %d taints, untrusted %v, %d withheld", len(result.Groups), taint.count, result.Untrusted, result.UntrustedWithheld)
			}
			group := result.Groups[0]
			if group.AgentLabel != "planner" || group.SidecarId == nil || *group.SidecarId != a.SidecarId ||
				group.MemberId == nil || *group.MemberId != a.MemberId || !group.Stub || !group.Active || len(group.Runs) != 1 {
				return fmt.Errorf("A's run's group: %+v", group)
			}
			shown := dirEvsSearchShown(result)
			if strings.Contains(shown, "rollout") || strings.Contains(shown, "prompt") {
				return fmt.Errorf("A's run's title reached B's agent: %q", shown)
			}
			if !strings.Contains(shown, s13SearchProject) || !strings.Contains(shown, "main") {
				return fmt.Errorf("a run in an announced general repo shows no project and branch: %q", shown)
			}
			// a run in a repo nothing announced: private, neither project nor branch
			result, err = dirEvsSearchAgents(ctx, world, search, s13SearchB, "", false, taint)
			if err != nil {
				return fmt.Errorf("search_agents with no task: %w", err)
			}
			labels := map[string]bool{}
			for _, group := range result.Groups {
				labels[group.AgentLabel] = true
			}
			if len(result.Groups) != 3 || !labels["planner"] || !labels["tuner"] || !labels["wirer"] || taint.count != 0 {
				return fmt.Errorf("the agents active: %v, %d taints", labels, taint.count)
			}
			if shown := dirEvsSearchShown(result); strings.Contains(shown, "example.org/team/importer") || strings.Contains(shown, "tuning") {
				return fmt.Errorf("a run in a repo nothing announced shows where it works: %q", shown)
			}
			// B's own run reads the same way: the directory's prose is a stub's whoever wrote it
			result, err = dirEvsSearchAgents(ctx, world, search, s13SearchB, "limiter", false, taint)
			if err != nil {
				return fmt.Errorf("search_agents for B's own run: %w", err)
			}
			b := world.Device(s13SearchB)
			if len(result.Groups) != 1 || result.Groups[0].AgentLabel != "wirer" || result.Groups[0].SidecarId == nil ||
				*result.Groups[0].SidecarId != b.SidecarId || !result.Groups[0].Stub || taint.count != 0 ||
				strings.Contains(dirEvsSearchShown(result), "limiter") {
				return fmt.Errorf("B's own run: %d groups, %d taints, %q", len(result.Groups), taint.count, dirEvsSearchShown(result))
			}
			return nil
		}},

		// a revoked announcement leaves no readable copy of the name
		{Actor: s13SearchOwner, Action: func(ctx context.Context, net *Net) error {
			owner := world.Device(s13SearchOwner)
			if err := owner.Client.Sync(ctx); err != nil {
				return err
			}
			var err error
			if revocation, err = owner.Client.RevokeRepo(ctx, &sidecar.DirectoryRevokeArgs{RepoId: world.Repo(s13SearchRepo), Confirmed: true}); err != nil {
				return fmt.Errorf("the revocation: %w", err)
			}
			return owner.Record.Flush(ctx)
		}},
		// past a card's write interval
		{Advance: DefaultFs99CardsSettings().WriteSpacing},
		{Actor: s13SearchA, Action: func(ctx context.Context, net *Net) error {
			// A's daemon reads the marker, and its runs' where follows
			a := world.Device(s13SearchA)
			if err := a.Client.Sync(ctx); err != nil {
				return err
			}
			return a.Client.Runs().Reconcile()
		}},
		{Actor: s13SearchAdmin, Action: func(ctx context.Context, net *Net) error {
			pass, err := world.Pass(ctx, s13SearchAdmin)
			if err != nil {
				return fmt.Errorf("the erasure runner's pass: %w", err)
			}
			if files := pass.Files[revocation.RequestId]; files == nil || len(files.ClosedPaths) != 2 || len(files.WaitingPaths) != 0 {
				return fmt.Errorf("the erasure runner's pass: %+v, files %+v", pass, files)
			}
			return nil
		}},
		{Actor: s13SearchB, Action: func(ctx context.Context, net *Net) error {
			defer search.Close()
			if err := sync(ctx); err != nil {
				return err
			}
			b := world.Device(s13SearchB)
			if alarms := b.Alarms(); len(alarms) != 0 {
				return fmt.Errorf("B alarmed: %v", alarms)
			}
			taint := &dirEvsSearchTaint{}
			result, err := dirEvsSearchAgents(ctx, world, search, s13SearchB, "rollout checklist", true, taint)
			if err != nil {
				return fmt.Errorf("search_agents after the revocation: %w", err)
			}
			if len(result.Groups) != 1 || result.Groups[0].AgentLabel != "planner" || taint.count != 1 {
				return fmt.Errorf("A's run after the revocation: %d groups, %d taints", len(result.Groups), taint.count)
			}
			if shown := dirEvsSearchShown(result); strings.Contains(shown, "pricing") {
				return fmt.Errorf("A's run still shows the revoked repo: %q", shown)
			}
			for _, task := range []string{"pricing notes", "pricing-notes"} {
				result, err := dirEvsSearchAgents(ctx, world, search, s13SearchB, task, true, taint)
				if err != nil {
					return fmt.Errorf("search_agents for %q: %w", task, err)
				}
				if len(result.Groups) != 0 {
					return fmt.Errorf("search_agents for %q found %q", task, dirEvsSearchShown(result))
				}
			}
			// no card or index file B's device reads holds the name
			contents := map[string][]byte{}
			for _, file := range b.Client.Cards() {
				contents[fmt.Sprintf("%s version %d", file.Path, file.Version)] = file.Content
			}
			indexFiles, err := world.CardsIndexFiles(ctx, s13SearchB)
			if err != nil {
				return err
			}
			for path, plaintext := range indexFiles {
				contents[path] = plaintext
			}
			if len(indexFiles) == 0 {
				return errors.New("the cards ref holds no index file")
			}
			for name, content := range contents {
				for _, text := range []string{s13SearchRepoTitle, s13SearchProject} {
					if bytes.Contains(content, []byte(text)) {
						return fmt.Errorf("%q is readable in %s", text, name)
					}
				}
			}
			return nil
		}},
	}
	return &Schedule{Id: "S13's search_agents", Steps: steps, Tiers: []Tier{TierT2}}
}

func TestS13SearchAgents(t *testing.T) {
	ctx := t.Context()
	net := sidecartest.NewNet(ctx, nil)
	defer net.Close()
	if result := Run(ctx, s13SearchAgents(net), net); result.Err != nil {
		t.Fatal(result.Err)
	}
}
