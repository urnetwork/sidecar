//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-88's searches case on T2 (§22.8; §16.11's Taint block and tools row, §16.10's stubs, D-MCP-16, D-MCP-29, I-9, I-20,
// FI-21; RECORD-M10-06), at the later of M6-out and M10-out, on real engines: the directory world on evs
// (fs_directory_evs.go) at format 2, where a daemon's runs ride its card and each card push carries its index entries,
// and a search device following the cards ref's index through its reader's evs client (sidecar's
// directory_search_testhooks.go). It extends RECORD-M6-26's case (fs88_test.go), whose canaries and starts it uses.
//
//	stubs      search_agents (SearchEngine.Agents behind the directory's folded view) answers a member's run with
//	           its title withheld and counted, the calling run's taint never asked for; the identifiers of an
//	           untainted member's run show, and those of a run written tainted come back withheld
//	include    include asks for the taint first and then returns the title; a taint that fails, as a failed fsync
//	           does, fails the call with nothing returned
//	canaries   a run whose prompt carries canaries past its first line announces the first line alone: no canary is
//	           in any card, stream entry or index file the directory holds (I-20), a search for one finds nothing,
//	           and a run under claims off is in none of them
//
// Not here: the MCP tool's own fsync of the run's taint file and ur directory ls (mcp/tools_directory_test.go,
// cli/directory_cmd_test.go), .ur's narrowing and widening, FI-21 through TEST-M10-02's oracle, whose ledger this
// world does not feed, and the search sync's adapter over EvsRepo, which no composition has yet: the hook answers
// each round by listing.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
)

var Fs88Searches = Register("FS-88", "searches", []Tier{TierT2}, Fs88SearchAgents)

const (
	fs88SearchAdmin  = "daemonD"
	fs88SearchMember = "daemonM"
	fs88SearchReader = "agentR"
	// the first lines of the member's runs, which alone are announced
	fs88SearchCleanTitle   = "fix the retry path"
	fs88SearchTaintedTitle = "review the loader"
	fs88SearchQuietTitle   = "announce nothing"
)

// One search_agents call's taint: how often it was asked for, and what asking answers.
type dirEvsSearchTaint struct {
	count int
	err   error
}

// search_agents as device's agent calls it: task over the directory through search, a search device synced now,
// behind device's folded view.
func dirEvsSearchAgents(ctx context.Context, world *DirEvsWorld, search *sidecar.SearchTestEvsDevice, device string, task string, include bool, taint *dirEvsSearchTaint) (*sidecar.SearchAgentsResult, error) {
	return search.Engine().Agents(ctx, sidecar.NewId(), world.NetworkId, &sidecar.SearchAgentsRequest{
		Task: task, Include: include, Reader: world.SearchReader(device), Fold: world.Device(device).Client.SearchAgentsFold,
		Taint: func(ctx context.Context) error {
			taint.count += 1
			return taint.err
		},
	})
}

// Every text a search_agents answer shows.
func dirEvsSearchShown(result *sidecar.SearchAgentsResult) string {
	text := &strings.Builder{}
	for _, group := range result.Groups {
		text.WriteString(group.AgentLabel + " ")
		for _, run := range group.Runs {
			text.WriteString(run.Title + " ")
		}
		for _, hit := range group.Top {
			text.WriteString(hit.Path + " " + hit.Snippet + " " + hit.Correction + " ")
			for _, field := range hit.Fields {
				text.WriteString(field.Text + " ")
			}
		}
	}
	return text.String()
}

// FS-88's searches case: see the file header.
func Fs88SearchAgents(net *Net) *Schedule {
	devices := []string{fs88SearchAdmin, fs88SearchMember, fs88SearchReader}
	world := NewDirEvsWorld(net, &DirEvsWorldSettings{
		Devices: []*DirEvsDeviceSettings{{Name: fs88SearchAdmin, Admin: true}, {Name: fs88SearchMember}, {Name: fs88SearchReader}},
	})
	cleanRun, taintedRun, quietRun := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	// every text the directory's files must not hold
	absent := append([]string{fs88TitleCanary, fs88SearchQuietTitle}, fs88Canaries...)
	steps := []*Step{
		{Actor: fs88SearchAdmin, Action: world.Setup},
		{Actor: fs88SearchAdmin, Action: world.InstallIndexWriters(devices...)},
		{Actor: fs88SearchMember, Action: func(ctx context.Context, net *Net) error {
			member := world.Device(fs88SearchMember)
			if err := member.Client.Sync(ctx); err != nil {
				return err
			}
			member.TaintRun(taintedRun)
			starts := []*sidecar.DirectoryRunStart{
				{
					RunId: cleanRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "app", AgentLabel: "builder", Harness: "codex",
					Title:   fs88SearchCleanTitle + "\n" + fs88Canaries[0] + " and read " + fs88Canaries[3] + "\n" + strings.Join(fs88Canaries, " "),
					Project: "example.org/team/app", Branch: "main",
				},
				{
					RunId: taintedRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "app", AgentLabel: "reviewer", Harness: "claude-code",
					Title: fs88SearchTaintedTitle + "\n" + fs88TitleCanary, Project: "example.org/team/app", Branch: "review",
				},
				{
					RunId: quietRun, Claims: sidecar.DirectoryRunClaimsOff, ProjectKey: "quiet", AgentLabel: "quiet", Harness: "cursor",
					Title: fs88SearchQuietTitle, Project: "example.org/team/quiet", Branch: "main",
				},
			}
			for _, start := range starts {
				if err := member.Client.Runs().Started(start); err != nil {
					return err
				}
			}
			// the start delay, each due run's item joining the daemon's card as it passes
			net.Clock().Advance(sidecar.DefaultDirectoryRunsSettings().StartDelay)
			if err := member.Client.Sync(ctx); err != nil {
				return err
			}
			items, err := member.Client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
			if err != nil || len(items) != 2 {
				return fmt.Errorf("the member's card shows %d runs: %v", len(items), err)
			}
			return nil
		}},
		{Actor: fs88SearchReader, Action: func(ctx context.Context, net *Net) error {
			reader := world.Device(fs88SearchReader)
			if err := reader.Client.Sync(ctx); err != nil {
				return err
			}
			host := searchHostNamed("desktop")
			search, err := world.SearchDevice(ctx, fs88SearchReader, host.settings(), host.conditions)
			if err != nil {
				return err
			}
			defer search.Close()
			if err := search.Sync(ctx); err != nil {
				return fmt.Errorf("the reader's index sync: %w", err)
			}
			member := world.Device(fs88SearchMember)

			// a member's run: a stub, its title withheld and counted, its identifiers shown, no taint asked for
			taint := &dirEvsSearchTaint{}
			result, err := dirEvsSearchAgents(ctx, world, search, fs88SearchReader, "retry path", false, taint)
			if err != nil {
				return fmt.Errorf("search_agents: %w", err)
			}
			if len(result.Groups) != 1 || !result.Groups[0].Stub || result.UntrustedWithheld == 0 || result.Untrusted || taint.count != 0 {
				return fmt.Errorf("a member's run: %d groups, %d withheld, untrusted %v, %d taints", len(result.Groups), result.UntrustedWithheld, result.Untrusted, taint.count)
			}
			group := result.Groups[0]
			if group.AgentLabel != "builder" || group.SidecarId == nil || *group.SidecarId != member.SidecarId ||
				group.MemberId == nil || *group.MemberId != member.MemberId || !group.Active {
				return fmt.Errorf("the untainted run's group: %+v", group)
			}
			if shown := dirEvsSearchShown(result); strings.Contains(shown, "retry") {
				return fmt.Errorf("a stub showed the run's title: %q", shown)
			}

			// a run written tainted: its identifiers come back withheld too
			result, err = dirEvsSearchAgents(ctx, world, search, fs88SearchReader, "loader", false, taint)
			if err != nil {
				return fmt.Errorf("search_agents for the tainted run: %w", err)
			}
			if len(result.Groups) != 1 || !result.Groups[0].Stub || result.Untrusted || taint.count != 0 {
				return fmt.Errorf("the tainted run: %d groups, untrusted %v, %d taints", len(result.Groups), result.Untrusted, taint.count)
			}
			if shown := dirEvsSearchShown(result); strings.Contains(shown, "reviewer") || strings.Contains(shown, "loader") || strings.Contains(shown, "review") {
				return fmt.Errorf("a tainted run's stub showed its identifiers: %q", shown)
			}

			// include: the taint first, then the title
			result, err = dirEvsSearchAgents(ctx, world, search, fs88SearchReader, "retry path", true, taint)
			if err != nil {
				return fmt.Errorf("search_agents with include: %w", err)
			}
			if taint.count != 1 || !result.Untrusted || result.UntrustedWithheld != 0 || result.Trust != sidecar.SearchTrustUntrusted {
				return fmt.Errorf("include: %d taints, untrusted %v, %d withheld, trust %v", taint.count, result.Untrusted, result.UntrustedWithheld, result.Trust)
			}
			if shown := dirEvsSearchShown(result); !strings.Contains(shown, fs88SearchCleanTitle) {
				return fmt.Errorf("include returned no title: %q", shown)
			}
			// a taint that fails returns nothing
			failing := &dirEvsSearchTaint{err: errors.New("the run file is read-only")}
			if result, err := dirEvsSearchAgents(ctx, world, search, fs88SearchReader, "retry path", true, failing); err == nil || result != nil || failing.count != 1 {
				return fmt.Errorf("a failing taint: %+v %v, %d taints", result, err, failing.count)
			}

			// nothing answers a search for what was never announced
			for _, task := range append([]string{"announce nothing", "quiet"}, fs88Canaries...) {
				result, err := dirEvsSearchAgents(ctx, world, search, fs88SearchReader, task, true, &dirEvsSearchTaint{})
				if err != nil {
					return fmt.Errorf("search_agents for %q: %w", task, err)
				}
				if len(result.Groups) != 0 {
					return fmt.Errorf("search_agents for %q found %d groups: %q", task, len(result.Groups), dirEvsSearchShown(result))
				}
			}
			return nil
		}},
		{Actor: "judge", Action: func(ctx context.Context, net *Net) error {
			// no canary, and nothing of the run under claims off, in any card, stream entry or index file
			admin := world.Device(fs88SearchAdmin)
			if err := admin.Client.Sync(ctx); err != nil {
				return err
			}
			contents := map[string][]byte{}
			for _, file := range admin.Client.Cards() {
				contents[fmt.Sprintf("card %s version %d", file.Path, file.Version)] = file.Content
			}
			titled := false
			for _, content := range contents {
				titled = titled || bytes.Contains(content, []byte(fs88SearchCleanTitle))
			}
			if !titled {
				return errors.New("no card read holds the announced title: the scan reads nothing")
			}
			indexFiles, err := world.CardsIndexFiles(ctx, fs88SearchAdmin)
			if err != nil {
				return err
			}
			if len(indexFiles) == 0 {
				return errors.New("the cards ref holds no index file")
			}
			for path, plaintext := range indexFiles {
				contents["index file "+path] = plaintext
			}
			reader := admin.Record.Reader()
			if err := reader.Sync(ctx, world.DirectoryId); err != nil {
				return err
			}
			entries, _ := reader.EntriesOfKinds(world.DirectoryId, 0)
			for index, entry := range entries {
				contents[fmt.Sprintf("entry %d", index)] = entry.Body
			}
			for name, content := range contents {
				for _, text := range absent {
					if bytes.Contains(content, []byte(text)) {
						return fmt.Errorf("%q reached the directory in %s", text, name)
					}
				}
			}
			return nil
		}},
	}
	return &Schedule{Id: "FS-88", Steps: steps, Tiers: []Tier{TierT2}}
}

func TestFs88Searches(t *testing.T) {
	RunRow(t, "FS-88", "searches", nil)
}
