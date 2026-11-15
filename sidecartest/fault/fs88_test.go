//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-88's M6 case on T2 (§22.8; §16.11's Taint block, D-MCP-29, I-9, I-20, FI-21; RECORD-M6-26), in the directory world
// (fs85_test.go), and §22.7's directory privacy row at M6:
//
//	stubs      directory_list's answer, DirectoryStubOf over the folded items, returns a member's run with its title
//	           withheld and counted, the identifiers of an untainted member run at member trust and those of a tainted
//	           run withheld as untrusted; include returns the title among the untrusted fields
//	canaries   a run whose prompt carries canaries past its first line announces the first line alone: no canary is in
//	           any announce entry, request entry or notice the directory holds (I-20), and a private repo's name never
//	           appears there
//	claims     a run under claims off announces nothing, and the member's project opt-out (SetRuns off) withdraws a
//	           running item at once
//
// After every step, FI-26 as the directory world holds it. Not here: the MCP tools' taint fsync and its failure
// (mcp/tools_directory_test.go, RECORD-M6-22), ur directory ls on a non-terminal (cli/directory_cmd_test.go,
// RECORD-M6-23), .ur's narrowing and widening (CORE-M6-02's daemon claims tests), FI-21 itself (TEST-M10-02's oracle),
// and the search_agents cases at the later of M6-out and M10-out.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs88M6 = Register("FS-88", "", []Tier{TierT2}, Fs88TaintAndPrivacy)

// The canaries a run's private inputs carry, none of which may reach the directory.
var fs88Canaries = []string{"CANARY-PROMPT-1d9e", "CANARY-TOOL-INPUT-77a0", "CANARY-TOOL-OUTPUT-3b21", "CANARY-PATH-c4f8", "CANARY-DIFF-905e", "CANARY-PRIVATE-REPO-6e2d"}

// A canary in a run's title, its first line: in sealed entries only, never in the clear at evs.
const fs88TitleCanary = "CANARY-TITLE-a47c"

// Whether the title canary shows in the clear in any stored entry or file at evs, and in the plaintext a reader opens.
func (self *dirWorld) titleCanary(ctx context.Context) (clear bool, opened bool, err error) {
	streams := self.streams.For(self.admin.sidecarId)
	heads, err := streams.Streams(ctx, self.directoryId)
	if err != nil {
		return false, false, err
	}
	for _, head := range heads {
		versions, err := streams.ReadStream(ctx, self.directoryId, head.SidecarId, 0)
		if err != nil {
			return false, false, err
		}
		for _, version := range versions {
			for _, entry := range version.Entries {
				clear = clear || bytes.Contains(entry.Entry, []byte(fs88TitleCanary))
			}
		}
	}
	reader := self.admin.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		return false, false, err
	}
	entries, _ := reader.EntriesOfKinds(self.directoryId, 0, sidecar.RecordKindAnnounce)
	for _, entry := range entries {
		opened = opened || bytes.Contains(entry.Body, []byte(fs88TitleCanary))
	}
	return clear, opened, nil
}

// Whether any file or entry the directory holds at evs carries one of the canaries.
func (self *dirWorld) canaryAnywhere(ctx context.Context) (string, error) {
	reader := self.admin.record.Reader()
	if err := reader.Sync(ctx, self.directoryId); err != nil {
		return "", err
	}
	entries, _ := reader.EntriesOfKinds(self.directoryId, 0)
	contents := [][]byte{}
	for _, entry := range entries {
		contents = append(contents, entry.Body)
	}
	for _, file := range self.admin.client.Cards() {
		contents = append(contents, file.Content)
	}
	for _, content := range contents {
		for _, canary := range fs88Canaries {
			if bytes.Contains(content, []byte(canary)) {
				return canary, nil
			}
		}
	}
	return "", nil
}

// FS-88's M6 case: see the file header.
func Fs88TaintAndPrivacy(net *Net) *Schedule {
	state := &dirState{}
	member := &dirDevice{}
	cleanRun, taintedRun, optedRun := sidecar.NewId(), sidecar.NewId(), sidecar.NewId()
	return dirSchedule(state, "FI-26/taint", []*Step{
		dirStep(state, "daemonM", func(ctx context.Context, world *dirWorld) error {
			var err error
			if member, err = world.device("member M", sidecar.NewId(), false); err != nil {
				return err
			}
			member.runs = map[sidecar.Id]bool{cleanRun: false, taintedRun: true, optedRun: false}
			world.publish()
			if err := world.open(member); err != nil {
				return err
			}
			if err := member.client.Sync(ctx); err != nil {
				return err
			}
			starts := []*sidecar.DirectoryRunStart{
				{
					RunId: cleanRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "app", AgentLabel: "builder", Harness: "codex",
					Title:   "fix the retry path\n" + fs88Canaries[0] + " and read " + fs88Canaries[3],
					Project: "example.org/team/app", Branch: "main",
				},
				{
					RunId: taintedRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "app", AgentLabel: "reviewer", Harness: "claude-code",
					Title: "review the loader " + fs88TitleCanary, Project: "example.org/team/app", Branch: "review",
				},
				{
					RunId: sidecar.NewId(), Claims: sidecar.DirectoryRunClaimsOff, ProjectKey: "quiet", AgentLabel: "quiet", Harness: "cursor",
					Title: "announce nothing", Project: "example.org/team/quiet", Branch: "main",
				},
				{
					RunId: optedRun, Claims: sidecar.DirectoryRunClaimsAuto, ProjectKey: "opted", AgentLabel: "opted", Harness: "codex",
					Title: "opted out later", Project: "example.org/team/opted", Branch: "main",
				},
			}
			for _, start := range starts {
				if err := member.client.Runs().Started(start); err != nil {
					return err
				}
			}
			world.clock.Advance(10 * time.Second)
			return member.record.Flush(ctx)
		}),
		dirStep(state, "daemonR", func(ctx context.Context, world *dirWorld) error {
			// a request to a repo nothing announced carries its id, never a name
			return world.file(ctx, "private", world.requester, &protocol.RequestTarget{RepoId: world.repoId.Bytes()}, protocol.RepoGrantRole_REPO_GRANT_ROLE_READER, 0)
		}),
		dirStep(state, "agentR", func(ctx context.Context, world *dirWorld) error {
			if err := world.requester.client.Sync(ctx); err != nil {
				return err
			}
			items, err := world.requester.client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
			if err != nil {
				return err
			}
			labels := map[string]*sidecar.DirectoryStub{}
			for _, item := range items {
				stub, err := sidecar.DirectoryStubOf(item, false)
				if err != nil {
					return err
				}
				if item.Announcement.GetWho().GetAgentLabel() == "quiet" {
					return errors.New("a run under claims off was announced")
				}
				labels[item.Announcement.GetWho().GetAgentLabel()] = stub
			}
			clean, tainted := labels["builder"], labels["reviewer"]
			if clean == nil || tainted == nil {
				return fmt.Errorf("the stubs shown: %v", labels)
			}
			if 0 < len(clean.Untrusted) || clean.UntrustedWithheld == 0 || clean.IdentifierTrust != sidecar.DirectoryStubTrustMember {
				return fmt.Errorf("the untainted run's stub: %+v", clean)
			}
			if tainted.IdentifierTrust != sidecar.DirectoryStubTrustUntrusted || 0 < len(tainted.Identifiers) {
				return fmt.Errorf("the tainted run's stub: %+v", tainted)
			}
			// include, which the tool sends only after the run's taint is fsynced, returns the title as untrusted
			for _, item := range items {
				if item.Announcement.GetWho().GetAgentLabel() != "builder" {
					continue
				}
				included, err := sidecar.DirectoryStubOf(item, true)
				if err != nil {
					return err
				}
				if title := included.Untrusted["what.title"]; title != "fix the retry path" {
					return fmt.Errorf("the included title %q", title)
				}
			}
			return nil
		}),
		dirStep(state, "judge", func(ctx context.Context, world *dirWorld) error {
			canary, err := world.canaryAnywhere(ctx)
			if err != nil {
				return err
			}
			if canary != "" {
				return fmt.Errorf("%s reached the directory", canary)
			}
			clear, opened, err := world.titleCanary(ctx)
			if err != nil {
				return err
			}
			if clear || !opened {
				return fmt.Errorf("the title canary in the clear %v, opened by a reader %v", clear, opened)
			}
			return nil
		}),
		dirStep(state, "daemonM", func(ctx context.Context, world *dirWorld) error {
			// the member's project opt-out withdraws its running item at once, whatever keeps the value
			if err := member.client.SetRuns(ctx, "opted", sidecar.DirectoryRunClaimsOff); err != nil && !errors.Is(err, sidecar.ErrDirectoryRunsConfigUnavailable) {
				return err
			}
			if err := member.record.Flush(ctx); err != nil {
				return err
			}
			if err := world.requester.client.Sync(ctx); err != nil {
				return err
			}
			items, err := world.requester.client.List(&sidecar.DirectoryFilter{Kind: sidecar.DirectoryAnnouncementKindRun})
			if err != nil {
				return err
			}
			for _, item := range items {
				if item.Announcement.GetWho().GetAgentLabel() == "opted" {
					return errors.New("an opted-out project's run still shows")
				}
			}
			return nil
		}),
	})
}

func TestFs88M6(t *testing.T) {
	RunRow(t, "FS-88", "", nil)
}
