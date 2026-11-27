//go:build !js && !ios && !android && !sdk_mobile_bind && !ios_extension && !sidecar_http

// The Harness's guard is MCP's table, row for row (HARN-M11-06; DESIGN §16.6, DESIGN-COMPUTE §7.5, §20.4): one corpus
// of targets through both, on the desktop legs where mcp/ links. The corpus is every target kind, every repo kind the
// protocol names and one it does not, every operation and two outside them, both refs, the paths each row reads, the
// three booleans, every signed type, every record kind up to past the registry, and every directory act: a row MCP adds
// later refuses some target of it that the Harness admits, and this test fails until the Harness has the row. Each MCP
// refusal is matched to the Harness's row by its text, so a refusal MCP words anew fails too, until the map is told.

package sidecar_test

import (
	"fmt"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// MCP's refusals by text, and the Harness row each is.
var harnessParityMcpRows = map[string]string{
	"MCP never reaches a secret repo": "secret",
	"MCP never reads or writes the config repo: use team_members, team_agents, acl_grants and acl_check":                    "config",
	"MCP never reads or writes the search index's files: use the search tools":                                              "index",
	"MCP never reads or writes the team directory through evs: use the directory tools":                                     "directory",
	"MCP never writes a repo of this kind":                                                                                  "writes",
	"MCP never writes the vault's harness config: run ur install-harness in your own terminal":                              "harness config",
	"MCP never reaches a mailbox's vault entries":                                                                           "mailbox vault",
	"MCP never reaches approved-recipient records":                                                                          "recipients",
	"an agents' inbox takes messages only: use agent_send, agent_broadcast and agent_close":                                 "agents' inbox",
	"MCP never reaches a repo this network does not hold":                                                                   "unheld repo",
	"MCP signs no authority, acl, bridge or approval statement but this sidecar's own filings: use ur in your own terminal": "statements",
	"record_append takes claim, handoff, ask, answer, check and note only":                                                  "record",
	"the directory's decisions, announcements and erasures are a person's, outside MCP":                                     "directory acts",
	"MCP never drops a version or cancels a drop: a person drops from a device":                                             "drop",
	"the tool touches something the guard does not judge":                                                                   "unjudged",
	"the tool reaches a repo in a way the guard does not judge":                                                             "unjudged operation",
}

// One corpus target, as each guard takes it.
type harnessParityCase struct {
	mcpTarget     mcp.McpTarget
	harnessTarget sidecar.HarnessGuardTestTarget
}

// The corpus: see the file header.
func harnessParityCorpus() []*harnessParityCase {
	kinds := []struct {
		mcp     mcp.McpTargetKind
		harness int
	}{
		{0, 0},
		{mcp.McpTargetRepo, sidecar.HarnessGuardTestTargetRepo},
		{mcp.McpTargetStatement, sidecar.HarnessGuardTestTargetStatement},
		{mcp.McpTargetRecordAppend, sidecar.HarnessGuardTestTargetRecordAppend},
		{mcp.McpTargetDirectoryAct, sidecar.HarnessGuardTestTargetDirectoryAct},
		{mcp.McpTargetDrop, sidecar.HarnessGuardTestTargetDrop},
		{99, 99},
	}
	operations := []struct {
		mcp     mcp.McpRepoOperation
		harness int
	}{
		{0, 0},
		{mcp.McpRepoName, sidecar.HarnessGuardTestRepoName},
		{mcp.McpRepoList, sidecar.HarnessGuardTestRepoList},
		{mcp.McpRepoRead, sidecar.HarnessGuardTestRepoRead},
		{mcp.McpRepoWrite, sidecar.HarnessGuardTestRepoWrite},
		{mcp.McpRepoDelete, sidecar.HarnessGuardTestRepoDelete},
		{mcp.McpRepoSearch, sidecar.HarnessGuardTestRepoSearch},
		{77, 77},
	}
	repoKinds := []protocol.RepoKind{}
	for value := range protocol.RepoKind_name {
		repoKinds = append(repoKinds, protocol.RepoKind(value))
	}
	slices.Sort(repoKinds)
	repoKinds = append(repoKinds, protocol.RepoKind(slices.Max(repoKinds)+1))
	refs := []string{"main", "ur/index", "feature"}
	paths := []string{
		"", "a", "a/b.txt", ".ur-index", ".ur-index/x", "x/.ur-index/y",
		"harness", "harness/", "harness/claude.json", "x/harness/y",
		"vault", "vault/ab", "vault/ab/entry", "vaults", "x/vault",
		"rcpt", "rcpt/ab", "rcpts", "x/rcpt",
		"inbox", "inbox/t/m.json", "inboxes", "x/inbox/m",
	}
	cases := []*harnessParityCase{}
	add := func(mcpTarget mcp.McpTarget, harnessTarget sidecar.HarnessGuardTestTarget) {
		cases = append(cases, &harnessParityCase{mcpTarget: mcpTarget, harnessTarget: harnessTarget})
	}
	for _, kind := range kinds {
		if kind.mcp != mcp.McpTargetRepo {
			continue
		}
		for _, operation := range operations {
			for _, repoKind := range repoKinds {
				for _, ref := range refs {
					for _, path := range paths {
						for flags := 0; flags < 4; flags++ {
							ordinary, teamInbox := flags&1 != 0, flags&2 != 0
							add(mcp.McpTarget{Kind: kind.mcp, RepoKind: repoKind, Operation: operation.mcp, Ref: ref, Path: path,
								OrdinaryFileRepo: ordinary, TeamInbox: teamInbox},
								sidecar.HarnessGuardTestTarget{Kind: kind.harness, RepoKind: repoKind, Operation: operation.harness, Ref: ref,
									Path: path, OrdinaryFileRepo: ordinary, TeamInbox: teamInbox})
						}
					}
				}
			}
		}
	}
	signedTypes := []bridge.SignedType{}
	for value := range bridge.SignedType_name {
		signedTypes = append(signedTypes, bridge.SignedType(value))
	}
	slices.Sort(signedTypes)
	signedTypes = append(signedTypes, slices.Max(signedTypes)+1)
	for _, signedType := range signedTypes {
		for flags := 0; flags < 4; flags++ {
			ownResource, harnessDecision := flags&1 != 0, flags&2 != 0
			add(mcp.McpTarget{Kind: mcp.McpTargetStatement, SignedType: signedType, OwnResource: ownResource, HarnessDecision: harnessDecision},
				sidecar.HarnessGuardTestTarget{Kind: sidecar.HarnessGuardTestTargetStatement, SignedType: signedType, OwnResource: ownResource,
					HarnessDecision: harnessDecision})
		}
	}
	for kind := sidecar.RecordKind(0); kind <= 80; kind++ {
		add(mcp.McpTarget{Kind: mcp.McpTargetRecordAppend, RecordKind: kind},
			sidecar.HarnessGuardTestTarget{Kind: sidecar.HarnessGuardTestTargetRecordAppend, RecordKind: kind})
	}
	for act := 0; act <= 10; act++ {
		add(mcp.McpTarget{Kind: mcp.McpTargetDirectoryAct, DirectoryAct: mcp.McpDirectoryAct(act)},
			sidecar.HarnessGuardTestTarget{Kind: sidecar.HarnessGuardTestTargetDirectoryAct, DirectoryAct: act})
	}
	for _, kind := range kinds {
		if kind.mcp == mcp.McpTargetRepo {
			continue
		}
		// each other kind with a repo's fields set, which no row of theirs reads
		add(mcp.McpTarget{Kind: kind.mcp, RepoKind: protocol.RepoKind_REPO_KIND_SECRET, Operation: mcp.McpRepoWrite, Path: "inbox/x"},
			sidecar.HarnessGuardTestTarget{Kind: kind.harness, RepoKind: protocol.RepoKind_REPO_KIND_SECRET,
				Operation: sidecar.HarnessGuardTestRepoWrite, Path: "inbox/x"})
	}
	return cases
}

// One corpus through both guards: each refuses what the other does, by the same row.
func TestHarnessGuardMatchesMcpGuard(t *testing.T) {
	cases := harnessParityCorpus()
	refused := map[string]int{}
	for _, test := range cases {
		want := ""
		if refusal := mcp.McpGuard([]mcp.McpTarget{test.mcpTarget}); refusal != nil {
			row, ok := harnessParityMcpRows[refusal.Message]
			if !ok {
				t.Fatalf("MCP refuses %+v with %q, a refusal the Harness's guard has no row for", test.mcpTarget, refusal.Message)
			}
			want = row
		}
		got := sidecar.HarnessGuardTestRow(&test.harnessTarget)
		if got != want {
			t.Fatalf("%+v: the Harness's guard answers %q and MCP's %q", test.harnessTarget, got, want)
		}
		refused[got] += 1
	}
	// every row of the table refused something of the corpus, so no row is left untried
	for _, row := range harnessParityMcpRows {
		if refused[row] == 0 {
			t.Fatalf("no target of the corpus reaches row %q", row)
		}
	}
	if len(cases) < 10000 {
		t.Fatalf("the corpus has %d targets", len(cases))
	}
}

// The evs tools read a path as an agent-config file exactly as MCP's do, on the default list and on entries with and
// without a directory.
func TestHarnessAgentConfigPathMatchesMcp(t *testing.T) {
	ingest := sidecar.DefaultSidecarSettings().Ingest
	ingest.AgentConfigPaths = append(slices.Clone(ingest.AgentConfigPaths), ".config/agent.json", "AGENTS.md")
	paths := []string{"AGENTS.md", "docs/AGENTS.md", "AGENTS.md.bak", "x/.config/agent.json", ".config/agent.json",
		"config/agent.json", "CLAUDE.md", ".claude/settings.json", "a/b/.claude/settings.json", "notes.md", ""}
	for _, entry := range ingest.AgentConfigPaths {
		paths = append(paths, entry, "deep/"+entry, entry+"x", fmt.Sprintf("x%s", entry))
	}
	for _, path := range paths {
		if got, want := sidecar.HarnessAgentConfigPathForTest(ingest, path), mcp.McpAgentConfigPath(ingest, path); got != want {
			t.Fatalf("%q: the Harness reads %t and MCP %t", path, got, want)
		}
	}
}
