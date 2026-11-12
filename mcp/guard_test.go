//go:build !js && !ios && !android && !sdk_mobile_bind

// McpGuard's rows, each refusal beside what its row lets pass: secret repos, the config repo but evs_repos naming
// it, the search index's files but evs_list naming them, the team directory, writes by kind, the vault's harness
// config, a mailbox's vault entries, an unknown repo, statements but the own-resource filings and the daemon's
// harness decisions, record_append's kinds, the directory's person acts, DROP, and a target the guard does not know.
//
// A mailbox's vault/ family (QD-673) is held against every reach of it: each evs tool, search tool and the ur://evs
// resource by the operation it reports, on the paths MailVault writes, the family's directory and shards included;
// evs_list and a search's hits leaving it out through McpGuardOmit; and tools that reach repos as the evs tools do,
// called through the framework, refused before their handlers. The evs tools, evs_drop_preview, the search tools
// and ur://evs are their owners' (MCP-M3-13, MCP-M10-01, SEARCH-M10-29), so these cases hold the targets each will
// report; their own tests call each one on a mailbox's vault/ family once it lands.

package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A repo target of kind, path and operation.
func testRepoTarget(kind protocol.RepoKind, operation McpRepoOperation, ref string, path string) McpTarget {
	return McpTarget{Kind: McpTargetRepo, RepoKind: kind, Operation: operation, Ref: ref, Path: path}
}

// A statement target.
func testStatementTarget(signedType bridge.SignedType, ownResource bool, harnessDecision bool) McpTarget {
	return McpTarget{Kind: McpTargetStatement, SignedType: signedType, OwnResource: ownResource, HarnessDecision: harnessDecision}
}

// Every row's refusals and what it lets pass.
func TestGuardRefusesItsTable(t *testing.T) {
	general := protocol.RepoKind_REPO_KIND_GENERAL
	cases := []struct {
		name    string
		target  McpTarget
		refused bool
	}{
		{name: "a general repo read", target: testRepoTarget(general, McpRepoRead, "", "notes/a.md")},
		{name: "a general repo write", target: testRepoTarget(general, McpRepoWrite, "", "notes/a.md")},
		{name: "a record repo searched", target: testRepoTarget(protocol.RepoKind_REPO_KIND_RECORD, McpRepoSearch, "", "")},

		{name: "a secret repo read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_SECRET, McpRepoRead, "", "key"), refused: true},
		{name: "a secret repo named", target: testRepoTarget(protocol.RepoKind_REPO_KIND_SECRET, McpRepoName, "", ""), refused: true},
		{name: "a secret repo searched", target: testRepoTarget(protocol.RepoKind_REPO_KIND_SECRET, McpRepoSearch, "", ""), refused: true},

		{name: "the config repo named", target: testRepoTarget(protocol.RepoKind_REPO_KIND_CONFIG, McpRepoName, "", "")},
		{name: "the config repo read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_CONFIG, McpRepoRead, "", "acl.hujson"), refused: true},
		{name: "the config repo listed", target: testRepoTarget(protocol.RepoKind_REPO_KIND_CONFIG, McpRepoList, "", ""), refused: true},
		{name: "the config repo written", target: testRepoTarget(protocol.RepoKind_REPO_KIND_CONFIG, McpRepoWrite, "", "acl.hujson"), refused: true},

		{name: "the index's files listed", target: testRepoTarget(general, McpRepoList, "", ".ur-index/i1")},
		{name: "the index's files read", target: testRepoTarget(general, McpRepoRead, "", ".ur-index/i1/b0"), refused: true},
		{name: "the index ref read", target: testRepoTarget(general, McpRepoRead, "ur/index", "i1/b0"), refused: true},
		{name: "the index's files written", target: testRepoTarget(general, McpRepoWrite, "", ".ur-index/i1/b0"), refused: true},

		{name: "the directory named", target: testRepoTarget(protocol.RepoKind_REPO_KIND_DIRECTORY, McpRepoName, "", "")},
		{name: "the directory read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_DIRECTORY, McpRepoRead, "", "a/1"), refused: true},

		{name: "mailcfg read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILCFG, McpRepoRead, "", "addr/x")},
		{name: "mailcfg written", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILCFG, McpRepoWrite, "", "addr/x"), refused: true},
		{name: "mailcfg deleted", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILCFG, McpRepoDelete, "", "addr/x"), refused: true},

		{name: "the vault's harness config read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_VAULT, McpRepoRead, "", "harness/config.json")},
		{name: "the vault's harness config written", target: testRepoTarget(protocol.RepoKind_REPO_KIND_VAULT, McpRepoWrite, "", "harness/config.json"), refused: true},
		{name: "another vault path written", target: testRepoTarget(protocol.RepoKind_REPO_KIND_VAULT, McpRepoWrite, "", "notes/x")},

		{name: "a mailbox's vault entry read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoRead, "", "vault/m1"), refused: true},
		{name: "a mailbox's vault entry searched", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoSearch, "", "vault/"), refused: true},
		{name: "a mailbox's vault directory read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoRead, "", "vault"), refused: true},
		{name: "a mailbox's vault directory listed", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoList, "", "vault"), refused: true},
		{name: "a mailbox's vault entry written", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoWrite, "", "vault/0a/m1"), refused: true},
		{name: "a mailbox's message read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoRead, "", "m/1")},
		{name: "a mailbox's root listed", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoList, "", "")},
		{name: "a mailbox named", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoName, "", "")},
		{name: "a mailbox's vaults/ read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoRead, "", "vaults/m1")},
		{name: "a general repo's vault/ read", target: testRepoTarget(general, McpRepoRead, "", "vault/m1")},

		{name: "an unknown repo read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_UNSPECIFIED, McpRepoRead, "", "x"), refused: true},
		{name: "an unknown operation", target: testRepoTarget(general, McpRepoOperation(99), "", "x"), refused: true},

		{name: "an AdminSet", target: testStatementTarget(bridge.SignedType_SIGNED_ADMIN_SET, true, false), refused: true},
		{name: "a SidecarAdmit", target: testStatementTarget(bridge.SignedType_SIGNED_SIDECAR_ADMIT, true, false), refused: true},
		{name: "a KeyRegister", target: testStatementTarget(bridge.SignedType_SIGNED_KEY_REGISTER, true, false), refused: true},
		{name: "an IndexerSet", target: testStatementTarget(bridge.SignedType_SIGNED_INDEXER_SET, true, false), refused: true},
		{name: "a person's decision", target: testStatementTarget(bridge.SignedType_SIGNED_APPROVAL_DECISION, false, false), refused: true},
		{name: "the daemon's harness decision", target: testStatementTarget(bridge.SignedType_SIGNED_APPROVAL_DECISION, false, true)},
		{name: "an ApprovalCancel", target: testStatementTarget(bridge.SignedType_SIGNED_APPROVAL_CANCEL, true, true), refused: true},
		{name: "its own GrantActivate", target: testStatementTarget(bridge.SignedType_SIGNED_GRANT_ACTIVATE, true, false)},
		{name: "another's GrantActivate", target: testStatementTarget(bridge.SignedType_SIGNED_GRANT_ACTIVATE, false, false), refused: true},
		{name: "its own GrantRevoke", target: testStatementTarget(bridge.SignedType_SIGNED_GRANT_REVOKE, true, false)},
		{name: "its own BridgeRoute", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_ROUTE, true, false)},
		{name: "its own BridgeMap", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_MAP, true, false)},
		{name: "its own BridgeAddress", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_ADDRESS, true, false)},
		{name: "its own BridgeWithdraw", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, true, false)},
		{name: "another's BridgeWithdraw", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_WITHDRAW, false, false), refused: true},
		{name: "a BridgeBlock", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_BLOCK, true, false), refused: true},
		{name: "a BridgeEgress", target: testStatementTarget(bridge.SignedType_SIGNED_BRIDGE_EGRESS, true, false), refused: true},
		{name: "a Suspend", target: testStatementTarget(bridge.SignedType_SIGNED_SUSPEND, true, false), refused: true},
		{name: "an EvsShare", target: testStatementTarget(bridge.SignedType_SIGNED_EVS_SHARE, true, false), refused: true},
		{name: "an OwnerConfirm", target: testStatementTarget(bridge.SignedType_SIGNED_OWNER_CONFIRM, true, false), refused: true},
		{name: "a RepoGrant", target: testStatementTarget(bridge.SignedType_SIGNED_REPO_GRANT, true, false), refused: true},

		{name: "a claim", target: McpTarget{Kind: McpTargetRecordAppend, RecordKind: sidecar.RecordKindClaim}},
		{name: "a note", target: McpTarget{Kind: McpTargetRecordAppend, RecordKind: sidecar.RecordKindNote}},
		{name: "an announce", target: McpTarget{Kind: McpTargetRecordAppend, RecordKind: sidecar.RecordKindAnnounce}, refused: true},
		{name: "a decision entry", target: McpTarget{Kind: McpTargetRecordAppend, RecordKind: sidecar.RecordKindDecision}, refused: true},

		{name: "a directory person act", target: McpTarget{Kind: McpTargetDirectoryAct}, refused: true},
		{name: "a DROP", target: McpTarget{Kind: McpTargetDrop}, refused: true},
		{name: "no kind", target: McpTarget{}, refused: true},
	}
	for _, c := range cases {
		refusal := McpGuard([]McpTarget{c.target})
		if (refusal != nil) != c.refused {
			t.Errorf("%s: refusal %v, want refused %t", c.name, refusal, c.refused)
		}
		if refusal != nil && refusal.Code != McpCodeRefused {
			t.Errorf("%s: code %d", c.name, refusal.Code)
		}
		if McpGuardAdmits(c.target) == c.refused {
			t.Errorf("%s: admits %t", c.name, !c.refused)
		}
	}
}

// One refused target refuses the whole call, and the refusal's text names its row, never the target.
func TestGuardRefusesTheCallAtItsFirstRefusedTarget(t *testing.T) {
	secretPath := "the-secret-name-of-a-file"
	refusal := McpGuard([]McpTarget{
		testRepoTarget(protocol.RepoKind_REPO_KIND_GENERAL, McpRepoRead, "", "fine"),
		testRepoTarget(protocol.RepoKind_REPO_KIND_SECRET, McpRepoRead, "", secretPath),
		testRepoTarget(protocol.RepoKind_REPO_KIND_CONFIG, McpRepoRead, "", "acl.hujson"),
	})
	if refusal == nil || refusal.Message != "MCP never reaches a secret repo" {
		t.Errorf("the refusal %v", refusal)
	}
	if McpGuard(nil) != nil {
		t.Error("no target refused")
	}
}

// The vault row's text, which names the row and never the path.
const testVaultRefusal = "MCP never reaches a mailbox's vault entries"

// The vault entry and message the mailbox fixture holds.
var (
	testVaultEntryId = sidecar.Id{0x01, 0x9a, 0x6e, 0x3b, 0x55, 0x10, 0x7c, 0x42, 0x8d, 0x21, 0x0f, 0xe4, 0x6a, 0x93, 0x17, 0xc8}
	testMessageId    = sidecar.Id{0x01, 0x9a, 0x6e, 0x3b, 0x56, 0x22, 0x0d, 0x14, 0x9b, 0x7e, 0x31, 0x05, 0xc2, 0x48, 0xd9, 0x6f}
)

// A mailbox's files (§15.7) from the paths the mail code writes: the vault/ family's, an entry, its shard and the
// family's directory; then every other family's, with names that only begin as the family does, or hold it deeper.
func testMailboxPaths() (vaultPaths []string, otherPaths []string) {
	entry := sidecar.MailVaultPath(testVaultEntryId)
	vaultPaths = []string{entry, entry[:strings.LastIndexByte(entry, '/')], "vault"}
	month := sidecar.MailYearMonth(202611)
	otherPaths = []string{
		sidecar.MailMessagePath(month, testMessageId), sidecar.MailGroupRefPath(month, testMessageId),
		sidecar.MailIndexPath(month, 1), sidecar.MailFlagPath(month, 1), sidecar.MailProverPath(testMessageId),
		sidecar.MailForwardPath, sidecar.MailSpamModelPath, "vaults/x", "vault-1", "m/vault",
	}
	effectKey := bytes.Repeat([]byte{0x5a}, 32)
	for _, pathOf := range []func(effectKey []byte) (string, error){sidecar.MailOutboxPath, sidecar.MailOutcomePath} {
		if path, err := pathOf(effectKey); err == nil {
			otherPaths = append(otherPaths, path)
		}
	}
	return vaultPaths, otherPaths
}

// What each evs tool, search tool and the ur://evs resource reports to the guard for a path it reaches (§16.5;
// McpRepoOperation's rows): its Targets' operation, which each item of a listing it makes takes as well.
var testRepoReaches = []struct {
	reach     string
	operation McpRepoOperation
}{
	{reach: "evs_repos", operation: McpRepoName},
	{reach: "evs_list", operation: McpRepoList},
	{reach: "evs_history", operation: McpRepoRead},
	{reach: "evs_read", operation: McpRepoRead},
	{reach: "evs_drop_preview", operation: McpRepoRead},
	{reach: "evs_write", operation: McpRepoWrite},
	{reach: "evs_delete", operation: McpRepoDelete},
	{reach: "search", operation: McpRepoSearch},
	{reach: "search_agents", operation: McpRepoSearch},
	{reach: "search_status", operation: McpRepoName},
	{reach: "ur://evs read", operation: McpRepoRead},
	{reach: "ur://evs subscribe", operation: McpRepoRead},
}

// QD-673: every evs tool, search tool and the ur://evs resource is refused on a mailbox's vault/ family, on any ref and
// by the vault row's text, the family as a prefix included; each passes on the mailbox's other files, naming the
// mailbox passes, and no other kind of repo's vault/ path is refused. Every §16.5 evs and search tool has a case, so a
// new one is held to the row.
func TestGuardRefusesEveryReachOfAMailboxVault(t *testing.T) {
	reachNames := map[string]bool{}
	for _, reach := range testRepoReaches {
		reachNames[reach.reach] = true
	}
	for _, design := range mcpCatalogDesign {
		if mcpCatalogGuarded(design.name) && !reachNames[design.name] {
			t.Errorf("%s reaches repos and has no case here", design.name)
		}
	}
	mailbox := protocol.RepoKind_REPO_KIND_MAILBOX
	vaultPaths, otherPaths := testMailboxPaths()
	for _, reach := range testRepoReaches {
		for _, ref := range []string{"", "other-ref"} {
			for _, path := range append(slices.Clone(vaultPaths), "vault/") {
				target := testRepoTarget(mailbox, reach.operation, ref, path)
				refusal := McpGuard([]McpTarget{target})
				// the row's own text, which names no path
				if refusal == nil || refusal.Code != McpCodeRefused || refusal.Message != testVaultRefusal || McpGuardAdmits(target) {
					t.Errorf("%s of %q on ref %q: %v", reach.reach, path, ref, refusal)
				}
			}
		}
		if reach.operation == McpRepoName {
			// naming the mailbox, as evs_repos and search_status do, names nothing in it
			if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, reach.operation, "", "")}); refusal != nil {
				t.Errorf("%s naming the mailbox: %v", reach.reach, refusal)
			}
			continue
		}
		for _, path := range otherPaths {
			if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, reach.operation, "", path)}); refusal != nil {
				t.Errorf("%s of the mailbox's %q: %v", reach.reach, path, refusal)
			}
		}
		// a group inbox, a record repo and the member's vault hold no mailbox vault entries
		for _, kind := range []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_VAULT} {
			if refusal := McpGuard([]McpTarget{testRepoTarget(kind, reach.operation, "", vaultPaths[0])}); refusal != nil {
				t.Errorf("%s of a %s repo's %q: %v", reach.reach, kind, vaultPaths[0], refusal)
			}
		}
	}
}

// QD-673: evs_list leaves a mailbox's vault/ family out. A listing of the mailbox's root names no vault directory, a
// listing of every path names nothing under it, each other file named in its order, and a listing of the family
// itself, its directory or a shard, is refused at the call. The index's files stay named, as evs_list names them
// when asked (§11.14).
func TestEvsListLeavesMailboxVaultOut(t *testing.T) {
	mailbox := protocol.RepoKind_REPO_KIND_MAILBOX
	listed := func(paths []string) []string {
		return McpGuardOmit(paths, func(path string) McpTarget { return testRepoTarget(mailbox, McpRepoList, "", path) })
	}
	rootPaths := []string{".ur-index", "f", "forward", "i", "m", "o", "or", "p", "r", "ra", "s", "vault"}
	if got := listed(rootPaths); !slices.Equal(got, rootPaths[:len(rootPaths)-1]) {
		t.Errorf("the root's listing %v", got)
	}
	vaultPaths, otherPaths := testMailboxPaths()
	if !slices.ContainsFunc(otherPaths, func(path string) bool { return strings.HasPrefix(path, "o/") }) {
		t.Fatalf("the fixture holds no outbox path: %v", otherPaths)
	}
	// the family's paths among the others, in a listing's order
	allPaths := slices.Concat(otherPaths[:2], vaultPaths[:1], otherPaths[2:5], vaultPaths[1:], otherPaths[5:], []string{".ur-index/i1/b0"})
	if got := listed(allPaths); !slices.Equal(got, slices.Concat(otherPaths, []string{".ur-index/i1/b0"})) {
		t.Errorf("every path's listing %v", got)
	}
	for _, path := range vaultPaths {
		if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, McpRepoList, "", path)}); refusal == nil || refusal.Message != testVaultRefusal {
			t.Errorf("evs_list of %q: %v", path, refusal)
		}
	}
	if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, McpRepoList, "", "")}); refusal != nil {
		t.Errorf("evs_list of the mailbox's root: %v", refusal)
	}
	if got := listed(nil); got == nil || len(got) != 0 {
		t.Errorf("an empty listing %v", got)
	}
}

// QD-673: a search of a mailbox's vault/ family is refused at the call, by its path_prefix filter, and a search of
// the mailbox names no hit there, each other hit kept: a second line, since no index holds vault/ (D-MAIL-16).
// search_status and evs_repos name the mailbox and leave a secret repo out.
func TestSearchLeavesMailboxVaultOut(t *testing.T) {
	mailbox := protocol.RepoKind_REPO_KIND_MAILBOX
	vaultPaths, otherPaths := testMailboxPaths()
	for _, prefix := range append(slices.Clone(vaultPaths), "vault/") {
		if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, McpRepoSearch, "", prefix)}); refusal == nil || refusal.Message != testVaultRefusal {
			t.Errorf("a search under %q: %v", prefix, refusal)
		}
	}
	if refusal := McpGuard([]McpTarget{testRepoTarget(mailbox, McpRepoSearch, "", "")}); refusal != nil {
		t.Errorf("a search of the mailbox: %v", refusal)
	}
	type hit struct {
		repoKind protocol.RepoKind
		path     string
	}
	hits := []hit{{repoKind: mailbox, path: vaultPaths[0]}, {repoKind: mailbox, path: otherPaths[0]},
		{repoKind: protocol.RepoKind_REPO_KIND_GENERAL, path: vaultPaths[0]}, {repoKind: mailbox, path: vaultPaths[1]}}
	kept := McpGuardOmit(hits, func(item hit) McpTarget { return testRepoTarget(item.repoKind, McpRepoSearch, "", item.path) })
	if !slices.Equal(kept, []hit{hits[1], hits[2]}) {
		t.Errorf("the hits kept %v", kept)
	}

	repoKinds := []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, protocol.RepoKind_REPO_KIND_SECRET, mailbox, protocol.RepoKind_REPO_KIND_CONFIG}
	namedRepoKinds := McpGuardOmit(repoKinds, func(kind protocol.RepoKind) McpTarget { return testRepoTarget(kind, McpRepoName, "", "") })
	if !slices.Equal(namedRepoKinds, []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, mailbox, protocol.RepoKind_REPO_KIND_CONFIG}) {
		t.Errorf("the repos named %v", namedRepoKinds)
	}
}

// A test tool's input: a repo by id and a path in it, as the evs tools take them.
type testRepoIn struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
}

// A test tool's output: the paths it names.
type testRepoOut struct {
	Paths []string `json:"paths"`
}

// path's target in in's repo, at the kind the call's network holds for the repo: UNSPECIFIED for one it does not
// hold, which the guard refuses but naming.
func testRepoTargetOf(call *McpCall, in *testRepoIn, operation McpRepoOperation, path string) McpTarget {
	kind := protocol.RepoKind_REPO_KIND_UNSPECIFIED
	if network, ok := mcpToolNetworkOf(call); ok {
		if repoId, err := sidecar.ParseId(in.Repo); err == nil {
			kind = network.RepoKind(repoId)
		}
	}
	return testRepoTarget(kind, operation, "", path)
}

// Registers test_repo_read, test_repo_write and test_repo_list, which reach a repo as the evs tools do: each reports
// its path at the network's kind for its repo, and test_repo_list names the mailbox fixture's paths under its prefix
// through McpGuardOmit.
func addTestRepoTools(catalog *McpCatalog) {
	none := func(call *McpCall, in *testRepoIn) ([]McpAccess, error) { return nil, nil }
	reach := func(operation McpRepoOperation) func(call *McpCall, in *testRepoIn) ([]McpTarget, error) {
		return func(call *McpCall, in *testRepoIn) ([]McpTarget, error) {
			return []McpTarget{testRepoTargetOf(call, in, operation, in.Path)}, nil
		}
	}
	echoPath := func(ctx context.Context, call *McpCall, in *testRepoIn, result *McpResult) (*testRepoOut, error) {
		result.SetSource("test:repo")
		return &testRepoOut{Paths: []string{in.Path}}, nil
	}
	AddTool(catalog, &McpToolSpec[testRepoIn]{Name: "test_repo_read", Tier: McpTierRead, Description: "reads a path", Access: none, Targets: reach(McpRepoRead)}, echoPath)
	AddTool(catalog, &McpToolSpec[testRepoIn]{Name: "test_repo_write", Tier: McpTierWrite, Description: "writes a path", Access: none, Targets: reach(McpRepoWrite)}, echoPath)
	AddTool(catalog, &McpToolSpec[testRepoIn]{Name: "test_repo_list", Tier: McpTierRead, Description: "lists under a path", Access: none, Targets: reach(McpRepoList)},
		func(ctx context.Context, call *McpCall, in *testRepoIn, result *McpResult) (*testRepoOut, error) {
			result.SetSource("test:repo")
			vaultPaths, otherPaths := testMailboxPaths()
			underPaths := []string{}
			for _, path := range slices.Concat(vaultPaths, otherPaths) {
				if in.Path == "" || path == in.Path || strings.HasPrefix(path, in.Path+"/") {
					underPaths = append(underPaths, path)
				}
			}
			return &testRepoOut{Paths: McpGuardOmit(underPaths, func(path string) McpTarget { return testRepoTargetOf(call, in, McpRepoList, path) })}, nil
		})
}

// A test_repo tool's output.
func testRepoOutOf(t *testing.T, response *testMcpResponse) *testRepoOut {
	t.Helper()
	out := &testRepoOut{}
	if err := json.Unmarshal(testEnvelopeOf(t, response).Data, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// QD-673 through the framework: a tool reaching a mailbox's vault/ family as the evs tools do is refused by the vault
// row before its handler runs, a write and a listing as well as a read, and a listing of the mailbox names nothing of
// the family, while the mailbox's other files read, write and list. A repo the network does not hold is refused
// whatever the path.
func TestToolsOnMailboxVaultRefusedBeforeTheirHandlers(t *testing.T) {
	env := newTestToolEnv(t)
	mailboxId := sidecar.NewId()
	env.tools.stateLock.Lock()
	env.tools.repoKinds[mailboxId] = protocol.RepoKind_REPO_KIND_MAILBOX
	env.tools.stateLock.Unlock()
	conn := env.conn("2025-06-18")
	callRepoTool := func(name string, path string) *testMcpResponse {
		return env.callTool(conn, "2025-06-18", name, map[string]any{"repo": mailboxId.String(), "path": path})
	}

	vaultPaths, otherPaths := testMailboxPaths()
	for _, path := range vaultPaths {
		for _, name := range []string{"test_repo_read", "test_repo_write", "test_repo_list"} {
			wantMcpError(t, callRepoTool(name, path), McpCodeRefused, testVaultRefusal)
		}
	}
	for _, name := range []string{"test_repo_read", "test_repo_write"} {
		if out := testRepoOutOf(t, callRepoTool(name, otherPaths[0])); !slices.Equal(out.Paths, otherPaths[:1]) {
			t.Errorf("%s of %q: %v", name, otherPaths[0], out.Paths)
		}
	}
	if out := testRepoOutOf(t, callRepoTool("test_repo_list", "")); !slices.Equal(out.Paths, otherPaths) {
		t.Errorf("the mailbox's listing %v", out.Paths)
	}
	// a vault name below the top, as m/vault, is no vault entry
	if out := testRepoOutOf(t, callRepoTool("test_repo_list", "m")); !slices.Equal(out.Paths, []string{otherPaths[0], "m/vault"}) {
		t.Errorf("the listing of m: %v", out.Paths)
	}

	unknown := env.callTool(conn, "2025-06-18", "test_repo_read", map[string]any{"repo": sidecar.NewId().String(), "path": otherPaths[0]})
	wantMcpError(t, unknown, McpCodeRefused, "does not hold")
}
