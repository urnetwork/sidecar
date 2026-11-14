//go:build !js && !ios && !android && !sdk_mobile_bind

// MCP-M6-01's guard rows (§16.6's refused table, 16.11; D-MCP-17, D-MCP-33, D-MCP-34, I-9): the team directory's
// person acts stay refused from MCP, one test each, so no session decides a request, announces, revokes, marks a repo
// private, changes the claims setting, a worker's announcement or the team's settings, or erases; the statements a
// decision or an announcement would sign are refused whatever a tool says of them; and every evs tool and ur://evs
// resource refuses the directory, evs_repos alone naming it. The last test runs a tool through the framework, so a
// refusal is seen before any handler.

package mcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The refusals' constant texts.
const (
	testDirectoryActRefusal  = "the directory's decisions, announcements and erasures are a person's, outside MCP"
	testDirectoryEvsRefusal  = "MCP never reads or writes the team directory through evs: use the directory tools"
	testStatementRefusalPart = "MCP signs no authority, acl, bridge or approval statement but this sidecar's own filings"
)

// A person act refused with the directory row's text, alone and after targets that pass.
func testDirectoryActRefused(t *testing.T, act McpDirectoryAct) {
	t.Helper()
	target := McpTarget{Kind: McpTargetDirectoryAct, DirectoryAct: act}
	refusal := McpGuard([]McpTarget{target})
	if refusal == nil || refusal.Code != McpCodeRefused || refusal.Message != testDirectoryActRefusal {
		t.Fatalf("act %d: %v", act, refusal)
	}
	if McpGuardAdmits(target) {
		t.Errorf("act %d is admitted", act)
	}
	passing := testRepoTarget(protocol.RepoKind_REPO_KIND_GENERAL, McpRepoRead, "", "notes/a.md")
	if refusal := McpGuard([]McpTarget{passing, target}); refusal == nil || refusal.Message != testDirectoryActRefusal {
		t.Errorf("act %d after a passing target: %v", act, refusal)
	}
}

// A statement refused whether or not a tool calls it its own resource or a harness decision.
func testStatementRefused(t *testing.T, signedType bridge.SignedType) {
	t.Helper()
	for _, ownResource := range []bool{false, true} {
		refusal := McpGuard([]McpTarget{testStatementTarget(signedType, ownResource, false)})
		if refusal == nil || refusal.Code != McpCodeRefused || !strings.Contains(refusal.Message, testStatementRefusalPart) {
			t.Errorf("%s with own resource %t: %v", signedType, ownResource, refusal)
		}
	}
}

// Deciding a request: no approve, deny or completion from a session, and none of what a decision signs, a RepoGrant,
// an EvsShare or an ApprovalDecision on another sidecar's request (D-MCP-34).
func TestGuardRefusesDecidingADirectoryRequest(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActDecide)
	testStatementRefused(t, bridge.SignedType_SIGNED_REPO_GRANT)
	testStatementRefused(t, bridge.SignedType_SIGNED_EVS_SHARE)
	// an ApprovalDecision passes only as the daemon's own harness decision, which is never one on another sidecar's
	// request: a tool that says "my own resource" of one changes nothing
	for _, ownResource := range []bool{false, true} {
		refusal := McpGuard([]McpTarget{testStatementTarget(bridge.SignedType_SIGNED_APPROVAL_DECISION, ownResource, false)})
		if refusal == nil || refusal.Code != McpCodeRefused {
			t.Errorf("an ApprovalDecision with own resource %t passed", ownResource)
		}
	}
	// record_append writes no decision entry either
	for _, kind := range []sidecar.RecordKind{sidecar.RecordKindDecision, sidecar.RecordKindAnnounce} {
		if refusal := McpGuard([]McpTarget{{Kind: McpTargetRecordAppend, RecordKind: kind}}); refusal == nil {
			t.Errorf("record_append of kind %v passed", kind)
		}
	}
}

func TestGuardRefusesAnnouncingARepo(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActAnnounce)
}

func TestGuardRefusesRevokingARepo(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActRevoke)
}

func TestGuardRefusesMarkingARepoPrivate(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActPrivate)
}

func TestGuardRefusesChangingClaims(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActClaims)
}

func TestGuardRefusesChangingAWorkerAnnouncement(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActWorker)
}

func TestGuardRefusesChangingDirectorySettings(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActSettings)
}

// Erasing: no directory erasure from a session, and no DROP, which is the one destructive push a tool could name
// (D-MCP-32, D-MCP-33).
func TestGuardRefusesErasingDirectoryItems(t *testing.T) {
	testDirectoryActRefused(t, McpDirectoryActErase)
	if refusal := McpGuard([]McpTarget{{Kind: McpTargetDrop}}); refusal == nil || refusal.Code != McpCodeRefused {
		t.Errorf("a DROP: %v", refusal)
	}
}

// An act the list does not name is refused as the named ones are: a new person act cannot pass unjudged.
func TestGuardRefusesAnUnnamedDirectoryAct(t *testing.T) {
	testDirectoryActRefused(t, 0)
	testDirectoryActRefused(t, McpDirectoryActErase+1)
}

// Every evs operation on the directory is refused, on any path and either ref, but evs_repos naming it; a search of
// it is refused too, since the directory tools are its only readers.
func TestGuardRefusesEveryEvsReachOfTheDirectory(t *testing.T) {
	directory := protocol.RepoKind_REPO_KIND_DIRECTORY
	for _, operation := range []McpRepoOperation{McpRepoList, McpRepoRead, McpRepoWrite, McpRepoDelete, McpRepoSearch} {
		for _, ref := range []string{"", "main", mcpIndexRefName} {
			for _, path := range []string{"", "a", "a/1", "r/repo", ".ur-index/x", "s/0001/7"} {
				refusal := McpGuard([]McpTarget{testRepoTarget(directory, operation, ref, path)})
				if refusal == nil || refusal.Code != McpCodeRefused {
					t.Errorf("operation %d on ref %q path %q passed", operation, ref, path)
				}
			}
		}
		if refusal := McpGuard([]McpTarget{testRepoTarget(directory, operation, "", "a/1")}); refusal == nil || refusal.Message != testDirectoryEvsRefusal {
			t.Errorf("operation %d: %v", operation, refusal)
		}
	}
	if refusal := McpGuard([]McpTarget{testRepoTarget(directory, McpRepoName, "", "")}); refusal != nil {
		t.Errorf("evs_repos naming the directory: %v", refusal)
	}
	// a listing leaves the directory's paths out and keeps its name among the repos
	repoKinds := []protocol.RepoKind{protocol.RepoKind_REPO_KIND_GENERAL, directory, protocol.RepoKind_REPO_KIND_RECORD}
	if named := McpGuardOmit(repoKinds, func(kind protocol.RepoKind) McpTarget { return testRepoTarget(kind, McpRepoName, "", "") }); !slices.Equal(named, repoKinds) {
		t.Errorf("the repos named %v", named)
	}
	if listed := McpGuardOmit(repoKinds, func(kind protocol.RepoKind) McpTarget { return testRepoTarget(kind, McpRepoList, "", "a/1") }); slices.Contains(listed, directory) {
		t.Errorf("a listing named the directory's paths: %v", listed)
	}
}

// Through the framework: a tool reaching the directory as the evs tools do is refused before its handler, a read, a
// write and a listing alike, in a tainted run and an untainted one.
func TestToolsOnTheDirectoryRefusedBeforeTheirHandlers(t *testing.T) {
	env := newTestToolEnv(t)
	directoryId := sidecar.NewId()
	env.tools.stateLock.Lock()
	env.tools.repoKinds[directoryId] = protocol.RepoKind_REPO_KIND_DIRECTORY
	env.tools.stateLock.Unlock()
	for _, version := range []string{"2025-06-18", "2026-07-28"} {
		conn := env.conn(version)
		for _, name := range []string{"test_repo_read", "test_repo_write", "test_repo_list"} {
			for _, path := range []string{"", "a/1", "r/repo"} {
				response := env.callTool(conn, version, name, map[string]any{"repo": directoryId.String(), "path": path})
				wantMcpError(t, response, McpCodeRefused, testDirectoryEvsRefusal)
			}
		}
	}
	// no refused call was recorded as a write that ran
	for _, call := range env.sink.sunk() {
		if call.err == nil {
			t.Errorf("%s on the directory was recorded as done", call.toolName)
		}
	}
}

// The daemon's catalog holds no tool for a person act: its directory tools are §16.5's three, two reads and the O
// request, and nothing else names the directory.
func TestCatalogHoldsNoDirectoryPersonAct(t *testing.T) {
	allowed := []string{"directory_list", "directory_requests", "directory_request"}
	for _, design := range mcpCatalogDesign {
		if len(design.name) < len("directory") || design.name[:len("directory")] != "directory" {
			continue
		}
		if !slices.Contains(allowed, design.name) {
			t.Errorf("%s is a directory tool §16.5 does not name", design.name)
		}
		if design.name == "directory_request" && design.tier != McpTierOutward {
			t.Errorf("directory_request is tier %s", design.tier)
		}
		if design.name != "directory_request" && design.tier != McpTierRead {
			t.Errorf("%s is tier %s", design.name, design.tier)
		}
	}
}
