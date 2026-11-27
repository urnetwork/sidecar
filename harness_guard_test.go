//go:build !ios_extension && !sidecar_http

package sidecar

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One target as the parity test (harness_guard_parity_test.go, package sidecar_test) builds it, every field the
// guard's own.
type HarnessGuardTestTarget struct {
	Kind             int
	RepoKind         protocol.RepoKind
	Operation        int
	Ref              string
	Path             string
	OrdinaryFileRepo bool
	TeamInbox        bool
	SignedType       bridge.SignedType
	OwnResource      bool
	HarnessDecision  bool
	RecordKind       RecordKind
	DirectoryAct     int
}

// The guard's target kinds and repo operations, for the parity test's mapping from MCP's.
const (
	HarnessGuardTestTargetRepo         = int(harnessTargetRepo)
	HarnessGuardTestTargetStatement    = int(harnessTargetStatement)
	HarnessGuardTestTargetRecordAppend = int(harnessTargetRecordAppend)
	HarnessGuardTestTargetDirectoryAct = int(harnessTargetDirectoryAct)
	HarnessGuardTestTargetDrop         = int(harnessTargetDrop)

	HarnessGuardTestRepoName   = int(harnessRepoName)
	HarnessGuardTestRepoList   = int(harnessRepoList)
	HarnessGuardTestRepoRead   = int(harnessRepoRead)
	HarnessGuardTestRepoWrite  = int(harnessRepoWrite)
	HarnessGuardTestRepoDelete = int(harnessRepoDelete)
	HarnessGuardTestRepoSearch = int(harnessRepoSearch)
)

// The row the guard refuses target by, "" where it passes.
func HarnessGuardTestRow(target *HarnessGuardTestTarget) string {
	refusal := harnessGuardRefusal(&harnessGuardTarget{
		Kind: harnessGuardTargetKind(target.Kind), RepoKind: target.RepoKind, Operation: harnessRepoOperation(target.Operation),
		Ref: target.Ref, Path: target.Path, OrdinaryFileRepo: target.OrdinaryFileRepo, TeamInbox: target.TeamInbox,
		SignedType: target.SignedType, OwnResource: target.OwnResource, HarnessDecision: target.HarnessDecision,
		RecordKind: target.RecordKind, DirectoryAct: target.DirectoryAct,
	})
	if refusal == nil {
		return ""
	}
	return refusal.Row
}

// Whether path is an agent-config path of ingest's, as the evs tools read it.
func HarnessAgentConfigPathForTest(ingest *SidecarIngestSettings, path string) bool {
	return harnessAgentConfigPath(ingest, path)
}

// Each row refuses what its line in the table names, and its text names the row, never the target: no path, repo or
// kind a target carries reaches the refusal.
func TestHarnessGuardRowsRefuseWithoutNamingTheTarget(t *testing.T) {
	path := "secret-plans/inbox/q3.txt"
	for _, test := range []struct {
		target harnessGuardTarget
		row    string
	}{
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_SECRET, Operation: harnessRepoName}, row: harnessGuardRowSecret},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_CONFIG, Operation: harnessRepoRead, Path: path}, row: harnessGuardRowConfig},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoRead, Path: ".ur-index/" + path}, row: harnessGuardRowIndex},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoRead, Ref: "ur/index", Path: path}, row: harnessGuardRowIndex},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_DIRECTORY, Operation: harnessRepoRead, Path: path}, row: harnessGuardRowDirectory},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_MAILCFG, Operation: harnessRepoWrite, Path: path}, row: harnessGuardRowWrites},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_VAULT, Operation: harnessRepoDelete, Path: "harness/" + path}, row: harnessGuardRowHarnessConfig},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_MAILBOX, Operation: harnessRepoList, Path: "vault"}, row: harnessGuardRowMailboxVault},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoRead, Path: "rcpt/" + path}, row: harnessGuardRowRecipients},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_AGENT, Operation: harnessRepoWrite, Path: "inbox/" + path}, row: harnessGuardRowAgentsInbox},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoWrite, Path: "inbox/x", TeamInbox: true}, row: harnessGuardRowAgentsInbox},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_UNSPECIFIED, Operation: harnessRepoRead, Path: path}, row: harnessGuardRowUnheld},
		{target: harnessGuardTarget{Kind: harnessTargetStatement, SignedType: bridge.SignedType_SIGNED_BRIDGE_BLOCK}, row: harnessGuardRowStatements},
		{target: harnessGuardTarget{Kind: harnessTargetStatement, SignedType: bridge.SignedType_SIGNED_APPROVAL_DECISION}, row: harnessGuardRowStatements},
		{target: harnessGuardTarget{Kind: harnessTargetRecordAppend, RecordKind: RecordKindToolCall}, row: harnessGuardRowRecord},
		{target: harnessGuardTarget{Kind: harnessTargetDirectoryAct, DirectoryAct: 99}, row: harnessGuardRowDirectoryActs},
		{target: harnessGuardTarget{Kind: harnessTargetDrop}, row: harnessGuardRowDrop},
		{target: harnessGuardTarget{Kind: 0}, row: harnessGuardRowUnjudged},
		{target: harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: 77}, row: harnessGuardRowUnjudgedOperate},
	} {
		err := harnessGuard([]harnessGuardTarget{test.target})
		refusal := &HarnessGuardError{}
		if !errors.As(err, &refusal) || refusal.Row != test.row || !errors.Is(err, ErrHarnessGuardRefused) {
			t.Fatalf("%+v: %v, want row %q", test.target, err, test.row)
		}
		if strings.Contains(err.Error(), "q3") || strings.Contains(err.Error(), "secret-plans") || strings.Contains(err.Error(), "REPO_KIND") {
			t.Fatalf("the refusal names its target: %q", err.Error())
		}
	}
}

// What the table lets through: a member's general repo read and written, a team inbox read, an agent repo's own files
// written, the own-resource filings and the harness decision, and the coordination kinds.
func TestHarnessGuardAdmitsTheOrdinaryCalls(t *testing.T) {
	for _, target := range []harnessGuardTarget{
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoWrite, Path: "notes/today.md"},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoRead, Path: "inbox/x", TeamInbox: true},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_AGENT, Operation: harnessRepoWrite, Path: "summary.md"},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_CONFIG, Operation: harnessRepoName},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoList, Path: ".ur-index"},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_DIRECTORY, Operation: harnessRepoSearch},
		{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, Operation: harnessRepoRead, Path: "rcpt/x", OrdinaryFileRepo: true},
		{Kind: harnessTargetStatement, SignedType: bridge.SignedType_SIGNED_GRANT_ACTIVATE, OwnResource: true},
		{Kind: harnessTargetStatement, SignedType: bridge.SignedType_SIGNED_APPROVAL_DECISION, HarnessDecision: true},
		{Kind: harnessTargetRecordAppend, RecordKind: RecordKindNote},
	} {
		if err := harnessGuard([]harnessGuardTarget{target}); err != nil {
			t.Fatalf("%+v: %v", target, err)
		}
	}
}

// A listing names only what the guard admits, in its order: a secret repo and a mailbox's vault family are left out,
// never named.
func TestHarnessGuardOmitLeavesOutRefusedItems(t *testing.T) {
	paths := []string{"a.txt", "vault", "vault/ab/entry", "b.txt", "rcpt"}
	kept := harnessGuardOmit(paths, func(path string) harnessGuardTarget {
		return harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: protocol.RepoKind_REPO_KIND_MAILBOX, Operation: harnessRepoList, Path: path}
	})
	if strings.Join(kept, ",") != "a.txt,b.txt" {
		t.Fatalf("kept %v", kept)
	}
}
