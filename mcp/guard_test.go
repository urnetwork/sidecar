//go:build !js && !ios && !android && !sdk_mobile_bind

// McpGuard's rows, each refusal beside what its row lets pass: secret repos, the config repo but evs_repos naming
// it, the search index's files but evs_list naming them, the team directory, writes by kind, the vault's harness
// config, a mailbox's vault entries, an unknown repo, statements but the own-resource filings and the daemon's
// harness decisions, record_append's kinds, the directory's person acts, DROP, and a target the guard does not know.

package mcp

import (
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
		{name: "a mailbox's message read", target: testRepoTarget(protocol.RepoKind_REPO_KIND_MAILBOX, McpRepoRead, "", "m/1")},

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
