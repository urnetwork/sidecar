//go:build !js && !ios && !android && !sdk_mobile_bind

// McpGuard: §16.6's "refused from MCP" table as one data-driven function (D-MCP-17, R-MCP-9, I-7, I-8). A tool says
// what a call would touch as McpTargets, before its handler runs, and the guard refuses the call at the first target
// a row refuses. No tool signs any of these, so the guard is a second line, which MCP-M3-26's actions suite tests
// through every tool. A listing tool asks McpGuardAdmits of each item and omits what it refuses, as evs_repos omits
// secret repos.
//
//	secret          every evs tool, search tool and ur://evs resource on a repo of kind secret, naming it included
//	config          every evs tool and ur://evs resource on the config repo but evs_repos naming it (QD-205)
//	index           every evs tool and ur://evs resource on the search index's files, .ur-index/ on a file-mode ref
//	                and anything on the ur/index ref, but evs_list naming them when asked (§11.14)
//	directory       every evs tool and ur://evs resource on the team directory but evs_repos naming it (16.11)
//	writes          evs_write and evs_delete on repos of kind config, mailcfg, secret and directory
//	harness config  evs_write and evs_delete on a vault's harness/ path (QD-104)
//	mailbox vault   every evs tool, search tool and ur://evs resource on a mailbox's vault/ family (QD-673)
//	statements      every authority statement, admissions, KeyRegister and IndexerSet included; approval statements
//	                but the daemon's own harness decisions; acl and bridge statements but the own-resource filings
//	                16.5's tools make about this sidecar's own resources, which the tool has checked are its own:
//	                GrantActivate of its own approved request, GrantRevoke of a grant whose subject it is, a
//	                BridgeRoute or BridgeMap it advertises or hosts, the BridgeAddress of its own sidecar_id, and
//	                BridgeWithdraw of its own rules (§8.8, §17.4, §17.8); so never BridgeBlock, BridgeEgress,
//	                Suspend, EvsShare, OwnerConfirm or an access-log statement
//	record          record_append of a kind other than claim, handoff, ask, answer, check and note
//	directory acts  the directory's person acts: deciding a request, announcing, revoking or marking a repo
//	                private, changing the claims setting, a worker's announcement or ServiceSettings.directory, and
//	                erasing directory items (16.11)
//	drop            DROP pushes and their cancels (§11.7; D-MCP-32)
//
// Each refusal is an McpError of McpCodeRefused whose text names the row, never the target. Package-level functions
// are safe for concurrent use: the table never changes.

package mcp

import (
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a target is.
type McpTargetKind int

const (
	// A repo's files or names, which an evs tool, a search tool or a ur://evs resource reaches.
	McpTargetRepo McpTargetKind = iota + 1
	// A statement filed to the authorization log, or an approval statement.
	McpTargetStatement
	// A record_append of one kind.
	McpTargetRecordAppend
	// A person's act in the team directory (16.11).
	McpTargetDirectoryAct
	// A DROP push or its cancel (§11.7).
	McpTargetDrop
)

// How a call reaches a repo.
type McpRepoOperation int

const (
	// evs_repos naming the repo, its contents untouched.
	McpRepoName McpRepoOperation = iota + 1
	// evs_list naming paths.
	McpRepoList
	// evs_read, evs_history or evs_drop_preview reading, or a ur://evs read or subscription.
	McpRepoRead
	// evs_write.
	McpRepoWrite
	// evs_delete.
	McpRepoDelete
	// A search tool's.
	McpRepoSearch
)

// One thing a call would touch.
type McpTarget struct {
	Kind McpTargetKind

	// McpTargetRepo's: the repo's kind at the call's state, the operation, the ref and the path, "" for the repo as a
	// whole. A repo the state does not hold has kind UNSPECIFIED, which every row refuses but naming.
	RepoKind  protocol.RepoKind
	Operation McpRepoOperation
	Ref       string
	Path      string

	// McpTargetStatement's: its type, and for an acl or bridge statement, whether the tool checked it is one of this
	// sidecar's own-resource filings, or for an ApprovalDecision, whether it is the daemon's own harness decision.
	SignedType      bridge.SignedType
	OwnResource     bool
	HarnessDecision bool

	// McpTargetRecordAppend's.
	RecordKind sidecar.RecordKind
}

// The search index's files (§11.14): the directory on a file-mode ref and the companion ref.
const (
	mcpIndexDirectoryPrefix = ".ur-index/"
	mcpIndexRefName         = "ur/index"
	// a vault's harness config (QD-104)
	mcpVaultHarnessPrefix = "harness/"
	// a mailbox's vault entries (QD-673)
	mcpMailboxVaultPrefix = "vault/"
)

// The own-resource filings a tool may make from MCP, under its tier (§16.6).
var mcpOwnResourceStatements = []bridge.SignedType{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE,
	bridge.SignedType_SIGNED_GRANT_REVOKE,
	bridge.SignedType_SIGNED_BRIDGE_ROUTE,
	bridge.SignedType_SIGNED_BRIDGE_MAP,
	bridge.SignedType_SIGNED_BRIDGE_ADDRESS,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
}

// The record_append kinds (16.8).
var mcpRecordAppendKinds = []sidecar.RecordKind{
	sidecar.RecordKindClaim, sidecar.RecordKindHandoff, sidecar.RecordKindAsk,
	sidecar.RecordKindAnswer, sidecar.RecordKindCheck, sidecar.RecordKindNote,
}

// One row of the table: its refusal and what it refuses.
type mcpGuardRow struct {
	refusal *McpError
	refuses func(target *McpTarget) bool
}

// Whether a repo target is a write.
func (self *McpTarget) repoWrite() bool {
	return self.Operation == McpRepoWrite || self.Operation == McpRepoDelete
}

// Whether a repo target is on the search index's files.
func (self *McpTarget) onIndex() bool {
	return self.Ref == mcpIndexRefName || strings.HasPrefix(self.Path, mcpIndexDirectoryPrefix)
}

// §16.6's table, in its order.
var mcpGuardRows = []mcpGuardRow{
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reaches a secret repo", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_SECRET
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reads or writes the config repo: use team_members, team_agents, acl_grants and acl_check", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_CONFIG && target.Operation != McpRepoName
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reads or writes the search index's files: use the search tools", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.onIndex() && target.Operation != McpRepoList && target.Operation != McpRepoName
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reads or writes the team directory through evs: use the directory tools", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_DIRECTORY && target.Operation != McpRepoName
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never writes a repo of this kind", false),
		refuses: func(target *McpTarget) bool {
			if target.Kind != McpTargetRepo || !target.repoWrite() {
				return false
			}
			switch target.RepoKind {
			case protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_SECRET,
				protocol.RepoKind_REPO_KIND_DIRECTORY, protocol.RepoKind_REPO_KIND_UNSPECIFIED:
				return true
			}
			return false
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never writes the vault's harness config: run ur install-harness in your own terminal", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.repoWrite() && target.RepoKind == protocol.RepoKind_REPO_KIND_VAULT &&
				strings.HasPrefix(target.Path, mcpVaultHarnessPrefix)
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reaches a mailbox's vault entries", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_MAILBOX &&
				strings.HasPrefix(target.Path, mcpMailboxVaultPrefix)
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never reaches a repo this network does not hold", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_UNSPECIFIED && target.Operation != McpRepoName
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP signs no authority, acl, bridge or approval statement but this sidecar's own filings: use ur in your own terminal", false),
		refuses: func(target *McpTarget) bool {
			if target.Kind != McpTargetStatement {
				return false
			}
			switch {
			case target.SignedType == bridge.SignedType_SIGNED_APPROVAL_DECISION:
				return !target.HarnessDecision
			case contains(mcpOwnResourceStatements, target.SignedType):
				return !target.OwnResource
			}
			return true
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "record_append takes claim, handoff, ask, answer, check and note only", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetRecordAppend && !contains(mcpRecordAppendKinds, target.RecordKind)
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "the directory's decisions, announcements and erasures are a person's, outside MCP", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetDirectoryAct
		},
	},
	{
		refusal: NewMcpError(McpCodeRefused, "MCP never drops a version or cancels a drop: a person drops from a device", false),
		refuses: func(target *McpTarget) bool {
			return target.Kind == McpTargetDrop
		},
	},
}

// Whether values holds value.
func contains[T comparable](values []T, value T) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

// The refusal of the first target a row refuses, nil when every target passes. A target of no kind this table knows
// is refused, so a new kind a tool reports cannot pass unjudged.
func McpGuard(targets []McpTarget) *McpError {
	for i := range targets {
		if refusal := mcpGuardRefusal(&targets[i]); refusal != nil {
			return refusal
		}
	}
	return nil
}

// Whether one target passes: what a listing asks of each item it would name.
func McpGuardAdmits(target McpTarget) bool {
	return mcpGuardRefusal(&target) == nil
}

// The first row's refusal of one target, nil when none refuses.
func mcpGuardRefusal(target *McpTarget) *McpError {
	switch target.Kind {
	case McpTargetRepo, McpTargetStatement, McpTargetRecordAppend, McpTargetDirectoryAct, McpTargetDrop:
	default:
		return NewMcpError(McpCodeRefused, "the tool touches something the guard does not judge", false)
	}
	if target.Kind == McpTargetRepo && (target.Operation < McpRepoName || McpRepoSearch < target.Operation) {
		return NewMcpError(McpCodeRefused, "the tool reaches a repo in a way the guard does not judge", false)
	}
	for _, row := range mcpGuardRows {
		if row.refuses(target) {
			return row.refusal
		}
	}
	return nil
}
