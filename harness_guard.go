//go:build !ios_extension && !sidecar_http

// The Harness's guard (DESIGN-COMPUTE §7.5, DESIGN §16.6's "refused from MCP" table, §20.4's inbox row, D-SKILL-7, I-7,
// I-8; HARN-M11-06): the in-process DESIGN tools (evs_*, search, record_query, record_append) run on every leg the
// Harness runs, and mcp/ links on no phone leg, so the root holds the table MCP's McpGuard holds, as one data-driven
// function. A tool says what a call would touch as harnessGuardTargets before it reaches anything, and the guard
// refuses the call at the first target a row refuses:
//
//	secret          every evs and search call on a repo of kind secret, naming it included
//	config          every evs call on the config repo but evs_repos naming it (QD-205)
//	index           every evs call on the search index's files, .ur-index/ on a file-mode ref and anything on the
//	                ur/index ref, but evs_list naming them when asked (§11.14)
//	directory       every evs call on the team directory but evs_repos naming it and a search reading its index
//	writes          evs_write and evs_delete on repos of kind config, mailcfg, secret and directory
//	harness config  evs_write and evs_delete on a vault's harness/ path (QD-104)
//	mailbox vault   every evs and search call on a mailbox's vault/ family, its directory and shards as well as its
//	                entries (QD-673)
//	recipients      the rcpt/ family on a mailbox or a general repo mailcfg cannot rule out as a group inbox
//	agents' inbox   evs_write and evs_delete of inbox or anything under it in an agent or agents repo or the Team
//	                inbox (DESIGN-COMPUTE §20.4): only agent_send, agent_broadcast and agent_close write a message there
//	unheld repo     every evs call but a naming on a repo this network's state does not hold
//	statements      every authority statement; approval statements but the daemon's own harness decisions; acl and
//	                bridge statements but the own-resource filings a tool checked are this sidecar's own
//	record          record_append of a kind other than claim, handoff, ask, answer, check and note
//	directory acts  the directory's person acts, every one (16.11)
//	drop            DROP pushes and their cancels (§11.7; D-MCP-32)
//
// A refusal names its row, never its target: no path, repo or name reaches its text (I-13). A target of a kind or an
// operation the table does not judge is refused, so a new kind a tool reports cannot pass unjudged. The table is MCP's
// row for row: harness_guard_parity_test.go runs one corpus through both, so a row MCP adds later fails it until the
// Harness has it too. The file never imports mcp.
//
// A listing passes what it would name through harnessGuardOmit, which leaves out each item a row refuses: evs_repos a
// secret repo, evs_list and a search's hits a mailbox's vault/ family.
//
// Package-level functions are safe for concurrent use: the table never changes.

package sidecar

import (
	"errors"
	"slices"
	"strings"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a target is.
type harnessGuardTargetKind int

const (
	// A repo's files or names, which an evs tool or a search reaches.
	harnessTargetRepo harnessGuardTargetKind = iota + 1
	// A statement filed to the authorization log, or an approval statement.
	harnessTargetStatement
	// A record_append of one kind.
	harnessTargetRecordAppend
	// A person's act in the team directory (16.11).
	harnessTargetDirectoryAct
	// A DROP push or its cancel (§11.7).
	harnessTargetDrop
)

// How a call reaches a repo.
type harnessRepoOperation int

const (
	// evs_repos naming the repo, its contents untouched.
	harnessRepoName harnessRepoOperation = iota + 1
	// evs_list naming paths: the path it lists, and each path it would name.
	harnessRepoList
	// evs_read or evs_history reading.
	harnessRepoRead
	// evs_write.
	harnessRepoWrite
	// evs_delete.
	harnessRepoDelete
	// A search's: the repo it searches under its path_prefix filter, and each hit it would name.
	harnessRepoSearch
)

// One thing a call would touch.
type harnessGuardTarget struct {
	Kind harnessGuardTargetKind

	// harnessTargetRepo's: the repo's kind at the call's state, the operation, the ref and the whole path from the
	// ref's root, "" for the repo as a whole. A repo the state does not hold has kind UNSPECIFIED.
	RepoKind  protocol.RepoKind
	Operation harnessRepoOperation
	Ref       string
	Path      string
	// A complete, verified view of mailcfg ruled out a group inbox for this general repo.
	OrdinaryFileRepo bool
	// This general repo is the network's Team inbox, or the network could not say it is not: its inbox/ takes
	// messages only (§20.4).
	TeamInbox bool

	// harnessTargetStatement's: its type, and for an acl or bridge statement, whether the tool checked it is one of
	// this sidecar's own-resource filings, or for an ApprovalDecision, whether it is the daemon's own harness decision.
	SignedType      bridge.SignedType
	OwnResource     bool
	HarnessDecision bool

	// harnessTargetRecordAppend's.
	RecordKind RecordKind

	// harnessTargetDirectoryAct's: which person act, for the tool's own account. Every value is refused.
	DirectoryAct int
}

// What every refusal wraps.
var ErrHarnessGuardRefused = errors.New("the harness guard refused the call")

// A call the guard refused: the row that refused it and its text, which names the row and never the target.
type HarnessGuardError struct {
	// The row's name, as the file header lists them.
	Row  string
	text string
}

// The row's text.
func (self *HarnessGuardError) Error() string {
	return self.text
}

// Matches ErrHarnessGuardRefused.
func (self *HarnessGuardError) Is(target error) bool {
	return target == ErrHarnessGuardRefused
}

// The rows' names, as refusals carry them.
const (
	harnessGuardRowSecret          = "secret"
	harnessGuardRowConfig          = "config"
	harnessGuardRowIndex           = "index"
	harnessGuardRowDirectory       = "directory"
	harnessGuardRowWrites          = "writes"
	harnessGuardRowHarnessConfig   = "harness config"
	harnessGuardRowMailboxVault    = "mailbox vault"
	harnessGuardRowRecipients      = "recipients"
	harnessGuardRowAgentsInbox     = "agents' inbox"
	harnessGuardRowUnheld          = "unheld repo"
	harnessGuardRowStatements      = "statements"
	harnessGuardRowRecord          = "record"
	harnessGuardRowDirectoryActs   = "directory acts"
	harnessGuardRowDrop            = "drop"
	harnessGuardRowUnjudged        = "unjudged"
	harnessGuardRowUnjudgedOperate = "unjudged operation"
)

// The search index's files (§11.14), the vault's harness config (QD-104), a mailbox's vault entries' family
// (§15.7; QD-673) and an agents' inbox (§20.4): the names MCP's guard holds.
const (
	harnessGuardIndexDirectoryPrefix = ".ur-index/"
	harnessGuardIndexRefName         = "ur/index"
	harnessGuardVaultHarnessPrefix   = "harness/"
	harnessGuardMailboxVaultFamily   = "vault"
	harnessGuardRecipientFamily      = "rcpt"
	harnessGuardAgentsInboxDirectory = "inbox"
)

// The own-resource filings a tool may make, under its tier (§16.6).
var harnessGuardOwnResourceStatements = []bridge.SignedType{
	bridge.SignedType_SIGNED_GRANT_ACTIVATE,
	bridge.SignedType_SIGNED_GRANT_REVOKE,
	bridge.SignedType_SIGNED_BRIDGE_ROUTE,
	bridge.SignedType_SIGNED_BRIDGE_MAP,
	bridge.SignedType_SIGNED_BRIDGE_ADDRESS,
	bridge.SignedType_SIGNED_BRIDGE_WITHDRAW,
}

// The record_append kinds (16.8).
var harnessGuardRecordAppendKinds = []RecordKind{
	RecordKindClaim, RecordKindHandoff, RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote,
}

// One row of the table: its refusal and what it refuses.
type harnessGuardRow struct {
	refusal *HarnessGuardError
	refuses func(target *harnessGuardTarget) bool
}

// A refusal of row with text.
func newHarnessGuardRefusal(row string, text string) *HarnessGuardError {
	return &HarnessGuardError{Row: row, text: text}
}

// Whether a repo target is a write.
func (self *harnessGuardTarget) repoWrite() bool {
	return self.Operation == harnessRepoWrite || self.Operation == harnessRepoDelete
}

// Whether a repo target is on the search index's files.
func (self *harnessGuardTarget) onIndex() bool {
	return self.Ref == harnessGuardIndexRefName || strings.HasPrefix(self.Path, harnessGuardIndexDirectoryPrefix)
}

// Whether a repo target is on a mailbox's vault/ family: its directory, a shard or an entry.
func (self *harnessGuardTarget) onMailboxVault() bool {
	return self.RepoKind == protocol.RepoKind_REPO_KIND_MAILBOX && harnessGuardFamily(self.Path, harnessGuardMailboxVaultFamily)
}

// Whether path is family's directory or anything under it.
func harnessGuardFamily(path string, family string) bool {
	return path == family || strings.HasPrefix(path, family+"/")
}

// The approved recipients' directory, shards and records.
func harnessGuardRecipientPath(path string) bool {
	return harnessGuardFamily(path, harnessGuardRecipientFamily)
}

// An agents' inbox: the directory and everything under it (§20.4).
func harnessGuardAgentsInboxPath(path string) bool {
	return harnessGuardFamily(path, harnessGuardAgentsInboxDirectory)
}

// The table, in §16.6's order, as MCP's guard holds it.
var harnessGuardRows = []harnessGuardRow{
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowSecret, "the Harness never reaches a secret repo"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_SECRET
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowConfig, "the Harness never reads or writes the config repo"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_CONFIG && target.Operation != harnessRepoName
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowIndex, "the Harness never reads or writes the search index's files: use search"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.onIndex() && target.Operation != harnessRepoList && target.Operation != harnessRepoName
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowDirectory, "the Harness never reads or writes the team directory through evs"),
		refuses: func(target *harnessGuardTarget) bool {
			// a search reads it through its index, its prose withheld as stubs unless the run is tainted first
			return target.Kind == harnessTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_DIRECTORY &&
				target.Operation != harnessRepoName && target.Operation != harnessRepoSearch
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowWrites, "the Harness never writes a repo of this kind"),
		refuses: func(target *harnessGuardTarget) bool {
			if target.Kind != harnessTargetRepo || !target.repoWrite() {
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
		refusal: newHarnessGuardRefusal(harnessGuardRowHarnessConfig, "the Harness never writes the vault's harness config: run ur install-harness in your own terminal"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.repoWrite() && target.RepoKind == protocol.RepoKind_REPO_KIND_VAULT &&
				strings.HasPrefix(target.Path, harnessGuardVaultHarnessPrefix)
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowMailboxVault, "the Harness never reaches a mailbox's vault entries"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.onMailboxVault()
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowRecipients, "the Harness never reaches approved-recipient records"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && harnessGuardRecipientPath(target.Path) &&
				(target.RepoKind == protocol.RepoKind_REPO_KIND_MAILBOX ||
					target.RepoKind == protocol.RepoKind_REPO_KIND_GENERAL && !target.OrdinaryFileRepo)
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowAgentsInbox, "an agents' inbox takes messages only: use agent_send, agent_broadcast and agent_close"),
		refuses: func(target *harnessGuardTarget) bool {
			if target.Kind != harnessTargetRepo || !target.repoWrite() || !harnessGuardAgentsInboxPath(target.Path) {
				return false
			}
			switch target.RepoKind {
			case protocol.RepoKind_REPO_KIND_AGENTS, protocol.RepoKind_REPO_KIND_AGENT:
				return true
			case protocol.RepoKind_REPO_KIND_GENERAL:
				return target.TeamInbox
			}
			return false
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowUnheld, "the Harness never reaches a repo this network does not hold"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRepo && target.RepoKind == protocol.RepoKind_REPO_KIND_UNSPECIFIED && target.Operation != harnessRepoName
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowStatements, "the Harness signs no authority, acl, bridge or approval statement but this sidecar's own filings: use ur in your own terminal"),
		refuses: func(target *harnessGuardTarget) bool {
			if target.Kind != harnessTargetStatement {
				return false
			}
			switch {
			case target.SignedType == bridge.SignedType_SIGNED_APPROVAL_DECISION:
				return !target.HarnessDecision
			case slices.Contains(harnessGuardOwnResourceStatements, target.SignedType):
				return !target.OwnResource
			}
			return true
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowRecord, "record_append takes claim, handoff, ask, answer, check and note only"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetRecordAppend && !slices.Contains(harnessGuardRecordAppendKinds, target.RecordKind)
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowDirectoryActs, "the directory's decisions, announcements and erasures are a person's, outside the Harness"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetDirectoryAct
		},
	},
	{
		refusal: newHarnessGuardRefusal(harnessGuardRowDrop, "the Harness never drops a version or cancels a drop: a person drops from a device"),
		refuses: func(target *harnessGuardTarget) bool {
			return target.Kind == harnessTargetDrop
		},
	},
}

// The refusals of a target the table does not judge.
var (
	errHarnessGuardUnjudged         = newHarnessGuardRefusal(harnessGuardRowUnjudged, "the tool touches something the guard does not judge")
	errHarnessGuardUnjudgedOperated = newHarnessGuardRefusal(harnessGuardRowUnjudgedOperate, "the tool reaches a repo in a way the guard does not judge")
)

// The refusal of the first target a row refuses, nil when every target passes.
func harnessGuard(targets []harnessGuardTarget) error {
	for i := range targets {
		if refusal := harnessGuardRefusal(&targets[i]); refusal != nil {
			return refusal
		}
	}
	return nil
}

// Whether one target passes: what a listing asks of each item it would name.
func harnessGuardAdmits(target harnessGuardTarget) bool {
	return harnessGuardRefusal(&target) == nil
}

// The items a listing would name that the guard admits, in their order, each judged by the target targetOf gives it.
// An item a row refuses is left out, never named; the call itself passed harnessGuard on what it lists.
func harnessGuardOmit[T any](items []T, targetOf func(item T) harnessGuardTarget) []T {
	kept := make([]T, 0, len(items))
	for _, item := range items {
		if harnessGuardAdmits(targetOf(item)) {
			kept = append(kept, item)
		}
	}
	return kept
}

// The first row's refusal of one target, nil when none refuses.
func harnessGuardRefusal(target *harnessGuardTarget) *HarnessGuardError {
	switch target.Kind {
	case harnessTargetRepo, harnessTargetStatement, harnessTargetRecordAppend, harnessTargetDirectoryAct, harnessTargetDrop:
	default:
		return errHarnessGuardUnjudged
	}
	if target.Kind == harnessTargetRepo && (target.Operation < harnessRepoName || harnessRepoSearch < target.Operation) {
		return errHarnessGuardUnjudgedOperated
	}
	for _, row := range harnessGuardRows {
		if row.refuses(target) {
			return row.refusal
		}
	}
	return nil
}

// Whether path is one of ingest's agent-config paths (§16.5's evs_write row): a bare name matching the path's last
// name, or a path matching it whole or as its suffix after a /. MCP's McpAgentConfigPath reads the same list the same
// way, which the parity test holds.
func harnessAgentConfigPath(ingest *SidecarIngestSettings, path string) bool {
	if ingest == nil {
		return false
	}
	name := path
	if index := strings.LastIndexByte(path, '/'); 0 <= index {
		name = path[index+1:]
	}
	for _, entry := range ingest.AgentConfigPaths {
		if !strings.Contains(entry, "/") {
			if name == entry {
				return true
			}
			continue
		}
		if path == entry || strings.HasSuffix(path, "/"+entry) {
			return true
		}
	}
	return false
}
