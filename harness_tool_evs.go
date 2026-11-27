//go:build !ios_extension && !sidecar_http

// The evs tools in process (DESIGN-COMPUTE §7.5's evs_* row; DESIGN §16.5, §16.6; R-HARN-8, I-7, I-9, D-MCP-16,
// D-MCP-17; HARN-M11-06): evs_repos, evs_list, evs_history and evs_read at R, evs_write and evs_delete at W, O for a
// shared repo's agent-config files, as MCP's tools of the same names (mcp/tools_evs.go) on every leg the Harness runs,
// with the same arguments, results, tiers and refusals. What the Harness does in MCP's framework's place:
//
//	guard      every call names what it reaches to harnessGuard (harness_guard.go) before anything is read: never a
//	           secret repo, the config's contents, the team directory, the search index's files, approved-recipient
//	           records, a mailbox's vault/ family, a vault's harness/ config, nor a write under an agents' inbox
//	           (§20.4). A listing omits refused items and names the index's files only when asked (include_index)
//	allow      §8's local allow of read, or write, on the repo for the sidecar the Harness runs on
//	reads      over EvsRepo with the read's purpose and the call's run in its context, so an owner-bound repo's
//	           receipt gate holds as it does for MCP (EVS1-M3-01's gate, D-MCP-18)
//	trust      by the version's push's sealed provenance (EvsFileInfo.Provenance): untrusted where a tainted run wrote
//	           it, an import brought it in, its agent's signature was refused, or the read gives none, and reading it
//	           taints the run, write-ahead, before its bytes are in the result, fenced (DESIGN §16.6); else own for this
//	           sidecar's version, member for another's
//	writes     a push sealing the run's tainted bit as the call reads it and the agent's id, its registered name the
//	           commit's label; a file-mode ref by path CAS on base_version, a git-mode ref through the local tier's
//	           WriteAtTip, which the phone and browser legs answer EVS_GIT_REF
//	outward    a write or delete of an agent-config file (SidecarIngestSettings.AgentConfigPaths) in a shared repo is
//	           O: the tool's before-hook builds the action through NewCanonicalAction and HarnessRun.Authorize waits
//	           on approval_pending until a person decides, the evs effect pushing once the gate reserves its use
//	secrets    a shared repo's write whose content the redactor's scan matches is refused (R-MCP-5)
//
// evs_drop_preview is MCP's alone: the Harness's local profile reaches no admin's dry run. The enclave profile's
// reach and the private mark on a read of the mailbox or a vault file are HARN-M14-06's.

package sidecar

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
)

// The tools' names, MCP's.
const (
	HarnessToolEvsRepos   = "evs_repos"
	HarnessToolEvsList    = "evs_list"
	HarnessToolEvsHistory = "evs_history"
	HarnessToolEvsRead    = "evs_read"
	HarnessToolEvsWrite   = "evs_write"
	HarnessToolEvsDelete  = "evs_delete"
)

// The tools' descriptions, MCP's text: fixed by the build.
const (
	harnessEvsReposDescription   = "Lists the repos this sidecar may read in the network, by id and kind, and whether it may write each; secret repos are never named."
	harnessEvsListDescription    = "Lists a directory of a repo at its newest version: each child's name and kind. The search index's files are named only when asked."
	harnessEvsHistoryDescription = "Lists a path's versions, newest first: each version's number, its push, its signer, its time and whether it removed the path."
	harnessEvsReadDescription    = "Reads a file of a repo, its newest version or an older one, or the file a search hit names by its hit id; content a tainted run wrote, or an import brought in from outside, comes back marked untrusted, and reading it taints the run."
	harnessEvsWriteDescription   = "Writes a file of a repo on the version it was read at, as one signed push; a shared repo's agent-config file is an outward action that waits for approval."
	harnessEvsDeleteDescription  = "Removes a file of a repo on the version it was read at, as one signed push; a shared repo's agent-config file is an outward action that waits for approval."
)

// The tools' argument schemas, MCP's arguments but network, which the Harness's own network fixes.
var (
	harnessEvsReposSchema = []byte(`{"type":"object","properties":{},"additionalProperties":false}`)
	harnessEvsListSchema  = []byte(`{"type":"object","properties":{` +
		`"repo":{"type":"string","description":"The repo's id."},` +
		`"path":{"type":"string","description":"A directory, empty for the root."},` +
		`"include_index":{"type":"boolean","description":"Names the search index's files too."}},` +
		`"required":["repo"],"additionalProperties":false}`)
	harnessEvsHistorySchema = []byte(`{"type":"object","properties":{` +
		`"repo":{"type":"string","description":"The repo's id."},` +
		`"path":{"type":"string","description":"The path: names joined by /."}},` +
		`"required":["repo","path"],"additionalProperties":false}`)
	harnessEvsReadSchema = []byte(`{"type":"object","properties":{` +
		`"repo":{"type":"string","description":"The repo's id."},` +
		`"path":{"type":"string","description":"The path: names joined by /."},` +
		`"version":{"type":"integer","minimum":0,"description":"An older version of the path, 0 the newest."},` +
		`"hit":{"type":"string","description":"A file's search hit, its hit_id, in place of repo, path and version."}},` +
		`"additionalProperties":false}`)
	harnessEvsWriteSchema = []byte(`{"type":"object","properties":{` +
		`"repo":{"type":"string","description":"The repo's id."},` +
		`"path":{"type":"string","description":"The path: names joined by /."},` +
		`"content":{"type":"string","description":"The file's new content."},` +
		`"base_version":{"type":"integer","minimum":0,"description":"The path's version the content was made on, 0 for a path that does not stand."},` +
		`"message":{"type":"string","description":"A git-mode ref's commit message."},` +
		`"versioning":{"type":"string","enum":["on","off"],"description":"Omitted, the path's own."}},` +
		`"required":["repo","path","content","base_version"],"additionalProperties":false}`)
	harnessEvsDeleteSchema = []byte(`{"type":"object","properties":{` +
		`"repo":{"type":"string","description":"The repo's id."},` +
		`"path":{"type":"string","description":"The path: names joined by /."},` +
		`"base_version":{"type":"integer","minimum":0,"description":"The path's version the removal was made on."}},` +
		`"required":["repo","path","base_version"],"additionalProperties":false}`)
)

// The ref every tool reads and writes: §16.2's tools write main.
const harnessEvsMainRef = "main"

// The search index's directory on a file-mode ref (§11.14), whose names evs_list gives only when asked.
const harnessEvsIndexName = ".ur-index"

// CanonicalAction's version that carries field 37, format 2's versioning (§16.8).
const harnessCanonicalActionVersionVersioning = 2

// What a pending drop's version reads with (§16.5), MCP's text.
const harnessEvsDropPendingWarning = "a drop lists this version: from not_before_millis its history is dropped, and it reads no more"

// The evs tools' refusals, each constant, MCP's meaning in the Harness's words.
var (
	errHarnessEvsUnavailable = errors.New("this sidecar holds no evs client for the network yet: the person can run ur status in their own terminal")
	errHarnessEvsRepo        = errors.New("repo is a repo's id")
	errHarnessEvsPath        = errors.New("path is names joined by /, with no empty name")
	errHarnessEvsErased      = errors.New("this version was erased")
	errHarnessEvsAbsent      = errors.New("nothing stands at that path")
	errHarnessEvsConflict    = errors.New("the path moved past base_version: read it again and write on its version")
	errHarnessEvsGitRef      = errors.New("EVS_GIT_REF: the repo's ref is git-mode, and this device has no local tier to commit through")
	errHarnessEvsVersioning  = errors.New("versioning off is refused here: outside format 2, in a locked repo or on a git-mode ref every version is kept")
	errHarnessEvsCollected   = errors.New("this version was replaced and is versionless, so evs keeps none of its content: read the path's newest version")
	errHarnessEvsDropped     = errors.New("EVS_DROPPED: this version's history was dropped, so nothing of it is read")
	errHarnessEvsSecret      = errors.New("the content holds what reads as a secret, which a shared repo never takes: write it to your vault, or leave it out")
	errHarnessEvsTooLarge    = errors.New("the file is past what a read in the Harness holds: the person can read it with ur evs in their own terminal")
	errHarnessEvsOutward     = errors.New("this write is outward and could not go through the gate")
	errHarnessEvsUncertain   = errors.New("the write's outcome is not known yet: send the same call again")
	errHarnessEvsReceipt     = errors.New("this repo's owner reads a receipt of every read first, and this device cannot deposit one now")
	errHarnessEvsTipMoved    = errors.New("the repo's tip moved on each of this device's tries while the path stood still: send the same call again")
	errHarnessEvsStale       = errors.New("the repo's head moved past this read on each of this device's tries: send the same call again")
	errHarnessEvsGitRefused  = errors.New("the repo's ref refused the commit")
	errHarnessEvsUnchanged   = errors.New("the write changes nothing: the path holds that content already, or a removal names a path the ref lacks")
	errHarnessEvsInvalid     = errors.New("the repo takes no such write: content past its file bound, or a name or label it cannot carry")
	errHarnessEvsPrefixRule  = errors.New("EVS_PREFIX_RULE: the repo's prefix rules hold this path")
	errHarnessEvsVersionArg  = errors.New("versioning is on or off, or omitted for the path's own")
)

// EVS_PREFIX_RULE's answers by detail, MCP's.
var errHarnessEvsPrefixRules = map[string]error{
	"refused":     errors.New("EVS_PREFIX_RULE (refused): the repo's prefix rules do not give this device the path"),
	"pending":     errors.New("EVS_PREFIX_RULE (pending): a rule set of the repo is not readable on this device yet"),
	"update":      errors.New("EVS_PREFIX_RULE (update): a rule set of the repo needs a later release"),
	"depth":       errors.New("EVS_PREFIX_RULE (depth): too many ignored versions lie over the path"),
	"unavailable": errors.New("EVS_PREFIX_RULE (unavailable): the version the rules allow is gone from evs and this device holds no copy"),
	"base":        errors.New("EVS_PREFIX_RULE (base): a new shared branch holds a file outside this device's prefixes"),
	"tag":         errors.New("EVS_PREFIX_RULE (tag): a tag reaches a file outside this device's prefixes"),
}

// Registers the six tools.
func init() {
	registerHarnessDesignTool(HarnessToolEvsRepos, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsRepos, description: harnessEvsReposDescription,
			schema: harnessEvsReposSchema, tier: HarnessToolTierRead, execute: harnessEvsRepos}
	})
	registerHarnessDesignTool(HarnessToolEvsList, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsList, description: harnessEvsListDescription,
			schema: harnessEvsListSchema, tier: HarnessToolTierRead, execute: harnessEvsList}
	})
	registerHarnessDesignTool(HarnessToolEvsHistory, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsHistory, description: harnessEvsHistoryDescription,
			schema: harnessEvsHistorySchema, tier: HarnessToolTierRead, execute: harnessEvsHistoryCall}
	})
	registerHarnessDesignTool(HarnessToolEvsRead, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsRead, description: harnessEvsReadDescription,
			schema: harnessEvsReadSchema, tier: HarnessToolTierRead, execute: harnessEvsReadCall}
	})
	registerHarnessDesignTool(HarnessToolEvsWrite, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsWrite, description: harnessEvsWriteDescription,
			schema: harnessEvsWriteSchema, tier: HarnessToolTierWrite, runTier: harnessEvsWriteTier,
			outward: harnessEvsWriteOutward, execute: harnessEvsWriteCall}
	})
	registerHarnessDesignTool(HarnessToolEvsDelete, func(harness *Harness) *harnessDesignTool {
		return &harnessDesignTool{harness: harness, name: HarnessToolEvsDelete, description: harnessEvsDeleteDescription,
			schema: harnessEvsDeleteSchema, tier: HarnessToolTierWrite, runTier: harnessEvsWriteTier,
			outward: harnessEvsWriteOutward, execute: harnessEvsWriteCall}
	})
}

// The repo a call names, its id parsed.
func harnessEvsRepoId(text string) (Id, error) {
	repoId, err := ParseId(text)
	if err != nil || repoId == (Id{}) {
		return Id{}, errHarnessEvsRepo
	}
	return repoId, nil
}

// A path a call names: names joined by /, none empty, "" the root alone where root is allowed.
func harnessEvsPath(path string, root bool) (string, error) {
	if path == "" {
		if root {
			return "", nil
		}
		return "", errHarnessEvsPath
	}
	if !utf8.ValidString(path) {
		return "", errHarnessEvsPath
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			return "", errHarnessEvsPath
		}
	}
	return path, nil
}

// A directory's path and a child's name joined.
func harnessEvsJoin(directory string, name string) string {
	if directory == "" {
		return name
	}
	return directory + "/" + name
}

// A repo kind's name: general, record, config, directory, team_record, mailcfg, vault, mailbox or secret.
func harnessRepoKindName(kind protocol.RepoKind) string {
	return strings.TrimPrefix(strings.ToLower(kind.String()), "repo_kind_")
}

// Whether a repo is shared: one its owner's devices alone do not read, so not vault, mailbox or secret.
func harnessEvsShared(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		return false
	}
	return true
}

// The guard's target of a call reaching repoId's path by operation, at the network's state: a general repo's rcpt/
// family judged by a complete view of mailcfg, and its inbox/ by whether it is the Team inbox.
func harnessEvsTarget(ctx context.Context, network harnessDesignNetwork, repoId Id, operation harnessRepoOperation, path string) harnessGuardTarget {
	kind := network.RepoKind(repoId)
	target := harnessGuardTarget{Kind: harnessTargetRepo, RepoKind: kind, Operation: operation, Ref: harnessEvsMainRef, Path: path}
	if kind == protocol.RepoKind_REPO_KIND_GENERAL && harnessGuardRecipientPath(path) {
		inboxes, err := network.MailGroupInboxes(ctx)
		target.OrdinaryFileRepo = err == nil && inboxes != nil && !inboxes[repoId]
	}
	if kind == protocol.RepoKind_REPO_KIND_GENERAL && harnessGuardAgentsInboxPath(path) {
		target.TeamInbox = network.AgentsInboxRepo(repoId)
	}
	return target
}

// The network's repo calls for repoId, refused where it holds no evs client.
func harnessEvsRepoOf(network harnessDesignNetwork, repoId Id) (harnessEvsRepo, error) {
	repo := network.EvsRepo(repoId)
	if repo == nil {
		return nil, errHarnessEvsUnavailable
	}
	return repo, nil
}

// An evs error as a tool answers it, by constant text, never a path (I-13).
func harnessEvsError(err error) error {
	var conflict *EvsPathConflictError
	switch {
	case errors.As(err, &conflict), errors.Is(err, ErrEvsPathMoved):
		return errHarnessEvsConflict
	case errors.Is(err, ErrEvsGitRef):
		return errHarnessEvsGitRef
	case errors.Is(err, ErrEvsErased):
		return errHarnessEvsErased
	case errors.Is(err, ErrEvsDropped):
		return errHarnessEvsDropped
	case errors.Is(err, ErrEvsCollected):
		return errHarnessEvsCollected
	case errors.Is(err, ErrEvsPathAbsent):
		return errHarnessEvsAbsent
	case errors.Is(err, ErrEvsFormatUnsupported):
		return errHarnessEvsVersioning
	case errors.Is(err, ErrEvsReceiptGate):
		return errHarnessEvsReceipt
	case harnessEvsGitTipMoved(err):
		return errHarnessEvsTipMoved
	case errors.Is(err, ErrEvsReadStale):
		return errHarnessEvsStale
	case errors.Is(err, ErrEvsGitOutcomePending):
		return errHarnessEvsUncertain
	case errors.Is(err, ErrEvsGitWriteRefused):
		return errHarnessEvsGitRefused
	case harnessEvsGitUnchanged(err):
		return errHarnessEvsUnchanged
	case errors.Is(err, ErrEvsPrefixRule), errors.Is(err, ErrAclPrefixRule):
		detail := ""
		var evsErr *EvsPrefixRuleError
		var aclErr *AclPrefixRuleError
		switch {
		case errors.As(err, &evsErr):
			detail = string(evsErr.Detail)
		case errors.As(err, &aclErr):
			detail = aclErr.Detail.String()
		}
		if answer, ok := errHarnessEvsPrefixRules[detail]; ok {
			return answer
		}
		return errHarnessEvsPrefixRule
	case errors.Is(err, ErrEvsWriteInvalid):
		return errHarnessEvsInvalid
	}
	return err
}

// A version's setting as the tools name it: on (0), off (1) or index (2), §11.7's.
func harnessEvsVersioningName(versioning uint32) string {
	switch protocol.EvsVersioning(versioning) {
	case protocol.EvsVersioning_EVS_VERSIONING_KEPT:
		return EvsVersioningOn
	case protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS:
		return EvsVersioningOff
	}
	return "index"
}

// An entry kind's name.
func harnessEvsEntryKindName(kind protocol.EvsEntryKind) string {
	return strings.TrimPrefix(strings.ToLower(kind.String()), "evs_entry_")
}

// evs_repos' data, MCP's.
type harnessEvsRepoOut struct {
	RepoId string `json:"repo_id"`
	Kind   string `json:"kind"`
	Write  bool   `json:"write"`
}

type harnessEvsReposOut struct {
	Repos []*harnessEvsRepoOut `json:"repos"`
}

// evs_list's arguments and data, MCP's.
type harnessEvsListIn struct {
	Repo         string `json:"repo"`
	Path         string `json:"path,omitempty"`
	IncludeIndex bool   `json:"include_index,omitempty"`
}

type harnessEvsEntryOut struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Versioning string `json:"versioning,omitempty"`
}

type harnessEvsListOut struct {
	Path        string                `json:"path"`
	HeadVersion uint64                `json:"head_version"`
	Entries     []*harnessEvsEntryOut `json:"entries"`
}

// evs_history's arguments and data, MCP's.
type harnessEvsHistoryIn struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
}

type harnessEvsVersionOut struct {
	Version         uint64 `json:"version"`
	CommitVersion   uint64 `json:"commit_version"`
	PushId          string `json:"push_id"`
	SignerId        string `json:"signer_id"`
	TimeMillis      int64  `json:"time_millis"`
	Removed         bool   `json:"removed,omitempty"`
	Versioning      string `json:"versioning"`
	State           string `json:"state"`
	DropId          string `json:"drop_id,omitempty"`
	DropSignerId    string `json:"drop_signer_id,omitempty"`
	NotBeforeMillis int64  `json:"not_before_millis,omitempty"`
}

type harnessEvsHistoryOut struct {
	Path        string                  `json:"path"`
	HeadVersion uint64                  `json:"head_version"`
	Versions    []*harnessEvsVersionOut `json:"versions"`
}

// evs_read's arguments and data, MCP's.
type harnessEvsReadIn struct {
	Repo    string `json:"repo,omitempty"`
	Path    string `json:"path,omitempty"`
	Version uint64 `json:"version,omitempty"`
	Hit     string `json:"hit,omitempty"`
}

type harnessEvsReadOut struct {
	Path            string `json:"path"`
	Version         uint64 `json:"version"`
	CommitVersion   uint64 `json:"commit_version"`
	SignerId        string `json:"signer_id"`
	TimeMillis      int64  `json:"time_millis"`
	Size            uint64 `json:"size"`
	Encoding        string `json:"encoding"`
	Content         string `json:"content"`
	Versioning      string `json:"versioning"`
	State           string `json:"state"`
	DropId          string `json:"drop_id,omitempty"`
	DropSignerId    string `json:"drop_signer_id,omitempty"`
	NotBeforeMillis int64  `json:"not_before_millis,omitempty"`
	Warning         string `json:"warning,omitempty"`
}

// evs_write's and evs_delete's arguments and data, MCP's.
type harnessEvsWriteIn struct {
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	Content     string `json:"content"`
	BaseVersion uint64 `json:"base_version"`
	Message     string `json:"message,omitempty"`
	Versioning  string `json:"versioning,omitempty"`
}

type harnessEvsDeleteIn struct {
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	BaseVersion uint64 `json:"base_version"`
}

type harnessEvsWriteOut struct {
	// written
	Status  string `json:"status"`
	Version uint64 `json:"version,omitempty"`
	PushId  string `json:"push_id,omitempty"`
}

// evs_repos: the repos the sidecar may read, by id and kind, and whether it may write each; secret repos never named.
func harnessEvsRepos(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	if err := harnessDesignArgs(args, &struct{}{}); err != nil {
		return nil, err
	}
	if network.Identity() == nil {
		return nil, errHarnessDesignUnenrolled
	}
	result := newHarnessDesignResult(call)
	result.SetSource("evs:repos")
	now := tool.now()
	out := &harnessEvsReposOut{Repos: []*harnessEvsRepoOut{}}
	repoIds := harnessGuardOmit(network.RepoIds(), func(repoId Id) harnessGuardTarget {
		return harnessEvsTarget(ctx, network, repoId, harnessRepoName, "")
	})
	for _, repoId := range repoIds {
		readable, installed := network.Allow(protocol.AclAction_ACL_ACTION_READ, AclResource{Kind: AclResourceRepo, RepoId: repoId}, now)
		if !installed {
			return nil, errHarnessDesignNoPolicy
		}
		if !readable.Allowed {
			continue
		}
		writable, _ := network.Allow(protocol.AclAction_ACL_ACTION_WRITE, AclResource{Kind: AclResourceRepo, RepoId: repoId}, now)
		out.Repos = append(out.Repos, &harnessEvsRepoOut{RepoId: repoId.String(), Kind: harnessRepoKindName(network.RepoKind(repoId)), Write: writable.Allowed})
	}
	return result.toolResult(network, out, nil)
}

// evs_list: a directory's children at the newest version, the refused ones omitted.
func harnessEvsList(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	in := &harnessEvsListIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	repoId, err := harnessEvsRepoId(in.Repo)
	if err != nil {
		return nil, err
	}
	path, err := harnessEvsPath(in.Path, true)
	if err != nil {
		return nil, err
	}
	if err := harnessGuard([]harnessGuardTarget{harnessEvsTarget(ctx, network, repoId, harnessRepoList, path)}); err != nil {
		return nil, err
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(repoId, protocol.AclAction_ACL_ACTION_READ)); err != nil {
		return nil, err
	}
	repo, err := harnessEvsRepoOf(network, repoId)
	if err != nil {
		return nil, err
	}
	result := newHarnessDesignResult(call)
	result.Member()
	result.SetSource("evs:" + repoId.String())
	listing, err := repo.List(ctx, &EvsReadArgs{Path: path, Settings: true, IndexFiles: in.IncludeIndex})
	if err != nil {
		return nil, harnessEvsError(err)
	}
	entries := harnessGuardOmit(listing.Entries, func(entry *EvsListEntry) harnessGuardTarget {
		return harnessEvsTarget(ctx, network, repoId, harnessRepoList, harnessEvsJoin(path, string(entry.Name)))
	})
	out := &harnessEvsListOut{Path: path, HeadVersion: listing.HeadVersion, Entries: []*harnessEvsEntryOut{}}
	for _, entry := range entries {
		full := harnessEvsJoin(path, string(entry.Name))
		if !in.IncludeIndex && (full == harnessEvsIndexName || strings.HasPrefix(full, harnessEvsIndexName+"/")) {
			continue
		}
		shown := &harnessEvsEntryOut{Name: string(entry.Name), Kind: harnessEvsEntryKindName(entry.Kind)}
		if entry.Kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
			shown.Versioning = harnessEvsVersioningName(entry.Versioning)
		}
		out.Entries = append(out.Entries, shown)
	}
	return result.toolResult(network, out, nil)
}

// evs_history: a path's versions, newest first.
func harnessEvsHistoryCall(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	in := &harnessEvsHistoryIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	repoId, err := harnessEvsRepoId(in.Repo)
	if err != nil {
		return nil, err
	}
	path, err := harnessEvsPath(in.Path, false)
	if err != nil {
		return nil, err
	}
	if err := harnessGuard([]harnessGuardTarget{harnessEvsTarget(ctx, network, repoId, harnessRepoRead, path)}); err != nil {
		return nil, err
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(repoId, protocol.AclAction_ACL_ACTION_READ)); err != nil {
		return nil, err
	}
	repo, err := harnessEvsRepoOf(network, repoId)
	if err != nil {
		return nil, err
	}
	result := newHarnessDesignResult(call)
	result.Member()
	result.SetSource("evs:" + repoId.String())
	history, err := repo.History(ctx, &EvsReadArgs{Path: path})
	if err != nil {
		return nil, harnessEvsError(err)
	}
	out := &harnessEvsHistoryOut{Path: path, HeadVersion: history.HeadVersion, Versions: []*harnessEvsVersionOut{}}
	for _, version := range history.Versions {
		state := version.State
		if state == "" {
			state = "kept"
		}
		shown := &harnessEvsVersionOut{
			Version:       version.Version,
			CommitVersion: version.CommitVersion,
			PushId:        version.PushId.String(),
			SignerId:      version.SignerSidecarId.String(),
			TimeMillis:    version.Time.UnixMilli(),
			Removed:       version.Removed,
			Versioning:    harnessEvsVersioningName(version.Versioning),
			State:         state,
		}
		if version.DropId != (Id{}) {
			shown.DropId, shown.DropSignerId = version.DropId.String(), version.DropSignerId.String()
			shown.NotBeforeMillis = version.DropNotBefore.UnixMilli()
		}
		out.Versions = append(out.Versions, shown)
	}
	return result.toolResult(network, out, nil)
}

// evs_read's file: its repo, path and version as named, or as its hit names them, a file's hit standing alone.
func harnessEvsReadOf(network harnessDesignNetwork, call *HarnessCall, in *harnessEvsReadIn) (*SearchHitRef, error) {
	if in.Hit == "" {
		repoId, err := harnessEvsRepoId(in.Repo)
		if err != nil {
			return nil, err
		}
		path, err := harnessEvsPath(in.Path, false)
		if err != nil {
			return nil, err
		}
		return &SearchHitRef{RepoId: repoId, Path: path, Version: in.Version}, nil
	}
	if in.Repo != "" || in.Path != "" || in.Version != 0 {
		return nil, errHarnessHitAlone
	}
	ref, err := harnessHitOfKind(network, call, in.Hit, IndexDocFile)
	if err != nil {
		return nil, err
	}
	// only a content ref whose name can be guarded may be opened
	if _, err := harnessEvsPath(ref.Path, false); err != nil || ref.RefName == "id:"+ref.RefId.String() {
		return nil, errHarnessHitKind
	}
	return ref, nil
}

// How a version reads by its signer and its push's sealed provenance: untrusted where the provenance is unknown, a
// tainted run's, an import's or one whose agent signature was refused; else own for this sidecar's, member for another's.
func harnessEvsTrust(info *EvsFileInfo, ownSidecarId Id) string {
	provenance := info.Provenance
	switch {
	case provenance == nil || provenance.Tainted || provenance.Imported || provenance.Refused:
		return harnessDesignTrustUntrusted
	case info.SignerSidecarId == ownSidecarId:
		return harnessDesignTrustOwn
	}
	return harnessDesignTrustMember
}

// A buffer that keeps at most limit bytes and fails the write past them.
type harnessLimitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
	over   bool
}

func (self *harnessLimitedBuffer) Write(p []byte) (int, error) {
	if self.limit < int64(self.buffer.Len()+len(p)) {
		self.over = true
		return 0, errHarnessEvsTooLarge
	}
	return self.buffer.Write(p)
}

// evs_read: one version of a file, its trust by its push's provenance, an untrusted version tainting the run first.
func harnessEvsReadCall(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	in := &harnessEvsReadIn{}
	if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	ref, err := harnessEvsReadOf(network, call, in)
	if err != nil {
		return nil, err
	}
	target := harnessEvsTarget(ctx, network, ref.RepoId, harnessRepoRead, ref.Path)
	if ref.RefName != "" {
		target.Ref = ref.RefName
	}
	if err := harnessGuard([]harnessGuardTarget{target}); err != nil {
		return nil, err
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(ref.RepoId, protocol.AclAction_ACL_ACTION_READ)); err != nil {
		return nil, err
	}
	repo, err := harnessEvsRepoOf(network, ref.RepoId)
	if err != nil {
		return nil, err
	}
	identity := network.Identity()
	if identity == nil {
		return nil, errHarnessDesignUnenrolled
	}
	result := newHarnessDesignResult(call)
	result.SetSource("evs:" + ref.RepoId.String())
	runId := call.Run().Id()
	ctx = WithEvsReadContext(ctx, &EvsReadContext{Purpose: RecordReadPurposeRead, RunId: &runId})
	content := &harnessLimitedBuffer{limit: network.Mcp().ResourceByteCount}
	readArgs := &EvsReadArgs{Path: ref.Path, Version: ref.Version, Provenance: true}
	if ref.RefName != "" {
		readArgs.RefName = []byte(ref.RefName)
	}
	info, err := repo.ReadHead(ctx, readArgs, content)
	if err != nil {
		if content.over {
			return nil, errHarnessEvsTooLarge
		}
		var dropped *EvsDroppedError
		if errors.As(err, &dropped) {
			return nil, errHarnessEvsDropped
		}
		return nil, harnessEvsError(err)
	}
	if in.Hit != "" {
		current, err := harnessHitOfKind(network, call, in.Hit, IndexDocFile)
		if err != nil {
			return nil, err
		}
		if *current != *ref {
			return nil, errHarnessHitUnknown
		}
		if ref.RefName != "" && (info.RefId != ref.RefId || info.Version != ref.Version) {
			return nil, errHarnessHitUnknown
		}
	}
	result.Meter(int64(content.buffer.Len()))
	out := &harnessEvsReadOut{
		Path:          ref.Path,
		Version:       info.Version,
		CommitVersion: info.CommitVersion,
		SignerId:      info.SignerSidecarId.String(),
		TimeMillis:    info.Time.UnixMilli(),
		Size:          info.Size,
		Encoding:      "utf-8",
		Versioning:    harnessEvsVersioningName(info.Versioning),
		State:         "kept",
	}
	if drop := info.Drop; drop != nil {
		out.State = EvsVersionStateDropPending
		out.DropId, out.DropSignerId = drop.DropId.String(), drop.SignerSidecarId.String()
		out.NotBeforeMillis = drop.NotBefore.UnixMilli()
		out.Warning = harnessEvsDropPendingWarning
	}
	text := content.buffer.String()
	if !utf8.ValidString(text) {
		out.Encoding = "base64"
		text = base64.StdEncoding.EncodeToString(content.buffer.Bytes())
	}
	switch harnessEvsTrust(info, identity.SidecarId) {
	case harnessDesignTrustOwn:
	case harnessDesignTrustMember:
		result.Member()
	default:
		// taint before data: the run file is fsynced before these bytes are in the result (D-MCP-16)
		if err := result.Untrusted(ctx); err != nil {
			return nil, err
		}
		text = result.Fence(text)
	}
	out.Content = text
	// the UI's view of a read holds its metadata, its content once, in the text the model reads
	details := *out
	details.Content = ""
	return result.toolResult(network, out, &details)
}

// One evs_write or evs_delete as planned before anything is written: what it reaches, judged by the guard and §8, and
// whether it is the outward case.
type harnessEvsWritePlan struct {
	repoId     Id
	path       string
	base       uint64
	content    []byte
	remove     bool
	message    string
	versioning string
	// a shared repo's agent-config file: O, through HarnessRun.Authorize (§16.5)
	outward bool
}

// The call's plan: its arguments read, the guard and §8's write allow passed, versioning off refused where §11.7
// refuses it, and a shared repo's content scanned for secrets.
func harnessEvsWritePlanOf(ctx context.Context, tool *harnessDesignTool, network harnessDesignNetwork, args []byte) (*harnessEvsWritePlan, error) {
	in := &harnessEvsWriteIn{}
	remove := tool.name == HarnessToolEvsDelete
	if remove {
		deleteIn := &harnessEvsDeleteIn{}
		if err := harnessDesignArgs(args, deleteIn); err != nil {
			return nil, err
		}
		in.Repo, in.Path, in.BaseVersion = deleteIn.Repo, deleteIn.Path, deleteIn.BaseVersion
	} else if err := harnessDesignArgs(args, in); err != nil {
		return nil, err
	}
	switch in.Versioning {
	case EvsVersioningKeepSetting, EvsVersioningOn, EvsVersioningOff:
	default:
		return nil, errHarnessEvsVersionArg
	}
	repoId, err := harnessEvsRepoId(in.Repo)
	if err != nil {
		return nil, err
	}
	path, err := harnessEvsPath(in.Path, false)
	if err != nil {
		return nil, err
	}
	operation := harnessRepoWrite
	if remove {
		operation = harnessRepoDelete
	}
	if err := harnessGuard([]harnessGuardTarget{harnessEvsTarget(ctx, network, repoId, operation, path)}); err != nil {
		return nil, err
	}
	if err := harnessDesignAllow(network, tool.now(), harnessDesignRepoAccess(repoId, protocol.AclAction_ACL_ACTION_WRITE)); err != nil {
		return nil, err
	}
	if in.Versioning == EvsVersioningOff && (!network.EvsFormat2Admitted() || network.EvsRepoLocked(repoId)) {
		return nil, errHarnessEvsVersioning
	}
	plan := &harnessEvsWritePlan{repoId: repoId, path: path, base: in.BaseVersion, remove: remove, message: in.Message,
		versioning: in.Versioning}
	if !remove {
		plan.content = []byte(in.Content)
	}
	shared := harnessEvsShared(network.RepoKind(repoId))
	if shared && !remove {
		scanner, err := NewRedactor(rand.Reader)
		if err != nil {
			return nil, errHarnessEvsSecret
		}
		if 0 < len(scanner.Scan(plan.content)) {
			return nil, errHarnessEvsSecret
		}
	}
	plan.outward = shared && harnessAgentConfigPath(network.Ingest(), path)
	return plan, nil
}

// W, or O for a shared repo's agent-config file. A call whose plan is refused runs at W, where Execute answers the
// refusal before anything is written.
func harnessEvsWriteTier(tool *harnessDesignTool, call *HarnessCall, args []byte) string {
	if tool.harness == nil || tool.harness.network == nil {
		return HarnessToolTierWrite
	}
	plan, err := harnessEvsWritePlanOf(context.Background(), tool, tool.harness.network, args)
	if err != nil || !plan.outward {
		return HarnessToolTierWrite
	}
	return HarnessToolTierOutward
}

// The agent-config write's action, bound to the run and agent by HarnessRun.Authorize, and the evs effect, sealing the
// same agent id and the run's taint as the call reads it. A write that names its versioning carries it as field 37 at
// version 2 (§16.8).
func harnessEvsWriteOutward(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessAuthorizeRequest, error) {
	plan, err := harnessEvsWritePlanOf(ctx, tool, network, args)
	if err != nil {
		return nil, err
	}
	if !plan.outward {
		return nil, ErrHarnessToolUngated
	}
	kind := SidecarActionAgentConfigWrite
	action := &protocol.CanonicalAction{RepoId: plan.repoId.Bytes(), Path: plan.path, BaseVersion: plan.base}
	if plan.remove {
		kind = SidecarActionAgentConfigDelete
	} else {
		sum := sha256.Sum256(plan.content)
		action.ContentSha256 = sum[:]
		switch plan.versioning {
		case EvsVersioningOn:
			action.Version, action.Versioning = harnessCanonicalActionVersionVersioning, uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
		case EvsVersioningOff:
			action.Version, action.Versioning = harnessCanonicalActionVersionVersioning, uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
		}
	}
	action.Kind = uint32(kind)
	stored, err := NewCanonicalAction(action)
	if err != nil {
		return nil, errHarnessEvsOutward
	}
	agentId := call.AgentId()
	effect := &EvsWriteEffect{
		Path: plan.path, BaseVersion: plan.base, Remove: plan.remove, Message: plan.message, AgentLabel: call.AgentName(),
		AgentId: &agentId, Tainted: call.Run().Tainted(), Versioning: plan.versioning,
	}
	if !plan.remove {
		effect.Content = plan.content
	}
	sidecarEffect := network.EvsWriteEffect(plan.repoId, effect)
	if sidecarEffect == nil {
		return nil, errHarnessEvsUnavailable
	}
	return &HarnessAuthorizeRequest{
		Kind:           kind,
		Action:         stored,
		PolicyRisk:     SidecarRiskNormal,
		AgentAskedRisk: SidecarRiskNormal,
		Effect:         sidecarEffect,
	}, nil
}

// evs_write and evs_delete: the W push, or for the outward case what the gate's effect came to.
func harnessEvsWriteCall(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error) {
	plan, err := harnessEvsWritePlanOf(ctx, tool, network, args)
	if err != nil {
		return nil, err
	}
	result := newHarnessDesignResult(call)
	result.SetSource("evs:" + plan.repoId.String())
	if plan.outward {
		outcome := call.Outcome()
		switch {
		case outcome == nil:
			// the before-hook ran no gate for this call: nothing outward runs ungated
			return nil, errHarnessEvsOutward
		case outcome.State == ApprovalOutcomeDone:
			out := &harnessEvsWriteOut{Status: "written"}
			if pushId, pathVersion, err := ParseEvsEffectRef(outcome.EffectRef); err == nil {
				out.Version, out.PushId = pathVersion, pushId.String()
				result.Meter(int64(len(plan.content)))
			}
			return result.toolResult(network, out, nil)
		case outcome.State == ApprovalOutcomeNotDone:
			return nil, errHarnessEvsConflict
		}
		return nil, errHarnessEvsUncertain
	}
	repo, err := harnessEvsRepoOf(network, plan.repoId)
	if err != nil {
		return nil, err
	}
	agentId := call.AgentId()
	// the run's taint as this call finds it, before anything is written: what the push's provenance seals (QD-042)
	tainted := call.Run().Tainted()
	write := &EvsPathWrite{Path: plan.path, Remove: plan.remove, IfBaseVersion: &plan.base}
	if !plan.remove {
		write.Content = bytes.NewReader(plan.content)
		write.Options = &EvsWriteOptions{Versioning: plan.versioning}
	}
	written, err := repo.WritePaths(ctx, &EvsWritePathsArgs{Writes: []*EvsPathWrite{write}, AgentId: &agentId, Tainted: tainted})
	if err == nil {
		result.Meter(int64(len(plan.content)))
		return result.toolResult(network, &harnessEvsWriteOut{Status: "written", Version: written.PathVersions[0], PushId: written.PushId.String()}, nil)
	}
	if !errors.Is(err, ErrEvsGitRef) {
		return nil, harnessEvsError(err)
	}
	if plan.versioning == EvsVersioningOff {
		return nil, errHarnessEvsVersioning
	}
	committed, err := repo.WriteAtTip(ctx, &EvsWriteAtTipArgs{
		Path: plan.path, BaseVersion: plan.base, Content: plan.content, Remove: plan.remove, Message: plan.message,
		AgentLabel: call.AgentName(), AgentId: &agentId, Tainted: tainted,
	})
	if err != nil {
		return nil, harnessEvsError(err)
	}
	result.Meter(int64(len(plan.content)))
	return result.toolResult(network, &harnessEvsWriteOut{Status: "written", Version: committed.PathVersion, PushId: committed.PushId.String()}, nil)
}
