//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's evs tools (R-MCP-5, R-MCP-9, D-MCP-8, D-MCP-13, D-MCP-17, D-MCP-18, D-MCP-32, I-7, I-9, FS-30; MCP-M3-13,
// MCP-M10-01): evs_repos, evs_list, evs_history, evs_read and evs_drop_preview at R, evs_write and evs_delete at W,
// outward for a shared repo's agent-config files. ur://evs/{repo}/{+path} is resources_evs.go's.
//
//	guard      every call names what it reaches to McpGuard (§16.6's refused table, guard.go): never a secret repo,
//	           the config's contents, the team directory, the search index's files, approved-recipient records,
//	           a mailbox's vault/ family or a vault's harness/ config. A listing omits refused items and names the
//	           index's files only when asked (include_index)
//	allow      §8's local allow of read, or write, on the repo for this sidecar
//	reads      over EvsRepo, the read's purpose and run in its context, so an owner-bound repo's reader that is not
//	           its writer deposits its receipt and awaits evs's 200 before anything decrypts (EVS1-M3-01's gate,
//	           D-MCP-18); a first read that cannot deposit is refused, the gate's own refusal
//	trust      by the version's push's sealed provenance, which the read asks EvsRepo for (EvsReadArgs.Provenance,
//	           EvsFileInfo.Provenance; QD-042, QD-851; plan-MCP-format1-tainted-files): untrusted where a tainted run
//	           wrote it, a signed import brought it in, its agent's subkey signature was refused, or the read gives
//	           no provenance (evs serves no record of the push, or the push sealed none, one from before the field),
//	           and reading it taints the run before its bytes return, fenced (D-MCP-16); else own where this sidecar
//	           signed it, its words from an untainted run; else member, another sidecar's untainted version, which
//	           taints nothing. A push bound to no run, a person's own git push among them, carries no bit and reads
//	           by its signer (§16.17's residual)
//	writes     a push on either ref mode, this sidecar as committer (owner decision 81), sealing the call's run's
//	           tainted bit as the call read it (McpCall.Tainted) in the push's provenance, so the version reads back
//	           untrusted in any run where a tainted run wrote it; the session's agent rides as the commit's label,
//	           and its agent_id in the network (McpSession.AgentId) is sealed beside the bit, where the host signs
//	           provenance under that agent's subkey (owner decision 470; QD-981), an outward write's effect and action
//	           carrying the same id; a session with no agent seals none. A file-mode ref by path CAS on base_version,
//	           a conflict answering FAILED_PRECONDITION; a git-mode ref through the local tier's WriteAtTip, which rebuilds on a
//	           newer tip while the path is unchanged, at most EvsSettings' WriteAtTipTryCount tips (owner decision
//	           141), the tool calling it once and its tries running out answering a retryable failure; a daemon with
//	           no local tier answers EVS_GIT_REF
//	format 2   (MCP-M10-01) evs_write's versioning is on or off, the path's own when omitted, a new path's from its
//	           rules (EvsWriteOptions, which each plan follows on its own read of the path), never retried by
//	           rebasing; off is refused FAILED_PRECONDITION outside §19.11's format2 gate, in a locked repo and on a
//	           git-mode ref (§11.7's refused row), and an outward write that names one carries it as field 37 at
//	           version 2. evs_list, evs_history and evs_read name each version's setting, on, off or index, and a
//	           replaced versionless version reads collected. evs_history and evs_read mark a version a checked DROP
//	           lists drop_pending, with not_before, or dropped, with the drop's id and signer; a dropped version's
//	           read answers EVS_DROPPED, FAILED_PRECONDITION, its data naming the drop, and a pending one reads with
//	           a warning. evs_drop_preview runs §11.13's dry run for a sidecar §8 lets administer the repo, within
//	           evs_drop_previews_per_day, which evs counts, and never drops: no MCP path signs a DROP or its cancel
//	           (D-MCP-32; the guard's DROP row)
//	outward    a write or delete of Ingest.AgentConfigPaths in a shared repo goes through §5.4's gate with the evs
//	           effect (EvsWriteEffect, EVS1-M3-01), which pushes only while its Lookup finds nothing and looks again
//	           after a refusal, so a crash after the effect takes no second push; pending answers approval_pending
//	secrets    a shared repo's write whose content Redactor.Scan matches is refused (R-MCP-5); owner-bound vault
//	           writes keep their bytes, as the vault's own redaction is the record's
//
// evs_read's hit, a file's search hit in place of repo, path and version, resolves through the session's cursors and
// then reads as those named would (tools_hit.go).

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One repo's calls the evs tools make: *sidecar.EvsRepo, or a test's.
type McpEvsRepo interface {
	List(ctx context.Context, args *sidecar.EvsReadArgs) (*sidecar.EvsListing, error)
	History(ctx context.Context, args *sidecar.EvsReadArgs) (*sidecar.EvsHistory, error)
	ReadHead(ctx context.Context, args *sidecar.EvsReadArgs, out io.Writer) (*sidecar.EvsFileInfo, error)
	WritePaths(ctx context.Context, args *sidecar.EvsWritePathsArgs) (*sidecar.EvsWritePathsResult, error)
	WriteAtTip(ctx context.Context, args *sidecar.EvsWriteAtTipArgs) (*sidecar.EvsWriteAtTipResult, error)
	Subscribe(ctx context.Context, args *sidecar.EvsSubscribeArgs) (*sidecar.EvsSubscription, error)
}

var _ McpEvsRepo = (*sidecar.EvsRepo)(nil)

// One network as the evs tools read it: its repos and their client.
type McpEvsNetwork interface {
	McpToolNetwork
	// The repos the installed state holds, sorted.
	RepoIds() []sidecar.Id
	// One repo's calls, nil while the daemon holds no evs client for the network.
	EvsRepo(repoId sidecar.Id) McpEvsRepo
	// The effect of an outward write or delete in repoId: EvsWriteEffect over its EvsRepo, nil with no client.
	EvsWriteEffect(repoId sidecar.Id, effect *sidecar.EvsWriteEffect) sidecar.SidecarEffect
}

// The evs view of hosted, its repos from engine's installed state and its calls through client.
func McpEvsNetworkOf(hosted *sidecar.Sidecar, engine *sidecar.AclEngine, client *sidecar.EvsClient) McpEvsNetwork {
	return &mcpSidecarNetwork{Sidecar: hosted, engine: engine, evs: client}
}

// The installed state's repos.
func (self *mcpSidecarNetwork) RepoIds() []sidecar.Id {
	engine, _ := self.policy()
	if engine == nil {
		return nil
	}
	state := engine.State()
	if state == nil {
		return nil
	}
	return state.RepoIds()
}

// The daemon's currently attached EVS client, or the one supplied by the embedding host.
func (self *mcpSidecarNetwork) evsClient() *sidecar.EvsClient {
	if self.follow {
		return self.Sidecar.EvsClient()
	}
	return self.evs
}

// The client's repo.
func (self *mcpSidecarNetwork) EvsRepo(repoId sidecar.Id) McpEvsRepo {
	client := self.evsClient()
	if client == nil {
		return nil
	}
	return client.Repo(repoId)
}

// The evs effect over the client's repo.
func (self *mcpSidecarNetwork) EvsWriteEffect(repoId sidecar.Id, effect *sidecar.EvsWriteEffect) sidecar.SidecarEffect {
	client := self.evsClient()
	if client == nil {
		return nil
	}
	effect.Repo = client.Repo(repoId)
	return effect
}

// The ref every tool reads and writes: §16.2's tools write main.
const mcpEvsMainRef = "main"

// The search index's directory on a file-mode ref (§11.14), whose names evs_list gives only when asked.
const mcpEvsIndexName = ".ur-index"

// The evs tools' refusals, each constant.
var (
	errMcpEvsUnavailable = NewMcpError(McpCodeUnavailable, "this daemon holds no evs client for the network yet: run ur status in your own terminal", true)
	errMcpEvsRepo        = NewMcpError(McpCodeInvalidArguments, "repo is a repo's id", false)
	errMcpEvsPath        = NewMcpError(McpCodeInvalidArguments, "path is names joined by /, with no empty name", false)
	errMcpEvsErased      = NewMcpError(McpCodeFailedPrecondition, "this version was erased", false)
	errMcpEvsAbsent      = NewMcpError(McpCodeFailedPrecondition, "nothing stands at that path", false)
	errMcpEvsConflict    = NewMcpError(McpCodeFailedPrecondition, "the path moved past base_version: read it again and write on its version", false)
	errMcpEvsGitRef      = NewMcpError(McpCodeFailedPrecondition, "EVS_GIT_REF: the repo's ref is git-mode, and this daemon has no local tier to commit through", false)
	errMcpEvsVersioning  = NewMcpError(McpCodeFailedPrecondition, "versioning off is refused here: outside format 2, in a locked repo or on a git-mode ref every version is kept", false)
	errMcpEvsCollected   = NewMcpError(McpCodeFailedPrecondition, "this version was replaced and is versionless, so evs keeps none of its content: read the path's newest version", false)
	errMcpEvsDropped     = NewMcpError(McpCodeFailedPrecondition, "EVS_DROPPED: this version's history was dropped, so nothing of it is read", false)
	errMcpEvsDropFollow  = NewMcpError(McpCodeInvalidArguments, "follow, a dry run through renames, is not built: preview the path alone", false)
	errMcpEvsDropLineage = NewMcpError(McpCodeFailedPrecondition, "the path's history cannot be previewed as one drop: evs cannot follow its lineage, or it is past one drop's bounds", false)
	errMcpEvsDropScope   = NewMcpError(McpCodeRefused, "evs takes a drop's dry run only from the repo's admins", false)
	errMcpEvsDropBudget  = NewMcpError(McpCodeRefused, "the repo's dry runs for today are spent: a person may preview it with ur history drop later", false)
	errMcpEvsSecret      = NewMcpError(McpCodeRefused, "the content holds what reads as a secret, which a shared repo never takes: write it to your vault, or leave it out", false)
	errMcpEvsTooLarge    = NewMcpError(McpCodeFailed, "the file is past what a read through MCP holds: read it with ur evs in your own terminal", false)
	errMcpEvsOutward     = NewMcpError(McpCodeRefused, "this write is outward and could not go through the gate: a person may approve it with ur approve", false)
	errMcpEvsUncertain   = NewMcpError(McpCodeFailed, "the write's outcome is not known yet: send the same call again", true)
	errMcpEvsReceipt     = NewMcpError(McpCodeRefused, "this repo's owner reads a receipt of every read first, and this daemon cannot deposit one: run ur status in your own terminal", true)
	errMcpEvsTipMoved    = NewMcpError(McpCodeFailed, "the repo's tip moved on each of this daemon's tries while the path stood still: send the same call again", true)
	errMcpEvsGitRefused  = NewMcpError(McpCodeFailed, "the repo's ref refused the commit: run ur evs in your own terminal to see why", false)
	errMcpEvsUnchanged   = NewMcpError(McpCodeFailedPrecondition, "the write changes nothing: the path holds that content already, or a removal names a path the ref lacks", false)
	errMcpEvsInvalid     = NewMcpError(McpCodeInvalidArguments, "the repo takes no such write: content past its file bound, or a name or label it cannot carry", false)
)

// The repo a call names, its id parsed.
func mcpEvsRepoId(text string) (sidecar.Id, error) {
	repoId, err := sidecar.ParseId(text)
	if err != nil || repoId == (sidecar.Id{}) {
		return sidecar.Id{}, errMcpEvsRepo
	}
	return repoId, nil
}

// A path a call names: names joined by /, none empty, "" the root alone where root is allowed.
func mcpEvsPath(path string, root bool) (string, error) {
	if path == "" {
		if root {
			return "", nil
		}
		return "", errMcpEvsPath
	}
	if !utf8.ValidString(path) {
		return "", errMcpEvsPath
	}
	for _, name := range strings.Split(path, "/") {
		if name == "" {
			return "", errMcpEvsPath
		}
	}
	return path, nil
}

// A repo kind's name: general, record, config, directory, team_record, mailcfg, vault, mailbox or secret.
func mcpRepoKindName(kind protocol.RepoKind) string {
	return strings.TrimPrefix(strings.ToLower(kind.String()), "repo_kind_")
}

// Whether a repo is shared: one its owner's devices alone do not read, so not vault, mailbox or secret.
func mcpEvsShared(kind protocol.RepoKind) bool {
	switch kind {
	case protocol.RepoKind_REPO_KIND_VAULT, protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET:
		return false
	}
	return true
}

// The evs network of a call and one repo's calls, refused where the daemon holds no evs client.
func mcpEvsRepoOf(call *McpCall, repoId sidecar.Id) (McpEvsNetwork, McpEvsRepo, error) {
	network, ok := call.Network.(McpEvsNetwork)
	if !ok {
		return nil, nil, errMcpEvsUnavailable
	}
	repo := network.EvsRepo(repoId)
	if repo == nil {
		return nil, nil, errMcpEvsUnavailable
	}
	return network, repo, nil
}

// The guard's target of a call reaching repoId's path by operation.
func mcpEvsTarget(call *McpCall, repoId sidecar.Id, operation McpRepoOperation, path string) McpTarget {
	kind := protocol.RepoKind_REPO_KIND_UNSPECIFIED
	if network, ok := mcpToolNetworkOf(call); ok {
		kind = network.RepoKind(repoId)
	}
	target := McpTarget{Kind: McpTargetRepo, RepoKind: kind, Operation: operation, Ref: mcpEvsMainRef, Path: path}
	if kind == protocol.RepoKind_REPO_KIND_GENERAL && mcpRecipientPath(path) && call.ordinaryFileRepo != nil {
		target.OrdinaryFileRepo = call.ordinaryFileRepo(repoId)
	}
	return target
}

// §8's grant a call needs on repoId.
func mcpEvsAccess(repoId sidecar.Id, action protocol.AclAction) []McpAccess {
	return []McpAccess{{Action: action, Resource: sidecar.AclResource{Kind: sidecar.AclResourceRepo, RepoId: repoId}}}
}

// An evs error as a tool answers it, by constant text, never a path (I-13).
func mcpEvsError(err error) error {
	var conflict *sidecar.EvsPathConflictError
	switch {
	case errors.As(err, &conflict), errors.Is(err, sidecar.ErrEvsPathMoved):
		return errMcpEvsConflict
	case errors.Is(err, sidecar.ErrEvsGitRef):
		return errMcpEvsGitRef
	case errors.Is(err, sidecar.ErrEvsErased):
		return errMcpEvsErased
	case errors.Is(err, sidecar.ErrEvsDropped):
		return errMcpEvsDropped
	case errors.Is(err, sidecar.ErrEvsCollected):
		return errMcpEvsCollected
	case errors.Is(err, sidecar.ErrEvsPathAbsent):
		return errMcpEvsAbsent
	case errors.Is(err, sidecar.ErrEvsFormatUnsupported):
		return errMcpEvsVersioning
	case errors.Is(err, sidecar.ErrEvsReceiptGate):
		return errMcpEvsReceipt
	case errors.Is(err, sidecar.ErrEvsGitTipMoved):
		// WriteAtTip's tries ran out on a tip that kept moving while the path stood at its base: the call may go again
		return errMcpEvsTipMoved
	case errors.Is(err, sidecar.ErrEvsGitOutcomePending):
		return errMcpEvsUncertain
	case errors.Is(err, sidecar.ErrEvsGitWriteRefused):
		return errMcpEvsGitRefused
	case errors.Is(err, sidecar.ErrEvsGitWriteUnchanged):
		return errMcpEvsUnchanged
	case errors.Is(err, sidecar.ErrEvsPrefixRule), errors.Is(err, sidecar.ErrAclPrefixRule):
		return mcpEvsPrefixRuleError(err)
	case errors.Is(err, sidecar.ErrEvsWriteInvalid):
		return errMcpEvsInvalid
	}
	return err
}

// CanonicalAction's version that carries field 37, format 2's versioning (§16.8).
const mcpCanonicalActionVersionVersioning = 2

// What a pending drop's version reads with (§16.5): the drop is named beside it.
const mcpEvsDropPendingWarning = "a drop lists this version: from not_before_millis its history is dropped, and it reads no more"

// A version's setting as the tools name it: on (0), off (1) or index (2), §11.7's.
func mcpEvsVersioningName(versioning uint32) string {
	switch protocol.EvsVersioning(versioning) {
	case protocol.EvsVersioning_EVS_VERSIONING_KEPT:
		return sidecar.EvsVersioningOn
	case protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS:
		return sidecar.EvsVersioningOff
	}
	return "index"
}

// EVS_DROPPED naming drop, its id, signer and window's end in the answer's data, ids only (I-13): the message stays
// constant.
func mcpEvsDroppedError(drop *sidecar.EvsDropState) *McpError {
	refusal := *errMcpEvsDropped
	refusal.Drop = &McpErrorDrop{
		DropId: drop.DropId.String(), SignerId: drop.SignerSidecarId.String(), NotBeforeMillis: drop.NotBefore.UnixMilli(),
	}
	return &refusal
}

// EVS_PREFIX_RULE as a tool answers it (DESIGN-DETAILS 16.2.7, 16.2.5, 8.2.8; QD-801): the code and its detail, one of
// refused, pending, update, depth, unavailable, base and tag, in constant text. The path the rules hold is the
// caller's own and is in no answer (I-13).
func mcpEvsPrefixRuleError(err error) error {
	detail := ""
	var evsErr *sidecar.EvsPrefixRuleError
	var aclErr *sidecar.AclPrefixRuleError
	switch {
	case errors.As(err, &evsErr):
		detail = string(evsErr.Detail)
	case errors.As(err, &aclErr):
		detail = aclErr.Detail.String()
	}
	if answer, ok := errMcpEvsPrefixRules[detail]; ok {
		return answer
	}
	return errMcpEvsPrefixRule
}

// EVS_PREFIX_RULE's answers by detail.
var (
	errMcpEvsPrefixRule  = errors.New("EVS_PREFIX_RULE: the repo's prefix rules hold this path")
	errMcpEvsPrefixRules = map[string]error{
		"refused":     errors.New("EVS_PREFIX_RULE (refused): the repo's prefix rules do not give this device the path"),
		"pending":     errors.New("EVS_PREFIX_RULE (pending): a rule set of the repo is not readable on this device yet"),
		"update":      errors.New("EVS_PREFIX_RULE (update): a rule set of the repo needs a later release"),
		"depth":       errors.New("EVS_PREFIX_RULE (depth): too many ignored versions lie over the path"),
		"unavailable": errors.New("EVS_PREFIX_RULE (unavailable): the version the rules allow is gone from evs and this device holds no copy"),
		"base":        errors.New("EVS_PREFIX_RULE (base): a new shared branch holds a file outside this device's prefixes"),
		"tag":         errors.New("EVS_PREFIX_RULE (tag): a tag reaches a file outside this device's prefixes"),
	}
)

// evs_repos takes nothing but the network.
type mcpEvsReposIn struct{}

// One repo this sidecar may read.
type mcpEvsRepoOut struct {
	RepoId string `json:"repo_id"`
	Kind   string `json:"kind"`
	Write  bool   `json:"write"`
}

// evs_repos' data.
type mcpEvsReposOut struct {
	Repos []*mcpEvsRepoOut `json:"repos"`
}

// A repo and path, as evs_list, evs_history and evs_delete's arguments start.
type mcpEvsListIn struct {
	Repo string `json:"repo"`
	// A directory, "" for the root.
	Path string `json:"path,omitempty"`
	// Names the search index's files too (§11.14).
	IncludeIndex bool `json:"include_index,omitempty"`
}

// One child of a directory.
type mcpEvsEntryOut struct {
	Name string `json:"name"`
	// file, directory, symlink or gitlink
	Kind string `json:"kind"`
	// A file's setting, on, off or index (§11.7); empty for a directory.
	Versioning string `json:"versioning,omitempty"`
}

// evs_list's data.
type mcpEvsListOut struct {
	Path        string            `json:"path"`
	HeadVersion uint64            `json:"head_version"`
	Entries     []*mcpEvsEntryOut `json:"entries"`
}

// evs_history's arguments.
type mcpEvsHistoryIn struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
}

// One version of a path.
type mcpEvsVersionOut struct {
	Version       uint64 `json:"version"`
	CommitVersion uint64 `json:"commit_version"`
	PushId        string `json:"push_id"`
	SignerId      string `json:"signer_id"`
	TimeMillis    int64  `json:"time_millis"`
	Removed       bool   `json:"removed,omitempty"`
	// on, off or index (§11.7): the version's setting
	Versioning string `json:"versioning"`
	// kept; collected, a replaced versionless version's whose content evs no longer serves; drop_pending, listed by a
	// DROP whose window has not ended; or dropped (§11.9)
	State string `json:"state"`
	// A listed version's drop, its signer and its window's end, ms; empty for any other version.
	DropId          string `json:"drop_id,omitempty"`
	DropSignerId    string `json:"drop_signer_id,omitempty"`
	NotBeforeMillis int64  `json:"not_before_millis,omitempty"`
}

// evs_history's data.
type mcpEvsHistoryOut struct {
	Path        string              `json:"path"`
	HeadVersion uint64              `json:"head_version"`
	Versions    []*mcpEvsVersionOut `json:"versions"`
}

// evs_read's arguments: repo and path, or a search hit standing for them.
type mcpEvsReadIn struct {
	Repo string `json:"repo,omitempty"`
	Path string `json:"path,omitempty"`
	// An older version of the path, 0 the newest.
	Version uint64 `json:"version,omitempty"`
	// A file's search hit, its hit_id, in place of repo, path and version: the version this session's search named,
	// while its cursor lives (§16.10's open row).
	Hit string `json:"hit,omitempty"`
}

// evs_read's data, and ur://evs's.
type mcpEvsReadOut struct {
	Path          string `json:"path"`
	Version       uint64 `json:"version"`
	CommitVersion uint64 `json:"commit_version"`
	SignerId      string `json:"signer_id"`
	TimeMillis    int64  `json:"time_millis"`
	Size          uint64 `json:"size"`
	// utf-8, or base64 for bytes that are not
	Encoding string `json:"encoding"`
	// between the untrusted markers where the version reads untrusted
	Content string `json:"content"`
	// on, off or index (§11.7)
	Versioning string `json:"versioning"`
	// kept, or drop_pending for a version a DROP lists whose window has not ended, which reads with a warning
	State           string `json:"state"`
	DropId          string `json:"drop_id,omitempty"`
	DropSignerId    string `json:"drop_signer_id,omitempty"`
	NotBeforeMillis int64  `json:"not_before_millis,omitempty"`
	Warning         string `json:"warning,omitempty"`
}

// evs_write's arguments.
type mcpEvsWriteIn struct {
	Repo    string `json:"repo"`
	Path    string `json:"path"`
	Content string `json:"content"`
	// The path's version the content was made on, 0 for a path that does not stand.
	BaseVersion uint64 `json:"base_version"`
	// A git-mode ref's commit message.
	Message string `json:"message,omitempty"`
	// on or off; omitted, the path's own.
	Versioning string `json:"versioning,omitempty"`
}

// evs_delete's arguments.
type mcpEvsDeleteIn struct {
	Repo        string `json:"repo"`
	Path        string `json:"path"`
	BaseVersion uint64 `json:"base_version"`
}

// What evs_drop_preview reaches of a repo: *sidecar.EvsRepo's dry run, or a test's. Only the dry run: no MCP path
// signs a drop or its cancel (D-MCP-32).
type mcpEvsDropPreviewRepo interface {
	DropHistoryPreview(ctx context.Context, args *sidecar.EvsDropPreviewArgs) (*sidecar.EvsDropPreview, error)
}

var _ mcpEvsDropPreviewRepo = (*sidecar.EvsRepo)(nil)

// evs_drop_preview's arguments.
type mcpEvsDropPreviewIn struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	// Through renames, by file_id: not built, refused.
	Follow bool `json:"follow,omitempty"`
}

// evs_drop_preview's data: §11.13's dry run of a drop of the path's history now.
type mcpEvsDropPreviewOut struct {
	// The dry run's id, hex, which a person's drop names; empty where the lists did not match.
	PreviewId string `json:"preview_id,omitempty"`
	// The versions a drop now would list, and the bytes evs's resolve reported.
	Versions    uint64 `json:"versions"`
	FreesBytes  uint64 `json:"frees_bytes"`
	SharedBytes uint64 `json:"shared_bytes"`
	InlineBytes uint64 `json:"inline_bytes"`
	// Bytes too young to free yet.
	Young uint64 `json:"young"`
	// Whether evs resolved the versions this device listed; false names nothing else, and asks for a fresh look at
	// evs_history first.
	ListMatch bool `json:"list_match"`
}

// A dry run's error as evs_drop_preview answers it, by constant text.
func mcpEvsDropPreviewError(err error) error {
	switch {
	case errors.Is(err, sidecar.ErrEvsDropPath):
		return errMcpEvsDropFollow
	case errors.Is(err, sidecar.ErrEvsDropUnlinked), errors.Is(err, sidecar.ErrEvsDropTooLarge):
		return errMcpEvsDropLineage
	}
	if evsError, ok := sidecar.EvsErrorOf(err); ok {
		switch evsError.Code {
		case protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE:
			return errMcpEvsDropScope
		case protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT,
			protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT:
			// past evs_drop_previews_per_day (§20.4), which evs counts
			return errMcpEvsDropBudget
		}
	}
	return mcpEvsError(err)
}

// evs_write's and evs_delete's data.
type mcpEvsWriteOut struct {
	// written, or approval_pending with approval_id
	Status     string `json:"status"`
	Version    uint64 `json:"version,omitempty"`
	PushId     string `json:"push_id,omitempty"`
	ApprovalId string `json:"approval_id,omitempty"`
}

// An entry kind's name.
func mcpEvsEntryKindName(kind protocol.EvsEntryKind) string {
	return strings.TrimPrefix(strings.ToLower(kind.String()), "evs_entry_")
}

// How a version reads by its signer and its push's sealed provenance (the header's trust row): untrusted where the
// provenance is unknown, a tainted run's, an import's or one whose agent signature was refused; else own for this
// sidecar's version, member for another's.
func mcpEvsTrust(info *sidecar.EvsFileInfo, ownSidecarId sidecar.Id) McpTrust {
	provenance := info.Provenance
	switch {
	case provenance == nil || provenance.Tainted || provenance.Imported || provenance.Refused:
		return McpTrustUntrusted
	case info.SignerSidecarId == ownSidecarId:
		return McpTrustOwn
	}
	return McpTrustMember
}

// A read of one path's version into the result: its bytes held to the settings' bound, its trust by its push's
// provenance (mcpEvsTrust), and for an untrusted version the run tainted first and its content fenced then. The
// resource of the path is named for an over-limit result.
func mcpEvsRead(ctx context.Context, call *McpCall, repo McpEvsRepo, ref *sidecar.SearchHitRef, hit string, result *McpResult) (*mcpEvsReadOut, error) {
	repoId, path := ref.RepoId, ref.Path
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, errMcpNoToolNetwork
	}
	identity := network.Identity()
	if identity == nil {
		return nil, errMcpUnenrolled
	}
	result.SetSource("evs:" + repoId.String())
	runId := call.RunId
	ctx = sidecar.WithEvsReadContext(ctx, &sidecar.EvsReadContext{Purpose: sidecar.RecordReadPurposeRead, RunId: &runId})
	limit := call.Session.server.settings.Mcp.ResourceByteCount
	content := &mcpLimitedBuffer{limit: limit}
	args := &sidecar.EvsReadArgs{Path: path, Version: ref.Version, Provenance: true}
	if ref.RefName != "" {
		args.RefName = []byte(ref.RefName)
	}
	info, err := repo.ReadHead(ctx, args, content)
	if err != nil {
		if content.over {
			return nil, errMcpEvsTooLarge
		}
		var dropped *sidecar.EvsDroppedError
		if errors.As(err, &dropped) {
			// EVS_DROPPED, naming the drop by its id and signer in the answer's data (§16.5)
			return nil, mcpEvsDroppedError(&dropped.Drop)
		}
		return nil, mcpEvsError(err)
	}
	if hit != "" {
		current, err := mcpHitOfKind(call, hit, sidecar.IndexDocFile)
		if err != nil {
			return nil, err
		}
		if *current != *ref {
			return nil, errMcpHitUnknown
		}
	}
	uri := McpEvsUri(repoId, path) + "?network=" + call.NetworkId.String() + "&version=" + strconv.FormatUint(info.Version, 10)
	if ref.RefName != "" {
		if info.RefId != ref.RefId || info.Version != ref.Version {
			return nil, errMcpHitUnknown
		}
		uri += "&hit=" + url.QueryEscape(hit)
	}
	result.SetResource(uri)
	McpMeter(ctx, int64(content.buffer.Len()))
	out := &mcpEvsReadOut{
		Path:          path,
		Version:       info.Version,
		CommitVersion: info.CommitVersion,
		SignerId:      info.SignerSidecarId.String(),
		TimeMillis:    info.Time.UnixMilli(),
		Size:          info.Size,
		Encoding:      "utf-8",
		Versioning:    mcpEvsVersioningName(info.Versioning),
		State:         "kept",
	}
	if drop := info.Drop; drop != nil {
		// a pending drop's version reads, with its drop named and a warning (§16.5's format-2 text)
		out.State = sidecar.EvsVersionStateDropPending
		out.DropId, out.DropSignerId = drop.DropId.String(), drop.SignerSidecarId.String()
		out.NotBeforeMillis = drop.NotBefore.UnixMilli()
		out.Warning = mcpEvsDropPendingWarning
	}
	text := content.buffer.String()
	if !utf8.ValidString(text) {
		out.Encoding = "base64"
		text = base64.StdEncoding.EncodeToString(content.buffer.Bytes())
	}
	switch mcpEvsTrust(info, identity.SidecarId) {
	case McpTrustOwn:
	case McpTrustMember:
		result.Member()
	default:
		// taint before data: the run file is fsynced before these bytes leave the daemon (D-MCP-16)
		if err := result.Untrusted(ctx); err != nil {
			return nil, err
		}
		text = result.Fence(text)
	}
	out.Content = text
	return out, nil
}

// A buffer that keeps at most limit bytes and fails the write past them.
type mcpLimitedBuffer struct {
	buffer bytes.Buffer
	limit  int64
	over   bool
}

func (self *mcpLimitedBuffer) Write(p []byte) (int, error) {
	if self.limit < int64(self.buffer.Len()+len(p)) {
		self.over = true
		return 0, errMcpEvsTooLarge
	}
	return self.buffer.Write(p)
}

// What evs_write's versioning off reads of a network (§11.7's refused row): whether it is inside §19.11's format2
// gate, and whether the installed state holds a repo locked. A network that cannot say refuses off.
type mcpEvsVersioningNetwork interface {
	EvsFormat2Admitted() bool
	EvsRepoLocked(repoId sidecar.Id) bool
}

// Whether the network's EVS client is inside §19.11's format2 gate.
func (self *mcpSidecarNetwork) EvsFormat2Admitted() bool {
	client := self.evsClient()
	return client != nil && client.Format2Admitted()
}

// Whether the installed state holds repoId locked (§8.8's RepoVersioning lock); true while no state is installed.
func (self *mcpSidecarNetwork) EvsRepoLocked(repoId sidecar.Id) bool {
	engine, _ := self.policy()
	if engine == nil {
		return true
	}
	state := engine.State()
	if state == nil {
		return true
	}
	return state.RepoLocked(repoId)
}

// Refuses versioning off where §11.7 or the repo's lock refuses it: outside §19.11's format2 gate, in a locked repo,
// or where the network cannot say (§16.5's evs_write row).
func mcpEvsVersioningOffAllowed(network McpEvsNetwork, repoId sidecar.Id) error {
	versioning, ok := network.(mcpEvsVersioningNetwork)
	if !ok || !versioning.EvsFormat2Admitted() || versioning.EvsRepoLocked(repoId) {
		return errMcpEvsVersioning
	}
	return nil
}

// One write or removal of path on base, the W path or, for a shared repo's agent-config file, the outward one, its
// version's setting versioning: "" the path's own, a new path's from its rules, or "on" or "off".
func mcpEvsWrite(ctx context.Context, call *McpCall, repoId sidecar.Id, path string, base uint64, content []byte, remove bool, message string, versioning string, result *McpResult) (*mcpEvsWriteOut, error) {
	network, repo, err := mcpEvsRepoOf(call, repoId)
	if err != nil {
		return nil, err
	}
	if versioning == sidecar.EvsVersioningOff {
		if err := mcpEvsVersioningOffAllowed(network, repoId); err != nil {
			return nil, err
		}
	}
	result.SetSource("evs:" + repoId.String())
	agentLabel := ""
	if agent := call.Session.Agent(); agent != nil {
		agentLabel = agent.Label
	}
	// the session's agent's id here, which the push's provenance seals (owner decision 470); nil for no agent
	agentId := mcpCallAgentId(call)
	// the run's taint as this call finds it, before anything is written: what the push's provenance seals, so a
	// tainted run's words read back untrusted in every run (QD-042). An unbound session's placeholder reads tainted
	tainted := call.Tainted()
	shared := mcpEvsShared(network.RepoKind(repoId))
	if shared && !remove {
		scanner, err := sidecar.NewRedactor(rand.Reader)
		if err != nil {
			return nil, errMcpFailed
		}
		if 0 < len(scanner.Scan(content)) {
			return nil, errMcpEvsSecret
		}
	}
	if shared && McpAgentConfigPath(call.Session.server.settings.Ingest, path) {
		return mcpEvsWriteOutward(ctx, call, network, repoId, path, base, content, remove, message, versioning, agentLabel, agentId, tainted)
	}
	write := &sidecar.EvsPathWrite{Path: path, Remove: remove, IfBaseVersion: &base}
	if !remove {
		write.Content = bytes.NewReader(content)
		// the plan takes the version's setting from this one on its own read of the path (§11.7's choose row)
		write.Options = &sidecar.EvsWriteOptions{Versioning: versioning}
	}
	written, err := repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{write}, AgentId: agentId, Tainted: tainted})
	if err == nil {
		McpMeter(ctx, int64(len(content)))
		return &mcpEvsWriteOut{Status: "written", Version: written.PathVersions[0], PushId: written.PushId.String()}, nil
	}
	if !errors.Is(err, sidecar.ErrEvsGitRef) {
		return nil, mcpEvsError(err)
	}
	if versioning == sidecar.EvsVersioningOff {
		// git-mode refs refuse versioning off (§11.7's refused row)
		return nil, errMcpEvsVersioning
	}
	// a git-mode ref: a commit through the local tier on the current tip, while the path is unchanged
	committed, err := repo.WriteAtTip(ctx, &sidecar.EvsWriteAtTipArgs{
		Path: path, BaseVersion: base, Content: content, Remove: remove, Message: message, AgentLabel: agentLabel,
		AgentId: agentId, Tainted: tainted,
	})
	if err != nil {
		return nil, mcpEvsError(err)
	}
	McpMeter(ctx, int64(len(content)))
	return &mcpEvsWriteOut{Status: "written", Version: committed.PathVersion, PushId: committed.PushId.String()}, nil
}

// An agent-config write or delete as an outward action (§16.5): its action, bound to the call's run and agent, and the
// evs effect, sealing the same agent id, through §5.4's gate. A write that names its versioning carries it as field 37
// at version 2, 0 on and 1 off, so an approver that does not know format 2 refuses it (§16.8); one that names none
// keeps the path's own setting and stays at version 1.
func mcpEvsWriteOutward(ctx context.Context, call *McpCall, network McpEvsNetwork, repoId sidecar.Id, path string, base uint64,
	content []byte, remove bool, message string, versioning string, agentLabel string, agentId *sidecar.Id, tainted bool) (*mcpEvsWriteOut, error) {
	authorizer, ok := call.Network.(mcpAuthorizer)
	if !ok {
		return nil, errMcpEvsOutward
	}
	kind := sidecar.SidecarActionAgentConfigWrite
	action := &protocol.CanonicalAction{RepoId: repoId.Bytes(), Path: path, BaseVersion: base}
	if remove {
		kind = sidecar.SidecarActionAgentConfigDelete
	} else {
		sum := sha256.Sum256(content)
		action.ContentSha256 = sum[:]
		switch versioning {
		case sidecar.EvsVersioningOn:
			action.Version, action.Versioning = mcpCanonicalActionVersionVersioning, uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT)
		case sidecar.EvsVersioningOff:
			action.Version, action.Versioning = mcpCanonicalActionVersionVersioning, uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS)
		}
	}
	action.Kind = uint32(kind)
	stored, err := sidecar.NewCanonicalAction(action)
	if err != nil {
		return nil, errMcpEvsOutward
	}
	runId := call.RunId
	sidecarAction, err := sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, agentId)
	if err != nil {
		return nil, errMcpEvsOutward
	}
	effect := &sidecar.EvsWriteEffect{
		Path: path, BaseVersion: base, Remove: remove, Message: message, AgentLabel: agentLabel, AgentId: agentId,
		Tainted: tainted, Versioning: versioning,
	}
	if !remove {
		effect.Content = content
	}
	sidecarAction.Effect = network.EvsWriteEffect(repoId, effect)
	if sidecarAction.Effect == nil {
		return nil, errMcpEvsUnavailable
	}
	if err := authorizer.Authorize(ctx, sidecarAction, nil); err != nil {
		var pending *sidecar.ApprovalPendingError
		if errors.As(err, &pending) {
			return &mcpEvsWriteOut{Status: "approval_pending", ApprovalId: pending.ApprovalId.String()}, nil
		}
		return nil, errMcpEvsOutward
	}
	outcome := sidecarAction.Outcome
	switch {
	case outcome == nil:
		return nil, errMcpEvsUncertain
	case outcome.State == sidecar.ApprovalOutcomeDone:
		pushId, pathVersion, err := sidecar.ParseEvsEffectRef(outcome.EffectRef)
		if err != nil {
			return &mcpEvsWriteOut{Status: "written"}, nil
		}
		McpMeter(ctx, int64(len(content)))
		return &mcpEvsWriteOut{Status: "written", Version: pathVersion, PushId: pushId.String()}, nil
	case outcome.State == sidecar.ApprovalOutcomeNotDone:
		return nil, errMcpEvsConflict
	}
	return nil, errMcpEvsUncertain
}

func init() {
	registerMcpTools(func(catalog *McpCatalog, server *McpServer) {
		addEvsTools(catalog)
	})
}

// Registers the six evs tools on catalog.
func addEvsTools(catalog *McpCatalog) {
	AddTool(catalog, &McpToolSpec[mcpEvsReposIn]{
		Name:        "evs_repos",
		Tier:        McpTierRead,
		Description: "Lists the repos this sidecar may read in the network, by id and kind, and whether it may write each; secret repos are never named.",
		// the listing names repos, each judged by the guard as it is named
		Targets: func(call *McpCall, in *mcpEvsReposIn) ([]McpTarget, error) { return nil, nil },
		Access:  func(call *McpCall, in *mcpEvsReposIn) ([]McpAccess, error) { return nil, nil },
	}, func(ctx context.Context, call *McpCall, in *mcpEvsReposIn, result *McpResult) (*mcpEvsReposOut, error) {
		network, ok := call.Network.(McpEvsNetwork)
		if !ok {
			return nil, errMcpEvsUnavailable
		}
		result.SetSource("evs:repos")
		now := mcpCallNow(call)
		out := &mcpEvsReposOut{Repos: []*mcpEvsRepoOut{}}
		repoIds := McpGuardOmit(network.RepoIds(), func(repoId sidecar.Id) McpTarget {
			return mcpEvsTarget(call, repoId, McpRepoName, "")
		})
		for _, repoId := range repoIds {
			readable, installed := network.Allow(protocol.AclAction_ACL_ACTION_READ, mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_READ)[0].Resource, now)
			if !installed {
				return nil, errMcpNoPolicy
			}
			if !readable.Allowed {
				continue
			}
			writable, _ := network.Allow(protocol.AclAction_ACL_ACTION_WRITE, mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_WRITE)[0].Resource, now)
			out.Repos = append(out.Repos, &mcpEvsRepoOut{RepoId: repoId.String(), Kind: mcpRepoKindName(network.RepoKind(repoId)), Write: writable.Allowed})
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpEvsListIn]{
		Name:        "evs_list",
		Tier:        McpTierRead,
		Description: "Lists a directory of a repo at its newest version: each child's name and kind. The search index's files are named only when asked.",
		Targets: func(call *McpCall, in *mcpEvsListIn) ([]McpTarget, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			path, err := mcpEvsPath(in.Path, true)
			if err != nil {
				return nil, err
			}
			return []McpTarget{mcpEvsTarget(call, repoId, McpRepoList, path)}, nil
		},
		Access: func(call *McpCall, in *mcpEvsListIn) ([]McpAccess, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			return mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_READ), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpEvsListIn, result *McpResult) (*mcpEvsListOut, error) {
		repoId, _ := mcpEvsRepoId(in.Repo)
		_, repo, err := mcpEvsRepoOf(call, repoId)
		if err != nil {
			return nil, err
		}
		result.Member()
		result.SetSource("evs:" + repoId.String())
		// each file's setting read too (§16.5's format-2 text), and the index's root only when asked
		listing, err := repo.List(ctx, &sidecar.EvsReadArgs{Path: in.Path, Settings: true, IndexFiles: in.IncludeIndex})
		if err != nil {
			return nil, mcpEvsError(err)
		}
		entries := McpGuardOmit(listing.Entries, func(entry *sidecar.EvsListEntry) McpTarget {
			return mcpEvsTarget(call, repoId, McpRepoList, mcpEvsJoin(in.Path, string(entry.Name)))
		})
		out := &mcpEvsListOut{Path: in.Path, HeadVersion: listing.HeadVersion, Entries: []*mcpEvsEntryOut{}}
		for _, entry := range entries {
			full := mcpEvsJoin(in.Path, string(entry.Name))
			if !in.IncludeIndex && (full == mcpEvsIndexName || strings.HasPrefix(full, mcpEvsIndexName+"/")) {
				continue
			}
			shown := &mcpEvsEntryOut{Name: string(entry.Name), Kind: mcpEvsEntryKindName(entry.Kind)}
			if entry.Kind != protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
				shown.Versioning = mcpEvsVersioningName(entry.Versioning)
			}
			out.Entries = append(out.Entries, shown)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpEvsHistoryIn]{
		Name:        "evs_history",
		Tier:        McpTierRead,
		Description: "Lists a path's versions, newest first: each version's number, its push, its signer, its time and whether it removed the path.",
		Targets: func(call *McpCall, in *mcpEvsHistoryIn) ([]McpTarget, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			path, err := mcpEvsPath(in.Path, false)
			if err != nil {
				return nil, err
			}
			return []McpTarget{mcpEvsTarget(call, repoId, McpRepoRead, path)}, nil
		},
		Access: func(call *McpCall, in *mcpEvsHistoryIn) ([]McpAccess, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			return mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_READ), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpEvsHistoryIn, result *McpResult) (*mcpEvsHistoryOut, error) {
		repoId, _ := mcpEvsRepoId(in.Repo)
		_, repo, err := mcpEvsRepoOf(call, repoId)
		if err != nil {
			return nil, err
		}
		result.Member()
		result.SetSource("evs:" + repoId.String())
		history, err := repo.History(ctx, &sidecar.EvsReadArgs{Path: in.Path})
		if err != nil {
			return nil, mcpEvsError(err)
		}
		out := &mcpEvsHistoryOut{Path: in.Path, HeadVersion: history.HeadVersion, Versions: []*mcpEvsVersionOut{}}
		for _, version := range history.Versions {
			state := version.State
			if state == "" {
				state = "kept"
			}
			shown := &mcpEvsVersionOut{
				Version:       version.Version,
				CommitVersion: version.CommitVersion,
				PushId:        version.PushId.String(),
				SignerId:      version.SignerSidecarId.String(),
				TimeMillis:    version.Time.UnixMilli(),
				Removed:       version.Removed,
				Versioning:    mcpEvsVersioningName(version.Versioning),
				State:         state,
			}
			if version.DropId != (sidecar.Id{}) {
				// a listed version names its drop, its signer and its window's end (§16.5)
				shown.DropId, shown.DropSignerId = version.DropId.String(), version.DropSignerId.String()
				shown.NotBeforeMillis = version.DropNotBefore.UnixMilli()
			}
			out.Versions = append(out.Versions, shown)
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpEvsReadIn]{
		Name:        "evs_read",
		Tier:        McpTierRead,
		Description: "Reads a file of a repo, its newest version or an older one, or the file a search hit names by its hit id; content a tainted run wrote, or an import brought in from outside, comes back marked untrusted, and reading it taints the run.",
		Targets: func(call *McpCall, in *mcpEvsReadIn) ([]McpTarget, error) {
			ref, err := mcpEvsReadOf(call, in)
			if err != nil {
				return nil, err
			}
			return []McpTarget{mcpEvsReadTarget(call, ref)}, nil
		},
		Access: func(call *McpCall, in *mcpEvsReadIn) ([]McpAccess, error) {
			ref, err := mcpEvsReadOf(call, in)
			if err != nil {
				return nil, err
			}
			return mcpEvsAccess(ref.RepoId, protocol.AclAction_ACL_ACTION_READ), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpEvsReadIn, result *McpResult) (*mcpEvsReadOut, error) {
		// a hit resolves again here: one whose cursor ended since the guard ran opens nothing
		ref, err := mcpEvsReadOf(call, in)
		if err != nil {
			return nil, err
		}
		_, repo, err := mcpEvsRepoOf(call, ref.RepoId)
		if err != nil {
			return nil, err
		}
		return mcpEvsRead(ctx, call, repo, ref, in.Hit, result)
	})

	AddTool(catalog, &McpToolSpec[mcpEvsDropPreviewIn]{
		Name: "evs_drop_preview",
		Tier: McpTierRead,
		Description: "Asks evs for a dry run of dropping a path's old history: how many versions a drop would list and the bytes it would free. " +
			"It never drops: only a person drops history, at a device. It takes a repo admin's grant and counts against the repo's daily dry runs.",
		// a dry run reads the path's history, so the guard's read rows hold: never a secret repo, the config's
		// contents, the team directory, a mailbox's vault/ or rcpt/ families or the index's files
		Targets: func(call *McpCall, in *mcpEvsDropPreviewIn) ([]McpTarget, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			path, err := mcpEvsPath(in.Path, false)
			if err != nil {
				return nil, err
			}
			return []McpTarget{mcpEvsTarget(call, repoId, McpRepoRead, path)}, nil
		},
		// an admin-scoped sidecar's alone (§16.5), as evs's preview route takes an admin's alone (§11.20)
		Access: func(call *McpCall, in *mcpEvsDropPreviewIn) ([]McpAccess, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			return mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_ADMIN), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpEvsDropPreviewIn, result *McpResult) (*mcpEvsDropPreviewOut, error) {
		if in.Follow {
			return nil, errMcpEvsDropFollow
		}
		repoId, _ := mcpEvsRepoId(in.Repo)
		_, repo, err := mcpEvsRepoOf(call, repoId)
		if err != nil {
			return nil, err
		}
		previewer, ok := repo.(mcpEvsDropPreviewRepo)
		if !ok {
			return nil, errMcpEvsUnavailable
		}
		result.SetSource("evs:" + repoId.String())
		preview, err := previewer.DropHistoryPreview(ctx, &sidecar.EvsDropPreviewArgs{Paths: []string{in.Path}})
		if errors.Is(err, sidecar.ErrEvsDropListMismatch) {
			// the history moved under the walk: evs resolved another count, and nothing else is reported
			return &mcpEvsDropPreviewOut{}, nil
		}
		if err != nil {
			return nil, mcpEvsDropPreviewError(err)
		}
		return &mcpEvsDropPreviewOut{
			PreviewId: hex.EncodeToString(preview.PreviewId), Versions: preview.VersionCount, FreesBytes: preview.FreedBytes,
			SharedBytes: preview.SharedBytes, InlineBytes: preview.InlineBytes, Young: preview.YoungBytes, ListMatch: true,
		}, nil
	})

	writeTargets := func(call *McpCall, repoText string, pathText string, operation McpRepoOperation) ([]McpTarget, error) {
		repoId, err := mcpEvsRepoId(repoText)
		if err != nil {
			return nil, err
		}
		path, err := mcpEvsPath(pathText, false)
		if err != nil {
			return nil, err
		}
		return []McpTarget{mcpEvsTarget(call, repoId, operation, path)}, nil
	}
	writeAccess := func(repoText string) ([]McpAccess, error) {
		repoId, err := mcpEvsRepoId(repoText)
		if err != nil {
			return nil, err
		}
		return mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_WRITE), nil
	}

	AddTool(catalog, &McpToolSpec[mcpEvsWriteIn]{
		Name:        "evs_write",
		Tier:        McpTierWrite,
		MayAct:      true,
		Description: "Writes a file of a repo on the version it was read at, as one signed push; a shared repo's agent-config file is an outward action that waits for approval.",
		Targets: func(call *McpCall, in *mcpEvsWriteIn) ([]McpTarget, error) {
			return writeTargets(call, in.Repo, in.Path, McpRepoWrite)
		},
		Access: func(call *McpCall, in *mcpEvsWriteIn) ([]McpAccess, error) { return writeAccess(in.Repo) },
	}, func(ctx context.Context, call *McpCall, in *mcpEvsWriteIn, result *McpResult) (*mcpEvsWriteOut, error) {
		switch in.Versioning {
		case sidecar.EvsVersioningKeepSetting, sidecar.EvsVersioningOn, sidecar.EvsVersioningOff:
		default:
			return nil, errMcpInvalidArguments
		}
		repoId, _ := mcpEvsRepoId(in.Repo)
		return mcpEvsWrite(ctx, call, repoId, in.Path, in.BaseVersion, []byte(in.Content), false, in.Message, in.Versioning, result)
	})

	AddTool(catalog, &McpToolSpec[mcpEvsDeleteIn]{
		Name:        "evs_delete",
		Tier:        McpTierWrite,
		MayAct:      true,
		Description: "Removes a file of a repo on the version it was read at, as one signed push; a shared repo's agent-config file is an outward action that waits for approval.",
		Targets: func(call *McpCall, in *mcpEvsDeleteIn) ([]McpTarget, error) {
			return writeTargets(call, in.Repo, in.Path, McpRepoDelete)
		},
		Access: func(call *McpCall, in *mcpEvsDeleteIn) ([]McpAccess, error) { return writeAccess(in.Repo) },
	}, func(ctx context.Context, call *McpCall, in *mcpEvsDeleteIn, result *McpResult) (*mcpEvsWriteOut, error) {
		repoId, _ := mcpEvsRepoId(in.Repo)
		return mcpEvsWrite(ctx, call, repoId, in.Path, in.BaseVersion, nil, true, "", sidecar.EvsVersioningKeepSetting, result)
	})
}

// A directory's path and a child's name joined.
func mcpEvsJoin(directory string, name string) string {
	if directory == "" {
		return name
	}
	return directory + "/" + name
}
