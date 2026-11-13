//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.5's evs tools (R-MCP-5, R-MCP-9, D-MCP-13, D-MCP-17, D-MCP-18, I-7, I-9, FS-30; MCP-M3-13): evs_repos,
// evs_list, evs_history and evs_read at R, evs_write and evs_delete at W, outward for a shared repo's agent-config
// files. ur://evs/{repo}/{+path} is resources_evs.go's.
//
//	guard      every call names what it reaches to McpGuard (§16.6's refused table, guard.go): never a secret repo,
//	           the config's contents, the team directory, the search index's files, a mailbox's vault/ family or a
//	           vault's harness/ config; a listing leaves such items out, and evs_list names the index's files only
//	           when asked (include_index)
//	allow      §8's local allow of read, or write, on the repo for this sidecar
//	reads      over EvsRepo, the read's purpose and run in its context, so an owner-bound repo's reader that is not
//	           its writer deposits its receipt and awaits evs's 200 before anything decrypts (EVS1-M3-01's gate,
//	           D-MCP-18); a first read that cannot deposit is refused, the gate's own refusal
//	trust      a version is this sidecar's own words only where this sidecar signed it in an untainted run and it
//	           imported nothing, and a member's untainted version is member's, which the push's sealed provenance
//	           says (QD-042, plan-MCP-format1-tainted-files). EvsRepo's writes do not set the tainted bit from the
//	           writing run on format 1 yet, nor do its reads return the provenance, so no version can show either:
//	           every version reads untrusted, this sidecar's own included, and taints the run before its bytes
//	           return (D-MCP-16), the closed reading until they do (question mcp-m3-16-format1-tainted-bit-owner)
//	writes     a push on either ref mode, this sidecar as committer (owner decision 81): a file-mode ref by path CAS on
//	           base_version, a conflict answering FAILED_PRECONDITION; a git-mode ref through the local tier's
//	           WriteAtTip, which rebuilds on a newer tip while the path is unchanged, at most EvsSettings'
//	           WriteAtTipTryCount tips (owner decision 141), the tool calling it once and its tries running out
//	           answering a retryable failure; a daemon with no local tier answers EVS_GIT_REF; versioning on alone,
//	           format 1's, off answering FAILED_PRECONDITION
//	outward    a write or delete of Ingest.AgentConfigPaths in a shared repo goes through §5.4's gate with the evs
//	           effect (EvsWriteEffect, EVS1-M3-01), which pushes only while its Lookup finds nothing and looks again
//	           after a refusal, so a crash after the effect takes no second push; pending answers approval_pending
//	secrets    a shared repo's write whose content Redactor.Scan matches is refused (R-MCP-5); owner-bound vault
//	           writes keep their bytes, as the vault's own redaction is the record's
//
// Format 2's versioning, drop states and collected versions are MCP-M10-01's. A version's search hit (evs_read's
// hit) is SEARCH-M10-30's.

package mcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"slices"
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

// A hosted Sidecar, its engine and its evs client, as the evs tools read them.
type mcpSidecarEvsNetwork struct {
	*mcpSidecarNetwork
	client *sidecar.EvsClient
}

// The evs view of hosted, its repos from engine's installed state and its calls through client.
func McpEvsNetworkOf(hosted *sidecar.Sidecar, engine *sidecar.AclEngine, client *sidecar.EvsClient) McpEvsNetwork {
	return &mcpSidecarEvsNetwork{mcpSidecarNetwork: &mcpSidecarNetwork{Sidecar: hosted, engine: engine}, client: client}
}

// The installed state's repos.
func (self *mcpSidecarEvsNetwork) RepoIds() []sidecar.Id {
	if self.engine == nil || self.engine.State() == nil {
		return nil
	}
	repoIds := []sidecar.Id{}
	for _, repo := range self.engine.State().Rows().GetRepos() {
		if repoId, err := sidecar.IdFromBytes(repo.GetRepoId()); err == nil {
			repoIds = append(repoIds, repoId)
		}
	}
	slices.SortFunc(repoIds, sidecar.Id.Cmp)
	return repoIds
}

// The client's repo.
func (self *mcpSidecarEvsNetwork) EvsRepo(repoId sidecar.Id) McpEvsRepo {
	if self.client == nil {
		return nil
	}
	return self.client.Repo(repoId)
}

// The evs effect over the client's repo.
func (self *mcpSidecarEvsNetwork) EvsWriteEffect(repoId sidecar.Id, effect *sidecar.EvsWriteEffect) sidecar.SidecarEffect {
	if self.client == nil {
		return nil
	}
	effect.Repo = self.client.Repo(repoId)
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
	errMcpEvsAbsent      = NewMcpError(McpCodeFailedPrecondition, "nothing stands at that path", false)
	errMcpEvsConflict    = NewMcpError(McpCodeFailedPrecondition, "the path moved past base_version: read it again and write on its version", false)
	errMcpEvsGitRef      = NewMcpError(McpCodeFailedPrecondition, "EVS_GIT_REF: the repo's ref is git-mode, and this daemon has no local tier to commit through", false)
	errMcpEvsVersioning  = NewMcpError(McpCodeFailedPrecondition, "versioning off is format 2's: this repo keeps every version", false)
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
	return McpTarget{Kind: McpTargetRepo, RepoKind: kind, Operation: operation, Ref: mcpEvsMainRef, Path: path}
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
	case errors.Is(err, sidecar.ErrEvsWriteInvalid):
		return errMcpEvsInvalid
	}
	return err
}

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
	// on: format 1 keeps every version
	Versioning string `json:"versioning"`
	// kept: format 1's only state
	State string `json:"state"`
}

// evs_history's data.
type mcpEvsHistoryOut struct {
	Path        string              `json:"path"`
	HeadVersion uint64              `json:"head_version"`
	Versions    []*mcpEvsVersionOut `json:"versions"`
}

// evs_read's arguments.
type mcpEvsReadIn struct {
	Repo string `json:"repo"`
	Path string `json:"path"`
	// An older version of the path, 0 the newest.
	Version uint64 `json:"version,omitempty"`
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
	// between the untrusted markers where the version is not this sidecar's
	Content    string `json:"content"`
	Versioning string `json:"versioning"`
	State      string `json:"state"`
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

// A read of one path's version into the result: its bytes held to the settings' bound, the run tainted first, since no
// version can show yet that an untainted run wrote it (the header's trust row), and its content fenced then. The
// resource of the path is named for an over-limit result.
func mcpEvsRead(ctx context.Context, call *McpCall, repoId sidecar.Id, repo McpEvsRepo, path string, version uint64, result *McpResult) (*mcpEvsReadOut, error) {
	network, ok := mcpToolNetworkOf(call)
	if !ok {
		return nil, errMcpNoToolNetwork
	}
	identity := network.Identity()
	if identity == nil {
		return nil, errMcpUnenrolled
	}
	result.SetSource("evs:" + repoId.String())
	result.SetResource(McpEvsUri(repoId, path))
	runId := call.RunId
	ctx = sidecar.WithEvsReadContext(ctx, &sidecar.EvsReadContext{Purpose: sidecar.RecordReadPurposeRead, RunId: &runId})
	limit := call.Session.server.settings.Mcp.ResourceByteCount
	content := &mcpLimitedBuffer{limit: limit}
	info, err := repo.ReadHead(ctx, &sidecar.EvsReadArgs{Path: path, Version: version}, content)
	if err != nil {
		if content.over {
			return nil, errMcpEvsTooLarge
		}
		return nil, mcpEvsError(err)
	}
	McpMeter(ctx, int64(content.buffer.Len()))
	out := &mcpEvsReadOut{
		Path:          path,
		Version:       info.Version,
		CommitVersion: info.CommitVersion,
		SignerId:      info.SignerSidecarId.String(),
		TimeMillis:    info.Time.UnixMilli(),
		Size:          info.Size,
		Encoding:      "utf-8",
		Versioning:    "on",
		State:         "kept",
	}
	text := content.buffer.String()
	if !utf8.ValidString(text) {
		out.Encoding = "base64"
		text = base64.StdEncoding.EncodeToString(content.buffer.Bytes())
	}
	// taint before data: the run file is fsynced before these bytes leave the daemon (D-MCP-16)
	if err := result.Untrusted(ctx); err != nil {
		return nil, err
	}
	out.Content = result.Fence(text)
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

// One write or removal of path on base, the W path or, for a shared repo's agent-config file, the outward one.
func mcpEvsWrite(ctx context.Context, call *McpCall, repoId sidecar.Id, path string, base uint64, content []byte, remove bool, message string, result *McpResult) (*mcpEvsWriteOut, error) {
	network, repo, err := mcpEvsRepoOf(call, repoId)
	if err != nil {
		return nil, err
	}
	result.SetSource("evs:" + repoId.String())
	agentLabel := ""
	if agent := call.Session.Agent(); agent != nil {
		agentLabel = agent.Label
	}
	shared := mcpEvsShared(network.RepoKind(repoId))
	if shared && McpAgentConfigPath(call.Session.server.settings.Ingest, path) {
		return mcpEvsWriteOutward(ctx, call, network, repoId, path, base, content, remove, message, agentLabel)
	}
	if shared && !remove {
		scanner, err := sidecar.NewRedactor(rand.Reader)
		if err != nil {
			return nil, errMcpFailed
		}
		if 0 < len(scanner.Scan(content)) {
			return nil, errMcpEvsSecret
		}
	}
	write := &sidecar.EvsPathWrite{Path: path, Remove: remove, IfBaseVersion: &base}
	if !remove {
		write.Content = bytes.NewReader(content)
	}
	written, err := repo.WritePaths(ctx, &sidecar.EvsWritePathsArgs{Writes: []*sidecar.EvsPathWrite{write}})
	if err == nil {
		McpMeter(ctx, int64(len(content)))
		return &mcpEvsWriteOut{Status: "written", Version: written.PathVersions[0], PushId: written.PushId.String()}, nil
	}
	if !errors.Is(err, sidecar.ErrEvsGitRef) {
		return nil, mcpEvsError(err)
	}
	// a git-mode ref: a commit through the local tier on the current tip, while the path is unchanged
	committed, err := repo.WriteAtTip(ctx, &sidecar.EvsWriteAtTipArgs{
		Path: path, BaseVersion: base, Content: content, Remove: remove, Message: message, AgentLabel: agentLabel,
	})
	if err != nil {
		return nil, mcpEvsError(err)
	}
	McpMeter(ctx, int64(len(content)))
	return &mcpEvsWriteOut{Status: "written", Version: committed.PathVersion, PushId: committed.PushId.String()}, nil
}

// An agent-config write or delete as an outward action (§16.5): its action, and the evs effect, through §5.4's gate.
func mcpEvsWriteOutward(ctx context.Context, call *McpCall, network McpEvsNetwork, repoId sidecar.Id, path string, base uint64,
	content []byte, remove bool, message string, agentLabel string) (*mcpEvsWriteOut, error) {
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
	}
	action.Kind = uint32(kind)
	stored, err := sidecar.NewCanonicalAction(action)
	if err != nil {
		return nil, errMcpEvsOutward
	}
	runId := call.RunId
	sidecarAction, err := sidecar.NewSidecarAction(stored, sidecar.SidecarRiskNormal, sidecar.SidecarRiskNormal, &runId, nil)
	if err != nil {
		return nil, errMcpEvsOutward
	}
	effect := &sidecar.EvsWriteEffect{Path: path, BaseVersion: base, Remove: remove, Message: message, AgentLabel: agentLabel}
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
		listing, err := repo.List(ctx, &sidecar.EvsReadArgs{Path: in.Path})
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
			out.Entries = append(out.Entries, &mcpEvsEntryOut{Name: string(entry.Name), Kind: mcpEvsEntryKindName(entry.Kind)})
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
			out.Versions = append(out.Versions, &mcpEvsVersionOut{
				Version:       version.Version,
				CommitVersion: version.CommitVersion,
				PushId:        version.PushId.String(),
				SignerId:      version.SignerSidecarId.String(),
				TimeMillis:    version.Time.UnixMilli(),
				Removed:       version.Removed,
				Versioning:    "on",
				State:         state,
			})
		}
		return out, nil
	})

	AddTool(catalog, &McpToolSpec[mcpEvsReadIn]{
		Name:        "evs_read",
		Tier:        McpTierRead,
		Description: "Reads a file of a repo, its newest version or an older one; content another writer made, or a tainted run wrote, comes back marked untrusted, and reading it taints the run.",
		Targets: func(call *McpCall, in *mcpEvsReadIn) ([]McpTarget, error) {
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
		Access: func(call *McpCall, in *mcpEvsReadIn) ([]McpAccess, error) {
			repoId, err := mcpEvsRepoId(in.Repo)
			if err != nil {
				return nil, err
			}
			return mcpEvsAccess(repoId, protocol.AclAction_ACL_ACTION_READ), nil
		},
	}, func(ctx context.Context, call *McpCall, in *mcpEvsReadIn, result *McpResult) (*mcpEvsReadOut, error) {
		repoId, _ := mcpEvsRepoId(in.Repo)
		_, repo, err := mcpEvsRepoOf(call, repoId)
		if err != nil {
			return nil, err
		}
		return mcpEvsRead(ctx, call, repoId, repo, in.Path, in.Version, result)
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
		case "", "on":
		case "off":
			return nil, errMcpEvsVersioning
		default:
			return nil, errMcpInvalidArguments
		}
		repoId, _ := mcpEvsRepoId(in.Repo)
		return mcpEvsWrite(ctx, call, repoId, in.Path, in.BaseVersion, []byte(in.Content), false, in.Message, result)
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
		return mcpEvsWrite(ctx, call, repoId, in.Path, in.BaseVersion, nil, true, "", result)
	})
}

// A directory's path and a child's name joined.
func mcpEvsJoin(directory string, name string) string {
	if directory == "" {
		return name
	}
	return directory + "/" + name
}
