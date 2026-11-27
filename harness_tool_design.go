//go:build !ios_extension && !sidecar_http

// What the in-process DESIGN tools share (DESIGN-COMPUTE §7.5's evs_*, search, record_query and record_append row,
// R-HARN-8, IC-12, I-7, I-9; HARN-M11-06): the network they read, and the result MCP's envelope tags, so a Harness
// agent and an MCP session read the same arguments, results, tiers and refusals on every leg the Harness runs.
//
//	network   harnessDesignNetwork: §8's local allow of the sidecar, every in-daemon agent sharing its grants (owner
//	          decision 6; §5.5), the repo kinds the guard judges, the network's evs client, record projection and
//	          search tools, the credentials no result may carry (I-7), and the limits MCP's tools hold to
//	          (SidecarMcpSettings' ResultByteCount and ResourceByteCount, the tools' own); on a Sidecar its own,
//	          read at each call, so a lock or a new client takes effect at the next call
//	envelope  {"trust": own | member | untrusted, "source": ..., "metered_bytes": n, "marker_broken": true?, "data"}
//	          as MCP's results carry it (mcp/result.go): the model reads it as the tool's text, the UI the data as
//	          the details; untrusted strings sit between §16.6's markers inside the data, as MCP's do
//	taint     Untrusted taints the call's run, write-ahead and fsynced (HarnessRun.Taint, D-MCP-16), before any
//	          untrusted text is read into the result, and a failed taint fails the call; a result with fenced text
//	          from a run that does not read tainted is refused, never returned
//	secrets   a result whose text holds the network's credentials or a token form is refused whole (I-7)
//	size      a result past ResultByteCount is refused: MCP links such a result to its ur:// resource, which an
//	          agent in the Harness cannot read, so the Harness answers the refusal in its place
//
// Errors are constant text and never name a path, a repo or an argument (I-13).

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One repo's calls the evs tools make: *EvsRepo, or a test's.
type harnessEvsRepo interface {
	List(ctx context.Context, args *EvsReadArgs) (*EvsListing, error)
	History(ctx context.Context, args *EvsReadArgs) (*EvsHistory, error)
	ReadHead(ctx context.Context, args *EvsReadArgs, out io.Writer) (*EvsFileInfo, error)
	WritePaths(ctx context.Context, args *EvsWritePathsArgs) (*EvsWritePathsResult, error)
	WriteAtTip(ctx context.Context, args *EvsWriteAtTipArgs) (*EvsWriteAtTipResult, error)
}

var _ harnessEvsRepo = (*EvsRepo)(nil)

// What the record tools read: *RecordProjection, or a test's.
type harnessRecord interface {
	ResolveLog(name string) (*RecordProjectionLog, error)
	AppendLog(kind RecordKind) (*RecordProjectionLog, bool, error)
	Query(ctx context.Context, args *RecordQueryArgs) (*RecordQueryPage, error)
	Append(ctx context.Context, args *RecordAppendArgs) (*RecordAppendResult, error)
}

var _ harnessRecord = (*RecordProjection)(nil)

// The network the DESIGN tools act on. Safe for concurrent use.
type harnessDesignNetwork interface {
	// Who the network's calls act as: the sidecar. Nil before enrollment.
	Identity() *SidecarIdentity
	// §8.9's local check of one grant for the sidecar at now; false while no policy is installed.
	Allow(action protocol.AclAction, resource AclResource, now time.Time) (check AclCheck, installed bool)
	// A repo's kind at the installed state, UNSPECIFIED for one it does not hold or before a policy installs.
	RepoKind(repoId Id) protocol.RepoKind
	// The repos the installed state holds, sorted.
	RepoIds() []Id
	// One repo's calls, nil while the network holds no evs client.
	EvsRepo(repoId Id) harnessEvsRepo
	// The effect of an outward write or delete in repoId: the EvsWriteEffect over its repo, nil with no client.
	EvsWriteEffect(repoId Id, effect *EvsWriteEffect) SidecarEffect
	// Whether the network's evs client is inside §19.11's format2 gate.
	EvsFormat2Admitted() bool
	// Whether the installed state holds repoId locked; true while no state is installed.
	EvsRepoLocked(repoId Id) bool
	// Whether a general repo's inbox/ takes messages only (§20.4): true where the network cannot say.
	AgentsInboxRepo(repoId Id) bool
	// The group inboxes a complete, verified view of mailcfg names; an error or nil where it cannot say.
	MailGroupInboxes(ctx context.Context) (map[Id]bool, error)
	// The network's record projection.
	Record() (harnessRecord, error)
	// The network's search tools, narrowed to the repos §8 lets the sidecar read; ErrSidecarSearchUnavailable while
	// no engine is installed.
	SearchTools() (harnessSearchTools, error)
	// The credentials no result may carry, read now; an error while locked or unenrolled.
	SecretMatcher() (func(text []byte) bool, error)
	// The ingest settings, whose AgentConfigPaths make an evs write outward (§16.5).
	Ingest() *SidecarIngestSettings
	// MCP's settings, whose result and resource bounds the DESIGN tools hold to.
	Mcp() *SidecarMcpSettings
}

// The refusals every DESIGN tool shares, each constant.
var (
	errHarnessDesignUnavailable = errors.New("this Harness has no network for the tool yet: the person can run ur status in their own terminal")
	errHarnessDesignUnenrolled  = errors.New("this sidecar is not enrolled in the network yet")
	errHarnessDesignNoPolicy    = errors.New("this sidecar holds no policy for the network yet, so every call is refused")
	errHarnessDesignNotAllowed  = errors.New("the network's policy does not let this sidecar do that")
	errHarnessDesignTaint       = errors.New("the run's taint did not persist, so nothing untrusted is returned")
	errHarnessDesignUntaint     = errors.New("the result holds untrusted text and the run does not read tainted, so it is withheld")
	errHarnessDesignSecret      = errors.New("the result holds what reads as a credential, so it is withheld")
	errHarnessDesignMatcher     = errors.New("the network's credentials cannot be read now, so no result is returned")
	errHarnessDesignTooLarge    = errors.New("the result is past what a tool result in the Harness holds: narrow the call")
	errHarnessDesignArguments   = errors.New("the arguments do not read")
	errHarnessDesignNoRun       = errors.New("the tool runs only in a Harness run")
)

// The trusts of a result, lowest last (mcp/result.go's McpTrust).
const (
	harnessDesignTrustOwn       = "own"
	harnessDesignTrustMember    = "member"
	harnessDesignTrustUntrusted = "untrusted"
)

// One call's result, as MCP's envelope tags it. Safe for concurrent use.
type harnessDesignResult struct {
	call *HarnessCall

	stateLock    sync.Mutex
	trust        string
	source       string
	fenced       bool
	markerBroken bool
	tainted      bool
	meteredBytes int64
}

// A fresh result of call, its trust own.
func newHarnessDesignResult(call *HarnessCall) *harnessDesignResult {
	return &harnessDesignResult{call: call, trust: harnessDesignTrustOwn}
}

// Names where the data came from, ids only (I-13).
func (self *harnessDesignResult) SetSource(source string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.source = source
}

// Lowers the trust to member, for data another member wrote.
func (self *harnessDesignResult) Member() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.trust == harnessDesignTrustOwn {
		self.trust = harnessDesignTrustMember
	}
}

// Adds bytes an evs call read or wrote to the result's metered_bytes.
func (self *harnessDesignResult) Meter(byteCount int64) {
	if byteCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.meteredBytes += byteCount
}

// Taints the call's run, write-ahead (D-MCP-16), then lowers the trust to untrusted. A tool calls it before it reads
// any untrusted text into the result, and fails when it fails.
func (self *harnessDesignResult) Untrusted(ctx context.Context) error {
	if self.call == nil || self.call.Run() == nil {
		return errHarnessDesignNoRun
	}
	if err := self.call.Run().Taint(ctx, RunTaintUntrustedData); err != nil {
		return errHarnessDesignTaint
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.trust = harnessDesignTrustUntrusted
	self.tainted = true
	return nil
}

// text between §16.6's fixed markers as MCP's Fence writes them, each marker's words inside it broken.
func (self *harnessDesignResult) Fence(text string) string {
	broken := harnessUntrustedBreakMarkers(text)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.fenced = true
	if broken != text {
		self.markerBroken = true
	}
	return HarnessUntrustedBegin + "\n" + broken + "\n" + HarnessUntrustedEnd
}

// The envelope a result goes out in, MCP's fields.
type harnessDesignEnvelope struct {
	Trust        string          `json:"trust"`
	Source       string          `json:"source"`
	MeteredBytes int64           `json:"metered_bytes"`
	MarkerBroken bool            `json:"marker_broken,omitempty"`
	Data         json.RawMessage `json:"data,omitempty"`
}

// The tool result of data under the result's tags: the envelope as the text the model reads and data as the details
// the UI reads (details, where given, in its place: a read's metadata without its content). Refused where fenced text
// comes from a run that does not read tainted, where the text holds a credential, and past the result bound.
func (self *harnessDesignResult) toolResult(network harnessDesignNetwork, data any, details any) (*HarnessToolResult, error) {
	encoded, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("the result does not encode: %w", err)
	}
	envelope := func() *harnessDesignEnvelope {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return &harnessDesignEnvelope{Trust: self.trust, Source: self.source, MeteredBytes: self.meteredBytes,
			MarkerBroken: self.markerBroken, Data: encoded}
	}()
	self.stateLock.Lock()
	fenced, trust, tainted := self.fenced, self.trust, self.tainted
	self.stateLock.Unlock()
	run := self.call.Run()
	if (fenced && (trust != harnessDesignTrustUntrusted || !tainted)) || (trust == harnessDesignTrustUntrusted && (run == nil || !run.Tainted())) {
		return nil, errHarnessDesignUntaint
	}
	text, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("the result does not encode: %w", err)
	}
	if limit := network.Mcp().ResultByteCount; limit < len(text) {
		return nil, errHarnessDesignTooLarge
	}
	matches, err := network.SecretMatcher()
	if err != nil {
		return nil, errHarnessDesignMatcher
	}
	if matches(text) {
		return nil, errHarnessDesignSecret
	}
	shown := encoded
	if details != nil {
		if shown, err = json.Marshal(details); err != nil {
			return nil, fmt.Errorf("the result does not encode: %w", err)
		}
	}
	result := &HarnessToolResult{Text: string(text), Details: shown, Trust: HarnessToolTrusted}
	if trust == harnessDesignTrustUntrusted {
		result.Trust = HarnessToolUntrusted
	}
	return result, nil
}

// args decoded into v as MCP's framework takes them: an object of v's keys and no other, refused with constant text.
func harnessDesignArgs(args []byte, v any) error {
	if len(bytes.TrimSpace(args)) == 0 {
		args = []byte("{}")
	}
	decoder := json.NewDecoder(bytes.NewReader(args))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return errHarnessDesignArguments
	}
	if decoder.More() {
		return errHarnessDesignArguments
	}
	return nil
}

// The call a DESIGN tool's Execute runs in, and its network, refusing a call outside a run or a Harness with none.
func harnessDesignCall(ctx context.Context, harness *Harness) (*HarnessCall, harnessDesignNetwork, error) {
	call, ok := HarnessCallFromContext(ctx)
	if !ok || call.Run() == nil {
		return nil, nil, errHarnessDesignNoRun
	}
	if harness == nil || harness.network == nil {
		return nil, nil, errHarnessDesignUnavailable
	}
	return call, harness.network, nil
}

// §8's local allow of every access a call needs, at now: refused where a policy is not installed or one is not allowed.
func harnessDesignAllow(network harnessDesignNetwork, now time.Time, accesses ...harnessDesignAccess) error {
	if network.Identity() == nil {
		return errHarnessDesignUnenrolled
	}
	for _, access := range accesses {
		check, installed := network.Allow(access.action, access.resource, now)
		if !installed {
			return errHarnessDesignNoPolicy
		}
		if !check.Allowed {
			return errHarnessDesignNotAllowed
		}
	}
	return nil
}

// One grant a call needs from §8's local evaluation.
type harnessDesignAccess struct {
	action   protocol.AclAction
	resource AclResource
}

// The grant of action on a repo.
func harnessDesignRepoAccess(repoId Id, action protocol.AclAction) harnessDesignAccess {
	return harnessDesignAccess{action: action, resource: AclResource{Kind: AclResourceRepo, RepoId: repoId}}
}

// A DESIGN tool's declaration and its call: one type serves all nine, each built from its own file's constants.
type harnessDesignTool struct {
	harness     *Harness
	name        string
	description string
	schema      []byte
	tier        string
	// W in the common case and O where the call is (evs_write's agent-config files): nil for a fixed tier
	runTier func(tool *harnessDesignTool, call *HarnessCall, args []byte) string
	// the O case's action and effect; nil for a tool that is never O
	outward func(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessAuthorizeRequest, error)
	execute func(ctx context.Context, tool *harnessDesignTool, call *HarnessCall, network harnessDesignNetwork, args []byte) (*HarnessToolResult, error)
}

var _ HarnessTool = (*harnessDesignTool)(nil)
var _ HarnessRunTier = (*harnessDesignTool)(nil)
var _ HarnessOutwardTool = (*harnessDesignTool)(nil)

// The tool's name, MCP's.
func (self *harnessDesignTool) Name() string {
	return self.name
}

// What the model reads of the tool: one of its file's constants.
func (self *harnessDesignTool) Description() string {
	return self.description
}

// The arguments' JSON schema, MCP's arguments.
func (self *harnessDesignTool) Schema() []byte {
	return self.schema
}

// Parallel: the writes of a batch already run one at a time in call order (harness_tools_run.go).
func (self *harnessDesignTool) Mode() string {
	return HarnessToolParallel
}

// DESIGN §16.5's tier.
func (self *harnessDesignTool) Tier() string {
	return self.tier
}

// The tier this call runs at: the tool's, or for evs_write and evs_delete O where the call writes an agent-config file.
func (self *harnessDesignTool) RunTier(call *HarnessCall, args []byte) string {
	if self.runTier == nil {
		return self.tier
	}
	return self.runTier(self, call, args)
}

// The O case's before-hook: the action the daemon builds from the call, and its effect.
func (self *harnessDesignTool) Outward(ctx context.Context, call *HarnessCall, args []byte) (*HarnessAuthorizeRequest, error) {
	if self.outward == nil {
		return nil, ErrHarnessToolUngated
	}
	if self.harness == nil || self.harness.network == nil {
		return nil, errHarnessDesignUnavailable
	}
	return self.outward(ctx, self, call, self.harness.network, args)
}

// Runs one call in its run, on the Harness's network.
func (self *harnessDesignTool) Execute(ctx context.Context, callId string, args []byte, update func(*HarnessToolUpdate)) (*HarnessToolResult, error) {
	call, network, err := harnessDesignCall(ctx, self.harness)
	if err != nil {
		return nil, err
	}
	return self.execute(ctx, self, call, network, args)
}

// The Harness's clock's now, for §8's checks.
func (self *harnessDesignTool) now() time.Time {
	if self.harness == nil {
		return clockOrReal(nil).Now()
	}
	return self.harness.clock.Now()
}

// Registers one DESIGN tool, name, for both profiles, built in, as harnessDesignTool over its Harness; left out of a
// Harness with no network.
func registerHarnessDesignTool(name string, build func(harness *Harness) *harnessDesignTool) {
	RegisterHarnessTool(&HarnessToolSpec{
		Name:     name,
		Profiles: []HarnessProfile{HarnessProfileLocal, HarnessProfileEnclave},
		BuiltIn:  true,
		New: func(harness *Harness) (HarnessTool, error) {
			if harness == nil || harness.network == nil {
				// a Harness built on no network, a test's among them
				return nil, ErrHarnessToolOff
			}
			return build(harness), nil
		},
	})
}

// The DESIGN tools' network on a Sidecar: the standing policy its config follower holds, its evs client, record
// projection and search tools, each read at the call.
type harnessSidecarNetwork struct {
	sidecar *Sidecar
}

var _ harnessDesignNetwork = (*harnessSidecarNetwork)(nil)

// The standing policy, nil before one installs.
func (self *harnessSidecarNetwork) engine() *AclEngine {
	follower := self.sidecar.ConfigFollower()
	if follower == nil {
		return nil
	}
	engine, _ := follower.StandingPolicy()
	return engine
}

// The sidecar's identity.
func (self *harnessSidecarNetwork) Identity() *SidecarIdentity {
	return self.sidecar.Identity()
}

// AclEngine.Check for the sidecar, false before a state installs or before enrollment.
func (self *harnessSidecarNetwork) Allow(action protocol.AclAction, resource AclResource, now time.Time) (AclCheck, bool) {
	identity := self.sidecar.Identity()
	engine := self.engine()
	if engine == nil || engine.State() == nil || identity == nil {
		return AclCheck{}, false
	}
	return engine.Check(AclSidecarSubject(identity.SidecarId), action, resource, now), true
}

// The installed state's repo row's kind.
func (self *harnessSidecarNetwork) RepoKind(repoId Id) protocol.RepoKind {
	engine := self.engine()
	if engine == nil || engine.State() == nil {
		return protocol.RepoKind_REPO_KIND_UNSPECIFIED
	}
	return engine.State().Repo(repoId).GetKind()
}

// The installed state's repos.
func (self *harnessSidecarNetwork) RepoIds() []Id {
	engine := self.engine()
	if engine == nil || engine.State() == nil {
		return nil
	}
	return engine.State().RepoIds()
}

// The attached evs client's repo.
func (self *harnessSidecarNetwork) EvsRepo(repoId Id) harnessEvsRepo {
	client := self.sidecar.EvsClient()
	if client == nil {
		return nil
	}
	return client.Repo(repoId)
}

// The evs effect over the client's repo.
func (self *harnessSidecarNetwork) EvsWriteEffect(repoId Id, effect *EvsWriteEffect) SidecarEffect {
	client := self.sidecar.EvsClient()
	if client == nil {
		return nil
	}
	effect.Repo = client.Repo(repoId)
	return effect
}

// Whether the evs client is inside §19.11's format2 gate.
func (self *harnessSidecarNetwork) EvsFormat2Admitted() bool {
	client := self.sidecar.EvsClient()
	return client != nil && client.Format2Admitted()
}

// Whether the installed state holds repoId locked; true while none is installed.
func (self *harnessSidecarNetwork) EvsRepoLocked(repoId Id) bool {
	engine := self.engine()
	if engine == nil || engine.State() == nil {
		return true
	}
	return engine.State().RepoLocked(repoId)
}

// Sidecar.AgentsInboxRepo.
func (self *harnessSidecarNetwork) AgentsInboxRepo(repoId Id) bool {
	return self.sidecar.AgentsInboxRepo(repoId)
}

// Sidecar.MailGroupInboxes.
func (self *harnessSidecarNetwork) MailGroupInboxes(ctx context.Context) (map[Id]bool, error) {
	return self.sidecar.MailGroupInboxes(ctx)
}

// Sidecar.RecordProjection.
func (self *harnessSidecarNetwork) Record() (harnessRecord, error) {
	return self.sidecar.RecordProjection()
}

// Sidecar.SearchTools, narrowed to the repos §8 lets the sidecar read.
func (self *harnessSidecarNetwork) SearchTools() (harnessSearchTools, error) {
	tools, err := self.sidecar.SearchTools()
	if err != nil {
		return nil, err
	}
	return tools.WithRepoAccess(func(repoId Id, now time.Time) bool {
		check, installed := self.Allow(protocol.AclAction_ACL_ACTION_READ, AclResource{Kind: AclResourceRepo, RepoId: repoId}, now)
		return installed && check.Allowed
	}), nil
}

// Sidecar.SecretMatcher's Matches.
func (self *harnessSidecarNetwork) SecretMatcher() (func(text []byte) bool, error) {
	matcher, err := self.sidecar.SecretMatcher()
	if err != nil {
		return nil, err
	}
	return matcher.Matches, nil
}

// The Sidecar's ingest settings.
func (self *harnessSidecarNetwork) Ingest() *SidecarIngestSettings {
	if self.sidecar.settings.Ingest == nil {
		return DefaultSidecarSettings().Ingest
	}
	return self.sidecar.settings.Ingest
}

// The Sidecar's MCP settings.
func (self *harnessSidecarNetwork) Mcp() *SidecarMcpSettings {
	if self.sidecar.settings.Mcp == nil {
		return DefaultSidecarSettings().Mcp
	}
	return self.sidecar.settings.Mcp
}
