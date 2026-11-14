//go:build !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-27 (§22.8; §16.6's monotone row, D-MCP-16, I-9, TS1, FI-7; MCP-M3-25, plan-MCP-taint-new-session) on T2, and the
// world FS-28 shares: the daemon's hooks, sessions and gate as one process over an approval world.
//
// The world composes what a daemon composes, each part the real one: sidecartest's ApprovalWorld, whose gate, ledger
// and run store are the root's over a fault-taking store; mcp's server and RunBinder over that run store, on a fake
// process table; mcp's Ingest sealing each hook event as a hook_event entry on a writer that keeps the drafts; mcp's
// HarnessEvidenceStore after it and HarnessEvidence as the gate's evidence; and one fixture O tool on mcp's tool
// framework, which hands a mail action in the call's run to the gate, as every O tool does. A harness is
// sidecartest's FakeHarness, its hooks handed to the running server, and a relay is an MCP session spoken to line by
// line. A daemon's kill drops all of it but the store and the log; its restart builds it again from them. A session's
// requests run on the server's own goroutines, outside any actor, so the schedules here hold no barrier: each step
// waits for its answer.
//
// FS-27, the refusal: under a standing grant an outward call runs with no approval; then the run reads untrusted data
// (a web tool's PostToolUse), the daemon and its relay are killed, the daemon restarts, and a benign hook rejoins the
// session. A shell child of the harness forges a SessionStart reporting a fresh start and a SessionEnd of the tainted
// session: the run the forged start opens inherits the taint and the end clears nothing. The next outward call under
// the same grant needs a fresh approval: its request is filed tainted, nothing runs, and once the phone approves it
// the call runs once. A second harness whose run was never tainted has its run file corrupted while the daemon is
// down: its next call needs an approval as well, a file that does not read being tainted. Its twin reads a local file
// where the refusal read the web and corrupts nothing: every call runs under the grant, the forged start's run
// included. FI-7 after every step.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mcp"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Identifiers of the hook world: the daemon's actor, the fixture O tool, the directory its harnesses work in, the MCP
// revision its relays speak and the harness's name for the tool.
const (
	fsHookDaemon   = "daemon"
	fsHookTool     = "outward_act"
	fsHookToolName = "mcp__ur__" + fsHookTool
	fsHookCwd      = "/work/project"
	fsHookProtocol = "2025-11-25"
)

// How long a relay waits on its session before the schedule calls itself broken. It bounds a hang and proves nothing.
const fsHookSessionTimeout = 30 * time.Second

var errFsHookNoDaemon = errors.New("no daemon is running")

// The fixture O tool's input and output.
type fsHookIn struct {
	Recipient string `json:"recipient"`
}

type fsHookOut struct {
	Pending bool `json:"pending"`
}

// What the gate answered one call of the fixture tool.
type fsHookAnswer struct {
	recipient string
	runId     sidecar.Id
	// the call's run read tainted as the tool ran
	tainted bool
	err     error
	action  *sidecar.SidecarAction
}

// The approval the answer waits under, false for an answer that is not pending.
func (self *fsHookAnswer) pending() (sidecar.Id, bool) {
	pending := &sidecar.ApprovalPendingError{}
	if errors.As(self.err, &pending) {
		return pending.ApprovalId, true
	}
	return sidecar.Id{}, false
}

// Whether the call's effect ran.
func (self *fsHookAnswer) done() bool {
	return self.err == nil && self.action.Outcome != nil && self.action.Outcome.State == sidecar.ApprovalOutcomeDone
}

// The record writer the ingest seals hook events on: every draft kept, each with a leaf of its own. The log outlives
// a daemon.
type fsHookWriter struct {
	stateLock sync.Mutex
	logId     sidecar.Id
	drafts    []*sidecar.RecordDraft
	leaves    [][sha256.Size]byte
}

func (self *fsHookWriter) Append(draft *sidecar.RecordDraft) ([]*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	seq := uint64(len(self.drafts) + 1)
	leaf := sha256.Sum256(binary.BigEndian.AppendUint64([]byte("fs hook entry "), seq))
	self.drafts = append(self.drafts, draft)
	self.leaves = append(self.leaves, leaf)
	entryId := sidecar.Id(leaf[:16])
	return []*sidecar.RecordEntryRef{{LogId: self.logId, EntryId: entryId, Seq: seq, Leaf: leaf}}, nil
}

// The draft sealed under leaf, nil for none.
func (self *fsHookWriter) draftOf(leaf []byte) *sidecar.RecordDraft {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i, kept := range self.leaves {
		if string(kept[:]) == string(leaf) {
			return self.drafts[i]
		}
	}
	return nil
}

// One daemon's memory beside the approval world's: what a kill drops.
type fsHookProcess struct {
	ctx      context.Context
	server   *mcp.McpServer
	evidence *mcp.HarnessEvidenceStore
}

// See the file header.
type fsHookWorld struct {
	net       *Net
	networkId sidecar.Id
	grants    *sidecartest.ApprovalWorldGrants
	table     *sidecartest.FakeProcessTable
	terminal  *sidecar.ProcessInfo
	writer    *fsHookWriter
	redactor  *sidecar.Redactor

	stateLock sync.Mutex
	world     *sidecartest.ApprovalWorld
	// the evidence store of the daemon being built, which its gate and its server share
	evidence *mcp.HarnessEvidenceStore
	process  *fsHookProcess
	answers  []*fsHookAnswer
	// what a schedule keeps between steps
	harnesses map[string]*sidecartest.FakeHarness
	relays    map[string]*fsHookRelay
	approvals map[string]sidecar.Id
}

// A hook world on net, its daemon started: a standing grant covering every action where granted, and the member's
// phone beside the laptop.
func newFsHookWorld(net *Net, granted bool) (*fsHookWorld, error) {
	redactor, err := sidecar.NewRedactor(strings.NewReader(strings.Repeat("fs hook redaction key ", 16)))
	if err != nil {
		return nil, err
	}
	table := sidecartest.NewFakeProcessTable(net.Clock())
	hooks := &fsHookWorld{
		net:       net,
		networkId: sidecartest.NewApprovalWorldIdOf("network " + fsHookDaemon),
		grants:    &sidecartest.ApprovalWorldGrants{Active: granted},
		table:     table,
		terminal:  table.Spawn(1, "zsh"),
		writer:    &fsHookWriter{logId: sidecartest.NewApprovalWorldIdOf("record log " + fsHookDaemon)},
		redactor:  redactor,
		harnesses: map[string]*sidecartest.FakeHarness{},
		relays:    map[string]*fsHookRelay{},
		approvals: map[string]sidecar.Id{},
	}
	_, err = sidecartest.NewApprovalWorldWith(net, fsHookDaemon, &sidecartest.ApprovalWorldOptions{
		Grants:  hooks.grants,
		Harness: hooks.harnessEvidence,
		Opened:  hooks.opened,
	})
	if err != nil {
		return nil, err
	}
	return hooks, nil
}

// The gate's harness evidence for a daemon being built: mcp's, over a store its server takes at opened.
func (self *fsHookWorld) harnessEvidence(ctx context.Context, world *sidecartest.ApprovalWorld, runs sidecar.RecordRunView) sidecar.ApprovalHarnessEvidence {
	store := mcp.NewHarnessEvidenceStore(sidecar.DefaultSidecarSettings().Ingest, self.net.Clock())
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.world = world
		self.evidence = store
	}()
	return mcp.NewHarnessEvidence(&mcp.HarnessEvidenceArgs{
		Store:     store,
		NetworkId: self.networkId,
		Signer:    world.HarnessSigner(),
		States:    func() (sidecar.HarnessStates, error) { return world.State(), nil },
		Runs:      runs,
	})
}

// A daemon's start: its server on the fake process table, every harness config reading unchanged, the ingest that
// seals each hook event, the evidence store after it, and the fixture tool.
func (self *fsHookWorld) opened(ctx context.Context, world *sidecartest.ApprovalWorld) error {
	settings := mcp.NewMcpServerSettings(sidecar.DefaultSidecarSettings(), sidecar.Version)
	settings.Clock = self.net.Clock()
	settings.Processes = self.table
	server := mcp.NewMcpServer(self, settings)
	server.Binder().SetConfigCheck(func(ctx context.Context, harness string, cwd string) (bool, error) {
		return false, nil
	})
	mcp.NewIngest(&mcp.IngestArgs{
		Server:    server,
		Writers:   func(network mcp.McpNetwork) (sidecar.RecordWriter, error) { return self.writer, nil },
		Redactors: func(network mcp.McpNetwork) (*sidecar.Redactor, error) { return self.redactor, nil },
	})
	catalog := mcp.NewMcpCatalog(settings.Mcp, self.net.Clock(), nil)
	mcp.AddTool(catalog, &mcp.McpToolSpec[fsHookIn]{
		Name:        fsHookTool,
		Tier:        mcp.McpTierOutward,
		Description: "sends one fixture mail through the gate",
		Access:      func(call *mcp.McpCall, in *fsHookIn) ([]mcp.McpAccess, error) { return nil, nil },
	}, self.act)
	catalog.Install(server)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.evidence.Install(server)
	self.process = &fsHookProcess{ctx: ctx, server: server, evidence: self.evidence}
	return nil
}

// The fixture O tool: a mail to the recipient, in the call's run, handed to the gate. What the gate answered is kept
// for the schedule's judge, and the tool answers whether the call waits.
func (self *fsHookWorld) act(ctx context.Context, call *mcp.McpCall, in *fsHookIn, result *mcp.McpResult) (*fsHookOut, error) {
	world := self.approvalWorld()
	stored, err := world.MailAction(in.Recipient)
	if err != nil {
		return nil, err
	}
	action := world.ActionIn(stored, call.RunId)
	answer := &fsHookAnswer{recipient: in.Recipient, runId: call.RunId, tainted: call.Tainted(), action: action}
	answer.err = world.Gate().Authorize(ctx, action, nil)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.answers = append(self.answers, answer)
	}()
	result.SetSource("fixture:" + fsHookTool)
	_, pending := answer.pending()
	return &fsHookOut{Pending: pending}, nil
}

func (self *fsHookWorld) approvalWorld() *sidecartest.ApprovalWorld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.world
}

// The running daemon's memory, or errFsHookNoDaemon while it is killed.
func (self *fsHookWorld) running() (*fsHookProcess, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.process == nil || self.process.ctx.Err() != nil {
		return nil, errFsHookNoDaemon
	}
	return self.process, nil
}

// The newest answer of a call for recipient.
func (self *fsHookWorld) answer(recipient string) (*fsHookAnswer, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for i := len(self.answers) - 1; 0 <= i; i -= 1 {
		if self.answers[i].recipient == recipient {
			return self.answers[i], nil
		}
	}
	return nil, fmt.Errorf("no call for %s reached the gate", recipient)
}

// mcp.McpDaemon: one network, the world's.

func (self *fsHookWorld) ResolveNetwork(hello *sidecar.DaemonHello, network string) (sidecar.Id, error) {
	return self.networkId, nil
}

func (self *fsHookWorld) Network(networkId sidecar.Id) (mcp.McpNetwork, bool) {
	if networkId != self.networkId {
		return nil, false
	}
	return &fsHookNetwork{hooks: self}, true
}

func (self *fsHookWorld) Agent(hello *sidecar.DaemonHello) (*sidecar.SidecarAgent, error) {
	return nil, nil
}

// The world's network as mcp's tools read it: Online, its run files and local state the approval world's daemon's, a
// policy installed that allows every grant asked.
type fsHookNetwork struct {
	hooks *fsHookWorld
}

var _ mcp.McpToolNetwork = (*fsHookNetwork)(nil)

func (self *fsHookNetwork) Status() sidecar.SidecarStatus {
	return sidecar.SidecarStatus{State: sidecar.SidecarStateOnline}
}

func (self *fsHookNetwork) Runs() (*sidecar.RunStore, error) {
	return self.hooks.approvalWorld().Runs(), nil
}

func (self *fsHookNetwork) Spool() (*sidecar.Spool, error) {
	return nil, sidecar.ErrSidecarStoreLocked
}

func (self *fsHookNetwork) LocalStore() sidecar.SidecarStore {
	return self.hooks.approvalWorld().LocalStore()
}

func (self *fsHookNetwork) Identity() *sidecar.SidecarIdentity {
	identity := self.hooks.approvalWorld().HarnessSigner().Identity()
	identity.NetworkId = self.hooks.networkId
	return identity
}

func (self *fsHookNetwork) PolicyInstalled() bool {
	return true
}

func (self *fsHookNetwork) Allow(action protocol.AclAction, resource sidecar.AclResource, now time.Time) (sidecar.AclCheck, bool) {
	return sidecar.AclCheck{Allowed: true}, true
}

func (self *fsHookNetwork) RepoKind(repoId sidecar.Id) protocol.RepoKind {
	return protocol.RepoKind_REPO_KIND_UNSPECIFIED
}

func (self *fsHookNetwork) SecretMatcher() (*sidecar.SecretMatcher, error) {
	return sidecar.NewSecretMatcher(nil, nil), nil
}

// hook.event on the running daemon, as `ur hook` delivers it: an error while no daemon runs, which the hook reports
// and its harness goes on past.
func (self *fsHookWorld) sink(hello *sidecar.DaemonHello, payload []byte) error {
	process, err := self.running()
	if err != nil {
		return err
	}
	network, _ := self.Network(self.networkId)
	return process.server.HandleHook(process.ctx, hello, self.networkId, network, &mcp.HookEventParams{Payload: payload, ByteCount: int64(len(payload))})
}

// Starts a harness of kind under the terminal and keeps it under name.
func (self *fsHookWorld) startHarness(name string, kind string) *sidecartest.FakeHarness {
	harness := sidecartest.NewFakeHarness(self.table, self.terminal.Identity.Pid, kind, fsHookCwd, self.sink)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.harnesses[name] = harness
	return harness
}

func (self *fsHookWorld) harness(name string) *sidecartest.FakeHarness {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.harnesses[name]
}

// A PermissionRequest's payload of harness for a call of the fixture tool to recipient in sessionId, reporting mode.
func fsHookPermissionRequest(harness *sidecartest.FakeHarness, sessionId string, recipient string, mode string) []byte {
	return harness.Payload(sessionId, "PermissionRequest", map[string]any{
		"tool_name":       fsHookToolName,
		"tool_input":      map[string]any{"recipient": recipient},
		"permission_mode": mode,
	})
}

// One relay: `ur mcp` under a harness, its session on the running daemon spoken to line by line.
type fsHookRelay struct {
	hooks   *fsHookWorld
	process *fsHookProcess
	pid     int
	conn    net.Conn
	cancel  context.CancelFunc
	reader  *bufio.Reader
	nextId  int
}

// A JSON-RPC answer as a relay reads it.
type fsHookResponse struct {
	Id     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int64  `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// Starts a relay under the harness kept as harnessName, kept under name: its session opened and its handshake done.
func (self *fsHookWorld) startRelay(name string, harnessName string) error {
	process, err := self.running()
	if err != nil {
		return err
	}
	hello := self.harness(harnessName).RelayHello("")
	serverConn, clientConn := net.Pipe()
	// the session ends with its relay or with its daemon, and is no actor's
	ctx, cancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(process.ctx, cancel)
	go func() {
		defer stop()
		defer serverConn.Close()
		process.server.Serve(ctx, hello, serverConn)
	}()
	relay := &fsHookRelay{hooks: self, process: process, pid: int(hello.Pid), conn: clientConn, cancel: cancel, reader: bufio.NewReader(clientConn)}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.relays[name] = relay
	}()
	if _, err := relay.request("initialize", map[string]any{
		"protocolVersion": fsHookProtocol,
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "fs hook relay", "version": "1"},
	}); err != nil {
		return err
	}
	return relay.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func (self *fsHookWorld) relay(name string) *fsHookRelay {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.relays[name]
}

func (self *fsHookRelay) send(line string) error {
	self.conn.SetWriteDeadline(time.Now().Add(fsHookSessionTimeout))
	_, err := self.conn.Write([]byte(line + "\n"))
	return err
}

// One request and its answer, the session's notifications between them passed over.
func (self *fsHookRelay) request(method string, params any) (*fsHookResponse, error) {
	if self.process.ctx.Err() != nil {
		return nil, errFsHookNoDaemon
	}
	encoded, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	self.nextId += 1
	id := fmt.Sprint(self.nextId)
	if err := self.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":%q,"params":%s}`, id, method, encoded)); err != nil {
		return nil, err
	}
	for {
		self.conn.SetReadDeadline(time.Now().Add(fsHookSessionTimeout))
		line, err := self.reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("the session ended before %s's answer: %w", method, err)
		}
		response := &fsHookResponse{}
		if json.Unmarshal(line, response) != nil || string(response.Id) != id {
			continue
		}
		if response.Error != nil {
			return nil, fmt.Errorf("%s: %d %s", method, response.Error.Code, response.Error.Message)
		}
		return response, nil
	}
}

// Calls the fixture tool for recipient and answers what the gate answered it.
func (self *fsHookRelay) act(recipient string) (*fsHookAnswer, error) {
	response, err := self.request("tools/call", map[string]any{"name": fsHookTool, "arguments": map[string]any{"recipient": recipient}})
	if err != nil {
		return nil, err
	}
	result := &struct {
		IsError bool `json:"isError"`
	}{}
	if err := json.Unmarshal(response.Result, result); err != nil || result.IsError {
		return nil, fmt.Errorf("the tool refused the call: %s", response.Result)
	}
	return self.hooks.answer(recipient)
}

// The relay's process ends: its session closes and its process leaves the table.
func (self *fsHookRelay) exit() {
	self.cancel()
	self.conn.Close()
	self.hooks.table.Exit(self.pid)
}

// A step of actor on the hook world a setup step made.
func fsHookStep(actor string, hooks **fsHookWorld, action func(ctx context.Context, hooks *fsHookWorld) error) *Step {
	return &Step{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		return action(ctx, *hooks)
	}}
}

// The relay kept as relayName calls the fixture tool for recipient; the answer is the judge's to read.
func fsHookCall(hooks **fsHookWorld, relayName string, recipient string) *Step {
	return fsHookStep(relayName, hooks, func(ctx context.Context, hooks *fsHookWorld) error {
		_, err := hooks.relay(relayName).act(recipient)
		return err
	})
}

// The call for recipient ran its effect, in a run that read untainted, and the kind's sink has done effectCount.
func (self *fsHookWorld) wantDone(recipient string, effectCount int) error {
	answer, err := self.answer(recipient)
	if err != nil {
		return err
	}
	if !answer.done() {
		return fmt.Errorf("the call for %s did not run: %v", recipient, answer.err)
	}
	return self.wantEffects(effectCount)
}

// The call for recipient waits for a person, its request filed tainted as tainted says, nothing run for it: the
// approval it waits under.
func (self *fsHookWorld) wantPending(recipient string, tainted bool, effectCount int) (sidecar.Id, error) {
	answer, err := self.answer(recipient)
	if err != nil {
		return sidecar.Id{}, err
	}
	approvalId, pending := answer.pending()
	if !pending {
		return sidecar.Id{}, fmt.Errorf("the call for %s did not wait for a person: %v, %+v", recipient, answer.err, answer.action.Outcome)
	}
	if answer.tainted != tainted {
		return sidecar.Id{}, fmt.Errorf("the call for %s ran in a run that read tainted %t", recipient, answer.tainted)
	}
	request := self.approvalWorld().Log().Request(approvalId)
	if request == nil || request.Request.GetTainted() != tainted {
		return sidecar.Id{}, fmt.Errorf("the request for %s is not filed tainted %t", recipient, tainted)
	}
	return approvalId, self.wantEffects(effectCount)
}

func (self *fsHookWorld) wantEffects(effectCount int) error {
	if count := self.approvalWorld().Sink(sidecar.SidecarActionMail).EffectCount(); count != effectCount {
		return fmt.Errorf("%d effects, not %d", count, effectCount)
	}
	return nil
}

// The channels of the decisions the ledger keeps for approvalId.
func (self *fsHookWorld) channels(approvalId sidecar.Id) ([]protocol.ApprovalChannel, error) {
	decisions, err := self.approvalWorld().Decisions(approvalId)
	if err != nil {
		return nil, err
	}
	channels := []protocol.ApprovalChannel{}
	for _, decision := range decisions {
		channels = append(channels, protocol.ApprovalChannel(decision.Decision.GetChannel()))
	}
	return channels, nil
}

func (self *fsHookWorld) keep(name string, approvalId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approvals[name] = approvalId
}

func (self *fsHookWorld) kept(name string) sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.approvals[name]
}

// The schedule's last step: every unresolved use reconciled, so FI-7's final check reads each Reserve with its
// Outcome.
func fsHookReconcile(hooks **fsHookWorld) *Step {
	return fsHookStep(fsHookDaemon, hooks, func(ctx context.Context, hooks *fsHookWorld) error {
		return hooks.approvalWorld().Reconcile(ctx)
	})
}

var Fs27 = Register("FS-27", "", []Tier{TierT2}, Twin(Fs27TaintedRunNeedsApproval, Fs27UntaintedRunKeepsGrant))

// See the file header.
func Fs27TaintedRunNeedsApproval(net *Net) *Schedule {
	schedule := fs27(true)
	schedule.Refuses = "an outward call under a standing grant in a run that read untrusted data before its daemon and relay were killed, in the run a forged SessionStart opens under its harness, and in a run whose file does not read"
	return schedule
}

// See the file header.
func Fs27UntaintedRunKeepsGrant(net *Net) *Schedule {
	return fs27(false)
}

// The sessions and recipients of FS-27's calls.
const (
	fs27Session       = "s1"
	fs27ForgedSession = "s-forged"
	fs27OtherSession  = "t1"
	fs27Before        = "before@recipient.example"
	fs27OtherBefore   = "other-before@recipient.example"
	fs27After         = "after@recipient.example"
	fs27OtherAfter    = "other-after@recipient.example"
)

// tainted is the refusal: the run reads the web and the second harness's run file is corrupted. Else its twin.
func fs27(tainted bool) *Schedule {
	var hooks *fsHookWorld
	return &Schedule{
		Steps: []*Step{
			{Actor: "setup", Action: func(ctx context.Context, net *Net) error {
				world, err := newFsHookWorld(net, true)
				if err != nil {
					return err
				}
				hooks = world
				if err := hooks.startHarness("harness", sidecartest.FakeHarnessClaudeCode).SessionStart(fs27Session, "startup"); err != nil {
					return err
				}
				if err := hooks.startHarness("other", sidecartest.FakeHarnessClaudeCode).SessionStart(fs27OtherSession, "startup"); err != nil {
					return err
				}
				return errors.Join(hooks.startRelay("relay", "harness"), hooks.startRelay("otherRelay", "other"))
			}},
			// under the standing grant, in untainted runs, each call runs with no approval
			fsHookCall(&hooks, "relay", fs27Before),
			fsHookCall(&hooks, "otherRelay", fs27OtherBefore),
			fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if err := errors.Join(hooks.wantDone(fs27Before, 2), hooks.wantDone(fs27OtherBefore, 2)); err != nil {
					return fmt.Errorf("under the grant, before any read: %w", err)
				}
				if ids := hooks.approvalWorld().Log().ApprovalIds(); len(ids) != 0 {
					return fmt.Errorf("%d requests filed under a standing grant", len(ids))
				}
				return nil
			}),
			// the read: the web in the refusal, a local file in its twin
			fsHookStep("harness", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if tainted {
					return hooks.harness("harness").ToolCall(fs27Session, false, "WebFetch", map[string]any{"url": "https://docs.example/page"})
				}
				return hooks.harness("harness").ToolCall(fs27Session, false, "Read", map[string]any{"file_path": fsHookCwd + "/a.go"})
			}),
			// the daemon and its relays die, and the daemon starts again from its files
			fsHookStep("relay", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				hooks.relay("relay").exit()
				hooks.relay("otherRelay").exit()
				return nil
			}),
			{Actor: fsHookDaemon, Kill: true},
			fsHookStep("disk", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if !tainted {
					return nil
				}
				other, err := hooks.answer(fs27OtherBefore)
				if err != nil {
					return err
				}
				return hooks.approvalWorld().CorruptRun(other.runId)
			}),
			{Actor: fsHookDaemon, Restart: fsHookDaemon},
			// a benign hook of each session
			fsHookStep("harness", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				return errors.Join(
					hooks.harness("harness").ToolCall(fs27Session, true, "Read", map[string]any{"file_path": fsHookCwd + "/b.go"}),
					hooks.harness("other").ToolCall(fs27OtherSession, true, "Read", map[string]any{"file_path": fsHookCwd + "/b.go"}),
				)
			}),
			// a shell child of the harness forges a fresh start and the tainted session's end
			fsHookStep("forger", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				harness := hooks.harness("harness")
				forger := harness.ShellChild("forger")
				return errors.Join(
					harness.HookFrom(forger, harness.Payload(fs27ForgedSession, "SessionStart", map[string]any{"source": "startup", "model": "test-model"})),
					harness.HookFrom(forger, harness.Payload(fs27Session, "SessionEnd", map[string]any{"reason": "other"})),
				)
			}),
			fsHookStep("relay2", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				return errors.Join(hooks.startRelay("relay2", "harness"), hooks.startRelay("otherRelay2", "other"))
			}),
			fsHookCall(&hooks, "relay2", fs27After),
			fsHookCall(&hooks, "otherRelay2", fs27OtherAfter),
			fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				// the forged start opened a run of its own under the harness, which the relay now acts in
				before, err := hooks.answer(fs27Before)
				if err != nil {
					return err
				}
				after, err := hooks.answer(fs27After)
				if err != nil {
					return err
				}
				if after.runId == before.runId {
					return errors.New("the forged SessionStart opened no run")
				}
				if !tainted {
					if err := errors.Join(hooks.wantDone(fs27After, 4), hooks.wantDone(fs27OtherAfter, 4)); err != nil {
						return fmt.Errorf("under the grant, in runs that read nothing untrusted: %w", err)
					}
					return nil
				}
				approvalId, err := hooks.wantPending(fs27After, true, 2)
				if err != nil {
					return fmt.Errorf("after the untrusted read, the kills, the restart and the forged start and end: %w", err)
				}
				hooks.keep(fs27After, approvalId)
				if _, err := hooks.wantPending(fs27OtherAfter, true, 2); err != nil {
					return fmt.Errorf("after the run file was corrupted: %w", err)
				}
				return nil
			}),
			// the fresh approval: the phone's decision, and the call again
			fsHookStep("phone", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if !tainted {
					return nil
				}
				world := hooks.approvalWorld()
				notAfter := hooks.net.Clock().Now().Add(sidecar.DefaultSidecarSettings().Mcp.ApprovalRequestTimeout)
				return world.Approve(ctx, hooks.kept(fs27After), 1, notAfter, nil)
			}),
			fsHookStep("relay2", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if !tainted {
					return nil
				}
				_, err := hooks.relay("relay2").act(fs27After)
				return err
			}),
			fsHookStep("judge", &hooks, func(ctx context.Context, hooks *fsHookWorld) error {
				if !tainted {
					return nil
				}
				if err := hooks.wantDone(fs27After, 3); err != nil {
					return fmt.Errorf("the approved call: %w", err)
				}
				channels, err := hooks.channels(hooks.kept(fs27After))
				if err != nil {
					return err
				}
				if len(channels) != 1 || channels[0] != protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE {
					return fmt.Errorf("the fresh approval's channels: %v", channels)
				}
				return nil
			}),
			fsHookReconcile(&hooks),
		},
		Check: []Invariant{FI(7)},
		Tiers: []Tier{TierT2},
	}
}

func TestFs27(t *testing.T) {
	RunRow(t, "FS-27", "", nil)
}
