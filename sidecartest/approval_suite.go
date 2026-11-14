// §22.7's approval suite on T2 (MCP-M3-24; §16.6; D-MCP-11, D-MCP-12, AD1-AD4, AU1-AU4, FI-7, TS1): ApprovalWorld is
// one requesting daemon's §16.6 gate, the real one (sidecar.NewApprovalGate), over:
//
//   - its sidecar's local state, a FakeStore that outlives a restart, so the ledger and the run file are what a
//     restarted daemon reads; every write of it is taken at the Net's fault queue as the fake host's are, a file's
//     commit and a log record's append as a put and a removal as a delete, keyed by the file's name and attributed to
//     the daemon's actor, so §22.8's unknown rule loses each one's response in turn (FaultStore);
//   - the network's verified state P as the gate reads it (ApprovalWorldState): a member M with the requesting laptop
//     L and an approval-capable phone, another member's device, and one requests rule whose approvers are k of the
//     eligible members on channel device, P moved by MovePin (FS-29);
//   - the approval family's log (ApprovalWorldLog): each request the router files, and each decision and cancel a test
//     has the phone, or another device, sign with its real key and deliver;
//   - one EffectSink for each kind the gate spends, each its kind's Lookup;
//   - one run, which a test taints.
//
// The daemon is a process of the Net (AddProcess): a kill drops its gate, inbox and router with every flight in them,
// and Restart builds them again from the store alone and runs Reconcile before it serves, as a host does; a use that
// reconcile could not record waits for the next one or a retry of its action. Callers,
// agents' MCP sessions, are actors of their own, each presenting an action as an O tool does (Authorize).
//
// FI-7's oracle (CheckEffects, which fault's fi7.go binds) reads the world after every step: per approval no more
// Reserves than its decision's uses, and none of another requester; each effect a sink did under a key has that key's
// Reserve in the ledger, at most one effect per key, and the effects of one approval at most its uses (AU1, AU2); a
// Reserve once seen never goes, its use stays consumed (AU3); the run's taint never clears; and at the end every
// Reserve has its Outcome, done, not_done or uncertain, once the daemon has reconciled.
//
// MCP-M3-25's rows build on the same world (approval_world_devices.go): the member's host pairing, the governing
// evidence list, a presence key, standing grants and a harness's evidence, each what a test sets, the run store and
// local state the daemon's hooks bind runs in, and FI-7's taint clause read over every run file.
//
// Safe for concurrent use: the world's own state is under stateLock, and the gate is the root's.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A write whose response a fault plan lost, or that died before it applied: the caller cannot tell which.
var ErrFaultStoreTransport = errors.New("fault store: the write's response was lost")

// A SidecarStore whose writes are taken at a fault queue, as the fake host's stores are: a file's Commit and a log
// record's Append are puts, a Remove a delete, each keyed by the file's name from the store's root and attributed to
// what ctx answers. Reads go through untouched. A plan's result: ApplyThenDrop applies the write and answers
// ErrFaultStoreTransport; FailBeforeApply, Precondition and Held answer it with nothing applied; CrashBeforeApply and
// CrashAfterApply crash the caller, the latter after the write applied. A Delay is refused, since a local file has no
// network to park in.
type FaultStore struct {
	inner  sidecar.SidecarStore
	faults *FaultQueue
	ctx    func() context.Context
	prefix string
}

var _ sidecar.SidecarStore = (*FaultStore)(nil)
var _ sidecar.SidecarStoreLogs = (*FaultStore)(nil)

// inner's writes taken at faults, under the context ctx answers at each write.
func NewFaultStore(inner sidecar.SidecarStore, faults *FaultQueue, ctx func() context.Context) *FaultStore {
	return &FaultStore{inner: inner, faults: faults, ctx: ctx}
}

// One write of op on name: the plan it takes, then apply as the plan's result says.
func (self *FaultStore) write(op string, name string, apply func() error) error {
	ctx := self.ctx()
	StopIfDead(ctx)
	plan := self.faults.Take(ctx, op, "", self.prefix+name, true)
	result := FaultResult(0)
	if plan != nil {
		result = plan.Result
	}
	switch result {
	case FailBeforeApply, Precondition, Held, Delay, QuorumLoss, DriveMiss:
		return ErrFaultStoreTransport
	case CrashBeforeApply:
		CrashCaller(ctx)
	}
	err := apply()
	switch result {
	case ApplyThenDrop:
		return ErrFaultStoreTransport
	case CrashAfterApply:
		CrashCaller(ctx)
	}
	return err
}

func (self *FaultStore) Open(name string) (io.ReadCloser, error) {
	return self.inner.Open(name)
}

func (self *FaultStore) Create(name string) (sidecar.SidecarStoreWriter, error) {
	writer, err := self.inner.Create(name)
	if err != nil {
		return nil, err
	}
	return &faultStoreWriter{store: self, name: name, inner: writer}, nil
}

func (self *FaultStore) Remove(name string) error {
	return self.write(FaultOpDelete, name, func() error {
		return self.inner.Remove(name)
	})
}

func (self *FaultStore) List(prefix string) ([]sidecar.SidecarStoreEntry, error) {
	return self.inner.List(prefix)
}

func (self *FaultStore) Directory(name string, class string) (sidecar.SidecarStore, error) {
	inner, err := self.inner.Directory(name, class)
	if err != nil {
		return nil, err
	}
	prefix := self.prefix
	if name != "" {
		prefix += name + "/"
	}
	return &FaultStore{inner: inner, faults: self.faults, ctx: self.ctx, prefix: prefix}, nil
}

func (self *FaultStore) Log(name string) (sidecar.SidecarStoreLog, error) {
	log, err := sidecar.OpenSidecarStoreLog(self.inner, name)
	if err != nil {
		return nil, err
	}
	return &faultStoreLog{store: self, name: name, inner: log}, nil
}

// A file on its way in, its Commit a put.
type faultStoreWriter struct {
	store *FaultStore
	name  string
	inner sidecar.SidecarStoreWriter
}

func (self *faultStoreWriter) Write(data []byte) (int, error) {
	return self.inner.Write(data)
}

func (self *faultStoreWriter) Commit() error {
	return self.store.write(FaultOpPut, self.name, self.inner.Commit)
}

func (self *faultStoreWriter) Close() error {
	return self.inner.Close()
}

// A log, each Append a put.
type faultStoreLog struct {
	store *FaultStore
	name  string
	inner sidecar.SidecarStoreLog
}

func (self *faultStoreLog) Append(record []byte) error {
	return self.store.write(FaultOpPut, self.name, func() error {
		return self.inner.Append(record)
	})
}

func (self *faultStoreLog) Read(visit func(index uint64, record []byte) error) error {
	return self.inner.Read(visit)
}

// One device of the world: its sidecar, its member and its identity key.
type ApprovalWorldDevice struct {
	SidecarId sidecar.Id
	MemberId  sidecar.Id
	Key       ed25519.PrivateKey
	// The identity key's public half for a device whose private half the world does not hold, a real Sidecar a test
	// admits: Key is nil then, and the world signs nothing as it.
	PublicKey ed25519.PublicKey
}

// The identity key's public half.
func (self *ApprovalWorldDevice) identityKey() ed25519.PublicKey {
	if self.Key == nil {
		return self.PublicKey
	}
	return self.Key.Public().(ed25519.PublicKey)
}

// A device from a fixed seed, so a world repeats.
func NewApprovalWorldDevice(label string, memberId sidecar.Id) *ApprovalWorldDevice {
	seed := sha256.Sum256([]byte("approval world device " + label))
	idHash := sha256.Sum256([]byte("approval world id " + label))
	return &ApprovalWorldDevice{SidecarId: sidecar.Id(idHash[:16]), MemberId: memberId, Key: ed25519.NewKeyFromSeed(seed[:])}
}

// The verified state P the gate reads: a pin, each version's chain the spender retains, the devices P admits, the
// members the rule finds eligible and how many of them a decision set needs. It is its own rule. Read-only once the
// gate reads it: MovePin installs another.
type ApprovalWorldState struct {
	pin *bridge.AuthPin
	// each version's chain the spender retains
	versionChains map[uint64][]byte
	devices       []*ApprovalWorldDevice
	// approval-capable devices, by sidecar
	capable  map[sidecar.Id]bool
	eligible []sidecar.Id
	k        int
	// the governing evidence list, nil for device alone, and whether a requests rule of its own names harness
	evidence         []protocol.ApprovalChannel
	ruleNamesHarness bool
	// the presence keys live at P
	presenceKeys []*bridge.KeyRow
}

var _ sidecar.ApprovalStates = (*ApprovalWorldState)(nil)
var _ sidecar.HarnessStates = (*ApprovalWorldState)(nil)

func (self *ApprovalWorldState) Pin() *bridge.AuthPin {
	return self.pin
}

func (self *ApprovalWorldState) ChainAt(version uint64) ([sha256.Size]byte, bool) {
	chain, ok := self.versionChains[version]
	if !ok {
		return [sha256.Size]byte{}, false
	}
	return [sha256.Size]byte(chain), true
}

func (self *ApprovalWorldState) Forked() bool {
	return false
}

func (self *ApprovalWorldState) IdentityKey(sidecarId sidecar.Id) []byte {
	for _, device := range self.devices {
		if device.SidecarId == sidecarId {
			return device.identityKey()
		}
	}
	return nil
}

func (self *ApprovalWorldState) ApprovalCapable(sidecarId sidecar.Id, memberId sidecar.Id) bool {
	if !self.capable[sidecarId] {
		return false
	}
	for _, device := range self.devices {
		if device.SidecarId == sidecarId && device.MemberId == memberId {
			return true
		}
	}
	return false
}

func (self *ApprovalWorldState) PresenceKey(keyId []byte, memberId sidecar.Id) *bridge.KeyRow {
	for _, key := range self.presenceKeys {
		if bytes.Equal(key.GetKeyId(), keyId) && bytes.Equal(key.GetMemberId(), memberId.Bytes()) {
			return key
		}
	}
	return nil
}

func (self *ApprovalWorldState) Govern(action *sidecar.StoredCanonicalAction, spender sidecar.Id, now time.Time) (sidecar.SpendRule, error) {
	return self, nil
}

func (self *ApprovalWorldState) Approvers(action *sidecar.StoredCanonicalAction, requester sidecar.Id, now time.Time) ([]sidecar.Id, error) {
	if len(self.eligible) == 0 {
		return nil, errors.New("no member approves")
	}
	approvers := slices.Clone(self.eligible)
	slices.SortFunc(approvers, func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) })
	return approvers, nil
}

func (self *ApprovalWorldState) RuleNamesHarness(action *sidecar.StoredCanonicalAction) bool {
	return self.ruleNamesHarness
}

func (self *ApprovalWorldState) Evidence() []protocol.ApprovalChannel {
	if self.evidence == nil {
		return []protocol.ApprovalChannel{protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE}
	}
	return slices.Clone(self.evidence)
}

func (self *ApprovalWorldState) ApproverCount() int {
	return max(self.k, 1)
}

func (self *ApprovalWorldState) Eligible(memberId sidecar.Id) bool {
	return slices.Contains(self.eligible, memberId)
}

func (self *ApprovalWorldState) AdminClauseMet(memberIds []sidecar.Id) bool {
	return true
}

// The approval family's log as the world keeps it: requests the router filed, by approval, in order; decisions and
// cancels a test delivered; and the approval_use entries filed.
type ApprovalWorldLog struct {
	stateLock   sync.Mutex
	approvalIds []sidecar.Id
	requests    map[sidecar.Id]*sidecar.StoredApprovalRequest
	decisions   map[sidecar.Id]*sidecar.StoredApprovalDecision
	cancels     map[sidecar.Id][]byte
	useCount    int
}

var _ sidecar.ApprovalLog = (*ApprovalWorldLog)(nil)

func newApprovalWorldLog() *ApprovalWorldLog {
	return &ApprovalWorldLog{
		requests:  map[sidecar.Id]*sidecar.StoredApprovalRequest{},
		decisions: map[sidecar.Id]*sidecar.StoredApprovalDecision{},
		cancels:   map[sidecar.Id][]byte{},
	}
}

func (self *ApprovalWorldLog) FileRequest(request *sidecar.StoredApprovalRequest) (*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	approvalId := request.ApprovalId()
	if _, ok := self.requests[approvalId]; !ok {
		self.approvalIds = append(self.approvalIds, approvalId)
	}
	self.requests[approvalId] = request
	return &sidecar.RecordEntryRef{LogId: sidecar.NewId(), EntryId: sidecar.NewId()}, nil
}

func (self *ApprovalWorldLog) Decision(ctx context.Context, approvalId sidecar.Id) (*sidecar.StoredApprovalDecision, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if decision, ok := self.decisions[approvalId]; ok {
		return decision, nil
	}
	if _, ok := self.cancels[approvalId]; ok {
		return nil, sidecar.ErrRecordApprovalCancelled
	}
	return nil, sidecar.ErrRecordApprovalPending
}

func (self *ApprovalWorldLog) Cancel(ctx context.Context, approvalId sidecar.Id) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if cancel, ok := self.cancels[approvalId]; ok {
		return bytes.Clone(cancel), nil
	}
	return nil, sidecar.ErrRecordApprovalPending
}

func (self *ApprovalWorldLog) FileUse(use *protocol.ApprovalUseBody, runId *sidecar.Id, actionId []byte) (*sidecar.RecordEntryRef, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.useCount += 1
	return &sidecar.RecordEntryRef{LogId: sidecar.NewId(), EntryId: sidecar.NewId()}, nil
}

// Every approval a request was filed under, in the order filed.
func (self *ApprovalWorldLog) ApprovalIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.approvalIds)
}

// The request filed under approvalId, nil for none.
func (self *ApprovalWorldLog) Request(approvalId sidecar.Id) *sidecar.StoredApprovalRequest {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.requests[approvalId]
}

// The run view the gate reads: the store's taint, failing closed.
type approvalWorldRuns struct {
	runs *sidecar.RunStore
}

func (self approvalWorldRuns) RunTainted(runId sidecar.Id) bool {
	return self.runs.Tainted(runId)
}

// The daemon's memory, which a kill drops and Restart builds again.
type approvalWorldDaemon struct {
	ledger *sidecar.ApprovalLedger
	runs   *sidecar.RunStore
	gate   *sidecar.ApprovalGate
	// the daemon's fault-taking view of its local state
	local sidecar.SidecarStore
}

// One requesting daemon's gate and what it reads. See the file's header.
type ApprovalWorld struct {
	net  *Net
	name string
	// the daemon's local state, kept across restarts
	store *FakeStore
	log   *ApprovalWorldLog
	sinks map[sidecar.SidecarActionKind]*EffectSink

	Member   sidecar.Id
	Laptop   *ApprovalWorldDevice
	Phone    *ApprovalWorldDevice
	Other    *ApprovalWorldDevice
	Stranger *ApprovalWorldDevice
	RunId    sidecar.Id
	AgentId  sidecar.Id

	stateLock sync.Mutex
	state     *ApprovalWorldState
	daemon    *approvalWorldDaemon
	// the daemon's actor context, for its store's faults
	daemonCtx context.Context
	// FI-7's memory between checks: each approval's Reserves seen, and each run seen tainted
	approvalReserveCounts map[sidecar.Id]int
	taintSeenRunIds       map[sidecar.Id]bool
	// what the daemon is built with beyond the defaults, nil for none (approval_world_devices.go)
	options *ApprovalWorldOptions
}

// A world on net, its daemon a process named name, started: a member with the requesting laptop and an
// approval-capable phone, a second member with a device of its own that is also eligible, a stranger whose device no
// rule names, one rule needing one of the first member alone, the run created untainted. Registered with the Net for
// FI-7's oracle.
func NewApprovalWorld(net *Net, name string) (*ApprovalWorld, error) {
	return NewApprovalWorldWith(net, name, nil)
}

// NewApprovalWorld with what options add to its daemon, nil for nothing.
func NewApprovalWorldWith(net *Net, name string, options *ApprovalWorldOptions) (*ApprovalWorld, error) {
	member := NewApprovalWorldIdOf("member " + name)
	otherMember := NewApprovalWorldIdOf("other member " + name)
	strangerMember := NewApprovalWorldIdOf("stranger " + name)
	world := &ApprovalWorld{
		net:                   net,
		name:                  name,
		store:                 NewFakeStore(),
		log:                   newApprovalWorldLog(),
		sinks:                 map[sidecar.SidecarActionKind]*EffectSink{},
		Member:                member,
		Laptop:                NewApprovalWorldDevice("laptop "+name, member),
		Phone:                 NewApprovalWorldDevice("phone "+name, member),
		Other:                 NewApprovalWorldDevice("other "+name, otherMember),
		Stranger:              NewApprovalWorldDevice("stranger "+name, strangerMember),
		RunId:                 NewApprovalWorldIdOf("run " + name),
		AgentId:               NewApprovalWorldIdOf("agent " + name),
		approvalReserveCounts: map[sidecar.Id]int{},
		taintSeenRunIds:       map[sidecar.Id]bool{},
		options:               options,
	}
	for _, kind := range []sidecar.SidecarActionKind{sidecar.SidecarActionMail, sidecar.SidecarActionDnsSet, sidecar.SidecarActionDnsDelete} {
		world.sinks[kind] = NewEffectSink()
	}
	chain := sha256.Sum256([]byte("approval world chain " + name))
	world.state = &ApprovalWorldState{
		pin:           &bridge.AuthPin{Version: 4, Chain: chain[:]},
		versionChains: map[uint64][]byte{4: chain[:]},
		devices:       []*ApprovalWorldDevice{world.Laptop, world.Phone, world.Other, world.Stranger},
		capable:       map[sidecar.Id]bool{world.Phone.SidecarId: true, world.Laptop.SidecarId: true, world.Other.SidecarId: true},
		eligible:      []sidecar.Id{member},
		k:             1,
	}
	// the run, untainted, written before the daemon starts and around the fault queue: the world's setup, not a write of
	// the daemon's the unknown rule loses
	runs, err := sidecar.NewRunStore(world.store.Root(), sidecar.DefaultSidecarSettings().Mcp, net.Clock())
	if err != nil {
		return nil, err
	}
	if err := runs.Create(net.Context(), &sidecar.RunFile{RunId: world.RunId, Harness: "claude-code"}); err != nil {
		return nil, err
	}
	if _, err := net.AddProcess(name, world.open); err != nil {
		return nil, err
	}
	net.addApprovalWorld(world)
	return world, nil
}

// A fixed id from label, so a world's ids repeat.
func NewApprovalWorldIdOf(label string) sidecar.Id {
	sum := sha256.Sum256([]byte("approval world " + label))
	return sidecar.Id(sum[:16])
}

// The daemon's process: its ledger, run store and gate built from the store alone, then the gate's Reconcile before
// it serves, as a host runs it.
func (self *ApprovalWorld) open(ctx context.Context, instance string) (any, error) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.daemonCtx = ctx
	}()
	local := NewFaultStore(self.store.Root(), self.net.Faults(), self.daemonContext)
	settings := sidecar.DefaultSidecarSettings().Mcp
	clock := self.net.Clock()
	ledger, err := sidecar.NewApprovalLedger(local, settings, clock)
	if err != nil {
		return nil, err
	}
	runs, err := sidecar.NewRunStore(local, settings, clock)
	if err != nil {
		return nil, err
	}
	args := &sidecar.ApprovalArgs{
		SidecarId: self.Laptop.SidecarId,
		Ledger:    ledger,
		Approvals: self.log,
		Runs:      approvalWorldRuns{runs: runs},
		States: func() (sidecar.ApprovalStates, error) {
			return self.State(), nil
		},
		Counter:  NewFakePresenceCounter(),
		Clock:    clock,
		Settings: settings,
	}
	inbox, err := sidecar.NewApprovalInbox(args)
	if err != nil {
		return nil, err
	}
	router, err := sidecar.NewApprovalRouter(args, inbox)
	if err != nil {
		return nil, err
	}
	gateArgs := &sidecar.ApprovalGateArgs{}
	if self.options != nil {
		gateArgs.Grants = self.options.Grants
		if self.options.Harness != nil {
			gateArgs.Harness = self.options.Harness(ctx, self, args.Runs)
		}
	}
	gateArgs.Lookups = func(kind sidecar.SidecarActionKind) sidecar.SidecarEffectLookup {
		sink, ok := self.sinks[kind]
		if !ok {
			return nil
		}
		return sink.Lookup
	}
	gate, err := sidecar.NewApprovalGate(args, inbox, router, gateArgs)
	if err != nil {
		return nil, err
	}
	// a use Reconcile could not record, a lost write's, stays for the next Reconcile or a retry of its action to
	// complete, as on a host, so the daemon serves either way
	gate.Reconcile(ctx)
	daemon := &approvalWorldDaemon{ledger: ledger, runs: runs, gate: gate, local: local}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.daemon = daemon
	}()
	if self.options != nil && self.options.Opened != nil {
		if err := self.options.Opened(ctx, self); err != nil {
			return nil, err
		}
	}
	return daemon, nil
}

// The daemon's actor context, background before it starts.
func (self *ApprovalWorld) daemonContext() context.Context {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.daemonCtx == nil {
		return context.Background()
	}
	return self.daemonCtx
}

// The daemon running now.
func (self *ApprovalWorld) currentDaemon() *approvalWorldDaemon {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.daemon
}

// The daemon's process name on the Net.
func (self *ApprovalWorld) Name() string {
	return self.name
}

// P now.
func (self *ApprovalWorld) State() *ApprovalWorldState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

// The gate running now.
func (self *ApprovalWorld) Gate() *sidecar.ApprovalGate {
	return self.currentDaemon().gate
}

// The kind's effect sink.
func (self *ApprovalWorld) Sink(kind sidecar.SidecarActionKind) *EffectSink {
	return self.sinks[kind]
}

// The approval family's log.
func (self *ApprovalWorld) Log() *ApprovalWorldLog {
	return self.log
}

// Moves P to P' at the next version, its chain new and the last one's kept, as the authorization log's next position
// does: with dropApprover the member is no longer eligible and its phone no longer approval-capable (FS-29), else
// nothing else changes.
func (self *ApprovalWorld) MovePin(dropApprover bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	old := self.state
	version := old.pin.GetVersion() + 1
	chain := sha256.Sum256(append([]byte(fmt.Sprintf("approval world chain %s at %d ", self.name, version)), old.pin.GetChain()...))
	moved := &ApprovalWorldState{
		pin:           &bridge.AuthPin{Version: version, Chain: chain[:]},
		versionChains: map[uint64][]byte{version: chain[:]},
		devices:       old.devices,
		capable:       map[sidecar.Id]bool{},
		eligible:      slices.Clone(old.eligible),
		k:             old.k,

		evidence:         old.evidence,
		ruleNamesHarness: old.ruleNamesHarness,
		presenceKeys:     old.presenceKeys,
	}
	for version, chain := range old.versionChains {
		moved.versionChains[version] = chain
	}
	for sidecarId, capable := range old.capable {
		moved.capable[sidecarId] = capable
	}
	if dropApprover {
		moved.eligible = slices.DeleteFunc(moved.eligible, func(memberId sidecar.Id) bool { return memberId == self.Member })
		delete(moved.capable, self.Phone.SidecarId)
	}
	self.state = moved
}

// Sets the rule's approvers to members, k of them needed (§16.6's k approvers row).
func (self *ApprovalWorld) SetApprovers(k int, members ...sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	updated := *self.state
	updated.eligible = slices.Clone(members)
	updated.k = k
	self.state = &updated
}

// A mail action to recipient, a local kind, its effect the mail sink's.
func (self *ApprovalWorld) MailAction(recipient string) (*sidecar.StoredCanonicalAction, error) {
	body := sha256.Sum256([]byte("approval world body for " + recipient))
	return sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionMail), Recipients: []string{recipient}, BodySha256: body[:], Alias: "me",
	})
}

// A mail template any of recipients falls inside, scope set.
func (self *ApprovalWorld) MailTemplate(recipients ...string) (*sidecar.StoredCanonicalAction, error) {
	return sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionMail), Scope: true, Recipients: recipients, Alias: "me",
	})
}

// A dns_set of value, a server-gated kind (§12.8).
func (self *ApprovalWorld) DnsAction(value string) (*sidecar.StoredCanonicalAction, error) {
	return sidecar.NewCanonicalAction(&protocol.CanonicalAction{
		Kind: uint32(sidecar.SidecarActionDnsSet), DnsName: "www", DnsType: "A", DnsValue: value, DnsTtl: 300,
	})
}

// stored as the O tool hands it to Authorize: the world's run and agent, the kind's sink its effect.
func (self *ApprovalWorld) Action(stored *sidecar.StoredCanonicalAction) *sidecar.SidecarAction {
	return self.ActionIn(stored, self.RunId)
}

// Action in runId, a run the daemon's hooks bound.
func (self *ApprovalWorld) ActionIn(stored *sidecar.StoredCanonicalAction, runId sidecar.Id) *sidecar.SidecarAction {
	agentId := self.AgentId
	kind := sidecar.SidecarActionKind(stored.Action.GetKind())
	return &sidecar.SidecarAction{
		Kind:      kind,
		Canonical: bytes.Clone(stored.Bytes),
		Risk:      sidecar.SidecarRiskNormal,
		RunId:     &runId,
		AgentId:   &agentId,
		Summary:   "agent words: do the thing",
		Effect:    self.sinks[kind],
	}
}

// The running gate's Authorize of action, decision nil.
func (self *ApprovalWorld) Authorize(ctx context.Context, action *sidecar.SidecarAction) error {
	return self.Gate().Authorize(ctx, action, nil)
}

// The phone's decision approving the request filed under approvalId for uses, until notAfter, delivered through the
// log, and the inbox polled. signer nil is the phone.
func (self *ApprovalWorld) Approve(ctx context.Context, approvalId sidecar.Id, uses uint32, notAfter time.Time, signer *ApprovalWorldDevice) error {
	if signer == nil {
		signer = self.Phone
	}
	decision, err := self.SignDecision(approvalId, uses, notAfter, signer, self.State().Pin())
	if err != nil {
		return err
	}
	return self.Deliver(ctx, approvalId, decision)
}

// decision, a Signed as stored, delivered as the first decision in approvalId's log, and the inbox polled.
func (self *ApprovalWorld) Deliver(ctx context.Context, approvalId sidecar.Id, decision []byte) error {
	parsed, err := sidecar.ParseStoredApprovalDecision(decision)
	if err != nil {
		return err
	}
	func() {
		self.log.stateLock.Lock()
		defer self.log.stateLock.Unlock()
		self.log.decisions[approvalId] = parsed
	}()
	return self.Gate().Inbox().Poll(ctx)
}

// signer's Signed decision approving the request filed under approvalId, as stored: for uses, until notAfter, under
// pin, the laptop its requester.
func (self *ApprovalWorld) SignDecision(approvalId sidecar.Id, uses uint32, notAfter time.Time, signer *ApprovalWorldDevice, pin *bridge.AuthPin) ([]byte, error) {
	request := self.log.Request(approvalId)
	if request == nil {
		return nil, fmt.Errorf("no request filed under approval %s", approvalId)
	}
	return approvalWorldSigned(signer, bridge.SignedType_SIGNED_APPROVAL_DECISION,
		self.decisionOf(request, uses, notAfter, signer.MemberId, protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, pin))
}

// An approving decision on request: for uses, until notAfter, by memberId on channel, under pin, the laptop its
// requester.
func (self *ApprovalWorld) decisionOf(request *sidecar.StoredApprovalRequest, uses uint32, notAfter time.Time, memberId sidecar.Id, channel protocol.ApprovalChannel, pin *bridge.AuthPin) *protocol.ApprovalDecision {
	requestSha256 := request.Sha256()
	payloadSha256 := request.Action.PayloadSha256()
	return &protocol.ApprovalDecision{
		ApprovalId:         request.Request.GetApprovalId(),
		RequestSha256:      requestSha256[:],
		PayloadSha256:      payloadSha256[:],
		Decision:           uint32(protocol.ApprovalVerdict_APPROVAL_VERDICT_APPROVE),
		Uses:               uses,
		NotAfterMillis:     notAfter.UnixMilli(),
		ApproverMemberId:   memberId.Bytes(),
		Channel:            uint32(channel),
		RequesterSidecarId: self.Laptop.SidecarId.Bytes(),
		AuthPin:            pin,
		Version:            1,
	}
}

// The inbox's next poll of the log, as its Run makes one every ApprovalPollInterval: what counts a decision whose row
// an earlier intake appended and whose answer that intake lost.
func (self *ApprovalWorld) PollInbox(ctx context.Context) error {
	return self.Gate().Inbox().Poll(ctx)
}

// The phone's ApprovalCancel of approvalId, delivered through the log, and the inbox polled.
func (self *ApprovalWorld) Cancel(ctx context.Context, approvalId sidecar.Id) error {
	cancel, err := approvalWorldSigned(self.Phone, bridge.SignedType_SIGNED_APPROVAL_CANCEL, &protocol.ApprovalCancel{ApprovalId: approvalId.Bytes()})
	if err != nil {
		return err
	}
	func() {
		self.log.stateLock.Lock()
		defer self.log.stateLock.Unlock()
		self.log.cancels[approvalId] = cancel
	}()
	return self.Gate().Inbox().Poll(ctx)
}

// Taints the world's run, write-ahead, as an untrusted read does (D-MCP-16).
func (self *ApprovalWorld) Taint(ctx context.Context) error {
	return self.currentDaemon().runs.Taint(ctx, self.RunId, sidecar.RunTaintUntrustedData)
}

// Reconciles every unresolved use on the running gate: what a host's start runs, and what a schedule's last step runs
// so FI-7's final check reads every Reserve with its Outcome.
func (self *ApprovalWorld) Reconcile(ctx context.Context) error {
	_, err := self.Gate().Reconcile(ctx)
	return err
}

// The ledger's rows for approvalId as the running daemon reads them.
func (self *ApprovalWorld) LedgerState(approvalId sidecar.Id) (*sidecar.ApprovalLedgerState, error) {
	return self.currentDaemon().ledger.State(approvalId)
}

// body signed by device under purpose approval, as stored.
func approvalWorldSigned(device *ApprovalWorldDevice, signedType bridge.SignedType, body proto.Message) ([]byte, error) {
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil, err
	}
	return approvalWorldSignedBody(device, signedType, bodyBytes)
}

// A body's deterministic bytes signed by device under purpose approval, as stored.
func approvalWorldSignedBody(device *ApprovalWorldDevice, signedType bridge.SignedType, bodyBytes []byte) ([]byte, error) {
	return proto.Marshal(&bridge.Signed{
		Body:      bodyBytes,
		SignerId:  device.SidecarId.Bytes(),
		Signature: ed25519.Sign(device.Key, bridge.SignedBytes(sidecar.ApprovalPurpose, signedType, bodyBytes)),
		Type:      uint32(signedType),
	})
}

// FI-7 over the world, as the file's header says; final adds the end's clause. Reads around every fault: the store
// directly, never through the daemon's fault-taking view.
func (self *ApprovalWorld) CheckEffects(final bool) error {
	settings := sidecar.DefaultSidecarSettings().Mcp
	ledger, err := sidecar.NewApprovalLedger(self.store.Root(), settings, self.net.Clock())
	if err != nil {
		return err
	}
	runs, err := sidecar.NewRunStore(self.store.Root(), settings, self.net.Clock())
	if err != nil {
		return err
	}
	reservedKeys := map[string]sidecar.Id{}
	for _, approvalId := range self.log.ApprovalIds() {
		state, err := ledger.State(approvalId)
		if err != nil {
			return fmt.Errorf("approval %s's ledger does not read: %w", approvalId, err)
		}
		uses := uint32(0)
		for _, signed := range state.Decisions {
			decision, err := sidecar.ParseStoredApprovalDecision(signed)
			if err != nil {
				continue
			}
			if !bytes.Equal(decision.Decision.GetRequesterSidecarId(), self.Laptop.SidecarId.Bytes()) {
				return fmt.Errorf("approval %s holds a decision of another requester", approvalId)
			}
			if uses == 0 || decision.Decision.GetUses() < uses {
				uses = decision.Decision.GetUses()
			}
		}
		if uint32(len(state.Reserves)) > uses {
			return fmt.Errorf("approval %s holds %d Reserves under %d uses (AU1)", approvalId, len(state.Reserves), uses)
		}
		for _, reserve := range state.Reserves {
			effectKey := sidecar.ApprovalEffectKey(approvalId, [sha256.Size]byte(reserve.ActionId))
			if !bytes.Equal(effectKey[:], reserve.EffectKey) {
				return fmt.Errorf("approval %s's use %d is under another approval's or action's effect key", approvalId, reserve.UseIndex)
			}
			reservedKeys[string(reserve.EffectKey)] = approvalId
			if final && state.Outcome(reserve.ActionId) == nil {
				return fmt.Errorf("approval %s's use %d ended with no Outcome, done, not_done or uncertain (AU3)", approvalId, reserve.UseIndex)
			}
		}
		seen := func() int {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			seen := self.approvalReserveCounts[approvalId]
			if seen <= len(state.Reserves) {
				self.approvalReserveCounts[approvalId] = len(state.Reserves)
			}
			return seen
		}()
		if len(state.Reserves) < seen {
			return fmt.Errorf("approval %s's Reserves went from %d to %d: a use came free (AU3)", approvalId, seen, len(state.Reserves))
		}
	}
	approvalEffects := map[sidecar.Id]int{}
	for kind, sink := range self.sinks {
		for _, effectKey := range sink.EffectKeys() {
			approvalId, ok := reservedKeys[string(effectKey)]
			if !ok {
				return fmt.Errorf("kind %d's effect under a key no Reserve holds (AU2)", kind)
			}
			approvalEffects[approvalId] += 1
		}
	}
	for approvalId, effectCount := range approvalEffects {
		state, err := ledger.State(approvalId)
		if err != nil {
			return err
		}
		if len(state.Reserves) < effectCount {
			return fmt.Errorf("approval %s had %d effects under %d Reserves (AU1)", approvalId, effectCount, len(state.Reserves))
		}
	}
	// the world's own run and every run the daemon's hooks opened: a file that does not read is tainted
	runIds := []sidecar.Id{self.RunId}
	if runDirectory, err := self.store.Root().Directory(approvalWorldRunDirectory, approvalWorldRunClass); err == nil {
		if entries, err := runDirectory.List(""); err == nil {
			for _, entry := range entries {
				if runId, err := sidecar.ParseId(entry.Name); err == nil && runId != self.RunId {
					runIds = append(runIds, runId)
				}
			}
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, runId := range runIds {
		tainted := runs.Tainted(runId)
		if self.taintSeenRunIds[runId] && !tainted {
			return fmt.Errorf("run %s's taint cleared", runId)
		}
		self.taintSeenRunIds[runId] = self.taintSeenRunIds[runId] || tainted
	}
	return nil
}

// FI-2's outcomes clause as the world shows it: per use, the first done or not_done Outcome is the one every later
// final Outcome of the use repeats, so a retry of a committed use answers its original result. Reads around every
// fault.
func (self *ApprovalWorld) CheckOutcomes() error {
	ledger, err := sidecar.NewApprovalLedger(self.store.Root(), sidecar.DefaultSidecarSettings().Mcp, self.net.Clock())
	if err != nil {
		return err
	}
	for _, approvalId := range self.log.ApprovalIds() {
		state, err := ledger.State(approvalId)
		if err != nil {
			return fmt.Errorf("approval %s's ledger does not read: %w", approvalId, err)
		}
		finals := map[string]*sidecar.ApprovalOutcome{}
		for _, outcome := range state.Outcomes {
			if outcome.State != sidecar.ApprovalOutcomeDone && outcome.State != sidecar.ApprovalOutcomeNotDone {
				continue
			}
			first, ok := finals[string(outcome.ActionId)]
			if !ok {
				finals[string(outcome.ActionId)] = outcome
				continue
			}
			if first.State != outcome.State || !bytes.Equal(first.EffectRef, outcome.EffectRef) {
				return fmt.Errorf("approval %s's use was %v and later %v: a retry did not answer its original result", approvalId, first.State, outcome.State)
			}
		}
	}
	return nil
}

// Each approval world on the Net, for FI-7's oracle.
func (self *Net) ApprovalWorlds() []*ApprovalWorld {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.approvalWorlds)
}

// Adds world to the Net's.
func (self *Net) addApprovalWorld(world *ApprovalWorld) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.approvalWorlds = append(self.approvalWorlds, world)
}
