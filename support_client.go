//go:build !ios_extension && !sidecar_http

// The support client (DESIGN-COMPUTE §28, D-SUP-1 to D-SUP-10): one per Sidecar, in the daemon or the app's sdk, which
// answers every surface of the support skill (the Harness's support_send, support_list and support_read, MCP's tools,
// `ur support` and the apps' Support()) and alone holds the feedback service's token and the outbox, so no agent holds
// either (I-7, R-CTX-9). An agent learns only an outcome.
//
// Send runs §28.6's checks in order, each failing only its call (§28.14):
//
//	release     the release's support switch (SupportSettings.ServiceEnabled), off until G-SUP-service passes
//	network     the compute block's support: egress on, persons, auto_only or off; agents and logs
//	person      the person's support key, {"agents": true, "agent_logs": true}, written only by their own act
//	disclosure  support:urnetwork acknowledged at its current version, else disclosure_required
//	form        16 KiB of UTF-8, control characters dropped, hidden text refused; files at most 3 of 10 MiB, UTF-8
//	            text, PNG or JPEG
//	secrets     a match refuses an agent's message, secret_in_message, and warns on a person's
//	gate        W for a Harness run that has read nothing untrusted, carries no private mark and names no file; kind 27
//	            for every other agent's message (approval_compute_support.go), whose effect is the outbox's
//	limits      §28.14's: an agent's 5 an hour and 20 a day, this device's 50 a day across agents, the person's 10 and 50,
//	            and the outbox's 10 waiting per agent and 50 per device; one bundle a network every 5 minutes
//	outbox      the body, its attachments and its client_ref kept in the device's state before the first post, then
//	            posted by the run loop, with the vault's kind-30 entry written as it leaves
//
// and answers at once: queued, or approval_pending with the request's id, never waiting for the service or the person.
// A message goes only to the host the newest verified policy names, over TLS (IC-24); nothing in it is sealed, since the
// support conversation is meant to be fully read by the platform (CO-46).
//
// The run loop posts what waits, after 1 minute and then twice as long each time up to an hour, for 7 days under one
// client_ref, then gives up, and reads the member's events by a cursor, each a kind-30 entry and a SupportUpdate to the
// listeners: enumerated fields only, which taint nothing (§28.9). A reply's text reaches a run only through Read, which
// taints the run first.
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What a support surface answers with the release's switch off, or the client gone.
var ErrSupportUnavailable = errors.New("support is not available in this release: reach support through the app's form")

// Where a message comes from, which decides its gate (§28.8).
type SupportSurface string

const (
	// The person: typed in an app, or ur support send confirmed on /dev/tty with no harness process among its ancestors.
	SupportSurfacePerson SupportSurface = "person"
	// A Harness run's support_send, local or in the member's enclave.
	SupportSurfaceHarness SupportSurface = "harness"
	// An MCP session's support_send, whose run counts as tainted (Q-SUP-8).
	SupportSurfaceMcp SupportSurface = "mcp"
	// ur support send from a harness's process, which counts as an MCP session's (Q-SUP-8).
	SupportSurfaceCliHarness SupportSurface = "cli_harness"
	// A call through an enclave's container socket, every one a tainted run's (§11.10).
	SupportSurfaceContainer SupportSurface = "container"
)

// What a Harness run is, as the Harness's run file and marks say (§7.8, DESIGN §16.6).
type SupportRun struct {
	RunId Id
	// The tool call's id, which a resumed run repeats, so the message's client_ref does too (§28.6).
	ToolCallId string
	Tainted    bool
	// The run file's taint reasons, field 48.
	TaintReasons []string
	// The run carries the private mark: it read the person's mail, calendars, connected accounts or vault files.
	Private bool
	// Whether the run's marks could be read at all; a run whose marks are unknown is taken as marked.
	MarksKnown bool
}

// Who sends: the person, or an agent by its registered name and where it runs.
type SupportSender struct {
	AgentName string
	AgentId   *Id
	Where     string
}

// One message to send.
type SupportSendArgs struct {
	Surface SupportSurface
	Sender  *SupportSender
	// A Harness run's; nil for every other surface.
	Run  *SupportRun
	Text string
	// The item it continues; empty opens one.
	Entry string
	// FB section 4's hint: bug, feature, question, praise, security, other or empty.
	Kind string
	// Attach the support log's bundle.
	Logs  bool
	Files []*SupportFile
	// A person's message the scan warned on, which the person read and still sends (FB section 10.1).
	SecretConfirmed bool
}

// What Send answers.
type SupportSendResult struct {
	// queued or approval_pending.
	Outcome    string
	ClientRef  string
	ApprovalId *Id
	// The entry the message continues, or once the service has acknowledged it, the one it opened.
	Entry string
	// The bundle's manifest, where the message carries one: what an agent learns of it (§28.7).
	Manifest *SupportLogManifest
}

// Send's outcomes.
const (
	SupportOutcomeQueued          = "queued"
	SupportOutcomeApprovalPending = "approval_pending"
)

// What changed in the member's conversation, as every notice carries it: enumerated values only, never a reply's text,
// so taking one taints nothing (§28.9, D-SUP-6).
type SupportUpdate struct {
	Product string `json:"product"`
	Entry   string `json:"entry"`
	Seq     uint32 `json:"seq"`
	Type    string `json:"type"`
	Status  string `json:"status"`
	FixedIn string `json:"fixed_in"`
	Final   bool   `json:"final"`
	// The agents that sent messages on the item, by name, so a notice reaches each one's inbox.
	Agents []string `json:"agents,omitempty"`
}

// The person's support key (§28.6): whether their agents may write to support, and whether those messages may carry the
// support log. Written only by the person's own act, never by MCP, a run or a server.
type SupportPersonKey struct {
	Agents    bool `json:"agents"`
	AgentLogs bool `json:"agent_logs"`
}

// What a SupportClient is built on: the parts of its Sidecar it uses, which a test may fake.
type supportHost interface {
	SecretMatcher() (*SecretMatcher, error)
	Authorize(ctx context.Context, action *SidecarAction, decision *bridge.Signed) error
	RegisterEffectLookup(kind SidecarActionKind, lookup SidecarEffectLookup) func()
	Runs() (*RunStore, error)
	supportRecords() (RecordWriter, error)
}

// The vault's writer for kind 30, from the Sidecar's record.
func (self *Sidecar) supportRecords() (RecordWriter, error) {
	record, err := self.Record()
	if err != nil {
		return nil, err
	}
	return record.Writer(), nil
}

// What a SupportClient is made with.
type SupportClientArgs struct {
	Host     supportHost
	Settings *SupportSettings
	// The process's support log: its writes and its bundles. Nil keeps no codes and attaches no bundle.
	Log *SupportLog
	// The device's sealed state, read at each use: the outbox, the conversation's view and its cursor, the limits and the
	// person's key. A Sidecar's resolves once it has enrolled, so a client built before that works after it.
	Store func() (SidecarStore, error)
	// Nil reads real time.
	Clock Clock
	// What a bundle's header says of the host.
	BundleHost *SupportLogBundleHost
	// The service's client, nil for one that verifies against the system's roots: a test sets one trusting its server.
	HttpClient *http.Client
	Sources    *SupportSources
	// No run loop: a test drives each pass itself, so what it reads is what one pass did.
	manual bool
}

// A Sidecar's support client.
type SupportClient struct {
	ctx        context.Context
	cancel     context.CancelFunc
	host       supportHost
	settings   *SupportSettings
	log        *SupportLog
	store      func() (SidecarStore, error)
	clock      Clock
	bundleHost *SupportLogBundleHost
	service    *supportService
	wake       chan struct{}
	runDone    chan struct{}
	closeOnce  sync.Once
	// kind 27's lookup, removed at Close
	unregisterLookup func()

	sourcesLock sync.Mutex
	sources     *SupportSources

	// held across a state file's read, change and write, outside stateLock
	storeLock sync.Mutex
	// held from a message's limits check until it is in the outbox, so two sends at once cannot both pass a limit one
	// of them reaches; taken before storeLock, never inside it
	sendLock sync.Mutex

	stateLock sync.Mutex
	// guarded by stateLock
	listeners      map[int]func(update *SupportUpdate)
	nextListenerId int
}

// A client on args, its run loop started; Close stops it. Its store is read at use, never here.
func NewSupportClient(args *SupportClientArgs) (*SupportClient, error) {
	if args == nil || args.Host == nil || args.Settings == nil || args.Store == nil {
		return nil, errors.New("a support client needs its host, settings and store")
	}
	ctx, cancel := context.WithCancel(context.Background())
	sources := args.Sources
	if sources == nil {
		sources = &SupportSources{}
	}
	self := &SupportClient{
		ctx:        ctx,
		cancel:     cancel,
		host:       args.Host,
		settings:   args.Settings,
		log:        args.Log,
		store:      args.Store,
		clock:      clockOrReal(args.Clock),
		bundleHost: args.BundleHost,
		service:    newSupportService(args.HttpClient, args.Settings),
		wake:       make(chan struct{}, 1),
		runDone:    make(chan struct{}),
		sources:    sources,
		listeners:  map[int]func(update *SupportUpdate){},
	}
	self.unregisterLookup = args.Host.RegisterEffectLookup(SidecarActionSupportSend, self.lookup)
	if args.manual {
		close(self.runDone)
	} else {
		go self.run()
	}
	return self, nil
}

// The client's settings, which a surface reads its bounds from; never changed through this.
func (self *SupportClient) Settings() *SupportSettings {
	return self.settings
}

// Replaces what the client reads beyond its Sidecar.
func (self *SupportClient) SetSources(sources *SupportSources) {
	if sources == nil {
		sources = &SupportSources{}
	}
	self.sourcesLock.Lock()
	defer self.sourcesLock.Unlock()
	self.sources = sources
	self.poke()
}

// The sources as SetSources last set them.
func (self *SupportClient) currentSources() *SupportSources {
	self.sourcesLock.Lock()
	defer self.sourcesLock.Unlock()
	return self.sources
}

// Wakes the run loop.
func (self *SupportClient) poke() {
	select {
	case self.wake <- struct{}{}:
	default:
	}
}

// Stops the run loop and removes kind 27's lookup. What waits stays in the outbox for the next start.
func (self *SupportClient) Close() {
	self.closeOnce.Do(func() {
		self.cancel()
		<-self.runDone
		if self.unregisterLookup != nil {
			self.unregisterLookup()
		}
	})
}

// Adds a listener for the conversation's updates, which it takes on the run loop's goroutine and must not block; the
// answer removes it.
func (self *SupportClient) AddListener(listener func(update *SupportUpdate)) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	listenerId := self.nextListenerId
	self.nextListenerId += 1
	self.listeners[listenerId] = listener
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.listeners, listenerId)
	}
}

// Tells each listener of update, outside every lock.
func (self *SupportClient) notify(update *SupportUpdate) {
	listeners := func() []func(update *SupportUpdate) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listeners := make([]func(update *SupportUpdate), 0, len(self.listeners))
		for _, listener := range self.listeners {
			listeners = append(listeners, listener)
		}
		return listeners
	}()
	for _, listener := range listeners {
		listener(update)
	}
}

// The person's support key, its defaults where they never set it.
func (self *SupportClient) PersonKey() (*SupportPersonKey, error) {
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	return &SupportPersonKey{Agents: state.PersonKey.Agents, AgentLogs: state.PersonKey.AgentLogs}, nil
}

// Writes the person's support key: only from their own act, in an app's UI or confirmed on /dev/tty with no harness
// process among its caller's ancestors, which the surface checks before it calls.
func (self *SupportClient) SetPersonKey(key *SupportPersonKey) error {
	return self.changeState(func(state *supportState) error {
		state.PersonKey = &SupportPersonKey{Agents: key.Agents, AgentLogs: key.AgentLogs}
		return nil
	})
}

// A refusal of an agent's or the person's message, recorded in the support log by its code and never its text.
func (self *SupportClient) refuse(args *SupportSendArgs, refusal *SupportRefusalError) error {
	tier := SupportLogTierAgent
	if args.Surface == SupportSurfacePerson {
		tier = SupportLogTierHuman
	}
	agentId, runId := []byte(nil), []byte(nil)
	if args.Sender != nil && args.Sender.AgentId != nil {
		agentId = args.Sender.AgentId.Bytes()
	}
	if args.Run != nil {
		runId = args.Run.RunId.Bytes()
	}
	self.log.Event(SupportLogCodeSupportMessageRefused, SupportLogFieldRefusal(supportRefusalLogValues[refusal.Refusal]),
		SupportLogFieldTier(tier), SupportLogFieldAgent(agentId), SupportLogFieldRun(runId))
	return refusal
}

// One message, through §28.6's checks in order; the file header gives them. A refusal is a *SupportRefusalError, which
// fails only the call; any other error is the device's, not the message's.
func (self *SupportClient) Send(ctx context.Context, args *SupportSendArgs) (*SupportSendResult, error) {
	if args == nil {
		return nil, errors.New("support: no message")
	}
	person := args.Surface == SupportSurfacePerson
	if !person && (args.Sender == nil || args.Sender.AgentName == "") {
		return nil, errors.New("support: an agent's message names its agent")
	}
	if args.Surface == SupportSurfaceHarness && args.Run == nil {
		return nil, errors.New("support: a Harness message names its run")
	}
	if !self.settings.ServiceEnabled {
		return nil, ErrSupportUnavailable
	}
	sources := self.currentSources()

	// network
	network := defaultSupportNetworkSettings()
	if sources.Network != nil {
		read, err := sources.Network.SupportNetwork()
		if err != nil {
			return nil, fmt.Errorf("support: the network's settings: %w", err)
		}
		network = read
	}
	if network.Paused {
		return nil, self.refuse(args, supportRefused(SupportRefusalPaused))
	}
	switch {
	case network.Egress == SupportEgressOn:
	case network.Egress == SupportEgressPersons && person:
	default:
		return nil, self.refuse(args, supportRefused(SupportRefusalSupportOff))
	}
	if !person && (!network.Agents || (args.Logs && !network.Logs)) {
		return nil, self.refuse(args, supportRefused(SupportRefusalSupportOff))
	}

	// person
	if !person {
		key, err := self.PersonKey()
		if err != nil {
			return nil, err
		}
		if !key.Agents || (args.Logs && !key.AgentLogs) {
			return nil, self.refuse(args, supportRefused(SupportRefusalSupportOff))
		}
	}

	// disclosure, grace 0: only the current version lets a message go
	disclosureVersion := uint32(0)
	if sources.Disclosures != nil {
		if disclosure, err := sources.Disclosures.SupportDisclosure(); err == nil && disclosure != nil &&
			0 < disclosure.Current && disclosure.Acknowledged == disclosure.Current {
			disclosureVersion = disclosure.Current
		}
	}
	if disclosureVersion == 0 {
		refusal := supportRefused(SupportRefusalDisclosureRequired)
		refusal.DisclosureId = SupportDisclosureId
		return nil, self.refuse(args, refusal)
	}

	// form
	text, err := supportFormText(args.Text, self.settings.MessageMaxByteCount)
	if err != nil {
		var refusal *SupportRefusalError
		errors.As(err, &refusal)
		return nil, self.refuse(args, refusal)
	}
	kind, ok := supportKindNumber(args.Kind)
	if !ok {
		return nil, self.refuse(args, supportRefused(SupportRefusalNotText))
	}
	if args.Entry != "" && !supportEntryPattern.MatchString(args.Entry) {
		return nil, self.refuse(args, supportRefused(SupportRefusalNotFound))
	}
	if self.settings.FileMaxCount < len(args.Files) {
		return nil, self.refuse(args, supportRefused(SupportRefusalFileRefused))
	}
	fileTypes := make([]uint32, len(args.Files))
	for i, file := range args.Files {
		if fileTypes[i], err = supportFileType(file, self.settings.FileMaxByteCount); err != nil {
			refusal := supportRefused(SupportRefusalFileRefused)
			refusal.FileIndex = i
			return nil, self.refuse(args, refusal)
		}
	}

	// secrets
	matcher, err := self.host.SecretMatcher()
	if err != nil {
		// a message no scan can read is never sent unchecked
		return nil, fmt.Errorf("support: the secret scan cannot run: %w", err)
	}
	var extra *SecretMatcher
	if sources.Secrets != nil {
		extra = NewSecretMatcher(sources.Secrets.SupportSecrets(), nil)
	}
	if found := supportScan(matcher, extra, text, args.Files, fileTypes); found != nil {
		if !person {
			return nil, self.refuse(args, found)
		}
		if !args.SecretConfirmed {
			found.Refusal = SupportRefusalSecretWarned
			return nil, found
		}
	}

	// gate: who decides, which the tier and the sender say
	outward := false
	run := args.Run
	switch args.Surface {
	case SupportSurfacePerson:
	case SupportSurfaceHarness:
		outward = run.Tainted || run.Private || !run.MarksKnown || 0 < len(args.Files)
	default:
		// an MCP session's, a harness process's and a container socket's: the person, inputs_unknown (Q-SUP-8)
		outward = true
	}

	// limits, before a person is asked about a message that could not go
	self.sendLock.Lock()
	defer self.sendLock.Unlock()
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	agentName := ""
	if !person {
		agentName = args.Sender.AgentName
	}
	if refusal := self.limitRefusal(state, agentName, args.Logs); refusal != nil {
		return nil, self.refuse(args, refusal)
	}

	// the message
	var clientRef []byte
	if run != nil && run.ToolCallId != "" {
		clientRef = SupportClientRefOfRun(run.RunId, run.ToolCallId)
	} else if clientRef, err = newSupportClientRef(); err != nil {
		return nil, err
	}
	tier := SupportTierAgent
	approved := SupportApprovedNone
	sender := &SupportBodySender{}
	if person {
		tier = SupportTierHuman
		sender.Person = true
	} else {
		sender.Agent, sender.Where = args.Sender.AgentName, args.Sender.Where
		sender.Tainted = outward && args.Surface != SupportSurfaceHarness || (run != nil && run.Tainted)
		sender.Approved = SupportApprovedNone
		if outward {
			// no one has decided when field 3 hashes the body: the decision gives the tier and the approver, which the
			// effect keeps and the post carries beside the body (QD-1398, supportOutboxEffect)
			sender.Approved, tier, approved = "", "", ""
		}
	}
	var bundle *SupportLogBundle
	if args.Logs {
		if self.log == nil {
			return nil, errors.New("support: no support log runs in this process")
		}
		since := time.Time{}
		if args.Entry != "" {
			since = state.itemStart(args.Entry)
		}
		if bundle, err = self.log.Bundle(&SupportLogBundleArgs{Since: since, Host: self.bundleHost}); err != nil {
			return nil, err
		}
	}
	body := &SupportBody{
		V:          supportBodyVersion,
		Product:    SupportProductUrnetwork,
		ClientRef:  supportClientRefText(clientRef),
		Entry:      args.Entry,
		Tier:       tier,
		Kind:       args.Kind,
		Text:       text,
		Sender:     sender,
		Disclosure: disclosureVersion,
	}
	if bundle != nil {
		body.Bundle = &SupportBodyAttachment{Sha256: hex.EncodeToString(bundle.Manifest.Sha256), Bytes: bundle.Manifest.ByteCount}
	}
	fileFields := []*protocol.FileFields{}
	for i, file := range args.Files {
		sum := sha256.Sum256(file.Data)
		body.Files = append(body.Files, &SupportBodyAttachment{
			Type: supportFileTypeNames[fileTypes[i]], Name: file.Name, Sha256: hex.EncodeToString(sum[:]), Bytes: int64(len(file.Data)),
		})
		fileFields = append(fileFields, &protocol.FileFields{Name: file.Name, Type: fileTypes[i], Size: uint64(len(file.Data)), Sha256: sum[:]})
	}
	encoded, err := body.encode()
	if err != nil {
		return nil, err
	}
	item := &supportOutboxItem{
		ClientRef:     body.ClientRef,
		Body:          encoded,
		Entry:         args.Entry,
		Agent:         agentName,
		Tier:          tier,
		Approved:      approved,
		Logs:          bundle != nil,
		FileCount:     len(args.Files),
		CreatedMillis: self.clock.Now().UnixMilli(),
		State:         supportOutboxPending,
		Disclosure:    disclosureVersion,
	}
	if args.Sender != nil {
		item.AgentId = args.Sender.AgentId
	}
	if bundle != nil {
		item.Manifest = bundle.Manifest
	}
	attachments := [][]byte{}
	if bundle != nil {
		attachments = append(attachments, bundle.Bytes)
	} else {
		attachments = append(attachments, nil)
	}
	for _, file := range args.Files {
		attachments = append(attachments, file.Data)
	}
	item.FileTypes = fileTypes
	result := &SupportSendResult{Outcome: SupportOutcomeQueued, ClientRef: body.ClientRef, Entry: args.Entry}
	if bundle != nil {
		result.Manifest = bundle.Manifest
	}

	if !outward {
		if err := self.enqueue(item, attachments, bundle); err != nil {
			return nil, err
		}
		self.logQueued(args, item, SupportLogDeciderNone)
		return result, nil
	}

	// kind 27: the message waits in the outbox until a decision spends it; the effect lets it go
	support := &protocol.SupportFields{
		Product: SupportProductUrnetwork, Entry: args.Entry, Kind: kind, Text: text, Files: fileFields, ClientRef: clientRef,
	}
	if bundle != nil {
		support.Bundle = supportBundleManifestFields(bundle.Manifest)
	}
	taintReasons := []string{}
	private := false
	if run != nil {
		taintReasons = slices.Clone(run.TaintReasons)
		private = args.Surface == SupportSurfaceHarness && (run.Private || !run.MarksKnown)
	}
	countsTainted := args.Surface != SupportSurfaceHarness || (run != nil && run.Tainted)
	stored, err := NewSupportSendAction(&SupportSendActionArgs{
		Body: encoded, Support: support, TaintReasons: taintReasons, CountsTainted: countsTainted, Private: private,
	})
	if err != nil {
		return nil, err
	}
	item.State = supportOutboxAwaiting
	item.Canonical = stored.Bytes
	if run != nil {
		runId := run.RunId
		item.RunId = &runId
	}
	if err := self.storeOutboxItem(item, attachments, bundle); err != nil {
		return nil, err
	}
	approvalId, err := self.authorize(ctx, item)
	if err != nil {
		return nil, err
	}
	if approvalId != nil {
		result.Outcome = SupportOutcomeApprovalPending
		result.ApprovalId = approvalId
	}
	self.logQueued(args, item, SupportLogDeciderPerson)
	return result, nil
}

// field 80's manifest from a bundle's.
func supportBundleManifestFields(manifest *SupportLogManifest) *protocol.BundleManifest {
	fields := &protocol.BundleManifest{
		Events: uint32(manifest.Events), First: manifest.First, Last: manifest.Last, Bytes: uint64(manifest.ByteCount),
		Sha256: slices.Clone(manifest.Sha256),
	}
	for _, code := range manifest.Codes {
		fields.Codes = append(fields.Codes, &protocol.BundleCodeCount{Component: code.Component, Code: code.Code, Count: uint32(code.Count)})
	}
	return fields
}

// The support log's tier of a message's, false for one no decision has given a tier yet.
func supportLogTierOf(tier SupportTier) (SupportLogTier, bool) {
	logTier, ok := map[SupportTier]SupportLogTier{
		SupportTierHuman: SupportLogTierHuman, SupportTierReleased: SupportLogTierReleased, SupportTierAgent: SupportLogTierAgent,
		SupportTierAuto: SupportLogTierAuto,
	}[tier]
	return logTier, ok
}

// The support log's message_queued for item: its tier where it has one, which a message awaiting kind 27's decision
// has not.
func (self *SupportClient) logQueued(args *SupportSendArgs, item *supportOutboxItem, decider SupportLogDecider) {
	outcome := SupportLogOutcomeQueued
	if item.State == supportOutboxAwaiting {
		outcome = SupportLogOutcomeApprovalPending
	}
	agentId, runId := []byte(nil), []byte(nil)
	if item.AgentId != nil {
		agentId = item.AgentId.Bytes()
	}
	if args != nil && args.Run != nil {
		runId = args.Run.RunId.Bytes()
	}
	tainted := args != nil && args.Run != nil && args.Run.Tainted
	if tier, ok := supportLogTierOf(item.Tier); ok {
		self.log.Event(SupportLogCodeSupportMessageQueued, SupportLogFieldOutcome(outcome), SupportLogFieldTier(tier),
			SupportLogFieldBodyBytes(int64(len(item.Body))), SupportLogFieldWithBundle(item.Logs), SupportLogFieldFiles(int64(item.FileCount)),
			SupportLogFieldTainted(tainted), SupportLogFieldDecider(decider), SupportLogFieldAgent(agentId), SupportLogFieldRun(runId),
			SupportLogFieldRequest([]byte(item.ClientRef)))
		return
	}
	self.log.Event(SupportLogCodeSupportMessageQueued, SupportLogFieldOutcome(outcome),
		SupportLogFieldBodyBytes(int64(len(item.Body))), SupportLogFieldWithBundle(item.Logs), SupportLogFieldFiles(int64(item.FileCount)),
		SupportLogFieldTainted(tainted), SupportLogFieldDecider(decider), SupportLogFieldAgent(agentId), SupportLogFieldRun(runId),
		SupportLogFieldRequest([]byte(item.ClientRef)))
}

// §28.14's limits for a message of agentName ("" the person's), from what this device sent and holds: the refusal, or
// nil.
func (self *SupportClient) limitRefusal(state *supportState, agentName string, logs bool) *SupportRefusalError {
	now := self.clock.Now()
	hourAgo, dayAgo := now.Add(-time.Hour).UnixMilli(), now.Add(-24*time.Hour).UnixMilli()
	hourCount, dayCount, deviceDayCount, waiting, deviceWaiting := 0, 0, 0, 0, 0
	oldestInHour, oldestInDay := int64(0), int64(0)
	for _, sent := range state.Sends {
		if sent.Millis < dayAgo {
			continue
		}
		if sent.Agent != "" {
			deviceDayCount += 1
		}
		if sent.Agent != agentName {
			continue
		}
		dayCount += 1
		if oldestInDay == 0 || sent.Millis < oldestInDay {
			oldestInDay = sent.Millis
		}
		if hourAgo <= sent.Millis {
			hourCount += 1
			if oldestInHour == 0 || sent.Millis < oldestInHour {
				oldestInHour = sent.Millis
			}
		}
	}
	for _, waitingItem := range state.Waiting {
		deviceWaiting += 1
		if waitingItem == agentName {
			waiting += 1
		}
	}
	hourMax, dayMax := self.settings.AgentHourMaxCount, self.settings.AgentDayMaxCount
	if agentName == "" {
		hourMax, dayMax = self.settings.PersonHourMaxCount, self.settings.PersonDayMaxCount
	}
	retryAfter := func(oldest int64, window time.Duration) *SupportRefusalError {
		refusal := supportRefused(SupportRefusalRateLimited)
		refusal.RetryAfter = time.UnixMilli(oldest).Add(window).Sub(now)
		return refusal
	}
	switch {
	case hourMax <= hourCount:
		return retryAfter(oldestInHour, time.Hour)
	case dayMax <= dayCount:
		return retryAfter(oldestInDay, 24*time.Hour)
	case agentName != "" && self.settings.NetworkDayMaxCount <= deviceDayCount:
		refusal := supportRefused(SupportRefusalRateLimited)
		refusal.RetryAfter = time.Hour
		return refusal
	case agentName != "" && self.settings.OutboxAgentMaxCount <= waiting, self.settings.OutboxDeviceMaxCount <= deviceWaiting:
		return supportRefused(SupportRefusalQueueFull)
	case logs && state.LastBundleMillis != 0 && now.Sub(time.UnixMilli(state.LastBundleMillis)) < self.settings.BundleMinInterval:
		refusal := supportRefused(SupportRefusalRateLimited)
		refusal.RetryAfter = time.UnixMilli(state.LastBundleMillis).Add(self.settings.BundleMinInterval).Sub(now)
		return refusal
	}
	return nil
}

// Files a kind-27 item's request, or spends its decision: nil once the effect ran, the request's id while a person
// decides. A decline answers the request's state as declined and removes the item.
func (self *SupportClient) authorize(ctx context.Context, item *supportOutboxItem) (*Id, error) {
	stored, err := ParseStoredCanonicalAction(item.Canonical)
	if err != nil {
		return nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskNormal, item.RunId, item.AgentId)
	if err != nil {
		return nil, err
	}
	action.Summary = "a message to URnetwork's support, which its team and the subprocessors its disclosure names will read"
	action.Effect = &supportOutboxEffect{client: self, clientRef: item.ClientRef}
	err = self.host.Authorize(ctx, action, nil)
	var pending *ApprovalPendingError
	switch {
	case errors.As(err, &pending):
		approvalId := pending.ApprovalId
		changeErr := self.changeOutboxItem(item.ClientRef, func(stored *supportOutboxItem) {
			stored.ApprovalId = &approvalId
		})
		return &approvalId, changeErr
	case err != nil:
		return nil, err
	}
	return nil, nil
}

// Kind 27's effect: the approved message, moved from awaiting to pending, which the run loop posts. Idempotent per
// client_ref: a second run finds it moved.
type supportOutboxEffect struct {
	client    *SupportClient
	clientRef string
}

// Moves the approved message to pending, with the tier and the approver its decision gives it, which the post carries
// beside the body (QD-1398), and wakes the loop; its reference is the client_ref. A decision spends only on the
// message its approver saw: where the stored action's field 3, or the decided action's, hashes another body than the
// outbox holds, nothing moves and the use is not done.
func (self *supportOutboxEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	var spend *ApprovalSpend
	approved := SupportApprovedPerson
	if spent, ok := ApprovalSpendFromContext(ctx); ok {
		spend = spent
		approved = supportDeciderOf(spent.Decisions)
	}
	moved, binds := false, true
	err := self.client.changeOutboxItem(self.clientRef, func(item *supportOutboxItem) {
		if item.State != supportOutboxAwaiting {
			return
		}
		if !supportOutboxItemBinds(item, spend) {
			binds = false
			return
		}
		item.State = supportOutboxPending
		item.Approved = approved
		item.Tier = supportTierOfDecider(approved)
		moved = true
	})
	if err != nil {
		if errors.Is(err, errSupportOutboxItemAbsent) {
			return nil, fmt.Errorf("%w: no waiting message", ErrSidecarEffectNotDone)
		}
		return nil, err
	}
	if !binds {
		return nil, fmt.Errorf("%w: the decision binds another message than the outbox holds", ErrSidecarEffectNotDone)
	}
	if moved {
		if err := self.client.noteWaiting(self.clientRef); err != nil {
			return nil, err
		}
		self.client.poke()
	}
	return []byte(self.clientRef), nil
}

// Who decided a use from the decisions it spent: the person where one of them is a person's, on another device, by a
// presence key or at the harness prompt; the classifier otherwise, channel 4's decisions (§27.9) and any that does not
// parse, so a person's approval is claimed only where a decision shows one.
func supportDeciderOf(decisions [][]byte) string {
	for _, stored := range decisions {
		decision, err := ParseStoredApprovalDecision(stored)
		if err != nil {
			continue
		}
		switch protocol.ApprovalChannel(decision.Decision.GetChannel()) {
		case protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE, protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE,
			protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS:
			return SupportApprovedPerson
		}
	}
	return SupportApprovedClassifier
}

// Whether item's stored action binds its body, and the action spend decided does too where it is kind 27's (§28.8):
// what a decision approved is what the post sends.
func supportOutboxItemBinds(item *supportOutboxItem, spend *ApprovalSpend) bool {
	stored, err := ParseStoredCanonicalAction(item.Canonical)
	if err != nil || !supportSendActionBinds(stored.Action, item.Body) {
		return false
	}
	if spend == nil || len(spend.Action) == 0 {
		return true
	}
	decided, err := ParseStoredCanonicalAction(spend.Action)
	if err != nil {
		return false
	}
	return SidecarActionKind(decided.Action.GetKind()) != SidecarActionSupportSend || supportSendActionBinds(decided.Action, item.Body)
}

// Who let item go, as its post says beside the body: what its decision or its sending set, else, for a message stored
// before the outbox kept it, what its tier says.
func (self *supportOutboxItem) approved() string {
	switch {
	case self.Approved != "":
		return self.Approved
	case self.Tier == SupportTierReleased:
		return SupportApprovedPerson
	}
	return SupportApprovedNone
}

// Kind 27's lookup (record_effect.go): done where the outbox holds the message past awaiting or the service holds its
// entry, not_done where the outbox holds it awaiting, uncertain otherwise.
func (self *SupportClient) lookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	stored, err := ParseStoredCanonicalAction(canonical)
	if err != nil {
		return nil, err
	}
	clientRef := supportClientRefText(stored.Action.GetSupport().GetClientRef())
	item, err := self.outboxItem(clientRef)
	switch {
	case err == nil && item.State == supportOutboxAwaiting:
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	case err == nil:
		return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: []byte(clientRef)}, nil
	case !errors.Is(err, errSupportOutboxItemAbsent):
		return nil, err
	}
	host, token, err := self.hostAndToken(ctx)
	if err != nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	entry, err := self.service.lookup(ctx, host, token, clientRef)
	if err != nil || entry == nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	return &SidecarOutcome{State: ApprovalOutcomeDone, EffectRef: []byte(clientRef)}, nil
}

// The policy's host and a token, or why there is none.
func (self *SupportClient) hostAndToken(ctx context.Context) (string, string, error) {
	sources := self.currentSources()
	if sources.Policy == nil {
		return "", "", supportRefused(SupportRefusalNoHost)
	}
	line, err := sources.Policy.SupportLine()
	if err != nil || line == nil || line.Host == "" {
		return "", "", supportRefused(SupportRefusalNoHost)
	}
	if sources.Tokens == nil {
		return "", "", &supportServiceError{result: SupportLogPostResultUnauthorized}
	}
	token, err := sources.Tokens.SupportToken(ctx)
	if err != nil || token == "" {
		self.log.Event(SupportLogCodeSupportTokenFailed, SupportLogFieldPostResult(SupportLogPostResultUnauthorized))
		return "", "", &supportServiceError{result: SupportLogPostResultUnauthorized}
	}
	return line.Host, token, nil
}

// The loop: posts what is due, spends decisions on what awaits one, reads the member's events, and prunes, each wake or
// interval.
func (self *SupportClient) run() {
	defer close(self.runDone)
	for {
		self.pass()
		select {
		case <-self.ctx.Done():
			return
		case <-self.wake:
		case <-self.clock.After(self.settings.LoopInterval):
		}
	}
}

// One pass of the loop.
func (self *SupportClient) pass() {
	if !self.settings.ServiceEnabled {
		return
	}
	items, err := self.outboxItems()
	if err != nil {
		return
	}
	now := self.clock.Now()
	for _, item := range items {
		if self.ctx.Err() != nil {
			return
		}
		switch item.State {
		case supportOutboxAwaiting:
			if self.settings.RetryWindow <= now.Sub(time.UnixMilli(item.CreatedMillis)) {
				// no decision in the window: not sent, and never sent again but by the person (§16.3)
				self.changeOutboxItem(item.ClientRef, func(stored *supportOutboxItem) { stored.State = supportOutboxGivenUp })
				self.log.Event(SupportLogCodeSupportMessageGivenUp, SupportLogFieldAttempts(int64(item.Attempts)),
					SupportLogFieldWaited(now.Sub(time.UnixMilli(item.CreatedMillis))), SupportLogFieldEntry([]byte(item.Entry)))
				continue
			}
			if _, err := self.authorize(self.ctx, item); err != nil && !errors.Is(err, ErrSidecarEffectNotDone) {
				continue
			}
		case supportOutboxPending:
			if now.UnixMilli() < item.NextMillis {
				continue
			}
			self.post(item)
		case supportOutboxPosted:
			// a given-up message stays, shown as not sent until the person removes it
			if self.settings.SentBundleRetention < now.Sub(time.UnixMilli(item.CreatedMillis)) {
				self.removeOutboxItem(item.ClientRef)
			}
		}
	}
	self.readEvents()
}

// Posts one message, its attachments after it, and records what came of it: posted, retried later, or given up.
func (self *SupportClient) post(item *supportOutboxItem) {
	now := self.clock.Now()
	waited := now.Sub(time.UnixMilli(item.CreatedMillis))
	host, token, err := self.hostAndToken(self.ctx)
	var answer *supportEntryAnswer
	if err == nil {
		// the vault's entry as the message first leaves (§28.6's outbox row, §28.12): its entry the item it continues or
		// none and its seq 0, until the service's acknowledgment, which its client_ref joins
		self.recordLeaving(item)
		answer, err = self.service.postMessage(self.ctx, host, token, item.ClientRef, item.Entry, item.Body, item.Tier, item.approved())
	}
	if err == nil {
		err = self.postAttachments(host, token, answer.Id, item)
	}
	if err != nil {
		result := supportServiceResultOf(err)
		attempts := item.Attempts + 1
		givenUp := !supportServiceRetryable(err) && SupportRefusalOf(err) != SupportRefusalNoHost || self.settings.RetryWindow <= waited
		self.log.Event(SupportLogCodeSupportPostFailed, SupportLogFieldPostResult(result), SupportLogFieldAttempts(int64(attempts)))
		self.changeOutboxItem(item.ClientRef, func(stored *supportOutboxItem) {
			stored.Attempts = attempts
			if givenUp {
				stored.State = supportOutboxGivenUp
				return
			}
			backoff := self.settings.RetryFirstInterval
			for range min(attempts-1, 32) {
				backoff *= 2
				if self.settings.RetryMaxInterval <= backoff {
					backoff = self.settings.RetryMaxInterval
					break
				}
			}
			stored.NextMillis = now.Add(backoff).UnixMilli()
		})
		if givenUp {
			self.dropWaiting(item.ClientRef)
			self.log.Event(SupportLogCodeSupportMessageGivenUp, SupportLogFieldAttempts(int64(attempts)), SupportLogFieldWaited(waited),
				SupportLogFieldEntry([]byte(item.Entry)))
			self.noteItem(&SupportUpdate{Product: SupportProductUrnetwork, Entry: item.Entry, Type: "not_sent"}, nil)
		}
		return
	}
	result := SupportLogPostResultAccepted
	if answer.Replayed {
		result = SupportLogPostResultReplayed
	}
	self.log.Event(SupportLogCodeSupportMessagePosted, SupportLogFieldPostResult(result), SupportLogFieldAttempts(int64(item.Attempts+1)),
		SupportLogFieldWaited(waited), SupportLogFieldEntry([]byte(answer.Id)))
	self.changeOutboxItem(item.ClientRef, func(stored *supportOutboxItem) {
		stored.State = supportOutboxPosted
		stored.Entry = answer.Id
		stored.Seq = answer.Seq
	})
	self.dropWaiting(item.ClientRef)
	self.noteSent(item, answer)
}

// Posts a message's bundle and files, each under the message's client_ref and its place.
func (self *SupportClient) postAttachments(host string, token string, entry string, item *supportOutboxItem) error {
	for index := 0; index <= item.FileCount; index += 1 {
		if index == 0 && !item.Logs {
			continue
		}
		data, err := self.outboxAttachment(item.ClientRef, index)
		if err != nil {
			return err
		}
		contentType := "application/gzip"
		if 0 < index {
			contentType = map[uint32]string{
				supportFileTypeText: "text/plain; charset=utf-8", supportFileTypePng: "image/png", supportFileTypeJpeg: "image/jpeg",
			}[item.FileTypes[index-1]]
		}
		key := fmt.Sprintf("%s-%d", item.ClientRef, index)
		if err := self.service.postAttachment(self.ctx, host, token, entry, key, contentType, data); err != nil {
			return err
		}
	}
	return nil
}

// Reads the member's events from the cursor, each into the conversation's view, a kind-30 entry and a notice.
func (self *SupportClient) readEvents() {
	host, token, err := self.hostAndToken(self.ctx)
	if err != nil {
		return
	}
	state, err := self.loadState()
	if err != nil {
		return
	}
	events := []*SupportServiceEvent{}
	cursor, err := self.service.events(self.ctx, host, token, state.Cursor, func(event *SupportServiceEvent) {
		events = append(events, event)
	})
	if err != nil {
		self.log.Event(SupportLogCodeSupportStreamChanged, SupportLogFieldStreamState(SupportLogStreamStateFailed),
			SupportLogFieldPostResult(supportServiceResultOf(err)))
	}
	for _, event := range events {
		self.receive(event)
	}
	if cursor != state.Cursor {
		self.changeState(func(state *supportState) error {
			state.Cursor = cursor
			return nil
		})
	}
}

// One event received: the view takes it, unless it holds its entry and seq already, as a second device's copy would;
// the vault records it; the listeners hear its enumerated fields.
func (self *SupportClient) receive(event *SupportServiceEvent) {
	var item *supportItem
	fresh := false
	self.changeState(func(state *supportState) error {
		item, fresh = state.apply(event, self.clock.Now(), self.settings.ConversationMaxItemCount)
		return nil
	})
	if !fresh {
		return
	}
	self.log.Event(SupportLogCodeSupportEventReceived, SupportLogFieldEntry([]byte(event.Entry)))
	self.recordReceived(event)
	self.noteItem(&SupportUpdate{
		Product: SupportProductUrnetwork, Entry: event.Entry, Seq: event.Seq, Type: event.Type, Status: item.Status,
		FixedIn: item.FixedIn, Final: item.Final,
	}, item)
}

// Tells the listeners of update, naming the agents of item's messages.
func (self *SupportClient) noteItem(update *SupportUpdate, item *supportItem) {
	if item != nil {
		update.Agents = slices.Clone(item.Agents)
	}
	self.notify(update)
}

// A message the service acknowledged: its place in the view and, where the view did not hold it already, the vault's
// entry of the acknowledgment, after the message's own entry where that was not written as it left.
func (self *SupportClient) noteSent(item *supportOutboxItem, answer *supportEntryAnswer) {
	body := supportOutboxBody(item)
	fresh := false
	self.changeState(func(state *supportState) error {
		fresh = state.applySent(answer, item, body, self.clock.Now(), self.settings.ConversationMaxItemCount)
		state.prune(self.clock.Now(), self.settings)
		return nil
	})
	self.recordLeaving(item)
	if fresh {
		self.recordAcknowledged(item, answer)
	}
}

// The vault's kind-30 entry of a message as it first leaves (§28.6's outbox row, §28.12): direction sent, its entry the
// item it continues or none, its seq 0, its text, label, bundle's manifest and files there, the team's projection
// holding none of them. Written once: the outbox item keeps that it was, so a retry writes none again. One that cannot
// be written is tried again at the next post and once the service acknowledges the message; a crash between the write
// and its mark writes it twice, which its client_ref joins as one.
func (self *SupportClient) recordLeaving(item *supportOutboxItem) {
	if item.Recorded {
		return
	}
	records, err := self.host.supportRecords()
	if err != nil {
		return
	}
	if _, err := records.Append(supportLeavingDraft(item, supportOutboxBody(item))); err != nil {
		return
	}
	item.Recorded = true
	self.changeOutboxItem(item.ClientRef, func(stored *supportOutboxItem) { stored.Recorded = true })
}

// An outbox message's body as the view and the vault read it: an enumerated report, which holds no text, read as its
// one line (support_report.go).
func supportOutboxBody(item *supportOutboxItem) *SupportBody {
	body := &SupportBody{}
	json.Unmarshal(item.Body, body)
	if item.Tier == SupportTierAuto {
		body.Text = supportReportSummary(item.Body)
	}
	return body
}

// The vault's entry of item as it leaves.
func supportLeavingDraft(item *supportOutboxItem, body *SupportBody) *RecordDraft {
	sum := sha256.Sum256(item.Body)
	message := &protocol.SupportMessageBody{
		Direction:         supportDirectionSent,
		Product:           SupportProductUrnetwork,
		Entry:             item.Entry,
		Type:              supportEventTypeNumber("submitted"),
		Tier:              supportTierNumber(item.Tier),
		ClientRef:         supportClientRefBytes(item.ClientRef),
		Text:              body.Text,
		BodySha256:        sum[:],
		BodyBytes:         uint64(len(item.Body)),
		ApprovalId:        supportIdBytes(item.ApprovalId),
		DisclosureVersion: item.Disclosure,
	}
	if item.Entry != "" {
		message.Type = supportEventTypeNumber("followup")
	}
	if body.Sender != nil && body.Sender.Agent != "" {
		message.AgentLabel = supportCut(strings.TrimSpace(body.Sender.Agent+" "+body.Sender.Where), DefaultRecordBodySettings().SupportAgentLabelByteCount)
	}
	for i, file := range body.Files {
		fileSha, _ := hex.DecodeString(file.Sha256)
		fileType := uint32(0)
		if i < len(item.FileTypes) {
			fileType = item.FileTypes[i]
		}
		message.Files = append(message.Files, &protocol.FileFields{Name: file.Name, Type: fileType, Size: uint64(file.Bytes), Sha256: fileSha})
	}
	switch {
	case item.Manifest != nil:
		message.Bundle = supportBundleManifestFields(item.Manifest)
	case body.Bundle != nil:
		bundleSha, _ := hex.DecodeString(body.Bundle.Sha256)
		message.Bundle = &protocol.BundleManifest{Bytes: uint64(body.Bundle.Bytes), Sha256: bundleSha}
	}
	source := RecordSourceObserved
	if item.Tier == SupportTierHuman {
		// the person's own message, typed in an app or confirmed on /dev/tty
		source = RecordSourceApprover
	}
	return &RecordDraft{
		Kind: RecordKindSupportMessage, Source: source, RunId: item.RunId, NoSession: item.RunId == nil, AgentId: item.AgentId, Body: message,
	}
}

// The vault's kind-30 entry of the service's acknowledgment of a message this device sent: direction received, the
// entry and seq it was given and its status, joined to the message's own entry by its client_ref, whose text that one
// holds.
func (self *SupportClient) recordAcknowledged(item *supportOutboxItem, answer *supportEntryAnswer) {
	records, err := self.host.supportRecords()
	if err != nil {
		return
	}
	settings := DefaultRecordBodySettings()
	message := &protocol.SupportMessageBody{
		Direction: supportDirectionReceived,
		Product:   SupportProductUrnetwork,
		Entry:     answer.Id,
		Seq:       answer.Seq,
		Type:      supportEventTypeNumber("submitted"),
		Tier:      supportTierNumber(item.Tier),
		ClientRef: supportClientRefBytes(item.ClientRef),
		Status:    supportStatusNumber(answer.Status),
	}
	if item.Entry != "" {
		message.Type = supportEventTypeNumber("followup")
	}
	if len(answer.FixedIn) <= settings.SupportFixedInByteCount {
		message.FixedIn = answer.FixedIn
	}
	records.Append(&RecordDraft{Kind: RecordKindSupportMessage, Source: RecordSourceObserved, NoSession: true, Body: message})
}

// The vault's kind-30 entry of an event received: a label past its bound cut at a character's edge and a fixed_in past
// its bound left out, so the service cannot keep an event off the record by its size.
func (self *SupportClient) recordReceived(event *SupportServiceEvent) {
	records, err := self.host.supportRecords()
	if err != nil {
		return
	}
	settings := DefaultRecordBodySettings()
	text := event.Note
	if text == "" {
		text = event.Body
	}
	message := &protocol.SupportMessageBody{
		Direction: supportDirectionReceived,
		Product:   SupportProductUrnetwork,
		Entry:     event.Entry,
		Seq:       event.Seq,
		Type:      supportEventTypeNumber(event.Type),
		Tier:      supportTierNumber(event.Tier),
		ClientRef: supportClientRefBytes(event.ClientRef),
		Text:      supportCut(text, settings.SupportTextByteCount),
		Status:    supportStatusNumber(event.Status),
	}
	if len(event.FixedIn) <= settings.SupportFixedInByteCount {
		message.FixedIn = event.FixedIn
	}
	if event.Agent != "" {
		message.AgentLabel = supportCut(event.Agent, settings.SupportAgentLabelByteCount)
	}
	records.Append(&RecordDraft{Kind: RecordKindSupportMessage, Source: RecordSourceObserved, NoSession: true, Body: message})
}

// text within maxByteCount bytes, cut at the last character's edge that fits.
func supportCut(text string, maxByteCount int) string {
	if len(text) <= maxByteCount {
		return text
	}
	cut := text[:maxByteCount]
	for !utf8.ValidString(cut) && 0 < len(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// SupportMessageBody.tier: 1 human, 2 released, 3 agent, and 0 for the auto tier and none.
func supportTierNumber(tier SupportTier) uint32 {
	switch tier {
	case SupportTierHuman:
		return supportTierNumberHuman
	case SupportTierReleased:
		return supportTierNumberReleased
	case SupportTierAgent:
		return supportTierNumberAgent
	}
	return 0
}

// A client_ref's 16 bytes from its hex, nil for none.
func supportClientRefBytes(clientRef string) []byte {
	decoded, err := hex.DecodeString(clientRef)
	if err != nil || len(decoded) != supportClientRefByteCount {
		return nil
	}
	return decoded
}

// An id's bytes, nil for none.
func supportIdBytes(id *Id) []byte {
	if id == nil {
		return nil
	}
	return id.Bytes()
}

// What List takes: the status to keep, empty for all; whose items, mine (the agent's own) or member (the whole
// conversation, which a run the person is attached to alone reads); and the caller.
type SupportListArgs struct {
	Status string
	// mine or member; empty is mine for an agent and member for the person
	Scope string
	// The agent asking, empty for the person.
	AgentName string
	// A run the person is attached to (§2.8's prompt row), which may read the member's whole conversation.
	PersonAttached bool
}

// One item as a stub (§28.4): never text.
type SupportItemStub struct {
	Entry   string   `json:"entry"`
	Status  string   `json:"status"`
	FixedIn string   `json:"fixed_in,omitempty"`
	Final   bool     `json:"final"`
	Senders []string `json:"senders"`
	// messages and replies, and replies the caller has not read
	Messages      int   `json:"messages"`
	Replies       int   `json:"replies"`
	UnreadReplies int   `json:"unread_replies"`
	FirstMillis   int64 `json:"first_ms"`
	UpdatedMillis int64 `json:"updated_ms"`
	// a message of the caller's still in the outbox, by client_ref, and one given up after 7 days
	Waiting  []string `json:"waiting,omitempty"`
	NotSent  []string `json:"not_sent,omitempty"`
	Approval []string `json:"approval_pending,omitempty"`
}

// The scope a caller may read: an agent its own items, the member's whole conversation only in a run its person is
// attached to (Q-SUP-12).
func supportListScope(args *SupportListArgs) (string, error) {
	scope := args.Scope
	if scope == "" {
		scope = "mine"
		if args.AgentName == "" {
			scope = "member"
		}
	}
	switch {
	case scope != "mine" && scope != "member":
		return "", supportRefused(SupportRefusalNotFound)
	case scope == "member" && args.AgentName != "" && !args.PersonAttached:
		return "", supportRefused(SupportRefusalNotFound)
	}
	return scope, nil
}

// The items the caller may see, as stubs, newest first; they taint nothing (§28.4).
func (self *SupportClient) List(args *SupportListArgs) ([]*SupportItemStub, error) {
	if args == nil {
		args = &SupportListArgs{}
	}
	scope, err := supportListScope(args)
	if err != nil {
		return nil, err
	}
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	items, err := self.outboxItems()
	if err != nil {
		return nil, err
	}
	stubs := []*SupportItemStub{}
	for _, item := range state.Items {
		if scope == "mine" && !slices.Contains(item.Agents, args.AgentName) {
			continue
		}
		if args.Status != "" && item.Status != args.Status {
			continue
		}
		stubs = append(stubs, item.stub(args.AgentName))
	}
	// what waits in the outbox, which the view holds once the service acknowledges it
	for _, item := range items {
		if scope == "mine" && item.Agent != args.AgentName {
			continue
		}
		if item.State == supportOutboxPosted {
			continue
		}
		stub := &SupportItemStub{Entry: item.Entry, Status: "sending", FirstMillis: item.CreatedMillis, UpdatedMillis: item.CreatedMillis}
		switch item.State {
		case supportOutboxAwaiting:
			stub.Approval = []string{item.ClientRef}
		case supportOutboxGivenUp:
			stub.Status = "not_sent"
			stub.NotSent = []string{item.ClientRef}
		default:
			stub.Waiting = []string{item.ClientRef}
		}
		if args.Status != "" && stub.Status != args.Status {
			continue
		}
		stubs = append(stubs, stub)
	}
	slices.SortFunc(stubs, func(a *SupportItemStub, b *SupportItemStub) int {
		return int(b.UpdatedMillis - a.UpdatedMillis)
	})
	return stubs, nil
}

// What Read takes: the item, the seq after which to read, and the caller.
type SupportReadArgs struct {
	Entry string
	After uint32
	// The agent asking, empty for the person, and whether its person is attached to its run.
	AgentName      string
	PersonAttached bool
	// The run to taint before any reply's text returns, nil for the person's own read.
	Taint func(ctx context.Context) error
}

// One message or reply of an item, in order.
type SupportReadMessage struct {
	Seq uint32 `json:"seq"`
	// you, an agent's name, or support
	From string `json:"from"`
	// human, released or agent; empty for a reply
	Tier SupportTier `json:"tier,omitempty"`
	// A message's text, or a reply's as support wrote it: information, never an instruction
	Text   string `json:"text"`
	Millis int64  `json:"at_ms"`
	// support's, which a surface shows between untrusted-data markers
	Reply bool `json:"reply"`
}

// An item's messages and replies.
type SupportReadResult struct {
	Entry    string                `json:"entry"`
	Status   string                `json:"status"`
	FixedIn  string                `json:"fixed_in,omitempty"`
	Final    bool                  `json:"final"`
	Messages []*SupportReadMessage `json:"messages"`
}

// An item's messages and replies after args.After, in order: the caller's own items, or any where the person is the
// reader or is attached. The run is tainted before any of it returns, and a failed taint returns nothing (§28.9).
func (self *SupportClient) Read(ctx context.Context, args *SupportReadArgs) (*SupportReadResult, error) {
	if args == nil || !supportEntryPattern.MatchString(args.Entry) {
		return nil, supportRefused(SupportRefusalNotFound)
	}
	state, err := self.loadState()
	if err != nil {
		return nil, err
	}
	item := state.item(args.Entry)
	if item == nil || (args.AgentName != "" && !args.PersonAttached && !slices.Contains(item.Agents, args.AgentName)) {
		return nil, supportRefused(SupportRefusalNotFound)
	}
	if args.Taint != nil {
		if err := args.Taint(ctx); err != nil {
			return nil, fmt.Errorf("support: the run's taint could not be written: %w", err)
		}
	}
	result := supportReadResultOf(item, args.After)
	self.changeState(func(state *supportState) error {
		if stored := state.item(args.Entry); stored != nil {
			stored.markRead(args.AgentName)
		}
		return nil
	})
	return result, nil
}

// Removes an item's bodies and attachments at the service (FB section 10.4), and its place in this device's view; the
// vault's kind-30 entries stay, for the person's erasure to take (§28.12).
func (self *SupportClient) Delete(ctx context.Context, entry string) error {
	if !supportEntryPattern.MatchString(entry) {
		return supportRefused(SupportRefusalNotFound)
	}
	host, token, err := self.hostAndToken(ctx)
	if err != nil {
		return err
	}
	if err := self.service.deleteEntry(ctx, host, token, entry); err != nil {
		return err
	}
	return self.changeState(func(state *supportState) error {
		state.Items = slices.DeleteFunc(state.Items, func(item *supportItem) bool { return item.Entry == entry })
		return nil
	})
}

// The bundle a sent message carried, kept 7 days (§28.7), for the person to read whole.
func (self *SupportClient) SentBundle(clientRef string) ([]byte, error) {
	item, err := self.outboxItem(clientRef)
	if err != nil || !item.Logs {
		return nil, supportRefused(SupportRefusalNotFound)
	}
	return self.outboxAttachment(clientRef, 0)
}

// A reader of what an io.Reader holds, within maxByteCount.
func supportReadAll(reader io.Reader, maxByteCount int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(reader, maxByteCount+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < int64(len(data)) {
		return nil, errors.New("support: a stored file past its bound")
	}
	return data, nil
}

// Whether two client_refs' texts name one message.
func supportSameClientRef(a string, b string) bool {
	return a != "" && bytes.Equal([]byte(a), []byte(b))
}
