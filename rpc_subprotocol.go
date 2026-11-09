//go:build !sidecar_http

// §6's dispatcher (D-PROTO-1): one Subprotocol per client generation, registered on that client's id
// 21842 by NewSubprotocol and unregistered by Close, so constructing it is registering it, and a second
// one on the same client is connect's error. It runs only on a sidecar-owned Required client (X10,
// I-3), whose settings went through ApplySidecarClientSettings. Sidecar-to-server calls never ride it:
// they are HTTPS (D-PROTO-3).
//
// connect calls the inline handler on its receive goroutine, so the handler never blocks and never
// sends (R-PROTO-7; connect/CODESTYLE.md, receive callbacks). Its checks run in this fixed order, each
// allocation-light and free of I/O:
//
//  1. size: envelopeCodec refused a frame past §6.5's limits before connect called the handler;
//  2. the version major, else Error{VERSION};
//  3. the source guard (D-PROTO-8, rpc_guard.go);
//  4. the provide mode, Network only (rpc_guard.go);
//  5. the identity gate (rpc_peer.go), closed to a peer until its Hello verifies (D-PROTO-13);
//  6. the contract class C13 sealed, control's narrow list on a control or unset class (rpc_contract_class.go);
//  7. SubprotocolEnv.Inbound, §8's hook (rpc_inbound.go).
//
// An envelope through all seven is copied into a pool buffer and offered to its source's bounded queue
// with zero wait (rpc_peer.go). Refusing a request answers it through the reply queue (rpc_send.go);
// refusing anything else drops it. Both are counted. A worker per active source drains its queue in
// order, reassembles chunked bodies (envelope_reassembly.go) and dispatches by Envelope.type: a Ping
// gets its Pong here, a Hello its check (rpc_hello.go), a Cancel the run it names (rpc_handle.go), a
// response the request it echoes (rpc_call.go), and a request the function its type registered
// (Handle), or UNIMPLEMENTED.
//
// ControlId's frames are the platform's hints, not a peer's (§6.8). Only push types pass the guard, and
// they skip steps 4 to 7, which ask about peers and contracts. Nothing is ever sent to ControlId.
//
// Safe for concurrent use. A dispatched function must never call Close, since Close joins the workers.

package sidecar

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// A SubprotocolEnv missing something the dispatcher cannot run without.
	errSubprotocolEnv = errors.New("invalid subprotocol env")
	// A client that is not Required, which no sidecar traffic ever rides (I-3).
	errSubprotocolNotRequired = errors.New("subprotocol client is not EncryptionModeRequired")
	// A second dispatch for one type, or one for a type the dispatcher answers itself.
	errSubprotocolDispatchTaken = errors.New("subprotocol dispatch already taken")
)

// What NewSubprotocol takes: its own env, not SidecarEnv, which holds the Subprotocol, so the
// dependency runs one way (CORE-M1-08 builds this from its generation).
type SubprotocolEnv struct {
	// The generation's client: sidecar-owned and EncryptionModeRequired (X10, I-3), from settings that
	// went through ApplySidecarClientSettings. NewSubprotocol refuses any other.
	Client *connect.Client
	// The network's component store, where PROTO-M1-04 keeps first-use pins (§2.8 EX6). Required: with
	// nowhere to write a pin, no peer could ever verify.
	Store SidecarStore
	// Nil logs to connect's default logger.
	Log Logger
	// §6.6's bounds, which validate holds to their maximums and to positive values.
	Settings *SidecarProtocolSettings
	// The process's share of §5's budget, shared with every other Subprotocol the host runs (§6.6).
	Budget *SubprotocolBudget
	// Nil reads real time.
	Clock Clock
	// §8's hook, the last inline check. Required, never an implied allow: M1's core passes
	// SubprotocolInboundWithoutPolicy, and ACL its AclEngine.AllowInbound.
	Inbound SubprotocolInboundFunction
	// This sidecar's network, which a peer's binding must name (§6.4). Unset, every peer's binding
	// names another, so no Hello verifies.
	NetworkId Id
	// This client generation's marshalled SignedSidecarIdentityBinding, which its Hello and HelloResult
	// carry (§5.5). Empty, every peer refuses this side's Hello.
	Binding []byte
	// Where Hello raises key_changed. Nil drops events.
	Event SidecarEventFunction
	// The verified state Hello's admission check reads (rpc_admission.go): from M2 a peer's identity key
	// must be its SidecarAdmit's, and a sidecar not itself admitted takes no peer. Nil keeps M1's
	// first-use pins (§2.8 EX6), which only a dispatcher with no state behind it runs on.
	Admissions SubprotocolAdmissions
}

// One client generation's dispatcher. See the file header.
type Subprotocol struct {
	ctx         context.Context
	cancel      context.CancelFunc
	client      *connect.Client
	store       SidecarStore
	log         Logger
	settings    *SidecarProtocolSettings
	budget      *SubprotocolBudget
	clock       Clock
	inbound     SubprotocolInboundFunction
	reassembler *reassembler
	// what RegisterSubprotocol returned
	unregister func()
	// the C15 key a frame carries: connect.Peer.VerifiedClientPublicKey outside internal tests
	clientPublicKeyOf func(peer connect.Peer) ([ed25519.PublicKeySize]byte, bool)
	send              subprotocolSendFunction

	// the reply queue, which runSender drains
	replies    chan subprotocolReply
	senderDone chan struct{}
	// one per running source worker
	workers   sync.WaitGroup
	closeOnce sync.Once

	stateLock sync.Mutex
	closed    bool
	// sources with a queue, which is to say a worker
	sourceIdPeers      map[connect.Id]*subprotocolPeer
	sourceIdIdentities map[connect.Id]subprotocolPeerIdentity
	// request types and their functions, as setMessageTypeDispatch registered them
	messageTypeDispatches map[uint32]*subprotocolDispatch
	responseDispatch      *subprotocolDispatch
	// one Hello in flight a peer, which every EnsureHello to it joins (rpc_hello.go)
	helloFlights map[connect.Id]*helloFlight
	// requests this side waits on, Hellos and calls (rpc_call.go)
	pendingRequests map[rpcPendingKey]*rpcPending
	// handler runs, for Cancel, and how many each peer has (rpc_handle.go)
	runningCalls      map[rpcCallKey]context.CancelCauseFunc
	sourceIdRunCounts map[connect.Id]int

	// Hello's identity: this side's network, binding and event sink, and the pins (rpc_identity.go)
	networkId Id
	binding   []byte
	event     SidecarEventFunction
	pins      identityPinSource
	// what the admission check reads; nil under M1's first-use pins
	admissions SubprotocolAdmissions
	// core's live raise of the secure floor, 0 for none (QD-032)
	raisedSecureFloor atomic.Uint32
	// mutating handlers' answers (rpc_idempotency.go)
	idempotency *idempotencyCache
	// one per handler run or joined retry, which Close waits for
	handlers sync.WaitGroup
	// the PushClient serving this dispatcher's push, which Subscribe reaches (push_client.go)
	pushClient atomic.Pointer[PushClient]
	// HeadCheck's transport while one is attached (rpc_headcheck.go)
	headCheck atomic.Pointer[headCheckTransport]
	// the feature bits this side sends, which the inline handler reads with no lock (rpc_features.go)
	features atomic.Pointer[subprotocolFeatureSet]
	// connect's C19 ledger, and the first-choice indexer and foreground the keepalive follows
	// (rpc_marked_pair.go)
	peerWindows subprotocolPeerWindows
	markedPair  *MonitorValue[subprotocolMarkedPair]
	// waits the keepalive has armed, so a test steps its clock with no sleep
	keepaliveMark *MonitorValue[uint64]
	// under stateLock: the keepalive loop runs, and Close joins it with the handlers
	keepaliveStarted bool

	stats subprotocolStats
}

// One registered dispatch function. A pointer, so remove can tell its own registration from a later
// one for the same type.
type subprotocolDispatch struct {
	function subprotocolDispatchFunction
}

// Receives one complete envelope on its source's worker, so it may take time, holding up only that
// source, but must return once ctx ends, which is when the Subprotocol closes. message is borrowed for
// the call.
type subprotocolDispatchFunction func(ctx context.Context, message *subprotocolMessage)

// One complete envelope as a worker hands it on. Borrowed for the call: envelope and its body are
// valid only until the function returns, so a function that keeps either copies it.
type subprotocolMessage struct {
	// the authenticated source; ControlId for a push
	sourceId connect.Id
	// the source's peer.TransferKey, which a reply passes through replyTransferKey
	transferKey connect.TransferKey
	// C15's key on the frame that completed the message, which Hello's check compares (PROTO-M1-04)
	clientPublicKey    [ed25519.PublicKeySize]byte
	hasClientPublicKey bool
	// whole: no Chunk and no MORE
	envelope *protocol.Envelope
	// when its last envelope passed the inline handler, from which a request's timeout_ms runs
	arrivalTime time.Time
}

// Whether the message asks for an answer: a request from a peer, which ControlId never sends.
func (self *subprotocolMessage) answerable() bool {
	return self.sourceId != connect.ControlId && self.envelope.Flags&(EnvelopeFlagResponse|EnvelopeFlagNoReply) == 0
}

// What the dispatcher has counted, each a running total. Everything dropped or refused is counted under
// one reason.
type subprotocolStats struct {
	// step 2: another wire major
	versionRefusedCount atomic.Uint64
	// step 3: the source guard
	sourceDroppedCount atomic.Uint64
	// step 4: a provide mode other than Network
	provideModeDroppedCount atomic.Uint64
	// step 5: the identity gate
	identityRefusedCount atomic.Uint64
	// step 6: what a control or unset contract class does not carry
	contractClassRefusedCount atomic.Uint64
	// step 7: §8's hook
	inboundRefusedCount atomic.Uint64
	// a full source queue
	queueFullCount atomic.Uint64
	// arrived as Close ran
	closedDroppedCount atomic.Uint64
	queuedCount        atomic.Uint64
	dispatchedCount    atomic.Uint64
	// requests of a type nothing registered, answered UNIMPLEMENTED
	unimplementedCount atomic.Uint64
	// complete envelopes nothing takes and nothing answers: responses with no response dispatch, pushes
	// and NO_REPLY envelopes of a type nothing registered
	unroutedCount atomic.Uint64
	// a dispatched function or a handler that panicked
	panicCount atomic.Uint64
	// Hellos this side refused
	helloRefusedCount atomic.Uint64
	// call sends connect refused before the deadline, sent again
	callSendRetryCount atomic.Uint64
	// Cancels connect would not take at once
	cancelDroppedCount atomic.Uint64
	// handler runs a peer's Cancel reached
	cancelledCount atomic.Uint64
	// retries of mutating calls answered from memory, and those that joined a live run
	idempotentAnswerCount atomic.Uint64
	idempotentJoinCount   atomic.Uint64

	replyQueuedCount  atomic.Uint64
	replyDroppedCount atomic.Uint64
	replySentCount    atomic.Uint64
	replyFailedCount  atomic.Uint64

	// pool buffers queued items hold now, which every drop and Close bring back to 0
	heldBufferCount atomic.Int64
}

// The dispatcher's counters as they stand, each a running total since NewSubprotocol: what Sidecar.Stats
// shows for the running generation, and what a test on another module's exchange reads.
func (self *Subprotocol) Stats() SidecarSubprotocolStats {
	stats := &self.stats
	return SidecarSubprotocolStats{
		VersionRefusedCount:     stats.versionRefusedCount.Load(),
		SourceDroppedCount:      stats.sourceDroppedCount.Load(),
		ProvideModeDroppedCount: stats.provideModeDroppedCount.Load(),
		IdentityRefusedCount:    stats.identityRefusedCount.Load(),
		InboundRefusedCount:     stats.inboundRefusedCount.Load(),
		QueueFullCount:          stats.queueFullCount.Load(),
		QueuedCount:             stats.queuedCount.Load(),
		DispatchedCount:         stats.dispatchedCount.Load(),
		UnroutedCount:           stats.unroutedCount.Load(),
		PanicCount:              stats.panicCount.Load(),
		ReplyDroppedCount:       stats.replyDroppedCount.Load(),
		ReplySentCount:          stats.replySentCount.Load(),
	}
}

// The settings a sidecar's connect client runs on, set here and nowhere else (D-PROTO-6, D-PROTO-10):
// Required, never Opportunistic or Off, so a peer that cannot seal gets no application data (I-3); C15's
// verified key exposed on every Peer, which Hello's identity check compares (D-PROTO-13); and no P2P
// stream asked for, so pairs stay relay-only until P2P is tested (FS-126). CORE-M1-08's client
// generations and the edges' platform clients call it on the settings they build a client from. A nil
// EncryptionSettings gets connect's defaults first.
func ApplySidecarClientSettings(clientSettings *connect.ClientSettings) {
	if clientSettings.EncryptionSettings == nil {
		clientSettings.EncryptionSettings = connect.DefaultEncryptionSettings()
	}
	clientSettings.EncryptionSettings.Mode = connect.EncryptionModeRequired
	clientSettings.EncryptionSettings.ExposeVerifiedPeerClientKey = true
	clientSettings.DefaultTransferOpts.ForceStream = false
}

// What internal tests put in place of connect's side of the dispatcher: how a frame's C15 key is read,
// how an envelope is sent, and where pins are kept. A nil field takes the real one.
type subprotocolSeams struct {
	clientPublicKeyOf func(peer connect.Peer) ([ed25519.PublicKeySize]byte, bool)
	send              subprotocolSendFunction
	pins              identityPinSource
	peerWindows       subprotocolPeerWindows
}

// A running dispatcher, registered on env.Client's id 21842 with C3's opt-in for ControlId's frames
// (WithSubprotocolControlSource), until Close or ctx ends its goroutines. Refuses an env missing a
// required field, settings past their bounds, and a client that is not Required. A client that already
// has id 21842 gets connect's registration error, and nothing is left running.
func NewSubprotocol(ctx context.Context, env *SubprotocolEnv) (*Subprotocol, error) {
	return newSubprotocol(ctx, env, &subprotocolSeams{})
}

// NewSubprotocol, with seams.
func newSubprotocol(ctx context.Context, env *SubprotocolEnv, seams *subprotocolSeams) (*Subprotocol, error) {
	if env == nil || env.Client == nil || env.Store == nil || env.Settings == nil || env.Budget == nil {
		return nil, fmt.Errorf("%w: Client, Store, Settings and Budget are required", errSubprotocolEnv)
	}
	if env.Inbound == nil {
		return nil, fmt.Errorf("%w: no Inbound function, which is never read as allow", errSubprotocolEnv)
	}
	if err := checkSettingsNumbers("ProtocolSettings", reflect.ValueOf(env.Settings), false); err != nil {
		return nil, err
	}
	if err := env.Settings.validate(); err != nil {
		return nil, err
	}
	if !env.Client.EncryptionSessionManager().RequireEncryption() {
		return nil, errSubprotocolNotRequired
	}

	log := loggerOrDefault(env.Log)
	clock := clockOrReal(env.Clock)
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &Subprotocol{
		ctx:                   cancelCtx,
		cancel:                cancel,
		client:                env.Client,
		store:                 env.Store,
		log:                   log,
		settings:              env.Settings,
		budget:                env.Budget,
		clock:                 clock,
		inbound:               env.Inbound,
		reassembler:           newReassembler(cancelCtx, env.Settings, env.Budget, clock, log),
		clientPublicKeyOf:     seams.clientPublicKeyOf,
		send:                  seams.send,
		replies:               make(chan subprotocolReply, env.Settings.PeerQueueMessageCount),
		senderDone:            make(chan struct{}),
		sourceIdPeers:         map[connect.Id]*subprotocolPeer{},
		sourceIdIdentities:    map[connect.Id]subprotocolPeerIdentity{},
		messageTypeDispatches: map[uint32]*subprotocolDispatch{},
		helloFlights:          map[connect.Id]*helloFlight{},
		pendingRequests:       map[rpcPendingKey]*rpcPending{},
		runningCalls:          map[rpcCallKey]context.CancelCauseFunc{},
		sourceIdRunCounts:     map[connect.Id]int{},
		networkId:             env.NetworkId,
		binding:               bytes.Clone(env.Binding),
		event:                 env.Event,
		pins:                  seams.pins,
		admissions:            env.Admissions,
		idempotency:           newIdempotencyCache(env.Settings, env.Budget, clock),
		peerWindows:           seams.peerWindows,
		markedPair:            NewMonitorValue(subprotocolMarkedPair{}),
		keepaliveMark:         NewMonitorValue[uint64](0),
	}
	if self.peerWindows == nil {
		self.peerWindows = env.Client.ContractManager()
	}
	if self.clientPublicKeyOf == nil {
		self.clientPublicKeyOf = connect.Peer.VerifiedClientPublicKey
	}
	if self.send == nil {
		self.send = self.connectSend
	}
	if self.pins == nil {
		if env.Admissions != nil {
			self.pins = newAdmissionIdentityPins(cancelCtx, env.Admissions, env.Store, env.Settings, clock, self.raiseEvent)
		} else {
			self.pins = newFirstUseIdentityPins(env.Store)
		}
	}
	// the dispatcher's own: Hello's check, Cancel and every response
	for _, register := range []func() error{
		func() error {
			_, err := self.setMessageTypeDispatch(protocol.MessageType_HELLO, self.dispatchHello)
			return err
		},
		func() error {
			_, err := self.setMessageTypeDispatch(protocol.MessageType_CANCEL, self.dispatchCancel)
			return err
		},
		func() error {
			_, err := self.setResponseDispatch(self.dispatchResponse)
			return err
		},
	} {
		if err := register(); err != nil {
			cancel()
			self.reassembler.close()
			return nil, err
		}
	}
	go self.runSender()

	// last, so connect calls the handler only on a dispatcher that is whole
	unregister, err := connect.RegisterSubprotocol(
		env.Client,
		SubprotocolId,
		envelopeCodec{},
		self.receive,
		connect.WithSubprotocolControlSource(),
	)
	if err != nil {
		self.stop()
		return nil, err
	}
	self.unregister = unregister
	return self, nil
}

// Unregisters from the client, ends the sender and every worker, and waits for them: each worker gives
// back its queued pool buffers without running them, and a dispatched function sees its ctx end and
// must return. Safe to call more than once; every call returns once the first has finished. Never call
// it from a dispatched function, which it would wait for.
func (self *Subprotocol) Close() {
	self.closeOnce.Do(func() {
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.closed = true
		}()
		self.unregister()
		self.stop()
	})
}

// Cancels, then joins the workers, the handler runs, the sender and the reassembler, and gives back
// what the idempotency cache held. closed is set first, or nothing was ever registered, so no worker
// starts after the join begins.
func (self *Subprotocol) stop() {
	self.cancel()
	self.workers.Wait()
	self.handlers.Wait()
	<-self.senderDone
	self.reassembler.close()
	self.idempotency.close()
}

// The inline handler connect calls with each envelope from id 21842. Runs the file header's seven
// checks in order and queues what passes them. Never blocks, never sends, and keeps nothing of
// envelope past its return.
func (self *Subprotocol) receive(source connect.TransferPath, envelope *protocol.Envelope, peer connect.Peer) {
	sourceId := source.SourceId
	answerable := sourceId != connect.ControlId && envelope.Flags&(EnvelopeFlagResponse|EnvelopeFlagNoReply) == 0
	refuse := func(code protocol.ErrorCode) {
		if answerable {
			self.offerReply(refusalReply(sourceId, peer.TransferKey, envelope.RequestId, envelope.StreamId, code))
		}
	}

	// (1) size: envelopeCodec refused anything past §6.5's limits before this ran
	// (2) the version major (§6.4), refused with this side's range (plan-PROTO-version-error-range.md)
	if envelope.Version != WireVersionMajor {
		self.stats.versionRefusedCount.Add(1)
		refuse(protocol.ErrorCode_ERR_VERSION)
		return
	}
	// (3) the source guard (D-PROTO-8)
	if !sourceAdmits(source, envelope.Type, peer.TransportType) {
		self.stats.sourceDroppedCount.Add(1)
		if self.log.V(1).Enabled() {
			self.log.Infof("[subprotocol]type %d from %s carrier=%s dropped by the source guard\n", envelope.Type, sourceId, peer.TransportType)
		}
		return
	}
	var clientPublicKey [ed25519.PublicKeySize]byte
	hasClientPublicKey := false
	if sourceId != connect.ControlId {
		// (4) the provide mode
		if !provideModeAdmits(peer.ProvideMode) {
			self.stats.provideModeDroppedCount.Add(1)
			return
		}
		// (5) the identity gate (D-PROTO-13)
		clientPublicKey, hasClientPublicKey = self.clientPublicKeyOf(peer)
		if !self.identityAdmits(sourceId, envelope.Type, envelope.Flags, clientPublicKey, hasClientPublicKey) {
			self.stats.identityRefusedCount.Add(1)
			refuse(protocol.ErrorCode_ERR_UNAUTHENTICATED)
			return
		}
		// (6) the contract class C13 sealed, read from this frame's Peer (rpc_contract_class.go): on
		// control, or unset, only §6.4's list and SEARCH at a sidecar serving it; other requests
		// refused PERMISSION_DENIED, a StreamOpen StreamReject{DENIED}, anything else dropped
		switch contractClassAdmits(peer.ContractClass, envelope.Type, envelope.Flags, self.servesSearch()) {
		case contractClassRefuse:
			self.stats.contractClassRefusedCount.Add(1)
			refuse(protocol.ErrorCode_ERR_PERMISSION_DENIED)
			return
		case contractClassRejectStream:
			self.stats.contractClassRefusedCount.Add(1)
			self.offerReply(streamRejectReply(sourceId, peer.TransferKey, envelope.StreamId, protocol.StreamRejectCode_SR_DENIED))
			return
		case contractClassDrop:
			self.stats.contractClassRefusedCount.Add(1)
			return
		}
		// (7) §8's hook
		inbound := SubprotocolInbound{
			SourceId:    Id(sourceId),
			MessageType: protocol.MessageType(envelope.Type),
			StreamId:    envelope.StreamId,
			Response:    envelope.Flags&EnvelopeFlagResponse != 0,
		}
		if !self.inbound(inbound) {
			self.stats.inboundRefusedCount.Add(1)
			refuse(protocol.ErrorCode_ERR_PERMISSION_DENIED)
			return
		}
	}

	switch self.enqueue(sourceId, peer.TransferKey, clientPublicKey, hasClientPublicKey, envelope) {
	case subprotocolQueueFull:
		self.stats.queueFullCount.Add(1)
		refuse(protocol.ErrorCode_ERR_RESOURCE_EXHAUSTED)
	case subprotocolEnqueueClosed:
		self.stats.closedDroppedCount.Add(1)
	}
}

// Runs one queued envelope on its source's worker: reassembly first, then dispatch of what completes.
// The item's pool buffer goes back when this returns, after dispatch, since an unchunked envelope is
// dispatched borrowing it.
func (self *Subprotocol) process(item *subprotocolInbound, barrierKey string) {
	defer item.release(&self.stats)
	whole, err := self.reassembler.offer(Id(item.sourceId), item.envelope())
	if err != nil {
		// a body over a cap answers RESOURCE_EXHAUSTED at its first chunk; anything else that broke a
		// group is dropped, and the reassembler counted it
		if code, ok := envelopeErrorCode(err); ok && item.answerable() {
			self.offerReply(refusalReply(item.sourceId, item.transferKey, item.requestId, item.streamId, code))
		}
		return
	}
	if whole == nil {
		return
	}
	message := &subprotocolMessage{
		sourceId:           item.sourceId,
		transferKey:        item.transferKey,
		clientPublicKey:    item.clientPublicKey,
		hasClientPublicKey: item.hasClientPublicKey,
		envelope:           whole,
		arrivalTime:        item.arrivalTime,
	}
	// a peer whose admission the state has since revoked or parked loses its gate here, off the inline
	// path, before anything of it is dispatched (rpc_admission.go)
	if item.sourceId != connect.ControlId && !helloExchange(whole.Type, whole.Flags) && !self.peerAdmissionStands(item.sourceId) {
		self.stats.identityRefusedCount.Add(1)
		if message.answerable() {
			self.offerReply(refusalReply(item.sourceId, item.transferKey, whole.RequestId, whole.StreamId, protocol.ErrorCode_ERR_UNAUTHENTICATED))
		}
		return
	}
	testHookBarrier("rpc.dispatch.before", barrierKey)
	self.dispatch(message)
	testHookBarrier("rpc.dispatch.after", barrierKey)
}

// Routes one complete envelope: a response to the response dispatch, a Ping to its Pong, a request to
// its type's function, or UNIMPLEMENTED (§6.4). ControlId's hints answer nothing this side asked, so
// they go by type whatever their flags. What nothing takes and nothing may answer is counted.
func (self *Subprotocol) dispatch(message *subprotocolMessage) {
	envelope := message.envelope
	if message.sourceId != connect.ControlId && envelope.Flags&EnvelopeFlagResponse != 0 {
		var dispatch *subprotocolDispatch
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			dispatch = self.responseDispatch
		}()
		if dispatch == nil {
			self.stats.unroutedCount.Add(1)
			return
		}
		self.callDispatch(dispatch, message)
		return
	}
	if protocol.MessageType(envelope.Type) == protocol.MessageType_PING {
		// Ping carries no body, and Pong echoes its request_id with none (§6.5)
		if !message.answerable() {
			self.stats.unroutedCount.Add(1)
			return
		}
		if 0 < len(envelope.Body) {
			self.offerReply(refusalReply(message.sourceId, message.transferKey, envelope.RequestId, envelope.StreamId, protocol.ErrorCode_ERR_INVALID_ARGUMENT))
			return
		}
		self.offerReply(subprotocolReply{
			destinationId: message.sourceId,
			transferKey:   message.transferKey,
			messageType:   protocol.MessageType_PONG,
			requestId:     envelope.RequestId,
			streamId:      envelope.StreamId,
		})
		// a marked pair's keepalive: its window's activity, and at the indexer its session (rpc_marked_pair.go)
		self.noteWindowActivity(message.sourceId)
		self.touchSession(message.sourceId)
		return
	}
	var dispatch *subprotocolDispatch
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		dispatch = self.messageTypeDispatches[envelope.Type]
	}()
	if dispatch == nil {
		if message.answerable() {
			self.stats.unimplementedCount.Add(1)
			self.offerReply(refusalReply(message.sourceId, message.transferKey, envelope.RequestId, envelope.StreamId, protocol.ErrorCode_ERR_UNIMPLEMENTED))
		} else {
			self.stats.unroutedCount.Add(1)
		}
		return
	}
	self.callDispatch(dispatch, message)
}

// Calls a dispatch function, keeping its panic to this message: the worker logs it and goes on to the
// next, as connect isolates a handler's panic from its receive goroutine.
func (self *Subprotocol) callDispatch(dispatch *subprotocolDispatch, message *subprotocolMessage) {
	defer func() {
		if r := recover(); r != nil {
			self.stats.panicCount.Add(1)
			self.log.Errorf("[subprotocol]dispatch of type %d from %s panic = %v\n", message.envelope.Type, message.sourceId, r)
		}
	}()
	self.stats.dispatchedCount.Add(1)
	dispatch.function(self.ctx, message)
}

// Sends every complete request of messageType, from any source, to function, on that source's
// worker; remove takes it away again. One function per type, and none for Ping, which is answered
// here. PROTO-M1-05's Handle, PROTO-M1-04's Hello and PROTO-M1-06's push client build on this.
func (self *Subprotocol) setMessageTypeDispatch(messageType protocol.MessageType, function subprotocolDispatchFunction) (remove func(), err error) {
	if function == nil || messageType == protocol.MessageType_PING {
		return nil, errSubprotocolDispatchTaken
	}
	key := uint32(messageType)
	dispatch := &subprotocolDispatch{function: function}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.messageTypeDispatches[key] != nil {
		return nil, errSubprotocolDispatchTaken
	}
	self.messageTypeDispatches[key] = dispatch
	remove = func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.messageTypeDispatches[key] == dispatch {
			delete(self.messageTypeDispatches, key)
		}
	}
	return remove, nil
}

// Sends every complete response, from any source, to function: PROTO-M1-05 matches each to its call by
// request_id. One function; remove takes it away again.
func (self *Subprotocol) setResponseDispatch(function subprotocolDispatchFunction) (remove func(), err error) {
	if function == nil {
		return nil, errSubprotocolDispatchTaken
	}
	dispatch := &subprotocolDispatch{function: function}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.responseDispatch != nil {
		return nil, errSubprotocolDispatchTaken
	}
	self.responseDispatch = dispatch
	remove = func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.responseDispatch == dispatch {
			self.responseDispatch = nil
		}
	}
	return remove, nil
}
