//go:build !sidecar_http && !ios_extension

// §9.6's listener admission (R-SOCK-1, R-SOCK-4, D-SOCK-4, D-SOCK-12, D-SOCK-14, I-3, I-4, I-5): what a listener runs on
// every StreamOpen of its target before a byte of it reaches AcceptSocket (FI-11), in step order, each refusal exact:
//
//	1  the ticket verifies under a key from the registration answers                          invalid
//	2  it names this client as its listener, and this listen; a listen that ended is retry,   invalid; retry
//	   as a racing ticket after an unlisten (the tcp_migrate_req analog)
//	3  its dialer is the Required session's source, always (D-SOCK-12); a sidecar passed       invalid
//	   §6.4's Hello and dials within the network, an edge (dialer_network_id urnetwork-edge)
//	   sent none and names a tls/ or smtp/ name, and nothing else dials an edge name
//	4  unexpired by the local clock plus the service's offset, and its ticket_id unseen,      invalid
//	   kept until the ticket expires
//	5  in flight below max_streams while serving; §20 has not stopped new streams             busy; quota
//	6  this device's own evaluation of its config, at the ticket's position or later, allows  denied; retry
//	   the dial (owner decision 6): a dial grant on an application or share/ name for the
//	   dialer's sidecar; on tls/ the listener's own listen and publish, on smtp/ its listen,
//	   since an edge's visitor is autogroup:public and the edge holds no config. A device
//	   behind the ticket's position waits ListenPositionWait for its state, else retry
//
// Step 6 never trusts the ticket's grant, only its position, which the state must reach. The replay set holds each
// ticket_id until its expiry and no longer, so it is bounded by the ticket lifetime times the rate tickets arrive.
//
// A platform listener on ur/<service> (SocketPlatformListener; SOCK-M9-01) runs steps 1 to 5 and 7: its dialer is a
// sidecar that sent it no Hello and no edge, and it holds no config, since the service authorizes what comes through
// it (§14.5). §20's stop it is told is urnetwork-edge's own, which stops no dialer's stream; Find judged the dialer's.
//
// socketAdmission is the logic, every input an argument and its clock passed in, so a T1 table steps it by hand; the
// listener (socket_listen.go) holds it with the state it reads. Nothing here logs a name (I-13). Safe for concurrent
// use.

package sidecar

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One open as admission judges it.
type socketAdmissionRequest struct {
	// StreamOpen.ticket as received.
	ticketBytes []byte
	// The session's source, as connect authenticated it.
	sourceId Id
	// The source's verified Hello, nil when it sent none.
	peer *SubprotocolPeerIdentity
	// The source is a Service-mode platform client (§6.10.1).
	edge bool
}

// What a listener admits against, read once per open.
type socketAdmissionInputs struct {
	// The registrar's newest answer: ticket keys, the service's clock offset, urnetwork-edge and §20's stop.
	admission *socketAdmissionState
	// This generation's client, which a ticket must name as its listener.
	clientId Id
	// This listener's own sidecar, the subject of its own standing on an edge name.
	sidecarId Id
	// This device's evaluation of its config, nil before any.
	policy SocketPolicy
	// Streams in flight now, and whether the listener takes new ones.
	inflight int
	serving  bool
}

// What admission came to: the ticket on an accept, or the refusal's code.
type socketAdmissionVerdict struct {
	ticket *protocol.SocketTicket
	// SR_UNSPECIFIED on an accept.
	code protocol.StreamRejectCode
}

// The listener's half that every open's admission shares: what it listens on and the replay set.
type socketAdmission struct {
	settings  *SidecarSocketSettings
	clock     Clock
	networkId Id
	listenId  Id
	namespace SocketNamespace
	name      string
	// the token paths this listener registers under, newest first; nil for an edge name
	nameTokens func() [][]byte
	maxStreams int

	stateLock sync.Mutex
	// ticket_id to its expiry in the service's milliseconds
	seenTicketIds map[Id]uint64
}

// The refusal for code.
func socketAdmissionRefusal(code protocol.StreamRejectCode) *socketAdmissionVerdict {
	return &socketAdmissionVerdict{code: code}
}

// Records a ticket_id until expireMillis, unless it was already seen: false then. Expired ids are dropped first, so
// the set holds only tickets that could still be presented.
func (self *socketAdmission) recordTicket(ticketId Id, expireMillis uint64, nowMillis uint64) bool {
	testHookBarrier("socket.admission.replay.before", self.listenId.String())
	defer testHookBarrier("socket.admission.replay.after", self.listenId.String())
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for seenTicketId, seenExpireMillis := range self.seenTicketIds {
		if seenExpireMillis <= nowMillis {
			delete(self.seenTicketIds, seenTicketId)
		}
	}
	if _, seen := self.seenTicketIds[ticketId]; seen {
		return false
	}
	self.seenTicketIds[ticketId] = expireMillis
	return true
}

// How many ticket ids the replay set holds now, for a test.
func (self *socketAdmission) seenCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.seenTicketIds)
}

// Whether a ticket names this listener's name: its edge name in the clear, or one of its token paths.
func (self *socketAdmission) namesThis(ticket *protocol.SocketTicket) bool {
	if !self.namespace.blinded() {
		return ticket.GetName() == self.name && len(ticket.GetNameToken()) == 0
	}
	if ticket.GetName() != "" {
		return false
	}
	for _, nameToken := range self.nameTokens() {
		if bytes.Equal(ticket.GetNameToken(), nameToken) {
			return true
		}
	}
	return false
}

// The verdict on one open. ctx bounds step 6's wait for the state.
func (self *socketAdmission) admit(ctx context.Context, request *socketAdmissionRequest, inputs *socketAdmissionInputs) *socketAdmissionVerdict {
	admission := inputs.admission
	if admission == nil || !admission.known {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}
	nowMillis := admission.serverNowMillis(self.clock.Now())

	// 1: the service's signature
	ticket, err := VerifySocketTicket(request.ticketBytes, admission.ticketKeys, nowMillis)
	if err != nil {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}

	// 2: this client, this listen
	if !bytes.Equal(ticket.GetListenerClientId(), inputs.clientId.Bytes()) || !bytes.Equal(ticket.GetNetworkId(), self.networkId.Bytes()) ||
		!self.namesThis(ticket) {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}
	if !bytes.Equal(ticket.GetListenId(), self.listenId.Bytes()) {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_RETRY)
	}

	// 3: the dialer is the session's source; a sidecar passed Hello within the network, an edge names an edge name
	if !bytes.Equal(ticket.GetDialerClientId(), request.sourceId.Bytes()) {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}
	edgeTicket := admission.urnetworkEdge != nil && bytes.Equal(ticket.GetDialerNetworkId(), admission.urnetworkEdge.Bytes())
	edgeName := self.namespace == SocketNamespaceTls || self.namespace == SocketNamespaceSmtp
	switch {
	case self.namespace == SocketNamespacePlatform:
		if edgeTicket || request.peer != nil {
			return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
		}
	case edgeTicket:
		if !edgeName || !request.edge || request.peer != nil {
			return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
		}
	default:
		if edgeName || request.edge || request.peer == nil || !bytes.Equal(ticket.GetDialerNetworkId(), self.networkId.Bytes()) {
			return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
		}
	}

	// 4: unexpired, and seen once
	if ticket.GetExpireTimeMillis() <= nowMillis {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}
	ticketId, err := IdFromBytes(ticket.GetTicketId())
	if err != nil || !self.recordTicket(ticketId, ticket.GetExpireTimeMillis(), nowMillis) {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_INVALID)
	}

	// 5: room, and §20's stop
	if !inputs.serving || self.maxStreams <= inputs.inflight {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_BUSY)
	}
	if admission.streamsStopped && self.namespace != SocketNamespacePlatform {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_QUOTA)
	}
	if self.namespace == SocketNamespacePlatform {
		// 7 at once: a platform listener holds no config for step 6
		return &socketAdmissionVerdict{ticket: ticket}
	}

	// 6: this device's own evaluation, at the ticket's position or later
	policy := inputs.policy
	if policy == nil {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_DENIED)
	}
	if policy.Position() < ticket.GetPolicyVersion() {
		waitCtx, cancel := context.WithCancel(ctx)
		stop := self.clock.AfterFunc(self.settings.ListenPositionWait, cancel)
		reached := policy.WaitPosition(waitCtx, ticket.GetPolicyVersion())
		stop()
		cancel()
		if !reached {
			return socketAdmissionRefusal(protocol.StreamRejectCode_SR_RETRY)
		}
	}
	if !self.allows(policy, request, inputs.sidecarId, ticket) {
		return socketAdmissionRefusal(protocol.StreamRejectCode_SR_DENIED)
	}

	// 7: accept, the ticket kept as reach evidence
	return &socketAdmissionVerdict{ticket: ticket}
}

// Step 6's evaluation at now, which a stream's live check repeats as the state moves: the grant re-derived, never
// the ticket's.
func (self *socketAdmission) allows(policy SocketPolicy, request *socketAdmissionRequest, sidecarId Id, ticket *protocol.SocketTicket) bool {
	if policy == nil {
		return false
	}
	now := self.clock.Now()
	switch self.namespace {
	case SocketNamespaceTls:
		listenerSubject := AclSidecarSubject(sidecarId)
		return policy.MayListen(listenerSubject, AclSocketName{PublicName: self.name}, now).Allowed &&
			policy.MayPublish(listenerSubject, socketTlsHost(self.name), now).Allowed
	case SocketNamespaceSmtp:
		return policy.MayListen(AclSidecarSubject(sidecarId), AclSocketName{PublicName: self.name}, now).Allowed
	}
	if request.peer == nil {
		return false
	}
	return policy.AllowInbound(&AclInbound{
		Source:     AclSidecarSubject(request.peer.SidecarId),
		SocketName: self.name,
		NameToken:  ticket.GetNameToken(),
	}, now).Allowed
}

// The host a tls/<port>/<host> name publishes: its last segment, as §13.9's dns:<host> names it.
func socketTlsHost(name string) string {
	segments, err := socketSegments(name)
	if err != nil || len(segments) != 3 {
		return ""
	}
	return segments[2]
}

// A new admission for one listen.
func newSocketAdmission(settings *SidecarSocketSettings, clock Clock, networkId Id, listenId Id, namespace SocketNamespace, name string, nameTokens func() [][]byte, maxStreams int) *socketAdmission {
	return &socketAdmission{
		settings:      settings,
		clock:         clock,
		networkId:     networkId,
		listenId:      listenId,
		namespace:     namespace,
		name:          name,
		nameTokens:    nameTokens,
		maxStreams:    maxStreams,
		seenTicketIds: map[Id]uint64{},
	}
}

// The service's milliseconds a ticket's grant ends at as this device's time: the expiry less the service's offset.
func socketGrantEndTime(admission *socketAdmissionState, grantExpireMillis uint64) time.Time {
	return time.UnixMilli(int64(grantExpireMillis) - admission.serverTimeOffsetMillis)
}
