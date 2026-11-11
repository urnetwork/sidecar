//go:build !sidecar_http && !ios_extension

// §9.6's dialer (R-SOCK-2, R-SOCK-4, R-SOCK-5, D-SOCK-1, D-SOCK-6, D-SOCK-8, D-SOCK-14): Sidecar.Dial resolves an
// address, Finds, checks each ticket's listener itself, and opens a §6 stream to it, retrying as §9.6 orders.
//
// Resolution (D-SOCK-1, D-DNS-2). An address with no <net> is this sidecar's network. A <net> resolves through §12's
// label table and never as a legacy name, since a Dial is no interactive input, and must be this sidecar's own
// network: other networks are reached by IP (§6.4). The namespace decides the rest. An application name goes to the
// service only as its token path under the newest K_sock (D-SOCK-13). tls/ and smtp/ are an edge's to dial (§9.4's
// table, SOCK-M5-13), share/ is `ur share get`'s alone (SOCK-M5-15), and a reserved name has no owner, so each is
// refused here. A ur/ name resolves to urnetwork-edge and stops there: its dial, with no Hello and no claim, is
// SOCK-M9-01's (plan reading 7), and until it lands such a Dial answers unavailable.
//
// Before OPEN (owner decision 3, I-5). A ticket names its listener's client; the dialer runs §6.4's Hello with it and
// checks the ticket's claim, a §6 Signed of purpose socket-registration, under the identity key that Hello verified,
// so a claim the listener's sidecar did not sign is never opened, and that the claim names the dialed network and
// name, the ticket's listen and, when the Dial asks one, the protocol. The listener's sidecar must then hold a listen
// grant on the name in this device's own evaluation of its config. `ur share get` dials a share/ name holding the
// link's sidecar_id (dialShare), and a listener whose verified Hello names another sidecar is refused here (§9.9). The ticket's own signature is the listener's to
// check (admission step 1); the dialer reads its fields only to know whom to open to, and a forged one fails the claim
// check against the client it names. Any failure here is the ticket's, reported as refused.
//
// Each attempt waits AcceptTimeout (5 s). retry, busy and timeouts try the next ticket; denied stops at once; quota
// waits retry_after_ms, at most DialQuotaMaxWait, then tries the next; invalid refetches once; a code of 0 or past
// §6.7's five reads as invalid. When every ticket has failed, the next Find carries them, at most DialFindCount Finds in
// all, with a jittered backoff after a busy one. A Find's own refusal other than busy ends the Dial with it. The error
// that ends a Dial is §9.9's, in §9.6's step order: a Find's refusal as it came, else quota, then busy, then no listener.
//
// socketDialer is the logic, on two seams a test scripts: socketStreamOpener, §6's dispatcher, and socketFindClient's
// send. Nothing here logs a name (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §9.9's dial settings. A zero AcceptTimeout takes SidecarSocketSettings.DialAcceptTimeout, 5 s.
type SocketDialSettings struct {
	// §9.7's filter: "" and 0 ask nothing, and no ALPN ids match every listener. The service applies them once sock-2
	// names them (plan-SOCK-metadata-rows); meanwhile a claim of another protocol fails the dialer's own check.
	Protocol   string
	MinVersion int
	Alpn       []string
	// §9.7's affinity key: tlsedge's keyed hash of a visitor's /24 or /48. A sidecar has none to send.
	AffinityKey []byte
	// How long each ticket's open waits for its listener's accept, Hello included.
	AcceptTimeout time.Duration
}

// What a dialer opens streams through: §6's dispatcher (subprotocolSocketOpener), or a test's pipe.
type socketStreamOpener interface {
	// Runs §6.4's Hello with clientId if none stands, and answers the identity it verified.
	verify(ctx context.Context, clientId Id) (*SubprotocolPeerIdentity, error)
	// StreamOpen to clientId: its stream once accepted, a *StreamRejectError once rejected, or the open's failure.
	open(ctx context.Context, clientId Id, request *StreamOpenRequest) (socketStream, error)
}

// socketStreamOpener over one generation's dispatcher.
type subprotocolSocketOpener struct {
	subprotocol *Subprotocol
}

// See socketStreamOpener.
func (self *subprotocolSocketOpener) verify(ctx context.Context, clientId Id) (*SubprotocolPeerIdentity, error) {
	if err := self.subprotocol.ensurePeerVerified(ctx, connect.Id(clientId)); err != nil {
		return nil, err
	}
	identity, _, ok := self.subprotocol.peerVerifiedIdentity(connect.Id(clientId))
	if !ok {
		return nil, &SubprotocolError{Code: protocol.ErrorCode_ERR_UNAUTHENTICATED}
	}
	return identity, nil
}

// See socketStreamOpener.
func (self *subprotocolSocketOpener) open(ctx context.Context, clientId Id, request *StreamOpenRequest) (socketStream, error) {
	stream, err := self.subprotocol.OpenStream(ctx, clientId, request)
	if err != nil {
		return nil, err
	}
	return newSubprotocolSocketStream(stream), nil
}

// What one Dial dials: the network, the name in its forms, and the stream target both ends name.
type socketDialTarget struct {
	networkId Id
	namespace SocketNamespace
	name      string
	// the token path of a blinded name; nil for an edge name
	nameToken []byte
	// <label>:<name>, StreamOpen.target (plan reading 12)
	streamTarget string
}

// Everything one Dial reads, fixed when it starts.
type socketDialer struct {
	settings *SidecarSocketSettings
	clock    Clock
	random   func() float64
	// this sidecar's network and the Required session's source every ticket must name (D-SOCK-12)
	networkId Id
	clientId  Id
	labels    *SocketNetworkLabels
	ring      *SocketKeyRing
	// the urnetwork-edge network, as the registrar's newest answer named it; nil before any
	urnetworkEdge *Id
	find          *socketFindClient
	opener        socketStreamOpener
	policy        SocketPolicy
	// ur share get's: the sidecar whose listener alone this Dial opens to, nil for any (§9.9)
	listenerSidecarId *Id
}

// How one ticket ended.
type socketAttemptKind int

const (
	socketAttemptAccepted socketAttemptKind = iota + 1
	// the ticket failed before any answer, or the listener answered retry: the next ticket
	socketAttemptRefused
	// no answer within AcceptTimeout: the next ticket
	socketAttemptTimeout
	socketAttemptBusy
	socketAttemptDenied
	socketAttemptQuota
	socketAttemptInvalid
)

// One ticket's attempt.
type socketAttempt struct {
	kind       socketAttemptKind
	conn       *SocketConn
	retryAfter time.Duration
}

// The Dial's target for address: see the file header's resolution. allowShare lets share/ through, for `ur share get`.
func (self *socketDialer) resolve(address *SocketAddress, allowShare bool) (*socketDialTarget, error) {
	name, namespace, err := ParseSocketName(address.Name)
	if err != nil {
		return nil, err
	}
	switch namespace {
	case SocketNamespaceApplication:
	case SocketNamespaceShare:
		if !allowShare {
			return nil, &SocketCodeError{Err: ErrSocketDenied}
		}
	case SocketNamespacePlatform:
		// ur/ names are urnetwork-edge's, and carry no <net> of their own
		if address.NetworkLabel != "" {
			return nil, errInvalidSocketAddress
		}
		// their dial is SOCK-M9-01's: no Hello, no claim, the service's signature checked here
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	default:
		// tls/ and smtp/ are an edge's, and a reserved name has no owner
		return nil, &SocketCodeError{Err: ErrSocketDenied}
	}
	if self.labels == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if address.NetworkLabel != "" && address.NetworkLabel != self.labels.Label {
		if self.labels.Resolver == nil {
			return nil, &SocketCodeError{Err: ErrSocketUnavailable}
		}
		networkId, _, err := self.labels.Resolver.ResolveNetworkLabel(self.labels.Root, address.NetworkLabel, false)
		if err != nil {
			return nil, &SocketCodeError{Err: ErrSocketNoListener}
		}
		// another network is reached by IP, never by a socket dial (§6.4)
		if networkId != self.networkId {
			return nil, &SocketCodeError{Err: ErrSocketDenied}
		}
	}
	if self.ring == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	nameToken, err := self.ring.Current().TokenPath(name)
	if err != nil {
		return nil, err
	}
	return &socketDialTarget{
		networkId:    self.networkId,
		namespace:    namespace,
		name:         name,
		nameToken:    nameToken,
		streamTarget: self.labels.Label + ":" + name,
	}, nil
}

// The ticket in a Find's answer, its fields as the service wrote them, unverified (see the file header).
func parseSocketFindTicket(ticketBytes []byte) (*protocol.SocketTicket, error) {
	if signedSocketTicketMaxByteCount < len(ticketBytes) {
		return nil, ErrSocketTicketMalformed
	}
	signedTicket := &protocol.SignedSocketTicket{}
	if err := proto.Unmarshal(ticketBytes, signedTicket); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketTicketMalformed, err)
	}
	ticket := &protocol.SocketTicket{}
	if err := proto.Unmarshal(signedTicket.GetTicket(), ticket); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSocketTicketMalformed, err)
	}
	if err := checkSocketTicket(ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

// Whether claimBytes is the listener's own claim, under identity's key, over what this dial dialed and the ticket's
// listen (§9.6's dialer check): protocol is the one the Dial asks, "" for any.
func checkSocketClaim(claimBytes []byte, identity *SubprotocolPeerIdentity, target *socketDialTarget, ticket *protocol.SocketTicket, protocolName string) error {
	errClaim := errors.New("socket claim refused")
	if identity == nil || len(identity.IdentityPublicKey) == 0 {
		return errClaim
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(claimBytes, signed); err != nil {
		return errClaim
	}
	err := bridge.VerifySigned(signed, SocketRegistrationPurpose, bridge.SignedType_SIGNED_SOCKET_REGISTRATION, bridge.SignedKeyAlgEd25519, identity.IdentityPublicKey)
	if err != nil {
		return errClaim
	}
	claim := &protocol.SocketRegistrationClaim{}
	if err := proto.Unmarshal(signed.GetBody(), claim); err != nil {
		return errClaim
	}
	switch {
	case !bytes.Equal(claim.GetNetworkId(), target.networkId.Bytes()),
		!bytes.Equal(claim.GetListenId(), ticket.GetListenId()),
		protocolName != "" && claim.GetProtocol() != protocolName:
		return errClaim
	case target.nameToken != nil:
		if claim.GetName() != "" || !bytes.Equal(claim.GetNameToken(), target.nameToken) {
			return errClaim
		}
	default:
		if len(claim.GetNameToken()) != 0 || claim.GetName() != target.name {
			return errClaim
		}
	}
	return nil
}

// A context that ends when ctx does or timeout passes on this dialer's clock, and the call that ends it.
func (self *socketDialer) attemptContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	attemptCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return attemptCtx, func() {
		stop()
		cancel()
	}
}

// Waits wait on this dialer's clock, or until ctx ends: false then.
func (self *socketDialer) wait(ctx context.Context, wait time.Duration) bool {
	if wait <= 0 {
		return ctx.Err() == nil
	}
	select {
	case <-ctx.Done():
		return false
	case <-self.clock.After(wait):
		return true
	}
}

// One ticket: the checks before OPEN, then the open, within acceptTimeout.
func (self *socketDialer) attempt(ctx context.Context, target *socketDialTarget, findTicket *SocketFindTicket, settings *SocketDialSettings, acceptTimeout time.Duration) *socketAttempt {
	ticket, err := parseSocketFindTicket(findTicket.Ticket)
	if err != nil {
		return &socketAttempt{kind: socketAttemptRefused}
	}
	// the ticket must be for what was dialed, and name this client as its dialer (D-SOCK-12)
	if !bytes.Equal(ticket.GetNetworkId(), target.networkId.Bytes()) || !bytes.Equal(ticket.GetDialerClientId(), self.clientId.Bytes()) ||
		!bytes.Equal(ticket.GetNameToken(), target.nameToken) || ticket.GetName() != "" {
		return &socketAttempt{kind: socketAttemptRefused}
	}
	listenerClientId, err := IdFromBytes(ticket.GetListenerClientId())
	if err != nil {
		return &socketAttempt{kind: socketAttemptRefused}
	}

	attemptCtx, done := self.attemptContext(ctx, acceptTimeout)
	defer done()
	timedOut := func() bool {
		return attemptCtx.Err() != nil && ctx.Err() == nil
	}

	identity, err := self.opener.verify(attemptCtx, listenerClientId)
	if err != nil {
		if timedOut() {
			return &socketAttempt{kind: socketAttemptTimeout}
		}
		return &socketAttempt{kind: socketAttemptRefused}
	}
	// a share's getter opens only to the sharer the link names, whose Hello verified (§9.9)
	if self.listenerSidecarId != nil && identity.SidecarId != *self.listenerSidecarId {
		return &socketAttempt{kind: socketAttemptRefused}
	}
	if err := checkSocketClaim(findTicket.Claim, identity, target, ticket, settings.Protocol); err != nil {
		return &socketAttempt{kind: socketAttemptRefused}
	}
	// the listener's listen grant, in this device's own config (owner decision 3)
	if self.policy == nil {
		return &socketAttempt{kind: socketAttemptRefused}
	}
	listenDecision := self.policy.MayListen(AclSidecarSubject(identity.SidecarId), AclSocketName{NameToken: target.nameToken}, self.clock.Now())
	if !listenDecision.Allowed {
		return &socketAttempt{kind: socketAttemptRefused}
	}

	stream, err := self.opener.open(attemptCtx, listenerClientId, &StreamOpenRequest{
		Target: target.streamTarget,
		Ticket: findTicket.Ticket,
	})
	if err == nil {
		localAddr := &SocketAddr{NetworkId: connect.Id(self.networkId), ClientId: connect.Id(self.clientId)}
		remoteAddr := &SocketAddr{NetworkId: connect.Id(target.networkId), ClientId: connect.Id(listenerClientId)}
		return &socketAttempt{kind: socketAttemptAccepted, conn: newSocketConn(stream, localAddr, remoteAddr, ticket, nil)}
	}
	var rejectErr *StreamRejectError
	if errors.As(err, &rejectErr) {
		switch SocketRejectCode(uint32(rejectErr.Code)) {
		case protocol.StreamRejectCode_SR_RETRY:
			return &socketAttempt{kind: socketAttemptRefused}
		case protocol.StreamRejectCode_SR_BUSY:
			return &socketAttempt{kind: socketAttemptBusy, retryAfter: rejectErr.RetryAfter}
		case protocol.StreamRejectCode_SR_DENIED:
			return &socketAttempt{kind: socketAttemptDenied}
		case protocol.StreamRejectCode_SR_QUOTA:
			return &socketAttempt{kind: socketAttemptQuota, retryAfter: rejectErr.RetryAfter}
		}
		return &socketAttempt{kind: socketAttemptInvalid}
	}
	if timedOut() {
		return &socketAttempt{kind: socketAttemptTimeout}
	}
	// the open failed below the listener: its dispatcher's error, which the next ticket may not share
	return &socketAttempt{kind: socketAttemptRefused}
}

// The busy backoff before Find number findIndex, the first being 0, after busyCount busy Finds: DialBusyBackoff
// doubling, at most DialBusyBackoffMax, drawn within ±Jitter, and never below the service's own wait.
func (self *socketDialer) busyBackoff(busyCount int, retryAfter time.Duration) time.Duration {
	backoff := self.settings.DialBusyBackoff
	for range busyCount - 1 {
		backoff *= 2
		if self.settings.DialBusyBackoffMax <= backoff {
			backoff = self.settings.DialBusyBackoffMax
			break
		}
	}
	jittered := time.Duration(float64(backoff) * (1 + self.settings.Jitter*(2*self.random()-1)))
	return max(jittered, retryAfter)
}

// One Dial: Finds and tickets, as the file header orders them.
func (self *socketDialer) dial(ctx context.Context, address *SocketAddress, settings *SocketDialSettings, allowShare bool) (*SocketConn, error) {
	if settings == nil {
		settings = &SocketDialSettings{}
	}
	acceptTimeout := settings.AcceptTimeout
	if acceptTimeout <= 0 {
		acceptTimeout = self.settings.DialAcceptTimeout
	}
	target, err := self.resolve(address, allowShare)
	if err != nil {
		return nil, err
	}
	args := &SocketFindArgs{
		NameToken:   target.nameToken,
		NetworkId:   (*connect.Id)(&target.networkId),
		Protocol:    settings.Protocol,
		MinVersion:  settings.MinVersion,
		Alpn:        settings.Alpn,
		AffinityKey: settings.AffinityKey,
	}

	failedTickets := []*SocketFailedTicket{}
	refetched := false
	busyCount := 0
	busyRetryAfter := time.Duration(0)
	// the strongest listener answer so far, in §9.6's step order: quota, then busy, then nothing better
	var listenerErr *SocketCodeError
	rank := func(codeErr *SocketCodeError) int {
		switch {
		case errors.Is(codeErr.Err, ErrSocketQuota):
			return 3
		case errors.Is(codeErr.Err, ErrSocketBusy):
			return 2
		}
		return 1
	}
	note := func(codeErr *SocketCodeError) {
		if listenerErr == nil || rank(listenerErr) < rank(codeErr) {
			listenerErr = codeErr
		}
	}
	for findIndex := 0; findIndex < self.settings.DialFindCount; findIndex += 1 {
		if 0 < busyCount && 0 < findIndex {
			if !self.wait(ctx, self.busyBackoff(busyCount, busyRetryAfter)) {
				return nil, &SocketCodeError{Err: ErrSocketUnavailable}
			}
		}
		args.FailedTickets = failedTickets
		answer, err := self.find.find(ctx, args)
		if err != nil {
			var codeErr *SocketCodeError
			if errors.As(err, &codeErr) && errors.Is(codeErr.Err, ErrSocketBusy) {
				busyCount += 1
				busyRetryAfter = codeErr.RetryAfter
				note(codeErr)
				continue
			}
			return nil, err
		}
		busyRetryAfter = 0
		busyThisFind := false
		refetch := false
		failedTickets = []*SocketFailedTicket{}
		for _, findTicket := range answer.tickets {
			attempt := self.attempt(ctx, target, findTicket, settings, acceptTimeout)
			if ctx.Err() != nil {
				return nil, &SocketCodeError{Err: ErrSocketUnavailable}
			}
			reason := SocketFailedReasonRefused
			switch attempt.kind {
			case socketAttemptAccepted:
				return attempt.conn, nil
			case socketAttemptDenied:
				return nil, &SocketCodeError{Err: ErrSocketDenied}
			case socketAttemptTimeout:
				reason = SocketFailedReasonTimeout
				note(&SocketCodeError{Err: ErrSocketNoListener})
			case socketAttemptBusy:
				busyThisFind = true
				busyRetryAfter = max(busyRetryAfter, attempt.retryAfter)
				note(&SocketCodeError{Err: ErrSocketBusy, RetryAfter: attempt.retryAfter})
			case socketAttemptQuota:
				note(&SocketCodeError{Err: ErrSocketQuota, RetryAfter: attempt.retryAfter})
				if !self.wait(ctx, min(attempt.retryAfter, self.settings.DialQuotaMaxWait)) {
					return nil, &SocketCodeError{Err: ErrSocketUnavailable}
				}
			case socketAttemptInvalid:
				note(&SocketCodeError{Err: ErrSocketNoListener})
				if !refetched {
					refetched = true
					refetch = true
				}
			default:
				note(&SocketCodeError{Err: ErrSocketNoListener})
			}
			failedTickets = append(failedTickets, &SocketFailedTicket{Ticket: findTicket.Ticket, Reason: reason})
			if refetch {
				// invalid refetches once, at once, carrying what failed
				break
			}
		}
		if busyThisFind {
			busyCount += 1
		} else if !refetch {
			busyCount = 0
		}
	}
	if listenerErr == nil {
		listenerErr = &SocketCodeError{Err: ErrSocketNoListener}
	}
	return nil, listenerErr
}

// A uniform draw in [0, 1), for jitter.
func socketDialRandom() float64 {
	return rand.Float64()
}

// The dialer for one Dial on this component, from the generation attached now.
func (self *SocketComponent) dialer() (*socketDialer, error) {
	generation, policy, labels := self.current()
	if generation == nil || generation.subprotocol == nil || generation.sidecarApi == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	admission := self.registrar.admission()
	ring := func() *SocketKeyRing {
		self.registrar.stateLock.Lock()
		defer self.registrar.stateLock.Unlock()
		return self.registrar.state.ring
	}()
	return &socketDialer{
		settings:      self.settings,
		clock:         self.clock,
		random:        socketDialRandom,
		networkId:     self.networkId,
		clientId:      generation.identity.ClientId,
		labels:        labels,
		ring:          ring,
		urnetworkEdge: admission.urnetworkEdge,
		find:          newSocketFindClient(generation.sidecarApi.SocketFind),
		opener:        &subprotocolSocketOpener{subprotocol: generation.subprotocol},
		policy:        policy,
	}, nil
}

// A Dial on this component; allowShare lets share/ through for `ur share get` (SOCK-M5-15).
func (self *SocketComponent) dial(ctx context.Context, address *SocketAddress, settings *SocketDialSettings, allowShare bool) (*SocketConn, error) {
	dialer, err := self.dialer()
	if err != nil {
		return nil, err
	}
	return dialer.dial(ctx, address, settings, allowShare)
}

// `ur share get`'s Dial (SOCK-M5-15): share/ let through, and a listener whose verified sidecar_id is not
// listenerSidecarId, the link's, refused before OPEN as a failed ticket (§9.9).
func (self *SocketComponent) dialShare(ctx context.Context, address *SocketAddress, listenerSidecarId Id) (*SocketConn, error) {
	dialer, err := self.dialer()
	if err != nil {
		return nil, err
	}
	dialer.listenerSidecarId = &listenerSidecarId
	return dialer.dial(ctx, address, nil, true)
}

// §9.9's Dial: a stream to one listener of address in this sidecar's network (§9.6). Errors are *net.OpError with Net
// "ur" around §9.9's values, which never repeat the address (I-13).
func (self *Sidecar) Dial(ctx context.Context, address string, settings *SocketDialSettings) (*SocketConn, error) {
	opError := func(err error) error {
		return &net.OpError{Op: "dial", Net: "ur", Err: err}
	}
	component := self.socketComponent()
	if component == nil {
		return nil, opError(&SocketCodeError{Err: ErrSocketUnavailable})
	}
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		return nil, opError(err)
	}
	conn, err := component.dial(ctx, parsed, settings, false)
	if err != nil {
		return nil, opError(err)
	}
	return conn, nil
}
