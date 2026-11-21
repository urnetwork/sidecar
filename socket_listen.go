//go:build !sidecar_http && !ios_extension

// §9.9's listener (R-SOCK-1, R-SOCK-8, D-SOCK-4, D-SOCK-8, D-SOCK-14, C9, X1): Sidecar.Listen registers a name through
// the component's registrar (§9.5) and takes its stream target, <label>:<name>, on each generation's §6 dispatcher, where
// every open runs admission (socket_admission.go) before a byte of it reaches AcceptSocket (FI-11).
//
// Which names. An application name listens as its token paths, so it needs the K_sock ring (D-SOCK-13). tls/ and smtp/
// are outward (I-8): Listen calls §5.4's Authorize first, which may answer *ApprovalPendingError, and holds the
// dispatcher's Service mode only while the registration is held (§13.6), so edges' contracts reach it. §13.9's system
// publish, tls/443/mta-sts, is a mail receiver's own component's alone, through ListenSystemPublish: it takes no tls/
// grant or approval of its own, so that entry asks this device's config for the receiver's approved smtp/25/mx listen
// grant instead, which stands in (SOCK-M8-01; socket_admission.go), and refuses with no approval filed. share/ is
// `ur share add`'s alone (SOCK-M5-15), ur/ the platform's (SOCK-M9-01), the system publish its entry's, and a reserved
// name has no owner: each is refused here. A <net> must be this sidecar's own network.
//
// The gate's action (§9.10, §16.6's grant row; QD-772, QD-740). A tls/ or smtp/ listen goes through Authorize as kind
// listen with a grant's fields alone, as a server may see them: this sidecar as subject, the socket as sock:<name> and
// listen allowed, with the rule_id and expiry of the requests rule that takes it (AclGrantFiler.Action); its name and
// weight ride the request beside it. Its effect is the grant component's. A standing grant, a document's rule or a
// grant already activated, passes it under an empty key with nothing to do; else the request is filed for the rule's
// approvers, and the listen asked again once a person approves spends the decision, whose use files the GrantActivate
// the approval fixes and is done with its grant_id, which the listen kind's Lookup finds again after a restart. A
// listen no requests rule takes names no rule and no expiry, so no decision could activate a grant for it: a standing
// grant alone passes it, and with none it is refused here (ErrSocketDenied), filing nothing. A use that came to
// not_done refuses the listen, and an uncertain one answers unavailable, which the same listen asked again completes
// under its key (AU4). The expiry a rule gives moves with the clock, so each listen's action is kept as its request was
// filed, by name and weight, until that expiry, and the listen asked again presents the bytes a decision names
// (keptListenAction); the copy is in memory alone, so a request filed before a restart is filed again after it.
//
// smtp/ is a receiver's (§15.5; SOCK-M7-01): smtp/25/mx, or a Team scope's smtp/25/mx.<scope>, protocol smtp-starttls,
// 16 streams unless the settings say otherwise. A receiver listens not serving, so its lease takes no ticket until §15
// has published its mail host key and calls SetServing(true): the closed direction until it can terminate TLS.
//
// What a listener does with its streams. An admitted stream counts in flight until its conn is closed or aborted, a
// reset ends it, or the listener resets it; the count goes to the registrar's load reports. A stream ends at its
// ticket's grant_expire_time_millis, and PolicyChanged re-derives each stream's grant (D-SOCK-14), resetting with
// RST_REVOKED those it no longer allows, as the registrar's revoked answer resets every stream of the entry.
//
//   - Close unlistens at once: the registration leaves the set and each dispatcher drops the target, so a racing ticket
//     answers retry. Accepted conns stay open; ones admitted but not yet taken are reset, as a socket's backlog is,
//     and a pending AcceptSocket answers net.ErrClosed.
//   - Drain sets draining, so no new tickets are issued while issued ones are still admitted, and ends at zero in
//     flight or the earlier of ctx and ListenDrainTimeout (30 s), resetting what remains with RST_DRAINING, then
//     closes (plan reading 6). SOCKET_HINT_DRAIN forces the same.
//   - SetServing(false) keeps the lease and takes no tickets; the listener then answers busy to a ticket issued
//     before, so its dialer tries the backup rather than a target that refuses (a reading).
//
// Nothing here logs a name (I-13). Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A name another listener holds: an exclusive one, or another protocol in the group (§9.5). It reaches EADDRINUSE,
// as a socket's bind does, since §9.9's six values have none for it (a reading).
var errSocketNameTaken error = &socketErrorValue{text: "socket name taken", errno: syscall.EADDRINUSE}

// §9.9's listen settings, defaults as §9.5 gives them: protocol "tcp" ("tls" on tls/, "smtp-starttls" on smtp/), the
// registration format's weight and max_streams (SocketFormatSettings: 100 and 256) or a receiver's on smtp/
// (SidecarSocketSettings.ReceiverMaxStreams: 16, §15.5), app_mode "http" on tls/.
type SocketListenSettings struct {
	Protocol string
	Version  int
	// tls/: the ALPN ids served.
	Alpn []string
	// tls/: "http" (default) or "raw" (§9.5).
	AppMode string
	// 1 to the format's MaxWeight. 0 takes its DefaultWeight.
	Weight int
	// At least 1. 0 takes the format's DefaultMaxStreams, or ReceiverMaxStreams on smtp/.
	MaxStreams int
	Exclusive  bool
	Affinity   bool
	// The ApprovalDecision for a tls/ or smtp/ listen (§5.4's gate).
	Decision *bridge.Signed
}

// §9.5's protocol and app mode names, and §8.4's action name a listen's grant allows.
const (
	socketListenDefaultProtocol   = "tcp"
	socketListenTlsProtocol       = "tls"
	socketListenSmtpProtocol      = "smtp-starttls"
	socketListenDefaultTlsAppMode = "http"
	socketListenTlsAppModeRaw     = "raw"
	socketListenNoAppMode         = ""
	socketListenGrantAllow        = "listen"
)

// One generation's part of a listener: the target on its dispatcher, and the Service hold.
type socketListenerAttachment struct {
	generation *socketGeneration
	remove     func()
	release    func()
}

// §9.9's listener. Sidecar.Listen makes one.
type SocketListener struct {
	component *SocketComponent
	settings  *SidecarSocketSettings
	clock     Clock
	networkId Id
	listenId  Id
	namespace SocketNamespace
	name      string
	target    string
	admission *socketAdmission
	// the conns admitted and not yet taken, at most max_streams, which in flight bounds
	accepted chan *SocketConn
	// closed by Close
	closed chan struct{}

	stateLock    sync.Mutex
	registration *socketRegistration
	closing      bool
	serving      bool
	draining     bool
	// the registration's lease is held, so a tls/ or smtp/ listener holds Service
	held        bool
	attachments map[uint64]*socketListenerAttachment
	streams     map[*socketListenerStream]bool
	// closed and replaced at each change of streams, which Drain waits on
	streamsChanged chan struct{}
}

var _ net.Listener = (*SocketListener)(nil)

// One admitted stream, counted in flight until it ends.
type socketListenerStream struct {
	listener *SocketListener
	stream   socketStream
	ticket   *protocol.SocketTicket
	request  *socketAdmissionRequest
	// the generation it was admitted on, whose sidecar its live check reads
	generation *socketGeneration
	// Set and removed under the listener's stateLock.
	stopExpiry func() bool
}

var _ socketStream = (*socketListenerStream)(nil)

// Takes the stream out of its listener's count, once.
func (self *socketListenerStream) end() {
	self.listener.untrack(self)
}

// Ends the count when err says the stream is gone.
func (self *socketListenerStream) observe(err error) {
	var resetErr *socketStreamResetError
	if errors.As(err, &resetErr) || errors.Is(err, net.ErrClosed) {
		self.end()
	}
}

// See socketStream.
func (self *socketListenerStream) Read(b []byte) (int, error) {
	n, err := self.stream.Read(b)
	if err != nil {
		self.observe(err)
	}
	return n, err
}

// See socketStream.
func (self *socketListenerStream) Write(b []byte) (int, error) {
	n, err := self.stream.Write(b)
	if err != nil {
		self.observe(err)
	}
	return n, err
}

// See socketStream.
func (self *socketListenerStream) CloseWrite() error {
	return self.stream.CloseWrite()
}

// See socketStream. The stream leaves the count.
func (self *socketListenerStream) Close() error {
	defer self.end()
	return self.stream.Close()
}

// See socketStream. The stream leaves the count.
func (self *socketListenerStream) Reset(code protocol.StreamResetCode) error {
	defer self.end()
	return self.stream.Reset(code)
}

// See socketStream.
func (self *socketListenerStream) SetReadDeadline(t time.Time) error {
	return self.stream.SetReadDeadline(t)
}

// See socketStream.
func (self *socketListenerStream) SetWriteDeadline(t time.Time) error {
	return self.stream.SetWriteDeadline(t)
}

// Whether a name of namespace holds Service while it is registered (§13.6).
func socketNamespaceProvidesService(namespace SocketNamespace) bool {
	return namespace == SocketNamespaceTls || namespace == SocketNamespaceSmtp
}

// Takes the target on generation's dispatcher and, while the lease is held, Service there.
func (self *SocketListener) attach(generation *socketGeneration) {
	if generation == nil || generation.subprotocol == nil {
		return
	}
	remove, err := generation.subprotocol.Listen(self.target, func(ctx context.Context, incoming *StreamIncoming) error {
		return self.accept(ctx, generation, incoming)
	})
	if err != nil {
		return
	}
	attachment := &socketListenerAttachment{generation: generation, remove: remove, release: func() {}}
	previous, keep := func() (*socketListenerAttachment, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closing {
			return nil, false
		}
		previous := self.attachments[generation.seq]
		self.attachments[generation.seq] = attachment
		return previous, true
	}()
	if previous != nil {
		previous.remove()
		previous.release()
	}
	if !keep {
		remove()
		return
	}
	self.holdService()
	go func() {
		<-generation.ctx.Done()
		self.detach(generation.seq, attachment)
	}()
}

// Ends one generation's part, if it is still the one attached.
func (self *SocketListener) detach(seq uint64, attachment *socketListenerAttachment) {
	stillAttached := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.attachments[seq] != attachment {
			return false
		}
		delete(self.attachments, seq)
		return true
	}()
	if stillAttached {
		attachment.remove()
		attachment.release()
	}
}

// Holds Service on each attached generation that lacks it, while the lease is held (§13.6, C9).
func (self *SocketListener) holdService() {
	if !socketNamespaceProvidesService(self.namespace) {
		return
	}
	attachments := func() []*socketListenerAttachment {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.held || self.closing {
			return nil
		}
		attachments := []*socketListenerAttachment{}
		for _, attachment := range self.attachments {
			attachments = append(attachments, attachment)
		}
		return attachments
	}()
	for _, attachment := range attachments {
		release, err := attachment.generation.subprotocol.HoldProvideMode(connectprotocol.ProvideMode_Service)
		if err != nil {
			continue
		}
		previous, replaced := func() (func(), bool) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closing || self.attachments[attachment.generation.seq] != attachment {
				return nil, false
			}
			previous := attachment.release
			attachment.release = release
			return previous, true
		}()
		if !replaced {
			release()
			continue
		}
		previous()
	}
}

// The token paths the registration goes under now, newest first: what a ticket's name_token must be one of.
func (self *SocketListener) nameTokens() [][]byte {
	ring := func() *SocketKeyRing {
		registrar := self.component.registrar
		registrar.stateLock.Lock()
		defer registrar.stateLock.Unlock()
		return registrar.state.ring
	}()
	if ring == nil {
		return nil
	}
	tokenPaths, err := ring.RegisterTokenPaths(self.name, self.clock.Now().UnixMilli())
	if err != nil {
		return nil
	}
	return tokenPaths
}

// One open of the target on generation's dispatcher: admission, then the accept queue.
func (self *SocketListener) accept(ctx context.Context, generation *socketGeneration, incoming *StreamIncoming) error {
	request := &socketAdmissionRequest{
		ticketBytes: incoming.Ticket,
		sourceId:    incoming.SourceId,
		peer:        incoming.Peer,
		edge:        incoming.Edge,
	}
	return self.acceptStream(ctx, generation, request, func() socketStream {
		return newSubprotocolSocketStream(incoming.Stream)
	}, incoming.Metadata)
}

// accept's logic on the seam: request admitted on generation, then the stream newStream makes, which carries nothing
// to its reader until this answers nil, queued for AcceptSocket. A refusal is a *StreamRejectError.
func (self *SocketListener) acceptStream(ctx context.Context, generation *socketGeneration, request *socketAdmissionRequest, newStream func() socketStream, metadata []byte) error {
	_, policy, _ := self.component.current()
	inflight, serving, closing := func() (int, bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return len(self.streams), self.serving, self.closing
	}()
	if closing {
		return &StreamRejectError{Code: protocol.StreamRejectCode_SR_RETRY}
	}
	verdict := self.admission.admit(ctx, request, &socketAdmissionInputs{
		admission: self.component.registrar.admission(),
		clientId:  generation.identity.ClientId,
		sidecarId: generation.identity.SidecarId,
		policy:    policy,
		inflight:  inflight,
		serving:   serving,
	})
	if verdict.code != protocol.StreamRejectCode_SR_UNSPECIFIED {
		return &StreamRejectError{Code: verdict.code}
	}

	tracked := &socketListenerStream{
		listener:   self,
		stream:     newStream(),
		ticket:     verdict.ticket,
		request:    request,
		generation: generation,
	}
	// the count's check and its increment in one step, so two opens never pass max_streams between them
	code := func() protocol.StreamRejectCode {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		switch {
		case self.closing:
			return protocol.StreamRejectCode_SR_RETRY
		case self.admission.maxStreams <= len(self.streams):
			return protocol.StreamRejectCode_SR_BUSY
		}
		self.streams[tracked] = true
		self.notifyStreamsWithLock()
		return protocol.StreamRejectCode_SR_UNSPECIFIED
	}()
	if code != protocol.StreamRejectCode_SR_UNSPECIFIED {
		return &StreamRejectError{Code: code}
	}
	if self.namespace == SocketNamespaceTls || self.namespace == SocketNamespaceSmtp {
		// A policy update can finish its live-stream scan between the ticket check and
		// tracking this stream. Check again once the stream is visible to every later scan.
		_, current, _ := self.component.current()
		if !self.admission.allows(current, request, generation.identity.SidecarId, verdict.ticket) {
			tracked.end()
			return &StreamRejectError{Code: protocol.StreamRejectCode_SR_DENIED}
		}
	}
	self.reportInflight()
	if grantExpireMillis := verdict.ticket.GetGrantExpireTimeMillis(); grantExpireMillis != 0 {
		admission := self.component.registrar.admission()
		stop := self.clock.AfterFunc(socketGrantEndTime(admission, grantExpireMillis).Sub(self.clock.Now()), func() {
			tracked.Reset(protocol.StreamResetCode_RST_REVOKED)
		})
		self.stateLock.Lock()
		trackedNow := self.streams[tracked]
		if trackedNow {
			tracked.stopExpiry = stop
		}
		self.stateLock.Unlock()
		if !trackedNow {
			stop()
		}
	}

	localAddr := &SocketAddr{NetworkId: connect.Id(self.networkId), ClientId: connect.Id(generation.identity.ClientId)}
	remoteAddr := &SocketAddr{ClientId: connect.Id(request.sourceId)}
	if dialerNetworkId, err := IdFromBytes(verdict.ticket.GetDialerNetworkId()); err == nil {
		remoteAddr.NetworkId = connect.Id(dialerNetworkId)
	}
	conn := newSocketConn(tracked, localAddr, remoteAddr, verdict.ticket, metadata)
	conn.signedTicket = append([]byte(nil), request.ticketBytes...)
	select {
	case self.accepted <- conn:
		return nil
	default:
		// in flight bounds the queue, so this is a close racing the accept
		tracked.end()
		return &StreamRejectError{Code: protocol.StreamRejectCode_SR_BUSY}
	}
}

// Closes the old channel and arms a new one, under the lock.
func (self *SocketListener) notifyStreamsWithLock() {
	close(self.streamsChanged)
	self.streamsChanged = make(chan struct{})
}

// Takes a stream out of the count and reports the load.
func (self *SocketListener) untrack(stream *socketListenerStream) {
	stopExpiry, removed := func() (func() bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.streams[stream] {
			return nil, false
		}
		delete(self.streams, stream)
		self.notifyStreamsWithLock()
		return stream.stopExpiry, true
	}()
	if stopExpiry != nil {
		stopExpiry()
	}
	if removed {
		self.reportInflight()
	}
}

// Hands the count to the registrar, which reports it at the next call, early when it moved enough (§9.5).
func (self *SocketListener) reportInflight() {
	registration, inflight := func() (*socketRegistration, int) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.registration, len(self.streams)
	}()
	if registration != nil {
		registration.setInflight(inflight)
	}
}

// Resets every stream in flight with code.
func (self *SocketListener) resetStreams(code protocol.StreamResetCode) {
	streams := func() []*socketListenerStream {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		streams := make([]*socketListenerStream, 0, len(self.streams))
		for stream := range self.streams {
			streams = append(streams, stream)
		}
		return streams
	}()
	for _, stream := range streams {
		stream.Reset(code)
	}
}

// Re-derives each stream's grant at now against policy (D-SOCK-14), resetting with RST_REVOKED each it no longer
// allows.
func (self *SocketListener) recheck(policy SocketPolicy) {
	streams := func() []*socketListenerStream {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		streams := make([]*socketListenerStream, 0, len(self.streams))
		for stream := range self.streams {
			streams = append(streams, stream)
		}
		return streams
	}()
	for _, stream := range streams {
		if !self.admission.allows(policy, stream.request, stream.generation.identity.SidecarId, stream.ticket) {
			stream.Reset(protocol.StreamResetCode_RST_REVOKED)
		}
	}
}

// The service ended the entry it had taken (§9.5's revoked): it closes with its streams. Called on the registrar's
// goroutine, which must not wait, so the work runs on its own.
func (self *SocketListener) ended(status SocketRegistrationStatus) {
	go func() {
		self.resetStreams(protocol.StreamResetCode_RST_REVOKED)
		self.Close()
	}()
}

// A SOCKET_HINT_DRAIN named this listen: the same drain Drain runs, on its own goroutine.
func (self *SocketListener) drainHinted() {
	go self.Drain(context.Background())
}

// The next admitted conn, or net.ErrClosed once the listener closed, or ctx's error.
func (self *SocketListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.accepted:
		return conn, nil
	default:
	}
	select {
	case conn := <-self.accepted:
		return conn, nil
	case <-self.closed:
		return nil, &net.OpError{Op: "accept", Net: "ur", Addr: self.Addr(), Err: net.ErrClosed}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// See net.Listener.
func (self *SocketListener) Accept() (net.Conn, error) {
	conn, err := self.AcceptSocket(context.Background())
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// This listener's network and its current generation's client (§9.9's addresses carry ids alone, I-13).
func (self *SocketListener) Addr() net.Addr {
	generation, _, _ := self.component.current()
	addr := &SocketAddr{NetworkId: connect.Id(self.networkId)}
	if generation != nil {
		addr.ClientId = connect.Id(generation.identity.ClientId)
	}
	return addr
}

// Unlistens at once (§9.9): see the file header. A second Close does nothing.
func (self *SocketListener) Close() error {
	registration, attachments, first := func() (*socketRegistration, []*socketListenerAttachment, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closing {
			return nil, nil, false
		}
		self.closing = true
		attachments := []*socketListenerAttachment{}
		for seq, attachment := range self.attachments {
			attachments = append(attachments, attachment)
			delete(self.attachments, seq)
		}
		return self.registration, attachments, true
	}()
	if !first {
		return nil
	}
	if registration != nil {
		registration.remove()
	}
	for _, attachment := range attachments {
		attachment.remove()
		attachment.release()
	}
	self.component.removeListener(self)
	close(self.closed)
	// what was admitted and never taken is reset, as a socket's backlog is
	for drained := false; !drained; {
		select {
		case conn := <-self.accepted:
			conn.stream.Reset(protocol.StreamResetCode_RST_CANCELLED)
		default:
			drained = true
		}
	}
	return nil
}

// §9.9's Drain: see the file header. nil once in flight reached zero or the drain's time ran out, ctx's error when it
// ended first; the listener is closed either way.
func (self *SocketListener) Drain(ctx context.Context) error {
	registration := func() *socketRegistration {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
		return self.registration
	}()
	if registration != nil {
		registration.setDraining(true)
	}
	timeout := self.clock.After(self.settings.ListenDrainTimeout)
	var drainErr error
	for {
		inflight, changed := func() (int, chan struct{}) {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return len(self.streams), self.streamsChanged
		}()
		if inflight == 0 {
			break
		}
		done := false
		select {
		case <-changed:
		case <-timeout:
			done = true
		case <-ctx.Done():
			drainErr = ctx.Err()
			done = true
		}
		if done {
			break
		}
	}
	self.resetStreams(protocol.StreamResetCode_RST_DRAINING)
	self.Close()
	return drainErr
}

// §9.9's SetServing: false keeps the lease and takes no tickets (§9.5).
func (self *SocketListener) SetServing(serving bool) {
	registration := func() *socketRegistration {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.serving = serving
		return self.registration
	}()
	if registration != nil {
		registration.setServing(serving)
	}
}

// Changes a tls/ registration's ALPN ids, certified names and ACME names under the same listen_id and sends the page
// now, through the registrar (DESIGN-DETAILS 17.2.10): what a front calls as its challenges and custom certificates
// come and go. The service keeps only the names its rows bear out (ValidateListen). Refused on a listener of another
// namespace, and with a list past what a registration may carry.
func (self *SocketListener) UpdateTls(alpns []string, certifiedNames []string, acmeNames []*SocketAcmeName) error {
	if self.namespace != SocketNamespaceTls {
		return fmt.Errorf("%w: UpdateTls is a tls/ listener's", errSocketRegistrationInvalid)
	}
	if self.component.format.AlpnMaxCount < len(alpns) || slices.Contains(alpns, "") {
		return fmt.Errorf("%w: too many ALPN ids, or an empty one", errSocketRegistrationInvalid)
	}
	for _, acmeName := range acmeNames {
		if acmeName == nil || acmeName.Name == "" {
			return fmt.Errorf("%w: an ACME name with no name", errSocketRegistrationInvalid)
		}
	}
	registration := func() *socketRegistration {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.registration
	}()
	if registration == nil {
		return &SocketCodeError{Err: ErrSocketUnavailable}
	}
	registration.setTls(alpns, certifiedNames, acmeNames)
	return nil
}

// UpdateTls with a front's update.
func (self *SocketListener) updateTls(update *TlsFrontUpdate) error {
	return self.UpdateTls(update.Alpn, update.CertifiedNames, update.AcmeNames)
}

// How many streams are in flight.
func (self *SocketListener) inflightCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.streams)
}

// Takes a listener out of the component's set.
func (self *SocketComponent) removeListener(listener *SocketListener) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.listeners, listener)
}

// Re-derives every live stream's grant against the policy as it stands now (D-SOCK-14): the host calls this once a
// newer verified state is installed, so a config change that drops a grant resets its streams.
func (self *SocketComponent) PolicyChanged() {
	policy, listeners := func() (SocketPolicy, []*SocketListener) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		listeners := make([]*SocketListener, 0, len(self.listeners))
		for listener := range self.listeners {
			listeners = append(listeners, listener)
		}
		return self.policy, listeners
	}()
	for _, listener := range listeners {
		listener.recheck(policy)
	}
}

// The key a listen's action is kept under (keptListenAction): its name and the weight its request binds.
type socketListenActionKey struct {
	name   string
	weight int32
}

// The effect of a listen no requests rule takes: a standing grant passes it under an empty key, with nothing to do, and
// no decision's use can activate a grant for it, since a GrantActivate names the requests rule its grant is asked under
// (§8.8), so a use proves that nothing happened.
type socketListenStandingEffect struct{}

// See SidecarEffect.
func (socketListenStandingEffect) Run(ctx context.Context, effectKey []byte) ([]byte, error) {
	if len(effectKey) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("%w: no requests rule takes this listen, so no grant activates for it", ErrSidecarEffectNotDone)
}

// The grant filer a tls/ or smtp/ listen's action is built and activated by: the one a host-less component was given,
// else one over the host's standing follower's ACL engine, the engine the host's gate reads its standing grants from
// (cli's bridge_filing_config.go), for this network alone. Nil while there is none.
func (self *SocketComponent) listenGrantFiler() *AclGrantFiler {
	grants := func() *AclGrantFiler {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.grants
	}()
	if grants != nil || self.host == nil {
		return grants
	}
	follower := self.host.ConfigFollower()
	if follower == nil {
		return nil
	}
	engine, client := follower.StandingPolicy()
	if engine == nil || client == nil || client.NetworkId() != self.networkId {
		return nil
	}
	return NewAclGrantFiler(self.host, engine)
}

// The §5.4 action a tls/ or smtp/ listen on name goes through Authorize as, with its effect (the file header): kind
// listen with the grant's fields for this generation's sidecar, its socket named as a server may see it
// (SocketListenGrantDst), and beside it the name and the weight it registers with, the format's default for none, as
// the request's socket_name and weight (QD-740). This listener accepts in process and binds no local port, so the
// request carries none. ErrSocketDenied where no requests rule takes the listen and no standing grant covers it, and
// ErrSocketUnavailable with no verified ACL state to judge it on.
func (self *SocketComponent) socketListenAction(ctx context.Context, generation *socketGeneration, name string, settings *SocketListenSettings) (*SidecarAction, error) {
	grants := self.listenGrantFiler()
	if grants == nil || grants.engine == nil || grants.engine.State() == nil || generation == nil || generation.identity == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	grantDst, err := SocketListenGrantDst(name, nil)
	if err != nil {
		return nil, err
	}
	weight := self.format.DefaultWeight
	if settings != nil && settings.Weight != 0 {
		weight = settings.Weight
	}
	subject := generation.identity.SidecarId
	now := self.clock.Now()
	ask := &AclGrantRequest{Subject: subject, GrantDst: []string{grantDst}, GrantAllow: []string{socketListenGrantAllow}}
	stored, err := grants.Action(ctx, &protocol.CanonicalAction{Kind: uint32(SidecarActionListen)}, ask, now)
	var effect SidecarEffect
	switch {
	case err == nil:
		stored = self.keptListenAction(socketListenActionKey{name: name, weight: int32(weight)}, stored, now)
		effect = grants.Effect(stored)
	case errors.Is(err, ErrAclRequestNoMatch):
		// no requests rule takes it, so no decision could activate its grant: a standing grant alone passes it, and with
		// none nothing is filed
		stored, err = NewCanonicalAction(&protocol.CanonicalAction{
			Kind: uint32(SidecarActionListen), Subject: subject.Bytes(), GrantDst: ask.GrantDst, GrantAllow: ask.GrantAllow,
		})
		if err != nil {
			return nil, err
		}
		if !grants.engine.ActiveGrant(stored, subject, now) {
			return nil, &SocketCodeError{Err: ErrSocketDenied}
		}
		effect = socketListenStandingEffect{}
	default:
		return nil, err
	}
	action, err := NewSidecarAction(stored, SidecarRiskNormal, SidecarRiskNormal, nil, nil)
	if err != nil {
		return nil, err
	}
	action.Detail = &SidecarActionDetail{SocketName: name, Weight: int32(weight)}
	action.Effect = effect
	return action, nil
}

// The action a listen's request was filed with, by name and weight, while its expiry is ahead, else fresh, which is
// kept in its place: the expiry a requests rule gives moves with the clock, so fresh, built now, asks another action,
// and a decision on the first would never be spent (the file header). fresh replaces a kept action that has expired,
// that asks a longer grant than the rule now gives, or that differs from fresh in anything but its expiry, a changed
// rule's id say. Expired actions are dropped as each is asked for, so the map holds one per name and weight listened
// on within a rule's lifetime.
func (self *SocketComponent) keptListenAction(key socketListenActionKey, fresh *StoredCanonicalAction, now time.Time) *StoredCanonicalAction {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	nowMs := now.UnixMilli()
	for keptKey, kept := range self.listenActions {
		if kept.Action.GetExpiresMillis() <= nowMs {
			delete(self.listenActions, keptKey)
		}
	}
	if kept := self.listenActions[key]; kept != nil {
		clear := proto.Clone(fresh.Action).(*protocol.CanonicalAction)
		clear.ExpiresMillis = kept.Action.GetExpiresMillis()
		if kept.Action.GetExpiresMillis() <= fresh.Action.GetExpiresMillis() && proto.Equal(kept.Action, clear) {
			return kept
		}
	}
	self.listenActions[key] = fresh
	return fresh
}

// The listen kind's Lookup (§16.6's grant row), which the host's gate reconciles a reserved use by: the grant
// component's, whether the grant_id the spend fixes is in the log the host's engine installed; a listen no requests
// rule names activated nothing (socketListenStandingEffect).
func (self *SocketComponent) listenLookup(ctx context.Context, canonical []byte, effectKey []byte) (*SidecarOutcome, error) {
	stored, err := ParseStoredCanonicalAction(canonical)
	if err != nil {
		return nil, err
	}
	if len(stored.Action.GetRuleId()) == 0 {
		return &SidecarOutcome{State: ApprovalOutcomeNotDone}, nil
	}
	grants := self.listenGrantFiler()
	if grants == nil {
		return &SidecarOutcome{State: ApprovalOutcomeUncertain}, nil
	}
	return grants.Lookup(ctx, canonical, effectKey)
}

// What a listen the gate passed answers for its outcome: nil once its grant stands, a standing grant's included;
// ErrSocketDenied where its use proved the grant did not activate; ErrSocketUnavailable while that is uncertain, which
// the same listen asked again completes under the use's key (AU4). A gate that set no outcome passed the listen with
// nothing more to say.
func socketListenOutcomeError(outcome *SidecarOutcome) error {
	if outcome == nil {
		return nil
	}
	switch outcome.State {
	case ApprovalOutcomeDone:
		return nil
	case ApprovalOutcomeNotDone:
		return &SocketCodeError{Err: ErrSocketDenied}
	}
	return &SocketCodeError{Err: ErrSocketUnavailable}
}

// The registration args for name with settings' defaults applied, from format and from sockets for a receiver, and
// held to format's bounds (§9.5).
func socketListenArgs(format *SocketFormatSettings, sockets *SidecarSocketSettings, name string, namespace SocketNamespace, settings *SocketListenSettings) (*socketRegistrationArgs, error) {
	args := &socketRegistrationArgs{
		Name:       name,
		Protocol:   settings.Protocol,
		Version:    settings.Version,
		Alpns:      append([]string(nil), settings.Alpn...),
		AppMode:    settings.AppMode,
		Weight:     settings.Weight,
		MaxStreams: settings.MaxStreams,
		Exclusive:  settings.Exclusive,
		Affinity:   settings.Affinity,
	}
	if args.Protocol == "" {
		args.Protocol = socketListenDefaultProtocol
		switch namespace {
		case SocketNamespaceTls:
			args.Protocol = socketListenTlsProtocol
		case SocketNamespaceSmtp:
			args.Protocol = socketListenSmtpProtocol
		}
	}
	if args.Weight == 0 {
		args.Weight = format.DefaultWeight
	}
	if args.MaxStreams == 0 {
		args.MaxStreams = format.DefaultMaxStreams
		if namespace == SocketNamespaceSmtp {
			args.MaxStreams = sockets.ReceiverMaxStreams
		}
	}
	if namespace == SocketNamespaceSmtp {
		// only a receiver listens on smtp/: mx or mx.<scope>, speaking smtp-starttls (§15.5)
		host := name[strings.LastIndexByte(name, '/')+1:]
		if label, _, _ := strings.Cut(host, "."); label != "mx" || args.Protocol != socketListenSmtpProtocol {
			return nil, fmt.Errorf("%w: smtp/ takes a receiver's mx host and smtp-starttls", errSocketRegistrationInvalid)
		}
		// a receiver takes no ticket until §15 has published its key and calls SetServing
		args.NotServing = true
	}
	if namespace == SocketNamespaceTls {
		if args.AppMode == "" {
			args.AppMode = socketListenDefaultTlsAppMode
		}
		if args.AppMode != socketListenDefaultTlsAppMode && args.AppMode != socketListenTlsAppModeRaw {
			return nil, fmt.Errorf("%w: an app mode is http or raw", errSocketRegistrationInvalid)
		}
	} else if args.AppMode != socketListenNoAppMode || 0 < len(args.Alpns) {
		return nil, fmt.Errorf("%w: only tls/ takes an app mode or ALPN ids", errSocketRegistrationInvalid)
	}
	switch {
	case args.Weight < socketRegistrationMinWeight || format.MaxWeight < args.Weight:
		return nil, fmt.Errorf("%w: a weight is %d to %d", errSocketRegistrationInvalid, socketRegistrationMinWeight, format.MaxWeight)
	case args.MaxStreams < 1:
		return nil, fmt.Errorf("%w: max_streams is at least 1", errSocketRegistrationInvalid)
	case format.AlpnMaxCount < len(args.Alpns), format.ProtocolMaxByteCount < len(args.Protocol):
		return nil, fmt.Errorf("%w: too many ALPN ids or too long a protocol", errSocketRegistrationInvalid)
	}
	return args, nil
}

// A Listen on this component; allowShare lets share/ through for `ur share add` (SOCK-M5-15). §13.9's system publish
// is refused here: only listenSystemPublish takes it.
func (self *SocketComponent) listen(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, allowShare bool) (*SocketListener, error) {
	return self.listenAs(ctx, address, settings, allowShare, false)
}

// §13.9's system publish on this component (SOCK-M8-01): tls/443/mta-sts in this network, on this sidecar's own
// approved smtp/25/mx listen grant (socket_admission.go).
func (self *SocketComponent) listenSystemPublish(ctx context.Context, settings *SocketListenSettings) (*SocketListener, error) {
	return self.listenAs(ctx, &SocketAddress{Name: SocketSystemPublishName}, settings, false, true)
}

// listen's body: allowShare lets share/ through, and systemPublish is the system publish's own entry, the one way to
// its name, which takes no other.
func (self *SocketComponent) listenAs(ctx context.Context, address *SocketAddress, settings *SocketListenSettings, allowShare bool, systemPublish bool) (*SocketListener, error) {
	if settings == nil {
		settings = &SocketListenSettings{}
	}
	name, namespace, err := ParseSocketName(address.Name)
	if err != nil {
		return nil, err
	}
	switch namespace {
	case SocketNamespaceApplication, SocketNamespaceTls, SocketNamespaceSmtp:
	case SocketNamespaceShare:
		if !allowShare {
			return nil, &SocketCodeError{Err: ErrSocketDenied}
		}
	default:
		// ur/ is the platform's (SOCK-M9-01), and a reserved name has no owner
		return nil, &SocketCodeError{Err: ErrSocketDenied}
	}
	if (name == SocketSystemPublishName) != systemPublish {
		// the system publish is a mail receiver's own component's, which no other caller reaches
		return nil, &SocketCodeError{Err: ErrSocketDenied}
	}
	if err := self.prepareSocketNetwork(ctx, address.NetworkLabel); err != nil {
		return nil, err
	}
	generation, policy, labels := self.current()
	if labels == nil {
		return nil, &SocketCodeError{Err: ErrSocketUnavailable}
	}
	if address.NetworkLabel != "" && address.NetworkLabel != labels.Label {
		if labels.Resolver == nil {
			return nil, &SocketCodeError{Err: ErrSocketUnavailable}
		}
		networkId, _, err := labels.Resolver.ResolveNetworkLabel(labels.Root, address.NetworkLabel, false)
		if err != nil || networkId != self.networkId {
			// a listener listens in its own network alone
			return nil, &SocketCodeError{Err: ErrSocketDenied}
		}
	}
	args, err := socketListenArgs(self.format, self.settings, name, namespace, settings)
	if err != nil {
		return nil, err
	}
	// an outward name goes through §5.4's gate first (I-8), except §13.9's system publish, whose receiver's approved
	// smtp/25/mx listen grant stands in for its tls/ grants and their approval (socket_admission.go)
	if systemPublish {
		if err := socketSystemPublishListenable(generation, policy, args, self.clock.Now()); err != nil {
			return nil, err
		}
	} else if socketNamespaceProvidesService(namespace) {
		if generation == nil || generation.authorize == nil {
			return nil, &SocketCodeError{Err: ErrSocketUnavailable}
		}
		action, err := self.listenAction(ctx, generation, name, settings)
		if err != nil {
			return nil, err
		}
		if err := generation.authorize(ctx, action, settings.Decision); err != nil {
			return nil, err
		}
		// the gate ran the listen's effect: its grant stands, or the use says why the listen cannot register
		if err := socketListenOutcomeError(action.Outcome); err != nil {
			return nil, err
		}
	}

	listener := &SocketListener{
		component:      self,
		settings:       self.settings,
		clock:          self.clock,
		networkId:      self.networkId,
		listenId:       NewId(),
		namespace:      namespace,
		name:           name,
		target:         labels.Label + ":" + name,
		accepted:       make(chan *SocketConn, args.MaxStreams),
		closed:         make(chan struct{}),
		serving:        !args.NotServing,
		attachments:    map[uint64]*socketListenerAttachment{},
		streams:        map[*socketListenerStream]bool{},
		streamsChanged: make(chan struct{}),
	}
	listener.admission = newSocketAdmission(self.settings, self.clock, self.networkId, listener.listenId, namespace, name, listener.nameTokens, args.MaxStreams)
	args.ListenId = listener.listenId
	args.Ended = listener.ended
	args.DrainHinted = listener.drainHinted

	// the target first, so a ticket that races the first verdict finds it
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.listeners[listener] = true
	}()
	if generation != nil {
		listener.attach(generation)
	}
	registration, err := self.registrar.add(args)
	if err != nil {
		listener.Close()
		return nil, err
	}
	func() {
		listener.stateLock.Lock()
		defer listener.stateLock.Unlock()
		listener.registration = registration
	}()
	status, err := registration.verdict(ctx)
	if err == nil && status != SocketRegistrationStatusOk {
		switch status {
		case SocketRegistrationStatusTaken:
			err = errSocketNameTaken
		case SocketRegistrationStatusInvalid:
			err = errSocketRegistrationInvalid
		default:
			err = &SocketCodeError{Err: ErrSocketDenied}
		}
	}
	if err != nil {
		listener.Close()
		return nil, err
	}
	func() {
		listener.stateLock.Lock()
		defer listener.stateLock.Unlock()
		listener.held = true
	}()
	listener.holdService()
	return listener, nil
}

// §9.9's Listen (§9.5): a registration on address in this sidecar's network, live once the service's first verdict
// takes it. On tls/ and smtp/ it calls §5.4's Authorize first (I-8), which may answer *ApprovalPendingError. §13.9's
// system publish, tls/443/mta-sts, is refused: it is ListenSystemPublish's. Other errors are *net.OpError with Net
// "ur", which never repeat the address (I-13).
func (self *Sidecar) Listen(ctx context.Context, address string, settings *SocketListenSettings) (*SocketListener, error) {
	opError := func(err error) error {
		return &net.OpError{Op: "listen", Net: "ur", Err: err}
	}
	component := self.socketComponent()
	if component == nil {
		return nil, opError(&SocketCodeError{Err: ErrSocketUnavailable})
	}
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		return nil, opError(err)
	}
	listener, err := component.listen(ctx, parsed, settings, false)
	if err != nil {
		var pending *ApprovalPendingError
		if errors.As(err, &pending) {
			return nil, err
		}
		return nil, opError(err)
	}
	return listener, nil
}

// §13.9's system publish (§9.10, §15.5; SOCK-M8-01): tls/443/mta-sts in this sidecar's network, where a mail
// receiver's own component serves its network's MTA-STS policy, audience public. It registers on this sidecar's own
// approved smtp/25/mx listen grant, which stands in for the name's tls/ listen and publish grants and their approval
// (I-8 was that grant's), so it asks no approval and files none: with no such grant in this device's config it is
// denied, and settings must leave app mode http, the publish's one mode. Listen and the daemon's sockets refuse the
// name, so only the component the daemon composes for a receiver reaches it. The grant's expiry or revocation ends
// the publish: the service answers revoked, which closes the listener, and its streams reset (socket_admission.go).
// Errors are as Listen's.
func (self *Sidecar) ListenSystemPublish(ctx context.Context, settings *SocketListenSettings) (*SocketListener, error) {
	opError := func(err error) error {
		return &net.OpError{Op: "listen", Net: "ur", Err: err}
	}
	component := self.socketComponent()
	if component == nil {
		return nil, opError(&SocketCodeError{Err: ErrSocketUnavailable})
	}
	listener, err := component.listenSystemPublish(ctx, settings)
	if err != nil {
		return nil, opError(err)
	}
	return listener, nil
}
