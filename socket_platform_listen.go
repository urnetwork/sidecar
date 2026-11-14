//go:build !sidecar_http && !ios_extension

// SocketPlatformListener (SOCK-M9-01; D-SOCK-11, D-SOCK-12, C9, X7, I-3): a platform service's listener on
// ur/<service>, which smtpedgeservice embeds so sidecars reach it through Find (§14). It needs no Sidecar. Each of the
// process's K platform clients in urnetwork-edge registers the name as a listener of its own, through a registrar on
// that client's own token, in the clear and with no claim, since a platform client holds no identity key or Hello
// binding (SOCK.md reading 7); and takes the name's stream target on its dispatcher in the edge role. The target is
// the name itself, ur/<service>: a ur/ name carries no <net>, and urnetwork-edge's label is nothing a dialer knows (a
// reading of SOCK.md reading 12).
//
// Admission is §9.6's steps 1 to 5 and 7 (socket_admission.go): the service's signature under the keys the
// registrations answered, this client and this listen, the dialer the session's source and no edge, the ticket
// unexpired and unseen, room while serving. Step 6 has no config to run on: the service authorizes what comes
// through it (§14.5), as §9.4 has ur/ names reached with no §8 check. §20's stop is the paying network's, the
// dialer's, which Find judged; the registration answer's stop is urnetwork-edge's own and stops nothing here. A
// sidecar's stream to an edge runs no Hello and is an edge stream at both ends (Service, C9).
//
// AcceptSocket hands on what every client admitted. A stream counts in flight until its conn ends, and ends at its
// ticket's grant_expire_time_millis. Close unlistens every client at once; Drain sets draining, so no ticket is
// issued while issued ones are still admitted, and ends at zero in flight or the earlier of ctx and ListenDrainTimeout,
// resetting the rest with RST_DRAINING. SetServing(false) keeps the leases and takes no tickets.
//
// Nothing here logs a name (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// What NewSocketPlatformListener takes.
type SocketPlatformListenerArgs struct {
	// ur/<service>.
	Name string
	// urnetwork-edge, the network the process's clients and the name's group are in.
	UrnetworkEdge Id
	// The process's platform clients, each with its dispatcher in the edge role: each registers the name.
	Clients []*SocketEdgeClient
	// How each client's registrations reach the sockets service, on the client's own token.
	Registrations *SocketPlatformRegistrationsArgs
	// The protocol, version, weight and max_streams each client registers with. "" and 0 take §9.5's "tcp", 100 and
	// 256.
	Protocol   string
	Version    int
	Weight     int
	MaxStreams int
	// The registrar's intervals and admission's. Nil is DefaultSidecarSocketSettings.
	Settings *SidecarSocketSettings
	// The listener's own limits. Nil is DefaultSocketPlatformListenSettings.
	Platform *SocketPlatformListenSettings
	// Nil is real time.
	Clock Clock
	// Nil is the default logger.
	Log Logger
}

// Where a platform listener's registrations go and how each client authenticates (§9.15's Client class).
type SocketPlatformRegistrationsArgs struct {
	// The sockets service's origin, with no trailing slash: §19.4's sockets url.
	SocketsUrl string
	// Carries every request: the host's own.
	Transport http.RoundTripper
	// clientId's own client token.
	Bearer func(ctx context.Context, clientId Id) (string, error)
}

// A platform listener's own limits.
type SocketPlatformListenSettings struct {
	// The most bytes of one registrations answer read: past it the answer is no page's. 64 KiB, a page of the
	// listener's one entry, the service's ticket keys and the rest in JSON, many times over.
	RegistrationsMaxAnswerByteCount int64
}

// The listener's defaults.
func DefaultSocketPlatformListenSettings() *SocketPlatformListenSettings {
	return &SocketPlatformListenSettings{
		RegistrationsMaxAnswerByteCount: 64 * 1024,
	}
}

// A platform client signs nothing: no ur/ entry carries a claim, so this is never called for one.
var errSocketPlatformSigns = errors.New("a platform client signs no socket claim")

// One client's part: its registration, its admission and its target on its dispatcher.
type socketPlatformClient struct {
	listener  *SocketPlatformListener
	clientId  Id
	registrar *socketRegistrar
	// the registration, and its ending
	registration *socketRegistration
	admission    *socketAdmission
	remove       func()
}

// The listener. NewSocketPlatformListener makes one.
type SocketPlatformListener struct {
	settings *SidecarSocketSettings
	clock    Clock
	name     string
	edge     Id
	ctx      context.Context
	cancel   context.CancelFunc
	clients  []*socketPlatformClient
	// the conns admitted and not yet taken, at most max_streams a client
	accepted chan *SocketConn
	// closed by Close
	closed chan struct{}

	stateLock sync.Mutex
	closing   bool
	serving   bool
	draining  bool
	streams   map[*socketPlatformStream]*socketPlatformClient
	// each client's streams in flight
	clientInflights map[*socketPlatformClient]int
	// closed and replaced at each change of streams, which Drain waits on
	streamsChanged chan struct{}
}

// A listener of args.Name on every one of args.Clients, registering at once, until ctx ends or Close. It answers once
// the registrations are under way; each client's lease is the service's to grant, and a ticket before it is refused.
func NewSocketPlatformListener(ctx context.Context, args *SocketPlatformListenerArgs) (*SocketPlatformListener, error) {
	if args == nil || len(args.Clients) == 0 || args.Registrations == nil || args.UrnetworkEdge == (Id{}) {
		return nil, fmt.Errorf("%w: a platform listener needs its name, network, clients and registrations", errInvalidSettings)
	}
	name, namespace, err := ParseSocketName(args.Name)
	if err != nil || namespace != SocketNamespacePlatform {
		return nil, fmt.Errorf("%w: a platform listener listens on a ur/ name", errSocketRegistrationInvalid)
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSidecarSocketSettings()
	}
	platformSettings := args.Platform
	if platformSettings == nil {
		platformSettings = DefaultSocketPlatformListenSettings()
	}
	if platformSettings.RegistrationsMaxAnswerByteCount <= 0 {
		return nil, fmt.Errorf("%w: a platform listener reads a positive answer", errInvalidSettings)
	}
	protocolName := args.Protocol
	if protocolName == "" {
		protocolName = socketListenDefaultProtocol
	}
	weight := args.Weight
	if weight == 0 {
		weight = socketListenDefaultWeight
	}
	maxStreams := args.MaxStreams
	if maxStreams == 0 {
		maxStreams = socketListenDefaultMaxStreams
	}
	seen := map[Id]bool{}
	for _, client := range args.Clients {
		if client == nil || client.Subprotocol == nil || client.Subprotocol.role != SubprotocolRoleEdge || seen[client.ClientId] {
			return nil, fmt.Errorf("%w: each platform client is distinct, with a dispatcher in the edge role", errInvalidSettings)
		}
		seen[client.ClientId] = true
	}
	listenerCtx, cancel := context.WithCancel(ctx)
	self := &SocketPlatformListener{
		settings:        settings,
		clock:           clockOrReal(args.Clock),
		name:            name,
		edge:            args.UrnetworkEdge,
		ctx:             listenerCtx,
		cancel:          cancel,
		accepted:        make(chan *SocketConn, maxStreams*len(args.Clients)),
		closed:          make(chan struct{}),
		serving:         true,
		streams:         map[*socketPlatformStream]*socketPlatformClient{},
		clientInflights: map[*socketPlatformClient]int{},
		streamsChanged:  make(chan struct{}),
	}
	fail := func(err error) (*SocketPlatformListener, error) {
		self.Close()
		return nil, err
	}
	for _, edgeClient := range args.Clients {
		clientId := edgeClient.ClientId
		registrar, err := newSocketRegistrar(listenerCtx, &socketRegistrarArgs{
			NetworkId: args.UrnetworkEdge,
			Settings:  settings,
			Sign: func(purpose string, signedType bridge.SignedType, body []byte, agentId *Id) (*bridge.Signed, error) {
				return nil, errSocketPlatformSigns
			},
			Clock: args.Clock,
			Log:   args.Log,
		})
		if err != nil {
			return fail(err)
		}
		listenId := NewId()
		client := &socketPlatformClient{
			listener:  self,
			clientId:  clientId,
			registrar: registrar,
			admission: newSocketAdmission(settings, self.clock, args.UrnetworkEdge, listenId, SocketNamespacePlatform, name, nil, maxStreams),
		}
		self.clients = append(self.clients, client)
		send, err := newSocketPlatformRegistrations(args.Registrations, platformSettings, clientId)
		if err != nil {
			return fail(err)
		}
		registrar.attach(listenerCtx, send, nil)
		registration, err := registrar.add(&socketRegistrationArgs{
			Name:       name,
			ListenId:   listenId,
			Protocol:   protocolName,
			Version:    args.Version,
			Weight:     weight,
			MaxStreams: maxStreams,
			Ended: func(status SocketRegistrationStatus) {
				// the service ended this client's lease: its streams go with it, and the client listens no more
				go client.end()
			},
		})
		if err != nil {
			return fail(err)
		}
		client.registration = registration
		remove, err := edgeClient.Subprotocol.Listen(name, func(ctx context.Context, incoming *StreamIncoming) error {
			return self.accept(ctx, client, &socketAdmissionRequest{
				ticketBytes: incoming.Ticket,
				sourceId:    incoming.SourceId,
				peer:        incoming.Peer,
				edge:        incoming.Edge,
			}, func() socketStream {
				return newSubprotocolSocketStream(incoming.Stream)
			}, incoming.Metadata)
		})
		if err != nil {
			return fail(err)
		}
		client.remove = remove
	}
	return self, nil
}

// Waits for each client's first answer from the service: nil once every client holds its lease, else the first
// refusal, as a *SocketCodeError around ErrSocketDenied, or ctx's error.
func (self *SocketPlatformListener) AwaitRegistered(ctx context.Context) error {
	for _, client := range self.clients {
		status, err := client.registration.verdict(ctx)
		if err != nil {
			return err
		}
		if status != SocketRegistrationStatusOk {
			return &SocketCodeError{Err: ErrSocketDenied}
		}
	}
	return nil
}

// A client's lease ended: its target leaves its dispatcher and its streams reset.
func (self *socketPlatformClient) end() {
	if self.remove != nil {
		self.remove()
	}
	self.listener.resetStreams(self, protocol.StreamResetCode_RST_REVOKED)
}

// One open on client's dispatcher: admission without step 6, then the accept queue. A refusal is a *StreamRejectError.
func (self *SocketPlatformListener) accept(ctx context.Context, client *socketPlatformClient, request *socketAdmissionRequest, newStream func() socketStream, metadata []byte) error {
	inflight, serving, closing := func() (int, bool, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.clientInflights[client], self.serving, self.closing
	}()
	if closing {
		return &StreamRejectError{Code: protocol.StreamRejectCode_SR_RETRY}
	}
	admissionState := client.registrar.admission()
	verdict := client.admission.admit(ctx, request, &socketAdmissionInputs{
		admission: admissionState,
		clientId:  client.clientId,
		inflight:  inflight,
		serving:   serving,
	})
	if verdict.code != protocol.StreamRejectCode_SR_UNSPECIFIED {
		return &StreamRejectError{Code: verdict.code}
	}
	tracked := &socketPlatformStream{
		listener: self,
		stream:   newStream(),
	}
	code := func() protocol.StreamRejectCode {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closing {
			return protocol.StreamRejectCode_SR_RETRY
		}
		if client.admission.maxStreams <= self.clientInflights[client] {
			return protocol.StreamRejectCode_SR_BUSY
		}
		self.streams[tracked] = client
		self.clientInflights[client] += 1
		self.notifyStreamsWithLock()
		return protocol.StreamRejectCode_SR_UNSPECIFIED
	}()
	if code != protocol.StreamRejectCode_SR_UNSPECIFIED {
		return &StreamRejectError{Code: code}
	}
	self.reportInflight(client)
	if grantExpireMillis := verdict.ticket.GetGrantExpireTimeMillis(); grantExpireMillis != 0 {
		tracked.stopExpiry = self.clock.AfterFunc(socketGrantEndTime(admissionState, grantExpireMillis).Sub(self.clock.Now()), func() {
			tracked.Reset(protocol.StreamResetCode_RST_REVOKED)
		})
	}
	localAddr := &SocketAddr{NetworkId: connect.Id(self.edge), ClientId: connect.Id(client.clientId)}
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
func (self *SocketPlatformListener) notifyStreamsWithLock() {
	close(self.streamsChanged)
	self.streamsChanged = make(chan struct{})
}

// The stream leaves its client's count, which the client's registrar reports.
func (self *SocketPlatformListener) untrack(stream *socketPlatformStream) {
	client := func() *socketPlatformClient {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		client := self.streams[stream]
		if client == nil {
			return nil
		}
		delete(self.streams, stream)
		self.clientInflights[client] -= 1
		self.notifyStreamsWithLock()
		return client
	}()
	if client != nil {
		self.reportInflight(client)
	}
}

// Hands client's count to its registrar, which reports it at the next call, early when it moved enough (§9.5).
func (self *SocketPlatformListener) reportInflight(client *socketPlatformClient) {
	inflight := func() int {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.clientInflights[client]
	}()
	if client.registration != nil {
		client.registration.setInflight(inflight)
	}
}

// Resets with code every stream in flight of client, or of every client when client is nil.
func (self *SocketPlatformListener) resetStreams(client *socketPlatformClient, code protocol.StreamResetCode) {
	streams := func() []*socketPlatformStream {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		streams := []*socketPlatformStream{}
		for stream, owner := range self.streams {
			if client == nil || owner == client {
				streams = append(streams, stream)
			}
		}
		return streams
	}()
	for _, stream := range streams {
		stream.Reset(code)
	}
}

// The next admitted conn, of any client, or net.ErrClosed once the listener closed, or ctx's error.
func (self *SocketPlatformListener) AcceptSocket(ctx context.Context) (*SocketConn, error) {
	select {
	case conn := <-self.accepted:
		return conn, nil
	default:
	}
	select {
	case conn := <-self.accepted:
		return conn, nil
	case <-self.closed:
		return nil, &net.OpError{Op: "accept", Net: "ur", Err: net.ErrClosed}
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// §9.9's SetServing on every client: false keeps the leases and takes no tickets (§9.5).
func (self *SocketPlatformListener) SetServing(serving bool) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.serving = serving
	}()
	for _, client := range self.clients {
		if client.registration != nil {
			client.registration.setServing(serving)
		}
	}
}

// How many streams are in flight across the clients.
func (self *SocketPlatformListener) InflightCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.streams)
}

// Unlistens every client at once (§9.9): accepted conns stay, admitted ones never taken are reset, a pending
// AcceptSocket answers net.ErrClosed, and the registrars end, so the leases lapse. A second Close does nothing.
func (self *SocketPlatformListener) Close() error {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closing {
			return false
		}
		self.closing = true
		return true
	}()
	if !first {
		return nil
	}
	for _, client := range self.clients {
		if client.registration != nil {
			client.registration.remove()
		}
		if client.remove != nil {
			client.remove()
		}
	}
	close(self.closed)
	for _, client := range self.clients {
		client.registrar.close()
	}
	self.cancel()
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

// §9.9's Drain on every client: nil once in flight reached zero or ListenDrainTimeout ran out, ctx's error when it ended
// first; the listener is closed either way.
func (self *SocketPlatformListener) Drain(ctx context.Context) error {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.draining = true
	}()
	for _, client := range self.clients {
		if client.registration != nil {
			client.registration.setDraining(true)
		}
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
	self.resetStreams(nil, protocol.StreamResetCode_RST_DRAINING)
	self.Close()
	return drainErr
}

// One admitted stream, counted in flight until it ends.
type socketPlatformStream struct {
	listener   *SocketPlatformListener
	stream     socketStream
	stopExpiry func() bool
	endOnce    sync.Once
}

var _ socketStream = (*socketPlatformStream)(nil)

// Takes the stream out of its listener's count, once.
func (self *socketPlatformStream) end() {
	self.endOnce.Do(func() {
		if self.stopExpiry != nil {
			self.stopExpiry()
		}
		self.listener.untrack(self)
	})
}

// Ends the count when err says the stream is gone.
func (self *socketPlatformStream) observe(err error) {
	var resetErr *socketStreamResetError
	if errors.As(err, &resetErr) || errors.Is(err, net.ErrClosed) {
		self.end()
	}
}

// See socketStream.
func (self *socketPlatformStream) Read(b []byte) (int, error) {
	n, err := self.stream.Read(b)
	if err != nil {
		self.observe(err)
	}
	return n, err
}

// See socketStream.
func (self *socketPlatformStream) Write(b []byte) (int, error) {
	n, err := self.stream.Write(b)
	if err != nil {
		self.observe(err)
	}
	return n, err
}

// See socketStream.
func (self *socketPlatformStream) CloseWrite() error {
	return self.stream.CloseWrite()
}

// See socketStream. The stream leaves the count.
func (self *socketPlatformStream) Close() error {
	defer self.end()
	return self.stream.Close()
}

// See socketStream. The stream leaves the count.
func (self *socketPlatformStream) Reset(code protocol.StreamResetCode) error {
	defer self.end()
	return self.stream.Reset(code)
}

// See socketStream.
func (self *socketPlatformStream) SetReadDeadline(t time.Time) error {
	return self.stream.SetReadDeadline(t)
}

// See socketStream.
func (self *socketPlatformStream) SetWriteDeadline(t time.Time) error {
	return self.stream.SetWriteDeadline(t)
}

// POST /socket/registrations on clientId's own token, the answer read as SidecarApi.SocketRegistrations reads it: a
// page's refusal is a 200 whose body holds error, an answer that refuses nothing carries one status per entry, and any
// other status is a *SidecarApiError carrying Retry-After's wait. Nothing here logs or wraps a name or the url (I-13).
func newSocketPlatformRegistrations(args *SocketPlatformRegistrationsArgs, settings *SocketPlatformListenSettings, clientId Id) (socketRegistrationsFunction, error) {
	if args == nil || args.SocketsUrl == "" || args.Bearer == nil || args.Transport == nil {
		return nil, fmt.Errorf("%w: a platform listener's registrations need the sockets url, a transport and a bearer", errInvalidSettings)
	}
	if err := checkServiceUrl("SocketsUrl", args.SocketsUrl, "http", "https"); err != nil {
		return nil, err
	}
	client := &http.Client{
		Transport: args.Transport,
		CheckRedirect: func(redirect *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	url := args.SocketsUrl + "/socket/registrations"
	return func(ctx context.Context, registrationsArgs *SocketRegistrationsArgs) (*SocketRegistrationsResult, error) {
		token, err := args.Bearer(ctx, clientId)
		if err != nil || token == "" {
			return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiNoToken)
		}
		body, err := json.Marshal(registrationsArgs)
		if err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiArgs)
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiArgs)
		}
		request.Header.Set("Accept", "application/json")
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+token)
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("sidecar api %s: the call failed", socketRegistrationsRoute)
		}
		defer response.Body.Close()
		answer, err := io.ReadAll(io.LimitReader(response.Body, settings.RegistrationsMaxAnswerByteCount+1))
		if err != nil || settings.RegistrationsMaxAnswerByteCount < int64(len(answer)) {
			return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiReply)
		}
		if response.StatusCode != http.StatusOK {
			apiErr := &SidecarApiError{Route: socketRegistrationsRoute, Status: response.StatusCode}
			if seconds, err := strconv.ParseUint(response.Header.Get("Retry-After"), 10, 32); err == nil {
				apiErr.RetryAfterMs = clampRetryAfterMs(float64(seconds) * 1000)
			}
			return nil, apiErr
		}
		result := &SocketRegistrationsResult{}
		if err := json.Unmarshal(answer, result); err != nil {
			return nil, fmt.Errorf("sidecar api %s: %w", socketRegistrationsRoute, ErrSidecarApiReply)
		}
		if result.Error == nil && len(result.Statuses) != len(registrationsArgs.Registrations) {
			return nil, fmt.Errorf("sidecar api %s: %w: %d statuses for %d entries", socketRegistrationsRoute, ErrSidecarApiReply,
				len(result.Statuses), len(registrationsArgs.Registrations))
		}
		return result, nil
	}, nil
}
