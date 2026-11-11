//go:build !sidecar_http && !ios_extension

// SocketEdgeDialer: the Find and open §13.5 and §15.4 share (R-SOCK-3, D-SOCK-6, D-SOCK-12, C9, X1, X6), so tlsedge and
// mxedge each write only their own front. An edge process holds K platform clients in urnetwork-edge, each with its §6
// dispatcher in the edge role. A Find sends their K ids, and the service names one of them in each ticket as its dialer,
// ids[h(listener_client_id) mod K], so a listener's edge streams share one client (§9.6's edge Finds). The stream opens
// from that client, with StreamOpen{target, metadata, ticket, early_data}: the caller's metadata for the ticket's grant
// expiry, such as TlsEdgeOpen, and its first bytes, the first 2,048 riding the open and the rest StreamData at once,
// before the accept. Edges send no Hello and carry no binding (§6.4): the listener admits on the ticket alone, and its
// own evaluation of its config decides (§9.6's steps 3 and 6). TLS never ends here (X1, X6).
//
// The limits are tlsedge.yml's: each Find bounded by FindTimeout (2 s), at most FindCount Finds (3), AcceptTimeout (5 s)
// a ticket. A ticket naming a client this process does not hold, or another network or name, is refused unopened.
// Only an accept timeout is reported as a failed ticket, never a listener's refusal and never the visitor's own reset
// or departure, which ends the dial with the caller's ctx and reports nothing (§9.6: edges report only accept
// timeouts). retry, busy and invalid try the next ticket; denied and quota stop. The name-to-network map, the negative
// cache and the kill switch stay with the caller (§13.5).
//
// Nothing here logs a name or a visitor (I-13). Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar/protocol"
)

// tlsedge.yml's dial limits (§13.5, §19).
type SocketEdgeDialSettings struct {
	// The most one Find may take: 2 s.
	FindTimeout time.Duration
	// The most Finds one dial sends, the first included: 3.
	FindCount int
	// How long each ticket's open waits for its listener's accept: 5 s, after which the backup is tried.
	AcceptTimeout time.Duration
}

// §13.5's values, the only source of their defaults.
func DefaultSocketEdgeDialSettings() *SocketEdgeDialSettings {
	return &SocketEdgeDialSettings{
		FindTimeout:   2 * time.Second,
		FindCount:     3,
		AcceptTimeout: 5 * time.Second,
	}
}

// One of the process's K platform clients in urnetwork-edge.
type SocketEdgeClient struct {
	ClientId Id
	// Its dispatcher, in SubprotocolRoleEdge.
	Subprotocol *Subprotocol
}

// What NewSocketEdgeDialer takes.
type SocketEdgeDialerArgs struct {
	// The process's K clients: every Find names them all, and a ticket names one.
	Clients []*SocketEdgeClient
	// How Find reaches the sockets service on the process's own client token.
	Find *SocketFindHttpArgs
	// Nil is DefaultSocketEdgeDialSettings.
	Settings *SocketEdgeDialSettings
	// Nil is real time.
	Clock Clock
}

// One connection's dial.
type SocketEdgeDialRequest struct {
	// The network the visitor's name mapped to, and its 10-character label, which the stream target names.
	NetworkId    Id
	NetworkLabel string
	// tls/<port>/<host> or smtp/25/<host>.
	Name string
	// §9.7's filter: "tls" or "smtp-starttls", and the visitor's offered ALPN ids. The service applies them once
	// sock-2 names them (plan-SOCK-metadata-rows).
	Protocol string
	Alpns    []string
	// §9.7's affinity key, a keyed hash of the visitor's /24 or /48.
	AffinityKey []byte
	// StreamOpen.metadata for a ticket whose grant ends at grantExpireTimeMillis, such as TlsEdgeOpen, whose
	// expire_time_millis is that time (§13.5). Called once for each ticket tried.
	Metadata func(grantExpireTimeMillis uint64) ([]byte, error)
	// The first bytes, such as the ClientHello.
	EarlyData []byte
}

// One edge stream to a listener. Close sends StreamClose and stops reading, CloseWrite sends StreamClose alone, and
// Reset sends StreamReset with its code, so a spent lease resets with RST_QUOTA (§13.6). Safe for concurrent use, as a
// net.Conn is.
type SocketEdgeStream struct {
	stream   socketStream
	ticket   *protocol.SocketTicket
	clientId Id
}

// See io.Reader.
func (self *SocketEdgeStream) Read(b []byte) (int, error) {
	return self.stream.Read(b)
}

// See io.Writer.
func (self *SocketEdgeStream) Write(b []byte) (int, error) {
	return self.stream.Write(b)
}

// StreamClose of this direction; reads go on.
func (self *SocketEdgeStream) CloseWrite() error {
	return self.stream.CloseWrite()
}

// StreamClose, and this end stops reading.
func (self *SocketEdgeStream) Close() error {
	return self.stream.Close()
}

// StreamReset with code.
func (self *SocketEdgeStream) Reset(code protocol.StreamResetCode) error {
	return self.stream.Reset(code)
}

// See net.Conn.
func (self *SocketEdgeStream) SetReadDeadline(t time.Time) error {
	return self.stream.SetReadDeadline(t)
}

// See net.Conn.
func (self *SocketEdgeStream) SetWriteDeadline(t time.Time) error {
	return self.stream.SetWriteDeadline(t)
}

// A copy of the ticket the stream opened on.
func (self *SocketEdgeStream) Ticket() *protocol.SocketTicket {
	return proto.Clone(self.ticket).(*protocol.SocketTicket)
}

// The process's client the stream opened from, which the ticket named.
func (self *SocketEdgeStream) ClientId() Id {
	return self.clientId
}

// Opens a stream from one of the process's clients: its dispatcher's OpenStream, or a test's pipe.
type socketEdgeOpenFunction func(ctx context.Context, clientId Id, listenerClientId Id, request *StreamOpenRequest) (socketStream, error)

// The edge dialer. NewSocketEdgeDialer makes one.
type SocketEdgeDialer struct {
	settings  *SocketEdgeDialSettings
	clock     Clock
	clientIds []Id
	held      map[Id]bool
	find      *socketFindClient
	open      socketEdgeOpenFunction
}

// A dialer over the process's clients, which needs at least one, each with a dispatcher in the edge role.
func NewSocketEdgeDialer(args *SocketEdgeDialerArgs) (*SocketEdgeDialer, error) {
	if args == nil || len(args.Clients) == 0 {
		return nil, fmt.Errorf("%w: an edge dialer needs its clients", errInvalidSettings)
	}
	subprotocols := map[Id]*Subprotocol{}
	clientIds := []Id{}
	for _, client := range args.Clients {
		if client == nil || client.Subprotocol == nil || client.Subprotocol.role != SubprotocolRoleEdge || subprotocols[client.ClientId] != nil {
			return nil, fmt.Errorf("%w: each edge client is distinct, with a dispatcher in the edge role", errInvalidSettings)
		}
		subprotocols[client.ClientId] = client.Subprotocol
		clientIds = append(clientIds, client.ClientId)
	}
	send, err := newSocketFindHttp(args.Find)
	if err != nil {
		return nil, err
	}
	open := func(ctx context.Context, clientId Id, listenerClientId Id, request *StreamOpenRequest) (socketStream, error) {
		stream, err := subprotocols[clientId].OpenStream(ctx, listenerClientId, request)
		if err != nil {
			return nil, err
		}
		return newSubprotocolSocketStream(stream), nil
	}
	return newSocketEdgeDialer(args.Settings, args.Clock, clientIds, newSocketFindClient(send), open)
}

// A dialer on its parts, which a test gives scripted ones.
func newSocketEdgeDialer(settings *SocketEdgeDialSettings, clock Clock, clientIds []Id, find *socketFindClient, open socketEdgeOpenFunction) (*SocketEdgeDialer, error) {
	if settings == nil {
		settings = DefaultSocketEdgeDialSettings()
	}
	if settings.FindTimeout <= 0 || settings.FindCount <= 0 || settings.AcceptTimeout <= 0 {
		return nil, fmt.Errorf("%w: an edge dialer's limits are positive", errInvalidSettings)
	}
	held := map[Id]bool{}
	for _, clientId := range clientIds {
		held[clientId] = true
	}
	return &SocketEdgeDialer{
		settings:  settings,
		clock:     clockOrReal(clock),
		clientIds: append([]Id(nil), clientIds...),
		held:      held,
		find:      find,
		open:      open,
	}, nil
}

// The K client ids every Find sends.
func (self *SocketEdgeDialer) ClientIds() []Id {
	return append([]Id(nil), self.clientIds...)
}

// A context that ends when ctx does or timeout passes on the dialer's clock, and the call that ends it.
func (self *SocketEdgeDialer) boundedContext(ctx context.Context, timeout time.Duration) (context.Context, func()) {
	boundedCtx, cancel := context.WithCancel(ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return boundedCtx, func() {
		stop()
		cancel()
	}
}

// How one edge ticket ended.
type socketEdgeAttempt struct {
	stream *SocketEdgeStream
	// a ticket to report: only an accept timeout
	timedOut bool
	// a refusal that ends the dial
	stop error
}

// One ticket: the checks, then the open from the client it names.
func (self *SocketEdgeDialer) attempt(ctx context.Context, request *SocketEdgeDialRequest, findTicket *SocketFindTicket) *socketEdgeAttempt {
	ticket, err := parseSocketFindTicket(findTicket.Ticket)
	if err != nil {
		return &socketEdgeAttempt{}
	}
	dialerClientId, err := IdFromBytes(ticket.GetDialerClientId())
	if err != nil || !self.held[dialerClientId] || !bytes.Equal(ticket.GetNetworkId(), request.NetworkId.Bytes()) ||
		ticket.GetName() != request.Name {
		return &socketEdgeAttempt{}
	}
	listenerClientId, err := IdFromBytes(ticket.GetListenerClientId())
	if err != nil {
		return &socketEdgeAttempt{}
	}
	var metadata []byte
	if request.Metadata != nil {
		if metadata, err = request.Metadata(ticket.GetGrantExpireTimeMillis()); err != nil {
			return &socketEdgeAttempt{}
		}
	}
	attemptCtx, done := self.boundedContext(ctx, self.settings.AcceptTimeout)
	defer done()
	stream, err := self.open(attemptCtx, dialerClientId, listenerClientId, &StreamOpenRequest{
		Target:    request.NetworkLabel + ":" + request.Name,
		Metadata:  metadata,
		Ticket:    findTicket.Ticket,
		EarlyData: request.EarlyData,
		Edge:      true,
	})
	if err == nil {
		return &socketEdgeAttempt{stream: &SocketEdgeStream{stream: stream, ticket: ticket, clientId: dialerClientId}}
	}
	if ctx.Err() != nil {
		// the visitor left: nothing to report
		return &socketEdgeAttempt{stop: &SocketCodeError{Err: ErrSocketUnavailable}}
	}
	var rejectErr *StreamRejectError
	if errors.As(err, &rejectErr) {
		switch SocketRejectCode(uint32(rejectErr.Code)) {
		case protocol.StreamRejectCode_SR_DENIED:
			return &socketEdgeAttempt{stop: &SocketCodeError{Err: ErrSocketDenied}}
		case protocol.StreamRejectCode_SR_QUOTA:
			return &socketEdgeAttempt{stop: &SocketCodeError{Err: ErrSocketQuota, RetryAfter: rejectErr.RetryAfter}}
		}
		return &socketEdgeAttempt{}
	}
	if attemptCtx.Err() != nil {
		return &socketEdgeAttempt{timedOut: true}
	}
	return &socketEdgeAttempt{}
}

// Finds a listener for request and opens a stream to it, trying each ticket in turn. A refusal is a *SocketCodeError
// around one of §9.9's values, which errors.Is reaches.
func (self *SocketEdgeDialer) Dial(ctx context.Context, request *SocketEdgeDialRequest) (*SocketEdgeStream, error) {
	if request == nil || request.NetworkLabel == "" {
		return nil, fmt.Errorf("%w: an edge dial names its network's label", errSocketRegistrationInvalid)
	}
	if _, namespace, err := ParseSocketName(request.Name); err != nil || (namespace != SocketNamespaceTls && namespace != SocketNamespaceSmtp) {
		return nil, fmt.Errorf("%w: an edge dials tls/ and smtp/ names", errSocketRegistrationInvalid)
	}
	networkId := connect.Id(request.NetworkId)
	clientIds := make([]*connect.Id, 0, len(self.clientIds))
	for _, clientId := range self.clientIds {
		id := connect.Id(clientId)
		clientIds = append(clientIds, &id)
	}
	args := &SocketFindArgs{
		Name:        request.Name,
		NetworkId:   &networkId,
		Protocol:    request.Protocol,
		Alpn:        request.Alpns,
		AffinityKey: request.AffinityKey,
		ClientIds:   clientIds,
	}
	failedTickets := []*SocketFailedTicket{}
	lastErr := error(&SocketCodeError{Err: ErrSocketNoListener})
	for findIndex := 0; findIndex < self.settings.FindCount; findIndex += 1 {
		args.FailedTickets = failedTickets
		answer, err := func() (*socketFindAnswer, error) {
			findCtx, done := self.boundedContext(ctx, self.settings.FindTimeout)
			defer done()
			return self.find.find(findCtx, args)
		}()
		if err != nil {
			return nil, err
		}
		failedTickets = []*SocketFailedTicket{}
		for _, findTicket := range answer.tickets {
			attempt := self.attempt(ctx, request, findTicket)
			switch {
			case attempt.stream != nil:
				return attempt.stream, nil
			case attempt.stop != nil:
				return nil, attempt.stop
			case attempt.timedOut:
				failedTickets = append(failedTickets, &SocketFailedTicket{Ticket: findTicket.Ticket, Reason: SocketFailedReasonTimeout})
			}
		}
		lastErr = &SocketCodeError{Err: ErrSocketNoListener}
	}
	return nil, lastErr
}
