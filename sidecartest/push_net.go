// §6.8's server push on the Net (PROTO-M1-11): residents, the hint state they and the long-poll read,
// and the rule that keeps what ControlId sends to hints.
//
// A client's resident is a connect client of id ControlId on the exchange, as server's resident is
// (server/connect/resident.go): what it sends its client needs no contract and no session, and reaches
// the client over the carrier SetLink gives the pair (connect.ControlId, client), h1 where no link names
// one, while what the client sends ControlId reaches the resident on h1. A receiver reads a frame's
// carrier from the route that read it, never from the frame, so a frame from ControlId over a P2P link
// is exactly what a P2P peer forging ControlId delivers, and over h1 what the platform delivers
// (D-PROTO-8).
//
// The hint state is the Net's FakeRedis, pushservice's scripts registered on it at first use. A
// resident hosts pushservice's own SidecarPublisher there, kicked from one key-event callback on
// {scp_*}n that this file demuxes to each client's publisher, as server's shared subscriber does
// (server/connect/key_event_subscriber.go), and the Net's api holds GET /sidecar/sync/poll on a
// pushservice.LongPoll over the same Redis (fake_api_sync.go). HintWriter writes as an owner does.
//
// A resident stands for the platform, as the contract issuer and the ControlId sink do (net_connect.go),
// so a row using one also runs on T3 against server's residents (Q-TEST-1). Safe for concurrent use.

package sidecartest

import (
	"context"
	"errors"
	"fmt"
	mathrand "math/rand/v2"
	"sync"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/connect"
	connectprotocol "github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/pushservice"
)

var (
	// A resident for a client the exchange does not hold, or a second one for a client that has one.
	errNetResident = errors.New("no resident")
	// A resident's frame that its client did not take, or whose ack never came.
	errNetResidentSend = errors.New("the resident's frame was not acked")
)

// The Net's hint state, made at first use. Safe for concurrent use.
type netPush struct {
	redis    *FakeRedis
	writer   *pushservice.HintWriter
	longPoll *pushservice.LongPoll
	// what takes the one key-event callback off FakeRedis
	removeCallback func()

	stateLock sync.Mutex
	// the running publisher of each client with a resident hosting one, which the callback kicks
	clientIdPublishers map[connect.Id]*pushservice.SidecarPublisher
}

// The shared subscriber's callback: kicks the publisher of the client whose n moved, or every one when
// the subscription came back, since what was published in the gap is gone. Never blocks.
func (self *netPush) keyEvent(event sidecar.RedisKeyEvent) {
	publishers := []*pushservice.SidecarPublisher{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if event.Resync {
			for _, publisher := range self.clientIdPublishers {
				publishers = append(publishers, publisher)
			}
			return
		}
		clientId, ok := pushservice.ParseHintSeqKey(event.Key)
		if !ok {
			return
		}
		if publisher, ok := self.clientIdPublishers[clientId]; ok {
			publishers = append(publishers, publisher)
		}
	}()
	for _, publisher := range publishers {
		publisher.Kick()
	}
}

func (self *netPush) close() {
	self.removeCallback()
	self.longPoll.Close()
}

// The Net's hint state: FakeRedis with pushservice's scripts, one key-event callback on {scp_*}n, and the
// long-poll the api's sync routes hold on, its holds on the Net's clock. Made on first use; Close ends it.
func (self *Net) push() (*netPush, error) {
	self.pushLock.Lock()
	defer self.pushLock.Unlock()
	if self.pushPlane != nil {
		return self.pushPlane, nil
	}
	if self.ctx.Err() != nil {
		return nil, self.ctx.Err()
	}
	redis := self.fakes.Redis
	RegisterPushScripts(redis)
	writer, err := pushservice.NewHintWriter(redis, nil, nil, nil)
	if err != nil {
		return nil, err
	}
	// each poll's lease write reaches the Net's api (http_page.go)
	longPoll, err := pushservice.NewLongPoll(self.ctx, redis, self.clock, nil, self.touchLease)
	if err != nil {
		return nil, err
	}
	plane := &netPush{
		redis:              redis,
		writer:             writer,
		longPoll:           longPoll,
		clientIdPublishers: map[connect.Id]*pushservice.SidecarPublisher{},
	}
	removeCallback, err := redis.AddKeyEventCallback(pushservice.HintSeqKeyPattern, plane.keyEvent)
	if err != nil {
		longPoll.Close()
		return nil, err
	}
	plane.removeCallback = removeCallback
	self.pushPlane = plane
	return plane, nil
}

// Ends the hint state's callback and long-poll, if made. Close runs it before the Redis closes.
func (self *Net) closePush() {
	self.pushLock.Lock()
	plane := self.pushPlane
	self.pushPlane = nil
	self.pushLock.Unlock()
	if plane != nil {
		plane.close()
	}
}

// pushservice's HintWriter on the Net's hint state: what an owner calls to tell clients a topic moved,
// which their residents' publishers and the long-poll carry.
func (self *Net) HintWriter() (*pushservice.HintWriter, error) {
	plane, err := self.push()
	if err != nil {
		return nil, err
	}
	return plane.writer, nil
}

// The topic versions the hint state holds for clientId, {scp_<C>}ver as GET /sidecar/sync/versions
// reads it: what the owners wrote, which a client's applied state is held to.
func (self *Net) HintVersions(ctx context.Context, clientId connect.Id) (map[string]uint64, error) {
	plane, err := self.push()
	if err != nil {
		return nil, err
	}
	fieldValues, err := plane.redis.HashGetAll(ctx, pushservice.HintVersionsKey(clientId))
	if err != nil {
		return nil, err
	}
	return pushservice.ParseHintVersions(fieldValues), nil
}

// One client's resident. Close kills it, as a resident's end does: its publisher stops and its client
// leaves the exchange.
type NetResident struct {
	// The client it serves.
	ClientId connect.Id

	net       *Net
	netClient *NetClient
	cancel    context.CancelFunc
	// frames the client has acked, each Send's, the publisher's among them
	acks *sidecar.MonitorValue[uint64]

	stateLock sync.Mutex
	publisher *pushservice.SidecarPublisher
	closed    bool
}

// Starts clientId's resident on the exchange, a connect client of id ControlId whose frames need no
// contract and no session. A client may have one resident at a time; the next starts once Close has
// run, as a client that reconnects meets a new one.
func (self *Net) AddResident(clientId connect.Id) (*NetResident, error) {
	exchange := self.exchange
	if exchange.client(clientId) == nil {
		return nil, fmt.Errorf("%w: the exchange holds no client %s", errNetResident, clientId)
	}
	ctx, cancel := context.WithCancel(exchange.ctx)
	settings := netClientSettings()
	clientTag := fmt.Sprintf("resident(%s)", clientId)
	client := connect.NewClientWithTag(ctx, connect.ControlId, clientTag, connect.NewNoContractClientOob(), settings)
	// the platform takes no contract to its client, as server's resident does
	client.ContractManager().AddNoContractPeer(clientId)
	resident := &NetResident{
		ClientId: clientId,
		net:      self,
		netClient: &NetClient{
			Name:          clientTag,
			ClientId:      connect.ControlId,
			Client:        client,
			exchange:      exchange,
			ctx:           ctx,
			receiveRoutes: map[connect.TransportType]connect.Route{},
		},
		cancel: cancel,
		acks:   sidecar.NewMonitorValue[uint64](0),
	}
	added := func() bool {
		exchange.stateLock.Lock()
		defer exchange.stateLock.Unlock()
		if _, ok := exchange.residents[clientId]; ok {
			return false
		}
		exchange.residents[clientId] = resident
		return true
	}()
	if !added {
		cancel()
		client.Cancel()
		return nil, fmt.Errorf("%w: %s already has one", errNetResident, clientId)
	}

	sendRoute := make(connect.Route)
	client.RouteManager().UpdateTransport(newNetSendTransport(false), []connect.Route{sendRoute})
	resident.netClient.receiveRoute(connect.TransportTypeH1)
	exchange.workers.Add(2)
	go func() {
		defer exchange.workers.Done()
		exchange.pump(ctx, resident.netClient, sendRoute)
	}()
	go func() {
		defer exchange.workers.Done()
		<-ctx.Done()
		resident.Close()
	}()
	return resident, nil
}

// Sends frame to the client, nil ack for none: the shape of pushservice.PublisherEnv.Send. Takes on
// success: a true return takes the frame's pool buffer, and on false the caller still owns it. Waits up
// to the Net's SendTimeout for the resident's client to take it.
func (self *NetResident) Send(frame *connectprotocol.Frame, ack connect.AckFunction) bool {
	counted := func(err error) {
		if err == nil {
			self.acks.Update(func(count uint64) uint64 {
				return count + 1
			})
		}
		if ack != nil {
			ack(err)
		}
	}
	return self.netClient.Client.SendWithTimeout(frame, self.ClientId, counted, self.net.settings.SendTimeout)
}

// Waits until the client has acked count of this resident's frames in all, a publisher's included, or
// ctx ends. An ack comes once the client's receive callbacks have run, so a frame acked has reached the
// client's dispatcher, which handles a source's frames in order.
func (self *NetResident) AwaitAcked(ctx context.Context, count uint64) error {
	for {
		acked, changed := self.acks.Get()
		if count <= acked {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("%w: %d of %d acked: %w", errNetResidentSend, acked, count, ctx.Err())
		}
	}
}

// Sends frame to the client and waits for its ack, which the client sends once its receive callbacks
// have run (connect's deliver-before-ack), so whatever the client's subprotocol dispatch made of the
// frame, taking it or dropping it, has happened when this returns nil. Takes the frame's pool buffer.
func (self *NetResident) SendAcked(ctx context.Context, frame *connectprotocol.Frame) error {
	acked := make(chan error, 1)
	if !self.Send(frame, func(err error) {
		select {
		case acked <- err:
		default:
		}
	}) {
		connect.MessagePoolReturn(frame.MessageBytes)
		return fmt.Errorf("%w: the resident's client refused it", errNetResidentSend)
	}
	select {
	case err := <-acked:
		if err != nil {
			return errors.Join(errNetResidentSend, err)
		}
		return nil
	case <-ctx.Done():
		return errors.Join(errNetResidentSend, ctx.Err())
	}
}

// Sends one push message, a PushReset or a PushHint, in the frame a resident's publisher sends
// (pushservice.PushFrame), and waits for its ack as SendAcked does.
func (self *NetResident) SendPushAcked(ctx context.Context, messageType protocol.MessageType, message proto.Message) error {
	frame, err := pushservice.PushFrame(messageType, message, mathrand.Uint64())
	if err != nil {
		return err
	}
	return self.SendAcked(ctx, frame)
}

// Starts pushservice's publisher for the client on the Net's hint state, kicked as each of its hints is
// written, until Close. settings nil takes the defaults; its coalescing window and backoff run on clock,
// which a test steps. One publisher a resident.
func (self *NetResident) StartPublisher(settings *pushservice.SidecarPublisherSettings, clock sidecar.Clock) (*pushservice.SidecarPublisher, error) {
	plane, err := self.net.push()
	if err != nil {
		return nil, err
	}
	publisher, err := pushservice.NewSidecarPublisher(settings, clock)
	if err != nil {
		return nil, err
	}
	started := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed || self.publisher != nil {
			return false
		}
		self.publisher = publisher
		return true
	}()
	if !started {
		return nil, fmt.Errorf("%w: the resident is closed or already hosts a publisher", errNetResident)
	}
	// registered first, so a hint written between the reset's reads and the registration still kicks it
	func() {
		plane.stateLock.Lock()
		defer plane.stateLock.Unlock()
		plane.clientIdPublishers[self.ClientId] = publisher
	}()
	publisher.Start(self.netClient.ctx, &pushservice.PublisherEnv{
		ClientId:  self.ClientId,
		NetworkId: connect.NewId(),
		Send:      self.Send,
		Redis:     plane.redis,
		// a sidecar's client: every topic
		Topics: nil,
	})
	return publisher, nil
}

// Kills the resident: its client leaves the exchange, its publisher stops, and frames the client sends
// ControlId go nowhere until another resident starts. The client goes first, so a publisher's send in
// flight is refused at once rather than waiting out its timeout. Safe to call more than once.
func (self *NetResident) Close() {
	publisher := func() *pushservice.SidecarPublisher {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return nil
		}
		self.closed = true
		return self.publisher
	}()
	exchange := self.net.exchange
	func() {
		exchange.stateLock.Lock()
		defer exchange.stateLock.Unlock()
		if exchange.residents[self.ClientId] == self {
			delete(exchange.residents, self.ClientId)
		}
	}()
	self.cancel()
	self.netClient.Client.Cancel()
	if publisher == nil {
		return
	}
	self.net.pushLock.Lock()
	plane := self.net.pushPlane
	self.net.pushLock.Unlock()
	if plane != nil {
		func() {
			plane.stateLock.Lock()
			defer plane.stateLock.Unlock()
			if plane.clientIdPublishers[self.ClientId] == publisher {
				delete(plane.clientIdPublishers, self.ClientId)
			}
		}()
	}
	publisher.Close()
}

// The resident serving clientId, nil for none.
func (self *netExchange) resident(clientId connect.Id) *NetResident {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.residents[clientId]
}

// Why a frame from ControlId to a client holds more than acks and hint fields (R-PROTO-8), or empty when
// it holds no more. A resident's push needs no session and travels in the clear (§6.8's exposure), so
// this is the rule that keeps it to hints: each message it carries in the clear is one PushReset or
// PushHint in a NO_REPLY envelope of id 21842, every field a known one and a hint's bytes within 256.
func controlFrameReason(frame []byte) string {
	transferFrame := &connectprotocol.TransferFrame{}
	if err := proto.Unmarshal(frame, transferFrame); err != nil {
		return fmt.Sprintf("a ControlId frame that does not parse: %v", err)
	}
	if 0 < len(transferFrame.EncryptedTransferFrame) {
		return "a sealed ControlId frame, which no session carries"
	}
	frames := []*connectprotocol.Frame{}
	if transferFrame.Frame != nil {
		frames = append(frames, transferFrame.Frame)
	}
	if transferFrame.Pack != nil {
		frames = append(frames, transferFrame.Pack.Frames...)
		if transferFrame.Pack.ContractFrame != nil {
			return "a ControlId pack with a contract, which the platform's frames need none of"
		}
	}
	for _, frame := range frames {
		if reason := pushFrameReason(frame); reason != "" {
			return reason
		}
	}
	return ""
}

// Why one frame from ControlId is more than a push message's hint fields, or empty.
func pushFrameReason(frame *connectprotocol.Frame) string {
	if frame.MessageType != connectprotocol.MessageType_Subprotocol {
		return fmt.Sprintf("a ControlId %s frame", frame.MessageType)
	}
	wrapper := &connectprotocol.SubprotocolMessage{}
	if err := proto.Unmarshal(frame.MessageBytes, wrapper); err != nil {
		return fmt.Sprintf("a ControlId subprotocol frame that does not parse: %v", err)
	}
	if wrapper.SubprotocolId != sidecar.SubprotocolId {
		return fmt.Sprintf("a ControlId frame of subprotocol %d", wrapper.SubprotocolId)
	}
	envelope := &protocol.Envelope{}
	if err := proto.Unmarshal(wrapper.MessageBytes, envelope); err != nil {
		return fmt.Sprintf("a ControlId envelope that does not parse: %v", err)
	}
	if envelope.Flags != sidecar.EnvelopeFlagNoReply || envelope.Chunk != nil {
		return fmt.Sprintf("a ControlId envelope of flags %d, chunked %t", envelope.Flags, envelope.Chunk != nil)
	}
	var message proto.Message
	switch protocol.MessageType(envelope.Type) {
	case protocol.MessageType_PUSH_RESET:
		message = &protocol.PushReset{}
	case protocol.MessageType_PUSH_HINT:
		message = &protocol.PushHint{}
	default:
		return fmt.Sprintf("a ControlId envelope of type %#04x", envelope.Type)
	}
	if err := proto.Unmarshal(envelope.Body, message); err != nil {
		return fmt.Sprintf("a ControlId push body that does not parse: %v", err)
	}
	if unknownFields(envelope.ProtoReflect()) || unknownFields(message.ProtoReflect()) {
		return "a ControlId push carrying fields no hint has"
	}
	if hint, ok := message.(*protocol.PushHint); ok && pushservice.MaxHintByteCount < len(hint.Hint) {
		return fmt.Sprintf("a ControlId hint of %d bytes, past %d", len(hint.Hint), pushservice.MaxHintByteCount)
	}
	return ""
}

// Whether message, or a message it holds, carries bytes of a field its descriptor does not name.
func unknownFields(message protoreflect.Message) bool {
	if 0 < len(message.GetUnknown()) {
		return true
	}
	found := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList() && field.Message() != nil:
			list := value.List()
			for i := range list.Len() {
				if unknownFields(list.Get(i).Message()) {
					found = true
				}
			}
		case !field.IsList() && !field.IsMap() && field.Message() != nil:
			found = unknownFields(value.Message())
		}
		return !found
	})
	return found
}
