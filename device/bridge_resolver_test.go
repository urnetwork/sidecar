// `ur tun`'s resolver (bridge_resolver.go), §22.7's private names: a name of the table gets A or NODATA for every query
// type, over UDP and over stateless TCP, with no query reaching the upstream; any other name passes to the upstream and
// its answer comes back, the queue dropping past its bound; malformed queries; a state swap at once; Route handing a
// block's <block>.0.53 port 53 to the resolver; and FuzzBridgeResolver.

package device_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"

	"github.com/urnetwork/sidecar/device"
)

const (
	resolverTestAsker    = "100.80.1.2"
	resolverTestResolver = "100.80.0.53"
)

// A query message for name of qtype, recursion desired.
func resolverTestQuery(id uint16, name string, qtype uint16) []byte {
	message := make([]byte, 12)
	binary.BigEndian.PutUint16(message[0:2], id)
	binary.BigEndian.PutUint16(message[2:4], 0x0100)
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(name, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return message
}

// An IPv4 packet from the asker to the resolver, carrying transport.
func resolverTestPacket(protocolNumber byte, transport []byte) []byte {
	return routeTestPacket(protocolNumber, resolverTestAsker, resolverTestResolver, transport)
}

// A UDP datagram from sourcePort to port 53 carrying message.
func resolverTestUdp(sourcePort uint16, message []byte) []byte {
	transport := make([]byte, 8+len(message))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], 53)
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], message)
	return resolverTestPacket(17, transport)
}

// A TCP segment from sourcePort to port 53.
func resolverTestTcp(sourcePort uint16, seq uint32, ack uint32, flags byte, payload []byte) []byte {
	transport := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], 53)
	binary.BigEndian.PutUint32(transport[4:8], seq)
	binary.BigEndian.PutUint32(transport[8:12], ack)
	transport[12] = 0x50
	transport[13] = flags
	copy(transport[20:], payload)
	return resolverTestPacket(6, transport)
}

// A query framed for TCP: its length, then itself.
func resolverTestFramed(message []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(message))), message...)
}

// One answer read off its packet.
type resolverTestAnswer struct {
	id        uint16
	flags     uint16
	addresses []netip.Addr
}

// Reads a DNS response: its id, flags and each A record's address.
func resolverTestReadAnswer(t testing.TB, message []byte) resolverTestAnswer {
	t.Helper()
	if len(message) < 12 {
		t.Fatalf("a response of %d bytes", len(message))
	}
	answer := resolverTestAnswer{
		id:    binary.BigEndian.Uint16(message[0:2]),
		flags: binary.BigEndian.Uint16(message[2:4]),
	}
	at := 12
	if binary.BigEndian.Uint16(message[4:6]) == 1 {
		for message[at] != 0 {
			at += 1 + int(message[at])
		}
		at += 5
	}
	for range binary.BigEndian.Uint16(message[6:8]) {
		recordType := binary.BigEndian.Uint16(message[at+2 : at+4])
		dataByteCount := int(binary.BigEndian.Uint16(message[at+10 : at+12]))
		if recordType != 1 || dataByteCount != 4 {
			t.Fatalf("a record of type %d and %d bytes", recordType, dataByteCount)
		}
		answer.addresses = append(answer.addresses, netip.AddrFrom4([4]byte(message[at+12:at+16])))
		at += 12 + dataByteCount
	}
	return answer
}

// A resolver on zoneTestZone, keeping copies of what it writes, with an upstream counting what reaches it.
type resolverTest struct {
	t        *testing.T
	resolver *device.BridgeResolverClient
	zone     atomic.Pointer[device.BridgeZone]
	written  chan []byte

	stateLock sync.Mutex
	upstream  [][]byte
	// answers the upstream with, nil for its error; waits while held
	upstreamAnswer func(query []byte) []byte
	upstreamHold   chan struct{}
	upstreamTaken  chan struct{}
}

// A resolver test, settings adjusted by edit; an upstream only if withUpstream.
func newResolverTest(t *testing.T, withUpstream bool, edit func(settings *device.BridgeSettings)) *resolverTest {
	t.Helper()
	self := &resolverTest{t: t, written: make(chan []byte, 256), upstreamTaken: make(chan struct{}, 64)}
	self.zone.Store(zoneTestZone())
	settings := device.DefaultBridgeSettings()
	if withUpstream {
		settings.ResolverUpstream = self.upstreamQuery
	}
	if edit != nil {
		edit(settings)
	}
	self.resolver = device.NewBridgeResolverClient(context.Background(), self.zone.Load, func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, packet []byte) {
		self.written <- bytes.Clone(packet)
	}, settings)
	t.Cleanup(self.resolver.Close)
	return self
}

// The upstream: records the query, waits while held, and answers it with the response upstreamAnswer gives.
func (self *resolverTest) upstreamQuery(ctx context.Context, query []byte) ([]byte, error) {
	self.stateLock.Lock()
	self.upstream = append(self.upstream, bytes.Clone(query))
	hold, answer := self.upstreamHold, self.upstreamAnswer
	self.stateLock.Unlock()
	self.upstreamTaken <- struct{}{}
	if hold != nil {
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if answer == nil {
		return nil, errors.New("no upstream answer")
	}
	return answer(query), nil
}

// Holds the upstream on hold, nil for none, and has it answer with answer, nil for an error.
func (self *resolverTest) setUpstream(hold chan struct{}, answer func(query []byte) []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.upstreamHold = hold
	self.upstreamAnswer = answer
}

// The queries that reached the upstream.
func (self *resolverTest) upstreamQueries() [][]byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([][]byte(nil), self.upstream...)
}

// Hands packet to the resolver.
func (self *resolverTest) send(packet []byte) {
	self.resolver.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, packet, time.Second)
}

// The next packet the resolver wrote.
func (self *resolverTest) next() []byte {
	self.t.Helper()
	select {
	case packet := <-self.written:
		return packet
	case <-time.After(time.Minute):
		self.t.Fatal("the resolver wrote nothing")
		return nil
	}
}

// That nothing more was written.
func (self *resolverTest) nothingMore() {
	self.t.Helper()
	select {
	case packet := <-self.written:
		self.t.Fatalf("the resolver wrote %x", packet)
	default:
	}
}

// Checks a reply packet goes from the resolver back to the asker, and returns its transport.
func resolverTestReply(t testing.TB, packet []byte, protocolNumber byte) []byte {
	t.Helper()
	if packet[9] != protocolNumber || netip.AddrFrom4([4]byte(packet[12:16])) != netip.MustParseAddr(resolverTestResolver) ||
		netip.AddrFrom4([4]byte(packet[16:20])) != netip.MustParseAddr(resolverTestAsker) {
		t.Fatalf("reply %x is not from the resolver to the asker", packet)
	}
	return packet[20:]
}

// A name of the table gets its A record, and NODATA for AAAA, HTTPS, MX and TXT, over UDP, with no query upstream.
func TestBridgeResolverAnswersPrivateNamesOverUdp(t *testing.T) {
	test := newResolverTest(t, true, nil)
	for i, qtype := range []uint16{1, 28, 65, 15, 16} {
		id := uint16(0x1000 + i)
		test.send(resolverTestUdp(40000, resolverTestQuery(id, "Laptop.acme.ur.example", qtype)))
		transport := resolverTestReply(t, test.next(), 17)
		if binary.BigEndian.Uint16(transport[2:4]) != 40000 || binary.BigEndian.Uint16(transport[0:2]) != 53 {
			t.Fatalf("reply ports %x", transport[:4])
		}
		answer := resolverTestReadAnswer(t, transport[8:])
		if answer.id != id || answer.flags&0x8000 == 0 || answer.flags&0x0400 == 0 || answer.flags&0x000F != 0 {
			t.Fatalf("type %d: id %x, flags %x", qtype, answer.id, answer.flags)
		}
		wantCount := 0
		if qtype == 1 {
			wantCount = 1
		}
		if len(answer.addresses) != wantCount || (wantCount == 1 && answer.addresses[0] != netip.MustParseAddr("100.80.1.4")) {
			t.Fatalf("type %d answered %v", qtype, answer.addresses)
		}
	}
	if queries := test.upstreamQueries(); len(queries) != 0 {
		t.Fatalf("%d queries reached the upstream", len(queries))
	}
}

// Over TCP with no state kept: a SYN gets a SYN-ACK, the query acknowledging it gets the answer and a FIN, a FIN gets
// its ACK, and a segment that acknowledges no SYN-ACK of the resolver's gets a reset; nothing reaches the upstream.
func TestBridgeResolverAnswersPrivateNamesOverTcp(t *testing.T) {
	test := newResolverTest(t, true, nil)
	test.send(resolverTestTcp(40001, 1000, 0, 0x02, nil))
	synAck := resolverTestReply(t, test.next(), 6)
	if synAck[13] != 0x12 || binary.BigEndian.Uint32(synAck[8:12]) != 1001 {
		t.Fatalf("SYN-ACK flags %x, ack %d", synAck[13], binary.BigEndian.Uint32(synAck[8:12]))
	}
	isn := binary.BigEndian.Uint32(synAck[4:8])
	for _, qtype := range []uint16{1, 28} {
		query := resolverTestFramed(resolverTestQuery(7, "laptop.acme.ur.example", qtype))
		test.send(resolverTestTcp(40001, 1001, isn+1, 0x18, query))
		segment := resolverTestReply(t, test.next(), 6)
		if segment[13]&0x11 != 0x11 || binary.BigEndian.Uint32(segment[4:8]) != isn+1 ||
			binary.BigEndian.Uint32(segment[8:12]) != 1001+uint32(len(query)) {
			t.Fatalf("answer segment flags %x, seq %d, ack %d", segment[13], binary.BigEndian.Uint32(segment[4:8]), binary.BigEndian.Uint32(segment[8:12]))
		}
		payload := segment[20:]
		if int(binary.BigEndian.Uint16(payload[:2])) != len(payload)-2 {
			t.Fatalf("a framed answer of %d bytes in %d", binary.BigEndian.Uint16(payload[:2]), len(payload)-2)
		}
		answer := resolverTestReadAnswer(t, payload[2:])
		if (qtype == 1) != (len(answer.addresses) == 1) {
			t.Fatalf("type %d over TCP answered %v", qtype, answer.addresses)
		}
	}
	test.send(resolverTestTcp(40001, 2000, isn+50, 0x11, nil))
	if ack := resolverTestReply(t, test.next(), 6); ack[13] != 0x10 || binary.BigEndian.Uint32(ack[8:12]) != 2001 {
		t.Fatalf("FIN's ACK flags %x, ack %d", ack[13], binary.BigEndian.Uint32(ack[8:12]))
	}
	test.send(resolverTestTcp(40001, 1001, isn+7, 0x18, resolverTestFramed(resolverTestQuery(8, "laptop.acme.ur.example", 1))))
	if reset := resolverTestReply(t, test.next(), 6); reset[13]&0x04 == 0 {
		t.Fatalf("a segment acknowledging no SYN-ACK got flags %x", reset[13])
	}
	test.send(resolverTestTcp(40001, 1001, isn+1, 0x18, resolverTestFramed(resolverTestQuery(9, "laptop.acme.ur.example", 1))[:10]))
	if reset := resolverTestReply(t, test.next(), 6); reset[13]&0x04 == 0 {
		t.Fatalf("a split query got flags %x", reset[13])
	}
	if queries := test.upstreamQueries(); len(queries) != 0 {
		t.Fatalf("%d queries reached the upstream", len(queries))
	}
}

// A name the zone does not own goes to the upstream as asked, and its answer comes back; with none, a server failure.
func TestBridgeResolverPassesOtherNamesThrough(t *testing.T) {
	test := newResolverTest(t, true, nil)
	test.setUpstream(nil, func(query []byte) []byte {
		response := bytes.Clone(query)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		return response
	})
	query := resolverTestQuery(0x2222, "app.acme.ur.example", 1)
	test.send(resolverTestUdp(40002, query))
	answer := resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:])
	if answer.id != 0x2222 || answer.flags != 0x8180 {
		t.Fatalf("relayed id %x, flags %x", answer.id, answer.flags)
	}
	if queries := test.upstreamQueries(); len(queries) != 1 || !bytes.Equal(queries[0], query) {
		t.Fatalf("the upstream got %x", queries)
	}

	none := newResolverTest(t, false, nil)
	none.send(resolverTestUdp(40002, resolverTestQuery(0x3333, "public.example", 1)))
	if answer := resolverTestReadAnswer(t, resolverTestReply(t, none.next(), 17)[8:]); answer.flags&0x000F != 2 {
		t.Fatalf("with no upstream, flags %x", answer.flags)
	}
}

// Past ResolverQueueCount the pass-through drops a query, counting it, and answers the ones it kept.
func TestBridgeResolverQueueDropsOnOverflow(t *testing.T) {
	test := newResolverTest(t, true, func(settings *device.BridgeSettings) {
		settings.ResolverQueueCount = 2
		settings.ResolverWorkerCount = 1
	})
	hold := make(chan struct{})
	test.setUpstream(hold, func(query []byte) []byte {
		response := bytes.Clone(query)
		binary.BigEndian.PutUint16(response[2:4], 0x8180)
		return response
	})
	test.send(resolverTestUdp(40003, resolverTestQuery(1, "one.example", 1)))
	<-test.upstreamTaken
	for id := uint16(2); id <= 4; id += 1 {
		test.send(resolverTestUdp(40003, resolverTestQuery(id, "more.example", 1)))
	}
	if _, _, droppedCount := test.resolver.Counts(); droppedCount != 1 {
		t.Fatalf("%d dropped, want 1", droppedCount)
	}
	close(hold)
	ids := map[uint16]bool{}
	for range 3 {
		ids[resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:]).id] = true
	}
	if !ids[1] || !ids[2] || !ids[3] || ids[4] {
		t.Fatalf("answered %v", ids)
	}
}

// A response sent to the resolver is dropped unanswered; a query with two questions gets a format error.
func TestBridgeResolverRefusesMalformedQueries(t *testing.T) {
	test := newResolverTest(t, true, nil)
	response := resolverTestQuery(5, "laptop.acme.ur.example", 1)
	binary.BigEndian.PutUint16(response[2:4], 0x8000)
	test.send(resolverTestUdp(40004, response))
	twoQuestions := resolverTestQuery(6, "laptop.acme.ur.example", 1)
	binary.BigEndian.PutUint16(twoQuestions[4:6], 2)
	test.send(resolverTestUdp(40004, twoQuestions))
	answer := resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:])
	if answer.id != 6 || answer.flags&0x000F != 1 {
		t.Fatalf("id %x, flags %x", answer.id, answer.flags)
	}
	test.nothingMore()
	if queries := test.upstreamQueries(); len(queries) != 0 {
		t.Fatalf("%d malformed queries reached the upstream", len(queries))
	}
}

// A new zone answers the next query at once.
func TestBridgeResolverStateSwapTakesEffectAtOnce(t *testing.T) {
	test := newResolverTest(t, true, nil)
	test.send(resolverTestUdp(40005, resolverTestQuery(1, "laptop.acme.ur.example", 1)))
	if answer := resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:]); answer.addresses[0] != netip.MustParseAddr("100.80.1.4") {
		t.Fatalf("answered %v", answer.addresses)
	}
	test.zone.Store(device.NewBridgeZone(map[string]uint32{"laptop": zoneTestAddress("100.80.3.3")}, []string{"acme.ur.example"}, nil))
	test.send(resolverTestUdp(40005, resolverTestQuery(2, "laptop.acme.ur.example", 1)))
	if answer := resolverTestReadAnswer(t, resolverTestReply(t, test.next(), 17)[8:]); answer.addresses[0] != netip.MustParseAddr("100.80.3.3") {
		t.Fatalf("after the swap answered %v", answer.addresses)
	}
}

// Route hands UDP and TCP to <block>.0.53 port 53 to the resolver, and only those.
func TestBridgeRouteHandsQueriesToTheResolver(t *testing.T) {
	test := newRouteTest(t, routeTestFixture(), nil)
	query := resolverTestUdp(40006, resolverTestQuery(1, "laptop.acme.ur.example", 1))
	resolver, ok := test.bridge.Route(query).(*device.BridgeResolverClient)
	if !ok {
		t.Fatalf("a query routed to %T", test.bridge.Route(query))
	}
	if _, ok := test.bridge.Route(resolverTestTcp(40006, 1, 0, 0x02, nil)).(*device.BridgeResolverClient); !ok {
		t.Fatal("a TCP query was not handed to the resolver")
	}
	if _, ok := test.bridge.Route(routeTestUdp(routeTestSource, "100.80.0.53", 54)).(*device.BridgeRejectClient); !ok {
		t.Fatal("another port of the resolver's address was not rejected")
	}
	resolver.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, query, time.Second)
	if received := test.takeReceived(); len(received) != 1 || received[0][9] != 17 {
		t.Fatalf("the resolver wrote %d packets into the tun", len(received))
	}
}

// Any packet, total: no panic, and what comes out is bounded by what went in.
func FuzzBridgeResolver(f *testing.F) {
	f.Add(resolverTestUdp(40000, resolverTestQuery(1, "laptop.acme.ur.example", 1)))
	f.Add(resolverTestUdp(40000, resolverTestQuery(2, "public.example", 28)))
	f.Add(resolverTestTcp(40000, 1, 0, 0x02, nil))
	f.Add(resolverTestTcp(40000, 1, 2, 0x18, resolverTestFramed(resolverTestQuery(3, "laptop.acme.ur.example", 1))))
	f.Add([]byte{0x45, 0, 0, 20})
	f.Fuzz(func(t *testing.T, packet []byte) {
		writeCount := 0
		writtenByteCount := 0
		resolver := device.NewBridgeResolverClient(context.Background(), func() *device.BridgeZone { return zoneTestZone() },
			func(source connect.TransferPath, provideMode protocol.ProvideMode, ipPath *connect.IpPath, reply []byte) {
				writeCount += 1
				writtenByteCount += len(reply)
			}, nil)
		defer resolver.Close()
		resolver.SendPacket(connect.TransferPath{}, protocol.ProvideMode_Network, bytes.Clone(packet), time.Second)
		if 2+len(packet)/536 < writeCount || 64+2*len(packet) < writtenByteCount {
			t.Fatalf("%d bytes in, %d packets and %d bytes out", len(packet), writeCount, writtenByteCount)
		}
	})
}
