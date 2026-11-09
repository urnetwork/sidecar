// §17.10's per-link resolver for `ur tun`, which has no UpgradeMux to carry C14's zone (§12.9): Route hands it UDP and
// TCP to a block's <block>.0.53 port 53, and it answers as a connect.UserNatClient, writing replies into the tun through
// receive:
//
//	owned      a name of the zone gets its A record, and NODATA for every other query type and class, so no query
//	           for a name of the table leaves the device
//	pass       any other name goes to the host's system resolver (ResolverUpstream) off the packet path, through a
//	           queue of ResolverQueueCount that drops and counts on overflow, since a published app.<net>.<root> must
//	           still resolve (§12.9's pass-through); with no upstream, or a failed one, a server failure
//	malformed  a query whose header reads gets a format error; anything else is dropped
//	tcp        stateless: a SYN gets a SYN-ACK whose sequence is a keyed hash of the connection, a segment carrying one
//	           whole query and acknowledging that hash gets the answer with a FIN, a FIN alone gets its ACK, and a
//	           query split across segments gets a reset, so the asker retries
//
// It keeps no name past a query and logs none (I-13). It decodes DNS itself, since this package imports nothing past
// connect, protocol/bridge, std and protobuf. Safe for concurrent use; Close stops its upstream workers.

package device

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
)

// Sends one DNS query, as its message's bytes, to the host's system resolver and returns its response's bytes: never to
// this bridge's own <block>.0.53, which would loop. Called off the packet path, on a worker of the resolver, until ctx
// ends.
type BridgeResolverUpstream func(ctx context.Context, query []byte) ([]byte, error)

// DNS's numbers (RFC 1035) that the resolver reads and writes.
const (
	bridgeDnsHeaderByteCount = 12
	bridgeDnsTypeA           = 1
	bridgeDnsTypeAny         = 255
	bridgeDnsClassIn         = 1
	bridgeDnsLabelMaxCount   = 63
	bridgeDnsFlagResponse    = 0x8000
	bridgeDnsFlagAuthority   = 0x0400
	bridgeDnsFlagRecursion   = 0x0100
	bridgeDnsFlagAvailable   = 0x0080
	bridgeDnsCodeFormat      = 1
	bridgeDnsCodeServer      = 2
	// a TCP message's length prefix
	bridgeDnsTcpPrefixByteCount = 2
	// the most one reply datagram's DNS message may take under an IPv4 header and UDP's
	bridgeDnsUdpMaxByteCount = 65535 - bridgeIpv4HeaderByteCount - 8
)

// TCP's numbers the resolver reads and writes.
const (
	bridgeTcpHeaderByteCount = 20
	bridgeTcpFlagFin         = 0x01
	bridgeTcpFlagSyn         = 0x02
	bridgeTcpFlagRst         = 0x04
	bridgeTcpFlagPsh         = 0x08
	bridgeTcpFlagAck         = 0x10
	bridgeTcpWindow          = 65535
	// the most an answer's segment carries: the MSS a peer that names none takes (RFC 9293 §3.7.1), since a
	// stateless resolver keeps no MSS the SYN named
	bridgeTcpSegmentByteCount = 536
)

// One query read off its packet.
type bridgeDnsQuery struct {
	id               uint16
	recursionDesired bool
	// the question as asked: its labels, type and class
	question []byte
	// the name, lowercase, its labels joined by dots, with no trailing dot
	name   string
	qtype  uint16
	qclass uint16
}

// Where an answer goes: the query's addresses and ports, which it swaps, and over TCP the sequence numbers it carries.
type bridgeResolverReply struct {
	provideMode     protocol.ProvideMode
	tcp             bool
	source          netip.Addr
	destination     netip.Addr
	sourcePort      uint16
	destinationPort uint16
	seq             uint32
	ack             uint32
}

// A query waiting for the upstream.
type bridgeResolverPass struct {
	reply   bridgeResolverReply
	id      uint16
	message []byte
}

// The resolver. See the file's comment.
type BridgeResolverClient struct {
	ctx      context.Context
	cancel   context.CancelFunc
	settings *BridgeSettings
	clock    Clock
	// the zone of the state in force, nil for none
	zone func() *BridgeZone
	// where replies enter the tun, which borrows each; nil sends none
	receive atomic.Pointer[connect.ReceivePacketFunction]
	queue   chan *bridgeResolverPass
	// keys the SYN-ACK sequences, so a segment's acknowledgement shows it answered this resolver's SYN-ACK
	secret  [32]byte
	workers sync.WaitGroup

	answeredCount atomic.Uint64
	passedCount   atomic.Uint64
	droppedCount  atomic.Uint64
}

var _ connect.UserNatClient = (*BridgeResolverClient)(nil)

// A resolver answering from zone, nil for none, writing through receive, which borrows each reply; with
// settings.ResolverUpstream, it starts the workers that pass other names on. Nil settings are DefaultBridgeSettings.
func NewBridgeResolverClient(ctx context.Context, zone func() *BridgeZone, receive connect.ReceivePacketFunction, settings *BridgeSettings) *BridgeResolverClient {
	if settings == nil {
		settings = DefaultBridgeSettings()
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	self := &BridgeResolverClient{
		ctx:      cancelCtx,
		cancel:   cancel,
		settings: settings,
		clock:    settings.clock(),
		zone:     zone,
		queue:    make(chan *bridgeResolverPass, settings.ResolverQueueCount),
	}
	if _, err := rand.Read(self.secret[:]); err != nil {
		// no randomness: every SYN-ACK's sequence is still keyed, by zeros, and a segment must still acknowledge it
		clear(self.secret[:])
	}
	self.SetReceive(receive)
	if settings.ResolverUpstream != nil {
		for range max(1, settings.ResolverWorkerCount) {
			self.workers.Add(1)
			go self.run()
		}
	}
	return self
}

// Where replies enter the tun from now on, which borrows each; nil sends none.
func (self *BridgeResolverClient) SetReceive(receive connect.ReceivePacketFunction) {
	if receive == nil {
		self.receive.Store(nil)
		return
	}
	self.receive.Store(&receive)
}

// connect.UserNatClient: stops the upstream workers and joins them; queries still queued are dropped.
func (self *BridgeResolverClient) Close() {
	self.cancel()
	self.workers.Wait()
}

func (self *BridgeResolverClient) Shuffle() {}

func (self *BridgeResolverClient) SecurityPolicyStats(reset bool) connect.SecurityPolicyStats {
	return connect.SecurityPolicyStats{}
}

func (self *BridgeResolverClient) SetLocalSecurityBypass(localSecurityBypass bool) {}

// Queries answered here, passed to the upstream, and dropped: malformed, or past the queue.
func (self *BridgeResolverClient) Counts() (answeredCount uint64, passedCount uint64, droppedCount uint64) {
	return self.answeredCount.Load(), self.passedCount.Load(), self.droppedCount.Load()
}

// connect.UserNatClient. Takes the packet, whatever it holds, and answers it by the file's rows; always true.
func (self *BridgeResolverClient) SendPacket(source connect.TransferPath, provideMode protocol.ProvideMode, packet []byte, timeout time.Duration) bool {
	self.receivePacket(provideMode, packet)
	connect.MessagePoolReturn(packet)
	return true
}

// Reads packet's IPv4 header and hands its UDP or TCP payload on. Borrows packet.
func (self *BridgeResolverClient) receivePacket(provideMode protocol.ProvideMode, packet []byte) {
	if len(packet) < bridgeIpv4HeaderByteCount || packet[0]>>4 != 4 {
		self.droppedCount.Add(1)
		return
	}
	headerByteCount := int(packet[0]&0x0F) * 4
	totalByteCount := int(binary.BigEndian.Uint16(packet[2:4]))
	if headerByteCount < bridgeIpv4HeaderByteCount || totalByteCount < headerByteCount || len(packet) < totalByteCount ||
		binary.BigEndian.Uint16(packet[6:8])&0x3FFF != 0 {
		// short, or a fragment: no whole query to answer
		self.droppedCount.Add(1)
		return
	}
	reply := bridgeResolverReply{
		provideMode: provideMode,
		source:      netip.AddrFrom4([4]byte(packet[12:16])),
		destination: netip.AddrFrom4([4]byte(packet[16:20])),
	}
	transport := packet[headerByteCount:totalByteCount]
	switch packet[9] {
	case bridgeProtocolUdp:
		if len(transport) < 8 {
			self.droppedCount.Add(1)
			return
		}
		udpByteCount := int(binary.BigEndian.Uint16(transport[4:6]))
		if udpByteCount < 8 || len(transport) < udpByteCount {
			self.droppedCount.Add(1)
			return
		}
		reply.sourcePort = binary.BigEndian.Uint16(transport[0:2])
		reply.destinationPort = binary.BigEndian.Uint16(transport[2:4])
		self.receiveQuery(reply, transport[8:udpByteCount])
	case bridgeProtocolTcp:
		self.receiveTcp(reply, transport)
	default:
		self.droppedCount.Add(1)
	}
}

// The SYN-ACK sequence of a connection: a keyed hash of its addresses and ports.
func (self *BridgeResolverClient) cookie(reply bridgeResolverReply) uint32 {
	var buffer [32 + 4 + 4 + 2 + 2]byte
	copy(buffer[:32], self.secret[:])
	source := reply.source.As4()
	destination := reply.destination.As4()
	copy(buffer[32:36], source[:])
	copy(buffer[36:40], destination[:])
	binary.BigEndian.PutUint16(buffer[40:42], reply.sourcePort)
	binary.BigEndian.PutUint16(buffer[42:44], reply.destinationPort)
	digest := sha256.Sum256(buffer[:])
	return binary.BigEndian.Uint32(digest[:4])
}

// The file's tcp row, on segment, the TCP header and what it carries.
func (self *BridgeResolverClient) receiveTcp(reply bridgeResolverReply, segment []byte) {
	if len(segment) < bridgeTcpHeaderByteCount {
		self.droppedCount.Add(1)
		return
	}
	dataOffset := int(segment[12]>>4) * 4
	if dataOffset < bridgeTcpHeaderByteCount || len(segment) < dataOffset {
		self.droppedCount.Add(1)
		return
	}
	reply.tcp = true
	reply.sourcePort = binary.BigEndian.Uint16(segment[0:2])
	reply.destinationPort = binary.BigEndian.Uint16(segment[2:4])
	seq := binary.BigEndian.Uint32(segment[4:8])
	ack := binary.BigEndian.Uint32(segment[8:12])
	flags := segment[13]
	payload := segment[dataOffset:]
	isn := self.cookie(reply)
	switch {
	case flags&bridgeTcpFlagRst != 0:
	case flags&bridgeTcpFlagSyn != 0 && flags&bridgeTcpFlagAck == 0:
		reply.seq = isn
		reply.ack = seq + 1
		self.write(reply, bridgeTcpFlagSyn|bridgeTcpFlagAck, nil)
	case 0 < len(payload):
		if flags&bridgeTcpFlagAck == 0 || ack != isn+1 {
			// no handshake of this resolver's
			reply.seq = ack
			self.write(reply, bridgeTcpFlagRst, nil)
			return
		}
		reply.seq = isn + 1
		reply.ack = seq + uint32(len(payload))
		if flags&bridgeTcpFlagFin != 0 {
			reply.ack += 1
		}
		if len(payload) < bridgeDnsTcpPrefixByteCount ||
			len(payload) != bridgeDnsTcpPrefixByteCount+int(binary.BigEndian.Uint16(payload[:bridgeDnsTcpPrefixByteCount])) {
			// one whole query a segment, or none: a stateless resolver joins nothing
			self.droppedCount.Add(1)
			self.write(reply, bridgeTcpFlagRst|bridgeTcpFlagAck, nil)
			return
		}
		self.receiveQuery(reply, payload[bridgeDnsTcpPrefixByteCount:])
	case flags&bridgeTcpFlagFin != 0:
		reply.seq = ack
		reply.ack = seq + 1
		self.write(reply, bridgeTcpFlagAck, nil)
	}
}

// The file's owned, pass and malformed rows, on one DNS message. Borrows message.
func (self *BridgeResolverClient) receiveQuery(reply bridgeResolverReply, message []byte) {
	query, ok, headerOk := parseBridgeDnsQuery(message)
	if !ok {
		self.droppedCount.Add(1)
		if headerOk {
			self.answer(reply, buildBridgeDnsResponse(query, bridgeDnsCodeFormat, false, nil, 0))
		}
		return
	}
	var zone *BridgeZone
	if self.zone != nil {
		zone = self.zone()
	}
	if zone != nil {
		addrs, ttl, owned := zone.Answer(query.name, query.qtype)
		if owned {
			if query.qclass != bridgeDnsClassIn || (query.qtype != bridgeDnsTypeA && query.qtype != bridgeDnsTypeAny) {
				addrs = nil
			}
			self.answeredCount.Add(1)
			self.answer(reply, buildBridgeDnsResponse(query, 0, true, addrs, ttl))
			return
		}
	}
	if self.settings.ResolverUpstream == nil {
		self.answer(reply, buildBridgeDnsResponse(query, bridgeDnsCodeServer, false, nil, 0))
		return
	}
	pass := &bridgeResolverPass{reply: reply, id: query.id, message: append([]byte(nil), message...)}
	select {
	case self.queue <- pass:
	default:
		self.droppedCount.Add(1)
	}
}

// An upstream worker: passes each queued query on, and answers with what comes back or a server failure.
func (self *BridgeResolverClient) run() {
	defer self.workers.Done()
	for {
		select {
		case <-self.ctx.Done():
			return
		case pass := <-self.queue:
			self.passQuery(pass)
		}
	}
}

// One pass-through, bounded by ResolverUpstreamTimeout on the injected clock.
func (self *BridgeResolverClient) passQuery(pass *bridgeResolverPass) {
	response, err := func() ([]byte, error) {
		ctx, cancel := context.WithCancel(self.ctx)
		defer cancel()
		stop := self.clock.AfterFunc(self.settings.ResolverUpstreamTimeout, cancel)
		defer stop()
		return self.settings.ResolverUpstream(ctx, pass.message)
	}()
	if self.ctx.Err() != nil {
		return
	}
	// an answer of another query, or none, is no answer
	if err != nil || len(response) < bridgeDnsHeaderByteCount || binary.BigEndian.Uint16(response[0:2]) != pass.id ||
		binary.BigEndian.Uint16(response[2:4])&bridgeDnsFlagResponse == 0 || bridgeDnsUdpMaxByteCount < len(response) {
		query, ok, _ := parseBridgeDnsQuery(pass.message)
		if ok {
			self.answer(pass.reply, buildBridgeDnsResponse(query, bridgeDnsCodeServer, false, nil, 0))
		}
		return
	}
	self.passedCount.Add(1)
	self.answer(pass.reply, response)
}

// Writes message back to the asker: one datagram, or over TCP as many segments as it takes, the last with a FIN.
func (self *BridgeResolverClient) answer(reply bridgeResolverReply, message []byte) {
	if !reply.tcp {
		self.write(reply, 0, message)
		return
	}
	data := make([]byte, bridgeDnsTcpPrefixByteCount+len(message))
	binary.BigEndian.PutUint16(data[:bridgeDnsTcpPrefixByteCount], uint16(len(message)))
	copy(data[bridgeDnsTcpPrefixByteCount:], message)
	for 0 < len(data) {
		segment := data[:min(len(data), bridgeTcpSegmentByteCount)]
		data = data[len(segment):]
		flags := byte(bridgeTcpFlagAck | bridgeTcpFlagPsh)
		if len(data) == 0 {
			flags |= bridgeTcpFlagFin
		}
		self.write(reply, flags, segment)
		reply.seq += uint32(len(segment))
	}
}

// Writes one packet back to the asker: UDP carrying payload, or a TCP segment with flags. Builds it in a pool buffer
// the receive borrows, and returns it after.
func (self *BridgeResolverClient) write(reply bridgeResolverReply, flags byte, payload []byte) {
	receive := self.receive.Load()
	if receive == nil {
		return
	}
	transportByteCount := 8 + len(payload)
	ipProtocol := connect.IpProtocolUdp
	if reply.tcp {
		transportByteCount = bridgeTcpHeaderByteCount + len(payload)
		ipProtocol = connect.IpProtocolTcp
	}
	packet := connect.MessagePoolGet(bridgeIpv4HeaderByteCount + transportByteCount)
	defer connect.MessagePoolReturn(packet)
	clear(packet)
	// the IPv4 header, from the resolver back to the asker
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[6:8], 0x4000)
	packet[8] = 64
	resolver := reply.destination.As4()
	asker := reply.source.As4()
	copy(packet[12:16], resolver[:])
	copy(packet[16:20], asker[:])
	transport := packet[bridgeIpv4HeaderByteCount:]
	binary.BigEndian.PutUint16(transport[0:2], reply.destinationPort)
	binary.BigEndian.PutUint16(transport[2:4], reply.sourcePort)
	if reply.tcp {
		packet[9] = bridgeProtocolTcp
		binary.BigEndian.PutUint32(transport[4:8], reply.seq)
		if flags&bridgeTcpFlagAck != 0 {
			binary.BigEndian.PutUint32(transport[8:12], reply.ack)
		}
		transport[12] = (bridgeTcpHeaderByteCount / 4) << 4
		transport[13] = flags
		binary.BigEndian.PutUint16(transport[14:16], bridgeTcpWindow)
		copy(transport[bridgeTcpHeaderByteCount:], payload)
		binary.BigEndian.PutUint16(transport[16:18], bridgeTransportChecksum(packet[12:20], bridgeProtocolTcp, transport))
	} else {
		packet[9] = bridgeProtocolUdp
		binary.BigEndian.PutUint16(transport[4:6], uint16(transportByteCount))
		copy(transport[8:], payload)
		checksum := bridgeTransportChecksum(packet[12:20], bridgeProtocolUdp, transport)
		if checksum == 0 {
			checksum = 0xFFFF
		}
		binary.BigEndian.PutUint16(transport[6:8], checksum)
	}
	binary.BigEndian.PutUint16(packet[10:12], bridgeChecksumFinish(bridgeChecksumAdd(0, packet[:bridgeIpv4HeaderByteCount])))
	// the asker's outbound flow, which the answer returns on
	ipPath := &connect.IpPath{
		Version:         4,
		Protocol:        ipProtocol,
		SourceIp:        net.IP(asker[:]),
		SourcePort:      int(reply.sourcePort),
		DestinationIp:   net.IP(resolver[:]),
		DestinationPort: int(reply.destinationPort),
	}
	(*receive)(connect.TransferPath{}, reply.provideMode, ipPath, packet)
}

// The one's complement sum of data as 16-bit words, added to sum.
func bridgeChecksumAdd(sum uint32, data []byte) uint32 {
	for 1 < len(data) {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if 0 < len(data) {
		sum += uint32(data[0]) << 8
	}
	return sum
}

// A sum folded and complemented.
func bridgeChecksumFinish(sum uint32) uint16 {
	for 0xFFFF < sum {
		sum = sum&0xFFFF + sum>>16
	}
	return ^uint16(sum)
}

// The checksum of a TCP or UDP segment under IPv4's pseudo-header: addresses, the source's then the destination's, as
// 8 bytes, the protocol and the segment's length.
func bridgeTransportChecksum(addresses []byte, ipProtocol byte, segment []byte) uint16 {
	var pseudo [4]byte
	pseudo[1] = ipProtocol
	binary.BigEndian.PutUint16(pseudo[2:4], uint16(len(segment)))
	sum := bridgeChecksumAdd(0, addresses)
	sum = bridgeChecksumAdd(sum, pseudo[:])
	return bridgeChecksumFinish(bridgeChecksumAdd(sum, segment))
}

// Reads message as one query (RFC 1035 §4.1): a header with QR clear, opcode QUERY, one question and no answers or
// authority, its name in plain labels, no compression. ok is false otherwise; headerOk says at least a query's header
// read, so a format error can answer it.
func parseBridgeDnsQuery(message []byte) (query bridgeDnsQuery, ok bool, headerOk bool) {
	if len(message) < bridgeDnsHeaderByteCount {
		return query, false, false
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&bridgeDnsFlagResponse != 0 {
		return query, false, false
	}
	query.id = binary.BigEndian.Uint16(message[0:2])
	query.recursionDesired = flags&bridgeDnsFlagRecursion != 0
	opcode := (flags >> 11) & 0x0F
	if opcode != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 || binary.BigEndian.Uint16(message[6:8]) != 0 ||
		binary.BigEndian.Uint16(message[8:10]) != 0 {
		return query, false, true
	}
	name := make([]byte, 0, 64)
	at := bridgeDnsHeaderByteCount
	for {
		if len(message) <= at {
			return query, false, true
		}
		labelByteCount := int(message[at])
		at += 1
		if labelByteCount == 0 {
			break
		}
		// a compression pointer's top bits read as a length past 63
		if bridgeDnsLabelMaxCount < labelByteCount || len(message) < at+labelByteCount {
			return query, false, true
		}
		if 0 < len(name) {
			name = append(name, '.')
		}
		for _, character := range message[at : at+labelByteCount] {
			if 'A' <= character && character <= 'Z' {
				character += 'a' - 'A'
			}
			name = append(name, character)
		}
		if bridgeZoneNameMaxByteCount < len(name) {
			return query, false, true
		}
		at += labelByteCount
	}
	if len(message) < at+4 {
		return query, false, true
	}
	query.qtype = binary.BigEndian.Uint16(message[at : at+2])
	query.qclass = binary.BigEndian.Uint16(message[at+2 : at+4])
	query.question = message[bridgeDnsHeaderByteCount : at+4]
	query.name = string(name)
	return query, true, true
}

// A response to query: rcode, authoritative or not, its question echoed when it has one, and an A record of each IPv4
// address of addrs.
func buildBridgeDnsResponse(query bridgeDnsQuery, rcode uint16, authoritative bool, addrs []netip.Addr, ttl uint32) []byte {
	answers := []netip.Addr{}
	for _, addr := range addrs {
		if addr = addr.Unmap(); addr.Is4() {
			answers = append(answers, addr)
		}
	}
	message := make([]byte, bridgeDnsHeaderByteCount, bridgeDnsHeaderByteCount+len(query.question)+16*len(answers))
	flags := uint16(bridgeDnsFlagResponse|bridgeDnsFlagAvailable) | rcode
	if authoritative {
		flags |= bridgeDnsFlagAuthority
	}
	if query.recursionDesired {
		flags |= bridgeDnsFlagRecursion
	}
	binary.BigEndian.PutUint16(message[0:2], query.id)
	binary.BigEndian.PutUint16(message[2:4], flags)
	if 0 < len(query.question) {
		binary.BigEndian.PutUint16(message[4:6], 1)
		message = append(message, query.question...)
	}
	binary.BigEndian.PutUint16(message[6:8], uint16(len(answers)))
	for _, addr := range answers {
		record := [16]byte{0xC0, bridgeDnsHeaderByteCount, 0, bridgeDnsTypeA, 0, bridgeDnsClassIn}
		binary.BigEndian.PutUint32(record[6:10], ttl)
		binary.BigEndian.PutUint16(record[10:12], 4)
		octets := addr.As4()
		copy(record[12:16], octets[:])
		message = append(message, record[:]...)
	}
	return message
}
