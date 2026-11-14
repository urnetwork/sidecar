// One visitor's connection, §13.5's steps in order:
//
//  1. take a process slot, then read the ClientHello inside client_hello.timeout_s. A hello that does not
//     parse answers decode_error. A hello offering ur-route-probe answers unrecognized_name at once,
//     whatever its SNI, with no lookup, Find, record or lease (§13.4's route probe);
//  2. normalize the SNI and map it with the listener's port to (network, tls/<port>/<host>);
//  3. check, all in memory, the kill switch, sidecar.yml's tlsedge gate, the caps and the negative cache;
//  4. Find and 5. open, through the dialer, as autogroup:public with the offered ALPN list, handing it the
//     hello's bytes whole, so the listener reads one contiguous stream;
//  6. splice (splice.go);
//  7. on any failure before the stream, one plaintext alert and close: unrecognized_name for an unmapped,
//     killed or denied name, which a visitor cannot tell apart, and internal_error for no listener, busy,
//     quota, a cap, a closed gate or an edge that is not ready (reading 5).
//
// Nothing here reads Postgres (I-12): the map, the kills, the caps and the cache are memory the engine's
// loops fill, and a record leaves through records.go's queue. tlsedge holds no key and no TLS library
// touches the visitor's bytes: what follows the hello passes untouched (D-TLS-1). The visitor's address
// goes into TlsEdgeOpen and the caps' keyed hashes and nowhere else, and no metric label holds a network,
// host or address (I-13).

package tlsedgeservice

import (
	cryptorand "crypto/rand"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The dialer answered with neither a stream nor an error, or a TlsEdgeOpen would not fit its bound.
var errTlsEdgeOpenRefused = errors.New("the stream's open could not be built")

// One connection from accept to its end.
type tlsEdgeConnection struct {
	service   *TlsEdgeService
	conn      net.Conn
	port      int
	startTime time.Time
	hold      *TlsCapHold

	// set once routed, before the splice, and not changed after
	visitor      netip.AddrPort
	target       *TlsEdgeTarget
	connectionId sidecar.Id
	stream       TlsEdgeStream
	lease        *tlsEdgeLease

	// bytes passed, both ways
	byteCount atomic.Int64
	// the clock's time of the last byte moved, in Unix nanoseconds
	lastActiveNanos atomic.Int64

	endOnce sync.Once
	// closed by end
	ended chan struct{}
	// set by end before ended closes
	endReason string
}

// The visitor's address: PROXY's when the host's listener took a header off, else the peer's.
func tlsEdgeVisitor(conn net.Conn) (netip.AddrPort, bool) {
	if proxied, ok := conn.(interface{ VisitorAddr() netip.AddrPort }); ok {
		visitor := proxied.VisitorAddr()
		return visitor, visitor.IsValid()
	}
	if address, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		visitor := address.AddrPort()
		return netip.AddrPortFrom(visitor.Addr().Unmap().WithZone(""), visitor.Port()), visitor.IsValid()
	}
	return netip.AddrPort{}, false
}

// One connection, start to end, counted by how it ended.
func (self *TlsEdgeService) serveConnection(conn net.Conn, port int) {
	connection := &tlsEdgeConnection{
		service:   self,
		conn:      conn,
		port:      port,
		startTime: self.clock.Now(),
		ended:     make(chan struct{}),
	}
	result := connection.serve()
	self.metrics.connections.Add(1, result)
	self.connectionEndCount.Update(func(count uint64) uint64 { return count + 1 })
}

// Writes the one alert a refused visitor gets, bounded by AlertTimeout on the engine's clock.
func (self *tlsEdgeConnection) alert(code TlsAlertCode) {
	stop := self.service.clock.AfterFunc(self.service.settings.AlertTimeout, func() {
		self.conn.Close()
	})
	defer stop()
	WriteTlsAlert(self.conn, code)
}

// §13.5's step 1's read: the hello, inside client_hello.timeout_s on the engine's clock.
func (self *tlsEdgeConnection) readHello() (*TlsClientHello, error) {
	timeout := newProxyHeaderTimeout(self.service.clock, self.service.settings.ClientHelloTimeout, self.conn)
	hello, err := ReadClientHello(self.conn, self.service.settings.ClientHelloMaxByteCount)
	if !timeout.end() && err == nil {
		// the deadline will not lift, so the splice could not read
		return nil, net.ErrClosed
	}
	return hello, err
}

// StreamOpen.metadata for a ticket whose grant ends at grantExpireTimeMillis.
func (self *tlsEdgeConnection) openMetadata(serverName string, alpnIds []string, helloByteCount int, grantExpireTimeMillis uint64) ([]byte, error) {
	metadata, err := proto.Marshal(&protocol.TlsEdgeOpen{
		ClientIp:             self.visitor.Addr().AsSlice(),
		ClientPort:           uint32(self.visitor.Port()),
		ServerName:           serverName,
		Alpn:                 alpnIds,
		ClientHelloByteCount: uint32(helloByteCount),
		ConnectionId:         self.connectionId[:],
		ExpireTimeMillis:     grantExpireTimeMillis,
	})
	if err != nil {
		return nil, err
	}
	if sidecar.TlsEdgeOpenMaxByteCount < len(metadata) {
		return nil, errTlsEdgeOpenRefused
	}
	return metadata, nil
}

// Runs the connection and returns its result, one of the tlsConnectionResult values.
func (self *tlsEdgeConnection) serve() string {
	service := self.service
	defer self.conn.Close()

	// step 1
	hold, capRefusal := service.caps.AdmitProcess()
	if capRefusal != TlsCapRefusalNone {
		service.metrics.capRefusals.Add(1, string(capRefusal))
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultProcessCap
	}
	self.hold = hold
	defer service.caps.Release(hold)

	hello, err := self.readHello()
	if err != nil {
		if errors.Is(err, ErrClientHelloRefused) {
			self.alert(TlsAlertDecodeError)
			return tlsConnectionResultHelloRefused
		}
		return tlsConnectionResultHelloIncomplete
	}
	if hello.OffersRouteProbe() {
		self.alert(TlsAlertUnrecognizedName)
		return tlsConnectionResultRouteProbe
	}

	// a closed gate and an edge that is not ready answer every name alike
	gate := service.host.GatesOrClosed().Service(sidecar.ServiceGateTlsedge)
	if !gate.Enabled() {
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultGateClosed
	}
	if !service.Ready() {
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultNotReady
	}

	// step 2
	target, ok := service.names.Resolve(hello.ServerName, self.port)
	if !ok {
		self.alert(TlsAlertUnrecognizedName)
		return tlsConnectionResultUnmapped
	}
	// Resolve normalized it the same way, so this cannot fail
	serverName, _ := NormalizeSni(hello.ServerName)

	// step 3
	if service.kills.Kills(target.NetworkId, target.Host) {
		self.alert(TlsAlertUnrecognizedName)
		return tlsConnectionResultKilled
	}
	if !gate.Admits(connect.Id(target.NetworkId)) {
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultGateClosed
	}
	visitor, ok := tlsEdgeVisitor(self.conn)
	if !ok {
		service.metrics.capRefusals.Add(1, string(TlsCapRefusalNoVisitor))
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultCap
	}
	self.visitor = visitor
	if capRefusal := service.caps.Admit(hold, visitor.Addr(), target, service.EndpointLimits(target.NetworkId)); capRefusal != TlsCapRefusalNone {
		service.metrics.capRefusals.Add(1, string(capRefusal))
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultCap
	}
	alpnIds := sidecar.TrimTlsEdgeOpenAlpn(serverName, hello.AlpnIds)
	if reason, ok := service.negativeCache.Lookup(serverName, self.port, alpnIds); ok {
		if reason == TlsNegativeDenied {
			self.alert(TlsAlertUnrecognizedName)
			return tlsConnectionResultNegativeDenied
		}
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultNegativeNoListener
	}

	// steps 4 and 5
	self.target = target
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(self.connectionId[:])
	var grantExpireTimeMillis atomic.Uint64
	request := &TlsEdgeDialRequest{
		Target:  target,
		AlpnIds: alpnIds,
		Metadata: func(ticketGrantExpireTimeMillis uint64) ([]byte, error) {
			// tickets are tried in turn, so the last asked for is the one that opened
			grantExpireTimeMillis.Store(ticketGrantExpireTimeMillis)
			return self.openMetadata(serverName, alpnIds, len(hello.RawBytes), ticketGrantExpireTimeMillis)
		},
		HelloBytes: hello.RawBytes,
	}
	stream, err := func() (TlsEdgeStream, error) {
		dialCtx, cancel := service.callContext(service.settings.AcceptSetupTimeout)
		defer cancel()
		stream, err := service.dialer.Dial(dialCtx, request)
		if err == nil && stream == nil {
			err = errTlsEdgeOpenRefused
		}
		return stream, err
	}()
	if err != nil {
		switch {
		case errors.Is(err, sidecar.ErrSocketDenied):
			service.metrics.negativeEvictions.Add(float64(service.negativeCache.Add(serverName, self.port, alpnIds, TlsNegativeDenied)))
			self.alert(TlsAlertUnrecognizedName)
			return tlsConnectionResultDenied
		case errors.Is(err, sidecar.ErrSocketNoListener):
			service.metrics.negativeEvictions.Add(float64(service.negativeCache.Add(serverName, self.port, alpnIds, TlsNegativeNoListener)))
			self.alert(TlsAlertInternalError)
			return tlsConnectionResultNoListener
		case errors.Is(err, sidecar.ErrSocketBusy):
			self.alert(TlsAlertInternalError)
			return tlsConnectionResultBusy
		case errors.Is(err, sidecar.ErrSocketQuota):
			self.alert(TlsAlertInternalError)
			return tlsConnectionResultQuota
		case errors.Is(err, sidecar.ErrSocketUnavailable):
			self.alert(TlsAlertInternalError)
			return tlsConnectionResultUnavailable
		}
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultSetupFailed
	}
	self.stream = stream

	// §13.6: the listening network pays for every byte, the hello's included
	lease, err := service.leases.Acquire(target.NetworkId)
	if err != nil {
		if errors.Is(err, errTlsLeaseSpent) {
			stream.Reset(protocol.StreamResetCode_RST_QUOTA)
			self.alert(TlsAlertInternalError)
			return tlsConnectionResultQuota
		}
		stream.Reset(protocol.StreamResetCode_RST_CANCELLED)
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultSetupFailed
	}
	self.lease = lease
	defer service.leases.Release(lease)
	if !service.leases.Spend(lease, len(hello.RawBytes)) {
		stream.Reset(protocol.StreamResetCode_RST_QUOTA)
		self.alert(TlsAlertInternalError)
		return tlsConnectionResultQuota
	}
	self.byteCount.Add(int64(len(hello.RawBytes)))
	service.metrics.bytes.Add(float64(len(hello.RawBytes)), tlsByteDirectionToListener)

	// step 6
	now := service.clock.Now()
	self.lastActiveNanos.Store(now.UnixNano())
	service.metrics.setupSeconds.Observe(now.Sub(self.startTime).Seconds())
	testHookBarrier("tlsedge.splice_register.before", self.connectionId.String())
	registered := service.addSplice(self)
	testHookBarrier("tlsedge.splice_register.after", self.connectionId.String())
	defer service.removeSplice(self)
	switch {
	case !registered:
		// a drain's reset or a close landed during the setup
		self.end(tlsStreamEndDrain, protocol.StreamResetCode_RST_DRAINING)
	case service.kills.Kills(target.NetworkId, target.Host):
		// a kill that landed after step 3 and before the walk could see this connection
		self.end(tlsStreamEndKilled, protocol.StreamResetCode_RST_REVOKED)
	case lease.spent.Load():
		self.end(tlsStreamEndQuota, protocol.StreamResetCode_RST_QUOTA)
	}
	if expireTimeMillis := grantExpireTimeMillis.Load(); 0 < expireTimeMillis {
		// streams end at the grant's expiry (§13.5)
		stop := service.clock.AfterFunc(time.UnixMilli(int64(expireTimeMillis)).Sub(now), func() {
			self.end(tlsStreamEndExpired, protocol.StreamResetCode_RST_REVOKED)
		})
		defer stop()
	}
	self.splice()

	endTime := service.clock.Now()
	service.metrics.streamEnds.Add(1, self.endReason)
	service.records.Add(&TlsConnectionRecord{
		ConnectionId: self.connectionId,
		NetworkId:    target.NetworkId,
		Host:         target.Host,
		StartTime:    tlsRecordTime(self.startTime),
		EndTime:      tlsRecordTime(endTime),
		ByteCount:    self.byteCount.Load(),
		VisitorHash:  service.visitorKeys.RecordHash(visitor.Addr()),
	})
	return tlsConnectionResultSpliced
}

// Records a spliced connection so a kill, a spent lease, a drain and a close can find it. False once a
// drain's reset or a close has passed, when the connection must end itself.
func (self *TlsEdgeService) addSplice(connection *tlsEdgeConnection) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed || self.drainReset {
		return false
	}
	connections, ok := self.networkIdSplices[connection.target.NetworkId]
	if !ok {
		connections = map[*tlsEdgeConnection]bool{}
		self.networkIdSplices[connection.target.NetworkId] = connections
	}
	connections[connection] = true
	return true
}

func (self *TlsEdgeService) removeSplice(connection *tlsEdgeConnection) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	connections, ok := self.networkIdSplices[connection.target.NetworkId]
	if !ok {
		return
	}
	delete(connections, connection)
	if len(connections) == 0 {
		delete(self.networkIdSplices, connection.target.NetworkId)
	}
}

// The spliced connections of one network, or of every network when networkId is nil.
func (self *TlsEdgeService) splices(networkId *sidecar.Id) []*tlsEdgeConnection {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	spliced := []*tlsEdgeConnection{}
	if networkId != nil {
		for connection := range self.networkIdSplices[*networkId] {
			spliced = append(spliced, connection)
		}
		return spliced
	}
	for _, connections := range self.networkIdSplices {
		for connection := range connections {
			spliced = append(spliced, connection)
		}
	}
	return spliced
}

// Resets the open connections a kill now refuses, among the networks whose kills changed (§13.9: within
// 5 s of the write). Called on the kills loop after each change, with no lock held.
func (self *TlsEdgeService) resetKilled(networkIds []sidecar.Id) {
	for _, networkId := range networkIds {
		for _, connection := range self.splices(&networkId) {
			if self.kills.Kills(networkId, connection.target.Host) {
				connection.end(tlsStreamEndKilled, protocol.StreamResetCode_RST_REVOKED)
			}
		}
	}
}

// Resets every open connection of a network whose lease ran out (§13.6).
func (self *TlsEdgeService) resetSpent(networkId sidecar.Id) {
	for _, connection := range self.splices(&networkId) {
		connection.end(tlsStreamEndQuota, protocol.StreamResetCode_RST_QUOTA)
	}
}
