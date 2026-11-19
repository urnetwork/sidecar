// The router role (§15.4, §15.6, D-MAIL-1, D-MAIL-2, I-12, I-13, I-14, X6, C9; MAIL-M7-19): mxedge on
// every lb interface but the platform listener's, a urnetwork-edge platform client in Service mode that
// holds no TLS key. It keeps the shared front, the caps, the banner, the pre-TLS dialog and its plaintext
// refusal (service.go, dialog.go), then at STARTTLS's 220 hands over here:
//
//  1. read the ClientHello through MxEdgeDeps.ReadClientHello, inside ClientHelloTimeout, keeping its
//     bytes verbatim; one that does not parse closes as decode_error;
//  2. sidecar.yml's mxedge gate, and the router's own readiness: closed or not ready, internal_error;
//  3. route on SNI alone through {mxr_<net>} (route_cache.go): no SNI or an unknown, suspended or
//     released name, unrecognized_name; Redis unanswered, internal_error;
//  4. the network's gate and its caps (caps.go's AdmitNetwork, reading 1): internal_error;
//  5. its lease on meter mx (splice.go): spent, internal_error;
//  6. Find <network_id>:smtp/25/<host> with the process's K client ids and open StreamOpen{ticket,
//     MailIngress, early_data} through MxEdgeDialer, the hello's first 2,048 B in early_data and the
//     rest in StreamData right behind it: no receiver, sockets down, busy or denied, internal_error; with
//     MxEdgeSettings.WakeHold on, a miss is first held up to 30 s while the network's receivers are woken
//     and the Find is asked again (wake_hold.go, §15.6's step 5);
//  7. splice (splice.go) until it ends.
//
// Every failure before the stream closes in the handshake with one WriteTlsAlert, and writes the sender's
// /24 or /48 to the closed-handshake memory first, so its plaintext retry gets 451. With the wake hold off,
// as it is by default until plan-KEYS-hint-addressing lands, a miss closes at once (owner decision 12). The
// router never answers SMTP after the 220, and no byte past the hello reaches a receiver before its accept
// (FI-11): the sender's next bytes stay in its socket until the splice starts.
//
// A session whose SNI named a network leaves one record through mxConnectionRecords at its end (mx-2),
// its result a word of the closed set in metrics.go; one that named none leaves none (QD-352). Nothing on
// the path reads Postgres (I-12): Redis answers the route and the closed-handshake memory, Quota the
// lease, the sockets service the Find, and the limits come from memory a loop fills. No log or metric
// holds an address, a name or a network (I-13).
//
// Safe for concurrent use.

package mxedgeservice

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §9.7's protocol filter for every Find the router sends: a receiver's smtp/ listen.
const MxFindProtocol = "smtp-starttls"

// One end of a stream to a receiver, as SocketConn is (§9.9): Close sends StreamClose and stops reading,
// CloseWrite sends StreamClose alone, and Reset sends StreamReset with its code, so a spent lease resets
// with RST_QUOTA. A Read or Write after a reset fails. Safe for concurrent use, as a net.Conn is.
type MxEdgeStream interface {
	io.Reader
	io.Writer
	CloseWrite() error
	Close() error
	Reset(code protocol.StreamResetCode) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// One session's Find and open.
type MxEdgeDialRequest struct {
	NetworkId sidecar.Id
	// The network's label, which the stream target <label>:<name> names.
	NetworkLabel string
	// smtp/25/mx, or smtp/25/mx.<scope>.
	Name string
	// StreamOpen.metadata for a ticket whose grant ends at grantExpireTimeMillis: the session's MailIngress,
	// which names no expiry, so every ticket gets the same bytes. Called once for each ticket tried.
	Metadata func(grantExpireTimeMillis uint64) ([]byte, error)
	// The hello's bytes as ReadClientHello read them: the first 2,048 ride StreamOpen and the rest follow in
	// StreamData at once, before the accept, within the receiver's initial window.
	HelloBytes []byte
}

// Find (§9.6) with the process's K client ids and protocol smtp-starttls, and the open from the client
// its ticket names (SOCK-M5-13's SocketEdgeDialer over TLS-M5-11's EdgeClientPool, which server's host
// adapts). A refusal is a sidecar.SocketCodeError around one of the ErrSocket values, which errors.Is
// reaches. Only an accept timeout blames a receiver, and a dead primary falls to the backup ticket
// (§9.6). Implementations are safe for concurrent use.
type MxEdgeDialer interface {
	// The K client ids this process holds in urnetwork-edge, which every Find sends. Fewer than
	// MxEdgeSettings.Clients leaves the router not ready.
	ClientIds() []sidecar.Id
	// Whether every client is connected now (D-TLS-9's rule, which mxedge shares).
	Ready() bool
	// Finds a receiver for the request's name and opens a stream to it, trying each ticket in turn. The
	// stream it answers holds the grant expiry its ticket named, 0 for none.
	Dial(ctx context.Context, request *MxEdgeDialRequest) (stream MxEdgeStream, grantExpireTimeMillis uint64, err error)
}

// What the router role needs beyond MxEdgeDeps, which server/mxedgehost's router block supplies.
type MxEdgeRouterDeps struct {
	// The Find and open. nil leaves the role not ready, and every session that reaches the 220 closes in
	// the handshake.
	Dialer MxEdgeDialer
	// The host's resolver for the forward-confirmed PTR: the names a PTR lookup of sender answers, and the
	// addresses a name's A and AAAA answer. Either nil leaves every ptr_name "".
	LookupPtr  func(ctx context.Context, sender netip.Addr) ([]string, error)
	LookupHost func(ctx context.Context, name string) ([]netip.Addr, error)
	// The licensed feed's local mirror (listings.go). nil lists no one: nothing is rejected at the banner
	// and no MailIngress carries a category, as with the feed down.
	Listings MxListingSource
}

// The router role's state, built once with the engine.
type mxRouter struct {
	service *MxEdgeService
	dialer  MxEdgeDialer
	routes  *mxRouteCache
	limits  *mxMessageLimits
	// nil when the host gave no Quota, and then no session is routed
	usage   *sidecar.QuotaUsageBatcher
	leases  *mxLeases
	lookups *mxPtrLookups
	// nil with no source
	listings *mxListings
	// §15.6's wake holds and their hints (wake_hold.go)
	holds *mxWakeHolds
	// the limits loop and the listings'
	loopGroup sync.WaitGroup
	// splices registered, so a drain's wait and a test can see one start or end
	spliceCount *sidecar.MonitorValue[int]

	stateLock sync.Mutex
	// every splice running, by listening network
	networkIdSplices map[sidecar.Id]map[*mxSplice]bool
	// a drain's wait is over or the engine is closing: what is open resets, and what is still setting up
	// ends itself
	resetting bool
}

// Starts the engine in the router role, which is ready once a probe has found the store and today's k,
// the dialer holds Clients connected clients and host gives a Quota. host needs Redis and Metrics, and
// settings must pass ValidateRouter. A nil store, deps, routerDeps or Quota is allowed and leaves the role
// not ready: every session that reaches the 220 then closes in the handshake.
func NewMxEdgeRouterService(
	ctx context.Context,
	host *sidecar.ServiceHost,
	store MxEdgeStore,
	deps *MxEdgeDeps,
	routerDeps *MxEdgeRouterDeps,
	settings *MxEdgeSettings,
) (*MxEdgeService, error) {
	if err := settings.ValidateRouter(); err != nil {
		return nil, err
	}
	if host == nil || host.Redis == nil || host.Metrics == nil {
		return nil, errors.New("mxedge needs a host with Redis and Metrics")
	}
	if routerDeps == nil {
		routerDeps = &MxEdgeRouterDeps{}
	}
	// the batcher ends at the engine's release (mxRouter.close), or with ctx
	var usage *sidecar.QuotaUsageBatcher
	if host.Quota != nil {
		var err error
		usage, err = sidecar.NewQuotaUsageBatcher(ctx, host, sidecar.QuotaProducerMxEdge, settings.Usage)
		if err != nil {
			return nil, err
		}
	}
	service, err := newMxEdgeService(ctx, host, store, deps, settings, func(self *MxEdgeService) {
		router := &mxRouter{
			service:          self,
			dialer:           routerDeps.Dialer,
			routes:           newMxRouteCache(self.ctx, host.Redis, settings, self.clock),
			limits:           newMxMessageLimits(settings, host.Quota, self.clock),
			usage:            usage,
			lookups:          newMxPtrLookups(self, routerDeps),
			holds:            newMxWakeHolds(self.ctx, host.Push, settings, self.clock, self.metrics),
			spliceCount:      sidecar.NewMonitorValue(0),
			networkIdSplices: map[sidecar.Id]map[*mxSplice]bool{},
		}
		router.leases = newMxLeases(self.ctx, host.Quota, usage, settings, self.clock, router.resetSpent)
		self.router = router
		self.handoff = self.serveRouter
		self.depsComplete = self.depsComplete && routerDeps.Dialer != nil && usage != nil
		router.loopGroup.Add(1)
		go func() {
			defer router.loopGroup.Done()
			router.limits.run(self.ctx)
		}()
		if routerDeps.Listings != nil {
			router.listings = newMxListings(routerDeps.Listings, settings, self.clock, self.metrics)
			self.bannerRefused = router.listings.Refused
			router.loopGroup.Add(1)
			go func() {
				defer router.loopGroup.Done()
				router.listings.run(self.ctx)
			}()
		}
	})
	if err != nil {
		if usage != nil {
			usage.Close()
		}
		return nil, err
	}
	return service, nil
}

// Whether the router can route: the dialer holds Clients client ids, all connected.
func (self *mxRouter) ready() bool {
	if self.dialer == nil || self.usage == nil {
		return false
	}
	return self.service.settings.Clients <= len(self.dialer.ClientIds()) && self.dialer.Ready()
}

// Starts what the router does from a session's admission: the sender's PTR lookup, read at the handoff,
// and the categories the feed mirror lists it under, which MailIngress carries.
func (self *mxRouter) admit(session *mxSession) {
	session.ptr = self.lookups.Start(session.sender)
	if self.listings != nil {
		session.listings = self.listings.Categories(session.sender)
	}
}

// Records a splice so a spent lease, a drain and a close can find it. False once a drain's reset or a
// close has passed, when the splice must end itself.
func (self *mxRouter) addSplice(splice *mxSplice) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.resetting {
		return false
	}
	splices, ok := self.networkIdSplices[splice.networkId]
	if !ok {
		splices = map[*mxSplice]bool{}
		self.networkIdSplices[splice.networkId] = splices
	}
	splices[splice] = true
	self.spliceCount.Update(func(count int) int { return count + 1 })
	return true
}

func (self *mxRouter) removeSplice(splice *mxSplice) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	splices, ok := self.networkIdSplices[splice.networkId]
	if !ok || !splices[splice] {
		return
	}
	delete(splices, splice)
	if len(splices) == 0 {
		delete(self.networkIdSplices, splice.networkId)
	}
	self.spliceCount.Update(func(count int) int { return count - 1 })
}

// The splices of one network, or of every network when networkId is nil.
func (self *mxRouter) splices(networkId *sidecar.Id) []*mxSplice {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	spliced := []*mxSplice{}
	for id, splices := range self.networkIdSplices {
		if networkId != nil && id != *networkId {
			continue
		}
		for splice := range splices {
			spliced = append(spliced, splice)
		}
	}
	return spliced
}

// Resets every splice of a network whose lease ran out (§20.6).
func (self *mxRouter) resetSpent(networkId sidecar.Id) {
	for _, splice := range self.splices(&networkId) {
		splice.end(mxSpliceEndQuota, protocol.StreamResetCode_RST_QUOTA)
	}
}

// Resets every splice still open with RST_DRAINING, and makes any that finishes its setup after this end
// itself: a drain whose wait is over, or the engine's close.
func (self *mxRouter) resetSplices() {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.resetting = true
	}()
	for _, splice := range self.splices(nil) {
		splice.end(mxSpliceEndDrain, protocol.StreamResetCode_RST_DRAINING)
	}
}

// What the engine's Drain does for the router once its wait is over: resets what is still open, then
// sends the last usage window inside RecordWriteTimeout, so a deploy bills what it moved. What it cannot
// send then is dropped at the close, counted by the batcher (under-billing, never double-billing).
func (self *mxRouter) drained() {
	self.resetSplices()
	if self.usage == nil {
		return
	}
	flushCtx, cancel := context.WithCancel(context.WithoutCancel(self.service.ctx))
	stop := self.service.clock.AfterFunc(self.service.settings.RecordWriteTimeout, cancel)
	defer func() {
		stop()
		cancel()
	}()
	self.usage.Drain(flushCtx)
}

// What the engine's release does for the router once every session has ended: waits for the lookups, the
// wake hints in flight and the limits loop, then stops the usage batcher, as a kill would.
func (self *mxRouter) close() {
	self.lookups.group.Wait()
	self.holds.close()
	self.loopGroup.Wait()
	if self.usage != nil {
		self.usage.Close()
	}
}

// Writes the one alert a session that reached TLS and goes no further gets, the closed-handshake memory
// first, so it exists before a sender can see the close and retry in plaintext. Bounded by AlertTimeout
// on the engine's clock, since the dialog's watchdog has stopped.
func (self *MxEdgeService) closeRouterHandshake(session *mxSession, alert MxTlsAlert) {
	self.recordClosedHandshake(session)
	if self.deps.WriteTlsAlert == nil {
		return
	}
	stop := self.clock.AfterFunc(self.settings.AlertTimeout, func() {
		session.conn.Close()
	})
	defer stop()
	self.deps.WriteTlsAlert(session.conn, alert)
}

// A context bounded by timeout on the engine's clock, and the call that ends it.
func (self *MxEdgeService) boundedContext(timeout time.Duration) (context.Context, func()) {
	ctx, cancel := context.WithCancel(self.ctx)
	stop := self.clock.AfterFunc(timeout, cancel)
	return ctx, func() {
		stop()
		cancel()
	}
}

// The sender's address and port as the host's PROXY listener reported them, unmapped.
func mxSenderAddrPort(addr net.Addr) netip.AddrPort {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		addrPort := tcpAddr.AddrPort()
		return netip.AddrPortFrom(addrPort.Addr().Unmap().WithZone(""), addrPort.Port())
	}
	if addr == nil {
		return netip.AddrPort{}
	}
	addrPort, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addrPort.Addr().Unmap().WithZone(""), addrPort.Port())
}

// The router's handoff: the file header's steps, returning the session's result.
func (self *MxEdgeService) serveRouter(session *mxSession) string {
	router := self.router
	conn := session.conn

	// step 1, the hello inside ClientHelloTimeout: closing conn ends a read that will not finish
	hello, err := func() (*MxClientHello, error) {
		stopHelloTimer := self.clock.AfterFunc(self.settings.ClientHelloTimeout, func() {
			conn.Close()
		})
		defer stopHelloTimer()
		if self.deps.ReadClientHello == nil {
			return nil, errors.New("no hello reader")
		}
		return self.deps.ReadClientHello(conn, self.settings.ClientHelloByteCount)
	}()
	if err != nil {
		self.closeRouterHandshake(session, MxTlsAlertDecodeError)
		return mxSessionResultHelloFailed
	}

	// step 2: a closed gate and a router that cannot route answer every name alike
	if self.deps.GateOpen == nil || !self.deps.GateOpen() {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultGateClosed
	}
	if !self.Ready() {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultNotReady
	}

	// step 3
	if hello.ServerName == "" {
		self.closeRouterHandshake(session, MxTlsAlertUnrecognizedName)
		return mxSessionResultNoSni
	}
	sni, ok := self.deps.NormalizeSni(hello.ServerName)
	if !ok {
		self.closeRouterHandshake(session, MxTlsAlertUnrecognizedName)
		return mxSessionResultUnknownName
	}
	route, err := func() (*MailRoute, error) {
		lookupCtx, done := self.boundedContext(self.settings.StoreTimeout)
		defer done()
		return router.routes.Lookup(lookupCtx, MailRouteName(self.settings.RouteRootDomainName, sni))
	}()
	if err != nil {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultRouteUnavailable
	}
	if route == nil {
		self.closeRouterHandshake(session, MxTlsAlertUnrecognizedName)
		return mxSessionResultUnknownName
	}

	// the session named a network: from here it leaves a record
	result, byteCount := self.routeNetwork(session, hello, sni, route)
	self.recordSession(session, route.NetworkId, byteCount, result)
	return result
}

// Steps 4 to 7 for a session whose SNI named route, returning its result and the bytes it passed.
func (self *MxEdgeService) routeNetwork(session *mxSession, hello *MxClientHello, sni string, route *MailRoute) (string, int64) {
	router := self.router
	networkId := route.NetworkId

	// step 4
	if self.deps.GateAdmits == nil || !self.deps.GateAdmits(networkId) {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultGateClosed, 0
	}
	if refusal := self.caps.AdmitNetwork(session.hold, networkId); refusal != mxCapRefusalNone {
		self.metrics.capRefusals.Add(1, string(refusal))
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultNetworkCap, 0
	}

	// step 5
	lease, err := router.leases.Acquire(networkId)
	if err != nil {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		if errors.Is(err, errMxLeaseSpent) {
			return mxSessionResultSpent, 0
		}
		return mxSessionResultSetupFailed, 0
	}
	defer router.leases.Release(lease)

	// step 6
	sender := mxSenderAddrPort(session.conn.RemoteAddr())
	ptrName := ""
	if session.ptr != nil {
		ptrName = session.ptr.Name()
	}
	ingress, err := buildMailIngress(self.settings.Ingress, &mxIngressFields{
		sender:      sender,
		sni:         sni,
		ehloName:    session.dialog.ehloName,
		ptrName:     ptrName,
		listings:    session.listings,
		receiveTime: session.startTime,
	})
	if err != nil {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultSetupFailed, 0
	}
	dial := func(timeout time.Duration) (MxEdgeStream, uint64, error) {
		dialCtx, done := self.boundedContext(timeout)
		defer done()
		stream, grantExpireTimeMillis, err := router.dialer.Dial(dialCtx, &MxEdgeDialRequest{
			NetworkId:    networkId,
			NetworkLabel: route.Label,
			Name:         route.SocketName(),
			Metadata: func(grantExpireTimeMillis uint64) ([]byte, error) {
				return ingress, nil
			},
			HelloBytes: hello.RawBytes,
		})
		if err == nil && stream == nil {
			err = errors.New("the dialer answered no stream")
		}
		return stream, grantExpireTimeMillis, err
	}
	stream, grantExpireTimeMillis, err := dial(self.settings.AcceptSetupTimeout)
	if err != nil {
		// §15.6's step 5: a miss waits for a woken receiver, when the hold is on
		stream, grantExpireTimeMillis, err = self.holdForReceiver(route, err, dial)
	}
	if err != nil {
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		switch {
		case errors.Is(err, sidecar.ErrSocketNoListener):
			return mxSessionResultNoReceiver, 0
		case errors.Is(err, sidecar.ErrSocketBusy):
			return mxSessionResultReceiverBusy, 0
		case errors.Is(err, sidecar.ErrSocketDenied):
			return mxSessionResultReceiverDenied, 0
		case errors.Is(err, sidecar.ErrSocketQuota):
			return mxSessionResultSpent, 0
		case errors.Is(err, sidecar.ErrSocketUnavailable):
			return mxSessionResultSocketsUnavailable, 0
		}
		return mxSessionResultSetupFailed, 0
	}

	// §20.6: the listening network pays for every byte, the hello's included
	if !router.leases.Spend(lease, len(hello.RawBytes)) {
		stream.Reset(protocol.StreamResetCode_RST_QUOTA)
		self.closeRouterHandshake(session, MxTlsAlertInternalError)
		return mxSessionResultSpent, 0
	}

	// step 7
	now := self.clock.Now()
	splice := &mxSplice{
		router:    router,
		conn:      session.conn,
		stream:    stream,
		lease:     lease,
		networkId: networkId,
		startTime: now,
		byteCap: int64(self.settings.SpliceMessageMultiple)*router.limits.MessageByteCount(networkId) +
			int64(self.settings.SpliceExtraByteCount),
		ended: make(chan struct{}),
	}
	splice.byteCount.Add(int64(len(hello.RawBytes)))
	splice.lastActiveNanos.Store(now.UnixNano())
	self.metrics.spliceBytes.Add(float64(len(hello.RawBytes)), mxByteDirectionToReceiver)
	registered := router.addSplice(splice)
	defer router.removeSplice(splice)
	switch {
	case !registered:
		// a drain's reset or a close landed during the setup
		splice.end(mxSpliceEndDrain, protocol.StreamResetCode_RST_DRAINING)
	case lease.spent.Load():
		splice.end(mxSpliceEndQuota, protocol.StreamResetCode_RST_QUOTA)
	}
	var grantExpireTime time.Time
	if 0 < grantExpireTimeMillis {
		grantExpireTime = time.UnixMilli(int64(grantExpireTimeMillis))
	}
	splice.run(grantExpireTime)
	self.metrics.spliceEnds.Add(1, splice.endReason)
	return mxSessionResultSplicePrefix + splice.endReason, splice.byteCount.Load()
}
