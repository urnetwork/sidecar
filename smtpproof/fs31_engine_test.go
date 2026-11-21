//go:build sidecar_testhooks

// FS-31's edge where the leg links smtpedgeservice's cross-module entry (SmtpEdgeTestListener, which only the
// sidecar_testhooks build has): the real engine on sidecartest's fakes, in an MxWorld whose recipient domain's MX is
// the row's, the preamble's gate, quota and issued values as in production, the stream served as the ur/smtpedge
// listener serves one admitted on a ticket, and each SHTS and part reaching the engine's handlers through the
// sender's own SmtpProofChannel. The verifier is smtpproof's Verifier holding FS-31's key set over the row's backend,
// so every session is edgeSession; what the engine's sessions refused is recorded as they refuse it.
//
// A forging edge (ExportedFs31EdgeArgs.ForgeServerFrom) sits between the MX and the engine's socket: from the MX's
// chosen application record on, each reaches the engine as a record sealed under a key the edge made up, which is all
// an edge holding no key can send.
//
// An external test, since a client package's own files may not import a <svc>service (§4.4): it registers its maker
// with the fixture and reads the fixture's internals through fs31_export_test.go's bridge.

package smtpproof_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
	"github.com/urnetwork/sidecar/smtpproof"
)

func init() {
	smtpproof.SetFs31EngineEdge(func(args *smtpproof.ExportedFs31EdgeArgs) *smtpproof.ExportedFs31Edge {
		world := &fs31EngineEdgeWorld{args: args}
		return &smtpproof.ExportedFs31Edge{
			Name:          "engine",
			Open:          world.open,
			QuitForwarded: world.quitForwarded,
			Done:          world.done,
			End:           world.end,
			Wait:          world.wait,
			Refusal:       world.refusal,
		}
	})
}

// A guard on what a test waits for, never a pause: each wait ends at the event it waits on.
const fs31EngineGuardTimeout = 60 * time.Second

// The engine's world for one connection: its root, network and sending address.
const (
	fs31EngineRoot     = "root.example"
	fs31EngineLabel    = "net"
	fs31EngineHeloName = "o1.out.root.example"
	// 26 lowercase base32 characters, a report_token's form (plan-SMTP-net-token)
	fs31EngineReportToken = "aaaaaaaaaaaaaaaaaaaaaaaaaa"
)

var (
	fs31EngineSendingAddress = netip.MustParseAddr("192.0.2.10")
	fs31EngineMxAddress      = netip.MustParseAddr("192.0.2.25")
)

// The engine for one connection.
type fs31EngineEdgeWorld struct {
	args     *smtpproof.ExportedFs31EdgeArgs
	ctx      context.Context
	clock    *sidecartest.FakeClock
	world    *sidecartest.MxWorld
	verifier *fs31Verifier
	store    *sidecartest.FakeSmtpEdgeStore
	service  *smtpedgeservice.SmtpEdgeService
	listener *smtpedgeservice.SmtpEdgeTestListener

	networkId    sidecar.Id
	edgeClientId sidecar.Id
	clientId     sidecar.Id
	sidecarId    sidecar.Id
	// closed once the latest stream's connection has ended
	served chan struct{}
	// every stream's service, each done once its connection has ended
	serving sync.WaitGroup
}

// Pro's smtp_* numbers (§20.4), with the recipients a message may name raised where a row asks.
func fs31EngineLimits(recipientLimit int) *sidecar.QuotaLimits {
	limits := &sidecar.QuotaLimits{Tier: "pro", Limits: map[string]int64{
		smtpedgeservice.SmtpLimitConnectionsPerDay:             200,
		smtpedgeservice.SmtpLimitBytesPerDay:                   1024 * 1024 * 1024,
		smtpedgeservice.SmtpLimitRecipientsPerMessage:          50,
		smtpedgeservice.SmtpLimitRecipientsPerDay:              1000,
		smtpedgeservice.SmtpLimitMessageBytes:                  25 * 1024 * 1024,
		smtpedgeservice.SmtpLimitBurst:                         50,
		smtpedgeservice.SmtpLimitBurstWindow:                   (10 * time.Minute).Milliseconds(),
		smtpedgeservice.SmtpLimitConcurrentConnections:         4,
		smtpedgeservice.SmtpLimitCommunityConnectionsPerHour:   500,
		smtpedgeservice.SmtpLimitCommunityMedianMultiple:       3,
		smtpedgeservice.SmtpLimitDestinationConnectionsPerHour: 200,
		smtpedgeservice.SmtpLimitDestinationConcurrency:        10,
		smtpedgeservice.SmtpLimitHardBouncePercent:             10,
		smtpedgeservice.SmtpLimitHardBounceFloor:               10,
	}}
	if 0 < recipientLimit {
		limits.Limits[smtpedgeservice.SmtpLimitRecipientsPerMessage] = int64(recipientLimit)
	}
	return limits
}

// Starts the engine in its world, its verifier smtpproof's Verifier holding FS-31's key set over the row's backend,
// then serves one stream to it and answers the preamble as the engine does.
func (self *fs31EngineEdgeWorld) open(ctx context.Context, declared *smtpproof.ExportedFs31Declared) (*smtpproof.ExportedFs31Opened, error) {
	// a session reads the clock start makes, which no session opens before
	verifier := self.args.NewVerifier(func() time.Time { return self.clock.Now() })
	if err := self.start(ctx, verifier); err != nil {
		return nil, err
	}
	sidecarEnd := self.stream()
	preamble := &protocol.SmtpPreamble{
		Version:          sidecar.SmtpPreambleVersion,
		RecipientDomain:  declared.RecipientDomain,
		RecipientCount:   declared.RecipientCount,
		MessageId:        declared.MessageId,
		HeaderFromDomain: declared.HeaderFromDomain,
		DkimSelector:     declared.DkimSelector,
		MessageByteCount: declared.MessageByteCount,
		ProofKeySet:      declared.KeySet,
	}
	if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
		sidecarEnd.Close()
		return nil, err
	}
	result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil)
	if err != nil {
		sidecarEnd.Close()
		return nil, err
	}
	opened := &smtpproof.ExportedFs31Opened{Conn: sidecarEnd}
	if result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		sidecarEnd.Close()
		opened.Code = result.GetCode()
		opened.Reason = protocol.SmtpPreambleCode(result.GetCode()).String()
		return opened, nil
	}
	opened.SendId = result.GetSendId()
	opened.HeloName = result.GetHeloName()
	opened.XUrRef = result.GetXUrRef()
	opened.FeedbackId = result.GetFeedbackId()
	opened.MxHost = result.GetMxHost()
	opened.EnvelopeDomain = "b." + fs31EngineLabel + "." + fs31EngineRoot
	opened.Channel = sidecar.NewSmtpProofTestChannel(&fs31EngineCaller{edge: self}, self.edgeClientId, result.GetSendId(), sidecar.DefaultSmtpSenderSettings())
	return opened, nil
}

// Starts the engine on sidecartest's fakes in an MxWorld whose recipient domain's MX is the row's, every preamble's
// session from verifier, and waits until it can answer a preamble OK. The engine ends with the test.
func (self *fs31EngineEdgeWorld) start(ctx context.Context, verifier sidecar.SmtpProofVerifier) error {
	t := self.args.T
	engineCtx, cancel := context.WithCancel(context.Background())
	self.ctx = engineCtx
	self.clock = sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	self.networkId = sidecar.NewId()
	self.edgeClientId = sidecar.NewId()
	self.clientId = sidecar.NewId()
	self.sidecarId = sidecar.NewId()
	if 0 < self.args.ForgeServerFrom && self.args.Version != tls.VersionTLS12 {
		cancel()
		return errors.New("an edge forges records only where their types are public, under TLS 1.2")
	}

	worldSettings := sidecartest.DefaultMxWorldSettings()
	worldSettings.Clock = self.clock
	world, err := sidecartest.NewMxWorld(worldSettings)
	if err != nil {
		cancel()
		return err
	}
	self.world = world
	for _, err := range []error{
		world.SetMx(self.args.RecipientDomain, &sidecar.SmtpMxHost{Preference: 10, Host: self.args.MxHost}),
		world.AddMx(self.args.MxHost, fs31EngineMxAddress, self.args.Mx),
		world.AddMx(fs31EngineHeloName, fs31EngineSendingAddress, nil),
	} {
		if err != nil {
			cancel()
			return err
		}
	}
	world.SetPtr(fs31EngineSendingAddress, fs31EngineHeloName)

	host := sidecartest.NewFakeHost(engineCtx, self.clock, sidecartest.NewFaultQueue(), nil, nil)
	sidecartest.RegisterSmtpQuotaScripts(host.Redis)
	host.Abuse.Set(connect.Id(self.networkId), sidecar.AbuseStandingStandard, true)
	limits := fs31EngineLimits(self.args.RecipientLimit)
	gate := sidecartest.NewFakeSmtpGate()
	gate.SetFacts(self.networkId, &smtpedgeservice.SmtpGateFacts{
		MailEnableTime: self.clock.Now().Add(-48 * time.Hour),
		Label:          fs31EngineLabel,
		ReportToken:    fs31EngineReportToken,
		Limits:         limits,
	})
	gate.SetMailSend(self.networkId, self.sidecarId, true)
	gate.SetBreaker(&smtpedgeservice.SmtpBreakerState{})
	communityLimits := fs31EngineLimits(0)
	communityLimits.Tier = "free"
	gate.SetCommunityLimits(communityLimits)
	host.Quota.SetLimits(connect.Id(self.networkId), limits)
	host.Gates.OpenService(sidecar.ServiceGateSmtpedge, connect.Id(self.networkId))
	host.Quota.SetBalance(connect.Id(self.networkId), 1024*1024*1024)
	self.verifier = &fs31Verifier{verifier: verifier, quit: make(chan struct{})}

	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	settings.Root = fs31EngineRoot
	settings.ReportHostName = "rpt." + fs31EngineRoot
	settings.SendingAddresses = []smtpedgeservice.SmtpSendingAddress{{Address: fs31EngineSendingAddress, HeloName: fs31EngineHeloName}}
	settings.XUrRefKeys = []*smtpedgeservice.SmtpXUrRefKey{{KeyId: 1, Key: bytes.Repeat([]byte{0x5a}, 32)}}
	settings.MxRefusedPrefixes = slices.DeleteFunc(slices.Clone(settings.MxRefusedPrefixes), func(prefix netip.Prefix) bool {
		return prefix == netip.MustParsePrefix("192.0.2.0/24")
	})
	dialer := &fs31EngineDialer{dialer: world, verifier: self.verifier, forgeFrom: self.args.ForgeServerFrom, suite: self.args.Suite}
	self.store = sidecartest.NewFakeSmtpEdgeStore(self.clock, nil)
	service, err := smtpedgeservice.NewSmtpEdgeServiceWithDeps(engineCtx, host.ServiceHost(), self.store, self.verifier, &smtpedgeservice.SmtpEdgeDeps{
		Gate:     gate,
		Resolver: world,
		Dialer:   dialer,
		Ptr:      world,
		Lookups:  self.store,
		Halts:    self.store,
		Sink:     sidecartest.NewFakeSmtpAbuseSink(),
	}, settings)
	if err != nil {
		cancel()
		return err
	}
	self.service = service
	t.Cleanup(func() {
		service.Close()
		world.Wait()
		cancel()
	})
	self.listener = smtpedgeservice.NewSmtpEdgeTestListener(service)
	return self.listener.AwaitStarted(ctx)
}

// One stream to the engine, served as the ur/smtpedge listener serves one admitted on a ticket naming the world's
// network, the sidecar's client and its sidecar, until its connection ends; the sidecar's end is returned.
func (self *fs31EngineEdgeWorld) stream() net.Conn {
	ticketId := make([]byte, 16)
	copy(ticketId, "fs31-ticket")
	now := self.clock.Now()
	ticket := &protocol.SocketTicket{
		TicketId:              ticketId,
		NetworkId:             sidecar.NewId().Bytes(),
		Name:                  smtpedgeservice.SmtpEdgeSocketName,
		ListenerClientId:      self.edgeClientId.Bytes(),
		DialerClientId:        self.clientId.Bytes(),
		DialerNetworkId:       self.networkId.Bytes(),
		DialerSidecarId:       self.sidecarId.Bytes(),
		IssueTimeMillis:       uint64(now.UnixMilli()),
		ExpireTimeMillis:      uint64(now.Add(30 * time.Second).UnixMilli()),
		GrantExpireTimeMillis: uint64(now.Add(time.Hour).UnixMilli()),
	}
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	served := make(chan struct{})
	self.served = served
	self.serving.Add(1)
	go func() {
		defer self.serving.Done()
		defer close(served)
		self.listener.Deliver(edgeEnd, ticket)
	}()
	return sidecarEnd
}

func (self *fs31EngineEdgeWorld) quitForwarded() <-chan struct{} {
	return self.verifier.quit
}

func (self *fs31EngineEdgeWorld) done() <-chan struct{} {
	if self.served == nil {
		closed := make(chan struct{})
		close(closed)
		return closed
	}
	return self.served
}

// Closes the engine, which ends its one connection as any engine's close does.
func (self *fs31EngineEdgeWorld) end() {
	if self.service != nil {
		self.service.Close()
	}
}

func (self *fs31EngineEdgeWorld) wait() {
	self.serving.Wait()
	if self.world != nil {
		self.world.Wait()
	}
}

func (self *fs31EngineEdgeWorld) refusal() error {
	if self.verifier == nil {
		return nil
	}
	return self.verifier.refusal()
}

// The sender's calls landing on the engine's handlers as the listener's dispatcher hands them over, from the client
// the stream's ticket names as dialer.
type fs31EngineCaller struct {
	edge *fs31EngineEdgeWorld
}

func (self *fs31EngineCaller) Call(ctx context.Context, clientId sidecar.Id, messageType protocol.MessageType, body []byte, options *sidecar.CallOptions) ([]byte, error) {
	if clientId != self.edge.edgeClientId {
		return nil, errors.New("a call to a client the ticket does not name")
	}
	return self.edge.listener.Call(ctx, self.edge.clientId, messageType, body)
}

// smtpproof's Verifier as the engine holds it, every session it opens recorded.
type fs31Verifier struct {
	verifier sidecar.SmtpProofVerifier
	// closed once the engine has written the MX the QUIT a session handed it last
	quit     chan struct{}
	quitOnce sync.Once

	stateLock sync.Mutex
	sessions  []*fs31Session
	// the QUIT record a session handed the engine, once it has
	quitRecord []byte
}

// Notes a record the engine wrote the MX, closing quit once it is the QUIT a session handed it.
func (self *fs31Verifier) wroteMx(record []byte) {
	self.stateLock.Lock()
	quitRecord := self.quitRecord
	self.stateLock.Unlock()
	if quitRecord != nil && bytes.Equal(record, quitRecord) {
		self.quitOnce.Do(func() { close(self.quit) })
	}
}

func (self *fs31Verifier) HoldsKeySet(keySet []byte) bool {
	return self.verifier.HoldsKeySet(keySet)
}

func (self *fs31Verifier) NewSmtpProofSession(preamble *sidecar.SmtpProofPreamble) (sidecar.SmtpProofSession, error) {
	session, err := self.verifier.NewSmtpProofSession(preamble)
	if err != nil {
		return nil, err
	}
	recorded := &fs31Session{session: session, verifier: self}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.sessions = append(self.sessions, recorded)
	return recorded, nil
}

// The first refusal of any session the engine opened.
func (self *fs31Verifier) refusal() error {
	self.stateLock.Lock()
	sessions := slices.Clone(self.sessions)
	self.stateLock.Unlock()
	for _, session := range sessions {
		if err := session.refusal(); err != nil {
			return err
		}
	}
	return nil
}

// A session as the engine drives it, its first refusal kept.
type fs31Session struct {
	session  sidecar.SmtpProofSession
	verifier *fs31Verifier

	stateLock sync.Mutex
	err       error
}

// Keeps a call's refusal, and the QUIT record once the gate hands it, the last record it ever forwards.
func (self *fs31Session) keep(forward [][]byte, err error) {
	if 0 < len(forward) {
		if smtpproof.ExportSessionFinished(self.session) {
			func() {
				self.verifier.stateLock.Lock()
				defer self.verifier.stateLock.Unlock()
				if self.verifier.quitRecord == nil {
					self.verifier.quitRecord = bytes.Clone(forward[len(forward)-1])
				}
			}()
		}
	}
	if err == nil {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.err == nil {
		self.err = err
	}
}

func (self *fs31Session) refusal() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.err
}

func (self *fs31Session) ClientRecord(record []byte) ([][]byte, error) {
	forward, err := self.session.ClientRecord(record)
	self.keep(forward, err)
	return forward, err
}

func (self *fs31Session) ServerRecord(record []byte) error {
	err := self.session.ServerRecord(record)
	self.keep(nil, err)
	return err
}

func (self *fs31Session) ServerClosed() {
	self.session.ServerClosed()
}

func (self *fs31Session) DiscloseShts(shts []byte) ([][]byte, error) {
	forward, err := self.session.DiscloseShts(shts)
	self.keep(forward, err)
	return forward, err
}

func (self *fs31Session) VerifyPart(ctx context.Context, part *sidecar.SmtpProofPart) ([][]byte, error) {
	forward, err := self.session.VerifyPart(ctx, part)
	self.keep(forward, err)
	return forward, err
}

func (self *fs31Session) MailForwarded() bool {
	return self.session.MailForwarded()
}

// The MX as the engine dials it: each record the engine writes noted for the verifier, and, for a malicious edge
// (fs31EdgeArgs.forgeServerFrom), what the MX sends forged from the chosen application record on.
type fs31EngineDialer struct {
	dialer    sidecar.SmtpMxDialer
	verifier  *fs31Verifier
	forgeFrom int
	suite     uint16
}

func (self *fs31EngineDialer) DialMx(ctx context.Context, sendingAddress netip.Addr, mxAddress netip.Addr) (net.Conn, error) {
	conn, err := self.dialer.DialMx(ctx, sendingAddress, mxAddress)
	if err != nil {
		return nil, err
	}
	return smtpproof.ExportFs31MxConn(conn, self.forgeFrom, self.suite, false, self.verifier.wroteMx), nil
}

// The sidecar's own sender's dialer onto a world's engine: each stream as the ur/smtpedge listener hands one over, and
// its calls and outcome landing on the engine's handlers from the client the ticket names.
type fs31EngineSenderDialer struct {
	edge *fs31EngineEdgeWorld
}

func (self *fs31EngineSenderDialer) DialSmtpEdge(ctx context.Context) (sidecar.SmtpEdgeStream, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &fs31EngineSenderStream{Conn: self.edge.stream(), edge: self.edge}, nil
}

type fs31EngineSenderStream struct {
	net.Conn
	edge *fs31EngineEdgeWorld
}

func (self *fs31EngineSenderStream) ProofChannel(sendId []byte) sidecar.SmtpProofChannel {
	return sidecar.NewSmtpProofTestChannel(&fs31EngineCaller{edge: self.edge}, self.edge.edgeClientId, sendId, sidecar.DefaultSmtpSenderSettings())
}

func (self *fs31EngineSenderStream) SendOutcome(ctx context.Context, outcome *protocol.SmtpOutcome) error {
	body, err := proto.Marshal(outcome)
	if err != nil {
		return err
	}
	return self.edge.service.AcceptOutcome(self.edge.clientId, body)
}

func (self *fs31EngineSenderStream) Abort() error {
	return self.Conn.Close()
}

// An in-memory keychain namespace, for the sender's DKIM keys.
type fs31Secrets struct {
	stateLock sync.Mutex
	values    map[string][]byte
}

func (self *fs31Secrets) Get(name string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.values[name]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

func (self *fs31Secrets) Put(name string, value []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.values[name] = bytes.Clone(value)
	return nil
}

func (self *fs31Secrets) Delete(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.values, name)
	return nil
}

func (self *fs31Secrets) List(prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	names := []string{}
	for name := range self.values {
		if strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	return names, nil
}

// POST /smtp/dkim-keys answering every publish.
type fs31Publisher struct{}

func (self fs31Publisher) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result := &sidecar.SmtpDkimKeysResult{}
	for _, publish := range args.Publish {
		result.Published = append(result.Published, publish.Selector)
	}
	return result, nil
}

// One message from the world's network to bob, sent by the sidecar's own SmtpSender through the world's engine, the
// sender's prover this package's Prover under keySet, whose Verifier the engine holds. The MX's own certificate lets
// it through only by the message's TL4 allowance, as an unauthenticated ScriptedMx can be sent to at all.
func fs31SendThroughTheEngine(t *testing.T, edge *fs31EngineEdgeWorld, keySet *smtpproof.RelationKeySet) *sidecar.SmtpDomainOutcome {
	t.Helper()
	settings := sidecar.DefaultSmtpSenderSettings()
	store := sidecartest.NewFakeStore()
	anchors, err := sidecar.NewSmtpDnssecAnchors(edge.world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	zone := sidecartest.NewFakeMailZone(edge.clock)
	pins := sidecar.NewSmtpPinStore(store.Root(), settings, edge.clock, nil)
	policy := sidecar.NewSmtpTlsPolicy(sidecar.NewSmtpDane(anchors, edge.clock, nil),
		sidecar.NewSmtpMtaSts(zone, edge.world.MtaStsTransport(), store.Root(), settings, edge.clock), pins,
		sidecar.NewSmtpTlsAllowanceStore(store.Root(), settings, edge.clock), nil, zone, nil, settings, edge.clock)
	sender, err := sidecar.NewSmtpSender(&sidecar.SmtpSenderArgs{
		Dialer:   &fs31EngineSenderDialer{edge: edge},
		Prover:   keySet.NewProver(nil),
		Measure:  func() *sidecar.SmtpProverMeasure { return &sidecar.SmtpProverMeasure{DataProofBytes: 1024 * 1024} },
		Policy:   policy,
		Pins:     pins,
		Dkim:     sidecar.NewSmtpDkimKeys(&fs31Secrets{values: map[string][]byte{}}, fs31Publisher{}, settings, edge.clock, nil),
		Mailbox:  sidecartest.NewFakeSmtpMailbox(nil),
		Settings: settings,
		Clock:    edge.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sender.Close)
	ctx, cancel := context.WithTimeout(context.Background(), fs31EngineGuardTimeout)
	defer cancel()
	networkDomain := fs31EngineLabel + "." + fs31EngineRoot
	result, err := sender.Send(ctx, &sidecar.SmtpOutboundMessage{
		EffectKey:  bytes.Repeat([]byte{0x31}, 32),
		SendId:     sidecar.NewId(),
		Sender:     "bounce-1@b." + networkDomain,
		Recipients: []string{"bob@" + edge.args.RecipientDomain},
		Message: []byte("From: alice@" + networkDomain + "\r\nTo: bob@" + edge.args.RecipientDomain + "\r\nSubject: through the engine\r\n" +
			"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@" + networkDomain + ">\r\n\r\nA body line.\r\n"),
		Tl4Domains: []string{edge.args.RecipientDomain},
		CreateTime: edge.clock.Now(),
	})
	if err != nil || len(result.Domains) != 1 {
		t.Fatalf("the send: %+v, %v", result, err)
	}
	return result.Domains[0]
}

// FS-31's last clause from the sender's side: an honest TLS 1.2 MX answers the message 451 while the edge forges 250
// for it. The edge holds no key, so its forgery is a record sealed under a key of its own, and it reads nothing of the
// MX's replies; it cannot tell the 451 it replaced from a 250. The sidecar's own SmtpSender, through the real engine
// over this package's Prover under a relation key set, keeps the message, deferred to a retry and never sent, and the
// MX took no transaction. The control beside it, the same world with an honest edge and an MX taking the message,
// sends it.
func TestFs31TheSenderKeepsAMessageTheEdgeForgedSent(t *testing.T) {
	for _, forged := range []bool{false, true} {
		script := sidecartest.DefaultMxScript()
		forgeFrom := 0
		if forged {
			script.MessageReply = "451 4.3.0 Try again later"
			// EHLO's, MAIL's and bob's RCPT's replies, then the chunk's
			forgeFrom = smtpproof.ExportFs31MessageReplyIndex(false, 1)
		}
		mx, err := sidecartest.NewScriptedMx("mx.recipient.example", script, &sidecartest.ScriptedMxSettings{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		})
		if err != nil {
			t.Fatal(err)
		}
		keySet, err := smtpproof.NewRelationKeySet()
		if err != nil {
			t.Fatal(err)
		}
		edge := &fs31EngineEdgeWorld{args: &smtpproof.ExportedFs31EdgeArgs{
			T:               t,
			Mx:              mx,
			Version:         tls.VersionTLS12,
			Suite:           tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			ForgeServerFrom: forgeFrom,
			RecipientDomain: "recipient.example",
			MxHost:          "mx.recipient.example",
		}}
		ctx, cancel := context.WithTimeout(context.Background(), fs31EngineGuardTimeout)
		if err := edge.start(ctx, keySet.NewVerifier(nil)); err != nil {
			cancel()
			t.Fatal(err)
		}
		cancel()
		outcome := fs31SendThroughTheEngine(t, edge, keySet)
		// the send's connection has ended by now; the MX's, once the engine closes, which an MX left waiting on a
		// refused chunk needs
		edge.end()
		edge.wait()
		transactions := mx.Transactions()
		if !forged {
			if outcome.Outcome != sidecar.SmtpOutcomeSent || len(transactions) != 1 || len(keySet.Refusals()) != 0 {
				t.Errorf("an honest edge: %+v, %d transactions, refusals %v", outcome, len(transactions), keySet.Refusals())
			}
			continue
		}
		if outcome.Outcome != sidecar.SmtpOutcomeDeferred || outcome.RetryAfter <= 0 || outcome.ReplyCode == 250 {
			t.Errorf("a forged 250: %+v", outcome)
		}
		if len(transactions) != 0 {
			t.Errorf("a forged 250: the MX took %d transactions", len(transactions))
		}
		replied451 := false
		for _, event := range mx.Events() {
			replied451 = replied451 || (event.Secure && strings.HasPrefix(event.Reply, "451"))
		}
		if !replied451 {
			t.Error("a forged 250: the MX never answered the chunk")
		}
	}
}
