//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// §15's receive path on T2 in one process (MAIL-M7-27; §22.4, §22.7's S7 and privacy harness, FS-13, FS-121): what S7,
// the mail privacy rows and the receive-side schedules compose, each of its parts its owner's code as it ships.
//
//	router    mxedgeservice's router role (MAIL-M7-19) on the world's FakeHost: its FakeRedis holds {mxr_<label>} as
//	          server's projection writes it and the fleet's closed-handshake memory, its FakeMxEdgeStore the
//	          mail_connection_record rows, its gate is open for the network and its Quota holds a balance. The
//	          ClientHello is read through tlsedgeservice, as server's host wires it (mxedgehost.NewEngineDeps)
//	open      the router's Find and open are a test's dialer: each open hands the receiver's end of an in-memory
//	          stream, the hello first as StreamOpen's early data, to the TLS front's test listener with a ticket the
//	          router's network signed and the router's MailIngress as the open's metadata, which is all §9.6's
//	          admission gives a receiver (SOCK-M5-13's dialer and §6's streams are their owners')
//	receiver  a test front ends TLS on a certificate for mx.<label>.<root> and hands the connection to the receiver's
//	          MailSessionServer (MAIL-M7-14) as MailReceiver does once its key serves; the receiver's listen, key,
//	          TLSA wait and admission are MailReceiver's (MAIL-M7-13), which only a Sidecar's own key store can build
//	checks    the session's reception-time checks (MAIL-M7-08, MAIL-M7-09) over the world's FakeMailZone, on the
//	          world's clock, so a selector's delay or a 30 s deadline moves only when a test moves it
//	deposit   the receiver's MailDepositor through EvsRepo.Deposit into evsservice's engine on the same host, on a
//	          deposit-only token, sealed to FakeGkm's drop key of the mailbox (§11.12)
//	ingest    the owner's consented device reads the deposits with MailIngestor (MAIL-M7-15) on its own EvsClient,
//	          writing m/ and i/ in one push and consuming them, under an authority that reads the world's rows
//
// What M8's composed runs add (MAIL-M8-10), each off unless a test's settings ask for it:
//
//	identity  the network, the member, the mailbox and the owner's and receiver's keys a test gives, so the world lines
//	          up with a network of the test's own, an AdmissionNet's log whose devices hold those keys
//	mailcfg   the network's mailcfg repo beside the mailbox, which the owner's device writes and every reader and the
//	          receiver read, and the session's Resolve a test gives, as the mail component resolves over mailcfg
//	hold      the router's own settings, such as its wake hold, the Push its host gives it, and a dialer that answers
//	          a refusal first, as a lapsed receiver's missing registration does; the route names the receiver, as
//	          model.ProjectMailRoutes writes it once the receiver's key is published (plan-MAIL-hints #2)
//	devices   DeviceOf: an evs client of a device whose key the world does not hold, a running Sidecar's
//	stores    the Redis and blob clusters the router, evs's engine, the mailbox's group objects and the world's own
//	          writes run on, by service, which a scenario's run gives so one builder runs on T2's fakes and on T3's
//	          real stores (MailWorldSettings.Stores); every other part of the host stays the fake host's
//
// Several worlds may share one clock, each on a host of its own: each step waits for every wait it means, its own and
// none another world's (AwaitTimerCountAt).
//
// The session runs on a clock of its own that a test moves only on purpose, so the world's clock moving for a check, a
// STARTTLS's quiet time or the evs engine never ends a session for idleness. Nothing sleeps: a step waits on a pipe, a
// timer it saw armed, or the session's reply.
//
// What a world names is synthetic: .example names and RFC 5737 and 3849 addresses (connect/CODESTYLE.md's test data
// rule). Only the sidecar_testhooks build has it, since the front's test listener is a testhooks type. It is a package of
// its own, not sidecartest's, since evs's engine's own tests import sidecartest and this world imports the engine.

package mailworld

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// What a MailWorld is built with.
type MailWorldSettings struct {
	// The user root and the network's label: mx.<label>.<root> is the receivers' host.
	Root  string
	Label string
	// The mailbox's addresses, which the session's resolver takes; every other address is unknown, 550 5.1.1.
	Addresses []string
	// GET /sidecar/limits' receiver keys.
	Limits map[string]int64
	// mxedge.yml's banner name and published deviation.
	BannerHostName string
	DeviationUrl   string
	// The engine's probe interval: 1,000 h, so after its first probe the router probes again only at the UTC date change,
	// which no test reaches. A probe whose 1 s store timeout a test's clock jump passes would mark the router not ready
	// for the next session, and the router's readiness is MAIL-M7-19's to test, not the composed path's.
	ProbeInterval time.Duration
	// The balance the network's Quota holds.
	QuotaBalanceByteCount int64
	// The receiver's checks; nil takes DefaultMailAuthSettings.
	Auth *sidecar.MailAuthSettings
	// How long one step may wait in real time before the test fails: a bound on a hang, never a pause.
	StepTimeout time.Duration
	// The network, the mailbox's owner and the mailbox, and the owner's device and the receiver, which a test sets to
	// line the world up with a network of its own, an AdmissionNet's log whose devices hold these keys; zero or nil
	// makes fresh ones.
	NetworkId sidecar.Id
	MemberId  sidecar.Id
	RepoId    sidecar.Id
	Owner     *sidecartest.FakeGkmSigner
	Receiver  *sidecartest.FakeGkmSigner
	// The network's mailcfg repo (§15.7), which the owner's device writes and every reader and the receiver read; zero
	// for none, as S7's world has.
	MailConfigRepoId sidecar.Id
	// How the receiver's session resolves a recipient, as the mail component resolves it over mailcfg; nil resolves
	// Addresses alone, each to the mailbox.
	Resolve func(ctx context.Context, address string) (*sidecar.MailSessionRecipient, error)
	// The router's settings past the world's own, such as its wake hold (§15.6's step 5); nil changes none.
	Router func(settings *mxedgeservice.MxEdgeSettings)
	// The Push the router's host gives it, which its wake hold hints through; nil keeps the host's.
	Push sidecar.Push
	// What the router's Find and open answer before a stream opens, a *sidecar.SocketCodeError as the dialer answers
	// one, as a lapsed receiver's missing registration does; nil, or a nil answer, opens.
	DialRefusal func(request *mxedgeservice.MxEdgeDialRequest) error
	// The host whose Redis and blob clusters a service of the world runs on: MailWorldServiceEvs for evs's engine,
	// MailWorldServiceMxedge for the router, and MailWorldServiceWorld for what the world writes itself in another's
	// stead, the route as model's projection writes it and each repo's place and repo objects and the mailbox's
	// group objects as evs's create and gkm write them. nil, or a nil answer, keeps the fake host's own, T2's; a
	// scenario gives its run's hosts, which are server's stores on T3. Every other part of a host stays the fake
	// host's: its gates, quota, authenticator, push and metrics.
	Stores func(service string) *sidecar.ServiceHost
	// Told of each request a device's client sent evs and the answer it took, its status and body, on the device's
	// goroutine, as M10's rows read a push's refusal (m10_rows.go); nil for none.
	EvsAnswered func(request *http.Request, status int, body []byte)
}

// The services MailWorldSettings.Stores is asked for.
const (
	MailWorldServiceEvs    = "evs"
	MailWorldServiceMxedge = "mxedge"
	MailWorldServiceWorld  = ""
)

func DefaultMailWorldSettings() *MailWorldSettings {
	return &MailWorldSettings{
		Root:      "root.example",
		Label:     "lbl0000001",
		Addresses: []string{"ann@lbl0000001.root.example"},
		Limits: map[string]int64{
			"mail_inbound_message_bytes": 50 * 1024 * 1024, "mail_inbound_recipients": 100, "mail_inbound_repos_per_message": 8,
		},
		BannerHostName:        "mx.banner.example",
		DeviationUrl:          "https://deviation.example/rfc3207",
		ProbeInterval:         1000 * time.Hour,
		QuotaBalanceByteCount: 1 << 40,
		StepTimeout:           30 * time.Second,
	}
}

// The receivers' host name the world's SNI names.
func (self *MailWorldSettings) MxHost() string {
	return "mx." + self.Label + "." + self.Root
}

// The world. Safe for concurrent use.
type MailWorld struct {
	t        testing.TB
	ctx      context.Context
	settings *MailWorldSettings

	Clock *sidecartest.FakeClock
	// The session's own clock, which a test moves only on purpose.
	SessionClock *sidecartest.FakeClock
	Host         *sidecartest.FakeHost
	Cluster      sidecar.BlobCluster

	NetworkId sidecar.Id
	RepoId    sidecar.Id
	MemberId  sidecar.Id
	ClientId  sidecar.Id
	// The network's mailcfg repo, zero where the world has none.
	MailConfigRepoId sidecar.Id
	// The urnetwork-edge network the router's tickets name.
	EdgeNetworkId sidecar.Id

	Owner    *sidecartest.FakeGkmSigner
	Receiver *sidecartest.FakeGkmSigner
	// The receiver's deposit-only client, which the session's depositor writes through.
	ReceiverEvs *sidecar.EvsClient
	View        *sidecartest.FakeGkmAuthView
	Gkm         *sidecartest.FakeGkm
	Engine      *evsservice.EvsEngine

	Zone    *sidecartest.FakeMailZone
	Session *sidecar.MailSessionServer
	Router  *mxedgeservice.MxEdgeService
	Records *sidecartest.FakeMxEdgeStore
	// The receiver's certificate's SPKI SHA-256.
	SpkiSha256 [sha256.Size]byte

	front     *sidecar.TlsFrontTestListener
	listener  *mailWorldListener
	serverTls *tls.Config
	log       *mailWorldLog

	authLog *sidecartest.FakeGkmAuthLog

	stateLock sync.Mutex
	// every reader device's id, the owner's first, and the signers of those admitted after it
	readerIds     []sidecar.Id
	readerSigners []*sidecartest.FakeGkmSigner
	// every gkm client a device of the world holds, each advanced to every newer view
	gkmClients []sidecar.GkmClient
	// what each open carried and what each side of its stream moved, in order
	opens []*MailWorldOpen
	// each sender's socket, under its MTA's TLS once STARTTLS runs, by its MTA
	senderConns map[*sidecartest.ScriptedMta]net.Conn
}

// One stream the router opened to the receiver: its MailIngress and the bytes each side wrote, as each end saw them.
type MailWorldOpen struct {
	Ingress *protocol.MailIngress
	// the hello the router read, which rode StreamOpen as early data
	HelloBytes []byte
	// what reached the receiver after the hello, and what the receiver wrote back, as each end of the stream saw it
	ToReceiver *bytes.Buffer
	ToSender   *bytes.Buffer
	stateLock  sync.Mutex
}

func (self *MailWorldOpen) bytesOf(buffer *bytes.Buffer) []byte {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(buffer.Bytes())
}

// What the receiver read after the hello.
func (self *MailWorldOpen) ReceiverRead() []byte {
	return self.bytesOf(self.ToReceiver)
}

// What the receiver wrote.
func (self *MailWorldOpen) ReceiverWrote() []byte {
	return self.bytesOf(self.ToSender)
}

// A log that keeps every line, for a scan.
type mailWorldLog struct {
	stateLock sync.Mutex
	lines     []string
}

func (self *mailWorldLog) keep(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

func (self *mailWorldLog) Info(args ...any)                 { self.keep(fmt.Sprint(args...)) }
func (self *mailWorldLog) Infof(format string, args ...any) { self.keep(fmt.Sprintf(format, args...)) }
func (self *mailWorldLog) Warningf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}
func (self *mailWorldLog) Errorf(format string, args ...any) { self.keep(fmt.Sprintf(format, args...)) }
func (self *mailWorldLog) V(level int32) sidecar.Verbose     { return &mailWorldVerbose{log: self} }

type mailWorldVerbose struct {
	log *mailWorldLog
}

func (self *mailWorldVerbose) Enabled() bool                    { return true }
func (self *mailWorldVerbose) Info(args ...any)                 { self.log.Info(args...) }
func (self *mailWorldVerbose) Infof(format string, args ...any) { self.log.Infof(format, args...) }

// The fake host as service's engine takes it, its Redis and blob clusters those MailWorldSettings.Stores names for
// the service.
func (self *MailWorld) serviceHost(service string) *sidecar.ServiceHost {
	host := self.Host.ServiceHost()
	if self.settings.Stores != nil {
		if stores := self.settings.Stores(service); stores != nil {
			host.Blobs = stores.Blobs
			host.Redis = stores.Redis
		}
	}
	return host
}

// The host's urnetwork_mxedge_ metric lines.
func (self *MailWorld) mxedgeMetrics() []string {
	lines := []string{}
	for _, line := range self.Host.Metrics.Dump() {
		if strings.Contains(line, "mxedge") {
			lines = append(lines, line)
		}
	}
	return lines
}

// Every line the router and the session logged.
func (self *MailWorld) LogLines() []string {
	self.log.stateLock.Lock()
	defer self.log.stateLock.Unlock()
	return slices.Clone(self.log.lines)
}

// evs's view of the world: every principal matches its binding and every scope it carries is honored, its token
// holding only what the world issued it, deposit alone for the receiver.
type mailWorldEvsAuth struct {
	world *MailWorld
}

func (self *mailWorldEvsAuth) CheckRevocation(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

func (self *mailWorldEvsAuth) MatchBinding(principal *sidecar.Principal) evsservice.EvsAuthAnswer {
	return evsservice.EvsAuthAllowed
}

func (self *mailWorldEvsAuth) HonorScope(principal *sidecar.Principal, repoId sidecar.Id, rights sidecar.AclEvsRights, now time.Time) evsservice.EvsAuthAnswer {
	if repoId != self.world.RepoId && (repoId != self.world.MailConfigRepoId || repoId == (sidecar.Id{})) {
		return evsservice.EvsAuthDenied
	}
	return evsservice.EvsAuthAllowed
}

func (self *mailWorldEvsAuth) Repo(principal *sidecar.Principal, repoId sidecar.Id) (*evsservice.EvsRepoFacts, evsservice.EvsAuthAnswer) {
	switch {
	case repoId == self.world.RepoId:
		return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_MAILBOX, NetworkId: self.world.NetworkId, OwnerMemberId: self.world.MemberId}, evsservice.EvsAuthAllowed
	case repoId == self.world.MailConfigRepoId && repoId != (sidecar.Id{}):
		return &evsservice.EvsRepoFacts{Kind: protocol.RepoKind_REPO_KIND_MAILCFG, NetworkId: self.world.NetworkId}, evsservice.EvsAuthAllowed
	}
	return nil, evsservice.EvsAuthDenied
}

// evs's push gate's view: the world's newest rows.
type mailWorldGateViews struct {
	world *MailWorld
}

func (self *mailWorldGateViews) View(networkId sidecar.Id) (sidecar.GkmAuthView, evsservice.EvsAuthAnswer) {
	if networkId != self.world.NetworkId {
		return nil, evsservice.EvsAuthUnknown
	}
	return self.world.view(), evsservice.EvsAuthAllowed
}

func (self *MailWorld) view() *sidecartest.FakeGkmAuthView {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.View
}

// Ingest's authority over the world's rows: a reader device ingests the mailbox, and the receiver's deposits are mail.
type mailWorldIngestAuthority struct {
	world *MailWorld
}

func (self *mailWorldIngestAuthority) Ingests(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return repoId == self.world.RepoId && slices.Contains(self.world.ReaderIds(), sidecarId)
}

func (self *mailWorldIngestAuthority) DepositorClass(repoId sidecar.Id, depositorId sidecar.Id, pin *bridge.AuthPin) sidecar.MailDepositorClass {
	if repoId != self.world.RepoId {
		return sidecar.MailDepositorUnknown
	}
	if depositorId == self.world.Receiver.SidecarId {
		return sidecar.MailDepositorMail
	}
	return sidecar.MailDepositorNone
}

func (self *mailWorldIngestAuthority) MaySendAs(signerSidecarId sidecar.Id, fromAddress string) bool {
	return false
}

// The router's side of a stream, and the receiver's: two io.Pipes, each end recording what crossed it.
type mailWorldStream struct {
	reader io.Reader
	closer *io.PipeReader
	writer *io.PipeWriter
	// what this end wrote, kept
	written *bytes.Buffer
	open    *MailWorldOpen
}

func (self *mailWorldStream) Read(b []byte) (int, error) { return self.reader.Read(b) }

func (self *mailWorldStream) Write(b []byte) (int, error) {
	n, err := self.writer.Write(b)
	if self.written != nil {
		// what crossed, never what the other end refused
		self.open.stateLock.Lock()
		self.written.Write(b[:n])
		self.open.stateLock.Unlock()
	}
	return n, err
}

func (self *mailWorldStream) CloseWrite() error { return self.writer.Close() }

func (self *mailWorldStream) Close() error {
	self.writer.Close()
	return self.closer.Close()
}

func (self *mailWorldStream) Reset(code protocol.StreamResetCode) error {
	self.writer.CloseWithError(errors.New("stream reset"))
	return self.closer.CloseWithError(errors.New("stream reset"))
}

func (self *mailWorldStream) SetReadDeadline(t time.Time) error  { return nil }
func (self *mailWorldStream) SetWriteDeadline(t time.Time) error { return nil }

// The Find and open: the world's K client ids, and each open handed to the receiver's front.
type mailWorldDialer struct {
	world     *MailWorld
	clientIds []sidecar.Id
}

func (self *mailWorldDialer) ClientIds() []sidecar.Id { return slices.Clone(self.clientIds) }
func (self *mailWorldDialer) Ready() bool             { return true }

func (self *mailWorldDialer) Dial(ctx context.Context, request *mxedgeservice.MxEdgeDialRequest) (mxedgeservice.MxEdgeStream, uint64, error) {
	world := self.world
	if request.NetworkId != world.NetworkId || request.Name != "smtp/25/mx" {
		return nil, 0, &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}
	}
	if refusal := world.settings.DialRefusal; refusal != nil {
		if err := refusal(request); err != nil {
			return nil, 0, err
		}
	}
	metadata, err := request.Metadata(0)
	if err != nil {
		return nil, 0, err
	}
	ingress := &protocol.MailIngress{}
	if err := proto.Unmarshal(metadata, ingress); err != nil {
		return nil, 0, err
	}
	open := &MailWorldOpen{Ingress: ingress, HelloBytes: bytes.Clone(request.HelloBytes), ToReceiver: &bytes.Buffer{}, ToSender: &bytes.Buffer{}}
	toReceiverReader, toReceiverWriter := io.Pipe()
	toRouterReader, toRouterWriter := io.Pipe()
	// what the receiver reads after the hello, as it reads it
	receiverReader := io.TeeReader(toReceiverReader, &mailWorldLocked{open: open, buffer: open.ToReceiver})
	receiverEnd := &mailWorldStream{
		reader: io.MultiReader(bytes.NewReader(slices.Clone(request.HelloBytes)), receiverReader),
		closer: toReceiverReader, writer: toRouterWriter, written: open.ToSender, open: open,
	}
	routerEnd := &mailWorldStream{reader: toRouterReader, closer: toRouterReader, writer: toReceiverWriter, open: open}
	ticket := &protocol.SocketTicket{DialerNetworkId: world.EdgeNetworkId.Bytes(), Name: request.Name}
	if !world.front.Deliver(receiverEnd, ticket, metadata) {
		return nil, 0, &sidecar.SocketCodeError{Err: sidecar.ErrSocketUnavailable}
	}
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.opens = append(world.opens, open)
	}()
	return routerEnd, 0, nil
}

// A buffer an open's lock guards.
type mailWorldLocked struct {
	open   *MailWorldOpen
	buffer *bytes.Buffer
}

func (self *mailWorldLocked) Write(b []byte) (int, error) {
	self.open.stateLock.Lock()
	defer self.open.stateLock.Unlock()
	return self.buffer.Write(b)
}

// Every open so far.
func (self *MailWorld) Opens() []*MailWorldOpen {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.opens)
}

// The lb's side of TCP 25: each connection a test makes is the server's end of a pipe, reporting the sender's address
// as the PROXY listener would.
type mailWorldListener struct {
	conns     chan net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (self *mailWorldListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *mailWorldListener) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return nil
}

func (self *mailWorldListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.25"), Port: 25}
}

type mailWorldServerConn struct {
	net.Conn
	sender net.Addr
}

func (self *mailWorldServerConn) RemoteAddr() net.Addr { return self.sender }

// A self-signed P-256 leaf for names, valid around now.
func mailWorldCertificate(names []string, now time.Time) (*tls.Certificate, [sha256.Size]byte, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(15),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	spki, err := x509.MarshalPKIXPublicKey(privateKey.Public())
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	return &tls.Certificate{Certificate: [][]byte{certificateBytes}, PrivateKey: privateKey}, sha256.Sum256(spki), nil
}

// The world on host and clock: evs's engine, the mailbox's group and place, the receiver's session over its depositor
// and checks, and the router serving the world's listener, ready once its first probe has found the store and today's
// k. A nil settings takes the defaults.
func NewMailWorld(t testing.TB, host *sidecartest.FakeHost, clock *sidecartest.FakeClock, settings *MailWorldSettings) *MailWorld {
	t.Helper()
	if settings == nil {
		settings = DefaultMailWorldSettings()
	}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	world := &MailWorld{
		t: t, ctx: ctx, settings: settings, Clock: clock, SessionClock: sidecartest.NewFakeClock(clock.Now()), Host: host,
		NetworkId: settings.NetworkId, RepoId: settings.RepoId, MemberId: settings.MemberId, ClientId: sidecar.NewId(), EdgeNetworkId: sidecar.NewId(),
		MailConfigRepoId: settings.MailConfigRepoId,
		Owner:            settings.Owner, Receiver: settings.Receiver, Zone: sidecartest.NewFakeMailZone(clock), Records: sidecartest.NewFakeMxEdgeStore(nil),
		log: &mailWorldLog{}, listener: &mailWorldListener{conns: make(chan net.Conn), closed: make(chan struct{})},
	}
	for _, id := range []*sidecar.Id{&world.NetworkId, &world.RepoId, &world.MemberId} {
		if *id == (sidecar.Id{}) {
			*id = sidecar.NewId()
		}
	}
	if world.Owner == nil {
		world.Owner = sidecartest.NewFakeGkmSigner()
	}
	if world.Receiver == nil {
		world.Receiver = sidecartest.NewFakeGkmSigner()
	}
	world.readerIds = []sidecar.Id{world.Owner.SidecarId}
	world.buildEvs()
	world.buildSession()
	world.buildRouter()
	return world
}

// evs's engine on the host, the mailbox's group in sidecartest.FakeGkm and its place and repo objects.
func (self *MailWorld) buildEvs() {
	t := self.t
	host := self.Host
	sidecartest.RegisterEvsTwins(host.Redis)
	host.Gates.OpenService(sidecar.ServiceGateEvs, connect.Id(self.NetworkId))
	host.Quota.SetBalance(connect.Id(self.NetworkId), self.settings.QuotaBalanceByteCount)
	evsHost := self.serviceHost(MailWorldServiceEvs)
	worldHost := self.serviceHost(MailWorldServiceWorld)
	cluster, err := worldHost.Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	self.Cluster = cluster
	self.authLog = sidecartest.NewFakeGkmAuthLog()
	self.View = self.authLog.Append(self.fixture())
	self.Gkm = sidecartest.NewFakeGkm(self.Clock, worldHost.Blobs, nil)
	ownerGkm := self.Gkm.Client(self.Owner.SidecarId, self.Owner.Sign)
	ownerGkm.AuthAdvanced(self.View)
	self.gkmClients = append(self.gkmClients, ownerGkm)
	memberId := self.MemberId
	if _, err := ownerGkm.CreateGroup(self.ctx, &sidecar.GkmCreateGroupArgs{RepoId: self.RepoId, Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: &memberId}); err != nil {
		t.Fatal(err)
	}
	if self.MailConfigRepoId != (sidecar.Id{}) {
		// mailcfg names no owner (§8.8's RepoCreate row): its first generation goes to every reader the view names
		if _, err := ownerGkm.CreateGroup(self.ctx, &sidecar.GkmCreateGroupArgs{RepoId: self.MailConfigRepoId, Kind: protocol.RepoKind_REPO_KIND_MAILCFG}); err != nil {
			t.Fatal(err)
		}
	}
	usage, err := evsservice.NewUsageBatcher(self.ctx, evsHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(usage.Close)
	quota, err := evsservice.NewQuotaGate(self.ctx, evsHost, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(quota.Close)
	receiptKey := sha256.Sum256([]byte("mail world receipt key"))
	receiptKeys, err := evsservice.NewReceiptKeys([]*evsservice.ReceiptKey{{KeyId: 1, Key: receiptKey[:], IssueFrom: self.Clock.Now().Add(-48 * time.Hour)}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	evsSettings := evsservice.DefaultEvsSettings()
	evsSettings.BatchFlushDelay = 0
	evsSettings.PushUnknownRereadInterval = 0
	evsSettings.RepoCacheTtl = 0
	self.Engine, err = evsservice.NewEvsEngine(self.ctx, evsHost, evsSettings, &evsservice.EvsEngineDeps{
		AuthState: &mailWorldEvsAuth{world: self},
		Uploads:   &evsservice.EvsUploadDeps{Keys: receiptKeys, Quota: quota, Usage: usage},
		GateViews: &mailWorldGateViews{world: self},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(self.Engine.Close)
	self.putRepo(self.RepoId, protocol.RepoKind_REPO_KIND_MAILBOX, self.MemberId.Bytes())
	if self.MailConfigRepoId != (sidecar.Id{}) {
		self.putRepo(self.MailConfigRepoId, protocol.RepoKind_REPO_KIND_MAILCFG, nil)
	}
}

// A repo's place and repo objects on the world's cluster, as evs's create writes them, the owner's device its creator.
func (self *MailWorld) putRepo(repoId sidecar.Id, kind protocol.RepoKind, ownerMemberIdBytes []byte) {
	t := self.t
	inspect := sidecartest.InspectContext(self.ctx)
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: self.Cluster.ClusterId(), CreatorSidecarId: self.Owner.SidecarId}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.Cluster.PutIfNoneMatch(inspect, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		t.Fatal(err)
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: kind, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: self.NetworkId.Bytes(), OwnerMemberId: ownerMemberIdBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := self.Cluster.PutIfNoneMatch(inspect, evsservice.RepoKey(repoId), repoBytes, nil); err != nil {
		t.Fatal(err)
	}
}

// The rows the world's view compiles: the mailbox, its owner's devices, every reader one, the owner its admin and the
// receiver a device of the member that only deposits; and where the world has one, mailcfg, which the readers write
// and the receiver reads too, as a member device policy grants the receiver's listen reads it (§15.7).
func (self *MailWorld) fixture() *sidecartest.FakeGkmAuthFixture {
	self.stateLock.Lock()
	readerIds := slices.Clone(self.readerIds)
	readerSigners := slices.Clone(self.readerSigners)
	self.stateLock.Unlock()
	repos := []*protocol.AclRepo{{
		RepoId: self.RepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILBOX, OwnerMemberId: self.MemberId.Bytes(),
		Admins: []*protocol.AclRepoAdminRow{{SidecarId: self.Owner.SidecarId.Bytes()}},
	}}
	repoReaders := map[sidecar.Id][]sidecar.Id{self.RepoId: readerIds}
	repoWriters := map[sidecar.Id][]sidecar.Id{self.RepoId: readerIds}
	if self.MailConfigRepoId != (sidecar.Id{}) {
		repos = append(repos, &protocol.AclRepo{RepoId: self.MailConfigRepoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_MAILCFG})
		repoReaders[self.MailConfigRepoId] = append(slices.Clone(readerIds), self.Receiver.SidecarId)
		repoWriters[self.MailConfigRepoId] = slices.Clone(readerIds)
	}
	rows := sidecartest.FakeGkmAuthRows(repos...)
	sidecarRows, member := sidecartest.FakeGkmAuthMemberDevices(self.MemberId, append(slices.Clone(readerIds), self.Receiver.SidecarId)...)
	rows.Sidecars = sidecarRows
	rows.Members = []*bridge.MemberRow{member}
	identityKeys := map[sidecar.Id][]byte{self.Receiver.SidecarId: self.Receiver.PublicKey()}
	for _, signer := range readerSigners {
		identityKeys[signer.SidecarId] = signer.PublicKey()
	}
	identityKeys[self.Owner.SidecarId] = self.Owner.PublicKey()
	return &sidecartest.FakeGkmAuthFixture{
		Rows:         rows,
		IdentityKeys: identityKeys,
		RepoReaders:  repoReaders,
		RepoWriters:  repoWriters,
	}
}

// The reader devices' ids, the owner's first.
func (self *MailWorld) ReaderIds() []sidecar.Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.readerIds)
}

// The devices' transport: the engine's handler, its step 8s waited out after each push.
func (self *MailWorld) RoundTrip(request *http.Request) (*http.Response, error) {
	recorder := httptest.NewRecorder()
	self.Engine.Handler().ServeHTTP(recorder, request)
	if strings.HasSuffix(request.URL.Path, "/push") {
		for {
			started, finished, changed := self.Engine.StepEights()
			if started == finished {
				break
			}
			select {
			case <-changed:
			case <-self.ctx.Done():
				return nil, self.ctx.Err()
			}
		}
	}
	if answered := self.settings.EvsAnswered; answered != nil {
		answered(request, recorder.Code, recorder.Body.Bytes())
	}
	return recorder.Result(), nil
}

// An evs client of signer on the world, its tokens holding the scopes it asks for, or deposit alone, as the exchange
// mints a deposit-only sidecar's, on clock, the world's when nil, over store.
func (self *MailWorld) Device(signer *sidecartest.FakeGkmSigner, depositOnly bool, store sidecar.SidecarStore, clock sidecar.Clock) *sidecar.EvsClient {
	self.t.Helper()
	return self.DeviceOf(signer.SidecarId, signer.PublicKey(), signer.Sign, depositOnly, store, clock)
}

// An evs client as Device makes one, for a device whose key the world does not hold: a running Sidecar of the test,
// which sign is (Sidecar.Sign), its identity key's public half publicKey. The world's view names only its own devices,
// so such a client's pushes and gkm calls are judged as a stranger's.
func (self *MailWorld) DeviceOf(sidecarId sidecar.Id, publicKey []byte, sign sidecar.GkmSignFunction, depositOnly bool, store sidecar.SidecarStore, clock sidecar.Clock) *sidecar.EvsClient {
	self.t.Helper()
	if clock == nil {
		clock = self.Clock
	}
	gkmClient := self.Gkm.Client(sidecarId, sign)
	gkmClient.AuthAdvanced(self.view())
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.gkmClients = append(self.gkmClients, gkmClient)
	}()
	identity := &sidecar.SidecarIdentity{NetworkId: self.NetworkId, SidecarId: sidecarId, ClientId: self.ClientId, Generation: 1, IdentityPublicKey: publicKey}
	client, err := sidecar.NewEvsClient(&sidecar.EvsClientArgs{
		NetworkId: self.NetworkId,
		EvsUrl:    "https://evs.example",
		Transport: self,
		ServiceToken: func(ctx context.Context, resource string, scopes []string) (string, error) {
			if depositOnly {
				scopes = []string{"repo:" + self.RepoId.String() + ":deposit"}
			}
			connectSidecarId := connect.Id(sidecarId)
			return self.Host.Authenticator.Issue(&sidecar.Principal{
				NetworkId: connect.Id(self.NetworkId), ClientId: connect.Id(self.ClientId), SidecarId: &connectSidecarId,
				Audience: evsservice.EvsAudience, Scopes: scopes, IssuedAt: self.Clock.Now(), ExpiresAt: self.Clock.Now().Add(15 * time.Minute),
			}), nil
		},
		Sign:     sidecar.EvsSignFunction(sign),
		Identity: func() *sidecar.SidecarIdentity { return identity },
		Gkm:      gkmClient,
		Store:    store,
		Config:   func() sidecar.GkmAuthView { return self.view() },
		Clock:    clock,
		Log:      sidecar.NewNoopLogger(),
		Settings: sidecar.DefaultEvsSettings(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	self.t.Cleanup(client.Close)
	return client
}

// The receiver's session: the world's addresses, limits and status, its checks over the zone on the world's clock, its
// deposits on a deposit-only client, and the test front that ends TLS and hands it each stream.
func (self *MailWorld) buildSession() {
	t := self.t
	self.ReceiverEvs = self.Device(self.Receiver, true, sidecartest.NewFakeStore().Root(), nil)
	depositor, err := sidecar.NewMailDepositor(&sidecar.MailDepositorArgs{Repo: self.ReceiverEvs.Repo, ReceiverSidecarId: self.Receiver.SidecarId})
	if err != nil {
		t.Fatal(err)
	}
	authSettings := self.settings.Auth
	if authSettings == nil {
		authSettings = sidecar.DefaultMailAuthSettings()
	}
	addresses := map[string]bool{}
	for _, address := range self.settings.Addresses {
		addresses[strings.ToLower(address)] = true
	}
	resolve := self.settings.Resolve
	if resolve == nil {
		resolve = func(ctx context.Context, address string) (*sidecar.MailSessionRecipient, error) {
			if !addresses[strings.ToLower(address)] {
				return &sidecar.MailSessionRecipient{}, nil
			}
			return &sidecar.MailSessionRecipient{Known: true, Address: strings.ToLower(address), RepoId: self.RepoId}, nil
		}
	}
	self.Session, err = sidecar.NewMailSessionServer(&sidecar.MailSessionArgs{
		ReceiverSidecarId: self.Receiver.SidecarId,
		Resolve:           resolve,
		PostmasterDomain: func(ctx context.Context) (string, error) {
			return self.settings.Label + "." + self.settings.Root, nil
		},
		Status: func(ctx context.Context) (*sidecar.MailNetworkStatus, error) {
			return &sidecar.MailNetworkStatus{Enabled: true}, nil
		},
		Limits: func(ctx context.Context) (*sidecar.QuotaLimits, error) {
			return &sidecar.QuotaLimits{Tier: "pro", Limits: self.settings.Limits}, nil
		},
		Checker:    sidecar.NewMailAuthChecker(sidecar.NewMailDnsStub(self.Zone, self.Clock, authSettings), self.Clock, authSettings),
		Slots:      sidecar.NewMailAuthSlots(authSettings),
		Depositor:  depositor,
		SpoolStore: sidecartest.NewFakeStore().Root(),
		Clock:      self.SessionClock,
		Log:        self.log,
	})
	if err != nil {
		t.Fatal(err)
	}
	certificate, spkiSha256, err := mailWorldCertificate([]string{"*." + self.settings.Label + "." + self.settings.Root, self.settings.Label + "." + self.settings.Root}, self.Clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	self.SpkiSha256 = spkiSha256
	self.serverTls = &tls.Config{Certificates: []tls.Certificate{*certificate}, MinVersion: tls.VersionTLS12}
	self.front = sidecar.NewTlsFrontTestListener(self.EdgeNetworkId)
	t.Cleanup(func() { self.front.Close() })
	go self.serveFront()
}

// The receiver's front: each admitted stream's handshake on the receiver's certificate, then its session, until the
// listener closes.
func (self *MailWorld) serveFront() {
	for {
		conn, err := self.front.AcceptSocket(self.ctx)
		if err != nil {
			return
		}
		go func() {
			tlsConn := tls.Server(conn, self.serverTls)
			if err := tlsConn.HandshakeContext(self.ctx); err != nil {
				tlsConn.Close()
				return
			}
			self.Session.Serve(self.ctx, &sidecar.MailReceiverStream{Conn: conn, Tls: tlsConn, SpkiSha256: self.SpkiSha256})
		}()
	}
}

// The router on the host: its route in FakeRedis as server's projection writes it, the gate open for the network and
// its K clients the dialer's.
func (self *MailWorld) buildRouter() {
	t := self.t
	host := self.Host
	host.Gates.OpenService(sidecar.ServiceGateMxedge, connect.Id(self.NetworkId))
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = self.settings.BannerHostName
	settings.DeviationUrl = self.settings.DeviationUrl
	settings.RouteRootDomainName = self.settings.Root
	settings.ReadyProbeInterval = self.settings.ProbeInterval
	// the batches wait for the engine's last write, at its close, or a test's Advance past it
	settings.RecordFlushInterval = 1000 * time.Hour
	if self.settings.Router != nil {
		self.settings.Router(settings)
	}
	dialer := &mailWorldDialer{world: self}
	for range settings.Clients {
		dialer.clientIds = append(dialer.clientIds, sidecar.NewId())
	}
	// the receiver's key is published, so the route names it (plan-MAIL-hints #2), as model.ProjectMailRoutes writes it
	routeValue, err := json.Marshal(&mxedgeservice.MailRoute{
		NetworkId: self.NetworkId, Label: self.settings.Label, Host: "mx", ReceiverSidecarIds: []sidecar.Id{self.Receiver.SidecarId},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := self.serviceHost(MailWorldServiceWorld).Redis.Set(sidecartest.InspectContext(self.ctx), mxedgeservice.MailRouteKey(self.settings.Label), routeValue, 0); err != nil {
		t.Fatal(err)
	}
	serviceHost := self.serviceHost(MailWorldServiceMxedge)
	if self.settings.Push != nil {
		serviceHost.Push = self.settings.Push
	}
	gates := serviceHost.GatesOrClosed()
	deps := &mxedgeservice.MxEdgeDeps{
		ReadClientHello: func(conn net.Conn, maxByteCount int) (*mxedgeservice.MxClientHello, error) {
			hello, err := tlsedgeservice.ReadClientHello(conn, maxByteCount)
			if err != nil {
				return nil, err
			}
			return &mxedgeservice.MxClientHello{ServerName: hello.ServerName, RawBytes: hello.RawBytes}, nil
		},
		NormalizeSni: tlsedgeservice.NormalizeSni,
		WriteTlsAlert: func(conn net.Conn, alert mxedgeservice.MxTlsAlert) error {
			return tlsedgeservice.WriteTlsAlert(conn, tlsedgeservice.TlsAlertCode(alert))
		},
		GateOpen: func() bool {
			return gates.Service(sidecar.ServiceGateMxedge).Enabled()
		},
		GateAdmits: func(networkId sidecar.Id) bool {
			return gates.Service(sidecar.ServiceGateMxedge).Admits(connect.Id(networkId))
		},
		Clock: self.Clock,
		Log:   self.log,
	}
	start := self.Clock.Now()
	// the first probe has found the store and made today's k once its next wait is armed
	// at the interval, or the UTC date change if that comes first: one more wait there than before the router, since
	// another world's router on the same clock may wait there already
	nextProbe := start.Add(self.settings.ProbeInterval)
	if dayChange := start.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour); dayChange.Before(nextProbe) {
		nextProbe = dayChange
	}
	waitsBefore := self.timerCountAt(nextProbe)
	self.Router, err = mxedgeservice.NewMxEdgeRouterService(self.ctx, serviceHost, self.Records, deps, &mxedgeservice.MxEdgeRouterDeps{
		Dialer: dialer,
		// a documentation address has no PTR; the lookups still run, as the host's resolver's would
		LookupPtr:  func(ctx context.Context, sender netip.Addr) ([]string, error) { return nil, nil },
		LookupHost: func(ctx context.Context, name string) ([]netip.Addr, error) { return nil, nil },
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(self.Router.Close)
	self.AwaitTimerCountAt(nextProbe, waitsBefore+1)
	if !self.Router.Ready() {
		t.Fatal("the router is not ready")
	}
	go self.Router.Serve(self.listener)
	t.Cleanup(func() { self.listener.Close() })
}

// The world's settings.
func (self *MailWorld) Settings() *MailWorldSettings {
	return self.settings
}

// Waits until a timer of the world's clock is set for at, so a step moves the clock only once the wait it means is
// armed.
func (self *MailWorld) AwaitTimerAt(at time.Time) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.StepTimeout)
	defer cancel()
	for {
		pending, added := self.Clock.WatchTimers()
		if slices.ContainsFunc(pending, at.Equal) {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("no timer was set for %v", at)
		}
	}
}

// How many of the clock's timers are set for at.
func (self *MailWorld) timerCountAt(at time.Time) int {
	pending, _ := self.Clock.WatchTimers()
	count := 0
	for _, timer := range pending {
		if timer.Equal(at) {
			count += 1
		}
	}
	return count
}

// Waits until count of the clock's timers are set for at: a step that moves the clock waits for every wait it means.
func (self *MailWorld) AwaitTimerCountAt(at time.Time, count int) {
	self.t.Helper()
	ctx, cancel := context.WithTimeout(self.ctx, self.settings.StepTimeout)
	defer cancel()
	for {
		pending, added := self.Clock.WatchTimers()
		found := 0
		for _, timer := range pending {
			if timer.Equal(at) {
				found += 1
			}
		}
		if count <= found {
			return
		}
		select {
		case <-added:
		case <-ctx.Done():
			self.t.Fatalf("%d of %d timers were set for %v", found, count, at)
		}
	}
}

// A sender's connection through the lb to the router, from sender.
func (self *MailWorld) Connect(sender netip.Addr) *sidecartest.ScriptedMta {
	self.t.Helper()
	return self.keepSender(self.connect(sender))
}

// A sender's connection as Connect makes it, every byte it writes and reads kept, as the sender's socket saw them.
func (self *MailWorld) ConnectRecorded(sender netip.Addr) (*sidecartest.ScriptedMta, *MailWorldRecording) {
	self.t.Helper()
	recording := &MailWorldRecording{Conn: self.connect(sender)}
	return self.keepSender(recording), recording
}

// An MTA on conn, its socket kept for Finish.
func (self *MailWorld) keepSender(conn net.Conn) *sidecartest.ScriptedMta {
	mta := sidecartest.NewScriptedMta(conn)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.senderConns == nil {
		self.senderConns = map[*sidecartest.ScriptedMta]net.Conn{}
	}
	self.senderConns[mta] = conn
	return mta
}

// Ends mta's session as a sender does after its last reply: QUIT, then its TLS read to the receiver's close_notify,
// then its socket read until the router closes it, which the router does only once the session has ended, its lease
// and caps given back and its record queued. So a test that moves the clock next moves it past no live session.
func (self *MailWorld) Finish(mta *sidecartest.ScriptedMta) {
	self.t.Helper()
	conn := func() net.Conn {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		conn := self.senderConns[mta]
		delete(self.senderConns, mta)
		return conn
	}()
	if quit, err := mta.Quit(); err == nil && quit.Is(221) {
		// the receiver's close_notify and the stream's end, so everything the receiver wrote has crossed
		io.Copy(io.Discard, mta.Conn())
	}
	if conn == nil {
		return
	}
	closed := make(chan struct{})
	go func() {
		defer close(closed)
		io.Copy(io.Discard, conn)
	}()
	select {
	case <-closed:
	case <-time.After(self.settings.StepTimeout):
		self.t.Fatal("the router never closed the sender's socket")
	}
}

func (self *MailWorld) connect(sender netip.Addr) net.Conn {
	self.t.Helper()
	serverConn, clientConn := net.Pipe()
	self.t.Cleanup(func() { clientConn.Close() })
	select {
	case self.listener.conns <- &mailWorldServerConn{Conn: serverConn, sender: net.TCPAddrFromAddrPort(netip.AddrPortFrom(sender, 40025))}:
	case <-time.After(self.settings.StepTimeout):
		self.t.Fatal("the router never accepted")
	}
	return clientConn
}

// A sender's socket that keeps every byte it wrote and read.
type MailWorldRecording struct {
	net.Conn

	stateLock sync.Mutex
	written   bytes.Buffer
	read      bytes.Buffer
}

func (self *MailWorldRecording) Read(b []byte) (int, error) {
	n, err := self.Conn.Read(b)
	self.stateLock.Lock()
	self.read.Write(b[:n])
	self.stateLock.Unlock()
	return n, err
}

func (self *MailWorldRecording) Write(b []byte) (int, error) {
	n, err := self.Conn.Write(b)
	self.stateLock.Lock()
	self.written.Write(b[:n])
	self.stateLock.Unlock()
	return n, err
}

// Every byte the sender wrote, and every byte it read.
func (self *MailWorldRecording) Bytes() (written []byte, read []byte) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return bytes.Clone(self.written.Bytes()), bytes.Clone(self.read.Bytes())
}

// The banner and the pre-TLS EHLO.
func (self *MailWorld) Greet(mta *sidecartest.ScriptedMta, ehloName string) {
	self.t.Helper()
	if reply, err := mta.Banner(); err != nil || !reply.Is(220) {
		self.t.Fatalf("the banner: %s %v", reply, err)
	}
	if reply, err := mta.Ehlo(ehloName); err != nil || !reply.Is(250) {
		self.t.Fatalf("EHLO before TLS: %s %v", reply, err)
	}
}

// STARTTLS, its 220 once the router's quiet time has passed on the world's clock, and the handshake under config.
func (self *MailWorld) StartTls(mta *sidecartest.ScriptedMta, config *tls.Config) (*tls.ConnectionState, error) {
	self.t.Helper()
	quietAt := self.Clock.Now().Add(mxedgeservice.DefaultMxEdgeSettings().StartTlsQuietTimeout)
	type outcome struct {
		state *tls.ConnectionState
		err   error
	}
	done := make(chan outcome, 1)
	go func() {
		state, err := mta.StartTls(config)
		done <- outcome{state: state, err: err}
	}()
	self.AwaitTimerAt(quietAt)
	self.Clock.Advance(quietAt.Sub(self.Clock.Now()))
	select {
	case result := <-done:
		return result.state, result.err
	case <-time.After(self.settings.StepTimeout):
		self.t.Fatal("STARTTLS never finished")
		return nil, nil
	}
}

// One message from sender through the router to the receiver over TLS naming sni, a whole transaction: the reply to
// its end of DATA, or the first reply before it that was not 250.
func (self *MailWorld) Send(sender netip.Addr, sni string, from string, recipients []string, message []byte) *sidecartest.MailReply {
	self.t.Helper()
	return self.SendWith(&MailWorldSend{Sender: sender, Sni: sni, From: from, Recipients: recipients, Message: message})
}

// One transaction as SendWith makes it.
type MailWorldSend struct {
	Sender netip.Addr
	// The ClientHello's server name; empty sends none.
	Sni  string
	From string
	// MAIL's parameters after the reverse path, such as REQUIRETLS; empty for none.
	FromParameters string
	Recipients     []string
	Message        []byte
	// The sender's socket, recorded: set by SendWith when Record is.
	Record    bool
	Recording *MailWorldRecording
}

// One transaction as send says, through the router: the reply to its end of DATA, or the first reply before it that
// was not 250. The sender then ends its session (Finish).
func (self *MailWorld) SendWith(send *MailWorldSend) *sidecartest.MailReply {
	self.t.Helper()
	mta, refused := self.begin(send)
	defer mta.Close()
	if refused != nil {
		return refused
	}
	reply, err := mta.Data(send.Message)
	if err != nil {
		self.t.Fatalf("DATA: %v", err)
	}
	self.Finish(mta)
	return reply
}

// A transaction as send says, up to its DATA: the dialog, STARTTLS, EHLO, MAIL and every RCPT, each answered 250, the
// sender's MTA returned for the test to send DATA itself, as a test that moves the clock during the checks does. A
// reply that is not 250 fails the test. The caller ends the session with Finish, or closes the MTA.
func (self *MailWorld) Begin(send *MailWorldSend) *sidecartest.ScriptedMta {
	self.t.Helper()
	mta, refused := self.begin(send)
	if refused != nil {
		mta.Close()
		self.t.Fatalf("the transaction before DATA: %s", refused)
	}
	return mta
}

// The transaction up to DATA, and the first reply to MAIL or RCPT that was not 250, nil when each was.
func (self *MailWorld) begin(send *MailWorldSend) (*sidecartest.ScriptedMta, *sidecartest.MailReply) {
	self.t.Helper()
	var mta *sidecartest.ScriptedMta
	if send.Record {
		mta, send.Recording = self.ConnectRecorded(send.Sender)
	} else {
		mta = self.Connect(send.Sender)
	}
	self.Greet(mta, "relay.sender.example")
	if _, err := self.StartTls(mta, sidecartest.MailMtaTlsConfig(send.Sni, tls.VersionTLS13)); err != nil {
		// the router's result words say why it closed the handshake; its log and metrics hold no address (I-13)
		self.t.Fatalf("STARTTLS: %v; the router's metrics: %s; its log: %s", err, strings.Join(self.mxedgeMetrics(), " | "), strings.Join(self.LogLines(), " | "))
	}
	if reply, err := mta.Ehlo("relay.sender.example"); err != nil || !reply.Is(250) {
		self.t.Fatalf("EHLO inside TLS: %s %v", reply, err)
	}
	mailCommand := "MAIL FROM:<" + send.From + ">"
	if send.FromParameters != "" {
		mailCommand += " " + send.FromParameters
	}
	reply, err := mta.Command(mailCommand)
	if err != nil {
		self.t.Fatalf("MAIL: %v", err)
	}
	if !reply.Is(250) {
		return mta, reply
	}
	for _, recipient := range send.Recipients {
		reply, err := mta.RcptTo(recipient)
		if err != nil {
			self.t.Fatalf("RCPT: %v", err)
		}
		if !reply.Is(250) {
			return mta, reply
		}
	}
	return mta, nil
}

// Erase's authority over the world's rows: the owner's device administers the mailbox, as its RepoAdmin row says.
type mailWorldEraseAuthority struct {
	world *MailWorld
}

func (self *mailWorldEraseAuthority) Erases(repoId sidecar.Id, sidecarId sidecar.Id) bool {
	return repoId == self.world.RepoId && sidecarId == self.world.Owner.SidecarId
}

// An eraser of the mailbox on client, a device's, on the world's clock.
func (self *MailWorld) Eraser(client *sidecar.EvsClient, sidecarId sidecar.Id) *sidecar.MailEraser {
	self.t.Helper()
	eraser, err := sidecar.NewMailEraser(&sidecar.MailEraserArgs{
		Repo:      client.Repo(self.RepoId),
		SidecarId: sidecarId,
		Authority: &mailWorldEraseAuthority{world: self},
		Clock:     self.Clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return eraser
}

// Adds a reader device to the mailbox, as a consented device admitted later would be: a new view naming it, which
// every client and the engine then read. Its signer.
func (self *MailWorld) AdmitReader() *sidecartest.FakeGkmSigner {
	signer := sidecartest.NewFakeGkmSigner()
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.readerIds = append(self.readerIds, signer.SidecarId)
		self.readerSigners = append(self.readerSigners, signer)
	}()
	view := self.authLog.Append(self.fixture())
	clients := func() []sidecar.GkmClient {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.View = view
		return slices.Clone(self.gkmClients)
	}()
	for _, client := range clients {
		client.AuthAdvanced(view)
	}
	return signer
}

// An ingestor of the mailbox on client, a reader device's, on the world's clock: each message its push wrote to
// message and each alarm to alarm, either nil for none.
func (self *MailWorld) Ingestor(client *sidecar.EvsClient, sidecarId sidecar.Id, message func(message *sidecar.MailMessage), alarm func(alarm *sidecar.MailIngestAlarm)) *sidecar.MailIngestor {
	self.t.Helper()
	ingestor, err := sidecar.NewMailIngestor(&sidecar.MailIngestArgs{
		Repo:      client.Repo(self.RepoId),
		SidecarId: sidecarId,
		Root:      self.settings.Root,
		Authority: &mailWorldIngestAuthority{world: self},
		Message:   message,
		Alarm:     alarm,
		Clock:     self.Clock,
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return ingestor
}

// The deposits the receiver has standing, each split as ingest splits it: the message and its MailDeposit, read by
// client, a reader device's. Nothing is consumed.
func (self *MailWorld) StandingDeposits(client *sidecar.EvsClient) ([]*MailWorldDeposit, error) {
	deposits := []*MailWorldDeposit{}
	err := client.Repo(self.RepoId).ReadDeposits(self.ctx, self.Receiver.SidecarId, 0, func(deposit *sidecar.EvsDeposit, body io.Reader) error {
		plaintext, err := io.ReadAll(body)
		if err != nil {
			return err
		}
		message, trailer, err := MailWorldSplitDeposit(plaintext)
		if err != nil {
			return err
		}
		deposits = append(deposits, &MailWorldDeposit{Deposit: deposit, Message: message, Trailer: trailer})
		return nil
	})
	return deposits, err
}

// One deposit as a reader opens it.
type MailWorldDeposit struct {
	Deposit *sidecar.EvsDeposit
	Message []byte
	Trailer *protocol.MailDeposit
}

// A deposit's plaintext split as MAIL-FORMAT.md writes it: the message, its MailDeposit, u32be of that encoding's
// length.
func MailWorldSplitDeposit(plaintext []byte) ([]byte, *protocol.MailDeposit, error) {
	if len(plaintext) < 4 {
		return nil, nil, errors.New("a deposit too short to hold its trailer")
	}
	trailerByteCount := int(uint32(plaintext[len(plaintext)-4])<<24 | uint32(plaintext[len(plaintext)-3])<<16 | uint32(plaintext[len(plaintext)-2])<<8 | uint32(plaintext[len(plaintext)-1]))
	if len(plaintext)-4 < trailerByteCount {
		return nil, nil, errors.New("a deposit's trailer past its body")
	}
	trailer := &protocol.MailDeposit{}
	if err := proto.Unmarshal(plaintext[len(plaintext)-4-trailerByteCount:len(plaintext)-4], trailer); err != nil {
		return nil, nil, err
	}
	return plaintext[:len(plaintext)-4-trailerByteCount], trailer, nil
}
