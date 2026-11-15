package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/mxedgeservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/tlsedgeservice"
)

// The census's synthetic names: the root, a test network's label and its inbox addresses.
const (
	censusTestRoot  = "root.example"
	censusTestLabel = "ab12cd34ef"
	censusTestSni   = "mx." + censusTestLabel + "." + censusTestRoot
)

// A self-signed certificate for the test receiver's mail host.
func censusTestCertificate(t *testing.T, now time.Time) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: censusTestSni},
		DNSNames:     []string{censusTestSni},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
	}
	certificateBytes, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certificateBytes}, PrivateKey: privateKey}
}

// One end of a stream to the receiver, over two io.Pipes.
type censusTestStream struct {
	reader *io.PipeReader
	writer *io.PipeWriter
}

func (self *censusTestStream) Read(b []byte) (int, error)  { return self.reader.Read(b) }
func (self *censusTestStream) Write(b []byte) (int, error) { return self.writer.Write(b) }
func (self *censusTestStream) CloseWrite() error           { return self.writer.Close() }
func (self *censusTestStream) Close() error {
	self.writer.Close()
	return self.reader.Close()
}
func (self *censusTestStream) Reset(code protocol.StreamResetCode) error {
	self.writer.CloseWithError(errors.New("reset"))
	return self.reader.CloseWithError(errors.New("reset"))
}
func (self *censusTestStream) SetReadDeadline(t time.Time) error  { return nil }
func (self *censusTestStream) SetWriteDeadline(t time.Time) error { return nil }

// The receiver's side of a stream: the early data first, then what the router splices.
type censusTestReceiverConn struct {
	net.Conn
	reader io.Reader
	writer *io.PipeWriter
}

func (self *censusTestReceiverConn) Read(b []byte) (int, error)  { return self.reader.Read(b) }
func (self *censusTestReceiverConn) Write(b []byte) (int, error) { return self.writer.Write(b) }
func (self *censusTestReceiverConn) Close() error                { return self.writer.Close() }

// The test network's receiver: TLS ended on its own certificate, then just enough SMTP to take a message,
// noting what it took as a receiver's view does.
type censusTestReceiver struct {
	certificate tls.Certificate
	clock       *sidecartest.FakeClock
	clientIds   []sidecar.Id

	stateLock sync.Mutex
	received  []*CensusReceived
	sessions  sync.WaitGroup
}

func (self *censusTestReceiver) ClientIds() []sidecar.Id { return self.clientIds }
func (self *censusTestReceiver) Ready() bool             { return true }

func (self *censusTestReceiver) Dial(ctx context.Context, request *mxedgeservice.MxEdgeDialRequest) (mxedgeservice.MxEdgeStream, uint64, error) {
	toReceiverReader, toReceiverWriter := io.Pipe()
	toRouterReader, toRouterWriter := io.Pipe()
	conn := &censusTestReceiverConn{
		Conn:   &net.TCPConn{},
		reader: io.MultiReader(bytes.NewReader(slices.Clone(request.HelloBytes)), toReceiverReader),
		writer: toRouterWriter,
	}
	self.sessions.Add(1)
	go func() {
		defer self.sessions.Done()
		defer toRouterWriter.Close()
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{self.certificate}, Time: self.clock.Now})
		if err := server.Handshake(); err != nil {
			return
		}
		state := server.ConnectionState()
		reader := bufio.NewReader(server)
		recipient := ""
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			verb := strings.ToUpper(strings.Fields(line + " ")[0])
			switch verb {
			case "EHLO":
				server.Write([]byte("250-receiver\r\n250 SMTPUTF8\r\n"))
			case "MAIL":
				server.Write([]byte("250 2.1.0 Ok\r\n"))
			case "RCPT":
				recipient = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(line[len("RCPT TO:"):]), "<"), ">")
				server.Write([]byte("250 2.1.5 Ok\r\n"))
			case "DATA":
				server.Write([]byte("354 Go ahead\r\n"))
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if line == ".\r\n" {
						break
					}
				}
				func() {
					self.stateLock.Lock()
					defer self.stateLock.Unlock()
					self.received = append(self.received, &CensusReceived{
						Recipient: recipient, Time: self.clock.Now(), Sni: state.ServerName, TlsVersion: state.Version,
					})
				}()
				server.Write([]byte("250 2.0.0 Taken\r\n"))
			case "QUIT":
				server.Write([]byte("221 2.0.0 Bye\r\n"))
				return
			default:
				server.Write([]byte("502 5.5.1 Not here\r\n"))
			}
		}
	}()
	return &censusTestStream{reader: toRouterReader, writer: toReceiverWriter}, 0, nil
}

// What the receiver took.
func (self *censusTestReceiver) Received() []*CensusReceived {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return slices.Clone(self.received)
}

// A listener a test feeds.
type censusTestListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func (self *censusTestListener) Accept() (net.Conn, error) {
	select {
	case conn := <-self.conns:
		return conn, nil
	case <-self.closed:
		return nil, net.ErrClosed
	}
}

func (self *censusTestListener) Close() error {
	self.once.Do(func() { close(self.closed) })
	return nil
}

func (self *censusTestListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("192.0.2.25"), Port: 25}
}

// The server's end of a sender's pipe, reporting the sender the PROXY listener would, and saying when the
// router closed it: the session's counters are written by then.
type censusTestServerConn struct {
	net.Conn
	sender    net.Addr
	closed    chan struct{}
	closeOnce sync.Once
}

func (self *censusTestServerConn) RemoteAddr() net.Addr { return self.sender }

func (self *censusTestServerConn) Close() error {
	self.closeOnce.Do(func() { close(self.closed) })
	return self.Conn.Close()
}

// A router on fake stores, the test receiver behind it, and the census's view of its counters.
type censusTestWorld struct {
	t        *testing.T
	ctx      context.Context
	clock    *sidecartest.FakeClock
	host     *sidecartest.FakeHost
	settings *mxedgeservice.MxEdgeSettings
	engine   *mxedgeservice.MxEdgeService
	receiver *censusTestReceiver
	listener *censusTestListener
}

func newCensusTestWorld(t *testing.T) *censusTestWorld {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	networkId := sidecar.NewId()
	host.Quota.SetBalance(connect.Id(networkId), 64*1024*1024)
	route, err := json.Marshal(&mxedgeservice.MailRoute{NetworkId: networkId, Label: censusTestLabel, Host: "mx"})
	if err != nil {
		t.Fatal(err)
	}
	if err := host.Redis.Set(sidecartest.InspectContext(ctx), mxedgeservice.MailRouteKey(censusTestLabel), route, 0); err != nil {
		t.Fatal(err)
	}
	settings := mxedgeservice.DefaultMxEdgeSettings()
	settings.BannerHostName = "mx.report.example"
	settings.DeviationUrl = "https://deviation.example/rfc3207"
	settings.RouteRootDomainName = censusTestRoot
	settings.StartTlsQuietTimeout = 37 * time.Millisecond
	// parked, so a minute's move of the clock runs no probe whose store timeout the same move would cut
	settings.ReadyProbeInterval = 1000 * time.Hour
	settings.RecordFlushInterval = 1000 * time.Hour
	receiver := &censusTestReceiver{certificate: censusTestCertificate(t, clock.Now()), clock: clock}
	for range settings.Clients {
		receiver.clientIds = append(receiver.clientIds, sidecar.NewId())
	}
	engine, err := mxedgeservice.NewMxEdgeRouterService(ctx, host.ServiceHost(), sidecartest.NewFakeMxEdgeStore(nil), &mxedgeservice.MxEdgeDeps{
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
		GateOpen:   func() bool { return true },
		GateAdmits: func(sidecar.Id) bool { return true },
		Clock:      clock,
	}, &mxedgeservice.MxEdgeRouterDeps{Dialer: receiver}, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	world := &censusTestWorld{
		t: t, ctx: ctx, clock: clock, host: host, settings: settings, engine: engine, receiver: receiver,
		listener: &censusTestListener{conns: make(chan net.Conn), closed: make(chan struct{})},
	}
	// the first probe made today's key once its next wait, the date change, is armed
	now := clock.Now().UTC()
	world.awaitTimerAt(time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, time.UTC))
	if !engine.Ready() {
		t.Fatal("the router is not ready")
	}
	go engine.Serve(world.listener)
	return world
}

// Waits until a timer at exactly at is pending, with no sleep.
func (self *censusTestWorld) awaitTimerAt(at time.Time) {
	self.t.Helper()
	for {
		pending, added := self.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(timer time.Time) bool { return timer.Equal(at) }) {
			return
		}
		select {
		case <-added:
		case <-self.ctx.Done():
			self.t.Fatal("no timer at", at)
		}
	}
}

// A scripted sender on a new connection from sender, and a channel that closes once the router has ended its
// session.
func (self *censusTestWorld) connect(sender string) (*sidecartest.ScriptedMta, <-chan struct{}) {
	self.t.Helper()
	serverConn, clientConn := net.Pipe()
	self.t.Cleanup(func() { clientConn.Close() })
	conn := &censusTestServerConn{Conn: serverConn, sender: &net.TCPAddr{IP: net.ParseIP(sender), Port: 2525}, closed: make(chan struct{})}
	self.listener.conns <- conn
	return sidecartest.NewScriptedMta(clientConn), conn.closed
}

// One TLS attempt from sender, naming sni ("" for none): STARTTLS, its quiet period on the fake clock,
// the handshake, and when it holds, one message to recipient. Whether the message was taken.
func (self *censusTestWorld) sendWithTls(sender string, sni string, recipient string) bool {
	self.t.Helper()
	mta, ended := self.connect(sender)
	defer func() { <-ended }()
	if reply, err := mta.Banner(); err != nil || !reply.Is(220) {
		self.t.Fatalf("banner %v %v", reply, err)
	}
	if reply, err := mta.Ehlo("relay.sender.example"); err != nil || !reply.Is(250) {
		self.t.Fatalf("EHLO %v %v", reply, err)
	}
	quietAt := self.clock.Now().Add(self.settings.StartTlsQuietTimeout)
	started := make(chan error, 1)
	go func() {
		_, err := mta.StartTls(sidecartest.MailMtaTlsConfig(sni, tls.VersionTLS13))
		started <- err
	}()
	self.awaitTimerAt(quietAt)
	self.clock.Advance(self.settings.StartTlsQuietTimeout)
	if err := <-started; err != nil {
		// a closed handshake, as a sender with no SNI meets one
		mta.Close()
		return false
	}
	if reply, err := mta.Ehlo("relay.sender.example"); err != nil || !reply.Is(250) {
		self.t.Fatalf("EHLO inside TLS %v %v", reply, err)
	}
	mta.MailFrom("sender@relay.sender.example")
	mta.RcptTo(recipient)
	reply, err := mta.Data([]byte("Subject: census\r\n\r\nA sign-up code.\r\n"))
	mta.Quit()
	mta.Close()
	return err == nil && reply.Is(250)
}

// A plaintext retry from sender: MAIL's reply code.
func (self *censusTestWorld) sendPlaintext(sender string) int {
	self.t.Helper()
	mta, ended := self.connect(sender)
	defer func() { <-ended }()
	mta.Banner()
	mta.Ehlo("relay.sender.example")
	reply, err := mta.PlaintextTransaction("sender@relay.sender.example")
	if err != nil {
		self.t.Fatal(err)
	}
	mta.Quit()
	mta.Close()
	return reply.Code
}

// The router's counters as a scrape would give them.
func (self *censusTestWorld) snapshot() *CensusCounterSnapshot {
	snapshot := &CensusCounterSnapshot{Time: self.clock.Now(), Series: map[string]float64{}}
	settings := DefaultCensusSettings()
	results := append(slices.Clone(censusClosedHandshakeResults), "splice_closed", "splice_sender_reset", "splice_receiver_reset")
	for _, result := range results {
		snapshot.Series[censusSeriesName(settings.SessionsSeries, result)] = self.host.Metrics.Value(settings.SessionsSeries, result)
	}
	for _, result := range censusPlaintextResults {
		snapshot.Series[censusSeriesName(settings.PlaintextSeries, result)] = self.host.Metrics.Value(settings.PlaintextSeries, result)
	}
	return snapshot
}

// The census over ScriptedMta senders through the router: senders with and without SNI give the right
// loss, weighted and not; a plaintext fallback after a closed handshake counts once; report senders are
// left out of the bar; and the table holds no address.
func TestCensusOnScriptedSenders(t *testing.T) {
	world := newCensusTestWorld(t)
	type plannedSend struct {
		send *CensusSend
		// the sender's address, which only the router sees
		address string
		sni     string
		// plaintext retries after a closed handshake
		retries int
		// whether it sends at all
		silent bool
	}
	planned := []*plannedSend{
		{send: &CensusSend{Sender: "signup-alpha", Kind: CensusKindSignup, Rank: 1, Asn: 64500, Recipient: "census-1@" + censusTestSni}, address: "203.0.113.10", sni: censusTestSni},
		{send: &CensusSend{Sender: "signup-bravo", Kind: CensusKindSignup, Rank: 2, Asn: 64501, Recipient: "census-2@" + censusTestSni}, address: "198.51.100.20", retries: 2},
		{send: &CensusSend{Sender: "signup-charlie", Kind: CensusKindSignup, Rank: 4, Asn: 64502, Recipient: "census-3@" + censusTestSni}, address: "192.0.2.30", sni: censusTestSni},
		{send: &CensusSend{Sender: "report-delta", Kind: CensusKindReport, Asn: 64503, Recipient: "census-4@" + censusTestSni}, address: "203.0.113.40"},
		{send: &CensusSend{Sender: "provider-echo", Kind: CensusKindProvider, Asn: 64504, Recipient: "census-5@" + censusTestSni}, address: "198.51.100.50", silent: true},
	}
	snapshots := []*CensusCounterSnapshot{world.snapshot()}
	sends := []*CensusSend{}
	for _, plan := range planned {
		plan.send.Start = world.clock.Now()
		if !plan.silent {
			taken := world.sendWithTls(plan.address, plan.sni, plan.send.Recipient)
			if taken != (plan.sni != "") {
				t.Fatalf("%s: taken %t", plan.send.Sender, taken)
			}
			for range plan.retries {
				if code := world.sendPlaintext(plan.address); code != 451 {
					t.Fatalf("%s: a plaintext retry after a closed handshake got %d", plan.send.Sender, code)
				}
			}
		}
		world.clock.Advance(time.Minute)
		plan.send.End = world.clock.Now()
		snapshots = append(snapshots, world.snapshot())
		world.clock.Advance(time.Minute)
		sends = append(sends, plan.send)
	}
	world.receiver.sessions.Wait()

	table, err := BuildCensus(nil, sends, snapshots, world.receiver.Received())
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]*CensusRow{}
	for _, row := range table.Rows {
		rows[row.Sender] = row
	}
	expect := func(sender string, delivered bool, sni CensusAnswer, fallback bool, tlsVersion string) {
		t.Helper()
		row := rows[sender]
		if row == nil || row.Delivered != delivered || row.Sni != sni || row.PlaintextFallback != fallback || row.TlsVersion != tlsVersion {
			t.Errorf("%s: %+v", sender, row)
		}
	}
	expect("signup-alpha", true, CensusYes, false, "1.3")
	expect("signup-bravo", false, CensusNo, true, "")
	expect("signup-charlie", true, CensusYes, false, "1.3")
	expect("report-delta", false, CensusNo, false, "")
	expect("provider-echo", false, CensusUnknown, false, "")
	if table.SignupAnswered != 3 || table.SignupWithoutSni != 1 || table.SignupUnknown != 0 {
		t.Errorf("sign-up counts %d, %d, %d", table.SignupAnswered, table.SignupWithoutSni, table.SignupUnknown)
	}
	if want := 0.5 / 1.75; math.Abs(table.WeightedLoss-want) > 1e-9 || math.Abs(table.UnweightedLoss-1.0/3) > 1e-9 || table.Pass {
		t.Errorf("weighted %v, unweighted %v, pass %t", table.WeightedLoss, table.UnweightedLoss, table.Pass)
	}

	var text bytes.Buffer
	if err := table.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	output := text.String()
	for _, plan := range planned {
		if strings.Contains(output, plan.send.Recipient) || strings.Contains(output, plan.address) || strings.Contains(output, "@") {
			t.Fatalf("the table holds an address:\n%s", output)
		}
		if !strings.Contains(output, plan.send.Sender) {
			t.Errorf("the table leaves out %s", plan.send.Sender)
		}
	}
	if !strings.Contains(output, "28.57% against the bar 5.00%: fail") || !strings.Contains(output, "33.33%") {
		t.Errorf("the bar's lines:\n%s", output)
	}
}

// A sender whose fallback retried many times counts as one fallback, and one that retried in plaintext
// without a closed handshake in its window counts none.
func TestCensusCountsAFallbackOnce(t *testing.T) {
	start := sidecartest.DefaultClockStart()
	settings := DefaultCensusSettings()
	series := func(sessions map[string]float64, plaintext float64) map[string]float64 {
		values := map[string]float64{censusSeriesName(settings.PlaintextSeries, "451"): plaintext}
		for result, value := range sessions {
			values[censusSeriesName(settings.SessionsSeries, result)] = value
		}
		return values
	}
	snapshots := []*CensusCounterSnapshot{
		{Time: start, Series: series(nil, 0)},
		{Time: start.Add(time.Minute), Series: series(map[string]float64{"no_sni": 1}, 7)},
		{Time: start.Add(2 * time.Minute), Series: series(map[string]float64{"no_sni": 1}, 9)},
	}
	sends := []*CensusSend{
		{Sender: "signup-retries", Kind: CensusKindSignup, Rank: 1, Recipient: "a", Start: start, End: start.Add(time.Minute)},
		{Sender: "signup-plain", Kind: CensusKindSignup, Rank: 3, Recipient: "b", Start: start.Add(time.Minute), End: start.Add(2 * time.Minute)},
	}
	table, err := BuildCensus(settings, sends, snapshots, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !table.Rows[0].PlaintextFallback || table.Rows[0].Sni != CensusNo {
		t.Errorf("seven retries after a closed handshake: %+v", table.Rows[0])
	}
	if table.Rows[1].PlaintextFallback || table.Rows[1].Sni != CensusUnknown {
		t.Errorf("plaintext with no closed handshake: %+v", table.Rows[1])
	}
	if table.SignupAnswered != 1 || table.SignupUnknown != 1 || table.WeightedLoss != 1 {
		t.Errorf("%+v", table)
	}
}

// The census refuses a list it cannot judge: no sender, an unknown kind, a window backwards, a sign-up
// sender with no rank. With no sign-up sender answered nothing passes.
func TestCensusRefusesAListItCannotJudge(t *testing.T) {
	start := sidecartest.DefaultClockStart()
	for name, send := range map[string]*CensusSend{
		"no sender":          {Kind: CensusKindEsp, Start: start, End: start},
		"an unknown kind":    {Sender: "x", Kind: "relay", Start: start, End: start},
		"a window backwards": {Sender: "x", Kind: CensusKindEsp, Start: start, End: start.Add(-time.Second)},
		"no rank":            {Sender: "x", Kind: CensusKindSignup, Start: start, End: start},
	} {
		if _, err := BuildCensus(nil, []*CensusSend{send}, nil, nil); err == nil {
			t.Errorf("%s: built", name)
		}
	}
	table, err := BuildCensus(nil, []*CensusSend{{Sender: "esp-only", Kind: CensusKindEsp, Start: start, End: start}}, nil, nil)
	if err != nil || table.Pass {
		t.Errorf("a census with no sign-up answer passed: %+v %v", table, err)
	}
}

// A scrape's urnetwork_mxedge_* series become a snapshot; other families and comments are skipped.
func TestCensusReadsAScrape(t *testing.T) {
	scrape := "# HELP urnetwork_mxedge_sessions_total Sessions.\n" +
		"# TYPE urnetwork_mxedge_sessions_total counter\n" +
		`urnetwork_mxedge_sessions_total{result="no_sni"} 4` + "\n" +
		`urnetwork_mxedge_plaintext_sessions_total{result="451"} 2` + "\n" +
		`urnetwork_tlsedge_connections_total{result="spliced"} 9` + "\n"
	snapshot, err := ParseCensusCounterText(scrape, sidecartest.DefaultClockStart())
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Series) != 2 || snapshot.Series[`urnetwork_mxedge_sessions_total{result="no_sni"}`] != 4 ||
		snapshot.Series[`urnetwork_mxedge_plaintext_sessions_total{result="451"}`] != 2 {
		t.Errorf("%v", snapshot.Series)
	}
	if _, err := ParseCensusCounterText(`urnetwork_mxedge_sessions_total{result="no_sni"} many`, sidecartest.DefaultClockStart()); err == nil {
		t.Error("a value that is no number was read")
	}
}
