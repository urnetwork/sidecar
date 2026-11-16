// The edge connection (SMTP-M9-13) on FakeSmtpProofVerifier, FakeSmtpProver and ScriptedMx in the MX world:
// only what the session clears reaches the MX, a cut counts and another refusal does not, the MX's close makes
// parts moot, the idle limits run on the fake clock, the send log holds smtp-3's fields, the lease spends and
// reports, a part with no client record reaches the session, an oversized proof request ends its connection,
// KEYS costs nothing, and the session's hold stops the sidecar's stream being read.

package smtpedgeservice_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A sender's channel landing as the RPCs would on the engine's handlers, from the world's client.
type testProofChannel struct {
	w      *edgeWorld
	sendId []byte
	// replaces a part's encoding when set
	rewrite func(part *protocol.SmtpProof) []byte
}

func (self *testProofChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	body, err := proto.Marshal(&protocol.SmtpHandshake{SendId: self.sendId, Shts: shts})
	if err != nil {
		return err
	}
	answer, err := self.w.service.HandleHandshakeForTest(ctx, self.w.clientId, body)
	if err != nil {
		return err
	}
	result := &protocol.SmtpHandshakeResult{}
	if err := proto.Unmarshal(answer, result); err != nil || result.GetCode() != uint32(protocol.SmtpHandshakeCode_SMTP_HANDSHAKE_OK) {
		return errors.New("the handshake was refused")
	}
	return nil
}

func (self *testProofChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	proof := &protocol.SmtpProof{
		SendId:            self.sendId,
		Index:             part.Index,
		Mode:              part.Mode,
		FirstRecord:       part.FirstRecord,
		LastRecord:        part.LastRecord,
		Proof:             part.Proof,
		Last:              part.Last,
		ServerRecordCount: part.ServerRecordCount,
		Records:           part.Records,
		KeyCommitment:     part.KeyCommitment,
		ReplyCount:        part.ReplyCount,
		HeaderRecordCount: part.HeaderRecordCount,
		Carry:             part.Carry,
	}
	var body []byte
	if self.rewrite != nil {
		body = self.rewrite(proof)
	} else {
		var err error
		if body, err = proto.Marshal(proof); err != nil {
			return err
		}
	}
	answer, err := self.w.service.HandleProofForTest(ctx, self.w.clientId, body)
	if err != nil {
		return err
	}
	result := &protocol.SmtpProofResult{}
	if err := proto.Unmarshal(answer, result); err != nil || result.GetCode() != uint32(protocol.SmtpProofCode_SMTP_PROOF_OK) {
		return errors.New("the part was refused")
	}
	return nil
}

// A message whose body holds canary, from n1.root.example.
func testSpliceMessage(canary string) []byte {
	return []byte("From: alice@n1.root.example\r\nTo: bob@dest.example\r\nSubject: a test\r\nMessage-ID: <aaaaaaaaaaaaaaaaaaaaaaaaaa@n1.root.example>\r\n\r\nhello " + canary + "\r\n")
}

// What one send through the engine came to.
type testSplice struct {
	result      *protocol.SmtpPreambleResult
	proofResult *sidecar.SmtpProofResult
	err         error
}

// Runs one send as SMTP-M9-07's driver will: the preamble frame, its result, then the prover over the same
// stream, its parts landing on the engine's handlers. Returns once the connection has ended and the MX is done.
func (self *edgeWorld) splice(prover *sidecartest.FakeSmtpProver, message []byte, channel *testProofChannel) *testSplice {
	self.t.Helper()
	preamble := self.preamble()
	preamble.MessageByteCount = uint64(len(message))
	preamble.ProofKeySet = sidecartest.FakeSmtpProverKeySet()
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	served := make(chan struct{})
	go func() {
		defer close(served)
		self.service.ServeTestStream(self.networkId, self.clientId, self.sidecarId, edgeEnd)
	}()
	splice := &testSplice{}
	func() {
		// an accepted send's connection ends at the MX's close after QUIT, and the sidecar closes its end after
		// that; any other leaves its end at once
		defer func() {
			if splice.err == nil && splice.proofResult != nil && splice.proofResult.Accepted {
				<-served
			}
			sidecarEnd.Close()
		}()
		if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
			self.t.Fatal(err)
		}
		result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil)
		if err != nil {
			self.t.Fatal(err)
		}
		splice.result = result
		if result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
			return
		}
		job := &sidecar.SmtpProofJob{
			SendId: result.GetSendId(),
			Preamble: &sidecar.SmtpProofPreamble{
				RecipientDomain:  preamble.GetRecipientDomain(),
				RecipientCount:   preamble.GetRecipientCount(),
				MessageId:        preamble.GetMessageId(),
				HeaderFromDomain: preamble.GetHeaderFromDomain(),
				DkimSelector:     preamble.GetDkimSelector(),
				MessageByteCount: preamble.GetMessageByteCount(),
				HeloName:         result.GetHeloName(),
				XUrRef:           result.GetXUrRef(),
				FeedbackId:       result.GetFeedbackId(),
				EnvelopeDomain:   "b.n1.root.example",
				MxHost:           result.GetMxHost(),
				ProofKeySet:      preamble.GetProofKeySet(),
			},
			SenderLocal:     "alice",
			RecipientLocals: []string{"bob", "carol"},
			Message:         message,
			VerifyPeer:      func(chain []*x509.Certificate) error { return nil },
			KeySet:          sidecartest.FakeSmtpProverKeySet(),
		}
		if channel == nil {
			channel = &testProofChannel{}
		}
		channel.w = self
		channel.sendId = result.GetSendId()
		splice.proofResult, splice.err = prover.SendSmtp(self.ctx, sidecarEnd, job, channel)
	}()
	<-served
	self.world.Wait()
	return splice
}

// The day counters {smq_} holds for the world's network.
func (self *edgeWorld) quotaField(prefix string) string {
	self.t.Helper()
	value, _, err := self.host.Redis.HashGet(self.ctx, "{smq_"+self.networkId.String()+"}", prefix+strconv.FormatInt(smtpedgeservice.SmtpSendDay(self.clock.Now()), 10))
	if err != nil {
		self.t.Fatal(err)
	}
	return string(value)
}

// The send records the log wrote, once it has flushed what it holds.
func (self *edgeWorld) loggedSends() []*smtpedgeservice.SmtpSendRecord {
	self.t.Helper()
	self.service.FlushSendLogForTest(self.ctx)
	return self.store.Sends()
}

func TestConnectionCarriesAnHonestSendThroughTheSession(t *testing.T) {
	w := newEdgeWorld(t, nil)
	// ClientHello, change_cipher_spec and Finished pass; EHLO is the fourth record and MAIL the fifth
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	if splice.err != nil || splice.proofResult == nil || !splice.proofResult.Accepted {
		t.Fatalf("the send: %+v, %v", splice.proofResult, splice.err)
	}
	transactions := w.mx.Transactions()
	if len(transactions) != 1 {
		t.Fatalf("%d transactions", len(transactions))
	}
	session := w.verifier.Sessions()[0]
	clientRecords := 0
	serverClosed := false
	for _, call := range session.Calls() {
		switch call.Method {
		case "ClientRecord":
			clientRecords += 1
		case "ServerClosed":
			serverClosed = true
		}
	}
	if released := session.Released(); len(released) != clientRecords {
		t.Fatalf("%d client records, %d released", clientRecords, len(released))
	}
	if !serverClosed || !session.MailForwarded() {
		t.Fatalf("server closed %v, mail forwarded %v", serverClosed, session.MailForwarded())
	}
	// MAIL charged the unit and the recipients
	if w.quotaField("c:") != "1" || w.quotaField("r:") != "2" {
		t.Fatalf("debited %q connections, %q recipients", w.quotaField("c:"), w.quotaField("r:"))
	}
	if w.service.LiveConnectionCount() != 0 {
		t.Fatal("a connection is still live")
	}
	sends := w.loggedSends()
	if len(sends) != 1 {
		t.Fatalf("%d sends logged", len(sends))
	}
	send := sends[0]
	if !bytes.Equal(send.SendId, splice.result.GetSendId()) || send.Result != "sent" || send.MxHost != testMxHost || send.RecipientCount != 2 ||
		send.TlsVersion != 0x0304 || send.ByteCount == 0 || send.NetworkId != w.networkId || send.ClientId != w.clientId || send.EndTime.IsZero() {
		t.Fatalf("the send record %+v", send)
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_connections_total", "sent", "bdat", "unknown"); value != 1 {
		t.Fatalf("%v sent connections counted", value)
	}
	if violations := w.host.Metrics.Violations(); len(violations) != 0 {
		t.Fatalf("metrics: %v", violations)
	}
}

// The lease spends every relayed octet on meter smtp, and the usage leaves once per window under smtpedge.
func TestConnectionSpendsTheLeaseAndReportsOncePerWindow(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.host.Quota.SetBalance(connect.Id(w.networkId), 1024*1024*1024)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	if splice.err != nil {
		t.Fatal(splice.err)
	}
	sends := w.loggedSends()
	if len(sends) != 1 {
		t.Fatalf("%d sends", len(sends))
	}
	if err := w.service.DrainUsageForTest(w.ctx); err != nil {
		t.Fatal(err)
	}
	batches := w.host.Quota.SentBatches()
	var reported int64
	for _, batch := range batches {
		if batch.Producer != "smtpedge" {
			t.Fatalf("producer %q", batch.Producer)
		}
		for _, event := range batch.Events {
			if event.NetworkId != connect.Id(w.networkId) || event.Meter != sidecar.QuotaMeterSmtp {
				t.Fatalf("event %+v", event)
			}
			reported += event.TransferByteCount
		}
	}
	if len(batches) != 1 || reported != int64(sends[0].ByteCount) {
		t.Fatalf("%d batches reporting %d octets, the send relayed %d", len(batches), reported, sends[0].ByteCount)
	}
}

// A part the session refuses with ErrSmtpRecordCut cuts the connection before MAIL: nothing it held reaches the
// MX, no unit is charged, and the cut counts; two cuts in a day halt the network.
func TestConnectionCutForwardsNothingHeldAndCounts(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, RefuseParts: map[uint32]error{2: sidecar.ErrSmtpRecordCut}})
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	if splice.err == nil {
		t.Fatal("a cut send succeeded")
	}
	if accepted := w.mx.Accepted(); slices.ContainsFunc(accepted, func(command string) bool { return len(command) >= 4 && command[:4] == "MAIL" }) {
		t.Fatalf("the MX accepted %q", accepted)
	}
	if w.quotaField("c:") != "" {
		t.Fatal("a cut connection charged a unit")
	}
	sends := w.loggedSends()
	if len(sends) != 1 || sends[0].Result != "cut" || sends[0].RecipientCount != 0 {
		t.Fatalf("sends %+v", sends)
	}
	// a second cut halts the network (§14.8)
	w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("y"), nil)
	if err := w.service.AwaitHaltWork(w.ctx, 2); err != nil {
		t.Fatal(err)
	}
	halts := w.store.Halts()
	if len(halts) != 1 || halts[0].Trigger != smtpedgeservice.SmtpHaltTriggerRecordCuts || halts[0].NetworkId != w.networkId {
		t.Fatalf("halts %+v", halts)
	}
}

// Any other refusal ends the connection and counts toward no halt.
func TestConnectionOtherRefusalIsNoCut(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, RefuseParts: map[uint32]error{2: errors.New("refused")}})
	for range 2 {
		w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	}
	sends := w.loggedSends()
	if len(sends) != 2 || sends[0].Result != "ended" || sends[1].Result != "ended" {
		t.Fatalf("sends %+v", sends)
	}
	if halts := w.store.Halts(); len(halts) != 0 {
		t.Fatalf("halts %+v", halts)
	}
}

// A part that opens no client record passes through to the session (DESIGN-DETAILS 3.2.5).
func TestConnectionPartWithNoClientRecordReachesTheSession(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	channel := &testProofChannel{}
	sent := false
	channel.rewrite = func(proof *protocol.SmtpProof) []byte {
		if !sent && proof.GetIndex() == 2 {
			sent = true
			// before part 2, a part of its own that opens nothing
			empty := proto.Clone(proof).(*protocol.SmtpProof)
			empty.Index = 2
			empty.LastRecord = empty.FirstRecord - 1
			empty.Records = nil
			body, _ := proto.Marshal(empty)
			answer, err := channel.w.service.HandleProofForTest(channel.w.ctx, channel.w.clientId, body)
			result := &protocol.SmtpProofResult{}
			if err != nil || proto.Unmarshal(answer, result) != nil || result.GetCode() != uint32(protocol.SmtpProofCode_SMTP_PROOF_OK) {
				channel.w.t.Errorf("the empty part was refused: %v", err)
			}
		}
		body, _ := proto.Marshal(proof)
		return body
	}
	w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), channel)
	session := w.verifier.Sessions()[0]
	for _, call := range session.Calls() {
		if call.Method == "VerifyPart" && call.Part.LastRecord+1 == call.Part.FirstRecord && call.Err == nil {
			return
		}
	}
	t.Fatal("no part with no client record reached the session")
}

// A proof request over ProofMaxByteCount is refused and its connection reset.
func TestConnectionOversizedProofResetsTheStream(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	channel := &testProofChannel{rewrite: func(proof *protocol.SmtpProof) []byte {
		if proof.GetIndex() == 2 {
			proof.Proof = make([]byte, 20*1024)
		}
		body, _ := proto.Marshal(proof)
		return body
	}}
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), channel)
	if splice.err == nil {
		t.Fatal("the send went on past an oversized part")
	}
	for _, call := range w.verifier.Sessions()[0].Calls() {
		if call.Method == "VerifyPart" && call.Part.Index == 2 {
			t.Fatal("the oversized part reached the session")
		}
	}
	sends := w.loggedSends()
	if len(sends) != 1 || sends[0].Result != "ended" || w.quotaField("c:") != "" {
		t.Fatalf("sends %+v, debit %q", sends, w.quotaField("c:"))
	}
}

// Another client's call never reaches a connection.
func TestConnectionTakesPartsFromItsDialerOnly(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	channel := &testProofChannel{}
	stranger := sidecar.NewId()
	channel.rewrite = func(proof *protocol.SmtpProof) []byte {
		body, _ := proto.Marshal(proof)
		if proof.GetIndex() == 1 {
			answer, _ := channel.w.service.HandleProofForTest(channel.w.ctx, stranger, body)
			result := &protocol.SmtpProofResult{}
			if proto.Unmarshal(answer, result) != nil || result.GetCode() != uint32(protocol.SmtpProofCode_SMTP_PROOF_INVALID) {
				channel.w.t.Errorf("a stranger's part answered %d", result.GetCode())
			}
		}
		return body
	}
	splice := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), channel)
	if splice.err != nil || !splice.proofResult.Accepted {
		t.Fatalf("the dialer's send: %+v %v", splice.proofResult, splice.err)
	}
	for _, call := range w.verifier.Sessions()[0].Calls() {
		if call.Method == "VerifyPart" && call.Err != nil {
			t.Fatalf("a part was refused: %v", call.Err)
		}
	}
}

// KEYS: a preamble naming a key set the verifier lacks is answered before any dial and costs nothing, a burst
// token included.
func TestConnectionKeysBeforeAnyDialCostNothing(t *testing.T) {
	w := newEdgeWorld(t, nil)
	keySet := bytes.Repeat([]byte{0x77}, 32)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{RefuseKeySets: [][]byte{keySet}})
	preamble := w.preamble()
	preamble.ProofKeySet = keySet
	w.expect(preamble, protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS)
	if dials := w.world.Dials(); len(dials) != 0 {
		t.Fatalf("dials %v", dials)
	}
	fields, err := w.host.Redis.HashGetAll(w.ctx, "{smq_"+w.networkId.String()+"}")
	if err != nil || len(fields) != 0 {
		t.Fatalf("KEYS left %v in {smq_}, %v", fields, err)
	}
}

// A stream that sends nothing past its preamble ends at ClientIdleTimeout on the fake clock.
func TestConnectionIdleLimitEndsTheStream(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		// no renewal before the idle limit, so the connection's next timer is that limit, at a time no other
		// timer of the world's shares
		world.settings.QuotaMemberTimeout = 2 * time.Hour
		world.settings.QuotaMemberRenewInterval = time.Hour
		world.settings.ClientIdleTimeout = 7*time.Minute + 13*time.Second
	})
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	defer sidecarEnd.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, edgeEnd)
	}()
	if err := sidecar.WriteSmtpPreamble(sidecarEnd, w.preamble(), nil); err != nil {
		t.Fatal(err)
	}
	result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil)
	if err != nil || result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("result %v, %v", result, err)
	}
	deadline := w.clock.Now().Add(w.settings.ClientIdleTimeout)
	for {
		pending, added := w.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(at time.Time) bool { return !at.Before(deadline) && at.Before(deadline.Add(time.Second)) }) {
			break
		}
		select {
		case <-added:
		case <-w.ctx.Done():
			t.Fatal("the idle timer was never armed")
		}
	}
	// a minute short of it the connection lives
	w.clock.Advance(w.settings.ClientIdleTimeout - time.Minute)
	if w.service.LiveConnectionCount() != 1 {
		t.Fatal("the connection ended early")
	}
	w.clock.Advance(time.Minute)
	<-served
	sends := w.loggedSends()
	if len(sends) != 1 || sends[0].Result != "timeout" {
		t.Fatalf("sends %+v", sends)
	}
}

// When the session holds ConnectionHeldMaxByteCount of client octets, the engine stops reading the sidecar's
// stream: what the sidecar writes past it waits in the stream, and no byte is dropped.
// An MX that takes STARTTLS and then reads in silence until the edge closes it.
type silentMx struct{}

func (silentMx) ServeMx(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	conn.Write([]byte("220 mx.quiet.example ESMTP\r\n"))
	reader.ReadString('\n')
	conn.Write([]byte("250-mx.quiet.example\r\n250 STARTTLS\r\n"))
	reader.ReadString('\n')
	conn.Write([]byte("220 2.0.0 Ready to start TLS\r\n"))
	io.Copy(io.Discard, reader)
}

func TestConnectionStopsReadingWhileTheSessionHolds(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.settings.ConnectionHeldMaxByteCount = 4096
		world.mustWorld(world.world.SetMx("quiet.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.quiet.example"}))
		world.mustWorld(world.world.AddMx("mx.quiet.example", netip.MustParseAddr("192.0.2.26"), silentMx{}))
	})
	// the first record passes and every later one waits for a part that never comes
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 1})
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	served := make(chan struct{})
	go func() {
		defer close(served)
		w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, edgeEnd)
	}()
	preamble := w.preamble()
	preamble.RecipientDomain = "quiet.example"
	if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
		t.Fatal(err)
	}
	if result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil); err != nil || result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("result %v, %v", result, err)
	}
	record := func(length int) []byte {
		return append([]byte{23, 3, 3, byte(length >> 8), byte(length)}, make([]byte, length)...)
	}
	// 1 record passes, then 1 KiB records until the hold is past 4 KiB, and 32 more behind them
	for range 40 {
		if _, err := sidecarEnd.Write(record(1024)); err != nil {
			t.Fatal(err)
		}
	}
	// the reader stops once the held octets reach the bound: 1 passed, then 4 held of 1,029 octets each
	if err := w.service.AwaitHeldWaits(w.ctx, 1); err != nil {
		t.Fatal(err)
	}
	session := w.verifier.Sessions()[0]
	countRecords := func() int {
		count := 0
		for _, call := range session.Calls() {
			if call.Method == "ClientRecord" {
				count += 1
			}
		}
		return count
	}
	if count := countRecords(); count != 5 {
		t.Fatalf("the engine read %d records while the session held its bound", count)
	}
	// a reader waiting for room hears no close: the client idle limit ends the connection
	w.clock.Advance(w.settings.ClientIdleTimeout)
	<-served
	sidecarEnd.Close()
	w.world.Wait()
}

// SmtpOutcome is taken from the connection's dialer alone, once, within OutcomeAcceptTimeout of the stream's
// end, and its hard bounces reach the halt rule.
func TestConnectionOutcomeIsTakenFromItsDialerOnce(t *testing.T) {
	w := newEdgeWorld(t, nil)
	w.verifier.SetScript(&sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	first := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("x"), nil)
	second := w.splice(sidecartest.NewFakeSmtpProver(nil), testSpliceMessage("y"), nil)
	outcome := func(sendId []byte) []byte {
		body, err := proto.Marshal(&protocol.SmtpOutcome{SendId: sendId, TlsLevel: 1, Mode: 1, HardBounceCount: 3})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	if err := w.service.AcceptOutcome(sidecar.NewId(), outcome(first.result.GetSendId())); err == nil {
		t.Fatal("a stranger's outcome was taken")
	}
	if err := w.service.AcceptOutcome(w.clientId, outcome(first.result.GetSendId())); err != nil {
		t.Fatalf("the dialer's outcome: %v", err)
	}
	if err := w.service.AwaitHaltWork(w.ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := w.service.AcceptOutcome(w.clientId, outcome(first.result.GetSendId())); err == nil {
		t.Fatal("a second outcome for one send was taken")
	}
	w.clock.Advance(w.settings.OutcomeAcceptTimeout)
	if err := w.service.AcceptOutcome(w.clientId, outcome(second.result.GetSendId())); err == nil {
		t.Fatal("a late outcome was taken")
	}
	if value := w.host.Metrics.Value("urnetwork_smtpedge_outcomes_total", "taken", "tl1", "bdat"); value != 1 {
		t.Fatalf("%v outcomes taken", value)
	}
	// 3 of the day's 4 recipients bounced, under smtp_hard_bounce_floor's 10 sent: no halt
	if halts := w.store.Halts(); len(halts) != 0 {
		t.Fatalf("halts %+v", halts)
	}
}

// Drain lets a live connection finish, and returns once it has; Close then joins a stream still in its
// preamble rather than waiting out its timeout.
func TestDrainWaitsForConnectionsAndCloseEndsPreambles(t *testing.T) {
	w := newEdgeWorld(t, func(world *edgeWorld) {
		world.settings.QuotaMemberTimeout = 2 * time.Hour
		world.settings.QuotaMemberRenewInterval = time.Hour
		world.settings.ClientIdleTimeout = 7*time.Minute + 17*time.Second
		world.mustWorld(world.world.SetMx("quiet.example", &sidecar.SmtpMxHost{Preference: 10, Host: "mx.quiet.example"}))
		world.mustWorld(world.world.AddMx("mx.quiet.example", netip.MustParseAddr("192.0.2.26"), silentMx{}))
	})
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	defer sidecarEnd.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, edgeEnd)
	}()
	preamble := w.preamble()
	preamble.RecipientDomain = "quiet.example"
	if err := sidecar.WriteSmtpPreamble(sidecarEnd, preamble, nil); err != nil {
		t.Fatal(err)
	}
	if result, err := sidecar.ReadSmtpPreambleResult(sidecarEnd, nil); err != nil || result.GetCode() != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		t.Fatalf("result %v, %v", result, err)
	}
	deadline := w.clock.Now().Add(w.settings.ClientIdleTimeout)
	for {
		pending, added := w.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(at time.Time) bool { return at.Equal(deadline) }) {
			break
		}
		select {
		case <-added:
		case <-w.ctx.Done():
			t.Fatal("the idle timer was never armed")
		}
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		w.service.Drain()
	}()
	// a live connection holds the drain: it cannot return before the connection ends
	select {
	case <-drained:
		t.Fatal("the drain returned with a connection live")
	default:
	}
	// the connection's own limit ends it, and the drain with it
	w.clock.Advance(w.settings.ClientIdleTimeout)
	<-served
	<-drained
	if w.service.Ready() {
		t.Fatal("a drained engine is ready")
	}
	// a drained engine takes no new stream
	other, otherEdge := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	defer other.Close()
	w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, otherEdge)
	if _, err := other.Read(make([]byte, 1)); err == nil {
		t.Fatal("a drained engine took a stream")
	}
}

// Close ends a stream waiting in its preamble at once.
func TestCloseEndsAStreamInItsPreamble(t *testing.T) {
	w := newEdgeWorld(t, nil)
	sidecarEnd, edgeEnd := sidecartest.NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	defer sidecarEnd.Close()
	served := make(chan struct{})
	go func() {
		defer close(served)
		w.service.ServeTestStream(w.networkId, w.clientId, w.sidecarId, edgeEnd)
	}()
	// the preamble's timer, armed once the stream reads its frame, found by its deadline: a count of the clock's timers
	// taken once the stream had started could already hold it, and then waited for one more that never came
	deadline := w.clock.Now().Add(w.settings.PreambleTimeout)
	for {
		pending, added := w.clock.WatchTimers()
		if slices.ContainsFunc(pending, func(at time.Time) bool { return at.Equal(deadline) }) {
			break
		}
		select {
		case <-added:
		case <-w.ctx.Done():
			t.Fatal("the preamble's timer was never armed")
		}
	}
	w.service.Close()
	<-served
}
