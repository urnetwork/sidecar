//go:build !sidecar_http

package sidecartest

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One recipient domain, mail.example, whose MX at preference 10 runs mx, behind the stub edge.
type testStubWorld struct {
	world    *MxWorld
	verifier *FakeSmtpProofVerifier
	edge     *StubSmtpEdge
}

func newTestStubWorld(t *testing.T, mx MxServer, certificate *tls.Certificate, script *FakeSmtpProofScript) *testStubWorld {
	t.Helper()
	world := testMxWorld(t)
	if err := world.AddZone(testRecipientHost, nil); err != nil {
		t.Fatal(err)
	}
	world.SetMx(testRecipientHost, &sidecar.SmtpMxHost{Preference: 10, Host: testMxHost})
	var tlsa []*sidecar.SmtpTlsaRecord
	if certificate != nil {
		tlsa = append(tlsa, MxTlsaFor(certificate.Leaf))
	}
	if err := world.AddMx(testMxHost, testMxAddress, mx, tlsa...); err != nil {
		t.Fatal(err)
	}
	verifier := NewFakeSmtpProofVerifier(script)
	return &testStubWorld{world: world, verifier: verifier, edge: NewStubSmtpEdge(world, world, verifier, nil)}
}

func testWirePreamble(job *sidecar.SmtpProofJob) *protocol.SmtpPreamble {
	return &protocol.SmtpPreamble{
		Version:          1,
		RecipientDomain:  job.Preamble.RecipientDomain,
		RecipientCount:   job.Preamble.RecipientCount,
		MessageId:        job.Preamble.MessageId,
		HeaderFromDomain: job.Preamble.HeaderFromDomain,
		DkimSelector:     job.Preamble.DkimSelector,
		MessageByteCount: job.Preamble.MessageByteCount,
		Flags:            job.Preamble.Flags,
		ProofKeySet:      job.KeySet,
	}
}

// One send as SMTP-M9-07's driver will run it: the preamble frame, its result, then the prover over the
// same stream, its parts landing on the stub's handlers. Returns once the edge and the MX are done.
func (self *testStubWorld) send(t *testing.T, prover *FakeSmtpProver, job *sidecar.SmtpProofJob) (*protocol.SmtpPreambleResult, *sidecar.SmtpProofResult, error) {
	t.Helper()
	ctx := context.Background()
	sidecarConn, edgeConn := NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	served := make(chan error, 1)
	go func() { served <- self.edge.Serve(ctx, edgeConn) }()
	defer func() {
		sidecarConn.Close()
		<-served
		self.world.Wait()
	}()
	if err := sidecar.WriteSmtpPreamble(sidecarConn, testWirePreamble(job), nil); err != nil {
		t.Fatal(err)
	}
	result, err := sidecar.ReadSmtpPreambleResult(sidecarConn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_OK) {
		return result, nil, nil
	}
	job.SendId = result.SendId
	job.Preamble.MxHost = result.MxHost
	job.Preamble.HeloName = result.HeloName
	job.Preamble.XUrRef = result.XUrRef
	job.Preamble.FeedbackId = result.FeedbackId
	proofResult, err := prover.SendSmtp(ctx, sidecarConn, job, self.edge.ProofChannel(result.SendId))
	return result, proofResult, err
}

func TestStubSmtpEdgeCarriesAnHonestSendThroughTheGate(t *testing.T) {
	mx, err := NewScriptedMx(testMxHost, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// ClientHello, change_cipher_spec and Finished pass; EHLO is the fourth record and MAIL the fifth
	stub := newTestStubWorld(t, mx, &mx.certificate, &FakeSmtpProofScript{HoldAfterClientRecords: 3, MailForwardedAtClientRecord: 5})
	job := testSmtpJob("a body line\r\n", sidecar.SmtpModeBdat, "bob", "carol")
	result, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), job)
	testExpectSent(t, "through the stub", proofResult, err, mx.Transactions(), job)

	if len(result.SendId) != 12 || len(result.XUrRef) != 36 || len(result.FeedbackId) != 40 || result.MxHost != testMxHost || result.HeloName != testHeloName {
		t.Errorf("issued %+v", result)
	}
	if !slices.Contains(result.EhloKeywords, "STARTTLS") {
		t.Errorf("pre-TLS keywords %q", result.EhloKeywords)
	}
	if _, err := testValidateChain(result.DnssecChain, stub.world.TrustAnchorDs(), time.Now()); err != nil {
		t.Errorf("the chain: %v", err)
	}
	session := stub.verifier.Sessions()[0]
	if !session.MailForwarded() {
		t.Error("MAIL went and the session never said so")
	}
	if session.Preamble().EnvelopeDomain != testEnvelopeDomain || session.Preamble().XUrRef != result.XUrRef {
		t.Errorf("the session's preamble %+v", session.Preamble())
	}
	// every client record reached the MX only by the session's leave, and in its order
	var clientRecords int
	for _, call := range session.Calls() {
		if call.Method == "ClientRecord" {
			clientRecords += 1
		}
	}
	if released := session.Released(); len(released) != clientRecords {
		t.Errorf("%d client records, %d released", clientRecords, len(released))
	}
	if shts := stub.verifier.Sessions()[0].Calls(); !slices.ContainsFunc(shts, func(call *FakeSmtpProofCall) bool { return call.Method == "DiscloseShts" && len(call.Data) == 32 }) {
		t.Error("1.3's SHTS never reached the session")
	}
}

// Each refusal answers before any byte reaches an MX, and the right code says why (§14.5).
func TestStubSmtpEdgeRefusesBeforeTheMx(t *testing.T) {
	for _, code := range []protocol.SmtpPreambleCode{
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_HALTED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_QUOTA,
		protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED, protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER,
	} {
		mx, _ := NewScriptedMx(testMxHost, nil, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		stub.edge.settings.Code = code
		stub.edge.settings.RetryAfter = 90 * time.Second
		result, _, _ := stub.send(t, NewFakeSmtpProver(nil), testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob"))
		if result.Code != uint32(code) || len(stub.world.Dials()) != 0 {
			t.Errorf("%s: answered %d after %d dials", code, result.Code, len(stub.world.Dials()))
		}
		if code != protocol.SmtpPreambleCode_SMTP_PREAMBLE_DENIED && result.RetryAfterMs != 90_000 {
			t.Errorf("%s: retry after %d", code, result.RetryAfterMs)
		}
	}

	// a null MX and a domain with no name at all: NO_MX
	for _, domain := range []string{"null.example", "nowhere.example"} {
		mx, _ := NewScriptedMx(testMxHost, nil, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		stub.world.AddZone("null.example", nil)
		stub.world.SetNullMx("null.example")
		job := testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob")
		job.Preamble.RecipientDomain = domain
		if result, _, _ := stub.send(t, NewFakeSmtpProver(nil), job); result.Code != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_MX) {
			t.Errorf("%s: answered %d", domain, result.Code)
		}
	}

	// no STARTTLS: NO_TLS; a refusing banner, or octets after STARTTLS's 220: TRY_LATER
	for _, c := range []struct {
		name   string
		script *MxScript
		want   protocol.SmtpPreambleCode
	}{
		{name: "no starttls", script: &MxScript{NoStartTls: true}, want: protocol.SmtpPreambleCode_SMTP_PREAMBLE_NO_TLS},
		{name: "421 banner", script: &MxScript{Banner: "421 4.3.2 Service not available"}, want: protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER},
		{name: "injected octets", script: &MxScript{AfterStartTls: []byte("250 forged\r\n")}, want: protocol.SmtpPreambleCode_SMTP_PREAMBLE_TRY_LATER},
	} {
		mx, _ := NewScriptedMx(testMxHost, c.script, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		if result, _, _ := stub.send(t, NewFakeSmtpProver(nil), testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob")); result.Code != uint32(c.want) {
			t.Errorf("%s: answered %d", c.name, result.Code)
		}
		if accepted := mx.Accepted(); slices.ContainsFunc(accepted, func(command string) bool { return command != "EHLO "+testHeloName && command != "STARTTLS" }) {
			t.Errorf("%s: the MX accepted %q", c.name, accepted)
		}
	}
}

// The second MX in preference order takes the send when the first refuses at its banner.
func TestStubSmtpEdgeWalksMxsInPreferenceOrder(t *testing.T) {
	first, _ := NewScriptedMx("mx0.mail.example", &MxScript{Banner: "421 4.3.2 Busy"}, nil)
	second, _ := NewScriptedMx(testMxHost, nil, nil)
	stub := newTestStubWorld(t, second, nil, nil)
	firstAddress := netip.MustParseAddr("198.51.100.24")
	stub.world.SetMx(testRecipientHost, &sidecar.SmtpMxHost{Preference: 5, Host: "mx0.mail.example"})
	stub.world.AddMx("mx0.mail.example", firstAddress, first)
	job := testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob")
	result, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), job)
	testExpectSent(t, "second mx", proofResult, err, second.Transactions(), job)
	if result.MxHost != testMxHost || !slices.Equal(stub.world.Dials(), []netip.Addr{firstAddress, testMxAddress}) {
		t.Errorf("mx %s after dials %v", result.MxHost, stub.world.Dials())
	}
}

// A refused part ends the connection before the records it was for: nothing past it reaches the MX.
func TestStubSmtpEdgeCutsAtARefusedPart(t *testing.T) {
	mx, _ := NewScriptedMx(testMxHost, nil, nil)
	stub := newTestStubWorld(t, mx, nil, &FakeSmtpProofScript{HoldAfterClientRecords: 3, RefuseParts: map[uint32]error{2: sidecar.ErrSmtpRecordCut}})
	_, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob"))
	if err == nil {
		t.Fatalf("a refused part sent: %+v", proofResult)
	}
	if accepted := mx.Accepted(); slices.ContainsFunc(accepted, func(command string) bool { return len(command) >= 4 && command[:4] == "MAIL" }) {
		t.Errorf("the MX accepted %q", accepted)
	}
	if !stub.verifier.Sessions()[0].Ended() {
		t.Error("the session goes on")
	}
}

// FS-31's scripted MXs through the stub: each refusal ends the send before the message, with the MX's
// code, and the MX took nothing; the capability cases pick the mode the post-TLS reply allows.
func TestScriptedMxCasesEndBeforeAnyEffect(t *testing.T) {
	for _, c := range []struct {
		name    string
		script  func(script *MxScript)
		mode    sidecar.SmtpMode
		refused string
	}{
		{name: "refused MAIL", script: func(script *MxScript) { script.Replies["MAIL"] = "550 5.7.1 Not accepted" }, refused: "550"},
		{name: "refused RCPT", script: func(script *MxScript) { script.Replies["RCPT"] = "550 5.1.1 No such user" }, refused: "550"},
		{name: "mixed recipients", script: func(script *MxScript) { script.RcptReplies["carol"] = "550 5.1.1 No such user" }, refused: "550"},
		{name: "451 under TLS", script: func(script *MxScript) { script.Replies["MAIL"] = "451 4.3.0 Try again later" }, refused: "451"},
		{name: "no 354", script: func(script *MxScript) {
			script.Keywords = []string{"PIPELINING"}
			script.Replies["DATA"] = "554 5.5.1 Transaction failed"
		}, mode: sidecar.SmtpModeData, refused: "554"},
		{name: "message refused", script: func(script *MxScript) { script.MessageReply = "552 5.3.4 Too big" }, refused: "552"},
	} {
		script := DefaultMxScript()
		c.script(script)
		mx, _ := NewScriptedMx(testMxHost, script, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		mode := c.mode
		if mode == sidecar.SmtpModeUnknown {
			mode = sidecar.SmtpModeBdat
		}
		_, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), testSmtpJob("body\r\n", mode, "bob", "carol"))
		if err != nil || proofResult.Accepted || proofResult.RefusedCode != c.refused {
			t.Errorf("%s: %+v, %v", c.name, proofResult, err)
		}
		if transactions := mx.Transactions(); len(transactions) != 0 {
			t.Errorf("%s: the MX took %d transactions", c.name, len(transactions))
		}
	}

	for _, c := range []struct {
		name     string
		script   func(script *MxScript)
		mode     sidecar.SmtpMode
		violated bool
	}{
		{name: "no CHUNKING", script: func(script *MxScript) { script.Keywords = []string{"PIPELINING"} }, mode: sidecar.SmtpModeData},
		{name: "CHUNKING before TLS only", script: func(script *MxScript) {
			script.PreTlsKeywords = []string{"PIPELINING", "CHUNKING"}
			script.Keywords = []string{"PIPELINING"}
		}, mode: sidecar.SmtpModeData},
		{name: "no PIPELINING", script: func(script *MxScript) { script.Keywords = []string{"CHUNKING"} }, mode: sidecar.SmtpModeBdat},
	} {
		script := DefaultMxScript()
		c.script(script)
		mx, _ := NewScriptedMx(testMxHost, script, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		job := testSmtpJob("body\r\n", c.mode, "bob", "carol")
		_, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), job)
		testExpectSent(t, c.name, proofResult, err, mx.Transactions(), job)
		if proofResult.Mode != uint32(c.mode) || mx.Transactions()[0].Mode != c.mode {
			t.Errorf("%s: mode %d", c.name, proofResult.Mode)
		}
		if mx.PipeliningViolated() {
			t.Errorf("%s: a command went ahead of its reply", c.name)
		}
	}
}

// The record lists each command the machine accepted, once, in order, though the client pipelined
// them: "before any effect" can be read off it exactly.
func TestScriptedMxRecordIsExactUnderPipelining(t *testing.T) {
	for _, mode := range []sidecar.SmtpMode{sidecar.SmtpModeBdat, sidecar.SmtpModeData} {
		script := DefaultMxScript()
		if mode == sidecar.SmtpModeData {
			script.Keywords = []string{"PIPELINING"}
		}
		mx, _ := NewScriptedMx(testMxHost, script, nil)
		stub := newTestStubWorld(t, mx, nil, nil)
		job := testSmtpJob("body\r\n", mode, "bob", "carol")
		_, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), job)
		testExpectSent(t, "pipelined", proofResult, err, mx.Transactions(), job)
		want := []string{
			"EHLO " + testHeloName, "STARTTLS", "EHLO " + testHeloName,
			"MAIL FROM:<bounce-1@" + testEnvelopeDomain + ">",
			"RCPT TO:<bob@" + testRecipientHost + ">", "RCPT TO:<carol@" + testRecipientHost + ">",
		}
		if mode == sidecar.SmtpModeBdat {
			want = append(want, "BDAT "+strconv.Itoa(len(job.Message))+" LAST")
		} else {
			want = append(want, "DATA", "<data "+strconv.Itoa(len(job.Message))+" octets>")
		}
		want = append(want, "QUIT")
		if accepted := mx.Accepted(); !slices.Equal(accepted, want) {
			t.Errorf("mode %d: accepted\n%q\nwant\n%q", mode, accepted, want)
		}
	}
}

// RFC 3030 §2: an MX without CHUNKING answers BDAT 500 and parses the alleged chunk as commands, so a
// second transaction hidden in a body is one its record shows, which is what the relation stops.
func TestScriptedMxWithoutChunkingReadsABodyAsCommands(t *testing.T) {
	script := DefaultMxScript()
	script.Keywords = []string{"PIPELINING"}
	script.LaxDataEnd = true
	mx, _ := NewScriptedMx(testMxHost, script, nil)
	client, server := NewMxPipe(&net.TCPAddr{}, &net.TCPAddr{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		mx.ServeMx(server)
	}()
	testPreTls(t, client)
	conn := tls.Client(client, &tls.Config{InsecureSkipVerify: true, ServerName: testMxHost})
	smuggled := "MAIL FROM:<x@evil.example>\r\nRCPT TO:<victim@" + testRecipientHost + ">\r\n"
	conn.Write([]byte("EHLO " + testHeloName + "\r\nBDAT " + strconv.Itoa(len(smuggled)) + " LAST\r\n" + smuggled + "QUIT\r\n"))
	reader := make([]byte, 4096)
	for {
		if _, err := conn.Read(reader); err != nil {
			break
		}
	}
	conn.Close()
	<-done
	accepted := mx.Accepted()
	if !slices.Contains(accepted, "MAIL FROM:<x@evil.example>") || !slices.Contains(accepted, "RCPT TO:<victim@"+testRecipientHost+">") {
		t.Errorf("accepted %q", accepted)
	}
	if !slices.ContainsFunc(mx.Events(), func(event *MxEvent) bool {
		return event.Command == "BDAT "+strconv.Itoa(len(smuggled))+" LAST" && !event.Accepted
	}) {
		t.Error("BDAT was not refused")
	}
	if len(mx.Transactions()) != 0 {
		t.Errorf("took %d transactions", len(mx.Transactions()))
	}
}

// DESIGN-DETAILS 3.2.5: a key set the verifier does not hold is answered KEYS before any MX is dialed,
// and one it holds opens the session under that set.
func TestStubSmtpEdgeAnswersKeysBeforeTheMx(t *testing.T) {
	refused := bytes.Repeat([]byte{4}, 32)
	mx, _ := NewScriptedMx(testMxHost, nil, nil)
	stub := newTestStubWorld(t, mx, nil, &FakeSmtpProofScript{RefuseKeySets: [][]byte{refused}})
	job := testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob")
	job.KeySet = refused
	result, proofResult, err := stub.send(t, NewFakeSmtpProver(nil), job)
	if err != nil || proofResult != nil || result.Code != uint32(protocol.SmtpPreambleCode_SMTP_PREAMBLE_KEYS) {
		t.Fatalf("answered %d: %+v, %v", result.Code, proofResult, err)
	}
	if len(stub.world.Dials()) != 0 || len(stub.verifier.Sessions()) != 0 {
		t.Errorf("KEYS after %d dials and %d sessions", len(stub.world.Dials()), len(stub.verifier.Sessions()))
	}

	mx, _ = NewScriptedMx(testMxHost, nil, nil)
	stub = newTestStubWorld(t, mx, &mx.certificate, &FakeSmtpProofScript{RefuseKeySets: [][]byte{refused}})
	job = testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob")
	job.KeySet = FakeSmtpProverKeySet()
	_, proofResult, err = stub.send(t, NewFakeSmtpProver(nil), job)
	testExpectSent(t, "a held key set", proofResult, err, mx.Transactions(), job)
	if kept := stub.verifier.Sessions()[0].Preamble().ProofKeySet; !bytes.Equal(kept, FakeSmtpProverKeySet()) {
		t.Errorf("the session's key set %x", kept)
	}
}

// Every SmtpProof field crosses the channel to the session as the prover set it (DESIGN-DETAILS 3.2.5).
func TestStubSmtpEdgeCarriesEveryProofField(t *testing.T) {
	mx, _ := NewScriptedMx(testMxHost, nil, nil)
	stub := newTestStubWorld(t, mx, &mx.certificate, nil)
	prover := NewFakeSmtpProver(nil)
	job := testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob", "carol")
	job.KeySet = FakeSmtpProverKeySet()
	_, proofResult, err := stub.send(t, prover, job)
	testExpectSent(t, "every field", proofResult, err, mx.Transactions(), job)
	sent := prover.Sends()[0].Parts
	var verified []*sidecar.SmtpProofPart
	for _, call := range stub.verifier.Sessions()[0].Calls() {
		if call.Method == "VerifyPart" {
			verified = append(verified, call.Part)
		}
	}
	if len(sent) != 3 || len(verified) != len(sent) {
		t.Fatalf("%d parts sent, %d verified", len(sent), len(verified))
	}
	for i, part := range sent {
		got := verified[i]
		if !bytes.Equal(got.KeyCommitment, part.KeyCommitment) || got.ReplyCount != part.ReplyCount ||
			got.HeaderRecordCount != part.HeaderRecordCount || !bytes.Equal(got.Carry, part.Carry) {
			t.Errorf("part %d: sent %+v, verified %+v", part.Index, part, got)
		}
	}
	// the key part alone commits to keys; the message's part covers the envelope's replies and opens the
	// header block
	if len(sent[0].KeyCommitment) != 64 || len(sent[1].KeyCommitment) != 0 || sent[1].ReplyCount != 1 ||
		sent[2].ReplyCount != 3 || sent[2].HeaderRecordCount != 1 || len(sent[2].Carry) != 64 {
		t.Errorf("parts %+v %+v %+v", sent[0], sent[1], sent[2])
	}
}

// A scripted envelope overflow ends the send after MAIL with EnvelopeRetry: the MX took no message.
func TestStubSmtpEdgeCarriesAnEnvelopeRetry(t *testing.T) {
	mx, _ := NewScriptedMx(testMxHost, nil, nil)
	stub := newTestStubWorld(t, mx, nil, nil)
	settings := DefaultFakeSmtpProverSettings()
	settings.EnvelopeRetry = func(job *sidecar.SmtpProofJob) bool { return job.EnvelopeGroupMaxCount == 0 }
	prover := NewFakeSmtpProver(settings)
	job := testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob", "carol")
	_, proofResult, err := stub.send(t, prover, job)
	if err != nil || !proofResult.EnvelopeRetry || proofResult.Accepted {
		t.Fatalf("%+v, %v", proofResult, err)
	}
	if transactions := mx.Transactions(); len(transactions) != 0 {
		t.Errorf("the MX took %d transactions", len(transactions))
	}
	if accepted := mx.Accepted(); !slices.ContainsFunc(accepted, func(command string) bool { return strings.HasPrefix(command, "MAIL") }) {
		t.Errorf("MAIL never went: %q", accepted)
	}

	// the retry with one command a group goes through
	mx, _ = NewScriptedMx(testMxHost, nil, nil)
	stub = newTestStubWorld(t, mx, nil, nil)
	job = testSmtpJob("body\r\n", sidecar.SmtpModeBdat, "bob", "carol")
	job.EnvelopeGroupMaxCount = 1
	_, proofResult, err = stub.send(t, prover, job)
	testExpectSent(t, "the retry", proofResult, err, mx.Transactions(), job)
}
