//go:build !sidecar_http

package sidecartest

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/urnetwork/sidecar"
)

const (
	testMxHost         = "mx1.mail.example"
	testRecipientHost  = "mail.example"
	testHeloName       = "o1.out.root.example"
	testEnvelopeDomain = "b.n1.root.example"
)

var (
	testSendingAddress = netip.MustParseAddr("192.0.2.25")
	testMxAddress      = netip.MustParseAddr("198.51.100.25")
)

// A channel that admits every part and keeps what it was sent, in place of an edge.
type testSmtpChannel struct {
	stateLock sync.Mutex
	shts      []byte
	parts     []*sidecar.SmtpProofPart
}

func (self *testSmtpChannel) DiscloseShts(ctx context.Context, shts []byte) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.shts = shts
	return nil
}

func (self *testSmtpChannel) SubmitPart(ctx context.Context, part *sidecar.SmtpProofPart) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.parts = append(self.parts, part)
	return nil
}

func testHeaderBlock() string {
	return "From: Alice Example <alice@n1.root.example>\r\n" +
		"To: <bob@" + testRecipientHost + ">\r\n" +
		"Subject: A synthetic message\r\n" +
		"Message-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example>\r\n" +
		"\r\n"
}

func testSmtpJob(body string, mode sidecar.SmtpMode, recipients ...string) *sidecar.SmtpProofJob {
	message := []byte(testHeaderBlock() + body)
	count := uint64(len(message))
	if mode == sidecar.SmtpModeData {
		count = uint64(len(fakeSmtpDotStuffed(message)))
	}
	return &sidecar.SmtpProofJob{
		SendId: bytes.Repeat([]byte{1}, 12),
		Preamble: &sidecar.SmtpProofPreamble{
			RecipientDomain:  testRecipientHost,
			RecipientCount:   uint32(len(recipients)),
			MessageId:        "qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example",
			HeaderFromDomain: "n1.root.example",
			MessageByteCount: count,
			HeloName:         testHeloName,
			EnvelopeDomain:   testEnvelopeDomain,
			MxHost:           testMxHost,
		},
		SenderLocal:     "bounce-1",
		RecipientLocals: recipients,
		Message:         message,
		VerifyPeer:      func(chain []*x509.Certificate) error { return nil },
	}
}

// What the edge does before it splices: the banner, EHLO and STARTTLS, which must answer 220.
func testPreTls(t *testing.T, conn net.Conn) []string {
	t.Helper()
	keywords, err := runSmtpPreTls(conn, testHeloName)
	if err != nil {
		t.Fatal(err)
	}
	return keywords
}

// One send from the fake prover through mx, the edge's pre-TLS run by hand.
func testSendThrough(t *testing.T, mx MxServer, prover *FakeSmtpProver, job *sidecar.SmtpProofJob) (*sidecar.SmtpProofResult, error, *testSmtpChannel) {
	t.Helper()
	client, server := NewMxPipe(net.TCPAddrFromAddrPort(netip.AddrPortFrom(testSendingAddress, 40000)), net.TCPAddrFromAddrPort(netip.AddrPortFrom(testMxAddress, 25)))
	done := make(chan struct{})
	go func() {
		defer close(done)
		mx.ServeMx(server)
	}()
	testPreTls(t, client)
	channel := &testSmtpChannel{}
	result, err := prover.SendSmtp(context.Background(), client, job, channel)
	client.Close()
	<-done
	return result, err, channel
}

func testExpectSent(t *testing.T, name string, result *sidecar.SmtpProofResult, err error, transactions []*MxTransaction, job *sidecar.SmtpProofJob) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if !result.Accepted {
		t.Fatalf("%s: not accepted: %+v", name, result)
	}
	if len(transactions) != 1 {
		t.Fatalf("%s: %d transactions", name, len(transactions))
	}
	if !bytes.Equal(transactions[0].Message, job.Message) {
		t.Errorf("%s: the MX took another message", name)
	}
	if len(transactions[0].Recipients) != len(job.RecipientLocals) {
		t.Errorf("%s: %d recipients", name, len(transactions[0].Recipients))
	}
}

func TestScriptedMxCompletesADialogWithCryptoTls(t *testing.T) {
	for _, c := range []struct {
		name     string
		settings *ScriptedMxSettings
		version  uint16
	}{
		{name: "tls13", settings: DefaultScriptedMxSettings(), version: tls.VersionTLS13},
		{name: "tls12 ecdsa", settings: &ScriptedMxSettings{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12}, version: tls.VersionTLS12},
		{name: "tls12 rsa", settings: &ScriptedMxSettings{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RsaKey: true}, version: tls.VersionTLS12},
	} {
		for _, mode := range []sidecar.SmtpMode{sidecar.SmtpModeBdat, sidecar.SmtpModeData} {
			script := DefaultMxScript()
			if mode == sidecar.SmtpModeData {
				script.Keywords = []string{"PIPELINING", "8BITMIME"}
			}
			mx, err := NewScriptedMx(testMxHost, script, c.settings)
			if err != nil {
				t.Fatal(err)
			}
			prover := NewFakeSmtpProver(nil)
			job := testSmtpJob("a body line\r\n.a dotted line\r\n", mode, "bob", "carol")
			result, err, channel := testSendThrough(t, mx, prover, job)
			testExpectSent(t, c.name, result, err, mx.Transactions(), job)
			if result.Mode != uint32(mode) {
				t.Errorf("%s: mode %d", c.name, result.Mode)
			}
			if version := prover.Sends()[0].TlsVersion; version != c.version {
				t.Errorf("%s: version %#x", c.name, version)
			}
			if (c.version == tls.VersionTLS13) != (len(channel.shts) == 32) {
				t.Errorf("%s: SHTS of %d octets", c.name, len(channel.shts))
			}
			if len(channel.parts) != 3 || !channel.parts[2].Last {
				t.Errorf("%s: %d parts", c.name, len(channel.parts))
			}
		}
	}
}

func testRecordMxLegs() []*RecordMxSettings {
	return []*RecordMxSettings{
		{Version: tls.VersionTLS13, Suite: tls.TLS_AES_128_GCM_SHA256},
		{Version: tls.VersionTLS13, Suite: tls.TLS_CHACHA20_POLY1305_SHA256},
		{Version: tls.VersionTLS12, Suite: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
		{Version: tls.VersionTLS12, Suite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}
}

// RecordMx is a second TLS implementation: crypto/tls must finish a dialog with it on every E1 leg,
// in both modes.
func TestRecordMxCompletesADialogWithCryptoTls(t *testing.T) {
	for _, settings := range testRecordMxLegs() {
		for _, mode := range []sidecar.SmtpMode{sidecar.SmtpModeBdat, sidecar.SmtpModeData} {
			script := DefaultMxScript()
			if mode == sidecar.SmtpModeData {
				script.Keywords = []string{"PIPELINING"}
			}
			mx, err := NewRecordMx(testMxHost, script, settings)
			if err != nil {
				t.Fatal(err)
			}
			prover := NewFakeSmtpProver(nil)
			job := testSmtpJob("a body line\r\n.a dotted line\r\n", mode, "bob", "carol")
			result, err, channel := testSendThrough(t, mx, prover, job)
			name := tls.VersionName(settings.Version) + " " + tls.CipherSuiteName(settings.Suite)
			if errs := mx.HandshakeErrors(); len(errs) != 0 {
				t.Fatalf("%s: %v", name, errs)
			}
			testExpectSent(t, name, result, err, mx.Transactions(), job)
			if version := prover.Sends()[0].TlsVersion; version != settings.Version {
				t.Errorf("%s: version %#x", name, version)
			}
			if (settings.Version == tls.VersionTLS13) != (len(channel.shts) == 32) {
				t.Errorf("%s: SHTS of %d octets", name, len(channel.shts))
			}
		}
	}
}

// What crypto/tls cannot do on demand: a ticket the client never asked for, a KeyUpdate, padded
// records and replies split across records. A client that follows RFC 8446 still finishes.
func TestRecordMxSendsALateTicketAKeyUpdateAndPaddedRecords(t *testing.T) {
	mx, err := NewRecordMx(testMxHost, nil, &RecordMxSettings{
		Version:              tls.VersionTLS13,
		Suite:                tls.TLS_AES_128_GCM_SHA256,
		TicketBeforeReply:    2,
		KeyUpdateBeforeReply: 3,
		PadReplyRecords:      17,
		SplitRepliesAt:       5,
	})
	if err != nil {
		t.Fatal(err)
	}
	job := testSmtpJob("a body line\r\n", sidecar.SmtpModeBdat, "bob")
	result, err, _ := testSendThrough(t, mx, NewFakeSmtpProver(nil), job)
	if errs := mx.HandshakeErrors(); len(errs) != 0 {
		t.Fatal(errs)
	}
	testExpectSent(t, "ticket and key update", result, err, mx.Transactions(), job)
}
