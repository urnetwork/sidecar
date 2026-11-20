//go:build !sidecar_http && !js && !ios_extension

// MAIL-M7-24's strict mode: the setting read from config.proto's mail_strict, off unless a head sets it; under strict a
// splice for a URnetwork-zone host refused and one for a custom MX host taken only where its customer-signed chain
// holds; a refused splice ending at a TLS alert before any SMTP byte, its session never run; strict_chain sealed only
// for a spliced session whose SNI names a custom MX host whose chain holds for its recipients, never for a
// URnetwork-zone host, a direct-MX session or with strict off; and the label's claim saying only the stated residual.

package sidecar

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/textproto"
	"slices"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// A chain that holds only for mx.customer.example over customer.example's recipients, as a customer-signed zone's
// would, recording what it was asked.
type mailStrictTestChain struct {
	asked [][]string
}

func (self *mailStrictTestChain) holds(ctx context.Context, sniHost string, recipientDomains []string, spkiSha256 []byte) bool {
	self.asked = append(self.asked, append([]string{sniHost}, recipientDomains...))
	if sniHost != "mx.customer.example" || len(recipientDomains) == 0 {
		return false
	}
	for _, domain := range recipientDomains {
		if domain != "customer.example" {
			return false
		}
	}
	return true
}

// A policy under root.example, strict as given, over chain.
func newMailStrictTestPolicy(strict bool, chain *mailStrictTestChain) *MailStrictPolicy {
	args := &MailStrictPolicyArgs{
		Strict: func() bool { return strict },
		Root:   func() string { return "root.example." },
	}
	if chain != nil {
		args.Chain = chain.holds
	}
	return NewMailStrictPolicy(args)
}

// The setting is ServiceSettings.mail_strict, field 7 (QD-204): off for no settings and for settings that leave it
// unset whatever else they set, on once a head sets it, and off again once a head clears it.
func TestMailStrictSettingReadsTheDeclaredField(t *testing.T) {
	if MailStrictSetting(nil) {
		t.Fatal("no settings read on")
	}
	field := (&protocol.ServiceSettings{}).ProtoReflect().Descriptor().Fields().ByNumber(7)
	if field == nil || field.Name() != "mail_strict" || field.Kind() != protoreflect.BoolKind {
		t.Fatalf("ServiceSettings' field 7 is %v", field)
	}
	settings := &protocol.ServiceSettings{TeamMail: protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS, WitnessBoundHours: 48, RecordRequired: true}
	if MailStrictSetting(settings) {
		t.Fatal("settings that leave mail_strict unset read strict on")
	}
	settings.MailStrict = true
	if !MailStrictSetting(settings) {
		t.Fatal("mail_strict set true reads off")
	}
	settings.MailStrict = false
	if MailStrictSetting(settings) {
		t.Fatal("mail_strict cleared reads on")
	}
}

// Under strict a URnetwork-zone host's splice is refused, a custom MX host's taken only where its chain holds; outside
// strict every splice is taken; with no chain to ask, no custom host is.
func TestMailStrictAdmitsOnlyACustomerSignedCustomMx(t *testing.T) {
	ctx := context.Background()
	spki := bytes.Repeat([]byte{7}, 32)
	chain := &mailStrictTestChain{}
	strict := newMailStrictTestPolicy(true, chain)
	for sni, want := range map[string]bool{
		"mx.lbl0000001.root.example": false, "mx.sales.lbl0000001.root.example": false, "root.example": false, "": false,
		"mx.customer.example": true, "MX.Customer.Example.": true, "mx.other.example": false, "example": false,
	} {
		if got := strict.AdmitSplice(ctx, sni, spki); got != want {
			t.Errorf("strict, %q: %t", sni, got)
		}
	}
	if !slices.ContainsFunc(chain.asked, func(asked []string) bool {
		return slices.Equal(asked, []string{"mx.customer.example", "customer.example"})
	}) {
		t.Errorf("the chain asked %v", chain.asked)
	}
	relaxed := newMailStrictTestPolicy(false, chain)
	for _, sni := range []string{"mx.lbl0000001.root.example", "mx.other.example", ""} {
		if !relaxed.AdmitSplice(ctx, sni, spki) {
			t.Errorf("strict off refused %q", sni)
		}
	}
	if newMailStrictTestPolicy(true, nil).AdmitSplice(ctx, "mx.customer.example", spki) {
		t.Error("a custom host taken with no chain to ask")
	}
}

// strict_chain holds only under strict, for a custom MX host whose chain holds for every recipient domain: never a
// URnetwork-zone host's, never with a recipient in another domain, never with strict off or with no recipient.
func TestMailStrictChainOnlyForACustomMxHost(t *testing.T) {
	ctx := context.Background()
	spki := bytes.Repeat([]byte{7}, 32)
	strict := newMailStrictTestPolicy(true, &mailStrictTestChain{})
	cases := []struct {
		sni     string
		domains []string
		want    bool
	}{
		{sni: "mx.customer.example", domains: []string{"customer.example"}, want: true},
		{sni: "mx.customer.example", domains: []string{"customer.example", "lbl0000001.root.example"}, want: false},
		{sni: "mx.lbl0000001.root.example", domains: []string{"lbl0000001.root.example"}, want: false},
		{sni: "mx.customer.example", domains: nil, want: false},
	}
	for _, c := range cases {
		if got := strict.StrictChain(ctx, c.sni, c.domains, spki); got != c.want {
			t.Errorf("%s %v: %t", c.sni, c.domains, got)
		}
	}
	if newMailStrictTestPolicy(false, &mailStrictTestChain{}).StrictChain(ctx, "mx.customer.example", []string{"customer.example"}, spki) {
		t.Error("strict_chain with strict off")
	}
	if got := mailRecipientDomains([]string{"a@Customer.Example", "b@customer.example", "c@lbl.root.example.", "no-at"}); !slices.Equal(got, []string{"customer.example", "lbl.root.example"}) {
		t.Errorf("recipient domains %v", got)
	}
}

// Under strict a splice for a URnetwork-zone host ends at a TLS alert before any SMTP byte, and no session runs; a
// custom MX host's splice whose chain holds is taken. The router's ingress names the SNI the receiver judges.
func TestMailStrictRefusesASpliceBeforeAnySmtpByte(t *testing.T) {
	world := newMailReceiverTestWorld(t, nil)
	served := make(chan *MailReceiverStream, 4)
	policy := newMailStrictTestPolicy(true, &mailStrictTestChain{})
	world.newReceiver(func(args *MailReceiverArgs) {
		args.Admit = func(ctx context.Context, metadata []byte, spkiSha256 []byte) bool {
			sni, ok := mailIngressSni(metadata, DefaultMailIngressFormatSettings().MaxByteCount)
			return ok && policy.AdmitSplice(ctx, sni, spkiSha256)
		}
		args.Serve = func(ctx context.Context, stream *MailReceiverStream) {
			served <- stream
			stream.Tls.Close()
		}
	})
	world.startServing()
	ingress := func(sni string) []byte {
		metadata, err := proto.Marshal(&protocol.MailIngress{Version: mailFormatVersion, SenderIp: []byte{192, 0, 2, 25}, SenderPort: 40000, Sni: sni})
		if err != nil {
			t.Fatal(err)
		}
		return metadata
	}
	open := func(sni string) error {
		listenerEnd, senderEnd := newSocketStreamPipe(256 * 1024)
		ticket := &protocol.SocketTicket{DialerNetworkId: world.edgeNetworkId.Bytes(), Name: "smtp/25/mx"}
		world.listener.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, ingress(sni))
		sender := tls.Client(newSocketConn(senderEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		defer sender.Close()
		if err := sender.HandshakeContext(world.ctx); err != nil {
			return err
		}
		// the session would greet nothing: RFC 3207 §4.2 has no second 220, so read for the stream's end
		text := textproto.NewConn(sender)
		text.ReadLine()
		return nil
	}
	err := open(testMailReceiverServerName)
	if err == nil || !strings.Contains(err.Error(), "handshake failure") {
		t.Fatalf("a URnetwork-zone splice under strict: %v", err)
	}
	select {
	case <-served:
		t.Fatal("a refused splice reached the session")
	default:
	}
	if err := open("mx.customer.example"); err != nil {
		t.Fatalf("a customer-signed custom MX splice: %v", err)
	}
	if stream := <-served; stream.Tls.ConnectionState().ServerName != "mx.customer.example" {
		t.Fatalf("the served stream named %q", stream.Tls.ConnectionState().ServerName)
	}
}

// strict_chain is sealed for a spliced session whose SNI names a customer-signed custom MX host and whose recipients
// are that customer's, and not for the same receiver's URnetwork-zone session; ingest then labels only the former
// strict_custom_mx, its words stating the residual alone.
func TestMailStrictSealsStrictChainOnlyForACustomHostSplice(t *testing.T) {
	chain := &mailStrictTestChain{}
	policy := newMailStrictTestPolicy(true, chain)
	world := newMailSessionTestWorld(t, func(args *MailSessionArgs) {
		clock := args.Clock.(*mailReceiverTestClock)
		settings := DefaultMailAuthSettings()
		forwarder := &mailSessionTestForwarder{records: map[string]string{}}
		args.Checker = NewMailAuthChecker(NewMailDnsStub(forwarder, clock, settings), clock, settings)
		args.Slots = NewMailAuthSlots(settings)
		args.StrictChain = policy.StrictChain
	})
	world.stateLock.Lock()
	world.recipients["ann@customer.example"] = &MailSessionRecipient{Known: true, Address: "ann@customer.example", RepoId: NewId()}
	world.stateLock.Unlock()
	send := func(serverName string, recipient string, subject string) *protocol.MailDeposit {
		t.Helper()
		listenerEnd, senderEnd := newSocketStreamPipe(1024 * 1024)
		ticket := &protocol.SocketTicket{DialerNetworkId: world.edgeNetworkId.Bytes(), Name: "smtp/25/mx"}
		world.listener.conns <- newSocketConn(listenerEnd, &SocketAddr{}, &SocketAddr{}, ticket, testMailSessionIngress(t))
		conn := tls.Client(newSocketConn(senderEnd, &SocketAddr{}, &SocketAddr{}, nil, nil), &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		if err := conn.HandshakeContext(world.ctx); err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		sender := &mailSessionTestSender{t: t, conn: conn, text: textproto.NewConn(conn)}
		sender.envelope(recipient)
		codes, messages := sender.data(testMailSessionMessage(subject))
		if code := <-codes; code != 250 {
			t.Fatalf("reply %d %s", code, <-messages)
		}
		deposits := world.takenDeposits()
		return deposits[len(deposits)-1].trailer
	}
	custom := send("mx.customer.example", "ann@customer.example", "custom")
	if !custom.GetEvidence().GetStrictChain() {
		t.Fatalf("a customer-signed custom MX splice sealed no strict_chain: %v", custom.GetEvidence())
	}
	zone := send(testMailReceiverServerName, testMailSessionAlice, "zone")
	if zone.GetEvidence() == nil || zone.GetEvidence().GetStrictChain() {
		t.Fatalf("a URnetwork-zone splice's evidence %v", zone.GetEvidence())
	}
	label := MailLabelDecide(&MailLabelInput{Deposit: custom, MessageSha256: custom.GetEvidence().GetMessageSha256(), Root: "root.example"})
	if !label.Basis.GetStrictCustomMx() {
		t.Fatalf("the custom MX mail's label %+v", label)
	}
	statement := label.Statement()
	if !strings.Contains(statement, "does not show this sender validated") || strings.Contains(statement, "end-to-end") ||
		strings.Contains(strings.ToLower(statement), "encrypted all the way") {
		t.Fatalf("the claim says more than the residual: %q", statement)
	}
	if zoneLabel := MailLabelDecide(&MailLabelInput{Deposit: zone, MessageSha256: zone.GetEvidence().GetMessageSha256(), Root: "root.example"}); zoneLabel.Basis.GetStrictCustomMx() {
		t.Fatal("URnetwork-zone mail carries the claim")
	}
}

// A direct-MX session never seals strict_chain, whatever its SNI: its records stay in URnetwork's zone (EX2).
func TestMailStrictNeverForADirectMxSession(t *testing.T) {
	chain := &mailStrictTestChain{}
	policy := newMailStrictTestPolicy(true, chain)
	server := &MailSessionServer{args: &MailSessionArgs{StrictChain: policy.StrictChain}}
	spki := bytes.Repeat([]byte{7}, 32)
	if server.strictChain(context.Background(), "mx.customer.example", []string{"ann@customer.example"}, spki, true) {
		t.Fatal("a direct session sealed strict_chain")
	}
	if !server.strictChain(context.Background(), "mx.customer.example", []string{"ann@customer.example"}, spki, false) {
		t.Fatal("a spliced custom-host session sealed none")
	}
	if (&MailSessionServer{args: &MailSessionArgs{}}).strictChain(context.Background(), "mx.customer.example", []string{"ann@customer.example"}, spki, false) {
		t.Fatal("no strict policy sealed strict_chain")
	}
}
