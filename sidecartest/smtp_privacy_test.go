//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// §22.7's privacy rows for §14 at T2 (SMTP-M9-31; R-SMTP-7, R-SMTP-10, I-2, I-13): canaries in a mail body, its
// subject, its From display name and a recipient's local part, sent through SmtpSendWorld's stub edge to a ScriptedMx,
// are found in nothing the edge read or answered, nothing the sender logged, and no DKIM key that testHookSecret
// reported is found anywhere; the MX, the destination, holds them all, which shows they were there to leak. A
// canary in a report through a fixture feedback loop and one in mail to abuse@ reach only mx-4's listener input,
// the one class §2.8 excepts, and nothing the intake stored, logged or counted.
//
// The edge here is StubSmtpEdge, whose reads are the frames, the records and the parts a real edge reads: the
// engine's own stores, Redis families and metrics under a send are smtpedgeservice's sender_test.go's, and T3's in
// server.

package sidecartest_test

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// What the stub edge read and answered, as CC1 items.
func smtpEdgePrivacyItems(world *sidecartest.SmtpSendWorld) []*sidecartest.PrivacyItem {
	items := []*sidecartest.PrivacyItem{}
	add := func(name string, message proto.Message) {
		body, err := proto.Marshal(message)
		if err == nil {
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassHandler, Name: name, Body: body})
		}
	}
	for _, preamble := range world.Edge.Preambles() {
		add("smtpedge preamble", preamble)
	}
	for _, result := range world.Edge.Results() {
		add("smtpedge preamble result", result)
	}
	for _, outcome := range world.Edge.Outcomes() {
		add("smtpedge outcome", outcome)
	}
	for _, session := range world.Verifier.Sessions() {
		for _, call := range session.Calls() {
			if 0 < len(call.Data) {
				items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassHandler, Name: "smtpedge " + call.Method, Body: call.Data})
			}
			if part := call.Part; part != nil {
				add("smtpedge part", &protocol.SmtpProof{
					SendId: part.SendId, Index: part.Index, Mode: part.Mode, FirstRecord: part.FirstRecord, LastRecord: part.LastRecord,
					Proof: part.Proof, Last: part.Last, ServerRecordCount: part.ServerRecordCount, Records: part.Records,
					KeyCommitment: part.KeyCommitment, ReplyCount: part.ReplyCount, HeaderRecordCount: part.HeaderRecordCount, Carry: part.Carry,
				})
			}
			for _, released := range call.Released {
				items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassHandler, Name: "smtpedge released", Body: released})
			}
		}
	}
	return items
}

func TestSmtpSendCarriesNoCanaryPastTheDevice(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	var secretLock sync.Mutex
	secretKinds := map[string]int{}
	remove, err := sidecartest.InstallTestHooks(func(kind string, secret []byte) {
		secretLock.Lock()
		secretKinds[kind] += 1
		secretLock.Unlock()
		capture.AddSecret(kind, secret)
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer remove()
	world := sidecartest.NewSmtpSendWorld(t, &sidecartest.SmtpSendWorldSettings{
		Verifier: &sidecartest.FakeSmtpProofScript{HoldAfterClientRecords: 3},
	})
	mx := world.AddDomain("mail.example", "mx.mail.example", netip.MustParseAddr("198.51.100.25"), nil, true)
	host := world.AddHost(sidecartest.SmtpSendWorldProver(1024*1024), nil, capture.Logger("smtp sender"))
	body := capture.CanaryText("mail body")
	subject := capture.CanaryText("mail subject")
	local := capture.CanaryText("recipient local part")
	name := capture.CanaryText("from display name")
	message := world.Message([]string{local + "@mail.example"}, nil, name, subject, "Hello "+body+"\r\n")
	result, err := host.Sender.Send(context.Background(), message)
	if err != nil {
		t.Fatal(err)
	}
	if result.Domains[0].Outcome != sidecar.SmtpOutcomeSent {
		t.Fatalf("outcome %+v", result.Domains[0])
	}
	transactions := mx.Transactions()
	if len(transactions) != 1 {
		t.Fatalf("%d transactions", len(transactions))
	}
	// the destination holds every canary, so a leak would have had them to leak
	for _, canary := range []string{body, subject, name} {
		if !bytes.Contains(transactions[0].Message, []byte(canary)) {
			t.Errorf("the MX got no %q", canary)
		}
	}
	if !bytes.Contains([]byte(transactions[0].Recipients[0]), []byte(local)) {
		t.Errorf("the MX got recipients %v", transactions[0].Recipients)
	}
	capture.AddSource(func() []*sidecartest.PrivacyItem { return smtpEdgePrivacyItems(world) })
	if capture.ItemCount(sidecartest.PrivacyClassHandler) < 10 {
		t.Fatalf("the edge read %d items", capture.ItemCount(sidecartest.PrivacyClassHandler))
	}
	for _, finding := range capture.Scan() {
		t.Error(finding)
	}
	secretLock.Lock()
	signingKeys := secretKinds["dkim_private_key"]
	secretLock.Unlock()
	if signingKeys == 0 {
		t.Error("no DKIM key reached the scan")
	}
	// a canary planted where a server would see it is found, so the clean scan read what it says it read
	capture.Add(sidecartest.PrivacyClassLog, "planted", []byte("a leak of "+body))
	if len(capture.Scan()) == 0 {
		t.Error("the scan missed a planted canary")
	}
}

// A canary in a report through a fixture feedback loop, and one in mail to abuse@, reach only mx-4's listener input:
// the intake stores, logs and counts none of either.
func TestSmtpReportCanariesStayInTheListenerInput(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	store := sidecartest.NewFakeSmtpEdgeStore(clock, nil)
	tokens := sidecartest.NewFakeSmtpNetTokens()
	token := tokens.Add(sidecar.NewId())
	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	settings.Root = "root.example"
	settings.ReportHostName = "rpt.report.example"
	settings.SendingAddresses = []smtpedgeservice.SmtpSendingAddress{{Address: netip.MustParseAddr("192.0.2.10"), HeloName: "o1.out.report.example"}}
	intake, err := smtpedgeservice.NewSmtpReportIntake(host.ServiceHost(), store, &smtpedgeservice.SmtpReportIntakeDeps{
		Tokens: tokens, Keys: sidecartest.NewFakeSmtpReportKeys(), Txt: sidecartest.NewFakeSmtpDnsTxt(), Log: capture.Logger("report intake"),
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	reported := []byte("From: alice@n1.root.example\r\nTo: " + capture.CanaryText("reported local part") + "@mail.example\r\n" +
		"Subject: " + capture.CanaryText("reported subject") + "\r\nMessage-ID: <qvsc2zbwd5c3m5rbnvzxjzpnay@n1.root.example>\r\n\r\n" +
		capture.CanaryText("reported body") + "\r\n")
	arf := sidecartest.BuildSmtpArfReport("loop.example", "abuse", reported, false)
	role := []byte("From: someone@other.example\r\nTo: abuse@root.example\r\nSubject: " + capture.CanaryText("abuse subject") +
		"\r\n\r\n" + capture.CanaryText("abuse body") + "\r\n")
	for _, message := range []*smtpedgeservice.SmtpReportMessage{
		{Recipient: token + "@" + settings.ReportHostName, ArrivalTime: clock.Now().Add(-time.Minute), Raw: arf},
		{Recipient: "abuse@" + settings.Root, ArrivalTime: clock.Now().Add(-time.Minute), Raw: role},
	} {
		if _, err := intake.Accept(ctx, message); err != nil {
			t.Fatal(err)
		}
		capture.Add(sidecartest.PrivacyClassMx4Input, "rpt listener", message.Raw)
	}
	capture.AddSource(store.PrivacyItems)
	for _, finding := range capture.Scan() {
		t.Error(finding)
	}
	// the listener's input held them, and the scan reads every class but that one
	if capture.ItemCount(sidecartest.PrivacyClassMx4Input) != 2 {
		t.Errorf("%d mx-4 items", capture.ItemCount(sidecartest.PrivacyClassMx4Input))
	}
	capture.Add(sidecartest.PrivacyClassPostgres, "planted", arf)
	if len(capture.Scan()) == 0 {
		t.Error("the scan missed the report planted in a store")
	}
}
