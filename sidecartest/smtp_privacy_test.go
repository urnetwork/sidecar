//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// §22.7's privacy rows for §14 at T2 (SMTP-M9-31; R-SMTP-7, R-SMTP-10, I-2, I-13): smtp_send_rows.go's privacy row on
// SmtpSendWorld's stub edge, whose reads are the frames, the records and the parts a real edge reads (T3 runs the same
// row on the smtpedge block's engine, its stores, Redis and logs scanned beside them: server/cli/smtpedge's
// s6_test.go); and a canary in a report through a fixture feedback loop and one in mail to abuse@ reach only mx-4's
// listener input, the one class §2.8 excepts, and nothing the intake stored, logged or counted: with no attribution,
// dropped unread, and attributed, only inside the copies sealed to the network's mail key.

package sidecartest_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

func TestSmtpSendCarriesNoCanaryPastTheDevice(t *testing.T) {
	sidecartest.RunSmtpSendCarriesNoCanaryPastTheDevice(t, sidecartest.NewSmtpSendWorld)
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

// A canary in an attributed report through a fixture feedback loop, and one in role mail to abuse@ about the same
// network, reach mx-4's listener input and the network's sealed copies alone: each complaint row holds its fields and
// its copy sealed to the network's mail key, §21's case its fields, and no row, case, log line or count a canary,
// while the copies are there, so a plaintext one would have been found.
func TestSmtpAttributedReportCanariesStaySealed(t *testing.T) {
	capture := sidecartest.NewPrivacyCapture()
	ctx := context.Background()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	host := sidecartest.NewFakeHost(ctx, clock, nil, nil, nil)
	store := sidecartest.NewFakeSmtpEdgeStore(clock, nil)
	networkId := sidecar.NewId()
	keys := sidecartest.NewFakeSmtpReportKeys()
	keys.Add(networkId)
	join := sidecartest.NewFakeSmtpReportJoin()
	join.Attribute("n1.root.example", networkId, "high")
	sink := sidecartest.NewFakeSmtpAbuseSink()
	loopKey := sidecartest.NewSmtpDkimFixtureEd25519Key("loop", "fbl1", "loop.example")
	txt := sidecartest.NewFakeSmtpDnsTxt()
	txt.Set(loopKey.RecordName(), loopKey.TxtRecord())
	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	settings.Root = "root.example"
	settings.ReportHostName = "rpt.report.example"
	settings.SendingAddresses = []smtpedgeservice.SmtpSendingAddress{{Address: netip.MustParseAddr("192.0.2.10"), HeloName: "o1.out.report.example"}}
	settings.LoopAllowlist = []string{"loop.example"}
	intake, err := smtpedgeservice.NewSmtpReportIntake(host.ServiceHost(), store, &smtpedgeservice.SmtpReportIntakeDeps{
		Tokens: sidecartest.NewFakeSmtpNetTokens(), Keys: keys, Txt: txt, Join: join, Sink: sink, Log: capture.Logger("report intake"),
	}, settings)
	if err != nil {
		t.Fatal(err)
	}
	enclosed := func(messageId string, kind string) []byte {
		return (&sidecartest.SmtpFixtureMessage{
			FromDomain:  "n1.root.example",
			MessageId:   messageId,
			XUrRef:      "1.abcdefghijklmnopqrstuvwxyz234567ab",
			ExtraFields: []string{"Cc: " + capture.CanaryText(kind+" local part") + "@receiver.example"},
			Subject:     capture.CanaryText(kind + " subject"),
			Body:        capture.CanaryText(kind+" body") + "\n",
		}).Bytes()
	}
	arf := sidecartest.SignSmtpDkimFixture(sidecartest.BuildSmtpArfReport("loop.example", "abuse", enclosed("<m1@n1.root.example>", "reported"), false), loopKey,
		&sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true, BodyRelaxed: true, Headers: []string{"from", "to", "subject", "date", "message-id"}})
	role := []byte("From: A Person <person@person.example>\r\nTo: abuse@" + settings.Root + "\r\nSubject: " + capture.CanaryText("abuse subject") + "\r\n" +
		"Content-Type: multipart/mixed; boundary=\"" + sidecartest.SmtpFixtureBoundary + "\"\r\n\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: text/plain\r\n\r\n" + capture.CanaryText("abuse body") + "\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: message/rfc822\r\n\r\n" + string(enclosed("<m2@n1.root.example>", "enclosed")) + "\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "--\r\n")
	for _, report := range []struct {
		message *smtpedgeservice.SmtpReportMessage
		want    smtpedgeservice.SmtpReportOutcome
	}{
		{message: &smtpedgeservice.SmtpReportMessage{Recipient: "root@" + settings.ReportHostName, ArrivalTime: clock.Now().Add(-time.Minute), Raw: arf}, want: smtpedgeservice.SmtpReportOutcomeComplaint},
		{message: &smtpedgeservice.SmtpReportMessage{Recipient: "abuse@" + settings.Root, ArrivalTime: clock.Now().Add(-time.Minute), Raw: role}, want: smtpedgeservice.SmtpReportOutcomeCase},
	} {
		outcome, err := intake.Accept(ctx, report.message)
		if err != nil || outcome != report.want {
			t.Fatalf("%s: %s, %v", report.message.Recipient, outcome, err)
		}
		capture.Add(sidecartest.PrivacyClassMx4Input, "rpt listener", report.message.Raw)
	}
	complaints := store.Complaints()
	if len(complaints) != 2 {
		t.Fatalf("%d complaints", len(complaints))
	}
	for _, complaint := range complaints {
		if complaint.NetworkId != networkId || len(complaint.SealedReport) == 0 {
			t.Errorf("a complaint for %v with %d sealed octets", complaint.NetworkId, len(complaint.SealedReport))
		}
	}
	if len(sink.Reports()) != 1 {
		t.Fatalf("%d cases", len(sink.Reports()))
	}
	capture.AddSource(store.PrivacyItems)
	capture.AddSource(func() []*sidecartest.PrivacyItem {
		items := []*sidecartest.PrivacyItem{}
		for _, report := range sink.Reports() {
			items = append(items, &sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassHandler, Name: "abuse case", Body: []byte(report.Domain + "\x00" + report.Category + "\x00" + report.JoinResult + "\x00" + report.ReporterClass)})
		}
		return items
	})
	for _, finding := range capture.Scan() {
		t.Error(finding)
	}
	// the copies are the network's to open, and a plaintext one in a store is found
	capture.Add(sidecartest.PrivacyClassPostgres, "planted", arf)
	if len(capture.Scan()) == 0 {
		t.Error("the scan missed the report planted in a store")
	}
}
