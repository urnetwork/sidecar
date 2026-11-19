//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// §22.7's privacy rows for §14 at T2 (SMTP-M9-31; R-SMTP-7, R-SMTP-10, I-2, I-13): smtp_send_rows.go's privacy row on
// SmtpSendWorld's stub edge, whose reads are the frames, the records and the parts a real edge reads (T3 runs the same
// row on the smtpedge block's engine, its stores, Redis and logs scanned beside them: server/cli/smtpedge's
// s6_test.go); and a canary in a report through a fixture feedback loop and one in mail to abuse@ reach only mx-4's
// listener input, the one class §2.8 excepts, and nothing the intake stored, logged or counted.

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
