// FS-39's report-intake cases at T2 (§14.8, §22.8): aggregates count once per reporter and report id,
// unverified and unattributable reports leave nothing, the raw bytes are sealed or dropped, and no
// canary from a report reaches a log, a row or a metric. S7's SNI-less abuse@<root> waits for MAIL's
// platform listener to call Accept (MAIL-M5-03).

package smtpedgeservice_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A Logger keeping every line, for a scan.
type captureLogger struct {
	stateLock sync.Mutex
	lines     []string
}

// Keeps a line.
func (self *captureLogger) keep(line string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lines = append(self.lines, line)
}

// Every line so far.
func (self *captureLogger) Lines() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return append([]string{}, self.lines...)
}

// Keeps it.
func (self *captureLogger) Info(args ...any) { self.keep(fmt.Sprint(args...)) }

// Keeps it.
func (self *captureLogger) Infof(format string, args ...any) { self.keep(fmt.Sprintf(format, args...)) }

// Keeps it.
func (self *captureLogger) Warningf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Keeps it.
func (self *captureLogger) Errorf(format string, args ...any) {
	self.keep(fmt.Sprintf(format, args...))
}

// Every level, so a verbose line is caught too.
func (self *captureLogger) V(level int32) sidecar.Verbose { return &captureVerbose{log: self} }

// Every level on.
type captureVerbose struct {
	log *captureLogger
}

// Always.
func (self *captureVerbose) Enabled() bool { return true }

// Keeps it.
func (self *captureVerbose) Info(args ...any) { self.log.Info(args...) }

// Keeps it.
func (self *captureVerbose) Infof(format string, args ...any) { self.log.Infof(format, args...) }

// The intake on fakes of everything it reads.
type testIntake struct {
	ctx     context.Context
	faults  *sidecartest.FaultQueue
	host    *sidecartest.FakeHost
	store   *sidecartest.FakeSmtpEdgeStore
	txt     *sidecartest.FakeSmtpDnsTxt
	tokens  *sidecartest.FakeSmtpNetTokens
	labels  *sidecartest.FakeSmtpLabels
	keys    *sidecartest.FakeSmtpReportKeys
	join    *sidecartest.FakeSmtpReportJoin
	sink    *sidecartest.FakeSmtpAbuseSink
	log     *captureLogger
	intake  *smtpedgeservice.SmtpReportIntake
	arrival time.Time
	// reporter.example, a DMARC reporter, and loop.example, the allowlisted feedback loop.
	reporterKey *sidecartest.SmtpDkimFixtureKey
	loopKey     *sidecartest.SmtpDkimFixtureKey
}

// An intake whose reporters' keys are in DNS. withJoin gives it SMTP-M9-15's place, faked.
func newTestIntake(t *testing.T, withJoin bool) *testIntake {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	self := &testIntake{
		ctx:         ctx,
		faults:      faults,
		host:        sidecartest.NewFakeHost(ctx, clock, faults, nil, nil),
		store:       sidecartest.NewFakeSmtpEdgeStore(clock, faults),
		txt:         sidecartest.NewFakeSmtpDnsTxt(),
		tokens:      sidecartest.NewFakeSmtpNetTokens(),
		labels:      sidecartest.NewFakeSmtpLabels(),
		keys:        sidecartest.NewFakeSmtpReportKeys(),
		sink:        sidecartest.NewFakeSmtpAbuseSink(),
		log:         &captureLogger{},
		arrival:     time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC),
		reporterKey: sidecartest.NewSmtpDkimFixtureRsaKey("rpt1", "reporter.example"),
		loopKey:     sidecartest.NewSmtpDkimFixtureEd25519Key("loop", "fbl1", "loop.example"),
	}
	for _, key := range []*sidecartest.SmtpDkimFixtureKey{self.reporterKey, self.loopKey} {
		self.txt.Set(key.RecordName(), key.TxtRecord())
	}
	deps := &smtpedgeservice.SmtpReportIntakeDeps{Tokens: self.tokens, Labels: self.labels, Keys: self.keys, Txt: self.txt, Sink: self.sink, Log: self.log}
	if withJoin {
		self.join = sidecartest.NewFakeSmtpReportJoin()
		deps.Join = self.join
	}
	settings := testSettings()
	settings.LoopAllowlist = []string{"loop.example"}
	intake, err := smtpedgeservice.NewSmtpReportIntake(self.host.ServiceHost(), self.store, deps, settings)
	if err != nil {
		t.Fatal(err)
	}
	self.intake = intake
	return self
}

// Takes raw for recipient, failing on an error.
func (self *testIntake) accept(t *testing.T, recipient string, raw []byte) smtpedgeservice.SmtpReportOutcome {
	t.Helper()
	outcome, err := self.intake.Accept(self.ctx, &smtpedgeservice.SmtpReportMessage{Recipient: recipient, ArrivalTime: self.arrival, Raw: raw})
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	return outcome
}

// The intake's metric for kind and result.
func (self *testIntake) reports(kind string, result string) float64 {
	return self.host.Metrics.Value("urnetwork_smtpedge_reports_total", kind, result)
}

// The rows dmarc.xml-like reports carry: two from the sending address, one from a third party.
func intakeDmarcRecords() []*sidecartest.SmtpFixtureDmarcRecord {
	return []*sidecartest.SmtpFixtureDmarcRecord{
		{SourceIp: "192.0.2.10", Count: 5, HeaderFrom: "quietnet.root.example", Disposition: "none", DkimAligned: "pass", SpfAligned: "fail", DkimDomain: "quietnet.root.example", DkimSelector: "abcdefghijklmnopqrstuvwxyz", DkimResult: "pass"},
		{SourceIp: "192.0.2.10", Count: 2, HeaderFrom: "quiet-otter.quietnet.root.example", Disposition: "reject", DkimAligned: "fail", SpfAligned: "fail", DkimDomain: "quiet-otter.quietnet.root.example", DkimSelector: "bcdefghijklmnopqrstuvwxyza", DkimResult: "fail"},
		{SourceIp: "198.51.100.7", Count: 9, HeaderFrom: "quietnet.root.example", Disposition: "reject", DkimAligned: "fail", SpfAligned: "fail", DkimDomain: "thirdparty.example", DkimSelector: "x", DkimResult: "fail"},
	}
}

// A gzip XML aggregate for recipient, signed by key.
func dmarcAggregate(key *sidecartest.SmtpDkimFixtureKey, recipient string, orgName string, reportId string, records []*sidecartest.SmtpFixtureDmarcRecord) []byte {
	xml := sidecartest.BuildSmtpDmarcXml(orgName, reportId, time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC), records)
	message := sidecartest.BuildSmtpAggregateMessage(key.Domain, recipient, "application/gzip", "report.xml.gz", sidecartest.SmtpFixtureGzip(xml))
	return sidecartest.SignSmtpDkimFixture(message, key, &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true, BodyRelaxed: true, Headers: []string{"from", "to", "subject", "date", "message-id"}})
}

// An ARF report from key about an enclosed message of fromDomain, its body holding bodyText.
func arfFrom(key *sidecartest.SmtpDkimFixtureKey, fromDomain string, subject string, bodyText string) []byte {
	enclosed := (&sidecartest.SmtpFixtureMessage{
		FromDomain:  fromDomain,
		MessageId:   "<m1@" + fromDomain + ">",
		XUrRef:      "1.abcdefghijklmnopqrstuvwxyz234567ab",
		Subject:     subject,
		Body:        bodyText,
		ExtraFields: []string{"Received: from o1.out.report.example (o1.out.report.example [192.0.2.10]) by mx.receiver.example; Tue, 03 Nov 2026 10:00:01 +0000"},
	}).Bytes()
	report := sidecartest.BuildSmtpArfReport(key.Domain, "abuse", enclosed, false)
	return sidecartest.SignSmtpDkimFixture(report, key, &sidecartest.SmtpDkimFixtureOptions{HeaderRelaxed: true, BodyRelaxed: true, Headers: []string{"from", "to", "subject", "date", "message-id"}})
}

// A person's mail to a role address enclosing a message of fromDomain.
func roleMail(fromDomain string, subject string, bodyText string) []byte {
	enclosed := (&sidecartest.SmtpFixtureMessage{FromDomain: fromDomain, MessageId: "<m2@" + fromDomain + ">", Subject: subject, Body: bodyText}).Bytes()
	return []byte("From: A Person <person@person.example>\r\nTo: abuse@root.example\r\nSubject: spam from your network\r\n" +
		"Content-Type: multipart/mixed; boundary=\"" + sidecartest.SmtpFixtureBoundary + "\"\r\n\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: text/plain\r\n\r\nPlease look at the attached.\r\n" +
		"--" + sidecartest.SmtpFixtureBoundary + "\r\nContent-Type: message/rfc822\r\n\r\n" + string(enclosed) + "\r\n--" + sidecartest.SmtpFixtureBoundary + "--\r\n")
}

func TestReportIntakeCountsAGzipXmlAggregateOncePerReporterAndReportId(t *testing.T) {
	ti := newTestIntake(t, false)
	networkId := sidecar.NewId()
	token := ti.tokens.Add(networkId)
	recipient := token + "@rpt.report.example"
	raw := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "report-1", intakeDmarcRecords())
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("first: %s", outcome)
	}
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeDuplicate {
		t.Fatalf("a repeat: %s", outcome)
	}
	aggregates := ti.store.Aggregates()
	if len(aggregates) != 1 {
		t.Fatalf("%d aggregates", len(aggregates))
	}
	report := aggregates[0]
	if report.Reporter != "reporter.example" || report.ReportId != "report-1" || report.Kind != smtpedgeservice.SmtpAggregateKindDmarc ||
		!report.Day.Equal(time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC)) || !report.ArrivalTime.Equal(ti.arrival) {
		t.Fatalf("%+v", report)
	}
	if len(report.Counts) != 2 {
		t.Fatalf("%d counts", len(report.Counts))
	}
	network := report.Counts[0]
	burner := report.Counts[1]
	if network.NetworkId != networkId || network.Domain != "quietnet.root.example" || network.MessageCount != 5 || network.DkimPassCount != 5 || network.SpfPassCount != 0 {
		t.Fatalf("the network's count %+v", network)
	}
	if burner.NetworkId != networkId || burner.Domain != "quiet-otter.quietnet.root.example" || burner.MessageCount != 2 || burner.RejectCount != 2 {
		t.Fatalf("the burner's count %+v", burner)
	}
	// another reporter's report of the same id is another report
	otherKey := sidecartest.NewSmtpDkimFixtureEd25519Key("other", "o1", "other-reporter.example")
	ti.txt.Set(otherKey.RecordName(), otherKey.TxtRecord())
	if outcome := ti.accept(t, recipient, dmarcAggregate(otherKey, recipient, "other-reporter.example", "report-1", intakeDmarcRecords())); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("another reporter: %s", outcome)
	}
	if ti.reports("dmarc", "counted") != 2 || ti.reports("dmarc", "duplicate") != 1 {
		t.Fatal("the metrics do not match")
	}
	if violations := ti.host.Metrics.Violations(); len(violations) != 0 {
		t.Fatalf("metrics: %v", violations)
	}
}

func TestReportIntakeCountsAGzipJsonTlsRptAggregateOnce(t *testing.T) {
	ti := newTestIntake(t, false)
	networkId := sidecar.NewId()
	recipient := ti.tokens.Add(networkId) + "@rpt.report.example"
	json := sidecartest.BuildSmtpTlsRptJson("reporter.example", "tlsrpt-1", time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC), []*sidecartest.SmtpFixtureTlsRptPolicy{
		{PolicyType: "sts", PolicyDomain: "quietnet.root.example", SuccessCount: 120, FailureCount: 3, SendingMtaIp: "198.51.100.33"},
	})
	message := sidecartest.BuildSmtpAggregateMessage("reporter.example", recipient, "application/tlsrpt+gzip", "report.json.gz", sidecartest.SmtpFixtureGzip(json))
	raw := sidecartest.SignSmtpDkimFixture(message, ti.reporterKey, &sidecartest.SmtpDkimFixtureOptions{Headers: []string{"from", "subject"}})
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("first: %s", outcome)
	}
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeDuplicate {
		t.Fatalf("a repeat: %s", outcome)
	}
	aggregates := ti.store.Aggregates()
	if len(aggregates) != 1 || aggregates[0].Kind != smtpedgeservice.SmtpAggregateKindTlsRpt {
		t.Fatalf("%d aggregates", len(aggregates))
	}
	count := aggregates[0].Counts[0]
	if count.PolicyType != "sts" || count.SuccessCount != 120 || count.FailureCount != 3 || count.NetworkId != networkId {
		t.Fatalf("%+v", count)
	}
	if ti.reports("tlsrpt", "counted") != 1 {
		t.Fatal("the metric does not match")
	}
}

func TestReportIntakeUnverifyingReporterCountsNothing(t *testing.T) {
	ti := newTestIntake(t, false)
	recipient := ti.tokens.Add(sidecar.NewId()) + "@rpt.report.example"
	// signed under a key DNS does not hold for that selector
	forger := sidecartest.NewSmtpDkimFixtureEd25519Key("forger", "rpt1", "reporter.example")
	if outcome := ti.accept(t, recipient, dmarcAggregate(forger, recipient, "reporter.example", "forged-1", intakeDmarcRecords())); outcome != smtpedgeservice.SmtpReportOutcomeUnverified {
		t.Fatalf("a forged signature: %s", outcome)
	}
	// not signed at all
	xml := sidecartest.BuildSmtpDmarcXml("reporter.example", "unsigned-1", time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC), intakeDmarcRecords())
	unsigned := sidecartest.BuildSmtpAggregateMessage("reporter.example", recipient, "application/gzip", "r.xml.gz", sidecartest.SmtpFixtureGzip(xml))
	if outcome := ti.accept(t, recipient, unsigned); outcome != smtpedgeservice.SmtpReportOutcomeUnverified {
		t.Fatalf("an unsigned report: %s", outcome)
	}
	if len(ti.store.Aggregates()) != 0 || len(ti.store.Complaints()) != 0 {
		t.Fatal("an unverified report left a row")
	}
}

func TestReportIntakeUnknownTokenDropsUnread(t *testing.T) {
	ti := newTestIntake(t, true)
	unknown := strings.Repeat("a", 26) + "@rpt.report.example"
	raw := dmarcAggregate(ti.reporterKey, unknown, "reporter.example", "report-2", intakeDmarcRecords())
	if outcome := ti.accept(t, unknown, raw); outcome != smtpedgeservice.SmtpReportOutcomeUnknownRecipient {
		t.Fatalf("an unknown token: %s", outcome)
	}
	if len(ti.tokens.Lookups()) != 1 {
		t.Fatal("the token was not looked up")
	}
	// not a token's shape, another host, another role: no lookup at all
	for _, recipient := range []string{strings.Repeat("a", 25) + "@rpt.report.example", "aaaaaaaaaaaaaaaaaaaaaaaaa1@rpt.report.example", "info@root.example", "abuse@other.example", "no-at-sign"} {
		if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeUnknownRecipient {
			t.Errorf("%s: %s", recipient, outcome)
		}
	}
	if len(ti.tokens.Lookups()) != 1 {
		t.Fatal("a recipient of no token's shape was looked up")
	}
	// unread: no reporter key fetched, no store call, no join
	if len(ti.txt.Lookups()) != 0 || len(ti.store.OpCounts()) != 0 || ti.join.JoinedReports() != 0 {
		t.Fatal("a report to nobody was read")
	}
	if ti.reports("unknown", "unknown_recipient") != 6 {
		t.Fatal("the metric does not match")
	}
}

func TestReportIntakeWithNoMailKeyKeepsFieldsAndDropsTheRawBytes(t *testing.T) {
	ti := newTestIntake(t, false)
	capture := sidecartest.NewPrivacyCapture()
	canary := capture.CanaryText("aggregate org name")
	networkId := sidecar.NewId()
	recipient := ti.tokens.Add(networkId) + "@rpt.report.example"
	if outcome := ti.accept(t, recipient, dmarcAggregate(ti.reporterKey, recipient, canary, "report-3", intakeDmarcRecords())); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("%s", outcome)
	}
	if len(ti.store.Aggregates()) != 1 {
		t.Fatal("the counts were not kept")
	}
	if len(ti.store.Complaints()) != 0 {
		t.Fatal("a sealed-copy row was written with nothing to seal")
	}
	capture.AddSource(ti.store.PrivacyItems)
	for _, line := range ti.log.Lines() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	if hits := capture.Scan(); len(hits) != 0 {
		t.Fatalf("the raw report was kept: %v", hits)
	}
}

func TestReportIntakeSealedCopyOpensToTheRawReport(t *testing.T) {
	ti := newTestIntake(t, false)
	networkId := sidecar.NewId()
	privateKey := ti.keys.Add(networkId)
	recipient := ti.tokens.Add(networkId) + "@rpt.report.example"
	raw := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "report-4", intakeDmarcRecords())
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("%s", outcome)
	}
	complaints := ti.store.Complaints()
	if len(complaints) != 1 {
		t.Fatalf("%d complaint rows", len(complaints))
	}
	home := complaints[0]
	if home.Type != smtpedgeservice.SmtpComplaintTypeRua || home.NetworkId != networkId || home.Reporter != "reporter.example" || home.Domain != "quietnet.root.example" {
		t.Fatalf("%+v", home)
	}
	opened, err := smtpedgeservice.OpenSealedReport(privateKey, networkId, ti.arrival, home.SealedReport)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("the sealed copy does not open to the report: %v", err)
	}
	if _, err := smtpedgeservice.OpenSealedReport(privateKey, sidecar.NewId(), ti.arrival, home.SealedReport); !errors.Is(err, smtpedgeservice.ErrSmtpSealedReportOpen) {
		t.Fatal("a copy opened as another network's")
	}
	if _, err := smtpedgeservice.OpenSealedReport(privateKey, networkId, ti.arrival.Add(time.Millisecond), home.SealedReport); !errors.Is(err, smtpedgeservice.ErrSmtpSealedReportOpen) {
		t.Fatal("a copy opened as another arrival's")
	}
	truncated := home.SealedReport[:len(home.SealedReport)-1]
	if _, err := smtpedgeservice.OpenSealedReport(privateKey, networkId, ti.arrival, truncated); !errors.Is(err, smtpedgeservice.ErrSmtpSealedReportOpen) {
		t.Fatal("a truncated copy opened")
	}
}

func TestReportIntakeSealsAReportOfManyChunks(t *testing.T) {
	ti := newTestIntake(t, false)
	networkId := sidecar.NewId()
	privateKey := ti.keys.Add(networkId)
	recipient := ti.tokens.Add(networkId) + "@rpt.report.example"
	// past three 64 KiB chunks, the aggregate's records making up the size
	records := intakeDmarcRecords()
	for len(records) < 1800 {
		records = append(records, intakeDmarcRecords()[2])
	}
	xml := sidecartest.BuildSmtpDmarcXml("reporter.example", "big-1", time.Date(2026, time.November, 2, 0, 0, 0, 0, time.UTC), records)
	message := sidecartest.BuildSmtpAggregateMessage("reporter.example", recipient, "text/xml", "report.xml", xml)
	raw := sidecartest.SignSmtpDkimFixture(message, ti.reporterKey, nil)
	if len(raw) < 3*64*1024 {
		t.Fatalf("a report of only %d bytes", len(raw))
	}
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("%s", outcome)
	}
	opened, err := smtpedgeservice.OpenSealedReport(privateKey, networkId, ti.arrival, ti.store.Complaints()[0].SealedReport)
	if err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("a many-chunk copy does not open to the report: %v", err)
	}
}

func TestReportIntakeSplitsRootRowsByHeaderFromLabel(t *testing.T) {
	ti := newTestIntake(t, false)
	quietnet := sidecar.NewId()
	othernet := sidecar.NewId()
	ti.labels.Set("quietnet", quietnet)
	ti.labels.Set("othernet", othernet)
	// keys exist, but <root>'s copy names many networks and is sealed to none
	ti.keys.Add(quietnet)
	ti.keys.Add(othernet)
	records := append(intakeDmarcRecords(),
		&sidecartest.SmtpFixtureDmarcRecord{SourceIp: "192.0.2.10", Count: 3, HeaderFrom: "othernet.root.example", Disposition: "none", DkimAligned: "pass", SpfAligned: "fail"},
		&sidecartest.SmtpFixtureDmarcRecord{SourceIp: "192.0.2.10", Count: 4, HeaderFrom: "unknownnet.root.example", Disposition: "none", DkimAligned: "pass", SpfAligned: "fail"},
		&sidecartest.SmtpFixtureDmarcRecord{SourceIp: "192.0.2.10", Count: 6, HeaderFrom: "notunder.example", Disposition: "none", DkimAligned: "pass", SpfAligned: "fail"},
	)
	recipient := "root@rpt.report.example"
	if outcome := ti.accept(t, recipient, dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "root-1", records)); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("%s", outcome)
	}
	counts := ti.store.Aggregates()[0].Counts
	want := []struct {
		networkId sidecar.Id
		domain    string
		count     uint64
	}{
		{networkId: quietnet, domain: "quietnet.root.example", count: 5},
		{networkId: quietnet, domain: "quiet-otter.quietnet.root.example", count: 2},
		{networkId: othernet, domain: "othernet.root.example", count: 3},
	}
	if len(counts) != len(want) {
		t.Fatalf("%d counts", len(counts))
	}
	for i, w := range want {
		if counts[i].NetworkId != w.networkId || counts[i].Domain != w.domain || counts[i].MessageCount != w.count {
			t.Errorf("count %d: %+v", i, counts[i])
		}
	}
	if len(ti.store.Complaints()) != 0 {
		t.Fatal("<root>'s report was sealed to a network")
	}
}

func TestReportIntakeArfIsUnattributedUntilAJoinLands(t *testing.T) {
	ti := newTestIntake(t, false)
	if outcome := ti.accept(t, "root@rpt.report.example", arfFrom(ti.loopKey, "quietnet.root.example", "hi", "body")); outcome != smtpedgeservice.SmtpReportOutcomeUnattributed {
		t.Fatalf("%s", outcome)
	}
	// dropped unread: not even the reporter's key was fetched
	if len(ti.txt.Lookups()) != 0 || len(ti.store.OpCounts()) != 0 {
		t.Fatal("an unattributable report was read past its headers")
	}
	if ti.reports("arf", "unattributed") != 1 {
		t.Fatal("the metric does not match")
	}
}

func TestReportIntakeArfFromAnAllowlistedLoopIsAComplaint(t *testing.T) {
	ti := newTestIntake(t, true)
	networkId := sidecar.NewId()
	privateKey := ti.keys.Add(networkId)
	ti.join.Attribute("quietnet.root.example", networkId, "high")
	raw := arfFrom(ti.loopKey, "quietnet.root.example", "hi", "body")
	if outcome := ti.accept(t, "root@rpt.report.example", raw); outcome != smtpedgeservice.SmtpReportOutcomeComplaint {
		t.Fatalf("%s", outcome)
	}
	complaints := ti.store.Complaints()
	if len(complaints) != 1 {
		t.Fatalf("%d complaints", len(complaints))
	}
	complaint := complaints[0]
	if complaint.Type != smtpedgeservice.SmtpComplaintTypeAbuse || complaint.Reporter != "loop.example" || complaint.NetworkId != networkId ||
		complaint.Domain != "quietnet.root.example" || complaint.JoinResult != "high" || complaint.XUrRef != "1.abcdefghijklmnopqrstuvwxyz234567ab" ||
		!bytes.Equal(complaint.MessageIdHash, smtpedgeservice.SmtpMessageIdHash("<m1@quietnet.root.example>")) || !complaint.ArrivalTime.Equal(ti.arrival) {
		t.Fatalf("%+v", complaint)
	}
	if opened, err := smtpedgeservice.OpenSealedReport(privateKey, networkId, ti.arrival, complaint.SealedReport); err != nil || !bytes.Equal(opened, raw) {
		t.Fatalf("the complaint's sealed copy: %v", err)
	}
	if len(ti.sink.Reports()) != 0 {
		t.Fatal("a loop's complaint reached the abuse sink, which only role mail does at M5")
	}
}

func TestReportIntakeArfFromAReporterOffTheAllowlistCountsNothing(t *testing.T) {
	ti := newTestIntake(t, true)
	ti.join.Attribute("quietnet.root.example", sidecar.NewId(), "high")
	if outcome := ti.accept(t, "root@rpt.report.example", arfFrom(ti.reporterKey, "quietnet.root.example", "hi", "body")); outcome != smtpedgeservice.SmtpReportOutcomeUnverified {
		t.Fatalf("%s", outcome)
	}
	if len(ti.store.Complaints()) != 0 {
		t.Fatal("a reporter off the allowlist left a complaint")
	}
}

func TestReportIntakeRoleMailAttributedOpensACase(t *testing.T) {
	ti := newTestIntake(t, true)
	networkId := sidecar.NewId()
	ti.join.Attribute("quietnet.root.example", networkId, "medium")
	if outcome := ti.accept(t, "Abuse@Root.Example", roleMail("quietnet.root.example", "buy now", "the spam")); outcome != smtpedgeservice.SmtpReportOutcomeCase {
		t.Fatalf("%s", outcome)
	}
	complaints := ti.store.Complaints()
	if len(complaints) != 1 || complaints[0].Type != smtpedgeservice.SmtpComplaintTypeRole || complaints[0].Reporter != "" {
		t.Fatalf("%+v", complaints)
	}
	reports := ti.sink.Reports()
	if len(reports) != 1 {
		t.Fatalf("%d cases", len(reports))
	}
	report := reports[0]
	if report.ComplaintId != complaints[0].ComplaintId || report.NetworkId != networkId || report.Domain != "quietnet.root.example" ||
		report.Category != smtpedgeservice.SmtpComplaintTypeRole || report.JoinResult != "medium" || report.ReporterClass != smtpedgeservice.SmtpReporterClassRole {
		t.Fatalf("%+v", report)
	}
	// the person who wrote is in no row and no log
	capture := sidecartest.NewPrivacyCapture()
	capture.AddSource(ti.store.PrivacyItems)
	for _, line := range ti.log.Lines() {
		capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
	}
	capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "case", Body: []byte(fmt.Sprintf("%+v", report))})
	if hits := capture.Scan(); len(hits) != 0 {
		t.Fatalf("%v", hits)
	}
	for _, item := range ti.store.PrivacyItems() {
		if bytes.Contains(item.Body, []byte("person@person.example")) || bytes.Contains(item.Body, []byte("buy now")) {
			t.Fatalf("%s holds the role mail's sender or subject", item.Name)
		}
	}
}

func TestReportIntakeUnattributedRoleMailDropsUnread(t *testing.T) {
	ti := newTestIntake(t, true)
	if outcome := ti.accept(t, "postmaster@root.example", roleMail("othernet.root.example", "x", "y")); outcome != smtpedgeservice.SmtpReportOutcomeUnattributed {
		t.Fatalf("%s", outcome)
	}
	if len(ti.store.Complaints()) != 0 || len(ti.sink.Reports()) != 0 {
		t.Fatal("unattributable role mail left a row or a case")
	}
	// a role mail enclosing nothing has nothing to join
	if outcome := ti.accept(t, "abuse@root.example", []byte("From: p@person.example\r\nContent-Type: text/plain\r\n\r\nyour network spams me")); outcome != smtpedgeservice.SmtpReportOutcomeRefused {
		t.Fatalf("a bare role mail: %s", outcome)
	}
}

func TestReportIntakeArfBodyCanaryInNoLogRowOrMetric(t *testing.T) {
	for _, withKey := range []bool{false, true} {
		ti := newTestIntake(t, true)
		capture := sidecartest.NewPrivacyCapture()
		bodyCanary := capture.CanaryText("enclosed body")
		subjectCanary := capture.CanaryText("enclosed subject")
		networkId := sidecar.NewId()
		if withKey {
			ti.keys.Add(networkId)
		}
		ti.join.Attribute("quietnet.root.example", networkId, "high")
		if outcome := ti.accept(t, "root@rpt.report.example", arfFrom(ti.loopKey, "quietnet.root.example", subjectCanary, bodyCanary)); outcome != smtpedgeservice.SmtpReportOutcomeComplaint {
			t.Fatalf("with key %v: %s", withKey, outcome)
		}
		if outcome := ti.accept(t, "abuse@root.example", roleMail("quietnet.root.example", subjectCanary, bodyCanary)); outcome != smtpedgeservice.SmtpReportOutcomeCase {
			t.Fatalf("with key %v, role: %s", withKey, outcome)
		}
		capture.AddSource(ti.store.PrivacyItems)
		for _, line := range ti.log.Lines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "log", Body: []byte(line)})
		}
		for _, line := range ti.host.Metrics.Dump() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "metric", Body: []byte(line)})
		}
		for _, report := range ti.sink.Reports() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: "CC4", Name: "case", Body: []byte(fmt.Sprintf("%+v", report))})
		}
		if hits := capture.Scan(); len(hits) != 0 {
			t.Fatalf("with key %v: %v", withKey, hits)
		}
	}
}

func TestReportIntakeStoreFailureAsksForARetry(t *testing.T) {
	ti := newTestIntake(t, false)
	recipient := ti.tokens.Add(sidecar.NewId()) + "@rpt.report.example"
	raw := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "retry-1", intakeDmarcRecords())
	if _, err := ti.faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "smtpedge.InsertAggregate", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	if _, err := ti.intake.Accept(ti.ctx, &smtpedgeservice.SmtpReportMessage{Recipient: recipient, ArrivalTime: ti.arrival, Raw: raw}); err == nil {
		t.Fatal("a store failure was taken as done")
	}
	if ti.reports("dmarc", "failed") != 1 {
		t.Fatal("the failure was not counted")
	}
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("the retry: %s", outcome)
	}
	for _, line := range ti.log.Lines() {
		if strings.Contains(line, "retry-1") || strings.Contains(line, recipient) {
			t.Fatalf("a log line holds report text: %q", line)
		}
	}
}

func TestReportIntakeReporterKeyNotAnsweringAsksForARetry(t *testing.T) {
	ti := newTestIntake(t, false)
	recipient := ti.tokens.Add(sidecar.NewId()) + "@rpt.report.example"
	raw := dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "dns-1", intakeDmarcRecords())
	ti.txt.SetFailing(ti.reporterKey.RecordName(), true)
	if _, err := ti.intake.Accept(ti.ctx, &smtpedgeservice.SmtpReportMessage{Recipient: recipient, ArrivalTime: ti.arrival, Raw: raw}); err == nil {
		t.Fatal("a DNS failure was taken as unverified")
	}
	ti.txt.SetFailing(ti.reporterKey.RecordName(), false)
	if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeCounted {
		t.Fatalf("the retry: %s", outcome)
	}
}

func TestReportIntakeRefusesWhatItCannotRead(t *testing.T) {
	ti := newTestIntake(t, false)
	recipient := ti.tokens.Add(sidecar.NewId()) + "@rpt.report.example"
	for _, raw := range [][]byte{
		[]byte("no header block ever ends"),
		[]byte("From: a@reporter.example\r\nContent-Type: text/plain\r\n\r\nno report"),
		dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "dtd-1", nil)[:0],
	} {
		if outcome := ti.accept(t, recipient, raw); outcome != smtpedgeservice.SmtpReportOutcomeRefused {
			t.Errorf("%q: %s", raw, outcome)
		}
	}
	// an aggregate from a verified reporter whose rows are all third parties' counts nothing
	thirdParty := []*sidecartest.SmtpFixtureDmarcRecord{intakeDmarcRecords()[2]}
	if outcome := ti.accept(t, recipient, dmarcAggregate(ti.reporterKey, recipient, "reporter.example", "third-1", thirdParty)); outcome != smtpedgeservice.SmtpReportOutcomeEmpty {
		t.Fatalf("an aggregate of third parties: %s", outcome)
	}
	if len(ti.store.Aggregates()) != 0 {
		t.Fatal("a refused report left a row")
	}
}

func TestReportIntakeNeedsASinkBesideAJoin(t *testing.T) {
	host := sidecartest.NewFakeHost(context.Background(), nil, nil, nil, nil)
	deps := &smtpedgeservice.SmtpReportIntakeDeps{Join: sidecartest.NewFakeSmtpReportJoin()}
	if _, err := smtpedgeservice.NewSmtpReportIntake(host.ServiceHost(), sidecartest.NewFakeSmtpEdgeStore(nil, nil), deps, testSettings()); err == nil {
		t.Fatal("an attribution with nowhere to send role mail was built")
	}
	if _, err := smtpedgeservice.NewSmtpReportIntake(host.ServiceHost(), nil, nil, testSettings()); err == nil {
		t.Fatal("an intake with no store was built")
	}
}
