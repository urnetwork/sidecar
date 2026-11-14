// The engine's lifecycle and readiness, its settings, and the records' hold to §2.8.

package smtpedgeservice_test

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
	"github.com/urnetwork/sidecar/smtpedgeservice"
)

// A verifier with no circuits behind it: enough for readiness, which needs one present.
type refusingVerifier struct{}

// Holds no key set.
func (self refusingVerifier) HoldsKeySet(keySet []byte) bool {
	return false
}

// Refuses every session.
func (self refusingVerifier) NewSmtpProofSession(preamble *sidecar.SmtpProofPreamble) (sidecar.SmtpProofSession, error) {
	return nil, errors.New("no circuits in this test")
}

// Settings for these tests: documentation names and one RFC 5737 sending address.
func testSettings() *smtpedgeservice.SmtpEdgeSettings {
	settings := smtpedgeservice.DefaultSmtpEdgeSettings()
	settings.Root = "root.example"
	settings.ReportHostName = "rpt.report.example"
	settings.SendingAddresses = []smtpedgeservice.SmtpSendingAddress{
		{Address: netip.MustParseAddr("192.0.2.10"), HeloName: "o1.out.report.example"},
	}
	return settings
}

// One engine on a fake host and the fake store.
type testEdge struct {
	ctx     context.Context
	clock   *sidecartest.FakeClock
	faults  *sidecartest.FaultQueue
	host    *sidecartest.FakeHost
	store   *sidecartest.FakeSmtpEdgeStore
	service *smtpedgeservice.SmtpEdgeService
}

// Builds the engine with what a test chooses, leaving it closed at the test's end.
func newTestEdge(t *testing.T, withStore bool, verifier sidecar.SmtpProofVerifier, settings *smtpedgeservice.SmtpEdgeSettings) *testEdge {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	self := &testEdge{ctx: ctx, clock: clock, faults: faults, host: host}
	var store smtpedgeservice.SmtpEdgeStore
	if withStore {
		self.store = sidecartest.NewFakeSmtpEdgeStore(clock, faults)
		store = self.store
	}
	service, err := smtpedgeservice.NewSmtpEdgeService(ctx, host.ServiceHost(), store, verifier, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(service.Close)
	self.service = service
	return self
}

// Waits for count probes, then fails on a metrics rule broken.
func (self *testEdge) awaitProbes(t *testing.T, count int) {
	t.Helper()
	if err := self.service.AwaitProbes(self.ctx, count); err != nil {
		t.Fatal(err)
	}
	if violations := self.host.Metrics.Violations(); len(violations) != 0 {
		t.Fatalf("metrics: %v", violations)
	}
}

func TestSmtpEdgeNotReadyWithoutVerifier(t *testing.T) {
	edge := newTestEdge(t, true, nil, testSettings())
	edge.awaitProbes(t, 1)
	if edge.service.Ready() {
		t.Fatal("ready with no verifier")
	}
	edge.clock.Advance(testSettings().HaltReloadInterval)
	edge.awaitProbes(t, 2)
	if edge.service.Ready() {
		t.Fatal("ready with no verifier after a second probe reached the store")
	}
	if value := edge.host.Metrics.Value("urnetwork_smtpedge_store_probes_total", "ok"); value != 2 {
		t.Fatalf("%v probes reached the store, want 2: readiness failed for want of the verifier alone", value)
	}
}

func TestSmtpEdgeReadyWithStoreVerifierAndAddresses(t *testing.T) {
	edge := newTestEdge(t, true, refusingVerifier{}, testSettings())
	edge.awaitProbes(t, 1)
	if !edge.service.Ready() {
		t.Fatal("not ready with everything present")
	}
}

func TestSmtpEdgeNotReadyWithoutStore(t *testing.T) {
	edge := newTestEdge(t, false, refusingVerifier{}, testSettings())
	edge.awaitProbes(t, 1)
	if edge.service.Ready() {
		t.Fatal("ready with no store")
	}
}

func TestSmtpEdgeNotReadyWithoutSendingAddresses(t *testing.T) {
	settings := testSettings()
	settings.SendingAddresses = nil
	edge := newTestEdge(t, true, refusingVerifier{}, settings)
	edge.awaitProbes(t, 1)
	if edge.service.Ready() {
		t.Fatal("ready with no sending address")
	}
}

func TestSmtpEdgeReadinessFollowsTheStoreProbe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	faults := sidecartest.NewFaultQueue()
	// the first probe fails, before the engine even starts
	if _, err := faults.Add(&sidecartest.FaultPlan{Op: sidecartest.FaultOpHost, KeyPrefix: "smtpedge.ActiveHalts", Result: sidecartest.FailBeforeApply}); err != nil {
		t.Fatal(err)
	}
	host := sidecartest.NewFakeHost(ctx, clock, faults, nil, nil)
	store := sidecartest.NewFakeSmtpEdgeStore(clock, faults)
	service, err := smtpedgeservice.NewSmtpEdgeService(ctx, host.ServiceHost(), store, refusingVerifier{}, testSettings())
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	if err := service.AwaitProbes(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if service.Ready() {
		t.Fatal("ready after a probe that failed")
	}
	clock.Advance(testSettings().HaltReloadInterval)
	if err := service.AwaitProbes(ctx, 2); err != nil {
		t.Fatal(err)
	}
	if !service.Ready() {
		t.Fatal("not ready after a probe that reached the store")
	}
	if host.Metrics.Value("urnetwork_smtpedge_store_probes_total", "failed") != 1 {
		t.Fatal("the failed probe was not counted")
	}
}

func TestSmtpEdgeDrainAndCloseEndReadiness(t *testing.T) {
	edge := newTestEdge(t, true, refusingVerifier{}, testSettings())
	edge.awaitProbes(t, 1)
	edge.service.Drain()
	if edge.service.Ready() {
		t.Fatal("ready while draining")
	}
	edge.service.Close()
	edge.service.Close()
	if edge.service.Ready() {
		t.Fatal("ready after close")
	}
}

func TestSmtpEdgeNeedsMetrics(t *testing.T) {
	if _, err := smtpedgeservice.NewSmtpEdgeService(context.Background(), &sidecar.ServiceHost{}, nil, nil, testSettings()); err == nil {
		t.Fatal("built with no metrics")
	}
}

func TestSmtpEdgeSettingsRefusals(t *testing.T) {
	cases := []struct {
		name   string
		change func(settings *smtpedgeservice.SmtpEdgeSettings)
	}{
		{name: "no root", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.Root = "" }},
		{name: "root with a space", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.Root = "root example" }},
		{name: "no report host", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.ReportHostName = "" }},
		{name: "an IPv6 sending address", change: func(settings *smtpedgeservice.SmtpEdgeSettings) {
			settings.SendingAddresses[0].Address = netip.MustParseAddr("2001:db8::1")
		}},
		{name: "a loopback sending address", change: func(settings *smtpedgeservice.SmtpEdgeSettings) {
			settings.SendingAddresses[0].Address = netip.MustParseAddr("127.0.0.1")
		}},
		{name: "a repeated sending address", change: func(settings *smtpedgeservice.SmtpEdgeSettings) {
			settings.SendingAddresses = append(settings.SendingAddresses, settings.SendingAddresses[0])
		}},
		{name: "a helo with a CR", change: func(settings *smtpedgeservice.SmtpEdgeSettings) {
			settings.SendingAddresses[0].HeloName = "o1.out\r.report.example"
		}},
		{name: "a negative fwmark", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.SendingAddresses[0].Fwmark = -1 }},
		{name: "an allowlisted name that is not LDH", change: func(settings *smtpedgeservice.SmtpEdgeSettings) {
			settings.LoopAllowlist = []string{"loop example"}
		}},
		{name: "a zero bound", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.ReportInflateRatio = 0 }},
		{name: "a negative timeout", change: func(settings *smtpedgeservice.SmtpEdgeSettings) { settings.ClientIdleTimeout = -time.Second }},
	}
	for _, c := range cases {
		settings := testSettings()
		c.change(settings)
		if err := settings.Validate(); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	if err := testSettings().Validate(); err != nil {
		t.Fatalf("the test settings: %v", err)
	}
}

func TestSmtpEdgeSettingsLoad(t *testing.T) {
	text := `
root: root.example
report_host: rpt.report.example
sending_addresses:
  - address: 192.0.2.10
    helo: o1.out.report.example
  - address: 192.0.2.11
    helo: o2.out.report.example
    fwmark: 7
loop_allowlist: [loop.example]
report_inflate_bytes: 1048576
halt_reload_interval: 30s
`
	settings, err := smtpedgeservice.LoadSmtpEdgeSettings([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if len(settings.SendingAddresses) != 2 || settings.SendingAddresses[1].Address != netip.MustParseAddr("192.0.2.11") || settings.SendingAddresses[1].Fwmark != 7 {
		t.Fatalf("sending addresses %+v", settings.SendingAddresses)
	}
	if settings.ReportInflateByteCount != 1024*1024 || settings.HaltReloadInterval != 30*time.Second {
		t.Fatal("a set value did not load")
	}
	if settings.ReportHeaderByteCount != smtpedgeservice.DefaultSmtpEdgeSettings().ReportHeaderByteCount {
		t.Fatal("an unset value lost its default")
	}
	for _, refused := range []string{
		text + "report_inflate_byts: 1\n",
		"report_host: rpt.report.example\n",
		text + "---\nroot: other.example\n",
	} {
		if _, err := smtpedgeservice.LoadSmtpEdgeSettings([]byte(refused)); !errors.Is(err, smtpedgeservice.ErrSmtpEdgeSettingsRefused) {
			t.Errorf("loaded %q: %v", refused, err)
		}
	}
}

// What a record's field may hold: the words of its §2.8 row that allow it, or why it needs none.
type recordFieldRule struct {
	term string
	// A row's own id, which names nothing outside the row.
	structural bool
}

func TestSmtpRecordsHoldNoThirdPartyAddress(t *testing.T) {
	list, err := sidecartest.LoadMetadataList()
	if err != nil {
		t.Fatal(err)
	}
	records := []struct {
		value any
		row   string
		rules map[string]recordFieldRule
		// The only netip.Addr field the record may have: the edge's own sending address.
		addressField string
	}{
		{value: smtpedgeservice.SmtpSendRecord{}, row: "smtp-3", addressField: "SendingAddress", rules: map[string]recordFieldRule{
			"SendId": {term: "send_id"}, "NetworkId": {term: "network"}, "ClientId": {term: "client"},
			"SendingAddress": {term: "sending IP"}, "RecipientDomain": {term: "recipient domain"}, "MxHost": {term: "MX host"},
			"StartTime": {term: "times"}, "EndTime": {term: "times"}, "ByteCount": {term: "bytes"},
			"MessageIdHash": {term: "Message-ID hash"}, "XUrRefKeyId": {term: "X-UR-Ref id"},
			"RecipientCount": {term: "proven counts"}, "MessageByteCount": {term: "proven counts"},
			"TlsVersion": {term: "TLS version"}, "TlsLevel": {term: "TLS version and level"}, "Result": {term: "result"},
			"RetryOfSendId": {term: "retry-of"},
		}},
		{value: smtpedgeservice.SmtpComplaint{}, row: "smtp-5", rules: map[string]recordFieldRule{
			"ComplaintId": {structural: true}, "NetworkId": {term: "per network"}, "Reporter": {term: "reporter"},
			"Type": {term: "type"}, "ArrivalTime": {term: "arrival"}, "Domain": {term: "domain"},
			"DkimDomain": {term: "DKIM d="}, "DkimSelector": {term: "s="}, "DkimResult": {term: "with result"},
			"MessageIdHash": {term: "Message-ID hash"}, "XUrRef": {term: "X-UR-Ref"}, "FeedbackId": {term: "Feedback-ID"},
			"JoinResult": {term: "join result"}, "SealedReport": {term: "sealed report copies"},
		}},
		{value: smtpedgeservice.SmtpAggregateReport{}, row: "smtp-5", rules: map[string]recordFieldRule{
			"Reporter": {term: "reporter"}, "ReportId": {term: "report_id"}, "Kind": {term: "RUA and TLS-RPT aggregates"},
			"Day": {term: "day"}, "ArrivalTime": {term: "arrival"}, "Counts": {term: "counts and results"},
		}},
		{value: smtpedgeservice.SmtpAggregateCount{}, row: "smtp-5", rules: map[string]recordFieldRule{
			"NetworkId": {term: "per network"}, "Domain": {term: "header_from domains, burner labels included"},
			"MessageCount": {term: "counts"}, "DkimPassCount": {term: "counts and results"}, "SpfPassCount": {term: "counts and results"},
			"QuarantineCount": {term: "counts and results"}, "RejectCount": {term: "counts and results"},
			"PolicyType": {term: "TLS-RPT aggregates"}, "SuccessCount": {term: "counts"}, "FailureCount": {term: "counts"},
		}},
		{value: smtpedgeservice.SmtpHalt{}, row: "smtp-4", rules: map[string]recordFieldRule{
			"HaltId": {structural: true}, "NetworkId": {term: "network or burner label"}, "Label": {term: "burner label"},
			"Trigger": {term: "trigger"}, "StartTime": {term: "start"},
		}},
		{value: smtpedgeservice.SmtpDkimKey{}, row: "smtp-6", rules: map[string]recordFieldRule{
			"Selector": {term: "opaque selectors"}, "Domain": {term: "the selectors' DNS records"},
			"NetworkId": {term: "per sending sidecar"}, "SidecarId": {term: "per sending sidecar"},
			"Algorithm": {term: "DKIM public keys"}, "PublicKey": {term: "DKIM public keys"}, "RetireTime": {term: "after rotation"},
		}},
	}
	// names no record may carry, whatever its row says: a recipient address, a third party's or an MX's
	// IP, report or message text, and a session's secrets (D-SMTP-10)
	forbidden := []string{"Received", "Source", "Rcpt", "Envelope", "Subject", "Body", "Text", "Plaintext", "MxIp", "MxAddress", "Shts", "Secret", "Ciphertext", "RecordLength"}
	addressType := reflect.TypeOf(netip.Addr{})
	for _, record := range records {
		recordType := reflect.TypeOf(record.value)
		row := list.Row(record.row)
		if row == nil || !row.Live() {
			t.Fatalf("%s: no live row %s", recordType.Name(), record.row)
		}
		rowText := row.Store + "\n" + row.Sees + "\n" + row.Ttl
		for i := range recordType.NumField() {
			field := recordType.Field(i)
			for _, name := range forbidden {
				if strings.Contains(field.Name, name) {
					t.Errorf("%s.%s names what no row allows", recordType.Name(), field.Name)
				}
			}
			if field.Type == addressType && field.Name != record.addressField {
				t.Errorf("%s.%s holds an address, and only the edge's own sending address may be held", recordType.Name(), field.Name)
			}
			rule, ok := record.rules[field.Name]
			if !ok {
				t.Errorf("%s.%s is in no %s term: add the row's words here, or a §2.8 row first (I-18)", recordType.Name(), field.Name, record.row)
				continue
			}
			if !rule.structural && !strings.Contains(rowText, rule.term) {
				t.Errorf("%s.%s: %s does not say %q", recordType.Name(), field.Name, record.row, rule.term)
			}
		}
		if len(record.rules) != recordType.NumField() {
			t.Errorf("%s: %d rules for %d fields", recordType.Name(), len(record.rules), recordType.NumField())
		}
	}
}

func TestSmtpMessageIdHashIgnoresBracketsAndSpace(t *testing.T) {
	a := smtpedgeservice.SmtpMessageIdHash("<abc@net.root.example>")
	b := smtpedgeservice.SmtpMessageIdHash("  abc@net.root.example ")
	if len(a) != 32 || string(a) != string(b) {
		t.Fatal("the same id hashed apart")
	}
	if smtpedgeservice.SmtpMessageIdHash("<>") != nil {
		t.Fatal("an empty id hashed")
	}
}
