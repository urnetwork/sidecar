// FS-33 at T2 (§22.7's strict-mode row; MAIL-M7-24, D-MAIL-12, FI-11, owner decision 98): over MxWorld's signed zones
// and the zone watch's StrictChain on them, C20's stand-in. A direct MX in URnetwork's zone is redirected by changing
// only operator records: a DANE sender's validated TLSA then holds the substitute's key, and no mail on that path can
// carry tls_basis.strict_custom_mx, since strict mode refuses a URnetwork-zone splice and seals no strict_chain for it.
// A customer-signed zone's custom MX cannot be redirected by operator records: its chain holds this receiver's key
// before and after the operator's writes, so its mail carries the claim, whose words state only the residual.

package sidecartest_test

import (
	"context"
	"crypto/sha256"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Resolvers that answer nothing, for a watch whose passes this scenario never reads.
type strictScenarioResolver struct{}

func (strictScenarioResolver) ResolverCount() int {
	return 2
}

func (strictScenarioResolver) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*sidecar.DnsWatchAnswer, error) {
	return &sidecar.DnsWatchAnswer{Values: []string{}}, nil
}

const (
	strictScenarioRoot     = "root.example."
	strictScenarioPlatform = "platform.example."
	strictScenarioLabel    = "lbl0000001"
	strictScenarioMx       = "mx.lbl0000001.root.example"
	strictScenarioCustomMx = "mx.customer.example"
)

// A TLSA 3 1 1 record of spki.
func strictScenarioTlsa(spki []byte) *sidecar.SmtpTlsaRecord {
	return &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: spki}
}

// The scenario's world, its watch under strict mode and the receiver's and the substitute's keys.
type strictScenario struct {
	world      *sidecartest.MxWorld
	policy     *sidecar.MailStrictPolicy
	receiver   []byte
	substitute []byte
	clock      *sidecartest.FakeClock
}

func newStrictScenario(t *testing.T) *strictScenario {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultMxWorldSettings()
	settings.Clock = clock
	world, err := sidecartest.NewMxWorld(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{strictScenarioRoot, strictScenarioPlatform, "customer.example."} {
		if err := world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	receiver := sha256.Sum256([]byte("the receiver's key"))
	substitute := sha256.Sum256([]byte("an operator's substitute's key"))
	anchors, err := sidecar.NewSmtpDnssecAnchors(world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	watchSettings := sidecar.DefaultDnsWatchSettings()
	watchSettings.UrnetworkZones = []string{strictScenarioPlatform}
	watch, err := sidecar.NewDnsWatch(context.Background(), &sidecar.DnsWatchArgs{
		Resolver: strictScenarioResolver{},
		Store:    sidecartest.NewFakeStore().Root(),
		Zone: func(ctx context.Context) (*sidecar.DnsZone, error) {
			return &sidecar.DnsZone{NetworkId: sidecar.NewId(), Root: strictScenarioRoot, Label: strictScenarioLabel, Version: 1}, nil
		},
		PublishedHosts: func() []string { return nil },
		Settings:       watchSettings,
		Clock:          clock,
		Strict:         sidecar.NewDnsWatchStrictValidator(world, anchors, nil),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(watch.Close)
	policy := sidecar.NewMailStrictPolicy(&sidecar.MailStrictPolicyArgs{
		Strict: func() bool { return true },
		Root:   func() string { return strictScenarioRoot },
		Chain:  watch.StrictChain,
	})
	return &strictScenario{world: world, policy: policy, receiver: receiver[:], substitute: substitute[:], clock: clock}
}

// A label decided for a receiver's deposit whose sealed evidence carries strictChain.
func strictScenarioLabelOf(strictChain bool) *sidecar.MailLabelResult {
	messageSha256 := sha256.Sum256([]byte("a message"))
	receiverId := sidecar.NewId()
	deposit := &protocol.MailDeposit{
		Version:           1,
		Recipients:        []string{"ann@customer.example"},
		ReceiverSidecarId: receiverId.Bytes(),
		Evidence: &protocol.MailAuthEvidence{
			Version: 1, MessageSha256: messageSha256[:], ReceiverSidecarId: receiverId.Bytes(), StrictChain: strictChain,
		},
	}
	return sidecar.MailLabelDecide(&sidecar.MailLabelInput{Deposit: deposit, MessageSha256: messageSha256[:], Root: strings.TrimSuffix(strictScenarioRoot, ".")})
}

// FS-33's first half: a URnetwork-zone direct MX, redirected by changing only operator records. A DANE sender's
// validated answer holds the substitute's key; strict mode takes no splice for the host and seals strict_chain for no
// key on it, so no mail on that path carries the claim.
func TestStrictScenarioAUrnetworkZoneDirectMxIsRedirectable(t *testing.T) {
	scenario := newStrictScenario(t)
	ctx := context.Background()
	if err := scenario.world.SetMx("lbl0000001.root.example", &sidecar.SmtpMxHost{Preference: 10, Host: strictScenarioMx}); err != nil {
		t.Fatal(err)
	}
	// the direct MX: the receiver's own address and TLSA
	if err := scenario.world.AddMx(strictScenarioMx, netip.MustParseAddr("192.0.2.25"), nil, strictScenarioTlsa(scenario.receiver)); err != nil {
		t.Fatal(err)
	}
	// the operator's write, in its own signed zone: a substitute's address and TLSA beside the receiver's
	if err := scenario.world.AddMx(strictScenarioMx, netip.MustParseAddr("198.51.100.66"), nil, strictScenarioTlsa(scenario.substitute)); err != nil {
		t.Fatal(err)
	}
	answer, err := scenario.world.LookupTlsa(ctx, strictScenarioMx)
	if err != nil {
		t.Fatal(err)
	}
	if !answer.Secure || !slices.ContainsFunc(answer.Records, func(record *sidecar.SmtpTlsaRecord) bool { return string(record.Data) == string(scenario.substitute) }) {
		t.Fatalf("a DANE sender does not validate the substitute's key: secure %t, %d records", answer.Secure, len(answer.Records))
	}
	for _, key := range [][]byte{scenario.receiver, scenario.substitute} {
		if scenario.policy.AdmitSplice(ctx, strictScenarioMx, key) {
			t.Error("strict mode took a URnetwork-zone splice")
		}
		if scenario.policy.StrictChain(ctx, strictScenarioMx, []string{"lbl0000001.root.example"}, key) {
			t.Error("strict_chain sealed for a URnetwork-zone host")
		}
	}
	if label := strictScenarioLabelOf(false); label.Basis.GetStrictCustomMx() {
		t.Fatal("mail without strict_chain carries the claim")
	}
}

// FS-33's second half: a customer-signed zone's custom MX. Operator records cannot redirect it: its chain holds this
// receiver's key before and after the operator writes its own zones, never the substitute's, and its mail carries
// the claim, whose words say only that URnetwork could not redirect a DANE-validating sender.
func TestStrictScenarioACustomerSignedCustomMxCarriesTheClaim(t *testing.T) {
	scenario := newStrictScenario(t)
	ctx := context.Background()
	if err := scenario.world.SetMx("customer.example", &sidecar.SmtpMxHost{Preference: 10, Host: strictScenarioCustomMx}); err != nil {
		t.Fatal(err)
	}
	if err := scenario.world.AddMx(strictScenarioCustomMx, netip.MustParseAddr("192.0.2.26"), nil, strictScenarioTlsa(scenario.receiver)); err != nil {
		t.Fatal(err)
	}
	holds := func() bool {
		return scenario.policy.AdmitSplice(ctx, strictScenarioCustomMx, scenario.receiver) &&
			scenario.policy.StrictChain(ctx, strictScenarioCustomMx, []string{"customer.example"}, scenario.receiver)
	}
	if !holds() {
		t.Fatal("a customer-signed custom MX's chain does not hold")
	}
	// the operator writes what it controls: its own zones, never the customer's
	if err := scenario.world.SetMx("lbl0000001.root.example", &sidecar.SmtpMxHost{Preference: 5, Host: "mx.platform.example"}); err != nil {
		t.Fatal(err)
	}
	if err := scenario.world.AddMx("mx.platform.example", netip.MustParseAddr("198.51.100.66"), nil, strictScenarioTlsa(scenario.substitute)); err != nil {
		t.Fatal(err)
	}
	if !holds() {
		t.Fatal("operator records redirected a customer-signed custom MX")
	}
	if scenario.policy.StrictChain(ctx, strictScenarioCustomMx, []string{"customer.example"}, scenario.substitute) {
		t.Fatal("the substitute's key holds the customer's chain")
	}
	label := strictScenarioLabelOf(true)
	if !label.Basis.GetStrictCustomMx() {
		t.Fatalf("mail with a sealed strict_chain lacks the claim: %+v", label.Basis)
	}
	statement := label.Statement()
	if !strings.Contains(statement, "URnetwork could not redirect a DANE-validating sender") || !strings.Contains(statement, "does not show this sender validated") ||
		strings.Contains(statement, "end-to-end") {
		t.Fatalf("the claim says more than the residual: %q", statement)
	}
}
