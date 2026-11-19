//go:build !sidecar_http && !ios_extension

// FS-33's mixed arrangements (TEST-M7-01; §22.7's strict-mode row, D-MAIL-12, FI-11, owner decision 98), which close
// ledger T4-05: "the claim holds only when the MX selection and its TLSA are both in customer-signed zones", and FS-33
// lacked R1b's mixes. A sender picks an MX host from the recipient domain's MX RRset, the selection, and pins the
// session to that host's TLSA. Whoever signs either can redirect a DANE-validating sender by changing records alone:
// the selection's signer names another host, the TLSA's signer names another key. So tls_basis.strict_custom_mx is
// the claim only where no URnetwork zone signs either.
//
// Each arrangement here is built on MxWorld's signed zones and asked of the zone watch's StrictChain under strict
// mode, C20's stand-in, with this receiver's key in the session host's TLSA every time: a refusal is the zone's,
// never a missing key's. What the watch answers is what the receiver seals as strict_chain, and the label decided
// from that evidence carries the claim only for the arrangement whose selection and TLSA are both customer-signed.

package fault

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

const (
	// URnetwork's zone of network labels, the watch's root, and a second zone its release lists as URnetwork's
	fs33MixedRoot     = "root.example."
	fs33MixedPlatform = "platform.example."
	fs33MixedLabel    = "lbl0000001"
	// the customer's signed zone, a second one, and one it never signed
	fs33MixedCustomer      = "customer.example."
	fs33MixedSecondSigned  = "second.example."
	fs33MixedUnsignedOwner = "unsigned.example."
)

// Resolvers that answer nothing, for a watch whose passes these arrangements never read.
type fs33MixedResolver struct{}

func (fs33MixedResolver) ResolverCount() int {
	return 2
}

func (fs33MixedResolver) Lookup(ctx context.Context, resolver int, name string, qType uint16) (*sidecar.DnsWatchAnswer, error) {
	return &sidecar.DnsWatchAnswer{Values: []string{}}, nil
}

// One recipient domain's MX RRset.
type fs33MixedSelection struct {
	domain string
	hosts  []string
}

// One arrangement: where each recipient domain's selection lives, and the session's host among them.
type fs33MixedArrangement struct {
	name       string
	selections []fs33MixedSelection
	sniHost    string
	// whether the selection and the TLSA are both customer-signed, for every domain and host
	claim bool
	// whether the session host's TLSA validates to the world's anchor: false only where its own zone is unsigned
	tlsaInsecure bool
}

func fs33MixedArrangements() []*fs33MixedArrangement {
	one := func(domain string, hosts ...string) []fs33MixedSelection {
		return []fs33MixedSelection{{domain: domain, hosts: hosts}}
	}
	return []*fs33MixedArrangement{
		{
			name:       "selection customer-signed, TLSA customer-signed",
			selections: one("customer.example", "mx.customer.example"),
			sniHost:    "mx.customer.example",
			claim:      true,
		},
		{
			name:       "selection customer-signed, TLSA customer-signed in another of the customer's zones",
			selections: one("customer.example", "mx.second.example"),
			sniHost:    "mx.second.example",
			claim:      true,
		},
		{
			name:       "selection customer-signed, TLSA in URnetwork's label zone",
			selections: one("customer.example", "mx.lbl0000001.root.example"),
			sniHost:    "mx.lbl0000001.root.example",
		},
		{
			name:       "selection customer-signed, TLSA in a listed URnetwork zone",
			selections: one("customer.example", "mx.platform.example"),
			sniHost:    "mx.platform.example",
		},
		{
			name:       "selection in URnetwork's label zone, TLSA customer-signed",
			selections: one("lbl0000001.root.example", "mx.customer.example"),
			sniHost:    "mx.customer.example",
		},
		{
			name:       "selection in a listed URnetwork zone, TLSA customer-signed",
			selections: one("mail.platform.example", "mx.customer.example"),
			sniHost:    "mx.customer.example",
		},
		{
			name:       "selection in URnetwork's label zone, TLSA in URnetwork's label zone",
			selections: one("lbl0000001.root.example", "mx.lbl0000001.root.example"),
			sniHost:    "mx.lbl0000001.root.example",
		},
		{
			name:       "selection in a listed URnetwork zone, TLSA in URnetwork's label zone",
			selections: one("mail.platform.example", "mx.lbl0000001.root.example"),
			sniHost:    "mx.lbl0000001.root.example",
		},
		{
			// the session is on the customer's host, but the selection also names one an operator's records hold
			name:       "selection customer-signed over a customer-signed host and a URnetwork-zone host",
			selections: one("customer.example", "mx.customer.example", "mx.platform.example"),
			sniHost:    "mx.customer.example",
		},
		{
			// one message, two recipient domains: the second's selection is URnetwork's
			name: "a customer-signed domain beside one whose selection is in URnetwork's label zone",
			selections: []fs33MixedSelection{
				{domain: "customer.example", hosts: []string{"mx.customer.example"}},
				{domain: "lbl0000001.root.example", hosts: []string{"mx.customer.example"}},
			},
			sniHost: "mx.customer.example",
		},
		{
			name: "two customer-signed domains on one customer-signed host",
			selections: []fs33MixedSelection{
				{domain: "customer.example", hosts: []string{"mx.customer.example"}},
				{domain: "second.example", hosts: []string{"mx.customer.example"}},
			},
			sniHost: "mx.customer.example",
			claim:   true,
		},
		{
			// a customer's zone is not customer-signed for being the customer's
			name:       "selection in a zone the customer never signed, TLSA customer-signed",
			selections: one("unsigned.example", "mx.customer.example"),
			sniHost:    "mx.customer.example",
		},
		{
			name:         "selection customer-signed, TLSA in a zone the customer never signed",
			selections:   one("customer.example", "mx.unsigned.example"),
			sniHost:      "mx.unsigned.example",
			tlsaInsecure: true,
		},
	}
}

// A world of the zones above, a watch under strict mode over it, and the strict policy the receiver asks.
type fs33MixedWorld struct {
	world    *sidecartest.MxWorld
	policy   *sidecar.MailStrictPolicy
	receiver []byte
}

func newFs33MixedWorld(t *testing.T) *fs33MixedWorld {
	t.Helper()
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	settings := sidecartest.DefaultMxWorldSettings()
	settings.Clock = clock
	world, err := sidecartest.NewMxWorld(settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, zone := range []string{fs33MixedRoot, fs33MixedPlatform, fs33MixedCustomer, fs33MixedSecondSigned} {
		if err := world.AddZone(zone, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := world.AddZone(fs33MixedUnsignedOwner, &sidecartest.MxWorldZoneOptions{Unsigned: true}); err != nil {
		t.Fatal(err)
	}
	anchors, err := sidecar.NewSmtpDnssecAnchors(world.TrustAnchorDs())
	if err != nil {
		t.Fatal(err)
	}
	watchSettings := sidecar.DefaultDnsWatchSettings()
	watchSettings.UrnetworkZones = []string{fs33MixedPlatform}
	watch, err := sidecar.NewDnsWatch(context.Background(), &sidecar.DnsWatchArgs{
		Resolver: fs33MixedResolver{},
		Store:    sidecartest.NewFakeStore().Root(),
		Zone: func(ctx context.Context) (*sidecar.DnsZone, error) {
			return &sidecar.DnsZone{NetworkId: sidecar.NewId(), Root: fs33MixedRoot, Label: fs33MixedLabel, Version: 1}, nil
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
		Root:   func() string { return fs33MixedRoot },
		Chain:  watch.StrictChain,
	})
	receiver := sha256.Sum256([]byte("the receiver's key"))
	return &fs33MixedWorld{world: world, policy: policy, receiver: receiver[:]}
}

// Publishes arrangement: each domain's MX RRset, and each host once with this receiver's key in its TLSA.
func (self *fs33MixedWorld) publish(t *testing.T, arrangement *fs33MixedArrangement) {
	t.Helper()
	published := []string{}
	address := netip.MustParseAddr("192.0.2.25")
	for _, selection := range arrangement.selections {
		hosts := []*sidecar.SmtpMxHost{}
		for index, host := range selection.hosts {
			hosts = append(hosts, &sidecar.SmtpMxHost{Preference: uint16(10 * (index + 1)), Host: host})
			if slices.Contains(published, host) {
				continue
			}
			published = append(published, host)
			tlsa := &sidecar.SmtpTlsaRecord{Usage: 3, Selector: 1, MatchingType: 1, Data: self.receiver}
			if err := self.world.AddMx(host, address, nil, tlsa); err != nil {
				t.Fatalf("%s: %v", arrangement.name, err)
			}
			address = address.Next()
		}
		if err := self.world.SetMx(selection.domain, hosts...); err != nil {
			t.Fatalf("%s: %v", arrangement.name, err)
		}
	}
}

// The label decided for a deposit to recipients whose sealed evidence carries strictChain.
func fs33MixedLabelOf(recipients []string, strictChain bool) *sidecar.MailLabelResult {
	messageSha256 := sha256.Sum256([]byte("a message"))
	receiverId := sidecar.NewId()
	deposit := &protocol.MailDeposit{
		Version:           1,
		Recipients:        recipients,
		ReceiverSidecarId: receiverId.Bytes(),
		Evidence: &protocol.MailAuthEvidence{
			Version: 1, MessageSha256: messageSha256[:], ReceiverSidecarId: receiverId.Bytes(), StrictChain: strictChain,
		},
	}
	return sidecar.MailLabelDecide(&sidecar.MailLabelInput{Deposit: deposit, MessageSha256: messageSha256[:], Root: strings.TrimSuffix(fs33MixedRoot, ".")})
}

// Every mix of where the MX selection and the TLSA live, across customer-signed and URnetwork zones: the receiver's
// key is in the session host's TLSA in each, and only the mixes whose selection and TLSA are both customer-signed
// seal strict_chain and carry tls_basis.strict_custom_mx.
func TestStrictMixedArrangements(t *testing.T) {
	ctx := context.Background()
	claimed := 0
	for _, arrangement := range fs33MixedArrangements() {
		// a world for each, so one arrangement's records are never another's
		world := newFs33MixedWorld(t)
		world.publish(t, arrangement)
		answer, err := world.world.LookupTlsa(ctx, arrangement.sniHost)
		if err != nil {
			t.Fatalf("%s: %v", arrangement.name, err)
		}
		holdsKey := slices.ContainsFunc(answer.Records, func(record *sidecar.SmtpTlsaRecord) bool {
			return string(record.Data) == string(world.receiver)
		})
		if !holdsKey || answer.Secure == arrangement.tlsaInsecure {
			t.Fatalf("%s: the session host's TLSA: secure %t, holds the receiver's key %t", arrangement.name, answer.Secure, holdsKey)
		}
		domains := []string{}
		recipients := []string{}
		for _, selection := range arrangement.selections {
			domains = append(domains, selection.domain)
			recipients = append(recipients, "ann@"+selection.domain)
		}
		strictChain := world.policy.StrictChain(ctx, arrangement.sniHost, domains, world.receiver)
		if strictChain != arrangement.claim {
			t.Errorf("%s: strict_chain %t", arrangement.name, strictChain)
		}
		label := fs33MixedLabelOf(recipients, strictChain)
		if label.Basis.GetStrictCustomMx() != arrangement.claim {
			t.Errorf("%s: tls_basis.strict_custom_mx %t", arrangement.name, label.Basis.GetStrictCustomMx())
		}
		if arrangement.claim {
			claimed += 1
			// the chain is this receiver's key's: another key on the same arrangement seals nothing
			other := sha256.Sum256([]byte("another key"))
			if world.policy.StrictChain(ctx, arrangement.sniHost, domains, other[:]) {
				t.Errorf("%s: strict_chain sealed for a key the TLSA does not hold", arrangement.name)
			}
			// and it is every recipient domain's: one more, whose selection URnetwork signs, withholds it
			if err := world.world.SetMx("lbl0000001.root.example", &sidecar.SmtpMxHost{Preference: 10, Host: arrangement.sniHost}); err != nil {
				t.Fatal(err)
			}
			if world.policy.StrictChain(ctx, arrangement.sniHost, append(slices.Clone(domains), "lbl0000001.root.example"), world.receiver) {
				t.Errorf("%s: strict_chain sealed with a recipient domain in URnetwork's zone", arrangement.name)
			}
		} else if statement := label.Statement(); strings.Contains(statement, "URnetwork could not redirect") {
			t.Errorf("%s: the label states the claim: %q", arrangement.name, statement)
		}
	}
	if claimed != 3 {
		t.Errorf("%d arrangements carry the claim", claimed)
	}
}

// The arrangements cover each of the four mixes of a customer-signed and a URnetwork zone for the selection and the
// TLSA, by where the first domain and the session's host live: a table that loses one is caught here.
func TestStrictMixedArrangementsCoverEveryMix(t *testing.T) {
	urnetwork := func(name string) bool {
		name = name + "."
		return strings.HasSuffix(name, "."+fs33MixedRoot) || strings.HasSuffix(name, "."+fs33MixedPlatform)
	}
	customerSigned := func(name string) bool {
		name = name + "."
		return name == fs33MixedCustomer || strings.HasSuffix(name, "."+fs33MixedCustomer) || name == fs33MixedSecondSigned || strings.HasSuffix(name, "."+fs33MixedSecondSigned)
	}
	mixes := map[[2]bool]int{}
	for _, arrangement := range fs33MixedArrangements() {
		allCustomerSigned := true
		for _, selection := range arrangement.selections {
			allCustomerSigned = allCustomerSigned && customerSigned(selection.domain)
			for _, host := range selection.hosts {
				allCustomerSigned = allCustomerSigned && customerSigned(host)
			}
		}
		if allCustomerSigned != arrangement.claim {
			t.Errorf("%s: claims %t, with every selection and host customer-signed %t", arrangement.name, arrangement.claim, allCustomerSigned)
		}
		if len(arrangement.selections) != 1 || len(arrangement.selections[0].hosts) != 1 {
			continue
		}
		domain, host := arrangement.selections[0].domain, arrangement.selections[0].hosts[0]
		if (urnetwork(domain) || customerSigned(domain)) && (urnetwork(host) || customerSigned(host)) {
			mixes[[2]bool{urnetwork(domain), urnetwork(host)}] += 1
		}
	}
	for _, mix := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		if mixes[mix] == 0 {
			t.Errorf("no arrangement with the selection in a URnetwork zone %t and the TLSA in one %t", mix[0], mix[1])
		}
	}
}
