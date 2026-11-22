//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S10's replying half (§22.7; §3.7's F10, burner lifecycle; R-MAIL-6, D-MAIL-7, D-DNS-11, I-13, I-14, owner decisions 32,
// 79; MAIL-M9-06): one builder that sidecartest's T2 test and server's sidecart3 T3 test both run under §22.7's harness
// and guard (RunScenario), as the receive-only half's s10.go is. M9World stands on the scenario's Net: M8's network, its
// log on the Net's tier and its MailWorld on the run's hosts, and the owner's laptop sending as a desktop ur daemon does,
// to a ScriptedMx through SMTP's stub edge; beside it the zone a tier serves (S10ReplyingSettings.Zone, the receive-only
// half's) and POST /smtp/dkim-keys's server half with key expiry over that zone (S10ReplyingSettings.Dkim): T2's
// S10FakeDkim over the DNS harness's store, or T3's through server's model. Canaries go in the burner's site, which
// names its local part, in the reply's recipient's local part, its subject and its body. Every step runs through
// MailClient, the root calls the bound API wraps (SidecarMail):
//
//   - create: CreateBurner makes a receive-only burner, which makes no child: the zone's serial and rows as before
//     (the receive-only half's clause, run again here as the reply's starting point);
//   - first selector: Reply queues a reply From the burner, flag BURNER, and marks the burner replying; the laptop's
//     runner sends it, and its signature's first selector is published through POST /smtp/dkim-keys, whose server
//     write puts <sel>._domainkey.<blabel> and <blabel>'s copy of the wildcard's records in one journal write
//     (D-DNS-11): the zone moves by that one serial, <blabel> answers the wildcard's MX and A and AAAA, the selector
//     answers the key the reply was signed under, the MX holds the reply signed d=<blabel> s=<sel>, and the burner
//     still takes mail;
//   - second selector: a rotation's call publishes another and retires the first in one write that adds no copy but
//     the new selector's own (QD-1190), and key expiry's run once the first's keep has passed takes it out with its
//     own copy while the label's copies stay;
//   - burn: Burn retires the label's last selector through the laptop's SmtpDkimKeys and changes no DNS (the zone's
//     serial as before), while the receiver answers 550 5.1.1 for the label at once (§15.9's burn row);
//   - last selector: key expiry's run once that keep has passed takes the last selector out, its write deleting the
//     copies, so nothing stands at or under the label and the wildcard answers it alone again;
//   - never: the burner's address reaches no store a server holds in the clear, nor does its label, but in DNS's rows
//     (dns-1), the selector's row (smtp-6) and a dns edge's queries (dns-2), which the run declares.

package mailworld

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// POST /smtp/dkim-keys's server half and SMTP-M9-17's key expiry over a tier's zone, as S10's replying half calls them.
type S10Dkim interface {
	sidecar.SmtpDkimPublisher
	// How long a retired selector stays in DNS: §14.6's 7 days, as the tier's key expiry keeps it.
	RetiredKeepTimeout() time.Duration
	// Key expiry's run at now: each selector retired more than RetiredKeepTimeout before now leaves DNS in a write of
	// its own, a burner's last one taking its label's copies with it. Returns once every edge serves the result.
	Expire(ctx context.Context, now time.Time) error
}

// What S10's replying half runs with beyond the scenario's Net.
type S10ReplyingSettings struct {
	// Serves the network's zone on the run's Net, as S10Settings.Zone does: nil for S10FakeZone, T2's.
	Zone func(ctx context.Context, t testing.TB, run *sidecartest.ScenarioRun, networkId sidecar.Id) (*S10Zone, error)
	// The server half over that zone, for the sending sidecarId of networkId: nil for S10FakeDkim, T2's.
	Dkim func(ctx context.Context, t testing.TB, run *sidecartest.ScenarioRun, zone *S10Zone, networkId sidecar.Id, sidecarId sidecar.Id) (S10Dkim, error)
}

// S10's replying half as a scenario (the file header's flow): settings nil is T2's.
func S10Replying(t testing.TB, settings *S10ReplyingSettings) *sidecartest.Scenario {
	if settings == nil {
		settings = &S10ReplyingSettings{}
	}
	return &sidecartest.Scenario{Id: "S10", Run: s10ReplyingRun(t, settings)}
}

// The reply's recipient domain's MX address, RFC 5737's.
var s10ReplyMxAddress = netip.MustParseAddr("198.51.100.25")

// A label no burner holds, which the wildcard alone answers: what the wildcard's records are.
const s10WildcardProbeLabel = "zz-0000"

// The flow on run's Net.
func s10ReplyingRun(t testing.TB, settings *S10ReplyingSettings) func(ctx context.Context, run *sidecartest.ScenarioRun) error {
	return func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		siteName := run.CanaryText("burner site")
		recipientLocalPart := run.CanaryText("mail local part")
		subject := run.CanaryText("mail subject")
		bodyCanary := run.CanaryText("mail body")

		// the network's log on the Net's tier, then its zone and the server half over it
		tier, err := run.Net.AdmissionTier()
		if err != nil {
			return err
		}
		tier.AclCompile = sidecartest.AclAdmissionCompile
		admission := sidecartest.NewAdmissionNet(t, tier)
		t.Cleanup(admission.Close)
		newZone := settings.Zone
		if newZone == nil {
			newZone = S10FakeZone
		}
		served, err := newZone(ctx, t, run, admission.NetworkId())
		if err != nil {
			return err
		}
		harness := served.Harness
		defer harness.Close()
		newDkim := settings.Dkim
		if newDkim == nil {
			newDkim = S10FakeDkim
		}
		tierDkim, err := newDkim(ctx, t, run, served, admission.NetworkId(), admission.Owner().SidecarId)
		if err != nil {
			return err
		}
		dkim := &s10DkimRecorder{S10Dkim: tierDkim}

		worldSettings := DefaultM9WorldSettings()
		worldSettings.M8 = &M8WorldSettings{
			Admission: admission,
			Root:      strings.TrimSuffix(harness.Root(), "."),
			Label:     served.Label,
			Stores: func(service string) *sidecar.ServiceHost {
				if service == MailWorldServiceWorld {
					return run.Net.Host()
				}
				return run.Host(service)
			},
		}
		worldSettings.Dkim = dkim
		world := NewM9World(t, run.Net, worldSettings)
		zoneName := world.M8.Zone()
		mxHost := world.M8.Mail.Settings().MxHost()
		zoneAt := func(label string) (*s10Zone, error) {
			return s10ZoneOf(ctx, harness, zoneName, label)
		}

		// create: a receive-only burner, which makes no child
		site := "https://" + siteName + ".example/signup"
		created, err := world.Owner.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: site})
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		if !s10BurnerLabelPattern.MatchString(created.Label) || created.Info == nil || created.Info.Replying {
			return fmt.Errorf("create: the burner %+v", created)
		}
		label := created.Label
		burnerDomain := world.BurnerDomain(label)
		capture := run.Net.Capture()
		capture.Forbid("a burner's address", []byte(created.Address))
		capture.Forbid("a burner's label", []byte(label))
		zone, err := zoneAt(label)
		if err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, served.Serial, mxHost); err != nil {
			return fmt.Errorf("a receive-only burner's creation: %w", err)
		}
		wildcard, err := s10AddressesOf(ctx, harness, s10WildcardProbeLabel+"."+zoneName)
		if err != nil {
			return err
		}
		if len(wildcard) == 0 {
			return errors.New("the wildcard answers no address")
		}

		// the reply: queued From the burner with flag BURNER, the burner replying, no DNS written yet
		recipient := recipientLocalPart + "@mail.example"
		mx := world.AddDomain("mail.example", s10ReplyMxAddress, nil, true)
		reply, err := world.Owner.Reply(ctx, &sidecar.MailReplyArgs{
			From: created.Address, To: []string{recipient}, Subject: "Re: " + subject, Text: "Thanks.\r\n" + bodyCanary,
		})
		if err != nil {
			return fmt.Errorf("reply: %w", err)
		}
		if len(reply.Recipients) != 1 || reply.Recipients[0].Outcome != sidecar.MailSendQueued || len(reply.EffectKey) == 0 {
			return fmt.Errorf("reply: %+v", reply)
		}
		if replying, err := s10Replying(ctx, world, label); err != nil || !replying {
			return fmt.Errorf("the replying burner reads replying %t: %v", replying, err)
		}
		if zone, err = zoneAt(label); err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, served.Serial, mxHost); err != nil {
			return fmt.Errorf("a queued reply: %w", err)
		}

		// first selector: the runner sends the reply, its signature's selector published with the label's copies in
		// one journal write
		if pass := world.RunOutbox(); pass.Sent != 1 {
			return fmt.Errorf("the outbox pass %+v", pass)
		}
		if outcome := world.Outcomes(reply.EffectKey)["mail.example"]; outcome == nil || outcome.Outcome != sidecar.SmtpOutcomeSent {
			return fmt.Errorf("the reply's outcome %+v", outcome)
		}
		published := dkim.published(burnerDomain)
		if len(published) != 1 {
			return fmt.Errorf("%d selectors published for the burner's domain, not one", len(published))
		}
		first := published[0]
		firstOwner := first.Selector + "._domainkey." + label + "." + zoneName
		copies := []string{dns.Fqdn("_domainkey." + label + "." + zoneName), dns.Fqdn(label + "." + zoneName)}
		firstSerial := served.Serial + 1
		if err := s10Copied(ctx, harness, zoneName, label, firstSerial, append(slices.Clone(copies), dns.Fqdn(firstOwner)), mxHost, wildcard); err != nil {
			return fmt.Errorf("the first selector: %w", err)
		}
		if err := s10KeyAnswered(ctx, harness, firstOwner, first.PublicKey); err != nil {
			return fmt.Errorf("the first selector: %w", err)
		}
		transactions := mx.Transactions()
		if len(transactions) != 1 {
			return fmt.Errorf("the MX took %d transactions", len(transactions))
		}
		if err := s10SignedBy(transactions[0].Message, created.Address, burnerDomain, first.Selector, bodyCanary); err != nil {
			return fmt.Errorf("the reply as the MX took it: %w", err)
		}
		world.M8.SyncReceiver()
		if reply := world.M8.Send(created.Address, subject+" after a reply", "A message to a replying burner."); !reply.Is(250) {
			return fmt.Errorf("a replying burner's mail: %s", reply)
		}

		// second selector: a rotation publishes one and retires the first in one write that adds no copy but the new
		// selector's own; key expiry past the first's keep takes it out with its own copy and leaves the label's
		if err := world.Dkim.Rotate(ctx, burnerDomain); err != nil {
			return fmt.Errorf("rotate: %w", err)
		}
		published = dkim.published(burnerDomain)
		if len(published) != 2 || !slices.Contains(dkim.retired(), first.Selector) {
			return fmt.Errorf("the rotation published %d selectors and retired %v", len(published), dkim.retired())
		}
		second := published[1]
		secondOwner := second.Selector + "._domainkey." + label + "." + zoneName
		if err := s10Copied(ctx, harness, zoneName, label, firstSerial+1, append(slices.Clone(copies), dns.Fqdn(firstOwner), dns.Fqdn(secondOwner)), mxHost, wildcard); err != nil {
			return fmt.Errorf("the second selector: %w", err)
		}
		expireAt := run.Net.Clock().Now().Add(dkim.RetiredKeepTimeout() + time.Minute)
		if err := dkim.Expire(ctx, expireAt); err != nil {
			return fmt.Errorf("the first selector's expiry: %w", err)
		}
		expiredSerial := firstSerial + 2
		if err := s10Copied(ctx, harness, zoneName, label, expiredSerial, append(slices.Clone(copies), dns.Fqdn(secondOwner)), mxHost, wildcard); err != nil {
			return fmt.Errorf("the first selector's expiry: %w", err)
		}

		// burn: the last selector retired, no DNS change, and the label refused at RCPT at once
		if err := world.Owner.Burn(ctx, created.Address); err != nil {
			return fmt.Errorf("burn: %w", err)
		}
		if !slices.Contains(dkim.retired(), second.Selector) {
			return fmt.Errorf("the burn retired %v, not the label's last selector", dkim.retired())
		}
		if err := s10Copied(ctx, harness, zoneName, label, expiredSerial, append(slices.Clone(copies), dns.Fqdn(secondOwner)), mxHost, wildcard); err != nil {
			return fmt.Errorf("a burn changed DNS: %w", err)
		}
		world.M8.SyncReceiver()
		if reply := world.M8.Send(created.Address, subject+" burned", "A message to a burned label.\r\n"+bodyCanary); !reply.Is(550) ||
			len(reply.Lines) == 0 || !strings.HasPrefix(reply.Lines[0], "5.1.1") {
			return fmt.Errorf("a burned replying label's mail: %s", reply)
		}

		// last selector: expiry past its keep takes it out with the copies, back to the wildcard alone
		if err := dkim.Expire(ctx, expireAt); err != nil {
			return fmt.Errorf("the last selector's expiry: %w", err)
		}
		if zone, err = zoneAt(label); err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, expiredSerial+1, mxHost); err != nil {
			return fmt.Errorf("the last selector's expiry: %w", err)
		}
		if addresses, err := s10AddressesOf(ctx, harness, label+"."+zoneName); err != nil || !slices.Equal(addresses, wildcard) {
			return fmt.Errorf("the label answers %v after its last selector, the wildcard %v: %v", addresses, wildcard, err)
		}

		// the label stands in DNS's rows and the selector's row (dns-1, smtp-6), which T3's capture reads in
		// Postgres, and in the queries a dns edge was sent (dns-2); mx-1 keeps the fleet's daily key in Redis
		for _, declared := range []struct {
			rowId string
			kind  string
			class sidecartest.PrivacyClass
		}{
			{rowId: "mx-1", kind: "K_mxc_day", class: sidecartest.PrivacyClassRedis},
			{rowId: "dns-1", kind: "a burner's label", class: sidecartest.PrivacyClassPostgres},
			{rowId: "smtp-6", kind: "a burner's label", class: sidecartest.PrivacyClassPostgres},
			{rowId: "dns-2", kind: "a burner's label", class: sidecartest.PrivacyClassDnsEdgeQuery},
		} {
			if err := capture.Declare(declared.rowId, declared.kind, declared.class); err != nil {
				return err
			}
		}
		for _, line := range world.M8.Mail.LogLines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassLog, Name: "mail log", Body: []byte(line)})
		}
		for _, line := range run.Net.Fakes().Metrics.Dump() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassMetric, Name: "metric", Body: []byte(line)})
		}
		return nil
	}
}

// Whether label's burner reads replying in the laptop's mailcfg.
func s10Replying(ctx context.Context, world *M9World, label string) (bool, error) {
	burners, err := world.Owner.Burners(ctx)
	if err != nil {
		return false, err
	}
	for _, burner := range burners {
		if burner.Label == label {
			return burner.Replying && burner.State == protocol.MailBurnerState_MAIL_BURNER_LIVE, nil
		}
	}
	return false, nil
}

// The A and AAAA an edge answers for name, sorted: what the wildcard answers a name with no rows.
func s10AddressesOf(ctx context.Context, harness *sidecartest.DnsHarness, name string) ([]string, error) {
	addresses := []string{}
	for _, rrType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		query := &dns.Msg{}
		query.SetQuestion(dns.Fqdn(name), rrType)
		reply, err := harness.Query(ctx, harness.Settings().Ns[0], query)
		if err != nil {
			return nil, err
		}
		if reply.Rcode != dns.RcodeSuccess {
			return nil, fmt.Errorf("%s %s answers %s", name, dns.TypeToString[rrType], dns.RcodeToString[reply.Rcode])
		}
		for _, record := range reply.Answer {
			switch record := record.(type) {
			case *dns.A:
				addresses = append(addresses, record.A.String())
			case *dns.AAAA:
				addresses = append(addresses, record.AAAA.String())
			}
		}
	}
	slices.Sort(addresses)
	return addresses, nil
}

// Whether the zone at label stands at serial with exactly owners at or under it, the label answering the wildcard's
// MX, and its addresses the wildcard's: a replying burner's records (D-DNS-11).
func s10Copied(ctx context.Context, harness *sidecartest.DnsHarness, zoneName string, label string, serial uint64, owners []string, mxHost string, wildcard []string) error {
	zone, err := s10ZoneOf(ctx, harness, zoneName, label)
	if err != nil {
		return err
	}
	have := slices.Clone(zone.labelRows)
	slices.Sort(have)
	have = slices.Compact(have)
	want := slices.Clone(owners)
	slices.Sort(want)
	switch {
	case zone.serial != serial:
		return fmt.Errorf("the zone stands at serial %d, not %d", zone.serial, serial)
	case !slices.Equal(have, want):
		return fmt.Errorf("the owners at or under the label are %v, not %v", have, want)
	case zone.mxRcode != dns.RcodeSuccess || !slices.Equal(zone.mxExchange, []string{"10 " + dns.Fqdn(mxHost)}):
		return fmt.Errorf("the label's MX answers %s %v, not the wildcard's", dns.RcodeToString[zone.mxRcode], zone.mxExchange)
	}
	addresses, err := s10AddressesOf(ctx, harness, label+"."+zoneName)
	if err != nil {
		return err
	}
	if !slices.Equal(addresses, wildcard) {
		return fmt.Errorf("the label answers addresses %v, the wildcard %v", addresses, wildcard)
	}
	return nil
}

// Whether an edge answers owner's TXT with publicKey's p=, the key a reply was signed under.
func s10KeyAnswered(ctx context.Context, harness *sidecartest.DnsHarness, owner string, publicKey []byte) error {
	query := &dns.Msg{}
	query.SetQuestion(dns.Fqdn(owner), dns.TypeTXT)
	reply, err := harness.Query(ctx, harness.Settings().Ns[0], query)
	if err != nil {
		return err
	}
	want := "p=" + base64.StdEncoding.EncodeToString(publicKey)
	for _, record := range reply.Answer {
		if txt, ok := record.(*dns.TXT); ok && strings.Contains(strings.Join(txt.Txt, ""), want) {
			return nil
		}
	}
	return fmt.Errorf("the selector's TXT answers %s %v, not its key", dns.RcodeToString[reply.Rcode], reply.Answer)
}

// A DKIM-Signature field's tag, as d=<domain> or s=<selector>.
var s10DkimTagPattern = regexp.MustCompile(`(?:^|;)\s*([a-z]+)=([^;]*)`)

// Whether message is from as the MX took it, holding bodyCanary, every DKIM-Signature it carries d=domain s=selector.
func s10SignedBy(message []byte, from string, domain string, selector string, bodyCanary string) error {
	text := string(message)
	if !strings.Contains(text, bodyCanary) {
		return errors.New("the body is not the reply's")
	}
	header, _, _ := strings.Cut(text, "\r\n\r\n")
	// unfold, so a field reads as one line
	header = strings.NewReplacer("\r\n ", " ", "\r\n\t", " ").Replace(header)
	fromFound := false
	signatureCount := 0
	for _, field := range strings.Split(header, "\r\n") {
		name, value, _ := strings.Cut(field, ":")
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "from":
			fromFound = fromFound || strings.Contains(value, from)
		case "dkim-signature":
			tags := map[string]string{}
			for _, match := range s10DkimTagPattern.FindAllStringSubmatch(value, -1) {
				tags[match[1]] = strings.TrimSpace(match[2])
			}
			if tags["d"] != domain || tags["s"] != selector {
				return fmt.Errorf("signed d=%s s=%s, not d=%s s=%s", tags["d"], tags["s"], domain, selector)
			}
			signatureCount += 1
		}
	}
	switch {
	case !fromFound:
		return errors.New("no From names the burner")
	case signatureCount == 0:
		return errors.New("no DKIM-Signature")
	}
	return nil
}

// Every call the tier's server half took, kept for the flow to read its selectors.
type s10DkimRecorder struct {
	S10Dkim

	stateLock sync.Mutex
	calls     []*sidecar.SmtpDkimKeysArgs
}

func (self *s10DkimRecorder) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	result, err := self.S10Dkim.SmtpDkimKeys(ctx, args)
	if err == nil {
		self.stateLock.Lock()
		self.calls = append(self.calls, args)
		self.stateLock.Unlock()
	}
	return result, err
}

// The selectors an applied call published for domain, in order.
func (self *s10DkimRecorder) published(domain string) []*sidecar.SmtpDkimKeyPublish {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	published := []*sidecar.SmtpDkimKeyPublish{}
	for _, call := range self.calls {
		for _, publish := range call.Publish {
			if publish.Domain == domain && !slices.ContainsFunc(published, func(earlier *sidecar.SmtpDkimKeyPublish) bool {
				return earlier.Selector == publish.Selector
			}) {
				published = append(published, publish)
			}
		}
	}
	return published
}

// The selectors an applied call retired.
func (self *s10DkimRecorder) retired() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	retired := []string{}
	for _, call := range self.calls {
		for _, retire := range call.Retire {
			retired = append(retired, retire.Selector)
		}
	}
	return retired
}

// What T2's server half (S10FakeDkim) holds to.
type S10FakeDkimSettings struct {
	// How long a retired selector stays in DNS: §14.6's 7 days, server's DkimRetiredKeepTimeout.
	RetiredKeepTimeout time.Duration
	// The most bytes one TXT character-string holds (RFC 1035 §3.3.14), into which a key record is cut, as DNS-M9-01's
	// writer cuts one.
	TxtStringMaxByteCount int
}

func DefaultS10FakeDkimSettings() *S10FakeDkimSettings {
	return &S10FakeDkimSettings{
		RetiredKeepTimeout:    7 * 24 * time.Hour,
		TxtStringMaxByteCount: 255,
	}
}

// T2's server half (S10ReplyingSettings.Dkim nil): POST /smtp/dkim-keys's write and key expiry for one sending sidecar
// of the network, over the DNS harness's store, as SMTP-M9-19's PublishSmtpDkimKeys and SMTP-M9-17's
// ExpireSmtpDkimKeys call DNS-M9-01's writers: a new selector is its key record at <sel>._domainkey.<domain> in one
// journal write with the copies dnsservice.PlanCopyRows plans for what the write leaves, which for a burner's first is
// <blabel>'s, _domainkey.<blabel>'s and its own; a retirement marks it retired and writes nothing; key expiry takes each
// selector retired more than RetiredKeepTimeout before its now out of DNS, one write each, with the copies its removal
// ends. A selector published again with its key, or retired again, is answered as before. Safe for concurrent use.
func S10FakeDkim(ctx context.Context, t testing.TB, run *sidecartest.ScenarioRun, zone *S10Zone, networkId sidecar.Id, sidecarId sidecar.Id) (S10Dkim, error) {
	root := zone.Harness.Root()
	return &s10FakeDkim{
		harness:   zone.Harness,
		root:      root,
		apex:      dns.CanonicalName(zone.Label + "." + root),
		networkId: networkId,
		sidecarId: sidecarId,
		clock:     run.Net.Clock(),
		settings:  DefaultS10FakeDkimSettings(),
		keys:      map[string]*s10FakeDkimKey{},
	}, nil
}

// One selector the fake holds.
type s10FakeDkimKey struct {
	domain    string
	publicKey []byte
	// its key record's owner
	owner      string
	retired    bool
	retireTime time.Time
	// whether its key record stands
	inDns bool
}

type s10FakeDkim struct {
	harness   *sidecartest.DnsHarness
	root      string
	apex      string
	networkId sidecar.Id
	sidecarId sidecar.Id
	clock     sidecar.Clock
	settings  *S10FakeDkimSettings

	// orders every call, as the server's lock on the network's zones does
	writeLock sync.Mutex
	// by selector
	keys map[string]*s10FakeDkimKey
}

func (self *s10FakeDkim) RetiredKeepTimeout() time.Duration {
	return self.settings.RetiredKeepTimeout
}

// A refusal as the route answers one for good: nothing in the call applies.
func s10FakeDkimRefusal(code string) error {
	return &sidecar.SidecarApiError{Route: "POST /smtp/dkim-keys", Status: 400, Code: code}
}

// The owner of a selector's key record for domain, the network's own name or a word-number burner label directly
// under it, and "" for any other domain.
func (self *s10FakeDkim) ownerOf(selector string, domain string) string {
	name := dns.CanonicalName(domain)
	if name == self.apex {
		return selector + "._domainkey." + self.apex
	}
	label, parent, _ := strings.Cut(name, ".")
	if parent != self.apex || !sidecar.IsWordNumberDnsLabel(label) {
		return ""
	}
	return selector + "._domainkey." + name
}

// A key record's text as DNS-M9-01's writer writes it: v=DKIM1; k=rsa; p=<the key>, cut into character-strings.
func (self *s10FakeDkim) keyRdata(publicKey []byte) string {
	value := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(publicKey)
	parts := []string{}
	for 0 < len(value) {
		cut := min(len(value), self.settings.TxtStringMaxByteCount)
		parts = append(parts, `"`+value[:cut]+`"`)
		value = value[cut:]
	}
	return strings.Join(parts, " ")
}

// The zone's rows as they stand: every row at or under the apex.
func (self *s10FakeDkim) zoneRows(ctx context.Context) ([]dnsservice.DnsRecordSet, error) {
	snapshot, err := self.harness.Store().Snapshot(ctx, self.root)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	rows := []dnsservice.DnsRecordSet{}
	for {
		row, err := snapshot.Next()
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, err
		}
		if dns.IsSubDomain(self.apex, dns.CanonicalName(row.Owner)) {
			rows = append(rows, row.Clone())
		}
	}
}

// One journal write of upserts and deletes with the copies they plan, served by every edge before it returns.
func (self *s10FakeDkim) writeWithLock(ctx context.Context, upserts []dnsservice.DnsRecordSet, deletes []dnsservice.DnsRecordKey) error {
	rows, err := self.zoneRows(ctx)
	if err != nil {
		return err
	}
	copyUpserts, copyDeletes := dnsservice.PlanCopyRows(self.apex, dnsservice.DnsRowsAfter(rows, upserts, deletes))
	_, err = self.harness.WriteServed(ctx, &dnsservice.DnsZoneWrite{
		Root:      self.root,
		NetworkId: self.networkId,
		Upserts:   append(slices.Clone(upserts), copyUpserts...),
		Deletes:   append(slices.Clone(deletes), copyDeletes...),
	})
	return err
}

func (self *s10FakeDkim) SmtpDkimKeys(ctx context.Context, args *sidecar.SmtpDkimKeysArgs) (*sidecar.SmtpDkimKeysResult, error) {
	if args == nil || len(args.Publish)+len(args.Retire) == 0 {
		return nil, s10FakeDkimRefusal("args")
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	// every new selector's place first, so a refusal applies nothing
	for _, publish := range args.Publish {
		if self.ownerOf(publish.Selector, publish.Domain) == "" {
			return nil, s10FakeDkimRefusal("domain")
		}
		if key := self.keys[publish.Selector]; key != nil && (key.retired || string(key.publicKey) != string(publish.PublicKey)) {
			return nil, s10FakeDkimRefusal("selector_taken")
		}
	}
	result := &sidecar.SmtpDkimKeysResult{Published: []string{}, Retired: []string{}}
	now := self.clock.Now()
	for _, retire := range args.Retire {
		// one this sidecar does not hold, or holds retired, is no error
		if key := self.keys[retire.Selector]; key != nil && !key.retired {
			key.retired = true
			key.retireTime = now
		}
		result.Retired = append(result.Retired, retire.Selector)
	}
	for _, publish := range args.Publish {
		if self.keys[publish.Selector] == nil {
			owner := self.ownerOf(publish.Selector, publish.Domain)
			row := dnsservice.DnsRecordSet{
				Owner: owner, Type: dns.TypeTXT, Ttl: self.harness.Settings().Ttl.Tlsa, Kind: dnsservice.DnsRecordKindKey,
				Rdata: []string{self.keyRdata(publish.PublicKey)},
			}
			if err := self.writeWithLock(ctx, []dnsservice.DnsRecordSet{row}, nil); err != nil {
				return nil, err
			}
			self.keys[publish.Selector] = &s10FakeDkimKey{
				domain: publish.Domain, publicKey: publish.PublicKey, owner: owner, inDns: true,
			}
		}
		result.Published = append(result.Published, publish.Selector)
	}
	return result, nil
}

func (self *s10FakeDkim) Expire(ctx context.Context, now time.Time) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	retiredBefore := now.Add(-self.settings.RetiredKeepTimeout)
	selectors := []string{}
	for selector, key := range self.keys {
		if key.retired && key.inDns && key.retireTime.Before(retiredBefore) {
			selectors = append(selectors, selector)
		}
	}
	// in retirement order, as the server's cursor reads them
	slices.SortFunc(selectors, func(first string, second string) int {
		if order := self.keys[first].retireTime.Compare(self.keys[second].retireTime); order != 0 {
			return order
		}
		return strings.Compare(first, second)
	})
	for _, selector := range selectors {
		key := self.keys[selector]
		if err := self.writeWithLock(ctx, nil, []dnsservice.DnsRecordKey{{Owner: key.owner, Type: dns.TypeTXT}}); err != nil {
			return err
		}
		key.inDns = false
	}
	return nil
}
