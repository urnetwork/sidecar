//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S10's receive-only half (§22.7; §3.7's F10, burner lifecycle; R-MAIL-6, R-MAIL-7, R-MAIL-11, D-MAIL-7, I-13, I-14,
// R-PHASE-7; MAIL-M8-10) on T2, under §22.7's harness and guard (RunScenario): mail_m8_test.go's world on the
// scenario's Net, so the router's Redis and records, evs's engine and its objects, the gkm objects and the network's
// log are the Net's, which the capture and the schema guard read at the end, beside a DNS harness's block and edges
// serving the network's zone from §12.7's wildcard rows. Canaries go in the burner's site, which names its local part
// and its vault entry, in a second local part, a subject and a body. Burner create and burn, the vault entry and the
// one-time code run through MailClient, the root calls the bound API wraps (SidecarMail, SDK-M8-04):
//
//   - create: CreateBurner, an outward action through the gate (I-8), makes <name>@<blabel>.<net>.<root>, its label
//     word-number and not replying, with its vault entry live, and neither the zone's serial nor any row moves: the
//     wildcard MX answers the label, and no owner sits at or under it, so a receive-only burner makes no child
//     (D-MAIL-7, D-DNS-11);
//   - receive: a sign-up message through the router to the burner, and one to another local part at its label, each
//     250 once deposited; the owner's ingest takes both, and OneTimeCodes gives the message's code;
//   - burn: Burn asks no approval and calls api not at all (owner decision 32); the receiver, its mailcfg read again as
//     a hint of the change has it, answers 550 5.1.1 for the label at RCPT, any local part alike, with the zone's
//     serial and rows as before, and the vault entry and the burner read burned;
//   - never: the label and the burner's address reach no store a server holds in the clear, which the capture's
//     scan reads (I-13), nor the router's log.
//
// The replying half, a first selector keeping <blabel>'s MX and A and a last restoring the wildcard-only state, is
// MAIL-M9-06's, with M9's sending; T3 runs neither half yet (mail_registrations.go).

package sidecartest_test

import (
	"context"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/dnsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// §15.9's word-number label.
var s10BurnerLabelPattern = regexp.MustCompile(`^[a-z]+-[0-9]{4}$`)

// The zone as one moment of the DNS harness's store and edge show it, for a label: the root's serial, the owners at
// or under the label's name, and what an edge answers for its MX.
type s10Zone struct {
	serial     uint64
	labelRows  []string
	mxRcode    int
	mxExchange []string
}

// The zone at harness for label under the network's zone.
func s10ZoneOf(ctx context.Context, harness *sidecartest.DnsHarness, label string) (*s10Zone, error) {
	root := harness.Root()
	state, err := harness.FakeStore().RootState(ctx, root)
	if err != nil {
		return nil, err
	}
	zone := &s10Zone{serial: state.Serial}
	name := label + "." + mailM8Label + "." + root
	snapshot, err := harness.FakeStore().Snapshot(ctx, root)
	if err != nil {
		return nil, err
	}
	defer snapshot.Close()
	for {
		row, err := snapshot.Next()
		if err != nil {
			break
		}
		owner := dns.Fqdn(strings.ToLower(row.Owner))
		if owner == name || strings.HasSuffix(owner, "."+name) {
			zone.labelRows = append(zone.labelRows, owner)
		}
	}
	query := &dns.Msg{}
	query.SetQuestion(name, dns.TypeMX)
	reply, err := harness.Query(ctx, harness.Settings().Ns[0], query)
	if err != nil {
		return nil, err
	}
	zone.mxRcode = reply.Rcode
	for _, record := range reply.Answer {
		if mx, ok := record.(*dns.MX); ok {
			zone.mxExchange = append(zone.mxExchange, fmt.Sprintf("%d %s", mx.Preference, strings.ToLower(mx.Mx)))
		}
	}
	return zone, nil
}

// Whether zone is the wildcard-only state at serial: no row at or under the label, and the wildcard's MX answering
// it.
func s10WildcardOnly(zone *s10Zone, serial uint64, mxHost string) error {
	switch {
	case zone.serial != serial:
		return fmt.Errorf("the zone moved from serial %d to %d", serial, zone.serial)
	case len(zone.labelRows) != 0:
		return fmt.Errorf("the zone holds %d rows at or under the label", len(zone.labelRows))
	case zone.mxRcode != dns.RcodeSuccess || !slices.Equal(zone.mxExchange, []string{"10 " + dns.Fqdn(mxHost)}):
		return fmt.Errorf("the label's MX answers %s %v, not the wildcard's", dns.RcodeToString[zone.mxRcode], zone.mxExchange)
	}
	return nil
}

// S10's receive-only flow on run's Net (the file header's flow).
func s10Run(t *testing.T) func(ctx context.Context, run *sidecartest.ScenarioRun) error {
	return func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		siteName := run.CanaryText("burner site")
		otherLocalPart := run.CanaryText("mail local part")
		subject := run.CanaryText("mail subject")
		bodyCanary := run.CanaryText("mail body")
		world := newMailM8World(t, run.Net, nil)
		mxHost := world.mail.Settings().MxHost()

		// the network's zone: §12.7's wildcard MX and the mail host, served by every edge
		dnsSettings := sidecartest.DefaultDnsHarnessSettings()
		dnsSettings.Directory = t.TempDir()
		harness, err := sidecartest.NewDnsHarness(ctx, run.Net, dnsSettings)
		if err != nil {
			return err
		}
		defer harness.Close()
		if harness.Root() != dns.Fqdn(mailM8Root) {
			return fmt.Errorf("the harness serves %s, not the mail root", harness.Root())
		}
		serial, err := harness.WriteServed(ctx, &dnsservice.DnsZoneWrite{
			NetworkId: world.admission.NetworkId(), Upserts: harness.NetworkRows(harness.Root(), mailM8Label),
		})
		if err != nil {
			return err
		}

		// create: an outward action through the gate (I-8), one burner, no record of its own anywhere but mailcfg
		site := "https://" + siteName + ".example/signup"
		created, err := world.ownerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: site})
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		if actions := world.gate.ActionCount(); actions != 1 {
			return fmt.Errorf("create: %d actions reached the gate, not one", actions)
		}
		if !s10BurnerLabelPattern.MatchString(created.Label) || created.Address != siteName+"@"+created.Label+"."+mailM8Label+"."+mailM8Root ||
			created.Info == nil || created.Info.Replying || created.EntryId == (sidecar.Id{}) {
			return fmt.Errorf("create: the burner %+v", created)
		}
		run.Net.Capture().Forbid("a burner's label", []byte(created.Label))
		run.Net.Capture().Forbid("a burner's address", []byte(created.Address))
		zone, err := s10ZoneOf(ctx, harness, created.Label)
		if err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, serial, mxHost); err != nil {
			return fmt.Errorf("a receive-only burner's creation: %w", err)
		}

		// receive: the burner takes mail at its address and at any local part under its label
		world.SyncReceiver()
		other := otherLocalPart + "@" + created.Label + "." + mailM8Label + "." + mailM8Root
		for _, recipient := range []struct {
			address string
			subject string
		}{{address: created.Address, subject: subject}, {address: other, subject: subject + " again"}} {
			if reply := world.Send(recipient.address, recipient.subject, "Your verification code is 482913.\r\n"+bodyCanary); !reply.Is(250) {
				return fmt.Errorf("a live burner's mail: %s", reply)
			}
		}
		messages := world.Ingest()
		for _, subject := range []string{subject, subject + " again"} {
			if message := messages[subject]; message == nil || message.DepositorId != world.receiver.SidecarId {
				return fmt.Errorf("a live burner's mail was not ingested: %+v", message)
			}
		}
		codes, err := world.ownerMail.OneTimeCodes(ctx, time.Time{})
		if err != nil {
			return fmt.Errorf("one-time codes: %w", err)
		}
		if !slices.ContainsFunc(codes, func(code *sidecar.MailOneTimeCode) bool {
			return code.Code == "482913" && code.Source == sidecar.MailOneTimeCodeMail && code.Address == created.Address
		}) {
			return fmt.Errorf("one-time codes %+v hold no code of the burner's mail", codes)
		}
		entries, err := world.ownerMail.VaultEntries(ctx)
		if err != nil || len(entries) != 1 || entries[0].GetAddress() != created.Address || entries[0].GetTitle() != site ||
			entries[0].GetState() != protocol.VaultEntryState_VAULT_ENTRY_LIVE {
			return fmt.Errorf("the burner's vault entry %+v: %v", entries, err)
		}

		// burn: local, with no approval and no call to api (owner decision 32), and the label refused at RCPT from then on
		callsBefore := world.api.Calls()
		actionsBefore := world.gate.ActionCount()
		if err := world.ownerMail.Burn(ctx, created.Address); err != nil {
			return fmt.Errorf("burn: %w", err)
		}
		if calls := world.api.Calls(); fmt.Sprint(calls) != fmt.Sprint(callsBefore) {
			return fmt.Errorf("a burn called api: %v, after %v", calls, callsBefore)
		}
		if actions := world.gate.ActionCount(); actions != actionsBefore {
			return fmt.Errorf("a burn reached the gate: %d actions after %d", actions, actionsBefore)
		}
		world.SyncReceiver()
		for _, recipient := range []string{created.Address, other} {
			reply := world.Send(recipient, subject+" burned", "A message to a burned label.\r\n"+bodyCanary)
			if !reply.Is(550) || len(reply.Lines) == 0 || !strings.HasPrefix(reply.Lines[0], "5.1.1") {
				return fmt.Errorf("a burned label's mail: %s", reply)
			}
		}
		zone, err = s10ZoneOf(ctx, harness, created.Label)
		if err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, serial, mxHost); err != nil {
			return fmt.Errorf("a burn: %w", err)
		}
		entries, err = world.ownerMail.VaultEntries(ctx)
		if err != nil || len(entries) != 1 || entries[0].GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED {
			return fmt.Errorf("the burned burner's vault entry %+v: %v", entries, err)
		}
		burners, err := world.ownerMail.Burners(ctx)
		if err != nil || len(burners) != 1 || burners[0].State != protocol.MailBurnerState_MAIL_BURNER_BURNED {
			return fmt.Errorf("the burners %+v: %v", burners, err)
		}
		// nothing of the burner's mail is deposited after the burn
		if after := world.Ingest(); len(after) != 0 {
			return fmt.Errorf("%d messages deposited after the burn", len(after))
		}

		// the capture reads the router's and the session's logs and the host's metrics beside the stores, none of which
		// may hold the label or an address (I-13); mx-1 keeps the fleet's daily key k in Redis at {vhk}mx:<yyyymmdd>,
		// which testHookSecret hands the capture
		capture := run.Net.Capture()
		if err := capture.Declare("mx-1", "K_mxc_day", sidecartest.PrivacyClassRedis); err != nil {
			return err
		}
		for _, line := range world.mail.LogLines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassLog, Name: "mail log", Body: []byte(line)})
		}
		for _, line := range run.Net.Fakes().Metrics.Dump() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassMetric, Name: "metric", Body: []byte(line)})
		}
		return nil
	}
}

// S10's receive-only half under the harness and guard (RunScenario's T2 defaults).
func TestScenarioS10ReceiveOnlyBurner(t *testing.T) {
	sidecartest.RunScenario(t, &sidecartest.Scenario{Id: "S10", Run: s10Run(t)}, nil)
}

// What the default registry reads for S10 at its gate: on T2 the receive-only half is this file's and only the
// replying half reads missing, MAIL-M9-06's; on T3 every part reads missing, since no T3 world composes the receiver
// and mailcfg on server's stores yet.
func TestS10ReceiveOnlyHalfIsRegisteredOnT2Alone(t *testing.T) {
	registry := sidecartest.DefaultScenarioRegistry()
	missingOf := func(tier string) []string {
		missing := []string{}
		for _, part := range registry.Missing("M9-out", tier) {
			if part.Row.Id == "S10" {
				missing = append(missing, part.Clause)
			}
		}
		return missing
	}
	if missing := missingOf(sidecartest.ScenarioTierT2); !slices.Equal(missing, []string{"first-selector-keeps-blabel-mx-and-a", "last-selector-restores-wildcard-only"}) {
		t.Errorf("S10's missing parts on T2: %q", missing)
	}
	if missing := missingOf(sidecartest.ScenarioTierT3); len(missing) != 4 {
		t.Errorf("S10's missing parts on T3: %q", missing)
	}
	tests := registry.Tests("S10", "burned-label-550-no-dns-change", sidecartest.ScenarioTierT2)
	if len(tests) != 1 || tests[0].Name != "TestScenarioS10ReceiveOnlyBurner" || tests[0].Tags != "sidecar_testhooks" {
		t.Errorf("S10's burned-label clause is registered to %v", tests)
	}
}
