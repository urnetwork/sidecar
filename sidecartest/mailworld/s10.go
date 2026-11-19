//go:build sidecar_testhooks && !sidecar_http && !js && !ios_extension

// S10's receive-only half (§22.7; §3.7's F10, burner lifecycle; R-MAIL-6, R-MAIL-7, R-MAIL-11, D-MAIL-7, I-13, I-14,
// R-PHASE-7; MAIL-M8-10): one builder that sidecartest's T2 test and server's sidecart3 T3 test both run under §22.7's
// harness and guard (RunScenario), never two hand copies. M8World stands on the scenario's Net: the network's log on
// the Net's tier, and the router's Redis, evs's engine and its objects and the gkm objects on the run's hosts, which are
// T2's fakes or T3's real stores, so the capture and the schema guard read them at the end; beside it a DNS harness's
// block and edges serve the network's zone from §12.7's wildcard rows, over T2's fake store or the store a tier gives
// (S10Settings.Zone). Canaries go in the burner's site, which names its local part and its vault entry, in a second
// local part, a subject and a body. Burner create and burn, the vault entry and the one-time code run through
// MailClient, the root calls the bound API wraps (SidecarMail, SDK-M8-04):
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
// MAIL-M9-06's, with M9's sending.

package mailworld

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

// The network's zone as a tier serves it to S10.
type S10Zone struct {
	// The harness whose block and edges serve the root, which the scenario closes.
	Harness *sidecartest.DnsHarness
	// The network's label under the harness's root.
	Label string
	// The root's serial with the network's rows served, §12.7's wildcard MX and the mail host among them.
	Serial uint64
}

// What S10's receive-only half runs with beyond the scenario's Net.
type S10Settings struct {
	// Serves the network's zone on the run's Net: nil for S10FakeZone, T2's. T3 gives a harness on server's store
	// with the network's rows written through model.
	Zone func(ctx context.Context, t testing.TB, run *sidecartest.ScenarioRun, networkId sidecar.Id) (*S10Zone, error)
}

// T2's zone (S10Settings.Zone): a harness on a FakeDnsStore of the Net's, the network at M8Label with §12.7's rows.
func S10FakeZone(ctx context.Context, t testing.TB, run *sidecartest.ScenarioRun, networkId sidecar.Id) (*S10Zone, error) {
	dnsSettings := sidecartest.DefaultDnsHarnessSettings()
	dnsSettings.Directory = t.TempDir()
	harness, err := sidecartest.NewDnsHarness(ctx, run.Net, dnsSettings)
	if err != nil {
		return nil, err
	}
	serial, err := harness.WriteServed(ctx, &dnsservice.DnsZoneWrite{
		NetworkId: networkId, Upserts: harness.NetworkRows(harness.Root(), M8Label),
	})
	if err != nil {
		harness.Close()
		return nil, err
	}
	return &S10Zone{Harness: harness, Label: M8Label, Serial: serial}, nil
}

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

// The zone at harness's store and first edge for label under the network's zone, networkZone.
func s10ZoneOf(ctx context.Context, harness *sidecartest.DnsHarness, networkZone string, label string) (*s10Zone, error) {
	root := harness.Root()
	state, err := harness.Store().RootState(ctx, root)
	if err != nil {
		return nil, err
	}
	zone := &s10Zone{serial: state.Serial}
	name := dns.Fqdn(label + "." + networkZone)
	snapshot, err := harness.Store().Snapshot(ctx, root)
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

// S10's receive-only half as a scenario (the file header's flow): settings nil is T2's.
func S10ReceiveOnly(t testing.TB, settings *S10Settings) *sidecartest.Scenario {
	if settings == nil {
		settings = &S10Settings{}
	}
	return &sidecartest.Scenario{Id: "S10", Run: s10Run(t, settings)}
}

// The flow on run's Net.
func s10Run(t testing.TB, settings *S10Settings) func(ctx context.Context, run *sidecartest.ScenarioRun) error {
	return func(ctx context.Context, run *sidecartest.ScenarioRun) error {
		siteName := run.CanaryText("burner site")
		otherLocalPart := run.CanaryText("mail local part")
		subject := run.CanaryText("mail subject")
		bodyCanary := run.CanaryText("mail body")

		// the network's log on the Net's tier, then its zone, whose label the tier gives: §12.7's wildcard MX and the
		// mail host, served by every edge
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
		serial := served.Serial

		// the world on the run's hosts: evs's and the router's writes recorded as theirs for the stored-state asserts, and
		// what the world writes in another's stead on the Net's host
		world := NewM8World(t, run.Net, &M8WorldSettings{
			Admission: admission,
			Root:      strings.TrimSuffix(harness.Root(), "."),
			Label:     served.Label,
			Stores: func(service string) *sidecar.ServiceHost {
				if service == MailWorldServiceWorld {
					return run.Net.Host()
				}
				return run.Host(service)
			},
		})
		mxHost := world.Mail.Settings().MxHost()

		// create: an outward action through the gate (I-8), one burner, no record of its own anywhere but mailcfg
		site := "https://" + siteName + ".example/signup"
		created, err := world.OwnerMail.CreateBurner(ctx, &sidecar.MailBurnerCreateArgs{Site: site})
		if err != nil {
			return fmt.Errorf("create: %w", err)
		}
		if actions := world.Gate.ActionCount(); actions != 1 {
			return fmt.Errorf("create: %d actions reached the gate, not one", actions)
		}
		if !s10BurnerLabelPattern.MatchString(created.Label) || created.Address != siteName+"@"+created.Label+"."+world.Zone() ||
			created.Info == nil || created.Info.Replying || created.EntryId == (sidecar.Id{}) {
			return fmt.Errorf("create: the burner %+v", created)
		}
		run.Net.Capture().Forbid("a burner's label", []byte(created.Label))
		run.Net.Capture().Forbid("a burner's address", []byte(created.Address))
		zone, err := s10ZoneOf(ctx, harness, world.Zone(), created.Label)
		if err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, serial, mxHost); err != nil {
			return fmt.Errorf("a receive-only burner's creation: %w", err)
		}

		// receive: the burner takes mail at its address and at any local part under its label
		world.SyncReceiver()
		other := otherLocalPart + "@" + created.Label + "." + world.Zone()
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
			if message := messages[subject]; message == nil || message.DepositorId != world.Receiver.SidecarId {
				return fmt.Errorf("a live burner's mail was not ingested: %+v", message)
			}
		}
		codes, err := world.OwnerMail.OneTimeCodes(ctx, time.Time{})
		if err != nil {
			return fmt.Errorf("one-time codes: %w", err)
		}
		if !slices.ContainsFunc(codes, func(code *sidecar.MailOneTimeCode) bool {
			return code.Code == "482913" && code.Source == sidecar.MailOneTimeCodeMail && code.Address == created.Address
		}) {
			return fmt.Errorf("one-time codes %+v hold no code of the burner's mail", codes)
		}
		entries, err := world.OwnerMail.VaultEntries(ctx)
		if err != nil || len(entries) != 1 || entries[0].GetAddress() != created.Address || entries[0].GetTitle() != site ||
			entries[0].GetState() != protocol.VaultEntryState_VAULT_ENTRY_LIVE {
			return fmt.Errorf("the burner's vault entry %+v: %v", entries, err)
		}

		// burn: local, with no approval and no call to api (owner decision 32), and the label refused at RCPT from then on
		callsBefore := world.Api.Calls()
		actionsBefore := world.Gate.ActionCount()
		if err := world.OwnerMail.Burn(ctx, created.Address); err != nil {
			return fmt.Errorf("burn: %w", err)
		}
		if calls := world.Api.Calls(); fmt.Sprint(calls) != fmt.Sprint(callsBefore) {
			return fmt.Errorf("a burn called api: %v, after %v", calls, callsBefore)
		}
		if actions := world.Gate.ActionCount(); actions != actionsBefore {
			return fmt.Errorf("a burn reached the gate: %d actions after %d", actions, actionsBefore)
		}
		world.SyncReceiver()
		for _, recipient := range []string{created.Address, other} {
			reply := world.Send(recipient, subject+" burned", "A message to a burned label.\r\n"+bodyCanary)
			if !reply.Is(550) || len(reply.Lines) == 0 || !strings.HasPrefix(reply.Lines[0], "5.1.1") {
				return fmt.Errorf("a burned label's mail: %s", reply)
			}
		}
		zone, err = s10ZoneOf(ctx, harness, world.Zone(), created.Label)
		if err != nil {
			return err
		}
		if err := s10WildcardOnly(zone, serial, mxHost); err != nil {
			return fmt.Errorf("a burn: %w", err)
		}
		entries, err = world.OwnerMail.VaultEntries(ctx)
		if err != nil || len(entries) != 1 || entries[0].GetState() != protocol.VaultEntryState_VAULT_ENTRY_BURNED {
			return fmt.Errorf("the burned burner's vault entry %+v: %v", entries, err)
		}
		burners, err := world.OwnerMail.Burners(ctx)
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
		// a dns edge is sent the label in an MX lookup, a sender's and this flow's own zone reads, and answers it from
		// the wildcard with no query kept (dns-2; §15.9), so the label passes in the queries an edge was sent and in
		// no other class, the edges' records and the upstream resolver's queries included
		if err := capture.Declare("dns-2", "a burner's label", sidecartest.PrivacyClassDnsEdgeQuery); err != nil {
			return err
		}
		for _, line := range world.Mail.LogLines() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassLog, Name: "mail log", Body: []byte(line)})
		}
		for _, line := range run.Net.Fakes().Metrics.Dump() {
			capture.AddItem(&sidecartest.PrivacyItem{Class: sidecartest.PrivacyClassMetric, Name: "metric", Body: []byte(line)})
		}
		return nil
	}
}
