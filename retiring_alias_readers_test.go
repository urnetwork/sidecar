//go:build !sidecar_http && !js && !ios_extension

// The two readers that saw only the zone's current label and alias, given the retiring aliases the network's label
// table keeps (§12.5's alias and retirement rows, D-DNS-10; dns_label_zone_row.go): mail's network row, which a
// receiver's mailcfg resolves an RCPT's zone by (MailZone.OfNetwork), and the socket host's label resolver, which a
// §9.4 address's <net> goes through on Listen and Dial. Mail addressed under an alias the zone moved from, or under one
// the zone names as retiring with api's end, is received until the alias's end and refused from then on, with no pass
// reading the zone again; an address naming such an alias listens and dials until then, and from then on its listen is
// denied and its dial finds no listener, through labels installed before the end too. The row itself takes the zone's
// time over the table's, the table's where the zone gives none, leaves out an alias live again, and keeps the zone's
// own where no table opens. All on clocks the test moves.

package sidecar

import (
	"context"
	"errors"
	"maps"
	"slices"
	"testing"
	"time"
)

// A mail client bound from a Sidecar whose label table reads clock and whose dns block answers zone, as the component
// binds one (bindFromSidecar), and, from the first bind, a receiver's sessions over a mailcfg on the client's network
// row holding ada's address in ada's mailbox.
type testRetiringAliasMail struct {
	t       *testing.T
	running *Sidecar
	dns     *DnsClient
	block   *testDnsBlock
	client  *MailClient
	world   *mailSessionTestWorld
}

func newTestRetiringAliasMail(t *testing.T, clock Clock, zone *DnsZone) *testRetiringAliasMail {
	t.Helper()
	zone.NetworkId = testNetworkId
	running, _, dns, block := newTestDnsLabelsSidecar(t, testNetworkId, zone)
	running.clock = clock
	client, err := NewMailClient(&MailClientArgs{NetworkId: testNetworkId, SidecarId: testMailConfigPhoneId, Store: newTestMemoryStore(), Clock: clock})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	client.sidecar = running
	return &testRetiringAliasMail{t: t, running: running, dns: dns, block: block, client: client}
}

// A pass's bind; at the first, the mailcfg on the row it bound, ada's address created under the zone's label, and the
// receiver's sessions on that mailcfg.
func (self *testRetiringAliasMail) bind() {
	self.t.Helper()
	self.client.bindFromSidecar(context.Background(), nil)
	if self.world != nil {
		return
	}
	repo, authority := newMailConfigTestWorld(self.t)
	device := newMailConfigTestDevice(self.t, repo, authority, testMailConfigPhoneId, func(args *MailConfigArgs) {
		args.Network = self.client.networkRow
	})
	device.createId(self.t, "ada")
	device.sync(self.t)
	self.world = newMailSessionTestWorld(self.t, func(args *MailSessionArgs) {
		args.Resolve = nil
		args.mailConfig = device.config
	})
}

// The replies to an RCPT of each recipient, in order, in one transaction on a fresh stream.
func (self *testRetiringAliasMail) rcpt(recipients ...string) []int {
	self.t.Helper()
	sender := self.world.open(testMailSessionIngress(self.t))
	sender.expect("EHLO mail.sender.example", 250)
	sender.expect("MAIL FROM:<bounce@sender.example>", 250)
	codes := []int{}
	for _, recipient := range recipients {
		code, _ := sender.command("RCPT TO:<" + recipient + ">")
		codes = append(codes, code)
	}
	return codes
}

// A message to recipient taken whole: its RCPT and its end of data answered 250, and its deposit made in ada's
// mailbox.
func (self *testRetiringAliasMail) receive(recipient string, subject string) {
	self.t.Helper()
	sender := self.world.open(testMailSessionIngress(self.t))
	sender.envelope(recipient)
	codes, messages := sender.data(testMailSessionMessage(subject))
	if code := <-codes; code != 250 {
		self.t.Fatalf("mail to %s: its end of data answered %d %s", recipient, code, <-messages)
	}
	deposits := self.world.takenDeposits()
	if len(deposits) == 0 || deposits[len(deposits)-1].repoId != testMailConfigMailboxId ||
		!slices.Equal(deposits[len(deposits)-1].trailer.GetRecipients(), []string{recipient}) {
		self.t.Fatalf("mail to %s: %d deposits, the last not to it in ada's mailbox", recipient, len(deposits))
	}
}

// The zone moves the network's alias after the label table took it live: mail under the alias it moved from is
// received, beside mail under the new alias and the label, until the alias's end, the table's 90 days from the move,
// and refused from then on with no pass between, where before the row named no retiring alias and the first RCPT was
// refused; the new alias and the label still take mail, and a pass past the end binds the old alias no more.
func TestMailReceivesUnderAnAliasTheTableSawRetireUntilItsEnd(t *testing.T) {
	clock := newTestLabelClock()
	moved := clock.Now()
	mail := newTestRetiringAliasMail(t, clock, &DnsZone{Root: testMailConfigRoot, Label: "acme", Alias: "widgets", Version: 1})
	if _, err := mail.running.NetworkLabels(); err != nil {
		t.Fatal(err)
	}
	if _, err := mail.dns.Zone(t.Context()); err != nil {
		t.Fatal(err)
	}
	mail.block.setZone(&DnsZone{NetworkId: testNetworkId, Root: testMailConfigRoot, Label: "acme", Alias: "gizmos", Version: 2})
	// the refetch a hint brings, which the table takes
	if _, err := mail.dns.fetchZone(t.Context()); err != nil {
		t.Fatal(err)
	}
	mail.bind()
	if codes := mail.rcpt("ada@widgets.root.example", "ada@gizmos.root.example", "ada@acme.root.example"); !slices.Equal(codes, []int{250, 250, 250}) {
		t.Fatalf("RCPTs within the window answered %v", codes)
	}
	mail.receive("ada@widgets.root.example", "retiring")

	end := moved.Add(DefaultNetworkLabelTableSettings().RetiringWindow)
	clock.set(end.Add(-time.Millisecond))
	if codes := mail.rcpt("ada@widgets.root.example"); !slices.Equal(codes, []int{250}) {
		t.Fatalf("an RCPT just before the end answered %v", codes)
	}
	clock.set(end)
	if codes := mail.rcpt("ada@widgets.root.example", "ada@gizmos.root.example", "ada@acme.root.example"); !slices.Equal(codes, []int{550, 250, 250}) {
		t.Fatalf("RCPTs at the end, with no pass since, answered %v", codes)
	}
	mail.bind()
	if codes := mail.rcpt("ada@widgets.root.example"); !slices.Equal(codes, []int{550}) {
		t.Fatalf("an RCPT after a pass past the end answered %v", codes)
	}
}

// A device whose table never held the old alias live, as one enrolled after the change, takes it from the zone, which
// names it with api's end: mail under it is received until then and refused from then on, while the live alias still
// takes mail.
func TestMailReceivesUnderARetiringAliasTheZoneNamesUntilApisEnd(t *testing.T) {
	clock := newTestLabelClock()
	end := clock.Now().Add(3 * 24 * time.Hour)
	mail := newTestRetiringAliasMail(t, clock, &DnsZone{
		Root:            testMailConfigRoot,
		Label:           "acme",
		Alias:           "gizmos",
		RetiringAliases: []NetworkLabelRetiringAlias{{Alias: "widgets", TombstoneTime: end}},
		Version:         7,
	})
	mail.bind()
	if codes := mail.rcpt("ada@widgets.root.example", "ada@gizmos.root.example"); !slices.Equal(codes, []int{250, 250}) {
		t.Fatalf("RCPTs before api's end answered %v", codes)
	}
	mail.receive("ada@widgets.root.example", "retiring")
	clock.set(end)
	if codes := mail.rcpt("ada@widgets.root.example", "ada@gizmos.root.example"); !slices.Equal(codes, []int{550, 250}) {
		t.Fatalf("RCPTs at api's end answered %v", codes)
	}
}

// A listen fixture whose component's host is a Sidecar on the fixture's clock, the label table's with it, its dns block
// answering zone, as the stock host composes one (Sidecar.NewSocketComponent).
func newTestRetiringAliasSockets(t *testing.T, zone *DnsZone) (*testListenFixture, *Sidecar, *DnsClient, *testDnsBlock) {
	t.Helper()
	fixture := newTestListenFixture(t)
	zone.NetworkId = testRegistrarNetworkId
	running, _, dns, block := newTestDnsLabelsSidecar(t, testRegistrarNetworkId, zone)
	running.clock = fixture.clock
	fixture.component.host = running
	return fixture, running, dns, block
}

// Sets clock's time to at and fires nothing: the registrar's waits stay armed where they were, and only reads of now
// move, as the label table's and a resolver's are.
func setTestSocketClockTime(clock *testSocketClock, at time.Time) {
	clock.stateLock.Lock()
	defer clock.stateLock.Unlock()
	clock.now = at
}

// The component's listen of address, as Listen calls it.
func testRetiringAliasListen(t *testing.T, fixture *testListenFixture, address string) error {
	t.Helper()
	parsed, err := ParseSocketAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := fixture.component.listen(t.Context(), parsed, nil, false)
	if listener != nil {
		listener.Close()
	}
	return err
}

// The zone moves the network's alias after the label table took it live: a §9.4 address naming the alias it moved
// from resolves to the network through the labels the host installs until the alias's end, so a listen on it
// registers and a dial reaches its listener, as under the new alias; from the end on its listen is denied and its dial
// finds no listener and asks no Find, through the labels installed before the end as well, while the new alias still
// dials.
func TestSocketAddressUnderAnAliasTheTableSawRetireResolvesUntilItsEnd(t *testing.T) {
	fixture, running, dns, block := newTestRetiringAliasSockets(t, &DnsZone{Root: testLabelRoot, Label: "abcdefghij", Alias: "team-live", Version: 1})
	moved := fixture.clock.Now()
	if _, err := running.NetworkLabels(); err != nil {
		t.Fatal(err)
	}
	if _, err := dns.Zone(t.Context()); err != nil {
		t.Fatal(err)
	}
	block.setZone(&DnsZone{NetworkId: testRegistrarNetworkId, Root: testLabelRoot, Label: "abcdefghij", Alias: "team-next", Version: 2})
	// the refetch a hint brings, which the table takes
	if _, err := dns.fetchZone(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"team-live:db/primary", "team-next:db/secondary"} {
		if err := testRetiringAliasListen(t, fixture, address); err != nil {
			t.Fatalf("a listen on %s within the window: %v", address, err)
		}
	}
	_, _, labels := fixture.component.current()
	if labels == nil || labels.Resolver == nil || labels.Label != "abcdefghij" || labels.Root != testLabelRoot {
		t.Fatalf("the labels the host installed: %+v", labels)
	}
	listener := newTestDialListener("primary")
	dial := newTestDialFixture(t, listener)
	dial.service.answers = [][]*testDialListener{{listener}}
	dial.dialer.labels = labels
	for _, address := range []string{"team-live:" + testDialName, "team-next:" + testDialName} {
		conn, err := dial.dial(address)
		if err != nil {
			t.Fatalf("a dial of %s within the window: %v", address, err)
		}
		conn.Close()
	}

	setTestSocketClockTime(fixture.clock.testSocketClock, moved.Add(DefaultNetworkLabelTableSettings().RetiringWindow))
	if err := testRetiringAliasListen(t, fixture, "team-live:db/tertiary"); !errors.Is(err, ErrSocketDenied) {
		t.Fatalf("a listen under the alias at its end: %v", err)
	}
	finds := len(dial.service.findArgs())
	if _, err := dial.dial("team-live:" + testDialName); !errors.Is(err, ErrSocketNoListener) || len(dial.service.findArgs()) != finds {
		t.Fatalf("a dial under the alias at its end, through the labels installed before it: %v, %d more finds", err, len(dial.service.findArgs())-finds)
	}
	conn, err := dial.dial("team-next:" + testDialName)
	if err != nil {
		t.Fatalf("a dial under the new alias at the old one's end: %v", err)
	}
	conn.Close()
}

// A device whose table never held the old alias live takes it from the zone, which names it with api's end: a listen
// under it registers until then, and from then on is denied.
func TestSocketAddressUnderARetiringAliasTheZoneNamesResolvesUntilApisEnd(t *testing.T) {
	end := testSocketNow.Add(3 * 24 * time.Hour)
	fixture, _, _, _ := newTestRetiringAliasSockets(t, &DnsZone{
		Root:            testLabelRoot,
		Label:           "abcdefghij",
		Alias:           "team-next",
		RetiringAliases: []NetworkLabelRetiringAlias{{Alias: "team-live", TombstoneTime: end}},
		Version:         7,
	})
	if err := testRetiringAliasListen(t, fixture, "team-live:db/primary"); err != nil {
		t.Fatalf("a listen under the zone's retiring alias before api's end: %v", err)
	}
	setTestSocketClockTime(fixture.clock.testSocketClock, end)
	if err := testRetiringAliasListen(t, fixture, "team-live:db/secondary"); !errors.Is(err, ErrSocketDenied) {
		t.Fatalf("a listen under the zone's retiring alias at api's end: %v", err)
	}
}

// The row the readers take: for an alias both name the zone's tombstone time over the table's, the table's where the
// zone gives none, the table's own retiring alias with its time, and an alias the zone gives live again left out; and
// with no table that opens, the zone's own alone.
func TestNetworkLabelZoneRowTakesTheZonesAndTheTablesRetiringAliases(t *testing.T) {
	clock := newTestLabelClock()
	apiEnd := clock.Now().Add(2 * 24 * time.Hour)
	tableEnd := clock.Now().Add(5 * 24 * time.Hour)
	networkId := testConfigId("retiring alias readers")
	zone := &DnsZone{
		NetworkId: networkId,
		Root:      testLabelRoot,
		Label:     "a7q2m9x4k1",
		Alias:     "owner-back",
		RetiringAliases: []NetworkLabelRetiringAlias{
			{Alias: "owner-both", TombstoneTime: apiEnd},
			{Alias: "owner-untimed"},
			{Alias: "owner-zone", TombstoneTime: apiEnd},
		},
		Version: 3,
	}
	running, _, dns, _ := newTestDnsLabelsSidecar(t, networkId, zone)
	running.clock = clock
	// the zone is fetched before the table opens, so the table never takes it, and holds what it held before
	if _, err := dns.Zone(t.Context()); err != nil {
		t.Fatal(err)
	}
	labels, err := running.NetworkLabels()
	if err != nil {
		t.Fatal(err)
	}
	if err := labels.SetNetwork(NetworkLabelRow{
		Root:            testLabelRoot,
		NetworkId:       networkId,
		Label:           "a7q2m9x4k1",
		Alias:           "owner-old",
		RetiringAliases: []string{"owner-back", "owner-both", "owner-table", "owner-untimed"},
		RetiringAliasTombstoneTimes: map[string]time.Time{
			"owner-back": tableEnd, "owner-both": tableEnd, "owner-table": tableEnd, "owner-untimed": tableEnd,
		},
	}); err != nil {
		t.Fatal(err)
	}
	read, row, err := running.networkLabelZoneRow(t.Context())
	if err != nil || read == nil || read.Version != 3 {
		t.Fatalf("the zone read: %+v, %v", read, err)
	}
	wantTimes := map[string]time.Time{"owner-both": apiEnd, "owner-table": tableEnd, "owner-untimed": tableEnd, "owner-zone": apiEnd}
	if row.Root != testLabelRoot || row.NetworkId != networkId || row.Label != "a7q2m9x4k1" || row.Alias != "owner-back" ||
		!slices.Equal(row.RetiringAliases, []string{"owner-both", "owner-table", "owner-untimed", "owner-zone"}) ||
		!maps.EqualFunc(row.RetiringAliasTombstoneTimes, wantTimes, time.Time.Equal) {
		t.Fatalf("the row: %+v", row)
	}

	// no keychain to open the table in: the zone's own, the one api gave no time unbounded, as a row in memory holds it
	tableless := &Sidecar{networkId: &networkId, settings: validSidecarSettings(), clock: clock}
	tableless.dns.client = newTestDnsClient(t, newTestDnsBlock(zone), nil, networkId)
	if _, err := tableless.NetworkLabels(); err == nil {
		t.Fatal("a table opened with no keychain")
	}
	_, row, err = tableless.networkLabelZoneRow(t.Context())
	wantTimes = map[string]time.Time{"owner-both": apiEnd, "owner-zone": apiEnd}
	if err != nil || !slices.Equal(row.RetiringAliases, []string{"owner-both", "owner-untimed", "owner-zone"}) ||
		!maps.EqualFunc(row.RetiringAliasTombstoneTimes, wantTimes, time.Time.Equal) {
		t.Fatalf("the row with no table: %+v, %v", row, err)
	}
}
