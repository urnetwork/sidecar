//go:build !sidecar_http && !js && !ios_extension

// MAIL-M8-03's coverage and codes, FS-82's M8 case on §7.9's test network: none with no receiver, foreground-only once
// a device may receive with no mail indexer, then indexer once one is designated; a designation the reader cannot open
// never reads as indexer; the exact copy as a golden, which says nothing of sending; and one-time codes from the vault's
// TOTP and the mailbox's i/ merged newest first since a time, the vault's left out for a device that may not read it.

package sidecar

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §15.9's and §18.5's copy, word for word: the golden.
const testMailCoverageGolden = "A phone alone cannot reliably receive mail: an indexer, an always-on device (a desktop ur daemon, a NAS or VPS), is needed; time-sensitive codes may not arrive"

// Grants each device the receiver's listen on smtp/25/mx by a rule of its own, in a base folding the tip.
func (self *testConfigNet) grantMailListen(devices ...testConfigDevice) {
	self.t.Helper()
	state := self.log.State()
	rows := state.Rows()
	aclRows := proto.Clone(state.aclRows).(*protocol.AclRows)
	for _, device := range devices {
		atom := NewId()
		aclRows.Atoms = append(aclRows.Atoms, &protocol.AclAtom{Atom: atom.Bytes(), SidecarIds: [][]byte{device.sidecarId.Bytes()}})
		aclRows.Rules = append(aclRows.Rules, &protocol.AclRule{
			RuleId: NewId().Bytes(), SrcAtoms: [][]byte{atom.Bytes()},
			Targets: []*protocol.AclTarget{{PublicName: aclMailReceiverName}}, Actions: []uint32{uint32(protocol.AclAction_ACL_ACTION_LISTEN)},
		})
	}
	aclRows.HasDocument = true
	rows.Acl = testConfigMarshal(self.t, aclRows)
	configVersion := state.Base().GetConfigVersion() + 1
	// the head's settings, team_mail's among them, carry over to the new config version
	if settings, ok := self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion-1))]; ok {
		self.source.settings[[sha256.Size]byte(testConfigHeadSha256(configVersion))] = settings
	}
	if verdict := self.pushBase(self.owner, rows, self.n, configVersion, state.threshold); !verdict.Accepted() {
		self.t.Fatal(verdict.Refusal)
	}
}

// The coverage of device's user at the net's newest state.
func testMailCoverageAt(t *testing.T, net *testConfigNet, device testConfigDevice, services MailIndexerServices) MailCoverage {
	t.Helper()
	config := net.log.State()
	acl, err := config.Acl()
	if err != nil {
		t.Fatal(err)
	}
	return mailCoverageOf(acl, config, device.sidecarId, services, time.UnixMilli(net.timeMs))
}

// The copy is the golden word for word, under foreground-only and none alike, and none under indexer; MailIndexerPrompt
// is the same text; and no copy speaks of sending (FS-123's clause as plan-MAIL-small-readings#21 reads it).
func TestMailCoverageCopyIsTheGolden(t *testing.T) {
	if MailCoverageCopy(MailCoverageForegroundOnly) != testMailCoverageGolden || MailCoverageCopy(MailCoverageNone) != testMailCoverageGolden {
		t.Fatalf("the copy %q", MailCoverageCopy(MailCoverageForegroundOnly))
	}
	if MailCoverageCopy(MailCoverageIndexer) != "" || MailCoverageCopy("later") != "" {
		t.Fatal("copy under indexer or an unknown value")
	}
	if MailIndexerPrompt != testMailCoverageGolden {
		t.Fatalf("the indexer prompt %q", MailIndexerPrompt)
	}
	for _, coverage := range []MailCoverage{MailCoverageIndexer, MailCoverageForegroundOnly, MailCoverageNone} {
		text := strings.ToLower(string(coverage) + " " + MailCoverageCopy(coverage))
		for _, word := range []string{"send", "sent", "outbound", "deliver to"} {
			if strings.Contains(text, word) {
				t.Errorf("coverage %s speaks of sending: %q", coverage, text)
			}
		}
	}
}

// FS-82's M8 case: with no device that may receive, none; once one may, with no mail indexer, foreground-only, so an
// online receiver takes mail; then indexer once a designation names one for mail.
func TestMailCoverageForegroundOnlyThenIndexer(t *testing.T) {
	net := newTestConfigNet(t)
	member, laptop := net.consentedMember("m")
	desktop := net.device("m desktop", member)
	net.admitDevice(laptop, desktop, 0)
	services := testMailIndexerServices(map[Id][]protocol.IndexerService{desktop.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_MAIL}})
	if coverage := testMailCoverageAt(t, net, laptop, services); coverage != MailCoverageNone {
		t.Fatalf("with no receiver: %s", coverage)
	}
	net.grantMailListen(laptop)
	if coverage := testMailCoverageAt(t, net, laptop, services); coverage != MailCoverageForegroundOnly {
		t.Fatalf("with a receiver and no mail indexer: %s", coverage)
	}
	net.mustPost(laptop, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(desktop, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	if coverage := testMailCoverageAt(t, net, laptop, services); coverage != MailCoverageIndexer {
		t.Fatalf("with a mail indexer designated: %s", coverage)
	}
	// a designation this device cannot open is not shown to be a mail indexer
	if coverage := testMailCoverageAt(t, net, laptop, nil); coverage != MailCoverageForegroundOnly {
		t.Fatalf("with an unopened designation: %s", coverage)
	}
	// a designation that names search alone is no mail indexer
	searchOnly := testMailIndexerServices(map[Id][]protocol.IndexerService{desktop.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_SEARCH}})
	if coverage := testMailCoverageAt(t, net, laptop, searchOnly); coverage != MailCoverageForegroundOnly {
		t.Fatalf("with a search-only designation: %s", coverage)
	}
}

// Under team_mail: indexers an undesignated tag:mail device granted the listen registers none, so it is no receiver
// coverage counts; the same device designated is an indexer.
func TestMailCoverageCountsOnlyReceiversThatRegister(t *testing.T) {
	team := newTestMailIndexerTeam(t, protocol.TeamMailMode_TEAM_MAIL_MODE_INDEXERS)
	team.net.grantMailListen(team.other)
	none := testMailIndexerServices(map[Id][]protocol.IndexerService{team.designated.sidecarId: {protocol.IndexerService_INDEXER_SERVICE_SEARCH}})
	if coverage := testMailCoverageAt(t, team.net, team.laptop, none); coverage != MailCoverageNone {
		t.Fatalf("an undesignated tag:mail device counted as a receiver: %s", coverage)
	}
	if coverage := testMailCoverageAt(t, team.net, team.laptop, team.services); coverage != MailCoverageIndexer {
		t.Fatalf("the designated tag:mail device: %s", coverage)
	}
}

// The client answers coverage at its bound state, and ErrMailUnbound before one is bound.
func TestMailClientReceiverCoverage(t *testing.T) {
	world := newMailClientTestWorld(t)
	ctx := context.Background()
	if coverage, err := world.client.ReceiverCoverage(ctx); err != nil || coverage != MailCoverageNone {
		t.Fatalf("with no receiver %s: %v", coverage, err)
	}
	unbound, err := NewMailClient(&MailClientArgs{NetworkId: testNetworkId, SidecarId: NewId(), Store: newTestMemoryStore()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unbound.ReceiverCoverage(ctx); !errors.Is(err, ErrMailUnbound) {
		t.Fatalf("unbound: %v", err)
	}
}

// The client world with a vault over an in-memory store for the member's mailbox.
type mailCodesTestParts struct {
	*mailClientTestParts
	vaultStore *mailVaultTestStore
	authority  *mailVaultTestAuthority
	clock      Clock
}

func (self *mailCodesTestParts) vault(mailboxId Id, ownerMemberId Id, args *MailVaultArgs) *MailVault {
	return newMailVault(self.vaultStore, ownerMemberId, args.SidecarId, self.authority, self.clock, nil, DefaultMailVaultSettings())
}

// Codes from both sources, newest first, since a time: two messages' codes an hour apart and a TOTP code for now; since
// leaves the older message's out; and a device the vault refuses gets the mail codes alone. No code reaches a log.
func TestMailOneTimeCodesMergesBothSourcesNewestFirst(t *testing.T) {
	world := newMailClientTestWorld(t)
	mailboxId := world.enable()
	now := time.UnixMilli(int64(testMailIngestReceiveMillis) + 3*time.Hour.Milliseconds()).UTC()
	clock := &mailTestClock{now: now}
	world.client.clock = clock
	parts := &mailCodesTestParts{
		mailClientTestParts: &mailClientTestParts{world: world},
		vaultStore:          newMailVaultTestStore(),
		authority:           newMailVaultTestAuthority(world.device, world.member),
		clock:               clock,
	}
	world.client.stateLock.Lock()
	world.client.partsOverride = parts
	world.client.stateLock.Unlock()
	ctx := context.Background()

	deposit := func(subject string, receiveMillis uint64) {
		message := testMailIngestMessage(subject, "Thanks for signing up.")
		trailer := testMailIngestTrailer(world.ingest.receiverId, message)
		trailer.Evidence.ReceiveTimeMillis = receiveMillis
		world.ingest.repo.deposit(world.ingest.receiverId, world.ingest.receiverId, testMailIngestPlaintext(t, message, trailer))
	}
	deposit("Your Example verification code is 482913", testMailIngestReceiveMillis)
	deposit("Your Other verification code is 905118", testMailIngestReceiveMillis+uint64(time.Hour.Milliseconds()))
	world.ingestAll(mailboxId)
	if _, err := world.client.PutVaultEntry(ctx, &protocol.VaultEntry{
		Address: "otter-4821@acme.root.example", Title: "example.org",
		Totp: &protocol.VaultTotp{Secret: []byte("12345678901234567890"), Algorithm: protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, Digits: 6, Period: 30},
	}); err != nil {
		t.Fatal(err)
	}

	codes, err := world.client.OneTimeCodes(ctx, time.UnixMilli(int64(testMailIngestReceiveMillis)))
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 3 || codes[0].Source != MailOneTimeCodeTotp || codes[1].Code != "905118" || codes[2].Code != "482913" {
		t.Fatalf("codes %+v", codes)
	}
	wantTotp, until, err := MailTotpCode(&protocol.VaultTotp{Secret: []byte("12345678901234567890"), Algorithm: protocol.VaultTotpAlgorithm_VAULT_TOTP_SHA1, Digits: 6, Period: 30}, now)
	if err != nil || codes[0].Code != wantTotp || !codes[0].Until.Equal(until) || codes[0].Address != "otter-4821@acme.root.example" {
		t.Fatalf("the TOTP code %+v, want %s until %s: %v", codes[0], wantTotp, until, err)
	}
	for index := 1; index < len(codes); index += 1 {
		if codes[index].Time.After(codes[index-1].Time) {
			t.Fatal("codes not newest first")
		}
	}

	// since past the first message leaves it out
	since := time.UnixMilli(int64(testMailIngestReceiveMillis) + 30*time.Minute.Milliseconds())
	codes, err = world.client.OneTimeCodes(ctx, since)
	if err != nil || len(codes) != 2 || codes[1].Code != "905118" {
		t.Fatalf("codes since %s: %+v, %v", since, codes, err)
	}

	// a device the vault refuses reads the mail codes alone
	parts.authority.set(world.device, world.member, false)
	codes, err = world.client.OneTimeCodes(ctx, time.UnixMilli(int64(testMailIngestReceiveMillis)))
	if err != nil || len(codes) != 2 || codes[0].Source != MailOneTimeCodeMail {
		t.Fatalf("codes on a device the vault refuses: %+v, %v", codes, err)
	}
	for _, line := range world.log.snapshot() {
		if strings.Contains(line, "482913") || strings.Contains(line, wantTotp) {
			t.Errorf("a line names a code: %q", line)
		}
	}
}
