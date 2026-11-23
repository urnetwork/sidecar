// QD-1207 where a reader checks a base's config head: CheckConfigBase keeps a ServiceSettings or VersioningRules record
// that the previous base's head held byte for byte without judging its signer again, revoked or demoted since, and
// judges every other record at S(n-1) as before, a new one, one put back after a head removed it and the same settings
// signed by another device alike; a reader that starts at a base takes both records with their hashes; and
// ConfigClient's verified heads keep the hashes across a restart, whose anchor reads no head, while a head the store
// kept without them is read again. config_head_records_revoked_test.go runs the rule through every kind of reader on
// T2's writer world.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The ServiceSettings a device files: head-only fields.
func testCarrySettings() *protocol.ServiceSettings {
	return &protocol.ServiceSettings{MailStrict: true, RecordRequired: true}
}

// The VersioningRules a device files.
func testCarryRules() *protocol.VersioningRules {
	return &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{SizeAboveBytes: 1024 * 1024, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
}

// The SHA-256 of a record's Signed bytes, as a state holds it.
func testCarrySha256(signedBytes []byte) []byte {
	digest := sha256.Sum256(signedBytes)
	return digest[:]
}

// A head of net's genesis holding the records, verbatim, each left out when nil.
func testCarryHead(t *testing.T, net *testConfigNet, settingsBytes []byte, rulesBytes []byte) *ConfigHead {
	t.Helper()
	head := testConfigHead(t, net)
	var err error
	if settingsBytes != nil {
		if head, err = head.WithFile(ConfigHeadServiceSettingsPath, settingsBytes); err != nil {
			t.Fatal(err)
		}
	}
	if rulesBytes != nil {
		if head, err = head.WithFile(ConfigHeadVersioningRulesPath, rulesBytes); err != nil {
			t.Fatal(err)
		}
	}
	return head
}

// state as a reader holds it whose previous base's head held the records hashing to settingsSha256 and rulesSha256, nil
// for a record that head held none of.
func testCarryHolding(state *ConfigState, settingsSha256 []byte, rulesSha256 []byte) *ConfigState {
	holding := configCopyState(state)
	holding.headSettingsRecordSha256, holding.headVersioningRulesRecordSha256 = settingsSha256, rulesSha256
	return holding
}

// CheckConfigBase of head at a base landing on previous that folds nothing more, its rows the head's compile with
// previous's.
func testCarryCheck(t *testing.T, previous *ConfigState, head *ConfigHead) (*ConfigHeadFacts, error) {
	t.Helper()
	rows := ConfigCompileRowsOf(previous)
	compiled, err := CompileProjectionRows(head, rows)
	if err != nil {
		t.Fatal(err)
	}
	return CheckConfigBase(head, &ConfigHeadCheck{
		Previous:    previous,
		Header:      &bridge.ProjectionHeader{FoldedThrough: previous.Base().GetFoldedThrough()},
		FoldedKnown: true,
		Rows:        compiled,
	}, rows)
}

// Fails unless err is the fork of a head whose record at path its signer does not sign, for why.
func testCarryRefused(t *testing.T, label string, err error, path string, why string) {
	t.Helper()
	if !errors.Is(err, ErrConfigHeadMismatch) || !strings.Contains(err.Error(), path+": its signer") || !strings.Contains(err.Error(), why) {
		t.Fatalf("%s: %v; want its %s's signer refused, %s", label, err, path, why)
	}
}

// An Owner's laptop signs both records, the base whose head first holds them judging their signer, who stands. Once the
// laptop is revoked as lost, a reader whose previous base's head held both keeps both, its signer not judged again, and
// keeps their hashes on; each record that head did not hold is judged and forks the base, and a hash held at one path
// stands for no record at the other.
func TestACarriedRecordStandsOnceItsSignerIsRevoked(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	laptop := net.device("owner laptop", net.ownerMemberId)
	net.admitDevice(net.owner, laptop, 0)
	settingsBytes := net.sign(laptop, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	rulesBytes := net.sign(laptop, bridge.SignedType_SIGNED_VERSIONING_RULES, testCarryRules())
	head := testCarryHead(t, net, settingsBytes, rulesBytes)
	settingsSha256, rulesSha256 := testCarrySha256(settingsBytes), testCarrySha256(rulesBytes)

	facts, err := testCarryCheck(t, net.log.State(), head)
	if err != nil {
		t.Fatalf("the records' first base: %v", err)
	}
	if !bytes.Equal(facts.settingsRecordSha256, settingsSha256) || !bytes.Equal(facts.versioningRulesRecordSha256, rulesSha256) {
		t.Fatalf("the first base's check found the hashes %x and %x", facts.settingsRecordSha256, facts.versioningRulesRecordSha256)
	}

	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	revoked := net.log.State()
	if _, standing := revoked.standingSidecar(laptop.sidecarId, revoked.TimeMs()); standing {
		t.Fatal("the laptop stands after its revocation")
	}

	facts, err = testCarryCheck(t, testCarryHolding(revoked, settingsSha256, rulesSha256), head)
	if err != nil {
		t.Fatalf("a reader holding both records: %v", err)
	}
	if !proto.Equal(facts.Settings, testCarrySettings()) || !proto.Equal(facts.VersioningRules, testCarryRules()) {
		t.Fatalf("a reader holding both records found %v and %v", facts.Settings, facts.VersioningRules)
	}
	if !bytes.Equal(facts.settingsRecordSha256, settingsSha256) || !bytes.Equal(facts.versioningRulesRecordSha256, rulesSha256) {
		t.Fatal("a reader holding both records does not hold their hashes on")
	}

	_, err = testCarryCheck(t, revoked, head)
	testCarryRefused(t, "a reader holding neither record", err, ConfigHeadServiceSettingsPath, "is not standing")
	_, err = testCarryCheck(t, testCarryHolding(revoked, settingsSha256, nil), head)
	testCarryRefused(t, "a reader holding the settings alone", err, ConfigHeadVersioningRulesPath, "is not standing")
	_, err = testCarryCheck(t, testCarryHolding(revoked, nil, rulesSha256), head)
	testCarryRefused(t, "a reader holding the rules alone", err, ConfigHeadServiceSettingsPath, "is not standing")
	_, err = testCarryCheck(t, testCarryHolding(revoked, rulesSha256, settingsSha256), head)
	testCarryRefused(t, "a reader holding each hash at the other's path", err, ConfigHeadServiceSettingsPath, "is not standing")
}

// Only the record the previous base's head held byte for byte is kept unjudged: a new record the revoked laptop signs,
// the same settings signed by another revoked device and the record put back after a head removed it, where the
// previous base's head holds none, are each judged and fork; a new record an Owner's standing device signs is judged,
// taken and held from then on.
func TestARecordThePreviousHeadDidNotHoldIsJudged(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	laptop, tablet := net.device("owner laptop", net.ownerMemberId), net.device("owner tablet", net.ownerMemberId)
	net.admitDevice(net.owner, laptop, 0)
	net.admitDevice(net.owner, tablet, 0)
	settingsBytes := net.sign(laptop, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	for _, device := range []testConfigDevice{laptop, tablet} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(device, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	}
	revoked := net.log.State()
	holding := testCarryHolding(revoked, testCarrySha256(settingsBytes), nil)

	if _, err := testCarryCheck(t, holding, testCarryHead(t, net, settingsBytes, nil)); err != nil {
		t.Fatalf("the record the previous base's head held: %v", err)
	}
	newer := net.sign(laptop, bridge.SignedType_SIGNED_SERVICE_SETTINGS, &protocol.ServiceSettings{MailStrict: true})
	_, err := testCarryCheck(t, holding, testCarryHead(t, net, newer, nil))
	testCarryRefused(t, "a new record the revoked laptop signs", err, ConfigHeadServiceSettingsPath, "is not standing")
	other := net.sign(tablet, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	_, err = testCarryCheck(t, holding, testCarryHead(t, net, other, nil))
	testCarryRefused(t, "the same settings signed by another revoked device", err, ConfigHeadServiceSettingsPath, "is not standing")
	_, err = testCarryCheck(t, revoked, testCarryHead(t, net, settingsBytes, nil))
	testCarryRefused(t, "the record put back after a head removed it", err, ConfigHeadServiceSettingsPath, "is not standing")

	resigned := net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	facts, err := testCarryCheck(t, holding, testCarryHead(t, net, resigned, nil))
	if err != nil {
		t.Fatalf("a new record an Owner's standing device signs: %v", err)
	}
	if !bytes.Equal(facts.settingsRecordSha256, testCarrySha256(resigned)) {
		t.Fatal("the new record's base holds another hash")
	}
}

// The role half alike: Admin b's laptop signs the ServiceSettings, and the owner and Admin c then set an AdminSet
// without b. b's laptop still stands, but its member holds no role that signs the record: a reader whose previous
// base's head held it keeps it, and one whose head did not forks.
func TestACarriedRecordStandsOnceItsSignersRoleGoes(t *testing.T) {
	team := newTestConfigTeam(t)
	registerTestConfigAclCompiler(t)
	settingsBytes := team.sign(team.adminB, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	head := testCarryHead(t, team.testConfigNet, settingsBytes, nil)
	if _, err := testCarryCheck(t, team.log.State(), head); err != nil {
		t.Fatalf("the Admin's record at its first base: %v", err)
	}

	demotion := &protocol.AdminSet{
		Header: team.header(),
		Owners: [][]byte{team.ownerMemberId.Bytes()},
		Admins: [][]byte{team.adminC.memberId.Bytes()},
	}
	_, setId := team.propose(team.owner, bridge.SignedType_SIGNED_ADMIN_SET, demotion)
	if verdict := team.cosign(team.adminC, setId); !verdict.Accepted() {
		t.Fatalf("the demotion: %v", verdict.Refusal)
	}
	demoted := team.log.State()
	if role := demoted.Member(team.adminB.memberId).GetRole(); role == bridge.MemberRole_MEMBER_ROLE_ADMIN || role == bridge.MemberRole_MEMBER_ROLE_OWNER {
		t.Fatalf("b's role after the demotion: %v", role)
	}
	if _, standing := demoted.standingSidecar(team.adminB.sidecarId, demoted.TimeMs()); !standing {
		t.Fatal("the demotion revoked b's laptop")
	}

	if _, err := testCarryCheck(t, testCarryHolding(demoted, testCarrySha256(settingsBytes), nil), head); err != nil {
		t.Fatalf("a reader holding the demoted Admin's record: %v", err)
	}
	_, err := testCarryCheck(t, demoted, head)
	testCarryRefused(t, "a reader holding none", err, ConfigHeadServiceSettingsPath, "holds no role that signs it")
}

// A reader that starts at a base judges no record's signer, a revoked one's included, and takes both records with their
// hashes, which its next base's check reads as held; a head holding neither gives none.
func TestTheAnchorTakesBothRecordsWithTheirHashes(t *testing.T) {
	net := newTestConfigNet(t)
	laptop := net.device("owner laptop", net.ownerMemberId)
	net.admitDevice(net.owner, laptop, 0)
	settingsBytes := net.sign(laptop, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	rulesBytes := net.sign(laptop, bridge.SignedType_SIGNED_VERSIONING_RULES, testCarryRules())
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))

	anchor := func(head *ConfigHead) *ConfigHeadFacts {
		t.Helper()
		facts, err := CheckConfigBase(head, &ConfigHeadCheck{
			Header:       &bridge.ProjectionHeader{FoldedThrough: 0},
			GenesisChain: bridge.GenesisChain(net.signedGenesis),
		}, nil)
		if err != nil {
			t.Fatalf("the anchor: %v", err)
		}
		return facts
	}
	facts := anchor(testCarryHead(t, net, settingsBytes, rulesBytes))
	if !proto.Equal(facts.Settings, testCarrySettings()) || !proto.Equal(facts.VersioningRules, testCarryRules()) {
		t.Fatalf("the anchor took %v and %v", facts.Settings, facts.VersioningRules)
	}
	if !bytes.Equal(facts.settingsRecordSha256, testCarrySha256(settingsBytes)) || !bytes.Equal(facts.versioningRulesRecordSha256, testCarrySha256(rulesBytes)) {
		t.Fatalf("the anchor took the hashes %x and %x", facts.settingsRecordSha256, facts.versioningRulesRecordSha256)
	}
	if facts := anchor(testConfigHead(t, net)); facts.settingsRecordSha256 != nil || facts.versioningRulesRecordSha256 != nil {
		t.Fatal("a head holding neither record gave a hash")
	}
}

// A desktop that verified the heads of its bases, each holding a ServiceSettings the genesis device signed, keeps each
// head's record hash in authlog/. Its restart anchors at its newest kept base with the head it verified there, while
// every head read would answer another network's head, and its state holds the hash the follow that verified the head
// held. So once the owner's laptop revokes the genesis device and folds, the restarted desktop takes the base whose
// head carries the record unchanged, its signer not judged again.
func TestTheClientKeepsItsVerifiedHeadsRecordHashesAcrossARestart(t *testing.T) {
	world := newTestConfigClientWorld(t)
	net := world.net
	settings := testCarrySettings()
	want := testCarrySha256(net.sign(net.owner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, settings))
	laptop := net.device("owner laptop", net.ownerMemberId)
	net.admitDevice(net.owner, laptop, 0)
	for _, c := range []struct {
		member        string
		configVersion uint64
	}{{member: "member a", configVersion: 2}, {member: "member b", configVersion: 3}} {
		net.admitMember(net.owner, testConfigId(c.member), bridge.MemberRole_MEMBER_ROLE_MEMBER)
		net.source.settings[[sha256.Size]byte(testConfigHeadSha256(c.configVersion))] = settings
		net.fold(net.owner, net.n, c.configVersion)
	}
	world.publish()

	desktop := DefaultConfigClientSettings()
	desktop.RetainFullTail = true
	client := world.client(desktop)
	state := world.caughtUp(client)
	if !bytes.Equal(state.headSettingsRecordSha256, want) || state.headVersioningRulesRecordSha256 != nil {
		t.Fatalf("the desktop holds the hashes %x and %x", state.headSettingsRecordSha256, state.headVersioningRulesRecordSha256)
	}
	client.Close()
	document := world.store.document(t)
	kept := false
	for _, record := range document.VerifiedHeads {
		if bytes.Equal(record.ConfigHeadSha256, state.Base().GetConfigHeadSha256()) {
			kept = record.RecordsKnown && bytes.Equal(record.SettingsRecordSha256, want) && len(record.VersioningRulesRecordSha256) == 0
		}
	}
	if !kept {
		t.Fatal("authlog/ keeps the newest base's head without its record hash")
	}
	first := &bridge.AuthEntry{}
	if err := proto.Unmarshal(document.Entries[0], first); err != nil || first.GetN() <= 1 {
		t.Fatalf("the kept entries start at %d: %v", first.GetN(), err)
	}

	world.heads.stateLock.Lock()
	world.heads.forged = testConfigHead(t, newTestConfigNetOf(t, "another network"))
	world.heads.stateLock.Unlock()
	restarted := world.client(desktop)
	restored := restarted.State()
	if restored == nil || !proto.Equal(restored.Pin(), state.Pin()) {
		t.Fatalf("the restart stands at %v, not %v", restarted.Pin(), state.Pin())
	}
	if !bytes.Equal(restored.headSettingsRecordSha256, want) || restored.headVersioningRulesRecordSha256 != nil {
		t.Fatalf("the restart holds the hashes %x and %x", restored.headSettingsRecordSha256, restored.headVersioningRulesRecordSha256)
	}
	world.heads.stateLock.Lock()
	world.heads.forged = nil
	world.heads.stateLock.Unlock()

	net.mustPost(laptop, bridge.SignedType_SIGNED_SIDECAR_REVOKE, net.revocation(net.owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST))
	net.source.settings[[sha256.Size]byte(testConfigHeadSha256(4))] = settings
	net.fold(laptop, net.n, 4)
	world.publish()
	taken := world.caughtUp(restarted)
	if taken.Base().GetConfigVersion() != 4 || !bytes.Equal(taken.headSettingsRecordSha256, want) {
		t.Fatalf("the restarted desktop stands on head %d holding %x", taken.Base().GetConfigVersion(), taken.headSettingsRecordSha256)
	}
	if held, known := taken.HeadSettings(); !known || !proto.Equal(held, settings) {
		t.Fatalf("the restarted desktop holds the settings %v (known %t)", held, known)
	}
	if restarted.Fork() != nil {
		t.Fatalf("the restarted desktop forked: %v", restarted.Fork())
	}
}

// What authlog/ kept of each verified head: one this build kept stands for its anchor with both records' hashes; a
// record of no field set, which encodes as no bytes, comes back as held, its hash saying so; a head holding neither
// comes back holding neither; and a head kept before the hashes were, or with a hash that is no SHA-256, does not
// stand for an anchor, so its head is read again.
func TestARestartReadsAgainAHeadVerifiedWithoutItsRecordHashes(t *testing.T) {
	net := newTestConfigNet(t)
	store := newTestConfigClientStore()
	settingsBytes := testConfigMarshal(t, testCarrySettings())
	rulesBytes := testConfigMarshal(t, testCarryRules())
	settingsSha256, rulesSha256 := testCarrySha256([]byte("a Signed ServiceSettings")), testCarrySha256([]byte("a Signed VersioningRules"))
	headSha256 := func(label string) []byte {
		return testCarrySha256([]byte("config head " + label))
	}
	document := &configClientDocument{
		Version:       configClientDocumentVersion,
		NetworkId:     net.networkId,
		SignedGenesis: net.signedGenesis,
		VerifiedHeads: []*configClientHeadRecord{
			{ConfigHeadSha256: headSha256("kept"), ConfigVersion: 2, Settings: settingsBytes, VersioningRules: rulesBytes, SettingsRecordSha256: settingsSha256, VersioningRulesRecordSha256: rulesSha256, RecordsKnown: true},
			{ConfigHeadSha256: headSha256("empty"), ConfigVersion: 3, SettingsRecordSha256: settingsSha256, RecordsKnown: true},
			{ConfigHeadSha256: headSha256("none"), ConfigVersion: 4, RecordsKnown: true},
			{ConfigHeadSha256: headSha256("older"), ConfigVersion: 5, Settings: settingsBytes},
			{ConfigHeadSha256: headSha256("short"), ConfigVersion: 6, Settings: settingsBytes, SettingsRecordSha256: settingsSha256[:16], RecordsKnown: true},
		},
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	store.files[configClientFileName] = data
	client := &ConfigClient{
		args:          &ConfigClientArgs{NetworkId: net.networkId, GenesisChain: bridge.GenesisChain(net.signedGenesis), Store: store},
		verifiedHeads: map[[sha256.Size]byte]*configVerifiedHead{},
	}
	if err := client.restoreFromStore(); err != nil {
		t.Fatal(err)
	}

	kept := client.verifiedHead(headSha256("kept"), 2)
	if kept == nil || !proto.Equal(kept.settings, testCarrySettings()) || !proto.Equal(kept.versioningRules, testCarryRules()) ||
		!bytes.Equal(kept.settingsRecordSha256, settingsSha256) || !bytes.Equal(kept.versioningRulesRecordSha256, rulesSha256) {
		t.Fatalf("the head kept with its hashes came back as %+v", kept)
	}
	empty := client.verifiedHead(headSha256("empty"), 3)
	if empty == nil || empty.settings == nil || !proto.Equal(empty.settings, &protocol.ServiceSettings{}) ||
		!bytes.Equal(empty.settingsRecordSha256, settingsSha256) || empty.versioningRules != nil || empty.versioningRulesRecordSha256 != nil {
		t.Fatalf("the head holding a record of no field set came back as %+v", empty)
	}
	none := client.verifiedHead(headSha256("none"), 4)
	if none == nil || none.settings != nil || none.versioningRules != nil || none.settingsRecordSha256 != nil || none.versioningRulesRecordSha256 != nil {
		t.Fatalf("the head holding neither record came back as %+v", none)
	}
	if older := client.verifiedHead(headSha256("older"), 5); older != nil {
		t.Error("a head kept before its record hashes stands for an anchor")
	}
	if short := client.verifiedHead(headSha256("short"), 6); short != nil {
		t.Error("a head kept with a short hash stands for an anchor")
	}
}
