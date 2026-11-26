//go:build !ios_extension

// The carried records' reasons (config_records_carried.go; D-TEAM-26; owner decision 699; QD-1207) that the revoked,
// role and parked tests of config_records_carried_test.go do not meet. A reader that starts at a base takes the head's
// ServiceSettings and VersioningRules at its anchor with their hashes and judges no signer (checkConfigAnchor), so a
// head every warm reader forked at can stand at such a reader holding a record no rule a new record meets would take.
// Each state here holds the records as that anchor took them, through CheckConfigBase itself:
//
//	tagged     a standing tagged sidecar signed it: no row and no role is named
//	unlisted   a sidecar_id no row holds signed it
//	signature  the owner's standing device's sidecar_id names it, signed under another key; or it names no identity key,
//	           a key_id in place of a sidecar_id, and no signer at all is named
//	expired    that tagged sidecar's not_after has passed by the log's time, which the listing names before tagged; and a
//	           record an Owner's ephemeral device signed, which a warm reader took judged while it stood
//
// No reason changes a verdict: each state takes the head as its anchor or its carry rule has it.

package sidecar

import (
	"crypto/ed25519"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// state as a reader that starts at its base holds head: the records the anchor took, with their hashes, unjudged.
func testCarriedAnchored(t *testing.T, net *testConfigNet, state *ConfigState, head *ConfigHead) *ConfigState {
	t.Helper()
	facts, err := CheckConfigBase(head, &ConfigHeadCheck{
		Header:       &bridge.ProjectionHeader{FoldedThrough: 0},
		GenesisChain: bridge.GenesisChain(net.signedGenesis),
	}, nil)
	if err != nil {
		t.Fatalf("the anchor: %v", err)
	}
	anchored := configCopyState(state)
	anchored.headSettings, anchored.headSettingsKnown, anchored.headVersioningRules = facts.Settings, true, facts.VersioningRules
	anchored.headSettingsRecordSha256 = facts.settingsRecordSha256
	anchored.headVersioningRulesRecordSha256 = facts.versioningRulesRecordSha256
	return anchored
}

// Fails unless state lists exactly want for head, field by field as their JSON says them.
func testCarriedReasonsAre(t *testing.T, label string, state *ConfigState, head *ConfigHead, want ...*ConfigCarriedRecord) {
	t.Helper()
	records, err := state.CarriedRecords(head)
	if err != nil {
		t.Fatalf("%s: the listing: %v", label, err)
	}
	if want == nil {
		want = []*ConfigCarriedRecord{}
	}
	got, err := json.Marshal(records)
	if err != nil {
		t.Fatal(err)
	}
	wanted, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(wanted) {
		t.Fatalf("%s lists\n  %s\nwant\n  %s", label, got, wanted)
	}
}

// A tagged CI runner of the owner's tag, its admission ending at notAfter, signs the ServiceSettings a cold reader's
// anchor takes: listed as tagged, with no member and no role, while it stands; once the log's time reaches its
// not_after, as expired at that not_after, the listing's order naming expired before tagged.
func TestCarriedRecordsNameATaggedSignerAndItsExpiry(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	tagId := testConfigId("tag ci")
	net.withTagOwner(tagId, net.ownerMemberId)
	runner := net.device("ci runner", Id{})
	notAfter := net.timeMs + (30 * 24 * time.Hour).Milliseconds()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(runner, []Id{tagId}, false, notAfter, 0))
	if row := net.log.State().SidecarRow(runner.sidecarId); row == nil || len(row.GetTagIds()) != 1 || row.GetNotAfter() != notAfter {
		t.Fatalf("the runner's row: %v", row)
	}
	head := testCarryHead(t, net, net.sign(runner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings()), nil)
	tagged := &ConfigCarriedRecord{Record: ConfigHeadServiceSettingsPath, SignerId: runner.sidecarId, Why: ConfigCarriedTagged}
	testCarriedReasonsAre(t, "a cold reader holding the runner's settings", testCarriedAnchored(t, net, net.log.State(), head), head, tagged)

	// the log's time reaches the runner's not_after at the next entry
	net.timeMs = notAfter - 1000
	net.admitMember(net.owner, testConfigId("a later member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	if state := net.log.State(); state.TimeMs() < notAfter {
		t.Fatalf("the log's time %d is before the runner's not_after %d", state.TimeMs(), notAfter)
	}
	expired := &ConfigCarriedRecord{Record: ConfigHeadServiceSettingsPath, SignerId: runner.sidecarId, Why: ConfigCarriedExpired, NotAfterMs: notAfter}
	testCarriedReasonsAre(t, "a cold reader past the runner's not_after", testCarriedAnchored(t, net, net.log.State(), head), head, expired)
}

// VersioningRules a sidecar_id no row holds signed: listed as unlisted, its signer named, no member.
func TestCarriedRecordsNameAnUnlistedSigner(t *testing.T) {
	net := newTestConfigNet(t)
	stranger := net.device("never admitted", net.ownerMemberId)
	head := testCarryHead(t, net, nil, net.sign(stranger, bridge.SignedType_SIGNED_VERSIONING_RULES, testCarryRules()))
	unlisted := &ConfigCarriedRecord{Record: ConfigHeadVersioningRulesPath, SignerId: stranger.sidecarId, Why: ConfigCarriedUnlisted}
	testCarriedReasonsAre(t, "a cold reader holding a stranger's rules", testCarriedAnchored(t, net, net.log.State(), head), head, unlisted)
}

// ServiceSettings whose Signed names the owner's standing device but whose signature another key made, beside
// VersioningRules the owner's device signed: the settings are listed as signature, with the owner's member and role,
// the rules not. Records naming no identity key, a key_id in place of a sidecar_id, are listed as signature with no
// signer at all.
func TestCarriedRecordsNameASignatureThatDoesNotVerify(t *testing.T) {
	net := newTestConfigNet(t)
	forged := testConfigDevice{sidecarId: net.owner.sidecarId, memberId: net.ownerMemberId, key: testConfigDeviceKey("not the owner device's key")}
	head := testCarryHead(t, net,
		net.sign(forged, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings()),
		net.sign(net.owner, bridge.SignedType_SIGNED_VERSIONING_RULES, testCarryRules()))
	ownerMemberId := net.ownerMemberId
	signature := &ConfigCarriedRecord{
		Record: ConfigHeadServiceSettingsPath, SignerId: net.owner.sidecarId, MemberId: &ownerMemberId, Why: ConfigCarriedSignature, Role: "owner",
	}
	testCarriedReasonsAre(t, "a cold reader holding forged settings", testCarriedAnchored(t, net, net.log.State(), head), head, signature)

	// a key_id names a key that is no identity key, so the record names no signer
	keyed := func(signedType bridge.SignedType, body []byte) []byte {
		purpose, _ := ConfigStatementPurpose(signedType)
		return testConfigMarshal(t, &bridge.Signed{
			Body:      body,
			KeyId:     testConfigId("a recovery key").Bytes(),
			Signature: ed25519.Sign(net.owner.key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		})
	}
	nameless := testCarryHead(t, net,
		keyed(bridge.SignedType_SIGNED_SERVICE_SETTINGS, testConfigMarshal(t, testCarrySettings())),
		keyed(bridge.SignedType_SIGNED_VERSIONING_RULES, testConfigMarshal(t, testCarryRules())))
	testCarriedReasonsAre(t, "a cold reader holding records that name no identity key", testCarriedAnchored(t, net, net.log.State(), nameless), nameless,
		&ConfigCarriedRecord{Record: ConfigHeadServiceSettingsPath, Why: ConfigCarriedSignature},
		&ConfigCarriedRecord{Record: ConfigHeadVersioningRulesPath, Why: ConfigCarriedSignature})
}

// An Owner's ephemeral device, its admission ending in an hour, signs the ServiceSettings: a warm reader judges it where
// a head first holds it and takes it, the device standing, and lists nothing. Once the log's time passes its
// not_after, the reader that holds it, judging it no more, lists it as expired at that not_after, with the owner's
// member and role.
func TestCarriedRecordsNameAnEphemeralSignerOnceItExpires(t *testing.T) {
	net := newTestConfigNet(t)
	registerTestConfigAclCompiler(t)
	burner := net.device("owner burner", net.ownerMemberId)
	notAfter := net.timeMs + time.Hour.Milliseconds()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(burner, nil, true, notAfter, 0))
	settingsBytes := net.sign(burner, bridge.SignedType_SIGNED_SERVICE_SETTINGS, testCarrySettings())
	head := testCarryHead(t, net, settingsBytes, nil)
	if _, err := testCarryCheck(t, net.log.State(), head); err != nil {
		t.Fatalf("the burner's settings where a head first holds them: %v", err)
	}
	holding := testCarryHolding(net.log.State(), testCarrySha256(settingsBytes), nil)
	testCarriedReasonsAre(t, "a warm reader while the burner stands", holding, head)

	net.timeMs = notAfter
	net.admitMember(net.owner, testConfigId("a later member"), bridge.MemberRole_MEMBER_ROLE_MEMBER)
	later := net.log.State()
	if _, err := testCarryCheck(t, testCarryHolding(later, testCarrySha256(settingsBytes), nil), head); err != nil {
		t.Fatalf("the next base of a warm reader holding the settings: %v", err)
	}
	ownerMemberId := net.ownerMemberId
	expired := &ConfigCarriedRecord{
		Record: ConfigHeadServiceSettingsPath, SignerId: burner.sidecarId, MemberId: &ownerMemberId, Why: ConfigCarriedExpired,
		NotAfterMs: notAfter, Role: "owner",
	}
	testCarriedReasonsAre(t, "a warm reader past the burner's not_after", testCarryHolding(later, testCarrySha256(settingsBytes), nil), head, expired)
}

// Who files another record of each kind is read from the rule a new record meets: an Owner or Admin for
// ServiceSettings, a Network admin as well for VersioningRules, no one for any other path.
func TestConfigCarriedRecordFilersFollowTheSignerRule(t *testing.T) {
	for _, c := range []struct {
		path  string
		roles []string
	}{
		{path: ConfigHeadServiceSettingsPath, roles: []string{"owner", "admin"}},
		{path: ConfigHeadVersioningRulesPath, roles: []string{"owner", "admin", "network_admin"}},
		{path: ConfigHeadPolicyPath},
		{path: ConfigHeadBridgeBlockPath},
	} {
		if roles := ConfigCarriedRecordFilers(c.path); !slices.Equal(roles, c.roles) {
			t.Errorf("%s is filed by %v, want %v", c.path, roles, c.roles)
		}
	}
	// each role the listing could name, and none other, by the rule itself
	for value := range bridge.MemberRole_name {
		role := bridge.MemberRole(value)
		if role == bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED {
			continue
		}
		name := configCarriedRoleName(role)
		if slices.Contains(ConfigCarriedRecordFilers(ConfigHeadServiceSettingsPath), name) != configAdminSignerRole(role) ||
			slices.Contains(ConfigCarriedRecordFilers(ConfigHeadVersioningRulesPath), name) != configVersioningRulesSignerRole(role) {
			t.Errorf("%s is listed against its rule", name)
		}
	}
}
