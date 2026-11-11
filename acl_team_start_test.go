//go:build !sidecar_http && !ios_extension

// Team's documents (ACL-M6-01), pure (T1): the starting document compiles to its golden and passes its own tests under
// Team's limits; two approvers validate on Team alone and are enforced at GrantActivate; scope hosts validate only for a
// scope the network holds and *.<scope> covers that scope alone, a member scope's hosts its member's consented devices
// alone; SCIM's group:<name>@<domain> validates with no groups entry; and FS-85's worker case at the rule level, a
// harness decision refused and the destination owner's device decision passing.

package sidecar

import (
	"encoding/hex"
	"errors"
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §20.4's Team column, as GET /sidecar/limits would give it.
func aclTestTeamLimits() *AclLimits {
	return &AclLimits{Rules: 5000, Groups: 500, Requests: 500, ApproversTwo: true, NetworkShares: 500, StandingPublishes: true}
}

// A team: dana with an invited first device and a second an admin admitted, amir with a device, an Owner, and tag
// recurd's row.
type aclTeamWorld struct {
	world       *aclCompileWorld
	owner       Id
	ownerDevice Id
	dana        Id
	danaFirst   Id
	danaSecond  Id
	amir        Id
	amirDevice  Id
}

func newAclTeamWorld(t testing.TB, policy string) *aclTeamWorld {
	world := newAclCompileWorld("team")
	self := &aclTeamWorld{world: world}
	self.owner = world.member("owner@team.example", bridge.MemberRole_MEMBER_ROLE_OWNER)
	self.ownerDevice = world.device("owner device", self.owner)
	self.dana = world.member("dana@team.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.danaFirst = world.device("dana first", self.dana)
	self.danaSecond = world.device("dana second", self.dana)
	self.amir = world.member("amir@team.example", bridge.MemberRole_MEMBER_ROLE_MEMBER)
	self.amirDevice = world.device("amir device", self.amir)
	for _, row := range world.sidecars {
		if Id(row.SidecarId) == self.danaFirst {
			// dana's invited first device, admitted by the Owner's device outside every cascade
			row.Capabilities = uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_INVITED)
			row.AdmissionSigners = [][]byte{self.ownerDevice.Bytes()}
		}
	}
	world.tag("recurd")
	world.setPolicy(t, policy)
	return self
}

// The starting document compiles to its golden, with has_document, validates on Team and passes its own tests.
func TestAclTeamStartCompilesToItsGoldenAndPassesItsTests(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	rows := team.world.compile(t)
	if !rows.GetHasDocument() || len(rows.GetRules()) != 2 || len(rows.GetRequests()) != 1 {
		t.Fatalf("has_document %v, %d rules, %d requests", rows.GetHasDocument(), len(rows.GetRules()), len(rows.GetRequests()))
	}
	golden, err := testAclVectorFiles.ReadFile("testdata/acl/vectors/team_start_rows.hex")
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(aclEncodeRows(t, rows)); got != strings.TrimSpace(string(golden)) {
		t.Fatalf("the starting document compiles to other rows:\n%s", got)
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("validation on Team: %v", err)
	}
	report, err := AclPolicyTestRun(&AclPolicyTestInput{Compile: team.world.input(), View: team.world.view(), Now: aclTestNow})
	if err != nil || !report.Passed() || report.TestCount != 2 || report.CheckCount != 6 {
		t.Fatalf("its tests: %+v, %v", report, err)
	}
	request := rows.GetRequests()[0]
	dstOwner := AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_DST_OWNER).Bytes()
	if !slices.ContainsFunc(request.GetApproverAtoms(), func(atom []byte) bool { return string(atom) == string(dstOwner) }) || request.GetApprovers() != 1 ||
		!slices.Equal(request.GetEvidence(), []uint32{uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE), uint32(protocol.ApprovalChannel_APPROVAL_CHANNEL_PRESENCE)}) {
		t.Errorf("the directory rule %+v", request)
	}
}

// The starting document with the directory rule given two approvers, the destination's owner and an admin.
const aclTestTeamTwoApprovers = `{
  "tagOwners": { "tag:recurd": ["autogroup:member"] },
  "grants": [ { "src": ["autogroup:member", "autogroup:untagged"], "dst": ["autogroup:self"], "allow": ["dial", "route"] } ],
  "requests": [
    { "src": ["autogroup:member", "autogroup:tagged"],
      "dst": ["autogroup:member", "autogroup:tagged", "sock:*"], "allow": ["dial"],
      "approver": ["autogroup:dst-owner", "autogroup:admin"], "approvers": 2,
      "evidence": ["device", "presence"], "maxExpiry": "30d" },
  ],
}`

// The decisions a GrantActivate of requester's dial to destination under the document's first requests rule carries.
func (self *aclTeamWorld) grantActivate(t *testing.T, requester Id, destination Id, approvals map[Id]protocol.ApprovalChannel) *AclStatement {
	t.Helper()
	grant := newAclTestGrant(t, self.world.documentRuleId(t, "request", 0).Bytes(), requester, []string{aclTestDst(destination)}, []string{"dial"}, 0)
	for _, approver := range slices.SortedFunc(maps.Keys(approvals), Id.Cmp) {
		grant.approve(t, approver, approvals[approver], aclTestDecisionNotAfter)
	}
	return &AclStatement{
		Type: bridge.SignedType_SIGNED_GRANT_ACTIVATE, Body: grant.activate(),
		Signers: []ConfigSigner{{Kind: ConfigSignerSidecar, SidecarId: requester}}, N: 100, TimeMs: aclTestNow.UnixMilli(),
	}
}

// Two approvers validate only on Team, and on Team one approver's decision activates nothing while two do.
func TestAclTeamTwoApproversOnTeamAlone(t *testing.T) {
	team := newAclTeamWorld(t, aclTestTeamTwoApprovers)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("on Team: %v", err)
	}
	pro := aclTestTeamLimits()
	pro.ApproversTwo = false
	validation := &AclValidationError{}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: pro}); !errors.As(err, &validation) ||
		len(validation.Refusals) != 1 || !strings.Contains(validation.Refusals[0].String(), "approvers") {
		t.Fatalf("below Team: %v", err)
	}
	state := team.world.state(t)
	device := protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE
	spend := &aclTestSpendCheck{refused: map[Id]bool{}}
	if _, err := state.CheckStatement(team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: device}), spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("one of two approvers: %v", err)
	}
	if _, err := state.CheckStatement(team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: device, team.owner: device}), spend); err != nil {
		t.Errorf("the owner of the destination and an admin: %v", err)
	}
}

// FS-85's worker case at the rule level: under the starting document's directory rule, the destination owner's harness
// decision activates nothing and its device decision does, meeting §8.6's admin clause (owner decision 180).
func TestAclTeamDirectoryRuleRefusesAHarnessDecision(t *testing.T) {
	team := newAclTeamWorld(t, string(AclTeamStartDocument()))
	state := team.world.state(t)
	spend := &aclTestSpendCheck{refused: map[Id]bool{}}
	harness := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: protocol.ApprovalChannel_APPROVAL_CHANNEL_HARNESS})
	if _, err := state.CheckStatement(harness, spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("a harness decision: %v", err)
	}
	device := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.amir: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE})
	if _, err := state.CheckStatement(device, spend); err != nil {
		t.Errorf("the owner's device decision: %v", err)
	}
	other := team.grantActivate(t, team.danaFirst, team.amirDevice, map[Id]protocol.ApprovalChannel{team.dana: protocol.ApprovalChannel_APPROVAL_CHANNEL_DEVICE})
	if _, err := state.CheckStatement(other, spend); !errors.Is(err, ErrConfigAuthority) {
		t.Errorf("the requester's own decision: %v", err)
	}
}

// A document publishing in the eng scope and dana's member scope.
const aclTestTeamScopes = `{
  "grants": [
    { "src": ["autogroup:member"], "dst": ["dns:*.eng", "dns:*.dana"], "allow": ["publish"] },
    { "src": ["autogroup:member"], "dst": ["sock:tls/443/*.eng", "sock:smtp/25/mx.eng", "sock:tls/443/*.dana"], "allow": ["listen"] },
  ],
}`

// Scope hosts: validation takes a scope the network's Team scopes hold and no other, nor any with no scopes known;
// *.<scope> covers its own scope's hosts and no other's; and a member scope's host takes its member's consented devices
// alone.
func TestAclTeamScopeHosts(t *testing.T) {
	team := newAclTeamWorld(t, aclTestTeamScopes)
	scopes := map[string]AclScope{"eng": {Label: "eng"}, "dana": {Label: "dana", MemberId: team.dana}}
	resolve := func(label string) (AclScope, bool) {
		scope, found := scopes[label]
		return scope, found
	}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits(), ResolveScope: resolve}); err != nil {
		t.Fatalf("known scopes: %v", err)
	}
	validation := &AclValidationError{}
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); !errors.As(err, &validation) || len(validation.Refusals) != 5 {
		t.Errorf("no scopes known: %v", err)
	}
	unknown := newAclTeamWorld(t, `{ "grants": [ { "src": ["autogroup:member"], "dst": ["dns:app.ops", "dns:app.*"], "allow": ["publish"] } ] }`)
	if err := ValidateAclPolicy(&AclValidateInput{Compile: unknown.world.input(), Limits: aclTestTeamLimits(), ResolveScope: resolve}); !errors.As(err, &validation) || len(validation.Refusals) != 2 {
		t.Errorf("an unknown scope and a glob scope: %v", err)
	}

	state := team.world.state(t)
	member := AclSidecarSubject(team.amirDevice)
	for _, c := range []struct {
		host string
		want bool
	}{
		{host: "app.eng", want: true}, {host: "app.ops", want: false}, {host: "eng", want: false}, {host: "app", want: false},
	} {
		if got := state.MayPublish(member, c.host, aclTestNow).Allowed; got != c.want {
			t.Errorf("publish %s: %v", c.host, got)
		}
	}
	for _, c := range []struct {
		name string
		want bool
	}{
		{name: "tls/443/app.eng", want: true}, {name: "tls/443/app.ops", want: false}, {name: "smtp/25/mx.eng", want: true}, {name: "smtp/25/mx.ops", want: false},
	} {
		if got := state.MayListen(member, AclSocketName{PublicName: c.name}, aclTestNow).Allowed; got != c.want {
			t.Errorf("listen %s: %v", c.name, got)
		}
	}
	danaScope := scopes["dana"]
	if decision := state.MayPublishInScope(AclSidecarSubject(team.danaFirst), "app.dana", danaScope, aclTestNow); !decision.Allowed {
		t.Errorf("dana's consented device in her scope: %+v", decision)
	}
	for name, subject := range map[string]Id{"dana's unconsented device": team.danaSecond, "amir's device": team.amirDevice} {
		if decision := state.MayPublishInScope(AclSidecarSubject(subject), "app.dana", danaScope, aclTestNow); decision.Allowed || decision.Reason != AclReasonUnconsented {
			t.Errorf("%s in dana's scope: %+v", name, decision)
		}
	}
	if decision := state.MayListenInScope(AclSidecarSubject(team.amirDevice), AclSocketName{PublicName: "tls/443/app.dana"}, danaScope, aclTestNow); decision.Allowed {
		t.Errorf("amir listening in dana's scope: %+v", decision)
	}
	if decision := state.MayPublishInScope(member, "app.eng", scopes["eng"], aclTestNow); !decision.Allowed {
		t.Errorf("a tag scope's host: %+v", decision)
	}
}

// SCIM's group:<name>@<domain> validates with no groups entry, as SCIM keeps its members (§7.6), and compiles to its
// atom.
func TestAclTeamScimGroup(t *testing.T) {
	team := newAclTeamWorld(t, `{ "grants": [ { "src": ["group:eng@corp.example"], "dst": ["autogroup:self"], "allow": ["dial"] } ] }`)
	atomId := team.world.group("eng@corp.example")
	if err := ValidateAclPolicy(&AclValidateInput{Compile: team.world.input(), Limits: aclTestTeamLimits()}); err != nil {
		t.Fatalf("a SCIM group: %v", err)
	}
	rows := team.world.compile(t)
	if !slices.ContainsFunc(rows.GetAtoms(), func(atom *protocol.AclAtom) bool {
		return Id(atom.GetAtom()) == atomId && len(atom.GetMemberIds()) == 0
	}) {
		t.Errorf("no atom for the SCIM group")
	}
}
