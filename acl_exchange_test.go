//go:build !ios_extension

// The exchange's repo scope table on TEAM's log (FS-19's scope rows, §7.8): each scope judged alone against the newest
// verified state, a read_only sidecar held to r and the receipt deposit, an ephemeral one to the config's r at both
// audiences, gkm's config rw for member devices, an owner-bound reader's receipt deposit, a forward_only client held to
// the config's r while its forwarding Delegation lives, and a 65th repo scope refusing the request. Pure, on every leg.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network for the exchange: a member's phone, read_only and ephemeral devices, a general repo members write, and an
// Owner's vault shared to the phone.
type aclExchangeNet struct {
	*testConfigNet
	member    Id
	phone     testConfigDevice
	readOnly  testConfigDevice
	ephemeral testConfigDevice
	configId  Id
	notesId   Id
	vaultId   Id
}

func newAclExchangeNet(t *testing.T) *aclExchangeNet {
	net := newTestConfigNet(t)
	self := &aclExchangeNet{testConfigNet: net, configId: testConfigId("config repo"), notesId: testConfigId("exchange notes"), vaultId: testConfigId("exchange vault")}
	self.member, self.phone = net.consentedMember("exchange")
	self.readOnly = net.device("exchange read only", self.member)
	net.admitDevice(net.owner, self.readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	self.ephemeral = net.device("exchange ephemeral", self.member)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(self.ephemeral, nil, true, net.timeMs+24*60*60*1000, 0))
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.HasDocument = true
		rows.Rules = append(rows.Rules, &protocol.AclRule{
			RuleId:   testConfigId("exchange member write").Bytes(),
			SrcAtoms: [][]byte{AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER).Bytes()},
			Targets:  []*protocol.AclTarget{{RepoId: self.notesId.Bytes()}},
			Actions:  []uint32{uint32(protocol.AclAction_ACL_ACTION_WRITE)},
		})
		rows.Repos = append(rows.Repos,
			&protocol.AclRepo{RepoId: self.configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG},
			&protocol.AclRepo{RepoId: self.notesId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
			&protocol.AclRepo{
				RepoId: self.vaultId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT, OwnerMemberId: net.ownerMemberId.Bytes(),
				ConsentedSidecarIds: [][]byte{net.owner.sidecarId.Bytes()},
				Shares:              []*protocol.AclRepoShareRow{{Subject: self.phone.sidecarId.Bytes(), Signer: net.owner.sidecarId.Bytes(), At: 1}},
			},
		)
	})
	return self
}

// A scope as the daemon asks it.
func aclExchangeScope(repoId Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// The exchange's answer for a device, failing the test on an error.
func (self *aclExchangeNet) exchange(t *testing.T, device testConfigDevice, audience AclTokenAudience, scopes ...string) *AclExchangeGrant {
	t.Helper()
	grant, err := AclExchangeScopes(self.log.State(), &AclExchangeRequest{
		SidecarId: device.sidecarId, Audience: audience, Scopes: scopes, Now: time.UnixMilli(self.timeMs),
	})
	if err != nil {
		t.Fatal(err)
	}
	return grant
}

// Whether the grant gave exactly granted and refused the rest, in the request's order.
func aclExchangeCheck(t *testing.T, name string, grant *AclExchangeGrant, granted []string, refused []string) {
	t.Helper()
	if !slices.Equal(grant.Scopes, granted) || !slices.Equal(grant.Refused, refused) {
		t.Errorf("%s: granted %v refused %v, want %v and %v", name, grant.Scopes, grant.Refused, granted, refused)
	}
}

// A member device writes what members write, reads the config, and commits its group only at gkm.
func TestAclExchangeScopesForAMemberDevice(t *testing.T) {
	net := newAclExchangeNet(t)
	notesRw, notesR, notesAdmin := aclExchangeScope(net.notesId, "rw"), aclExchangeScope(net.notesId, "r"), aclExchangeScope(net.notesId, "admin")
	configR, configRw := aclExchangeScope(net.configId, "r"), aclExchangeScope(net.configId, "rw")
	grant := net.exchange(t, net.phone, AclTokenAudienceEvs, notesRw, notesR, notesAdmin, configR, configRw)
	aclExchangeCheck(t, "evs", grant, []string{notesRw, notesR, configR}, []string{notesAdmin, configRw})
	if grant.ProjVersion != net.log.State().Pin().GetVersion() {
		t.Errorf("proj_v %d", grant.ProjVersion)
	}
	aclExchangeCheck(t, "gkm", net.exchange(t, net.phone, AclTokenAudienceGkm, configRw), []string{configRw}, []string{})
	aclExchangeCheck(t, "a config writer at evs", net.exchange(t, net.owner, AclTokenAudienceEvs, configRw), []string{configRw}, []string{})
}

// FS-19's scope rows: a read_only sidecar gets only r and the receipt deposit, an ephemeral one no config rw at either
// audience, and an owner-bound repo's reader that does not write the receipt deposit.
func TestAclExchangeScopesFs19Rows(t *testing.T) {
	net := newAclExchangeNet(t)
	notesR, notesRw, notesDeposit := aclExchangeScope(net.notesId, "r"), aclExchangeScope(net.notesId, "rw"), aclExchangeScope(net.notesId, "deposit")
	aclExchangeCheck(t, "read_only", net.exchange(t, net.readOnly, AclTokenAudienceEvs, notesR, notesRw, notesDeposit),
		[]string{notesR, notesDeposit}, []string{notesRw})
	aclExchangeCheck(t, "read_only at gkm", net.exchange(t, net.readOnly, AclTokenAudienceGkm, aclExchangeScope(net.configId, "rw")),
		[]string{}, []string{aclExchangeScope(net.configId, "rw")})

	configR, configRw := aclExchangeScope(net.configId, "r"), aclExchangeScope(net.configId, "rw")
	for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
		aclExchangeCheck(t, fmt.Sprintf("ephemeral at %d", audience), net.exchange(t, net.ephemeral, audience, configR, configRw, notesRw),
			[]string{configR}, []string{configRw, notesRw})
	}

	vaultR, vaultDeposit, vaultRw := aclExchangeScope(net.vaultId, "r"), aclExchangeScope(net.vaultId, "deposit"), aclExchangeScope(net.vaultId, "rw")
	aclExchangeCheck(t, "a share's reader", net.exchange(t, net.phone, AclTokenAudienceEvs, vaultR, vaultDeposit, vaultRw),
		[]string{vaultR, vaultDeposit}, []string{vaultRw})
	aclExchangeCheck(t, "the owner's consented device", net.exchange(t, net.owner, AclTokenAudienceEvs, vaultRw),
		[]string{vaultRw}, []string{})
}

// What is not this table's is refused: another kind of scope, a malformed repo scope, another audience's token, a
// client bound to no sidecar; and 65 repo scopes refuse the request whole.
func TestAclExchangeScopesRefusals(t *testing.T) {
	net := newAclExchangeNet(t)
	notesR := aclExchangeScope(net.notesId, "r")
	recovery := "recovery:" + net.member.String()
	aclExchangeCheck(t, "other scopes", net.exchange(t, net.phone, AclTokenAudienceEvs, recovery, "repo:not-an-id:r", aclExchangeScope(net.notesId, "own"), notesR),
		[]string{notesR}, []string{recovery, "repo:not-an-id:r", aclExchangeScope(net.notesId, "own")})
	aclExchangeCheck(t, "another audience", net.exchange(t, net.phone, 0, notesR), []string{}, []string{notesR})
	grant, err := AclExchangeScopes(net.log.State(), &AclExchangeRequest{Audience: AclTokenAudienceEvs, Scopes: []string{notesR}, Now: time.UnixMilli(net.timeMs)})
	if err != nil {
		t.Fatal(err)
	}
	aclExchangeCheck(t, "no sidecar", grant, []string{}, []string{notesR})

	scopes := []string{}
	for i := range AclExchangeMaxRepoScopeCount + 1 {
		scopes = append(scopes, aclExchangeScope(testConfigId(fmt.Sprintf("repo %d", i)), "r"))
	}
	if _, err := AclExchangeScopes(net.log.State(), &AclExchangeRequest{SidecarId: net.phone.sidecarId, Audience: AclTokenAudienceEvs, Scopes: scopes}); !errors.Is(err, ErrAclExchangeScope) {
		t.Errorf("65 repo scopes: %v", err)
	}
	if _, err := AclExchangeScopes(net.log.State(), &AclExchangeRequest{SidecarId: net.phone.sidecarId, Audience: AclTokenAudienceEvs, Scopes: scopes[:AclExchangeMaxRepoScopeCount]}); err != nil {
		t.Errorf("64 repo scopes: %v", err)
	}
	if _, err := AclExchangeScopes(nil, &AclExchangeRequest{}); !errors.Is(err, ErrAclExchangeScope) {
		t.Errorf("no state: %v", err)
	}
}

// A forward_only client gets the config's r alone, and only while its sidecar's forwarding Delegation lives (owner
// decision 197), whatever the sidecar itself reads.
func TestAclExchangeScopesForAForwardOnlyClient(t *testing.T) {
	net := newAclExchangeNet(t)
	configR, configRw, notesR := aclExchangeScope(net.configId, "r"), aclExchangeScope(net.configId, "rw"), aclExchangeScope(net.notesId, "r")
	request := func() *AclExchangeRequest {
		return &AclExchangeRequest{SidecarId: net.phone.sidecarId, Audience: AclTokenAudienceEvs, Scopes: []string{configR, configRw, notesR},
			ForwardOnly: true, Now: time.UnixMilli(net.timeMs)}
	}
	grant, err := AclExchangeScopes(net.log.State(), request())
	if err != nil {
		t.Fatal(err)
	}
	aclExchangeCheck(t, "with no forwarding Delegation", grant, []string{}, []string{configR, configRw, notesR})
	net.forward(net.phone, "exchange")
	if grant, err = AclExchangeScopes(net.log.State(), request()); err != nil {
		t.Fatal(err)
	}
	aclExchangeCheck(t, "while it lives", grant, []string{configR}, []string{configRw, notesR})
}
