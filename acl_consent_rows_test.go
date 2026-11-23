// The owner's consented sidecar_ids of owner-bound repos (acl_access_log.go's consented row, config_coverage.go's
// configAdvanceConsents): a device its owner's consented device admits after the repo's RepoCreate, or one an
// AdmissionConfirm by that device confirms, is listed at the entry that consents it, so it reads and writes its
// owner's vault and mailbox, holds their keys and takes their scopes at the exchange, at every reader, a rows-only gate
// and a reader that starts at a later base included; an unconsented, ephemeral or other member's device is not.

package sidecar

import (
	"bytes"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// signer's RepoCreate of a fresh repo of kind, owner-bound to signer's member where the kind is.
func testConsentRowsRepo(net *testConfigNet, signer testConfigDevice, label string, kind protocol.RepoKind) Id {
	net.t.Helper()
	repoId := testConfigId(label)
	net.mustPost(signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: kind})
	return repoId
}

// Whether the state's row of repoId lists sidecarId among its owner's consented devices.
func testConsentRowsListed(state *ConfigState, repoId Id, sidecarId Id) bool {
	return slices.ContainsFunc(state.Repo(repoId).GetConsentedSidecarIds(), func(listed []byte) bool {
		return bytes.Equal(listed, sidecarId.Bytes())
	})
}

// The rights the state gives sidecarId on repoId for audience at the state's own time.
func testConsentRowsRights(t testing.TB, state *ConfigState, sidecarId Id, repoId Id, audience AclTokenAudience) AclEvsRights {
	t.Helper()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	return acl.EvsAccess(AclSidecarSubject(sidecarId), repoId, audience, time.UnixMilli(state.timeMs)).Rights
}

// The scopes of the asked the exchange's table grants sidecarId at audience on the state.
func testConsentRowsExchange(t testing.TB, state *ConfigState, sidecarId Id, audience AclTokenAudience, scopes ...string) []string {
	t.Helper()
	grant, err := AclExchangeScopes(state, &AclExchangeRequest{SidecarId: sidecarId, Audience: audience, Scopes: scopes, Now: time.UnixMilli(state.timeMs)})
	if err != nil {
		t.Fatal(err)
	}
	return grant.Scopes
}

func testConsentRowsScope(repoId Id, role string) string {
	return aclExchangeRepoScopePrefix + repoId.String() + ":" + role
}

// The e2e-gkm-concurrency second device's case at the rows (TestE2eGkmConcurrencySecondDevice): in a personal
// network the genesis device makes a vault and a mailbox, then admits a second device of its member, consented by
// §8.5's scoped clause. The second device is listed in both at its admission, reads and writes them at evs and gkm,
// holds their keys with no shrink (an Add keeps the generation, §10.5), and the exchange's table grants it r and rw
// there but no admin, which it does not hold; every reader folds the same lists, before a base and after one.
func TestAclAPersonalNetworksSecondDeviceIsListedInItsOwnersRepos(t *testing.T) {
	net := newTestConfigNet(t)
	vaultId := testConsentRowsRepo(net, net.owner, "consent rows vault", protocol.RepoKind_REPO_KIND_VAULT)
	mailboxId := testConsentRowsRepo(net, net.owner, "consent rows mailbox", protocol.RepoKind_REPO_KIND_MAILBOX)
	generalId := testConsentRowsRepo(net, net.owner, "consent rows general", protocol.RepoKind_REPO_KIND_GENERAL)
	second := net.device("owner second device", net.ownerMemberId)
	before := net.log.State()
	if testConsentRowsListed(before, vaultId, second.sidecarId) {
		t.Fatal("a device not yet admitted is listed")
	}
	net.admitDevice(net.owner, second, 0)
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	if !acl.ConsentedFor(second.sidecarId, net.ownerMemberId) {
		t.Fatal("the scoped clause does not consent the second device")
	}
	for _, repoId := range []Id{vaultId, mailboxId} {
		listed := state.Repo(repoId).GetConsentedSidecarIds()
		if len(listed) != 2 || !bytes.Equal(listed[0], net.owner.sidecarId.Bytes()) || !bytes.Equal(listed[1], second.sidecarId.Bytes()) {
			t.Errorf("repo %s lists %x", repoId, listed)
		}
		for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
			rights := testConsentRowsRights(t, state, second.sidecarId, repoId, audience)
			if !rights.Has(AclEvsRead) || !rights.Has(AclEvsWrite) || rights.Has(AclEvsAdmin) {
				t.Errorf("repo %s at audience %d: %b", repoId, audience, rights)
			}
		}
		holders, err := KeyHolders(state, repoId, time.UnixMilli(state.timeMs))
		if err != nil {
			t.Fatal(err)
		}
		if !holders.Contains(GkmHolderLeaf, second.sidecarId.Bytes()) {
			t.Errorf("repo %s's key holders leave out the second device", repoId)
		}
		if shrunkAt := state.Repo(repoId).GetHoldersShrunkAt(); shrunkAt != before.Repo(repoId).GetHoldersShrunkAt() {
			t.Errorf("repo %s shrank at the admission, to %d", repoId, shrunkAt)
		}
	}
	if 0 < len(state.Repo(generalId).GetConsentedSidecarIds()) {
		t.Error("a general repo lists consented devices")
	}
	granted := testConsentRowsExchange(t, state, second.sidecarId, AclTokenAudienceGkm,
		testConsentRowsScope(vaultId, "r"), testConsentRowsScope(vaultId, "rw"), testConsentRowsScope(vaultId, "admin"))
	if !slices.Equal(granted, []string{testConsentRowsScope(vaultId, "r"), testConsentRowsScope(vaultId, "rw")}) {
		t.Errorf("the exchange's table grants %v", granted)
	}
	net.everyReaderAgrees()

	// a base carries the lists, so a reader that starts there holds them too
	net.fold(net.owner, net.n, 2)
	if !testConsentRowsListed(net.log.State(), vaultId, second.sidecarId) {
		t.Error("the base dropped the second device's listing")
	}
	third := net.device("owner third device", net.ownerMemberId)
	net.admitDevice(second, third, 0)
	if !testConsentRowsListed(net.log.State(), vaultId, third.sidecarId) || !testConsentRowsListed(net.log.State(), mailboxId, third.sidecarId) {
		t.Error("a device the second device admitted after the base is not listed")
	}
	net.everyReaderAgrees()
}

// A device of member M that no consent clause holds for is not listed, and keeps only what §8.5 gives M's other
// subjects in M's vault (deposit), as are an ephemeral device and another member's device, which holds no role there:
// the exchange's table grants none of them a read. M's consented device's AdmissionConfirm of the unconsented one then
// consents it (the confirmed clause), which lists it, and a device M's consented device admits is listed at once.
func TestAclOnlyAConsentedDeviceIsListedInItsOwnersVault(t *testing.T) {
	net := newTestConfigNet(t)
	member, first := net.consentedMember("m")
	vaultId := testConsentRowsRepo(net, first, "consent rows m vault", protocol.RepoKind_REPO_KIND_VAULT)

	// the network owner's device admits a device of m: one admin's signature, no consent of m's (owner decision 126)
	unconsented := net.device("m unconsented", member)
	net.admitDevice(net.owner, unconsented, 0)
	ephemeral := net.device("m ephemeral", member)
	net.mustPost(first, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.admission(ephemeral, nil, true, net.timeMs+24*60*60*1000, 0))
	state := net.log.State()
	acl, err := state.Acl()
	if err != nil {
		t.Fatal(err)
	}
	for name, sidecarId := range map[string]Id{"the unconsented device": unconsented.sidecarId, "the ephemeral device": ephemeral.sidecarId} {
		if acl.Consented(sidecarId) || testConsentRowsListed(state, vaultId, sidecarId) {
			t.Errorf("%s: consented %v, listed %v", name, acl.Consented(sidecarId), testConsentRowsListed(state, vaultId, sidecarId))
		}
		if rights := testConsentRowsRights(t, state, sidecarId, vaultId, AclTokenAudienceGkm); rights != AclEvsDeposit {
			t.Errorf("%s in m's vault: %b", name, rights)
		}
		if granted := testConsentRowsExchange(t, state, sidecarId, AclTokenAudienceGkm, testConsentRowsScope(vaultId, "r"), testConsentRowsScope(vaultId, "rw")); len(granted) != 0 {
			t.Errorf("%s: the exchange's table grants %v", name, granted)
		}
	}
	// the network owner's own device, an admin of m but no device of m's, holds no role in m's vault
	if rights := testConsentRowsRights(t, state, net.owner.sidecarId, vaultId, AclTokenAudienceGkm); rights != 0 || testConsentRowsListed(state, vaultId, net.owner.sidecarId) {
		t.Errorf("the network owner's device in m's vault: %b", rights)
	}
	if granted := testConsentRowsExchange(t, state, net.owner.sidecarId, AclTokenAudienceGkm, testConsentRowsScope(vaultId, "deposit"), testConsentRowsScope(vaultId, "r")); len(granted) != 0 {
		t.Errorf("another member's device: the exchange's table grants %v", granted)
	}

	net.mustPost(first, bridge.SignedType_SIGNED_ADMISSION_CONFIRM, &protocol.AdmissionConfirm{Header: net.header(), SidecarId: unconsented.sidecarId.Bytes()})
	state = net.log.State()
	if !testConsentRowsListed(state, vaultId, unconsented.sidecarId) {
		t.Error("m's AdmissionConfirm did not list the device it consented")
	}
	if rights := testConsentRowsRights(t, state, unconsented.sidecarId, vaultId, AclTokenAudienceGkm); !rights.Has(AclEvsRead) || !rights.Has(AclEvsWrite) {
		t.Errorf("the confirmed device in m's vault: %b", rights)
	}
	if testConsentRowsListed(state, vaultId, ephemeral.sidecarId) {
		t.Error("the ephemeral device was listed at another device's confirmation")
	}

	second := net.device("m second", member)
	net.admitDevice(first, second, 0)
	if !testConsentRowsListed(net.log.State(), vaultId, second.sidecarId) {
		t.Error("a device m's consented device admitted is not listed")
	}
	net.everyReaderAgrees()
}

// A listed device leaves the list at its revocation, which ends its consent (QD-1191), and reads nothing: the list
// holds exactly the owner's consented devices now (acl_consented_list_drops_test.go has the other endings).
func TestAclARevokedListedDeviceReadsNothing(t *testing.T) {
	net := newTestConfigNet(t)
	vaultId := testConsentRowsRepo(net, net.owner, "consent rows revoked vault", protocol.RepoKind_REPO_KIND_VAULT)
	second := net.device("owner revoked device", net.ownerMemberId)
	net.admitDevice(net.owner, second, 0)
	if !testConsentRowsListed(net.log.State(), vaultId, second.sidecarId) {
		t.Fatal("the admission did not list the second device")
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, &bridge.SidecarRevoke{
		Header: net.header(), SidecarId: second.sidecarId.Bytes(), Reason: bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST,
	})
	state := net.log.State()
	if listed := state.Repo(vaultId).GetConsentedSidecarIds(); len(listed) != 1 || !bytes.Equal(listed[0], net.owner.sidecarId.Bytes()) {
		t.Errorf("after the revocation the vault lists %x, want the genesis device alone", listed)
	}
	if rights := testConsentRowsRights(t, state, second.sidecarId, vaultId, AclTokenAudienceGkm); rights != 0 {
		t.Errorf("the revoked device in the vault: %b", rights)
	}
	net.everyReaderAgrees()
}
