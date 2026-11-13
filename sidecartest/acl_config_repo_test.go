// QD-719 through the real gates on T2 (question team-m2-15-config-repo-acl-row): no state's rows hold an AclRepo for
// the network's config repo, since §7.9's bootstrap creates it and a RepoCreate of kind config is refused, so ACL's
// state adds the row from the Genesis and every gate answers from it. One network on the admission world's real log,
// bootstrapped by BootstrapNetwork on the Net's api, read by §8.9's real gate cache over the Net's Redis and first
// metadata cluster, with evs's real EvsAuthState and engine over that cache:
//
//	exchange   AclExchangeScopes grants repo:<config_repo_id>:r and :rw as §8.5's kind default gives them, the
//	           bootstrap sidecar's :admin (§7.9), and a forward_only client's r alone while its sidecar's forwarding
//	           Delegation lives (owner decision 197)
//	evs        PUT /evs/v1/repos/<config> places the config repo at bootstrap under the bootstrap sidecar's admin
//	           scope, and no other sidecar's; GET honors a member device's and an ephemeral sidecar's r, and a
//	           revocation closes it at the gate's next load
//	gkm        AclGateCache.HonorScope for the gkm audience, the answer gkm's guard reads: a member device's rw in the
//	           config group, never a read_only or ephemeral one's. gkm's engine over its own GkmAuthState on this
//	           cache (QD-718) runs in gkm_auth_state_acl_test.go
//
// No sleeps: each load is awaited by the cache's OnLoad, and the clock is the Net's.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// rev/ holding no object.
type aclConfigRepoRevocations struct{}

func (self aclConfigRepoRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

// The world: the Net, its admission network, the real gate cache and evs over it.
type aclConfigRepoWorld struct {
	t         *testing.T
	net       *Net
	admission *AdmissionNet
	cache     *sidecar.AclGateCache
	loads     chan *bridge.AuthPin
	engine    *evsservice.EvsEngine
	configId  sidecar.Id
}

func newAclConfigRepoWorld(t *testing.T) *aclConfigRepoWorld {
	net := NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = AclAdmissionCompile
	admission := NewAdmissionNet(t, tier)
	t.Cleanup(admission.Close)
	world := &aclConfigRepoWorld{
		t: t, net: net, admission: admission, loads: make(chan *bridge.AuthPin, 64),
		configId: admission.ConfigRepoId(),
	}
	host := net.Fakes()
	RegisterEvsTwins(host.Redis)
	host.Gates.OpenService(sidecar.ServiceGateEvs, connect.Id(admission.NetworkId()))
	host.Quota.SetBalance(connect.Id(admission.NetworkId()), 1<<40)

	gateSettings := sidecar.DefaultAclGateSettings()
	gateSettings.Log = sidecar.NewNoopLogger()
	gateSettings.PollInterval = 0
	gateSettings.FailureBackoff = 0
	gateSettings.OnLoad = func(networkId sidecar.Id, pin *bridge.AuthPin, err error) {
		if err != nil {
			t.Errorf("the gate's load: %v", err)
		}
		world.loads <- pin
	}
	world.cache = sidecar.NewAclGateCache(admission.Context(), sidecar.NewAclGateDirectSource(net.Host().Redis, net.Host().Blobs, gateSettings),
		net.Clock(), gateSettings)

	settings := evsservice.DefaultEvsSettings()
	settings.RepoCacheTtl = 0
	world.engine, err = evsservice.NewEvsEngine(t.Context(), net.Host(), settings, &evsservice.EvsEngineDeps{
		AuthState: evsservice.NewAclEvsAuthState(world.cache, aclConfigRepoRevocations{}),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	return world
}

// Tells the gate the log moved and waits for its load to reach the tip.
func (self *aclConfigRepoWorld) load() {
	self.t.Helper()
	networkId := self.admission.NetworkId()
	self.cache.Changed(networkId)
	want := self.admission.Tip()
	for {
		select {
		case <-self.loads:
		case <-self.admission.Context().Done():
			self.t.Fatalf("no load reached %d: %v", want.GetVersion(), self.admission.Context().Err())
		}
		snapshot, status := self.cache.State(networkId)
		if status == sidecar.AclGateLoaded && snapshot != nil && proto.Equal(snapshot.Pin, want) {
			return
		}
		self.cache.Changed(networkId)
	}
}

// The client api bound to a device's sidecar, which the exchange writes into its tokens (QD-717).
func (self *aclConfigRepoWorld) clientOf(device *AdmissionDevice) sidecar.Id {
	return self.admission.Id("client of " + device.SidecarId.String())
}

// An evs token of the device's sidecar carrying scopes, as the exchange would mint it.
func (self *aclConfigRepoWorld) token(device *AdmissionDevice, scopes ...string) string {
	sidecarId := connect.Id(device.SidecarId)
	now := self.net.Clock().Now()
	return self.net.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.admission.NetworkId()),
		ClientId:  connect.Id(self.clientOf(device)),
		SidecarId: &sidecarId,
		Audience:  evsservice.EvsAudience,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
}

// One request of the device to evs's config repo route, with the scopes its token carries: the status and the refusal.
func (self *aclConfigRepoWorld) serve(method string, device *AdmissionDevice, scopes ...string) (int, protocol.EvsRefusalCode) {
	self.t.Helper()
	request := httptest.NewRequestWithContext(self.t.Context(), method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.configId), nil)
	request.Header.Set("Authorization", "Bearer "+self.token(device, scopes...))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	if recorder.Code == http.StatusOK {
		return recorder.Code, 0
	}
	reply := &protocol.EvsRefusalReply{}
	if err := proto.Unmarshal(recorder.Body.Bytes(), reply); err != nil {
		self.t.Fatalf("a refusal that does not parse: %v", err)
	}
	return recorder.Code, reply.GetCode()
}

// The scopes the exchange grants the device's sidecar of those asked, at the tip.
func (self *aclConfigRepoWorld) exchange(device *AdmissionDevice, audience sidecar.AclTokenAudience, forwardOnly bool, scopes ...string) []string {
	self.t.Helper()
	grant, err := sidecar.AclExchangeScopes(self.admission.State(), &sidecar.AclExchangeRequest{
		SidecarId: device.SidecarId, Audience: audience, Scopes: scopes, ForwardOnly: forwardOnly, Now: self.net.Clock().Now(),
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return grant.Scopes
}

// The gate's answer for a device's config scope at an audience, at the Net's clock.
func (self *aclConfigRepoWorld) honored(device *AdmissionDevice, scope sidecar.AclEvsRights, audience sidecar.AclTokenAudience) sidecar.AclScopeAnswer {
	return self.cache.HonorScope(self.admission.NetworkId(), device.SidecarId, self.configId, scope, audience, self.net.Clock().Now())
}

func aclConfigRepoScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

// The bootstrap, then the network's later devices: the exchange, the gate cache at both audiences and evs answer the
// config repo's scopes from the row the state adds, with no AclRepo of it in any rows.
func TestAclConfigRepoRowAtTheRealGates(t *testing.T) {
	world := newAclConfigRepoWorld(t)
	admission := world.admission
	owner := admission.Owner()
	configR, configRw, configAdmin := aclConfigRepoScope(world.configId, "r"), aclConfigRepoScope(world.configId, "rw"), aclConfigRepoScope(world.configId, "admin")
	all := []string{configR, configRw, configAdmin}
	evs, gkm := sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm

	// base 1: the bootstrap sidecar holds the config's admin, and places the repo with it
	world.load()
	rowless := func() {
		t.Helper()
		acl, err := admission.State().Acl()
		if err != nil {
			t.Fatal(err)
		}
		for _, repo := range acl.Rows().GetRepos() {
			if bytes.Equal(repo.GetRepoId(), world.configId.Bytes()) || repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG {
				t.Fatalf("the rows hold a config row at %d: %v", admission.Tip().GetVersion(), repo)
			}
		}
		if row := acl.Repo(world.configId); row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || len(row.GetAdmins()) != 0 {
			t.Fatalf("the state's config row at %d: %v", admission.Tip().GetVersion(), row)
		}
	}
	rowless()
	for _, audience := range []sidecar.AclTokenAudience{evs, gkm} {
		if granted := world.exchange(owner, audience, false, all...); !slices.Equal(granted, all) {
			t.Fatalf("the bootstrap sidecar's scopes at %d: %v", audience, granted)
		}
		if answer := world.honored(owner, sidecar.AclEvsAdmin, audience); answer != sidecar.AclScopeHonored {
			t.Fatalf("the bootstrap sidecar's admin at %d: %d", audience, answer)
		}
	}
	if status, code := world.serve(http.MethodGet, owner, configR); status != http.StatusNotFound || code != protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND {
		t.Fatalf("a read before the repo is placed: %d %s", status, code)
	}
	if status, code := world.serve(http.MethodPut, owner, configAdmin); status != http.StatusOK {
		t.Fatalf("the bootstrap's PUT: %d %s", status, code)
	}
	first, err := world.net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	place, err := sidecar.ReadEvsRepoPlace(t.Context(), first, world.configId)
	if err != nil || place.CreatorSidecarId != owner.SidecarId {
		t.Fatalf("place/: %+v, %v", place, err)
	}
	cluster, err := world.net.Host().Blobs.Cluster(place.ClusterId)
	if err != nil {
		t.Fatal(err)
	}
	object, err := cluster.Get(t.Context(), sidecar.EvsRepoObjectKey(world.configId))
	if err != nil {
		t.Fatalf("repo/: %v", err)
	}
	repoBytes := new(bytes.Buffer)
	_, err = repoBytes.ReadFrom(object.Body)
	object.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	repo := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(repoBytes.Bytes(), repo); err != nil {
		t.Fatal(err)
	}
	if repo.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || repo.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING ||
		!bytes.Equal(repo.GetRepoId(), world.configId.Bytes()) || !bytes.Equal(repo.GetNetworkId(), admission.NetworkId().Bytes()) ||
		len(repo.GetOwnerMemberId()) != 0 {
		t.Fatalf("repo/: %v", repo)
	}
	if status, code := world.serve(http.MethodPut, owner, configAdmin); status != http.StatusOK {
		t.Errorf("the bootstrap's PUT again: %d %s", status, code)
	}
	if status, code := world.serve(http.MethodGet, owner, configR); status != http.StatusOK {
		t.Errorf("the bootstrap sidecar's read: %d %s", status, code)
	}

	// the network's later devices: another config writer, a member's device, a read_only one and an ephemeral one
	ownerPhone := admission.Device("owner phone", owner.MemberId)
	admission.AdmitDevice(owner, ownerPhone, 0)
	memberId, phone := admission.ConsentedMember("config repo")
	readOnly := admission.Device("config repo read only", memberId)
	admission.AdmitDevice(owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	ephemeral := admission.Device("config repo ephemeral", memberId)
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		admission.Admission(ephemeral, nil, true, world.net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	if !admission.State().IsConfigWriter(ownerPhone.SidecarId) {
		t.Fatal("the owner's second device writes no config head")
	}
	world.load()
	rowless()
	cases := []struct {
		name   string
		device *AdmissionDevice
		evs    []string
		gkm    []string
	}{
		{name: "the bootstrap sidecar", device: owner, evs: all, gkm: all},
		{name: "another config writer", device: ownerPhone, evs: []string{configR, configRw}, gkm: []string{configR, configRw}},
		{name: "a member device", device: phone, evs: []string{configR}, gkm: []string{configR, configRw}},
		{name: "a read_only device", device: readOnly, evs: []string{configR}, gkm: []string{configR}},
		{name: "an ephemeral device", device: ephemeral, evs: []string{configR}, gkm: []string{configR}},
	}
	rights := map[string]sidecar.AclEvsRights{configR: sidecar.AclEvsRead, configRw: sidecar.AclEvsWrite, configAdmin: sidecar.AclEvsAdmin}
	for _, c := range cases {
		for audience, want := range map[sidecar.AclTokenAudience][]string{evs: c.evs, gkm: c.gkm} {
			if granted := world.exchange(c.device, audience, false, all...); !slices.Equal(granted, want) {
				t.Errorf("%s: the exchange at %d grants %v, want %v", c.name, audience, granted, want)
			}
			// the gate honors exactly what the exchange grants (D-ACL-21)
			for _, scope := range all {
				wantAnswer := sidecar.AclScopeRefused
				if slices.Contains(want, scope) {
					wantAnswer = sidecar.AclScopeHonored
				}
				if answer := world.honored(c.device, rights[scope], audience); answer != wantAnswer {
					t.Errorf("%s: the gate's answer for %s at %d: %d, want %d", c.name, scope, audience, answer, wantAnswer)
				}
			}
		}
		if status, code := world.serve(http.MethodGet, c.device, configR); status != http.StatusOK {
			t.Errorf("%s: evs's read: %d %s", c.name, status, code)
		}
		if c.device != owner {
			// a token that claims the config's admin without the state's leave places nothing
			if status, code := world.serve(http.MethodPut, c.device, configAdmin); status != http.StatusForbidden || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
				t.Errorf("%s: a PUT under an admin scope the state does not give: %d %s", c.name, status, code)
			}
		}
	}

	// a forward_only client of the phone's sidecar: the config's r alone, while its forwarding Delegation lives
	if granted := world.exchange(phone, evs, true, all...); len(granted) != 0 {
		t.Errorf("a forward_only client with no forwarding Delegation: %v", granted)
	}
	forwardingSeed := sha256.Sum256([]byte("config repo forwarding key"))
	forwardingKey := ed25519.NewKeyFromSeed(forwardingSeed[:])
	forwarding := admission.Sign(phone, bridge.SignedType_SIGNED_DELEGATION, &protocol.Delegation{
		Header:               admission.Header(),
		Pubkey:               forwardingKey.Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: bytes.Repeat([]byte{0x5a}, 1216),
		Forward:              &bridge.ForwardScope{ForwardSidecarId: phone.SidecarId.Bytes()},
	})
	admission.MustLand(forwarding)
	world.load()
	for _, audience := range []sidecar.AclTokenAudience{evs, gkm} {
		if granted := world.exchange(phone, audience, true, all...); !slices.Equal(granted, []string{configR}) {
			t.Errorf("a forward_only client at %d: %v", audience, granted)
		}
	}
	// its token names the phone's sidecar, so evs honors it by the phone's rights
	if status, code := world.serve(http.MethodGet, phone, configR); status != http.StatusOK {
		t.Errorf("a forward_only client's read: %d %s", status, code)
	}
	admission.MustLand(admission.Sign(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, admission.DelegationRevoke(AdmissionStatementId(forwarding), 0)))
	world.load()
	if granted := world.exchange(phone, evs, true, all...); len(granted) != 0 {
		t.Errorf("a forward_only client after its Delegation's revoke: %v", granted)
	}

	// a revocation closes the config's scopes at the next load, at both audiences and at evs
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	world.load()
	rowless()
	for _, audience := range []sidecar.AclTokenAudience{evs, gkm} {
		if granted := world.exchange(phone, audience, false, all...); len(granted) != 0 {
			t.Errorf("a revoked device's scopes at %d: %v", audience, granted)
		}
		if answer := world.honored(phone, sidecar.AclEvsRead, audience); answer != sidecar.AclScopeRefused {
			t.Errorf("a revoked device's config r at %d: %d", audience, answer)
		}
	}
	if status, code := world.serve(http.MethodGet, phone, configR); status != http.StatusForbidden {
		t.Errorf("a revoked device's read: %d %s", status, code)
	}
	if status, code := world.serve(http.MethodGet, readOnly, configR); status != http.StatusOK {
		t.Errorf("another device's read after the revocation: %d %s", status, code)
	}
}

// Every reader of the admission world, full, rows-only and started at a base, builds the same row for the config repo
// from its rows and the Genesis, at a base and in its tail alike, and no reader's rows hold it.
func TestAclConfigRepoRowIsAlikeInEveryReader(t *testing.T) {
	world := newAclConfigRepoWorld(t)
	admission := world.admission
	memberId, phone := admission.ConsentedMember("alike")
	admission.Fold(true)
	ephemeral := admission.Device("alike ephemeral", memberId)
	admission.MustLand(admission.Sign(admission.Owner(), bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		admission.Admission(ephemeral, nil, true, world.net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	now := world.net.Clock().Now()
	readers := 0
	admission.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
		readers += 1
		row := acl.Repo(world.configId)
		if row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || len(row.GetAdmins()) != 0 || row.GetHoldersShrunkAt() != state.Pin().GetVersion() {
			return fmt.Errorf("the config row: %v", row)
		}
		for _, repo := range acl.Rows().GetRepos() {
			if bytes.Equal(repo.GetRepoId(), world.configId.Bytes()) {
				return fmt.Errorf("the rows hold the config row")
			}
		}
		for sidecarId, want := range map[sidecar.Id]sidecar.AclEvsRights{
			admission.Owner().SidecarId: sidecar.AclEvsRead | sidecar.AclEvsWrite | sidecar.AclEvsAdmin,
			phone.SidecarId:             sidecar.AclEvsRead,
			ephemeral.SidecarId:         sidecar.AclEvsRead,
		} {
			if rights := acl.EvsAccess(sidecar.AclSidecarSubject(sidecarId), world.configId, sidecar.AclTokenAudienceEvs, now).Rights; rights != want {
				return fmt.Errorf("%s holds %b on the config, want %b", sidecarId, rights, want)
			}
		}
		return nil
	})
	if readers < 2 {
		t.Errorf("%d readers answered", readers)
	}
}
