// QD-719 through the real gates on T2 (question team-m2-15-config-repo-acl-row): no state's rows hold an AclRepo for
// the network's config repo before its key holders first shrink, since §7.9's bootstrap creates it and a RepoCreate of
// kind config is refused, so ACL's state adds the row from the Genesis, with holders_shrunk_at 0, and every gate
// answers from it; from the first shrink the rows hold it at that entry's position (QD-762). One network on the
// admission world's real log, bootstrapped by BootstrapNetwork on the Net's api, read by §8.9's real gate cache over
// the Net's Redis and first metadata cluster, with evs's real EvsAuthState and engine over that cache:
//
//	exchange   AclExchangeScopes grants repo:<config_repo_id>:r and :rw as §8.5's kind default gives them, :admin to
//	           every config writer (QD-894), §7.9's bootstrap sidecar the first of them, and a forward_only client's r
//	           alone while its sidecar's forwarding Delegation lives (owner decision 197)
//	evs        PUT /evs/v1/repos/<config> places the config repo under a config writer's admin scope, the bootstrap
//	           sidecar's at bootstrap or another's once that one is revoked, and no other sidecar's: the guard honors
//	           every config writer's admin, and §11.8's placement rule then answers 409 to any but the placement's
//	           creator. POST .../activate takes a config writer's admin alike. GET honors a member device's and an
//	           ephemeral sidecar's r, and a revocation closes it at the gate's next load
//	gkm        AclGateCache.HonorScope for the gkm audience, the answer gkm's guard reads: a member device's rw in the
//	           config group, never a read_only or ephemeral one's. gkm's real engine over its AclGkmAuthState on this
//	           cache (QD-718) forms the config group under the bootstrap sidecar's admin and, once that sidecar is
//	           revoked, re-forms it and takes its ladder under another config writer's, and no other sidecar's; the
//	           rest of gkm's routes over that state run in gkm_auth_state_acl_test.go
//	drop       a config writer's admin drops nothing in the config: MayDrop refuses it in the gate's own state
//	           (D-ACL-25)
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
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// rev/ holding no object.
type aclConfigRepoRevocations struct{}

func (self aclConfigRepoRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	return nil
}

// The purpose a GroupForm is signed under (QD-527).
const aclConfigRepoGroupFormPurpose = "group-form"

// The cipher suite a group takes (owner decision 44).
const aclConfigRepoCipherSuite uint32 = 0x0010

// The world: the Net, its admission network, the real gate cache, and evs and gkm over it.
type aclConfigRepoWorld struct {
	t         *testing.T
	net       *Net
	admission *AdmissionNet
	cache     *sidecar.AclGateCache
	loads     chan *bridge.AuthPin
	engine    *evsservice.EvsEngine
	gkm       *gkmservice.GkmEngine
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

	host.Gates.OpenService(sidecar.ServiceGateGkm, connect.Id(admission.NetworkId()))
	world.gkm, err = gkmservice.NewGkmEngine(t.Context(), net.Host(), nil, &gkmservice.GkmEngineDeps{
		AuthState: gkmservice.NewAclGkmAuthState(world.cache, aclConfigRepoRevocations{}, net.Clock()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.gkm.Close)
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
	return self.serveAt(method, "", device, scopes...)
}

// serve, on a route under the config repo's: suffix is the path after the repo's id.
func (self *aclConfigRepoWorld) serveAt(method string, suffix string, device *AdmissionDevice, scopes ...string) (int, protocol.EvsRefusalCode) {
	self.t.Helper()
	request := httptest.NewRequestWithContext(self.t.Context(), method, "/evs/v1/repos/"+sidecar.EvsKeyId(self.configId)+suffix, nil)
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

// One request of the device to gkm, with the scopes its gkm token carries: the status.
func (self *aclConfigRepoWorld) serveGkm(path string, body proto.Message, device *AdmissionDevice, scopes ...string) int {
	self.t.Helper()
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	sidecarId := connect.Id(device.SidecarId)
	now := self.net.Clock().Now()
	token := self.net.Fakes().Authenticator.Issue(&sidecar.Principal{
		NetworkId: connect.Id(self.admission.NetworkId()),
		ClientId:  connect.Id(self.clientOf(device)),
		SidecarId: &sidecarId,
		Audience:  gkmservice.GkmAudience,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	})
	request := httptest.NewRequestWithContext(self.t.Context(), http.MethodPost, path, bytes.NewReader(bodyBytes))
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	self.gkm.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// The device's identity key signing as its sidecar, as a gkm statement is signed.
func aclConfigRepoSign(device *AdmissionDevice) sidecar.GkmSignFunction {
	return func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
		return &bridge.Signed{
			Body:      bytes.Clone(body),
			SignerId:  device.SidecarId.Bytes(),
			Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, body)),
			Type:      uint32(signedType),
		}, nil
	}
}

// A GroupForm of the config repo by signer at the tip: a creation's with no previous group, else a re-form's.
func (self *aclConfigRepoWorld) groupForm(signer *AdmissionDevice, groupId sidecar.Id, previousGroupId *sidecar.Id, generation uint64) *bridge.Signed {
	self.t.Helper()
	body := &protocol.GroupForm{RepoId: self.configId.Bytes(), GroupId: groupId.Bytes(), Generation: generation, Auth: self.admission.Tip()}
	if previousGroupId != nil {
		body.PreviousGroupId = previousGroupId.Bytes()
	}
	bodyBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		self.t.Fatal(err)
	}
	signed, err := aclConfigRepoSign(signer)(aclConfigRepoGroupFormPurpose, bridge.SignedType_SIGNED_GROUP_FORM, bodyBytes, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	return signed
}

// KF1's request for the config repo's first group by signer: its form and gen/1 at the tip and the Net's clock. The
// holders hash, GenWrap and GroupInfo are stand-ins gkm stores and never opens.
func (self *aclConfigRepoWorld) groupCreate(signer *AdmissionDevice, groupId sidecar.Id) *protocol.GkmGroupCreateRequest {
	self.t.Helper()
	holdersSha256 := sha256.Sum256([]byte("config repo holders"))
	_, rotate, err := sidecar.NewGkmFirstGeneration(self.configId, groupId, &sidecar.GkmGenerationArgs{
		Cause:         sidecar.GkmCauseRequest,
		Auth:          self.admission.Tip(),
		Time:          self.net.Clock().Now(),
		HoldersSha256: holdersSha256[:],
	})
	if err != nil {
		self.t.Fatal(err)
	}
	signedRotate, err := sidecar.SignGenRotate(rotate, aclConfigRepoSign(signer))
	if err != nil {
		self.t.Fatal(err)
	}
	return &protocol.GkmGroupCreateRequest{
		Form:            self.groupForm(signer, groupId, nil, 1),
		GenRotate:       signedRotate,
		GenWrap:         bytes.Repeat([]byte{7}, 24+32+16),
		SealedGroupInfo: []byte("sealed group info of the config group's epoch 0"),
		CipherSuite:     aclConfigRepoCipherSuite,
	}
}

// A re-form of the config repo's group previousGroupId into groupId by signer, at generation 1.
func (self *aclConfigRepoWorld) groupReform(signer *AdmissionDevice, groupId sidecar.Id, previousGroupId sidecar.Id) *protocol.GkmGroupReformRequest {
	self.t.Helper()
	return &protocol.GkmGroupReformRequest{
		Form:            self.groupForm(signer, groupId, &previousGroupId, 1),
		GenWrap:         bytes.Repeat([]byte{5}, 24+32+16),
		SealedGroupInfo: []byte("sealed group info of the re-formed config group's epoch 0"),
		CipherSuite:     aclConfigRepoCipherSuite,
	}
}

// The bytes of an object on the config repo's cluster, nil for none.
func (self *aclConfigRepoWorld) configClusterObject(key string) []byte {
	self.t.Helper()
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	place, err := sidecar.ReadEvsRepoPlace(self.t.Context(), first, self.configId)
	if err != nil {
		self.t.Fatal(err)
	}
	cluster, err := self.net.Host().Blobs.Cluster(place.ClusterId)
	if err != nil {
		self.t.Fatal(err)
	}
	object, err := cluster.Get(self.t.Context(), key)
	if err != nil {
		return nil
	}
	defer object.Body.Close()
	objectBytes := new(bytes.Buffer)
	if _, err := objectBytes.ReadFrom(object.Body); err != nil {
		self.t.Fatal(err)
	}
	return objectBytes.Bytes()
}

// The gate's own state at its newest load.
func (self *aclConfigRepoWorld) gateAcl() *sidecar.AclState {
	self.t.Helper()
	snapshot, status := self.cache.State(self.admission.NetworkId())
	if status != sidecar.AclGateLoaded || snapshot == nil || snapshot.Acl == nil {
		self.t.Fatalf("the gate holds no state: %d", status)
	}
	return snapshot.Acl
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

// The state's config row at the tip: kind config with no admins and holders_shrunk_at shrunkAt, from no rows while
// shrunkAt is 0, and from the rows' one row of it from the config's first shrink on.
func (self *aclConfigRepoWorld) configRowIs(shrunkAt uint64) {
	self.t.Helper()
	tip := self.admission.Tip().GetVersion()
	acl, err := self.admission.State().Acl()
	if err != nil {
		self.t.Fatal(err)
	}
	held := []*protocol.AclRepo{}
	for _, repo := range acl.Rows().GetRepos() {
		if bytes.Equal(repo.GetRepoId(), self.configId.Bytes()) || repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG {
			held = append(held, repo)
		}
	}
	if want := min(shrunkAt, 1); uint64(len(held)) != want {
		self.t.Fatalf("the rows hold %d config rows at %d, want %d: %v", len(held), tip, want, held)
	}
	row := acl.Repo(self.configId)
	if row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || len(row.GetAdmins()) != 0 || row.GetHoldersShrunkAt() != shrunkAt {
		self.t.Fatalf("the state's config row at %d: %v, want holders_shrunk_at %d", tip, row, shrunkAt)
	}
}

// The bootstrap, then the network's later devices: the exchange, the gate cache at both audiences and evs answer the
// config repo's scopes from the row the state adds, with no AclRepo of it in any rows until the config's holders
// first shrink, and from the rows' own after. Every config writer administers the config (QD-894): the owner's second
// device holds its admin beside the bootstrap sidecar and, once that sidecar is revoked, is the one that re-forms the
// config group at gkm, posts its ladder and activates the repo at evs, while a member's device that writes no config
// head and a read_only device are refused each, and no config writer drops in the config.
func TestAclConfigRepoRowAtTheRealGates(t *testing.T) {
	world := newAclConfigRepoWorld(t)
	admission := world.admission
	owner := admission.Owner()
	configR, configRw, configAdmin := aclConfigRepoScope(world.configId, "r"), aclConfigRepoScope(world.configId, "rw"), aclConfigRepoScope(world.configId, "admin")
	all := []string{configR, configRw, configAdmin}
	evs, gkm := sidecar.AclTokenAudienceEvs, sidecar.AclTokenAudienceGkm

	// base 1: the bootstrap sidecar holds the config's admin, and places the repo with it
	world.load()
	world.configRowIs(0)
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
	// and forms the config group at gkm under the same admin (KF1)
	groupId := admission.Id("config repo group")
	create := world.groupCreate(owner, groupId)
	if status := world.serveGkm("/gkm/groups", create, owner, configR); status != http.StatusForbidden {
		t.Errorf("a group's creation under the config's r: %d", status)
	}
	if status := world.serveGkm("/gkm/groups", create, owner, configAdmin); status != http.StatusOK {
		t.Fatalf("the bootstrap sidecar's creation of the config group: %d", status)
	}
	rotate1 := world.configClusterObject(gkmservice.GkmGenerationKey(groupId, 1))
	if len(rotate1) == 0 {
		t.Fatal("the config group holds no gen/1")
	}

	// the network's later devices: another config writer, a member's devices, a read_only one and an ephemeral one
	ownerPhone := admission.Device("owner phone", owner.MemberId)
	admission.AdmitDevice(owner, ownerPhone, 0)
	memberId, phone := admission.ConsentedMember("config repo")
	laptop := admission.Device("config repo laptop", memberId)
	admission.AdmitDevice(owner, laptop, 0)
	readOnly := admission.Device("config repo read only", memberId)
	admission.AdmitDevice(owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	ephemeral := admission.Device("config repo ephemeral", memberId)
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		admission.Admission(ephemeral, nil, true, world.net.Clock().Now().Add(24*time.Hour).UnixMilli(), 0)))
	if !admission.State().IsConfigWriter(ownerPhone.SidecarId) {
		t.Fatal("the owner's second device writes no config head")
	}
	world.load()
	world.configRowIs(0)
	cases := []struct {
		name   string
		device *AdmissionDevice
		evs    []string
		gkm    []string
	}{
		{name: "the bootstrap sidecar", device: owner, evs: all, gkm: all},
		{name: "another config writer", device: ownerPhone, evs: all, gkm: all},
		{name: "a member device", device: phone, evs: []string{configR}, gkm: []string{configR, configRw}},
		{name: "a member's second device", device: laptop, evs: []string{configR}, gkm: []string{configR, configRw}},
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
		if slices.Contains(c.evs, configAdmin) {
			// a config writer's PUT passes the guard: the placement's creator continues, and another config writer
			// is told the placement stands (§11.8's step 2), never that its scope is refused
			want := http.StatusConflict
			if c.device == owner {
				want = http.StatusOK
			}
			if status, code := world.serve(http.MethodPut, c.device, configAdmin); status != want {
				t.Errorf("%s: a config writer's PUT: %d %s, want %d", c.name, status, code, want)
			}
		} else {
			// a token that claims the config's admin without the state's leave places nothing
			if status, code := world.serve(http.MethodPut, c.device, configAdmin); status != http.StatusForbidden || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
				t.Errorf("%s: a PUT under an admin scope the state does not give: %d %s", c.name, status, code)
			}
		}
		// no admin of the config drops in it (D-ACL-25)
		if decision := world.gateAcl().MayDrop(c.device.SidecarId, world.configId, world.net.Clock().Now()); decision.Allowed {
			t.Errorf("%s: a drop in the config: %+v", c.name, decision)
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
	// the forwarding holder leaves the config's holders, its first shrink: the rows take the config's row there
	ended := admission.MustLand(admission.Sign(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, admission.DelegationRevoke(AdmissionStatementId(forwarding), 0)))
	world.load()
	world.configRowIs(ended.Pin.GetVersion())
	if granted := world.exchange(phone, evs, true, all...); len(granted) != 0 {
		t.Errorf("a forward_only client after its Delegation's revoke: %v", granted)
	}

	// a revocation closes the config's scopes at the next load, at both audiences and at evs, and advances the row
	revoked := admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	world.load()
	world.configRowIs(revoked.Pin.GetVersion())
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

	// the bootstrap sidecar is revoked by the owner's other device: its scopes close, and the config's admin stays
	// with the config writer that stands (QD-894)
	removed := admission.MustLand(admission.Sign(ownerPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
	world.load()
	world.configRowIs(removed.Pin.GetVersion())
	if !admission.State().IsConfigWriter(ownerPhone.SidecarId) || admission.State().IsConfigWriter(owner.SidecarId) {
		t.Fatal("the config's writers after the bootstrap sidecar's revocation")
	}
	for _, audience := range []sidecar.AclTokenAudience{evs, gkm} {
		if granted := world.exchange(owner, audience, false, all...); len(granted) != 0 {
			t.Errorf("the revoked bootstrap sidecar's scopes at %d: %v", audience, granted)
		}
		if answer := world.honored(owner, sidecar.AclEvsAdmin, audience); answer != sidecar.AclScopeRefused {
			t.Errorf("the revoked bootstrap sidecar's admin at %d: %d", audience, answer)
		}
		if granted := world.exchange(ownerPhone, audience, false, all...); !slices.Equal(granted, all) {
			t.Errorf("the standing config writer's scopes at %d: %v", audience, granted)
		}
		if answer := world.honored(ownerPhone, sidecar.AclEvsAdmin, audience); answer != sidecar.AclScopeHonored {
			t.Errorf("the standing config writer's admin at %d: %d", audience, answer)
		}
		for name, device := range map[string]*AdmissionDevice{"a member's device": laptop, "a read_only device": readOnly} {
			if granted := world.exchange(device, audience, false, configAdmin); len(granted) != 0 {
				t.Errorf("%s: the exchange grants the config's admin at %d", name, audience)
			}
			if answer := world.honored(device, sidecar.AclEvsAdmin, audience); answer != sidecar.AclScopeRefused {
				t.Errorf("%s: the config's admin at %d: %d", name, audience, answer)
			}
		}
	}

	// evs: the config writer's admin passes the real guard, where the placement the bootstrap sidecar made stands
	// (§11.8's step 2); the revoked bootstrap sidecar, a member's device and a read_only one are refused by the
	// guard, at the PUT and at the activation
	if status, code := world.serve(http.MethodPut, ownerPhone, configAdmin); status != http.StatusConflict {
		t.Errorf("the config writer's PUT once the bootstrap sidecar is revoked: %d %s", status, code)
	}
	for name, device := range map[string]*AdmissionDevice{"the revoked bootstrap sidecar": owner, "a member's device": laptop, "a read_only device": readOnly} {
		if status, code := world.serve(http.MethodPut, device, configAdmin); status != http.StatusForbidden {
			t.Errorf("%s: a PUT under the config's admin: %d %s", name, status, code)
		}
		if status, code := world.serveAt(http.MethodPost, "/activate", device, configAdmin); status != http.StatusForbidden {
			t.Errorf("%s: an activation under the config's admin: %d %s", name, status, code)
		}
	}

	// gkm: the config writer re-forms the config group (§10.8) and posts its ladder, gen/1 byte for byte; the others'
	// re-forms and ladders are refused by the guard, the re-form's own form signed by each as its sidecar
	reformedGroupId := admission.Id("config repo group re-formed")
	formsPath := "/gkm/repos/" + sidecar.EvsKeyId(world.configId) + "/forms"
	ladderPath := "/gkm/groups/" + sidecar.EvsKeyId(reformedGroupId) + "/ladder"
	signedRotate1 := &bridge.Signed{}
	if err := proto.Unmarshal(rotate1, signedRotate1); err != nil {
		t.Fatal(err)
	}
	ladder := &protocol.GkmLadderRequest{Generations: []*bridge.Signed{signedRotate1}}
	for name, device := range map[string]*AdmissionDevice{"the revoked bootstrap sidecar": owner, "a member's device": laptop, "a read_only device": readOnly} {
		if status := world.serveGkm(formsPath, world.groupReform(device, reformedGroupId, groupId), device, configAdmin); status != http.StatusForbidden {
			t.Errorf("%s: a re-form of the config group: %d", name, status)
		}
	}
	if world.configClusterObject(gkmservice.GkmGroupOwnerKey(reformedGroupId)) != nil {
		t.Fatal("a refused re-form wrote the group's owner marker")
	}
	if status := world.serveGkm(formsPath, world.groupReform(ownerPhone, reformedGroupId, groupId), ownerPhone, configRw); status != http.StatusForbidden {
		t.Errorf("the config writer's re-form under the config's rw: %d", status)
	}
	if status := world.serveGkm(formsPath, world.groupReform(ownerPhone, reformedGroupId, groupId), ownerPhone, configAdmin); status != http.StatusOK {
		t.Fatalf("the config writer's re-form of the config group: %d", status)
	}
	for name, device := range map[string]*AdmissionDevice{"the revoked bootstrap sidecar": owner, "a member's device": laptop, "a read_only device": readOnly} {
		if status := world.serveGkm(ladderPath, ladder, device, configAdmin); status != http.StatusForbidden {
			t.Errorf("%s: the re-formed config group's ladder: %d", name, status)
		}
	}
	if world.configClusterObject(gkmservice.GkmGenerationKey(reformedGroupId, 1)) != nil {
		t.Fatal("a refused ladder wrote gen/1")
	}
	if status := world.serveGkm(ladderPath, ladder, ownerPhone, configAdmin); status != http.StatusOK {
		t.Fatalf("the config writer's ladder: %d", status)
	}
	if carried := world.configClusterObject(gkmservice.GkmGenerationKey(reformedGroupId, 1)); !bytes.Equal(carried, rotate1) {
		t.Errorf("gen/1 of the re-formed config group is not the first group's bytes")
	}
	// and activates the repo at evs, its re-formed group ready
	if status, code := world.serveAt(http.MethodPost, "/activate", ownerPhone, configRw); status != http.StatusForbidden || code != protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE {
		t.Errorf("the config writer's activation under the config's rw: %d %s", status, code)
	}
	if status, code := world.serveAt(http.MethodPost, "/activate", ownerPhone, configAdmin); status != http.StatusOK {
		t.Fatalf("the config writer's activation of the config repo: %d %s", status, code)
	}
	activated := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(world.configClusterObject(sidecar.EvsRepoObjectKey(world.configId)), activated); err != nil || activated.GetState() != protocol.EvsRepoState_EVS_REPO_ACTIVE {
		t.Errorf("repo/ after the activation: %v, %v", activated, err)
	}

	// the config writer's admin still drops nothing in the config (D-ACL-25)
	if decision := world.gateAcl().MayDrop(ownerPhone.SidecarId, world.configId, world.net.Clock().Now()); decision.Allowed || decision.Reason != sidecar.AclReasonNoGrant {
		t.Errorf("the config writer's drop in the config: %+v", decision)
	}
}

// QD-894 from the first byte: a network whose bootstrap sidecar is revoked before the config repo is placed. The
// owner's other device, a config writer, places the repo through evs's real guard, as its creator, and forms its
// group at gkm; the revoked bootstrap sidecar places nothing.
func TestAclConfigRepoIsPlacedByAConfigWriterOnceTheBootstrapSidecarIsGone(t *testing.T) {
	world := newAclConfigRepoWorld(t)
	admission := world.admission
	owner := admission.Owner()
	configR, configAdmin := aclConfigRepoScope(world.configId, "r"), aclConfigRepoScope(world.configId, "admin")
	ownerPhone := admission.Device("placed by owner phone", owner.MemberId)
	admission.AdmitDevice(owner, ownerPhone, 0)
	admission.MustLand(admission.Sign(ownerPhone, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(owner, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_REMOVED, 0)))
	world.load()

	if status, code := world.serve(http.MethodPut, owner, configAdmin); status != http.StatusForbidden {
		t.Fatalf("the revoked bootstrap sidecar's PUT: %d %s", status, code)
	}
	if status, code := world.serve(http.MethodGet, ownerPhone, configR); status != http.StatusNotFound || code != protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND {
		t.Fatalf("a read before the repo is placed: %d %s", status, code)
	}
	if status, code := world.serve(http.MethodPut, ownerPhone, configAdmin); status != http.StatusOK {
		t.Fatalf("the config writer's PUT: %d %s", status, code)
	}
	first, err := world.net.Host().Blobs.FirstCluster()
	if err != nil {
		t.Fatal(err)
	}
	place, err := sidecar.ReadEvsRepoPlace(t.Context(), first, world.configId)
	if err != nil || place.CreatorSidecarId != ownerPhone.SidecarId {
		t.Fatalf("place/: %+v, %v", place, err)
	}
	repo := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(world.configClusterObject(sidecar.EvsRepoObjectKey(world.configId)), repo); err != nil {
		t.Fatal(err)
	}
	if repo.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || repo.GetState() != protocol.EvsRepoState_EVS_REPO_KEYING ||
		!bytes.Equal(repo.GetRepoId(), world.configId.Bytes()) {
		t.Fatalf("repo/: %v", repo)
	}
	if status, code := world.serve(http.MethodGet, ownerPhone, configR); status != http.StatusOK {
		t.Errorf("the config writer's read: %d %s", status, code)
	}

	groupId := admission.Id("placed by group")
	if status := world.serveGkm("/gkm/groups", world.groupCreate(owner, groupId), owner, configAdmin); status != http.StatusForbidden {
		t.Errorf("the revoked bootstrap sidecar's creation of the config group: %d", status)
	}
	if status := world.serveGkm("/gkm/groups", world.groupCreate(ownerPhone, groupId), ownerPhone, configAdmin); status != http.StatusOK {
		t.Fatalf("the config writer's creation of the config group: %d", status)
	}
	if world.configClusterObject(gkmservice.GkmGenerationKey(groupId, 1)) == nil {
		t.Error("the config group holds no gen/1")
	}
}

// Every reader of the admission world, full, rows-only and started at a base, builds the same row for the config repo
// from its rows and the Genesis, at a base and in its tail alike, and no reader's rows hold it while nothing shrank
// the config's holders.
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
		if row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || len(row.GetAdmins()) != 0 || row.GetHoldersShrunkAt() != 0 {
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

// QD-762 on the admission world's real writer and every reader it runs: the config's row joins the rows at a
// revocation, the writer's next base compiles it into the base's own rows, which the new device and the gate started at
// that base take with no tail to re-apply, and a later revocation advances it alike at every reader, none forking.
func TestAclConfigRepoRowJoinsTheRowsAndRidesTheWritersBase(t *testing.T) {
	world := newAclConfigRepoWorld(t)
	admission := world.admission
	owner := admission.Owner()
	_, phone := admission.ConsentedMember("config row rides")
	_, laptop := admission.ConsentedMember("config row rides later")
	everyReaderHolds := func(label string, shrunkAt uint64) {
		t.Helper()
		readers := 0
		admission.EveryAcl(func(state *sidecar.ConfigState, acl *sidecar.AclState) error {
			readers += 1
			held := []*protocol.AclRepo{}
			for _, repo := range acl.Rows().GetRepos() {
				if bytes.Equal(repo.GetRepoId(), world.configId.Bytes()) || repo.GetKind() == protocol.RepoKind_REPO_KIND_CONFIG {
					held = append(held, repo)
				}
			}
			want := &protocol.AclRepo{RepoId: world.configId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_CONFIG, HoldersShrunkAt: shrunkAt}
			if (shrunkAt == 0 && len(held) != 0) || (shrunkAt != 0 && (len(held) != 1 || !proto.Equal(held[0], want))) {
				return fmt.Errorf("%s: the rows hold %v", label, held)
			}
			if row := acl.Repo(world.configId); row.GetKind() != protocol.RepoKind_REPO_KIND_CONFIG || row.GetHoldersShrunkAt() != shrunkAt ||
				state.ShrunkAt(world.configId) != shrunkAt {
				return fmt.Errorf("%s: the state's config row %v, want holders_shrunk_at %d", label, row, shrunkAt)
			}
			return nil
		})
		if readers < 2 {
			t.Errorf("%s: %d readers answered", label, readers)
		}
	}
	everyReaderHolds("before any shrink", 0)
	revoked := admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	everyReaderHolds("the revocation", revoked.Pin.GetVersion())
	base := admission.Fold(true)
	if header := admission.State().Base(); header.GetVersion() != base.GetVersion() || header.GetFoldedThrough() != base.GetVersion()-1 {
		t.Fatalf("the writer's base at %d folds through %d", header.GetVersion(), header.GetFoldedThrough())
	}
	everyReaderHolds("the writer's base", revoked.Pin.GetVersion())
	later := admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(laptop, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	everyReaderHolds("a later revocation", later.Pin.GetVersion())
	if forks := admission.Forks(); len(forks) != 0 {
		t.Errorf("readers forked: %v", forks)
	}
}
