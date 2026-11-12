// gkm's two real authorization seams on T2 (QD-718, question keys-m2-17-gkm-auth-state-owner): gkmservice's
// AclGkmAuthState and AclGkmReconcilerState over §8.9's real gate cache, which reads the admission world's log from
// the Net's Redis and first metadata cluster, with gkm's engine and reconciler over them:
//
//	token       a gkm token's scope is honored only by the state: 503 while the network is not loaded, the ask
//	            starting its load, then the config's r for every admitted sidecar, gkm's rw for member devices but
//	            read_only ones, admin for the bootstrap sidecar alone, and 403 for a repo the state does not hold
//	revoked     a SidecarRevoke closes the sidecar's routes at the gate's next load, and a rev/ object voids its
//	            token's writes
//	answers     the gkm-only answers from the same state: a sidecar's facts, readers and writers, pending targets,
//	            pins, a forwarding Delegation's key and reach, late holders and dropped holders
//	reconciler  a hint ({acl_<networkId>}v's INCR) while the load it starts is held open wakes nothing and the old
//	            state still reads; once the load installs, the reconciler's pass reads the new state, never the old
//
// No sleeps: each load is awaited by the cache's OnLoad, a load is held open in its source, and the clock is the
// Net's.

package sidecartest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The gate's source, whose reads of the log a test holds open.
type gkmAclStateSource struct {
	inner     sidecar.AclGateSource
	stateLock sync.Mutex
	// while set, each Entries call reports on started and waits on it
	hold    chan struct{}
	started chan struct{}
}

func (self *gkmAclStateSource) Genesis(ctx context.Context, networkId sidecar.Id) ([]byte, error) {
	return self.inner.Genesis(ctx, networkId)
}

func (self *gkmAclStateSource) Rows(ctx context.Context, networkId sidecar.Id, rowsSha256 []byte) ([]byte, error) {
	return self.inner.Rows(ctx, networkId, rowsSha256)
}

func (self *gkmAclStateSource) Entries(ctx context.Context, networkId sidecar.Id, after *bridge.AuthPin) ([][]byte, error) {
	hold := func() chan struct{} {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.hold
	}()
	if hold != nil {
		self.started <- struct{}{}
		select {
		case <-hold:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return self.inner.Entries(ctx, networkId, after)
}

// Holds every load from now on open; the returned call lets them through.
func (self *gkmAclStateSource) holdLoads() (release func()) {
	hold := make(chan struct{})
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.hold = hold
	return func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.hold = nil
		close(hold)
	}
}

// rev/ as a test fills it: the sidecars an object voids.
type gkmAclStateRevocations struct {
	stateLock sync.Mutex
	voided    map[sidecar.Id]bool
}

func (self *gkmAclStateRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if principal.SidecarId != nil && self.voided[sidecar.Id(*principal.SidecarId)] {
		return sidecar.ErrRevocationVoidsToken
	}
	return nil
}

func (self *gkmAclStateRevocations) void(sidecarId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.voided[sidecarId] = true
}

// The world: the Net, its admission network, the real gate cache and gkm's real state and engine over it.
type gkmAclStateWorld struct {
	t           *testing.T
	net         *Net
	admission   *AdmissionNet
	source      *gkmAclStateSource
	cache       *sidecar.AclGateCache
	loads       chan *bridge.AuthPin
	revocations *gkmAclStateRevocations
	state       *gkmservice.AclGkmAuthState
	engine      *gkmservice.GkmEngine
	configId    sidecar.Id
}

func newGkmAclStateWorld(t *testing.T) *gkmAclStateWorld {
	net := NewNet(t.Context(), nil)
	t.Cleanup(net.Close)
	tier, err := net.AdmissionTier()
	if err != nil {
		t.Fatal(err)
	}
	tier.AclCompile = AclAdmissionCompile
	admission := NewAdmissionNet(t, tier)
	t.Cleanup(admission.Close)
	world := &gkmAclStateWorld{
		t: t, net: net, admission: admission, loads: make(chan *bridge.AuthPin, 256),
		revocations: &gkmAclStateRevocations{voided: map[sidecar.Id]bool{}},
		configId:    admission.ConfigRepoId(),
	}
	net.Fakes().Gates.OpenService(sidecar.ServiceGateGkm, connect.Id(admission.NetworkId()))

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
	world.source = &gkmAclStateSource{
		inner:   sidecar.NewAclGateDirectSource(net.Host().Redis, net.Host().Blobs, gateSettings),
		started: make(chan struct{}, 256),
	}
	world.cache = sidecar.NewAclGateCache(admission.Context(), world.source, net.Clock(), gateSettings)
	world.state = gkmservice.NewAclGkmAuthState(world.cache, world.revocations, net.Clock())
	world.engine, err = gkmservice.NewGkmEngine(t.Context(), net.Host(), nil, &gkmservice.GkmEngineDeps{AuthState: world.state})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(world.engine.Close)
	return world
}

// Fails the test after a real-time bound that only a broken cache or reconciler reaches.
func gkmAclStateAwait[T any](t *testing.T, what string, values chan T) T {
	t.Helper()
	select {
	case value := <-values:
		return value
	case <-time.After(60 * time.Second):
		t.Fatalf("no %s", what)
	}
	var none T
	return none
}

// Waits for the gate's loads to reach the log's tip, starting none.
func (self *gkmAclStateWorld) awaitTip() {
	self.t.Helper()
	want := self.admission.Tip()
	for {
		gkmAclStateAwait(self.t, "load", self.loads)
		snapshot, status := self.cache.State(self.admission.NetworkId())
		if status == sidecar.AclGateLoaded && snapshot != nil && proto.Equal(snapshot.Pin, want) {
			return
		}
		self.cache.Changed(self.admission.NetworkId())
	}
}

// Tells the gate the log moved and waits for its load to reach the tip.
func (self *gkmAclStateWorld) load() {
	self.t.Helper()
	self.cache.Changed(self.admission.NetworkId())
	self.awaitTip()
}

// What api's script does after an entry, the part a gate hears: the INCR of {acl_<networkId>}v.
func (self *gkmAclStateWorld) hint() {
	self.t.Helper()
	if _, err := self.net.Host().Redis.Increment(self.t.Context(), sidecar.AclVersionKey(self.admission.NetworkId()), 48*time.Hour); err != nil {
		self.t.Fatal(err)
	}
}

// A gkm token's principal for the device's sidecar carrying scopes, as the exchange would mint it.
func (self *gkmAclStateWorld) principal(device *AdmissionDevice, scopes ...string) *sidecar.Principal {
	sidecarId := connect.Id(device.SidecarId)
	now := self.net.Clock().Now()
	return &sidecar.Principal{
		NetworkId: connect.Id(self.admission.NetworkId()),
		ClientId:  connect.Id(self.admission.Id("gkm client of " + device.SidecarId.String())),
		SidecarId: &sidecarId,
		Audience:  gkmservice.GkmAudience,
		Scopes:    scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
}

// One request of the device to gkm with the scopes its token carries: the status.
func (self *gkmAclStateWorld) serve(method string, path string, device *AdmissionDevice, scopes ...string) int {
	self.t.Helper()
	return self.serveBody(method, path, nil, device, scopes...)
}

// serve, with a body.
func (self *gkmAclStateWorld) serveBody(method string, path string, body []byte, device *AdmissionDevice, scopes ...string) int {
	self.t.Helper()
	request := httptest.NewRequestWithContext(self.t.Context(), method, path, bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer "+self.net.Fakes().Authenticator.Issue(self.principal(device, scopes...)))
	recorder := httptest.NewRecorder()
	self.engine.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// The device's ReaderKey, signed by its identity key now and good for six days, as its upkeep uploads it.
func (self *gkmAclStateWorld) readerKey(device *AdmissionDevice) []byte {
	self.t.Helper()
	now := self.net.Clock().Now()
	signed, _, err := sidecar.NewGkmReaderKey(device.SidecarId, now, now.Add(6*24*time.Hour),
		func(purpose string, signedType bridge.SignedType, body []byte, agentId *sidecar.Id) (*bridge.Signed, error) {
			return &bridge.Signed{
				Body:      bytes.Clone(body),
				SignerId:  device.SidecarId.Bytes(),
				Signature: ed25519.Sign(device.Key, bridge.SignedBytes(purpose, signedType, body)),
				Type:      uint32(signedType),
			}, nil
		})
	if err != nil {
		self.t.Fatal(err)
	}
	signedBytes, err := proto.Marshal(signed)
	if err != nil {
		self.t.Fatal(err)
	}
	return signedBytes
}

// Places a repo on the first cluster, as evs's PUT does at its creation, so gkm resolves its cluster.
func (self *gkmAclStateWorld) place(repoId sidecar.Id, creator *AdmissionDevice) {
	self.t.Helper()
	first, err := self.net.Host().Blobs.FirstCluster()
	if err != nil {
		self.t.Fatal(err)
	}
	place, err := (&sidecar.EvsRepoPlace{ClusterId: first.ClusterId(), CreatorSidecarId: creator.SidecarId}).Marshal()
	if err != nil {
		self.t.Fatal(err)
	}
	if _, err := first.PutIfNoneMatch(self.t.Context(), sidecar.EvsPlaceKey(repoId), place, nil); err != nil {
		self.t.Fatal(err)
	}
}

func gkmAclStateScope(repoId sidecar.Id, role string) string {
	return "repo:" + repoId.String() + ":" + role
}

func gkmAclStateFormsPath(repoId sidecar.Id) string {
	return "/gkm/repos/" + sidecar.EvsKeyId(repoId) + "/forms"
}

func gkmAclStateSorted(devices ...*AdmissionDevice) []sidecar.Id {
	sidecarIds := []sidecar.Id{}
	for _, device := range devices {
		sidecarIds = append(sidecarIds, device.SidecarId)
	}
	slices.SortFunc(sidecarIds, sidecar.Id.Cmp)
	return sidecarIds
}

// A token is judged by the gate's newest verified state alone: nothing is honored cold, each scope follows the
// state's rights for the gkm audience exactly as the cache's own HonorScope answers them, a revocation closes a
// sidecar's routes at the next load, a rev/ object voids its token, and every gkm-only answer reads the same state.
func TestGkmAuthStateJudgesATokenByTheGatesState(t *testing.T) {
	world := newGkmAclStateWorld(t)
	admission := world.admission
	owner := admission.Owner()
	now := world.net.Clock().Now
	configR := gkmAclStateScope(world.configId, "r")
	forms := gkmAclStateFormsPath(world.configId)

	// cold: the cache has not heard of the network, so nothing is honored, and the ask starts its load, held open
	// here so that the answers while it runs are read
	release := world.source.holdLoads()
	if status := world.serve(http.MethodGet, forms, owner, configR); status != http.StatusServiceUnavailable {
		t.Fatalf("a request before the network's state is loaded: %d", status)
	}
	gkmAclStateAwait(t, "load started by the ask", world.source.started)
	if answer := world.state.HonorScope(world.principal(owner), world.configId, sidecar.AclEvsRead, now()); answer != gkmservice.GkmAuthUnknown {
		t.Fatalf("a scope honored while the network loads: %d", answer)
	}
	if status := world.serve(http.MethodGet, forms, owner, configR); status != http.StatusServiceUnavailable {
		t.Fatalf("a request while the network loads: %d", status)
	}
	release()
	world.awaitTip()
	world.place(world.configId, owner)
	if status := world.serve(http.MethodGet, forms, owner, configR); status != http.StatusOK {
		t.Fatalf("the bootstrap sidecar's read: %d", status)
	}
	stranger := admission.Id("gkm no such repo")
	world.place(stranger, owner)
	if status := world.serve(http.MethodGet, gkmAclStateFormsPath(stranger), owner, gkmAclStateScope(stranger, "r")); status != http.StatusForbidden {
		t.Errorf("a scope on a repo the state does not hold: %d", status)
	}

	// the network's later devices
	ownerPhone := admission.Device("gkm owner phone", owner.MemberId)
	admission.AdmitDevice(owner, ownerPhone, 0)
	memberId, phone := admission.ConsentedMember("gkm state")
	secondPhone := admission.Device("gkm state second device", memberId)
	admission.AdmitDevice(owner, secondPhone, 0)
	readOnly := admission.Device("gkm state read only", memberId)
	admission.AdmitDevice(owner, readOnly, uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY))
	ephemeral := admission.Device("gkm state ephemeral", memberId)
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT,
		admission.Admission(ephemeral, nil, true, now().Add(24*time.Hour).UnixMilli(), 0)))
	world.load()

	allowed, denied := gkmservice.GkmAuthAllowed, gkmservice.GkmAuthDenied
	read, write, admin := sidecar.AclEvsRead, sidecar.AclEvsWrite, sidecar.AclEvsAdmin
	scopes := []struct {
		name   string
		device *AdmissionDevice
		rights map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer
	}{
		{name: "the bootstrap sidecar", device: owner, rights: map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer{read: allowed, write: allowed, admin: allowed}},
		{name: "another config writer", device: ownerPhone, rights: map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer{read: allowed, write: allowed, admin: denied}},
		{name: "a member device", device: phone, rights: map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer{read: allowed, write: allowed, admin: denied}},
		{name: "a read_only device", device: readOnly, rights: map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer{read: allowed, write: denied, admin: denied}},
		{name: "an ephemeral device", device: ephemeral, rights: map[sidecar.AclEvsRights]gkmservice.GkmAuthAnswer{read: allowed, write: denied, admin: denied}},
	}
	for _, c := range scopes {
		for right, want := range c.rights {
			if answer := world.state.HonorScope(world.principal(c.device), world.configId, right, now()); answer != want {
				t.Errorf("%s: right %b on the config: %d, want %d", c.name, right, answer, want)
			}
			// the state's answer is the cache's own for the gkm audience: no second scope check
			cacheAnswer := world.cache.HonorScope(admission.NetworkId(), c.device.SidecarId, world.configId, right, sidecar.AclTokenAudienceGkm, now())
			if (cacheAnswer == sidecar.AclScopeHonored) != (want == allowed) {
				t.Errorf("%s: the cache's answer for right %b: %d", c.name, right, cacheAnswer)
			}
		}
		if status := world.serve(http.MethodGet, forms, c.device, configR); status != http.StatusOK {
			t.Errorf("%s: gkm's read under the config's r: %d", c.name, status)
		}
	}
	if answer := world.state.HonorScope(&sidecar.Principal{NetworkId: connect.Id(admission.NetworkId())}, world.configId, read, now()); answer != denied {
		t.Errorf("a token naming no sidecar: %d", answer)
	}

	// a sidecar's facts
	facts, answer := world.state.Sidecar(world.principal(owner), owner.SidecarId)
	if answer != allowed || !facts.MemberDevice || facts.MemberId == nil || *facts.MemberId != owner.MemberId || !bytes.Equal(facts.IdentityPublicKey, owner.PublicKey()) ||
		facts.ReadOnly || facts.Revoked || facts.Parked || facts.Suspended || facts.CoveringDelegationId != nil {
		t.Errorf("the bootstrap sidecar's facts: %+v, %d", facts, answer)
	}
	if facts, answer := world.state.Sidecar(world.principal(owner), readOnly.SidecarId); answer != allowed || !facts.ReadOnly || !facts.MemberDevice {
		t.Errorf("a read_only device's facts: %+v, %d", facts, answer)
	}
	if facts, answer := world.state.Sidecar(world.principal(owner), ephemeral.SidecarId); answer != allowed || facts.MemberDevice {
		t.Errorf("an ephemeral device's facts: %+v, %d", facts, answer)
	}
	if facts, answer := world.state.Sidecar(world.principal(owner), admission.Id("gkm stranger")); answer != denied || facts != nil {
		t.Errorf("a sidecar the log never admitted: %+v, %d", facts, answer)
	}

	// readers, writers and who a first KeyPackage upload's hint goes to
	if answer := world.state.Reads(world.principal(owner), world.configId, phone.SidecarId, now()); answer != allowed {
		t.Errorf("a member device reads the config: %d", answer)
	}
	if answer := world.state.Reads(world.principal(owner), world.configId, admission.Id("gkm stranger"), now()); answer != denied {
		t.Errorf("a stranger reads the config: %d", answer)
	}
	everyone := gkmAclStateSorted(owner, ownerPhone, phone, secondPhone, readOnly, ephemeral)
	if readerIds, answer := world.state.RepoReaders(world.principal(owner), world.configId, now()); answer != allowed || !slices.Equal(readerIds, everyone) {
		t.Errorf("the config's readers: %v, %d, want %v", readerIds, answer, everyone)
	}
	writers := gkmAclStateSorted(owner, ownerPhone)
	if writerIds, answer := world.state.RepoWriters(world.principal(owner), world.configId, now()); answer != allowed || !slices.Equal(writerIds, writers) {
		t.Errorf("the config's writers: %v, %d, want %v", writerIds, answer, writers)
	}
	targets, answer := world.state.PendingTargets(world.principal(phone), phone.SidecarId, now())
	if answer != allowed || len(targets) != 1 || targets[0].RepoId != world.configId || !slices.Equal(targets[0].SidecarIds, writers) {
		t.Errorf("a member device's pending targets: %+v, %d", targets, answer)
	}

	// pins: the tip agrees, one past it is not reached yet, one off the chain or missing is refused
	tip := admission.Tip()
	if answer := world.state.CheckPin(world.principal(owner), tip); answer != allowed {
		t.Errorf("the tip's pin: %d", answer)
	}
	if answer := world.state.CheckPin(world.principal(owner), &bridge.AuthPin{Version: tip.GetVersion() + 1, Chain: tip.GetChain()}); answer != gkmservice.GkmAuthUnknown {
		t.Errorf("a pin past the state: %d", answer)
	}
	forked := sha256.Sum256([]byte("gkm state forked chain"))
	if answer := world.state.CheckPin(world.principal(owner), &bridge.AuthPin{Version: tip.GetVersion(), Chain: forked[:]}); answer != denied {
		t.Errorf("a pin off the chain: %d", answer)
	}
	if answer := world.state.CheckPin(world.principal(owner), nil); answer != denied {
		t.Errorf("no pin: %d", answer)
	}

	// a late ask is widened to who may sign a LATE delivery: the recipient's member's other device first, then the
	// rest, member devices before the ephemeral one, never the recipient or a read_only device
	lateIds, answer := world.state.LateHolders(world.principal(phone), world.configId, "s:"+hex.EncodeToString(phone.SidecarId.Bytes()), now())
	wantLate := slices.Concat([]sidecar.Id{secondPhone.SidecarId}, gkmAclStateSorted(owner, ownerPhone), []sidecar.Id{ephemeral.SidecarId})
	if answer != allowed || !slices.Equal(lateIds, wantLate) {
		t.Errorf("the late holders: %v, %d, want %v", lateIds, answer, wantLate)
	}
	if _, answer := world.state.LateHolders(world.principal(phone), world.configId, "nobody", now()); answer != denied {
		t.Errorf("a late ask naming nothing: %d", answer)
	}

	// dropped holders: none since the tip; no pin, and a repo the state does not hold, cannot be told
	if answer := world.state.HoldersDropped(world.principal(owner), world.configId, tip, now(), now()); answer != denied {
		t.Errorf("holders dropped since the tip: %d", answer)
	}
	if answer := world.state.HoldersDropped(world.principal(owner), world.configId, nil, now(), now()); answer != gkmservice.GkmAuthUnknown {
		t.Errorf("holders dropped since no pin: %d", answer)
	}
	if answer := world.state.HoldersDropped(world.principal(owner), stranger, tip, now(), now()); answer != gkmservice.GkmAuthUnknown {
		t.Errorf("holders dropped in a repo the state does not hold: %d", answer)
	}

	// a forwarding Delegation of the phone: its key facts from its row, and its reach the config alone while it lives
	forwardingSeed := sha256.Sum256([]byte("gkm state forwarding key"))
	forwardingKey := ed25519.NewKeyFromSeed(forwardingSeed[:])
	readerKey := bytes.Repeat([]byte{0x5a}, 1216)
	forwarding := admission.Sign(phone, bridge.SignedType_SIGNED_DELEGATION, &protocol.Delegation{
		Header:               admission.Header(),
		Pubkey:               forwardingKey.Public().(ed25519.PublicKey),
		ReaderXwingPublicKey: readerKey,
		Forward:              &bridge.ForwardScope{ForwardSidecarId: phone.SidecarId.Bytes()},
	})
	admission.MustLand(forwarding)
	world.load()
	delegationId := AdmissionStatementId(forwarding)
	readerKeySha256 := sha256.Sum256(readerKey)
	keyFacts, answer := world.state.DelegationKey(world.principal(phone), delegationId)
	if answer != allowed || keyFacts.ForwardSidecarId == nil || *keyFacts.ForwardSidecarId != phone.SidecarId || keyFacts.ConfigRepoId != world.configId ||
		!bytes.Equal(keyFacts.ReaderKeySha256, readerKeySha256[:]) {
		t.Errorf("a forwarding Delegation's key facts: %+v, %d", keyFacts, answer)
	}
	if keyFacts, answer := world.state.DelegationKey(world.principal(phone), forked[:]); answer != denied || keyFacts != nil {
		t.Errorf("a Delegation the state holds no row of: %+v, %d", keyFacts, answer)
	}
	if answer := world.state.DelegationReads(world.principal(owner), world.configId, delegationId, now()); answer != allowed {
		t.Errorf("a live forwarding Delegation reads the config: %d", answer)
	}
	if answer := world.state.DelegationReads(world.principal(owner), stranger, delegationId, now()); answer != denied {
		t.Errorf("a forwarding Delegation reads a repo the state does not hold: %d", answer)
	}
	admission.MustLand(admission.Sign(phone, bridge.SignedType_SIGNED_DELEGATION_REVOKE, admission.DelegationRevoke(delegationId, 0)))
	world.load()
	if answer := world.state.DelegationReads(world.principal(owner), world.configId, delegationId, now()); answer != denied {
		t.Errorf("a revoked forwarding Delegation reads the config: %d", answer)
	}
	if _, answer := world.state.DelegationKey(world.principal(phone), delegationId); answer != allowed {
		t.Errorf("an ended Delegation's key facts: %d", answer)
	}

	// a revocation closes the sidecar's routes at the gate's next load, and no one else's
	beforeRevocation := admission.Tip()
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	if status := world.serve(http.MethodGet, forms, phone, configR); status != http.StatusOK {
		t.Fatalf("the phone's read before the gate loaded its revocation: %d", status)
	}
	world.load()
	if status := world.serve(http.MethodGet, forms, phone, configR); status != http.StatusForbidden {
		t.Errorf("a revoked sidecar's read: %d", status)
	}
	if answer := world.state.HonorScope(world.principal(phone), world.configId, read, now()); answer != denied {
		t.Errorf("a revoked sidecar's config r: %d", answer)
	}
	if facts, answer := world.state.Sidecar(world.principal(owner), phone.SidecarId); answer != allowed || !facts.Revoked {
		t.Errorf("a revoked sidecar's facts: %+v, %d", facts, answer)
	}
	if status := world.serve(http.MethodGet, forms, secondPhone, configR); status != http.StatusOK {
		t.Errorf("another device's read after the revocation: %d", status)
	}
	// the revocation dropped a key holder of the config: a shrink since the pin before it, none since the tip
	if answer := world.state.HoldersDropped(world.principal(owner), world.configId, beforeRevocation, now(), now()); answer != allowed {
		t.Errorf("holders dropped since the pin before the revocation: %d", answer)
	}
	if answer := world.state.HoldersDropped(world.principal(owner), world.configId, admission.Tip(), now(), now()); answer != denied {
		t.Errorf("holders dropped since the revocation's own pin: %d", answer)
	}

	// rev/, read on every write (§7.8), voids a token whatever the state gives its sidecar, and no other sidecar's:
	// a device's ReaderKey upload is checked under the identity key the state's row holds for it
	if status := world.serveBody(http.MethodPost, "/gkm/reader-key", world.readerKey(ephemeral), ephemeral, configR); status != http.StatusOK {
		t.Fatalf("a ReaderKey upload before any rev/ object: %d", status)
	}
	world.revocations.void(ephemeral.SidecarId)
	if status := world.serveBody(http.MethodPost, "/gkm/reader-key", world.readerKey(ephemeral), ephemeral, configR); status != http.StatusUnauthorized {
		t.Errorf("a write under a token a rev/ object voids: %d", status)
	}
	if status := world.serveBody(http.MethodPost, "/gkm/reader-key", world.readerKey(secondPhone), secondPhone, configR); status != http.StatusOK {
		t.Errorf("another sidecar's ReaderKey upload: %d", status)
	}
	if status := world.serveBody(http.MethodPost, "/gkm/reader-key", world.readerKey(secondPhone), readOnly, configR); status != http.StatusForbidden {
		t.Errorf("a ReaderKey another sidecar's key signed: %d", status)
	}
	if err := gkmservice.NewAclGkmAuthState(world.cache, nil, nil).CheckRevocation(t.Context(), world.principal(owner)); err == nil {
		t.Error("a state with no rev/ reader passed a token")
	}
}

// The reconciler's state as a real reconciler reads it, recording the pin of every state it was given.
type gkmAclStateRecorder struct {
	inner gkmservice.GkmReconcilerState
	reads chan *bridge.AuthPin
}

func (self *gkmAclStateRecorder) Watch(changed func(change *gkmservice.GkmStateChange)) (func(), error) {
	return self.inner.Watch(changed)
}

func (self *gkmAclStateRecorder) Networks() []sidecar.Id {
	return self.inner.Networks()
}

func (self *gkmAclStateRecorder) State(ctx context.Context, networkId sidecar.Id) (*gkmservice.GkmNetworkState, error) {
	state, err := self.inner.State(ctx, networkId)
	if err != nil {
		self.reads <- nil
		return nil, err
	}
	self.reads <- state.View.Pin()
	return state, nil
}

func (self *gkmAclStateRecorder) SidecarStanding(ctx context.Context, sidecarId sidecar.Id) (sidecar.Id, bool, bool, error) {
	return self.inner.SidecarStanding(ctx, sidecarId)
}

// A hint says the log moved, not that the gate has read it: while the load a hint starts is held open the reconciler
// is told nothing and the state still reads the old position, and once the load installs, the pass it wakes reads
// the new state. A sidecar's network and its revocation come from the same installed state.
func TestGkmReconcilerStateIsToldOnceTheGateInstalls(t *testing.T) {
	world := newGkmAclStateWorld(t)
	admission := world.admission
	owner := admission.Owner()
	networkId := admission.NetworkId()
	ctx := t.Context()
	stopWatch, err := world.cache.Watch(world.net.Host().Redis)
	if err != nil {
		t.Fatal(err)
	}
	defer stopWatch()

	state := gkmservice.NewAclGkmReconcilerState(world.cache)
	changes := make(chan *gkmservice.GkmStateChange, 64)
	stopChanges, err := state.Watch(func(change *gkmservice.GkmStateChange) {
		changes <- change
	})
	if err != nil {
		t.Fatal(err)
	}
	defer stopChanges()
	if change := gkmAclStateAwait(t, "first change", changes); change != nil {
		t.Fatalf("the watch's first change: %+v", change)
	}
	if networkIds := state.Networks(); len(networkIds) != 0 {
		t.Fatalf("networks before any load: %v", networkIds)
	}
	if _, err := state.State(ctx, networkId); err == nil {
		t.Fatal("a state before any load")
	}
	if _, _, known, err := state.SidecarStanding(ctx, owner.SidecarId); err != nil || known {
		t.Fatalf("a sidecar's standing before any load: %t, %v", known, err)
	}
	if _, err := gkmservice.NewAclGkmReconcilerState(nil).Watch(func(change *gkmservice.GkmStateChange) {}); err == nil {
		t.Fatal("a state with no gate cache took a watch")
	}

	recorder := &gkmAclStateRecorder{inner: state, reads: make(chan *bridge.AuthPin, 64)}
	reconciler, err := gkmservice.NewGkmReconciler(ctx, world.net.Host(), nil, &gkmservice.GkmReconcilerDeps{State: recorder})
	if err != nil {
		t.Fatal(err)
	}
	defer reconciler.Close()

	// the first hint: the network loads, and the reconciler reads it at the tip
	world.hint()
	change := gkmAclStateAwait(t, "change", changes)
	if change == nil || change.NetworkId != networkId {
		t.Fatalf("the first install's change: %+v", change)
	}
	if pin := gkmAclStateAwait(t, "reconciler read", recorder.reads); !proto.Equal(pin, admission.Tip()) {
		t.Fatalf("the reconciler read %d, the tip is %d", pin.GetVersion(), admission.Tip().GetVersion())
	}
	if networkIds := state.Networks(); !slices.Equal(networkIds, []sidecar.Id{networkId}) {
		t.Fatalf("the networks: %v", networkIds)
	}
	old := admission.Tip()
	networkState, err := state.State(ctx, networkId)
	if err != nil || !proto.Equal(networkState.View.Pin(), old) || !slices.Contains(networkState.RepoIds, world.configId) {
		t.Fatalf("the network's state: %+v, %v", networkState, err)
	}
	if standingNetworkId, revoked, known, err := state.SidecarStanding(ctx, owner.SidecarId); err != nil || !known || revoked || standingNetworkId != networkId {
		t.Fatalf("the owner's standing: %s, %t, %t, %v", standingNetworkId, revoked, known, err)
	}

	// the log moves and the hint comes, while the load it starts is held open
	memberId, phone := admission.ConsentedMember("gkm reconciler")
	_ = memberId
	moved := admission.Tip()
	for len(world.source.started) != 0 {
		<-world.source.started
	}
	release := world.source.holdLoads()
	world.hint()
	gkmAclStateAwait(t, "held load", world.source.started)
	select {
	case change := <-changes:
		t.Fatalf("a change before the load installed: %+v", change)
	case pin := <-recorder.reads:
		t.Fatalf("the reconciler read %d on the hint alone", pin.GetVersion())
	default:
	}
	// what a reader woken by the hint itself would have seen: the state before
	if held, err := state.State(ctx, networkId); err != nil || !proto.Equal(held.View.Pin(), old) {
		t.Fatalf("the state while the load is held: %v", err)
	}
	if _, _, known, _ := state.SidecarStanding(ctx, phone.SidecarId); known {
		t.Fatal("a sidecar's standing known before its admission installed")
	}
	release()
	change = gkmAclStateAwait(t, "change", changes)
	if change == nil || change.NetworkId != networkId || change.SignerId == nil {
		t.Fatalf("the install's change: %+v", change)
	}
	if pin := gkmAclStateAwait(t, "reconciler read", recorder.reads); !proto.Equal(pin, moved) {
		t.Fatalf("the reconciler read %d after the install, the tip is %d", pin.GetVersion(), moved.GetVersion())
	}
	if standingNetworkId, revoked, known, err := state.SidecarStanding(ctx, phone.SidecarId); err != nil || !known || revoked || standingNetworkId != networkId {
		t.Fatalf("the admitted device's standing: %s, %t, %t, %v", standingNetworkId, revoked, known, err)
	}

	// a revocation: told with its signer, read at its position, and the sidecar's standing follows
	admission.MustLand(admission.Sign(owner, bridge.SignedType_SIGNED_SIDECAR_REVOKE, admission.Revocation(phone, bridge.SidecarRevokeReason_SIDECAR_REVOKE_REASON_LOST, 0)))
	revokedAt := admission.Tip()
	world.hint()
	change = gkmAclStateAwait(t, "change", changes)
	if change == nil || change.SignerId == nil || *change.SignerId != owner.SidecarId {
		t.Fatalf("the revocation's change: %+v", change)
	}
	if pin := gkmAclStateAwait(t, "reconciler read", recorder.reads); !proto.Equal(pin, revokedAt) {
		t.Fatalf("the reconciler read %d after the revocation, the tip is %d", pin.GetVersion(), revokedAt.GetVersion())
	}
	if _, revoked, known, err := state.SidecarStanding(ctx, phone.SidecarId); err != nil || !known || !revoked {
		t.Fatalf("the revoked device's standing: %t, %t, %v", revoked, known, err)
	}
	networkState, err = state.State(ctx, networkId)
	if err != nil {
		t.Fatal(err)
	}
	if at, known := networkState.PositionTime(revokedAt.GetVersion()); !known || at.UnixMilli() != admission.State().TimeMs() {
		t.Errorf("the revocation's time: %v, %t", at, known)
	}
	if _, known := networkState.PositionTime(revokedAt.GetVersion() + 1); known {
		t.Error("a position past the state has a time")
	}
	select {
	case pin := <-recorder.reads:
		t.Errorf("a read no change asked for, at %d", pin.GetVersion())
	default:
	}
}
