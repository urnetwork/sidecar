package computeservice

// The real ComputeAuthState (CSRV-M12-01, §14.2's Auth row) over hand-installed states, as the process's AclGateCache
// would hold them: the caller read from its row, a sidecar out of standing refused, rev/'s answers mapped, the features
// read from ProjectionSettings' field 3 whether this build declares it or not, and the guard running on it.

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// rev/ as a test says it reads.
type testComputeRevocations struct {
	err   error
	count int
}

func (self *testComputeRevocations) Check(ctx context.Context, principal *sidecar.Principal) error {
	self.count += 1
	return self.err
}

// Hand-made loaded states by network, each with a zero ConfigState beside its acl part, whose settings are the
// defaults: what the real state reads.
type testComputeGate struct {
	snapshots map[sidecar.Id]*sidecar.AclGateSnapshot
	changed   []sidecar.Id
}

func newTestComputeGate() *testComputeGate {
	return &testComputeGate{snapshots: map[sidecar.Id]*sidecar.AclGateSnapshot{}}
}

// Builds the network's state from rows and view and installs it.
func (self *testComputeGate) install(t testing.TB, networkId sidecar.Id, rows *protocol.AclRows, view *sidecartest.FakeAclView) {
	t.Helper()
	acl, err := sidecar.NewAclState(rows, view)
	if err != nil {
		t.Fatal(err)
	}
	self.snapshots[networkId] = &sidecar.AclGateSnapshot{Pin: view.Pin(), Config: &sidecar.ConfigState{}, Acl: acl}
}

func (self *testComputeGate) State(networkId sidecar.Id) (*sidecar.AclGateSnapshot, sidecar.AclGateStatus) {
	snapshot := self.snapshots[networkId]
	if snapshot == nil {
		return nil, sidecar.AclGateUnknown
	}
	return snapshot, sidecar.AclGateLoaded
}

func (self *testComputeGate) Changed(networkId sidecar.Id) {
	self.changed = append(self.changed, networkId)
}

// A principal for sidecarId of networkId, audience compute.
func testComputePrincipal(networkId sidecar.Id, sidecarId sidecar.Id) *sidecar.Principal {
	sidecarConnectId := connect.Id(sidecarId)
	return &sidecar.Principal{
		NetworkId: connect.Id(networkId),
		ClientId:  connect.Id(testComputeId("client-" + string(sidecarId[:4]))),
		SidecarId: &sidecarConnectId,
		Audience:  ComputeAudience,
	}
}

// A member device's caller carries its member, role, consent and flags from its row; a tagged agent's carries its tags
// and no member; the read_only and enclave bits, a Delegation and an ephemeral admission each show.
func TestComputeAuthStateReadsTheCallerFromTheState(t *testing.T) {
	networkId := testComputeId("network-a")
	view := sidecartest.NewFakeAclView()
	memberId := view.AddMember(bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN)
	device := view.AddDevice(memberId)
	reader := view.AddDevice(memberId)
	view.Sidecar(reader).Row.Capabilities |= uint32(bridge.SidecarCapability_SIDECAR_CAPABILITY_READ_ONLY)
	view.Sidecar(reader).Row.DelegationId = testComputeId("delegation-1").Bytes()
	tagId := testComputeId("tag-ci")
	agent := view.AddAgent(memberId, tagId)
	view.Sidecar(agent).Row.Capabilities |= computeSidecarCapabilityEnclave
	view.Sidecar(agent).Ephemeral = true
	gate := newTestComputeGate()
	gate.install(t, networkId, &protocol.AclRows{}, view)
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	state := NewComputeAuthState(gate, &testComputeRevocations{}, clock)

	caller, answer := state.Caller(testComputePrincipal(networkId, device))
	if answer != ComputeAuthAllowed || caller.SidecarId != device || caller.NetworkId != networkId || caller.MemberId != memberId ||
		caller.Role != bridge.MemberRole_MEMBER_ROLE_BILLING_ADMIN || caller.Tagged() || caller.ReadOnly || caller.EnclaveIncarnation ||
		caller.DelegationAdmitted || caller.Snapshot == nil {
		t.Fatalf("the member device's caller is %+v (%v)", caller, answer)
	}
	caller, answer = state.Caller(testComputePrincipal(networkId, reader))
	if answer != ComputeAuthAllowed || !caller.ReadOnly || !caller.DelegationAdmitted {
		t.Fatalf("the read_only device's caller is %+v (%v)", caller, answer)
	}
	caller, answer = state.Caller(testComputePrincipal(networkId, agent))
	if answer != ComputeAuthAllowed || caller.MemberId != (sidecar.Id{}) || !caller.Tagged() || caller.TagIds[0] != tagId ||
		caller.Role != bridge.MemberRole_MEMBER_ROLE_UNSPECIFIED || !caller.EnclaveIncarnation || !caller.Ephemeral {
		t.Fatalf("the agent's caller is %+v (%v)", caller, answer)
	}
}

// A sidecar the state never admitted, one it revoked, one parked, one suspended, one past its not_after, one another
// network admitted and a token naming no sidecar are each refused, and nothing is allowed while the state is unknown.
func TestComputeAuthStateRefusesWhatHasNoStanding(t *testing.T) {
	networkId := testComputeId("network-a")
	otherNetworkId := testComputeId("network-b")
	clock := sidecartest.NewFakeClock(sidecartest.DefaultClockStart())
	view := sidecartest.NewFakeAclView()
	memberId := view.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	revoked := view.AddDevice(memberId)
	view.Revoke(revoked)
	parked := view.AddDevice(memberId)
	view.Park(parked)
	suspended := view.AddDevice(memberId)
	expired := view.AddDevice(memberId)
	view.Sidecar(expired).Row.NotAfter = clock.Now().UnixMilli()
	standing := view.AddDevice(memberId)
	otherView := sidecartest.NewFakeAclView()
	elsewhere := otherView.AddDevice(otherView.AddMember(bridge.MemberRole_MEMBER_ROLE_MEMBER))
	gate := newTestComputeGate()
	gate.install(t, networkId, &protocol.AclRows{Suspensions: []*protocol.AclSuspension{{
		Subject: suspended.Bytes(), SuspendId: testComputeId("suspend").Bytes(), SignerClass: 2, Signer: testComputeId("admin").Bytes(), At: 3,
	}}}, view)
	gate.install(t, otherNetworkId, &protocol.AclRows{}, otherView)
	state := NewComputeAuthState(gate, &testComputeRevocations{}, clock)

	for label, sidecarId := range map[string]sidecar.Id{
		"never admitted": testComputeId("sidecar-x"), "revoked": revoked, "parked": parked, "suspended": suspended,
		"past its not_after": expired, "admitted elsewhere": elsewhere,
	} {
		if caller, answer := state.Caller(testComputePrincipal(networkId, sidecarId)); caller != nil || answer != ComputeAuthDenied {
			t.Errorf("%s: %v", label, answer)
		}
	}
	if _, answer := state.Caller(testComputePrincipal(networkId, standing)); answer != ComputeAuthAllowed {
		t.Fatalf("the device in standing: %v", answer)
	}
	noSidecar := testComputePrincipal(networkId, standing)
	noSidecar.SidecarId = nil
	if _, answer := state.Caller(noSidecar); answer != ComputeAuthDenied {
		t.Errorf("a token naming no sidecar: %v", answer)
	}
	if _, answer := state.Caller(testComputePrincipal(testComputeId("network-c"), standing)); answer != ComputeAuthUnknown {
		t.Errorf("an unloaded network: %v", answer)
	}
	if features, answer := state.Features(networkId); features != 0 || answer != ComputeAuthAllowed {
		t.Errorf("the default settings' features: %d %v", features, answer)
	}
	if _, answer := NewComputeAuthState(nil, nil, nil).Caller(testComputePrincipal(networkId, standing)); answer != ComputeAuthUnknown {
		t.Errorf("a state over no gate: %v", answer)
	}
}

// rev/'s answers: a voiding object is ErrComputeTokenRevoked, an unreadable one stays an error that is no revocation,
// and a state with no reader cannot tell.
func TestComputeAuthStateMapsRevocations(t *testing.T) {
	principal := testComputePrincipal(testComputeId("network-a"), testComputeId("sidecar-a"))
	revocations := &testComputeRevocations{err: sidecar.ErrRevocationVoidsToken}
	state := NewComputeAuthState(newTestComputeGate(), revocations, nil)
	if err := state.CheckRevocation(context.Background(), principal); !errors.Is(err, ErrComputeTokenRevoked) {
		t.Fatalf("a voiding object: %v", err)
	}
	revocations.err = errors.New("rev/ did not answer")
	if err := state.CheckRevocation(context.Background(), principal); err == nil || errors.Is(err, ErrComputeTokenRevoked) {
		t.Fatalf("an unreadable rev/: %v", err)
	}
	revocations.err = nil
	if err := state.CheckRevocation(context.Background(), principal); err != nil {
		t.Fatalf("no object: %v", err)
	}
	if err := NewComputeAuthState(newTestComputeGate(), nil, nil).CheckRevocation(context.Background(), principal); err == nil {
		t.Fatal("a state with no rev/ reader allowed")
	}
}

// ProjectionSettings' field 3 read by number: none is no feature, an unknown field 3 carries its bits, the last one
// standing, and a value of the wrong wire type, a broken varint or one past 32 bits does not parse.
func TestComputeProjectionFeaturesReadsField3(t *testing.T) {
	withUnknown := func(unknown []byte) *bridge.ProjectionSettings {
		settings := &bridge.ProjectionSettings{SelfAdmit: 1}
		settings.ProtoReflect().SetUnknown(unknown)
		return settings
	}
	varint := func(value uint64) []byte {
		return protowire.AppendVarint(protowire.AppendTag(nil, computeProjectionAuthFeaturesField, protowire.VarintType), value)
	}
	if features, ok := computeProjectionFeatures(&bridge.ProjectionSettings{SelfAdmit: 1}); !ok || features != 0 {
		t.Fatalf("no field: %d %v", features, ok)
	}
	if features, ok := computeProjectionFeatures(nil); !ok || features != 0 {
		t.Fatalf("no settings: %d %v", features, ok)
	}
	twice := append(varint(uint64(ComputeAuthFeatureAgentRepos)), varint(uint64(ComputeAuthFeatureComputePolicy|ComputeAuthFeatureEnclaves))...)
	other := protowire.AppendBytes(protowire.AppendTag(nil, 9, protowire.BytesType), []byte("later field"))
	if features, ok := computeProjectionFeatures(withUnknown(append(other, twice...))); !ok || features != ComputeAuthFeatureComputePolicy|ComputeAuthFeatureEnclaves {
		t.Fatalf("an unknown field 3: %d %v", features, ok)
	}
	if computeFeaturesLacking(ComputeAuthFeatureComputePolicy|ComputeAuthFeatureEnclaves) != ComputeAuthFeatureEnclaves {
		t.Fatal("enclaves is implemented already")
	}
	for label, unknown := range map[string][]byte{
		"a field 3 of bytes": protowire.AppendBytes(protowire.AppendTag(nil, computeProjectionAuthFeaturesField, protowire.BytesType), []byte{8}),
		"a broken varint":    protowire.AppendTag(nil, computeProjectionAuthFeaturesField, protowire.VarintType),
		"past 32 bits":       varint(1 << 33),
	} {
		if _, ok := computeProjectionFeatures(withUnknown(unknown)); ok {
			t.Errorf("%s parsed", label)
		}
	}
}

// The guard on the real state: an admitted device reaches its handler, and once its admission is revoked in a new
// state the same live token is refused 403 at once.
func TestComputeGuardRunsOnTheRealState(t *testing.T) {
	counting := &countingComputeHandler{}
	fixture := newComputeFixture(t, &computeFixtureOptions{handlers: countingComputeHandlers(counting)})
	view := sidecartest.NewFakeAclView()
	memberId := view.AddMember(bridge.MemberRole_MEMBER_ROLE_OWNER)
	device := view.AddDevice(memberId)
	gate := newTestComputeGate()
	gate.install(t, fixture.networkId, &protocol.AclRows{}, view)
	engine, err := NewComputeEngine(fixture.ctx, fixture.host, nil, &ComputeEngineDeps{
		AuthState:    NewComputeAuthState(gate, &testComputeRevocations{}, fixture.clock),
		testHandlers: countingComputeHandlers(counting),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(engine.Close)
	fixture.engine = engine
	principal := testComputePrincipal(fixture.networkId, device)
	principal.IssuedAt = fixture.clock.Now()
	principal.ExpiresAt = fixture.clock.Now().Add(15 * time.Minute)
	token := fixture.authenticator.Issue(principal)
	if recorder := fixture.serve(http.MethodGet, "/v1/catalog", token, "", nil); recorder.Code != http.StatusOK {
		t.Fatalf("the admitted device: %d %s", recorder.Code, recorder.Body.String())
	}
	view.Revoke(device)
	gate.install(t, fixture.networkId, &protocol.AclRows{}, view)
	requireComputeRefusal(t, fixture.serve(http.MethodGet, "/v1/catalog", token, "", nil), http.StatusForbidden, ComputeRefusalScope)
	if counting.count() != 1 {
		t.Fatalf("the handler ran %d times", counting.count())
	}
}
