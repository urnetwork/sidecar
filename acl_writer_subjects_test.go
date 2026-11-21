//go:build !sidecar_http && !ios_extension

package sidecar

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A new policy email requests exactly that lookup from the host. The proposed id must
// stand in the signed state, whose role and actual device ids are carried in the preview.
func TestAclWriterPlansOnlyLiveNamedMembers(t *testing.T) {
	net := newTestConfigNet(t)
	head, state := testConfigHead(t, net), net.log.State()
	const email = "person@example.test"
	source := []byte(`{"grants":[{"src":["user:person@example.test"],"dst":["autogroup:self"],"allow":["dial"]}]}`)
	writer := &Sidecar{clock: RealClock{}}
	ctx := context.Background()
	_, err := writer.aclWriterPlan(ctx, source, nil, state, head)
	var required *AclMemberLookupRequired
	if !errors.As(err, &required) || !slices.Equal(required.Emails, []string{email}) {
		t.Fatalf("missing proposal: %v", err)
	}
	subjects := &AclWriterSubjects{Members: map[string]Id{email: testConfigId("not a member")}}
	if _, err := writer.aclWriterPlan(ctx, source, subjects, state, head); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Fatalf("unsigned admission: %v", err)
	}
	subjects.Members[email] = net.ownerMemberId
	plan, err := writer.aclWriterPlan(ctx, source, subjects, state, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Preview.Resolutions) != 1 {
		t.Fatalf("preview: %+v", plan.Preview.Resolutions)
	}
	row := plan.Preview.Resolutions[0]
	if row.Text != email || row.Id != net.ownerMemberId || row.Role != state.Member(net.ownerMemberId).GetRole() ||
		!slices.Equal(row.SidecarIds, []Id{net.owner.sidecarId}) {
		t.Fatalf("new member binding: %+v", row)
	}
	other := newTestConfigNetOf(t, "another network")
	otherPlan, err := writer.aclWriterPlan(ctx, source, subjects, other.log.State(), testConfigHead(t, other))
	if err != nil || otherPlan.Digest == plan.Digest {
		t.Fatalf("different network accepted the same confirmation: %v", err)
	}
	net.tick(&bridge.ApiTick{})
	unchanged, err := writer.aclWriterPlan(ctx, source, subjects, net.log.State(), head)
	if err != nil || unchanged.Digest != plan.Digest {
		t.Fatalf("an unrelated log tick changed the confirmation: %v", err)
	}
	device := net.device("another owner device", net.ownerMemberId)
	net.admitDevice(net.owner, device, 0)
	replanned, err := writer.aclWriterPlan(ctx, source, subjects, net.log.State(), head)
	if err != nil || replanned.Digest == plan.Digest || !slices.Contains(replanned.Preview.Resolutions[0].SidecarIds, device.sidecarId) {
		t.Fatalf("a changed device list did not require a fresh confirmation: %v", err)
	}
}

// A client lookup uses the dual-signed binding and the admitted key. A missing binding
// remains a literal client, whereas an untrusted binding or lookup failure stops the save.
func TestAclWriterVerifiesClientBindings(t *testing.T) {
	net := newTestConfigNet(t)
	ctx := context.Background()
	clientId := testConfigId("client generation")
	binding := &SidecarIdentityBinding{NetworkId: net.networkId, SidecarId: net.owner.sidecarId, ClientId: clientId,
		Generation: 1, IssuedAt: time.UnixMilli(testConfigStartMs)}
	check := func(status int, body string) (Id, bool, error) {
		api := newTestSidecarApi(t, answerWith(status, body))
		installTestDpopSigner(t, api)
		return (&aclWriterSubjectResolver{writer: &Sidecar{sidecarApi: api}, state: net.log.State()}).ResolveClient(ctx, clientId)
	}
	response := func(seed []byte) string {
		signed, err := NewSidecarIdentityBinding(binding, seed, testConfigDeviceKey("acl client key").Seed())
		if err != nil {
			t.Fatal(err)
		}
		reply, err := json.Marshal(sidecarIdentityReply{SidecarId: &net.owner.sidecarId, IdentityPublicKey: net.owner.publicKey(),
			IdentityAlg: "ed25519", Status: "active", Binding: signed})
		if err != nil {
			t.Fatal(err)
		}
		return string(reply)
	}
	if got, bound, err := check(200, response(net.owner.key.Seed())); err != nil || !bound || got != net.owner.sidecarId {
		t.Fatalf("signed binding: %v, %t, %v", got, bound, err)
	}
	if _, _, err := check(200, response(testConfigDeviceKey("another signer").Seed())); err == nil {
		t.Fatal("unadmitted identity key accepted")
	}
	if _, bound, err := check(404, `{"error":"unknown"}`); err != nil || bound {
		t.Fatalf("literal client: bound %t, %v", bound, err)
	}
	if _, _, err := check(403, `{"error":"refused"}`); err == nil {
		t.Fatal("a lookup failure was treated as an unbound client")
	}
}

func TestAclWriterUsesNonInteractiveNetworkLabels(t *testing.T) {
	id := testConfigId("named network")
	resolver := &aclWriterSubjectResolver{root: testLabelRoot, labels: &NetworkLabelTable{rows: []NetworkLabelRow{
		{Root: testLabelRoot, Label: "a7q2m9x4k1", Alias: "team-live", RetiringAliases: []string{"team-old"}, LegacyName: "legacy", NetworkId: id},
	}}}
	for _, text := range []string{"a7q2m9x4k1", "team-live", "team-old"} {
		if got, ok, err := resolver.ResolveNetwork(context.Background(), text); err != nil || !ok || got != id {
			t.Errorf("%s: %v, %t, %v", text, got, ok, err)
		}
	}
	if _, ok, err := resolver.ResolveNetwork(context.Background(), "legacy"); ok || !errors.Is(err, ErrNetworkLabelUnknown) {
		t.Fatalf("legacy name: %t, %v", ok, err)
	}
	resolver.unreadLabels = errors.New("another enrollment is offline")
	if _, ok, err := resolver.ResolveNetwork(context.Background(), "team-live"); !ok || err != nil {
		t.Fatalf("fresh live alias: %t, %v", ok, err)
	}
	if _, ok, err := resolver.ResolveNetwork(context.Background(), "team-old"); ok || !errors.Is(err, resolver.unreadLabels) {
		t.Fatalf("retiring alias on an incomplete view: %t, %v", ok, err)
	}
}

// A daemon that follows a network tests against the base it already verified. A cold
// head cache withholds a result even while the host's network reader could answer.
func TestAclWriterTestsOnlyItsLocallyVerifiedHead(t *testing.T) {
	world := newTestConfigClientWorld(t)
	client := world.client(nil)
	world.caughtUp(client)
	running := &Sidecar{clock: world.clock}
	running.authorities.authority = client.Authority()
	ctx := context.Background()
	source := []byte(`{"tests":[{"src":"autogroup:member","deny":["evs:00000000000000000000000000000001#read"]}]}`)
	for _, writer := range []*ConfigWriter{nil, {args: &ConfigWriterArgs{SidecarId: world.net.owner.sidecarId}}} {
		client.writer.Store(writer)
		report, err := running.TestAclPolicy(ctx, source)
		if err != nil || report.DocumentAlone || !report.Passed() {
			t.Fatalf("verified base: %+v, %v", report, err)
		}
	}
	client.writer.Store(nil)
	client.localHead.Store(nil)
	if report, err := running.TestAclPolicy(ctx, source); !errors.Is(err, ErrConfigHeadUnavailable) || report != nil {
		t.Fatalf("unavailable local head: %+v, %v", report, err)
	}
}
