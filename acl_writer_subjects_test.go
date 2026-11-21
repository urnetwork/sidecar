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

func newTestAclWriterDevice(t *testing.T) *Sidecar {
	t.Helper()
	api := newTestSidecarApi(t, answerWith(200, `{"tier":"team","limits":{"acl_rules":5000,"acl_network_shares":1},"enforced":true}`))
	return &Sidecar{clock: RealClock{}, sidecarApi: api}
}

// A new policy email requests exactly that lookup from the host. The proposed id must
// stand in the signed state, whose role and actual device ids are carried in the preview.
func TestAclWriterPlansOnlyLiveNamedMembers(t *testing.T) {
	net := newTestConfigNet(t)
	head, state := testConfigHead(t, net), net.log.State()
	const email = "person@example.test"
	source := []byte(`{"grants":[{"src":["user:person@example.test"],"dst":["autogroup:self"],"allow":["dial"]}]}`)
	writer := newTestAclWriterDevice(t)
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
	if _, err := writer.aclWriterPlan(ctx, source, nil, state, plan.Head); !errors.As(err, &required) {
		t.Fatalf("the previous policy's email binding answered a fresh save without a proposal: %v", err)
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

// The confirmation covers the signed owner of each referenced scope even when a later
// base retains the same policy files and the same host labels.
func TestAclWriterBindsTheScopeOwnerInItsPreview(t *testing.T) {
	net := newTestConfigNet(t)
	other, _ := net.consentedMember("scope owner")
	writer := newTestAclWriterDevice(t)
	source := []byte(`{"grants":[{"src":["autogroup:member"],"dst":["sock:tls/443/*.crew"],"allow":["listen"]}]}`)
	head := testConfigHead(t, net)
	planAt := func(owner Id) *AclSavePlan {
		t.Helper()
		state := net.log.State()
		rows := state.Rows()
		rows.TeamScopes = []*bridge.TeamScopeRow{{Label: "crew", MemberId: owner.Bytes()}}
		if verdict := net.pushBase(net.owner, rows, net.n, state.Base().GetConfigVersion()+1, 0); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
		plan, err := writer.aclWriterPlan(t.Context(), source, nil, net.log.State(), head)
		if err != nil {
			t.Fatal(err)
		}
		resolved := plan.Preview.Resolutions
		if len(resolved) != 1 || resolved[0].Kind != "member_scope" || resolved[0].Text != "crew" || resolved[0].Id != owner {
			t.Fatalf("scope preview: %+v", resolved)
		}
		return plan
	}
	before := planAt(net.ownerMemberId)
	if planAt(other).Digest == before.Digest {
		t.Fatal("changing the signed owner preserved its preview digest")
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

// Both planning and confirmation read each enrollment's authenticated zone. An answer
// must name that enrollment even when its proposed label is still the same.
func TestAclWriterRechecksThePartnerNetwork(t *testing.T) {
	net := newTestConfigNet(t)
	state, head := net.log.State(), testConfigHead(t, net)
	enrollment := func(networkId Id, label, alias string) (*Sidecar, *testDnsBlock) {
		t.Helper()
		running := newTestAclWriterDevice(t)
		zone := &DnsZone{NetworkId: networkId, Root: testLabelRoot, Label: label, Alias: alias, Version: 1}
		block := newTestDnsBlock(zone)
		dns := newTestDnsClient(t, block, running.clock, networkId)
		labels, err := OpenNetworkLabelTable(newTestDnsMemoryStore())
		if err != nil {
			t.Fatal(err)
		}
		dns.FeedLabels(labels)
		running.dns.client = dns
		return running, block
	}
	writer, _ := enrollment(net.networkId, "a7q2m9x4k1", "owner-team")
	partnerId := testConfigId("another enrolled network")
	partner, reply := enrollment(partnerId, "b7q2m9x4k2", "partner-team")
	subjects := &AclWriterSubjects{Networks: []*Sidecar{writer, partner}}
	source := []byte(`{"grants":[{"src":["network:partner-team"],"dst":["autogroup:member"],"allow":["dial"]}]}`)
	plan, err := writer.aclWriterPlan(t.Context(), source, subjects, state, head)
	if err != nil {
		t.Fatal(err)
	}
	if rows := plan.Preview.Resolutions; len(rows) != 1 || rows[0].Kind != "network" || rows[0].Id != partnerId || rows[0].Text != "partner-team" {
		t.Fatalf("partner preview: %+v", rows)
	}
	confirmed, err := writer.aclWriterPlan(t.Context(), source, subjects, state, head)
	if err != nil || confirmed.Digest != plan.Digest {
		t.Fatalf("partner confirmation: %v", err)
	}
	teamApi := writer.sidecarApi
	writer.sidecarApi = newTestSidecarApi(t, answerWith(200, `{"tier":"team","limits":{"acl_rules":5000},"enforced":true}`))
	if _, err := writer.aclWriterPlan(t.Context(), source, subjects, state, head); !errors.Is(err, ErrAclPolicyInvalid) {
		t.Fatalf("a network whose effective limits exclude sharing could sign the partner policy: %v", err)
	}
	writer.sidecarApi = teamApi
	reply.stateLock.Lock()
	reply.zone.NetworkId = net.networkId
	reply.stateLock.Unlock()
	if _, err := writer.aclWriterPlan(t.Context(), source, subjects, state, head); !errors.Is(err, ErrDnsClientReply) {
		t.Fatalf("a zone for a different enrollment answered the confirmation: %v", err)
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
