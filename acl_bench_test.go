// §22.5's gate budget for AclState's checks, on a state of 4,096 atoms: under 1 us and no allocation a check.
// TestAclChecksDoNotAllocate holds the allocation half in every test.sh; the benchmarks measure the time,
// which a test cannot hold on a shared machine.

package sidecar

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A large state and subjects to check on it.
type aclBenchState struct {
	state      *AclState
	devices    []Id
	agents     []Id
	repos      []Id
	tokenPaths [][]byte
}

// A network at §8.8's atom bound: 4,096 atom rows, 512 rules, 2,000 sidecars and 256 repos, drawn from a
// fixed seed.
func newAclBenchState(tb testing.TB) *aclBenchState {
	tb.Helper()
	random := rand.New(rand.NewPCG(8, 6))
	fixture := newAclTestFixture()
	bench := &aclBenchState{}
	members := []Id{}
	for i := range 96 {
		role := bridge.MemberRole_MEMBER_ROLE_MEMBER
		if i%16 == 0 {
			role = bridge.MemberRole_MEMBER_ROLE_ADMIN
		}
		members = append(members, fixture.member(role))
	}
	tags := []Id{}
	for range 3000 {
		tags = append(tags, fixture.tag(members[random.IntN(len(members))]))
	}
	groups := []Id{}
	for range 1000 {
		groups = append(groups, fixture.group(members[random.IntN(len(members))], members[random.IntN(len(members))]))
	}
	for _, member := range members {
		groups = append(groups, fixture.group(member))
	}
	for i := range 1500 {
		bench.devices = append(bench.devices, fixture.device(members[i%len(members)]))
	}
	for range 500 {
		bench.agents = append(bench.agents, fixture.agent(members[random.IntN(len(members))], tags[random.IntN(len(tags))], tags[random.IntN(len(tags))]))
	}
	for range 256 {
		repoId, _ := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
		bench.repos = append(bench.repos, repoId)
	}
	for i := range 64 {
		bench.tokenPaths = append(bench.tokenPaths, aclTestTokenPath(byte(i), byte(i+1)))
	}
	atomOf := func() Id {
		if random.IntN(2) == 0 {
			return tags[random.IntN(len(tags))]
		}
		return groups[random.IntN(len(groups))]
	}
	for i := range 512 {
		src := []Id{atomOf(), atomOf(), atomOf()}
		switch i % 4 {
		case 0:
			fixture.rule(src, []*protocol.AclTarget{aclAtomTarget(atomOf()), aclAtomTarget(atomOf())}, protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_ROUTE)
		case 1:
			rule := fixture.rule(src, []*protocol.AclTarget{aclAtomTarget(atomOf())}, protocol.AclAction_ACL_ACTION_DIAL)
			rule.PortsLimited = true
			rule.Expires = aclTestNow.Add(-1).UnixMilli()
		case 2:
			fixture.rule(src, []*protocol.AclTarget{aclRepoTarget(bench.repos[random.IntN(len(bench.repos))])}, protocol.AclAction_ACL_ACTION_READ, protocol.AclAction_ACL_ACTION_WRITE)
		case 3:
			tokenPath := bench.tokenPaths[random.IntN(len(bench.tokenPaths))]
			fixture.rule(src, []*protocol.AclTarget{aclSocketRowTarget(false, tokenPath)}, protocol.AclAction_ACL_ACTION_DIAL, protocol.AclAction_ACL_ACTION_LISTEN)
		}
	}
	if len(fixture.rows.Atoms) != aclRowsMaxAtomCount {
		tb.Fatalf("%d atoms", len(fixture.rows.Atoms))
	}
	bench.state = fixture.state(tb)
	return bench
}

// Every check a gate runs allocates nothing, allowed or refused, sidecar or client, before or after a
// rule's expiry.
func TestAclChecksDoNotAllocate(t *testing.T) {
	bench := newAclBenchState(t)
	state := bench.state
	source := AclSidecarSubject(bench.devices[0])
	destination := AclSidecarSubject(bench.agents[0])
	client := AclClientSubject(NewId(), bench.state.sidecarState(bench.devices[1]).memberId, []string{"kiosk"}, "user-1")
	address := netip.MustParseAddr("10.0.0.1")
	checks := map[string]func(){
		"Reach":         func() { state.Reach(source, destination, aclTestNow) },
		"Reach client":  func() { state.Reach(client, destination, aclTestNow) },
		"Reach to one":  func() { state.Reach(source, client, aclTestNow) },
		"MayDial":       func() { state.MayDial(source, destination, aclTestNow) },
		"MayDialSocket": func() { state.MayDialSocket(source, bench.tokenPaths[0], aclTestNow) },
		"MayListen":     func() { state.MayListen(destination, AclSocketName{NameToken: bench.tokenPaths[1]}, aclTestNow) },
		"MayListen tls": func() { state.MayListen(destination, AclSocketName{PublicName: "tls/443/blog"}, aclTestNow) },
		"MayRoute":      func() { state.MayRoute(source, address, destination, aclTestNow) },
		"MayPublish":    func() { state.MayPublish(destination, "app-preview", aclTestNow) },
		"MaySend":       func() { state.MaySend(source, aclTestNow) },
		"EvsAccess":     func() { state.EvsAccess(source, bench.repos[0], AclTokenAudienceEvs, aclTestNow) },
	}
	for name, check := range checks {
		if allocs := testing.AllocsPerRun(50, check); allocs != 0 {
			t.Errorf("%s: %.1f allocations", name, allocs)
		}
	}
}

func BenchmarkAclReach(b *testing.B) {
	bench := newAclBenchState(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i += 1 {
		bench.state.Reach(AclSidecarSubject(bench.devices[i%len(bench.devices)]), AclSidecarSubject(bench.agents[i%len(bench.agents)]), aclTestNow)
	}
}

func BenchmarkAclMayDial(b *testing.B) {
	bench := newAclBenchState(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i += 1 {
		bench.state.MayDial(AclSidecarSubject(bench.devices[i%len(bench.devices)]), AclSidecarSubject(bench.agents[i%len(bench.agents)]), aclTestNow)
	}
}

func BenchmarkAclEvsAccess(b *testing.B) {
	bench := newAclBenchState(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; b.Loop(); i += 1 {
		bench.state.EvsAccess(AclSidecarSubject(bench.devices[i%len(bench.devices)]), bench.repos[i%len(bench.repos)], AclTokenAudienceEvs, aclTestNow)
	}
}

func BenchmarkNewAclState(b *testing.B) {
	bench := newAclBenchState(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if _, err := NewAclState(bench.state.rows, bench.state.view); err != nil {
			b.Fatal(err)
		}
	}
}
