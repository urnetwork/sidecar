// Who mirrors what, and `ur status`'s coverage lines (EVSB-M2-19; §11.13's durability and status rows), on the config
// test network's real state: a network-scope indexer designated for mirror keeps the team record and not a member's
// vault, the member's own indexer keeps that vault, a device with no designation mirrors nothing, and the lines name
// each repo this device mirrors, each kept repo no indexer keeps, a network no indexer mirrors, and each indexer with
// its services and newest sign. The sync, coverage and erasure clauses run end to end in
// sidecartest/evs_mirror_world_test.go.

package sidecar

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A network with a team record its owner's device reads, a member a's vault, a general repo, and the owner's device
// and a's laptop designated as indexers.
type evsMirrorTestNet struct {
	net         *testConfigNet
	laptopA     testConfigDevice
	memberA     Id
	teamRecord  Id
	vault       Id
	general     Id
	unwatched   Id
	designation map[Id][]protocol.IndexerService
}

func newEvsMirrorTestNet(t *testing.T) *evsMirrorTestNet {
	t.Helper()
	net := newTestConfigNet(t)
	memberA, laptopA := net.consentedMember("a")
	self := &evsMirrorTestNet{
		net: net, laptopA: laptopA, memberA: memberA,
		teamRecord: testConfigId("team record"), vault: testConfigId("a's vault"), general: testConfigId("general"),
		unwatched:   testConfigId("an unread ledger"),
		designation: map[Id][]protocol.IndexerService{},
	}
	// an owner-bound repo's owner is its creating device's member
	create := func(signer testConfigDevice, repoId Id, kind protocol.RepoKind) {
		net.mustPost(signer, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: kind})
	}
	create(net.owner, self.teamRecord, protocol.RepoKind_REPO_KIND_TEAM_RECORD)
	create(net.owner, self.general, protocol.RepoKind_REPO_KIND_GENERAL)
	// a ledger a's laptop made, which the owner's device does not read and a's member indexer does not keep
	create(laptopA, self.unwatched, protocol.RepoKind_REPO_KIND_RECORD)
	create(laptopA, self.vault, protocol.RepoKind_REPO_KIND_VAULT)
	for _, repoId := range []Id{self.teamRecord, self.general} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: repoId.Bytes(), Subject: net.owner.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(net.owner, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false))
	net.mustPost(laptopA, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(laptopA, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	return self
}

// Services as a config reader opens them: what the test set, mirror and search by default.
func (self *evsMirrorTestNet) services(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
	if services, ok := self.designation[indexer.SidecarId]; ok {
		return services, true
	}
	return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MIRROR, protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
}

func TestEvsMirrorPlanFollowsTheMirrorDesignations(t *testing.T) {
	test := newEvsMirrorTestNet(t)
	state := test.net.log.State()
	ownerPlan := EvsMirrorPlan(state, test.net.owner.sidecarId, test.services)
	if !slices.Contains(ownerPlan, test.teamRecord) || slices.Contains(ownerPlan, test.vault) || slices.Contains(ownerPlan, test.general) {
		t.Errorf("the network indexer keeps %v", ownerPlan)
	}
	if slices.Contains(ownerPlan, test.unwatched) {
		t.Errorf("the network indexer keeps a ledger it does not read: %v", ownerPlan)
	}
	laptopPlan := EvsMirrorPlan(state, test.laptopA.sidecarId, test.services)
	if !slices.Equal(laptopPlan, []Id{test.vault}) {
		t.Errorf("a's member indexer keeps %v, want its vault", laptopPlan)
	}
	// a designation whose services do not name the mirror, or that cannot be opened, keeps nothing
	test.designation[test.laptopA.sidecarId] = []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}
	if plan := EvsMirrorPlan(state, test.laptopA.sidecarId, test.services); len(plan) != 0 {
		t.Errorf("a search-only indexer keeps %v", plan)
	}
	unopened := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) { return nil, false }
	if plan := EvsMirrorPlan(state, test.net.owner.sidecarId, unopened); len(plan) != 0 {
		t.Errorf("services that cannot be opened keep %v", plan)
	}
	// a device with no designation mirrors nothing unasked
	other := test.net.device("a phone", test.memberA)
	if plan := EvsMirrorPlan(state, other.sidecarId, test.services); len(plan) != 0 {
		t.Errorf("an undesignated device keeps %v", plan)
	}
}

func TestEvsMirrorStatusLinesNameWhatIsAndIsNotMirrored(t *testing.T) {
	test := newEvsMirrorTestNet(t)
	state := test.net.log.State()
	signedAt := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	args := &EvsMirrorStatusArgs{
		State:     state,
		SidecarId: test.net.owner.sidecarId,
		Services:  test.services,
		NewestSign: func(sidecarId Id) (time.Time, bool) {
			return signedAt, sidecarId == test.laptopA.sidecarId
		},
		// this device keeps no mirror yet
		Mirror: func(repoId Id) *EvsMirror { return nil },
	}
	lines, err := EvsMirrorStatusLines(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(lines, "\n")
	want := []string{
		"coverage:   repo " + test.teamRecord.String() + " none: this device is designated to mirror it and holds no mirror",
		"unmirrored: repo " + test.unwatched.String() + " (record): no indexer designated for mirror keeps it",
		"indexer:    " + test.net.owner.sidecarId.String() + " (network scope): services mirror, search; no sign of it held",
		"indexer:    " + test.laptopA.sidecarId.String() + " (member scope): services mirror, search; newest sign 2026-11-01T12:00:00Z",
	}
	for _, line := range want {
		if !strings.Contains(text, line) {
			t.Errorf("no line %q in:\n%s", line, text)
		}
	}
	for _, repoId := range []Id{test.teamRecord, test.vault, test.general} {
		if strings.Contains(text, "unmirrored: repo "+repoId.String()) {
			t.Errorf("repo %s named unmirrored:\n%s", repoId, text)
		}
	}
	if strings.Contains(text, "no indexer is designated for mirror") {
		t.Errorf("a network with mirror indexers named as having none:\n%s", text)
	}
	// with no mirror designation anywhere, every kept repo is unmirrored and the network says so
	searchOnly := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
	}
	args.Services = searchOnly
	lines, err = EvsMirrorStatusLines(t.Context(), args)
	if err != nil {
		t.Fatal(err)
	}
	text = strings.Join(lines, "\n")
	for _, repoId := range []Id{test.teamRecord, test.vault, test.unwatched} {
		if !strings.Contains(text, "unmirrored: repo "+repoId.String()) {
			t.Errorf("repo %s not named unmirrored:\n%s", repoId, text)
		}
	}
	if strings.Contains(text, "unmirrored: repo "+test.general.String()) {
		t.Errorf("a general repo named unmirrored:\n%s", text)
	}
	if !strings.Contains(text, "unmirrored: network "+state.NetworkId().String()+": no indexer is designated for mirror") {
		t.Errorf("no network line:\n%s", text)
	}
	if strings.Contains(text, "coverage:") {
		t.Errorf("coverage named with no designation:\n%s", text)
	}
	if _, err := EvsMirrorStatusLines(t.Context(), &EvsMirrorStatusArgs{}); err == nil {
		t.Error("lines with no verified state")
	}
}

func TestEvsMirrorKeepsTheConfigAndRecordClassKinds(t *testing.T) {
	for kind, kept := range map[protocol.RepoKind]bool{
		protocol.RepoKind_REPO_KIND_GENERAL:     false,
		protocol.RepoKind_REPO_KIND_RECORD:      true,
		protocol.RepoKind_REPO_KIND_CONFIG:      true,
		protocol.RepoKind_REPO_KIND_DIRECTORY:   true,
		protocol.RepoKind_REPO_KIND_TEAM_RECORD: true,
		protocol.RepoKind_REPO_KIND_MAILCFG:     true,
		protocol.RepoKind_REPO_KIND_VAULT:       true,
		protocol.RepoKind_REPO_KIND_MAILBOX:     true,
		protocol.RepoKind_REPO_KIND_SECRET:      true,
	} {
		if EvsMirrorKeptKind(kind) != kept {
			t.Errorf("%s kept: %v", kind, !kept)
		}
	}
}

func TestEvsMirrorSettingsRefuseNonPositiveBounds(t *testing.T) {
	for _, mutate := range []func(settings *EvsMirrorSettings){
		func(settings *EvsMirrorSettings) { settings.HeadLag = 0 },
		func(settings *EvsMirrorSettings) { settings.CheckMaxAge = -1 },
		func(settings *EvsMirrorSettings) { settings.ReadObjectCount = 0 },
		func(settings *EvsMirrorSettings) { settings.ReadRangeCount = 0 },
		func(settings *EvsMirrorSettings) { settings.ReadRangeByteCount = 0 },
		func(settings *EvsMirrorSettings) { settings.MissingNameCount = 0 },
	} {
		settings := DefaultEvsMirrorSettings()
		mutate(settings)
		if _, err := NewEvsMirror(nil, Id{}, settings); err == nil {
			t.Errorf("settings %+v taken", settings)
		}
	}
}
