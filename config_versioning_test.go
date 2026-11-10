// TEAM-M10-01's VersioningRules: FS-68's rule cases, a glob's dialect, a full reader taking the network's record from
// its base's head and a rows-only reader answering it unknown, and FS-83's search scope over designated indexers.
// Pure rule evaluation, so every leg runs the same vectors.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"slices"
	"testing"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// FS-68's rule cases on a general repo: no record gives the platform rule, versionless only above 64 MiB; a present
// record matching nothing leaves a 65 MiB file versioned; first match wins, an empty selector matching all; a repo's
// own rules replace the network's.
func TestVersioningRulesFirstMatchAndThePlatformRule(t *testing.T) {
	repoId := testConfigId("versioned repo")
	general := protocol.RepoKind_REPO_KIND_GENERAL
	mib := uint64(1024 * 1024)
	platform := ConfigPlatformVersioningRules()
	nothing := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{Kinds: []uint32{uint32(protocol.RepoKind_REPO_KIND_RECORD)}, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
	ordered := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{
		{PathGlob: "keep/**", Versioning: protocol.VersioningMode_VERSIONING_MODE_ON},
		{PathGlob: "**/*.bin", SizeAboveBytes: mib, Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
		{RepoIds: [][]byte{repoId.Bytes()}, PathGlob: "build/*", Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF},
	}}
	cases := []struct {
		name  string
		rules *protocol.VersioningRules
		path  string
		size  uint64
		want  uint32
	}{
		{name: "no record, 65 MiB", rules: platform, path: "big.iso", size: 65 * mib, want: ConfigVersioningVersionless},
		{name: "no record, 63 MiB", rules: platform, path: "big.iso", size: 63 * mib, want: ConfigVersioningKeep},
		{name: "a record matching nothing, 65 MiB", rules: nothing, path: "big.iso", size: 65 * mib, want: ConfigVersioningKeep},
		{name: "the first match keeps", rules: ordered, path: "keep/deep/a.bin", size: 2 * mib, want: ConfigVersioningKeep},
		{name: "a glob and a size", rules: ordered, path: "out/a.bin", size: 2 * mib, want: ConfigVersioningVersionless},
		{name: "under the size", rules: ordered, path: "out/a.bin", size: mib, want: ConfigVersioningKeep},
		{name: "the repo's own rule", rules: ordered, path: "build/x", size: 1, want: ConfigVersioningVersionless},
		{name: "a glob segment does not cross a slash", rules: ordered, path: "build/x/y", size: 1, want: ConfigVersioningKeep},
	}
	for _, c := range cases {
		if got := ConfigVersioningUnder(c.rules, repoId, general, c.path, c.size); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	other := testConfigId("another repo")
	if got := ConfigVersioningUnder(ordered, other, general, "build/x", 1); got != ConfigVersioningKeep {
		t.Errorf("another repo matched the repo's rule: %d", got)
	}
	malformed := []*protocol.VersioningRules{
		{Rules: []*protocol.VersioningRule{{}}},
		{Rules: []*protocol.VersioningRule{{RepoIds: [][]byte{{1, 2}}, Versioning: protocol.VersioningMode_VERSIONING_MODE_ON}}},
		{Rules: []*protocol.VersioningRule{{PathGlob: "[", Versioning: protocol.VersioningMode_VERSIONING_MODE_ON}}},
		{Rules: []*protocol.VersioningRule{{Kinds: []uint32{999}, Versioning: protocol.VersioningMode_VERSIONING_MODE_ON}}},
	}
	for i, rules := range malformed {
		if err := CheckVersioningRules(rules); !errors.Is(err, ErrConfigVersioningMalformed) {
			t.Errorf("malformed %d: %v", i, err)
		}
	}
	if err := CheckVersioningRules(ordered); err != nil {
		t.Error(err)
	}
}

// A full reader takes the network's record from the head its base names, and the platform rule before one; a repo's
// own rules replace it; config is never covered; a rows-only reader answers the record unknown.
func TestVersioningForReadsTheHeadAtAFullReaderAlone(t *testing.T) {
	net := newTestConfigNet(t)
	repoId := testConfigId("general")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	mib := uint64(1024 * 1024)
	if setting, err := net.log.State().VersioningFor(repoId, "big.iso", 65*mib, nil); err != nil || setting != ConfigVersioningVersionless {
		t.Fatalf("the platform rule: %d %v", setting, err)
	}
	rules := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{PathGlob: "logs/**", Versioning: protocol.VersioningMode_VERSIONING_MODE_OFF}}}
	net.source.versioning[[sha256.Size]byte(testConfigHeadSha256(2))] = rules
	net.fold(net.owner, net.n, 2)
	state := net.log.State()
	if setting, err := state.VersioningFor(repoId, "big.iso", 65*mib, nil); err != nil || setting != ConfigVersioningKeep {
		t.Errorf("a record matching nothing: %d %v", setting, err)
	}
	if setting, err := state.VersioningFor(repoId, "logs/a/b.log", 1, nil); err != nil || setting != ConfigVersioningVersionless {
		t.Errorf("the record's rule: %d %v", setting, err)
	}
	own := &protocol.VersioningRules{Rules: []*protocol.VersioningRule{{Versioning: protocol.VersioningMode_VERSIONING_MODE_ON}}}
	if setting, err := state.VersioningFor(repoId, "logs/a/b.log", 1, own); err != nil || setting != ConfigVersioningKeep {
		t.Errorf("the repo's own rules: %d %v", setting, err)
	}
	configRepoId := Id(net.log.State().Genesis().GetConfigRepoId())
	if _, err := state.VersioningFor(configRepoId, "policy.hujson", 1, nil); !errors.Is(err, ErrConfigVersioningNotCovered) {
		t.Errorf("the config repo: %v", err)
	}
	gate, err := RestoreConfigLogRowsOnly(testConfigLogSettings(), net.log.Retained(), net.rowsOnlySource(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gate.State().VersioningFor(repoId, "logs/a/b.log", 1, nil); !errors.Is(err, ErrConfigVersioningUnknown) {
		t.Errorf("a rows-only reader: %v", err)
	}
}

// FS-83's scope rule: a network indexer answers member devices over team repos they read; a member indexer its own
// member's devices over what they read, and not another member's; an indexer offering no search answers none.
func TestSearchIndexersAnswerByScope(t *testing.T) {
	net := newTestConfigNet(t)
	memberA, laptopA := net.consentedMember("a")
	phoneA := net.device("a phone", memberA)
	net.admitDevice(laptopA, phoneA, 0)
	_, laptopB := net.consentedMember("b")
	repoId := testConfigId("team repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{Header: net.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL})
	for _, reader := range []testConfigDevice{laptopA, phoneA, laptopB, net.owner} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_GRANT, &protocol.RepoGrant{
			Header: net.header(), RepoId: repoId.Bytes(), Subject: reader.sidecarId.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER,
		})
	}
	// the owner's device indexes the network, a's laptop its member
	net.mustPost(net.owner, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(net.owner, protocol.IndexerScope_INDEXER_SCOPE_NETWORK, false))
	net.mustPost(laptopA, bridge.SignedType_SIGNED_INDEXER_SET, net.indexerSet(laptopA, protocol.IndexerScope_INDEXER_SCOPE_MEMBER, false))
	state := net.log.State()
	search := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_SEARCH}, true
	}
	if got := state.SearchIndexersFor(phoneA.sidecarId, repoId, search); !slices.Contains(got, net.owner.sidecarId) || !slices.Contains(got, laptopA.sidecarId) {
		t.Errorf("a's phone searches through %v", got)
	}
	if got := state.SearchIndexersFor(laptopB.sidecarId, repoId, search); !slices.Equal(got, []Id{net.owner.sidecarId}) {
		t.Errorf("b's laptop searches through %v", got)
	}
	unopened := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) { return nil, false }
	if got := state.SearchIndexersFor(phoneA.sidecarId, repoId, unopened); len(got) != 0 {
		t.Errorf("services it cannot open answer: %v", got)
	}
	mailOnly := func(indexer ConfigIndexer) ([]protocol.IndexerService, bool) {
		return []protocol.IndexerService{protocol.IndexerService_INDEXER_SERVICE_MAIL}, true
	}
	if got := state.SearchIndexersFor(phoneA.sidecarId, repoId, mailOnly); len(got) != 0 {
		t.Errorf("a mail indexer answers searches: %v", got)
	}
}
