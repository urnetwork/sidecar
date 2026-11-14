//go:build !ios_extension

// DESIGN-DETAILS 16.6's unit bullets for section 16 (QD-212).
//
// ACL-M2-18's half, the first bullet: RepoPrefixRules' id-level rule on the fake view, one case for each row of 16.2.2's
// table beside its positive twin: the signer, each refused repo kind and a deleted repo, a body of 47, 48, 303 and 304 B
// and one past the cap, the 256th and 257th set. The fold: a row per set in position order and nothing else moved,
// ReapplyStatement giving the rows ApplyStatement gave. Then through TEAM's ConfigLog: a set no format-1 reader refuses
// as unknown, a base's tail re-applied, the base's compile, a new device and a rows-only reader holding one list, and
// the rows half of the base-independence test on generated logs, against the list the log's own verdicts give; and
// AclRowsCheckLimits counting the rows.
//
// ACL-M6-04's prefix half, the second to seventh bullets and QD-801's (acl_prefix.go): a set's states, opened, each void
// cause in turn, newer, and pending then opened or void, a body sealed for another repo or statement opening in none;
// the sealer refusing what no reader opens; names' table of the seven subject forms against a member device, an
// ephemeral one, a tagged one and a tombstone of each, a group's, a role's and autogroup:admin's atom naming nobody;
// PrefixVerdict line by line with each twin, and the set in force by position; the delta rule against a generated corpus
// of a design planner's deltas, each single mutation ignored; under in plaintext equal to under on tokens in two
// epochs; base independence on real code, which a hook keeping only the newest row breaks, as asserted;
// AllowPrefixWrite drawing its paths as QD-801 says; AclPrefixSets opening each set once and keeping it in the sealed
// store; and AclPrefixRulesFiler filing through a real Sidecar's act onto the test log. Deterministic, with no clock.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"iter"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// A sealed_rules of byteCount bytes. The check reads its length alone, so any bytes do.
func aclTestSealedRules(byteCount int) []byte {
	sealed := make([]byte, byteCount)
	for i := range sealed {
		sealed[i] = byte(i*7 + 3)
	}
	return sealed
}

// The smallest sealed_rules 16.2.2 takes: config_seal's 48 B of framing around one 256 B block.
const aclTestSealedRulesByteCount = 48 + 256

// A RepoPrefixRules on a repo with the smallest body that fits.
func aclTestPrefixRules(repoId Id) *protocol.RepoPrefixRules {
	return &protocol.RepoPrefixRules{RepoId: repoId.Bytes(), SealedRules: aclTestSealedRules(aclTestSealedRulesByteCount)}
}

// The cast's general repo, its laptop the admin.
func (self *aclStatementCast) generalRepo() (Id, *protocol.AclRepo) {
	repoId, row := self.fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	row.Admins = []*protocol.AclRepoAdminRow{{SidecarId: self.laptop.Bytes(), Signer: self.laptop.Bytes(), At: 1}}
	return repoId, row
}

// Checks each case at state, wanting its refusal class or none.
func aclTestCheckCases(t *testing.T, state *AclState, cases []aclTestCheckCase) {
	t.Helper()
	for _, c := range cases {
		_, err := state.CheckStatement(c.statement, nil)
		if c.refusal == nil && err != nil || c.refusal != nil && aclTestRefusal(err) != c.refusal {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
}

// One statement a table checks, and the refusal class it wants, nil for one that takes effect.
type aclTestCheckCase struct {
	name      string
	statement *AclStatement
	refusal   error
}

// 16.2.2's signer row: a repo admin standing at the entry's position or a config writer, checkRepoVersioning's test;
// never a member who is neither, a tagged agent, a stranger, a removed admin, a read_only or revoked device, or k of n.
func TestAclRepoPrefixRulesSigners(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := cast.generalRepo()
	// the phone was an admin, removed at position 2: it stands no longer
	row.Admins = append(row.Admins, &protocol.AclRepoAdminRow{SidecarId: cast.phone.Bytes(), Signer: cast.laptop.Bytes(), At: 1, RemovedAt: 2})
	state := fixture.state(t)
	statement := func(signer Id) *AclStatement {
		return fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(repoId), signer)
	}
	aclTestCheckCases(t, state, []aclTestCheckCase{
		{name: "the repo admin", statement: statement(cast.laptop)},
		{name: "a config writer that is no repo admin", statement: statement(cast.adminDevice)},
		{name: "the owner's config writer", statement: statement(cast.ownerDevice)},
		{name: "a removed admin, a member who is neither", statement: statement(cast.phone), refusal: ErrConfigAuthority},
		{name: "a tagged agent", statement: statement(cast.agent), refusal: ErrConfigAuthority},
		{name: "a stranger", statement: statement(cast.stranger), refusal: ErrConfigAuthority},
		{name: "a read_only device of an Admin", statement: statement(cast.pageWorker), refusal: ErrConfigReadOnly},
		{name: "a revoked device", statement: statement(cast.revoked), refusal: ErrConfigAuthority},
		{name: "k of n", statement: fixture.authorityStatement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(repoId), cast.laptop, cast.ownerDevice), refusal: ErrConfigRule},
		{name: "a body of another type", statement: fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, &protocol.RepoVersioning{RepoId: repoId.Bytes()}, cast.laptop), refusal: ErrConfigRule},
	})

	// the agent is named an admin: now it may
	row.Admins = append(row.Admins, &protocol.AclRepoAdminRow{SidecarId: cast.agent.Bytes(), Signer: cast.laptop.Bytes(), At: 3})
	if _, err := fixture.state(t).CheckStatement(statement(cast.agent), nil); err != nil {
		t.Errorf("an agent the repo names its admin: %v", err)
	}
}

// 16.2.2's repo row: in the rows, of kind general, not deleted (16.9, small reading 1; QD-795). Every other kind is
// refused, the config, a repo the rows do not hold and malformed ids among them, and a restored repo takes a set again.
func TestAclRepoPrefixRulesTakesOnlyALiveGeneralRepo(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	generalId, _ := cast.generalRepo()
	kindIds := map[protocol.RepoKind]Id{}
	for _, kind := range []protocol.RepoKind{
		protocol.RepoKind_REPO_KIND_RECORD, protocol.RepoKind_REPO_KIND_CONFIG, protocol.RepoKind_REPO_KIND_DIRECTORY,
		protocol.RepoKind_REPO_KIND_TEAM_RECORD, protocol.RepoKind_REPO_KIND_MAILCFG, protocol.RepoKind_REPO_KIND_VAULT,
		protocol.RepoKind_REPO_KIND_MAILBOX, protocol.RepoKind_REPO_KIND_SECRET,
	} {
		ownerId := Id{}
		if aclRepoKindOwnerBound(kind) {
			ownerId = cast.admin
		}
		kindIds[kind] = aclTestKindRepo(fixture, kind, ownerId)
	}
	deletedId, deleted := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	deleted.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next(), DeletedTimeMs: aclTestNow.UnixMilli()}
	restoredId, restored := fixture.repo(protocol.RepoKind_REPO_KIND_GENERAL, Id{})
	restored.Deletion = &protocol.AclRepoDeletionRow{DeletionId: NewId().Bytes(), DeletedAt: fixture.next(), RestoredAt: fixture.next()}
	state := fixture.state(t)

	// the Admin's config writer device signs each, so the repo, never the signer, decides
	statement := func(repoIdBytes []byte) *AclStatement {
		return fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES,
			&protocol.RepoPrefixRules{RepoId: repoIdBytes, SealedRules: aclTestSealedRules(aclTestSealedRulesByteCount)}, cast.adminDevice)
	}
	cases := []aclTestCheckCase{
		{name: "a general repo", statement: statement(generalId.Bytes())},
		{name: "a restored general repo", statement: statement(restoredId.Bytes())},
		{name: "a deleted general repo", statement: statement(deletedId.Bytes()), refusal: ErrConfigRule},
		{name: "a repo the rows do not hold", statement: statement(NewId().Bytes()), refusal: ErrConfigRule},
		{name: "the wildcard's zero id", statement: statement(make([]byte, len(Id{}))), refusal: ErrConfigRule},
		{name: "a repo_id of 15 bytes", statement: statement(generalId.Bytes()[:15]), refusal: ErrConfigRule},
	}
	for kind, repoId := range kindIds {
		cases = append(cases, aclTestCheckCase{name: kind.String(), statement: statement(repoId.Bytes()), refusal: ErrConfigRule})
	}
	aclTestCheckCases(t, state, cases)
}

// 16.2.2's body row: sealed_rules is 48 B and a positive multiple of 256 B, at most SealedMaxByteCount, read by its
// length alone: 304 B and the largest that fits pass; 0, 47, 48, 303, 305, the cap itself, which is no such length,
// and the first such length past it are refused.
func TestAclRepoPrefixRulesBodyByteCounts(t *testing.T) {
	cast := newAclStatementCast()
	repoId, _ := cast.generalRepo()
	state := cast.fixture.state(t)
	settings := DefaultAclPrefixSettings()
	largest := 48 + (settings.SealedMaxByteCount-48)/256*256
	cases := []struct {
		byteCount int
		fits      bool
	}{
		{byteCount: 0},
		{byteCount: 47},
		{byteCount: 48},
		{byteCount: 303},
		{byteCount: 304, fits: true},
		{byteCount: 305},
		{byteCount: 48 + 2*256, fits: true},
		{byteCount: largest, fits: true},
		{byteCount: settings.SealedMaxByteCount},
		{byteCount: largest + 256},
	}
	for _, c := range cases {
		statement := cast.fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES,
			&protocol.RepoPrefixRules{RepoId: repoId.Bytes(), SealedRules: aclTestSealedRules(c.byteCount)}, cast.laptop)
		_, err := state.CheckStatement(statement, nil)
		if c.fits && err != nil || !c.fits && !errors.Is(err, ErrConfigRule) {
			t.Errorf("a body of %d bytes: %v", c.byteCount, err)
		}
		if settings.SealedByteCountFits(c.byteCount) != c.fits {
			t.Errorf("the settings say %d bytes fit: %v", c.byteCount, !c.fits)
		}
	}
	if largest != 65328 {
		t.Errorf("the largest body under 64 KiB is %d", largest)
	}
	// the limit is the settings' field: a larger one takes the length past the default cap, and none takes nothing
	wider := DefaultAclPrefixSettings()
	wider.SealedMaxByteCount = largest + 256
	if !wider.SealedByteCountFits(largest + 256) {
		t.Error("a wider cap does not take the next length")
	}
	if (&AclPrefixSettings{}).SealedByteCountFits(aclTestSealedRulesByteCount) {
		t.Error("a zero cap takes a body")
	}
}

// 16.2.2's count row: the 256th set lands and the 257th is refused, naming the limit; a set in another repo still lands.
func TestAclRepoPrefixRulesStopsAtSetMaxCount(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := cast.generalRepo()
	otherId, _ := cast.generalRepo()
	setMaxCount := DefaultAclPrefixSettings().SetMaxCount
	for range setMaxCount - 1 {
		row.PrefixRules = append(row.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: cast.laptop.Bytes(), At: fixture.next()})
	}
	state := fixture.state(t)
	state, _ = fixture.apply(t, state, fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(repoId), cast.laptop))
	if count := len(state.Repo(repoId).GetPrefixRules()); count != setMaxCount {
		t.Fatalf("the 256th set leaves %d rows", count)
	}
	_, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(repoId), cast.adminDevice), nil)
	if !errors.Is(err, ErrConfigRule) || !strings.Contains(err.Error(), "SetMaxCount") || !strings.Contains(err.Error(), "256") {
		t.Errorf("the 257th set: %v", err)
	}
	if _, err := state.CheckStatement(fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(otherId), cast.laptop), nil); err != nil {
		t.Errorf("a set in another repo: %v", err)
	}
	if !DefaultAclPrefixSettings().SetFits(setMaxCount-1) || DefaultAclPrefixSettings().SetFits(setMaxCount) || (&AclPrefixSettings{}).SetFits(0) {
		t.Error("SetFits disagrees with the limit")
	}
}

// 16.2.3's fold: a row per set in position order, each with its signer, a later set never replacing an earlier one; the
// repos given are not changed; and nothing else of the row moves.
func TestFoldAclReposAppendsAPrefixRulesRowPerSet(t *testing.T) {
	repoId := NewId()
	creator, admin, writer := NewId(), NewId(), NewId()
	prefixRules := func(signer Id, at uint64) AclAccessLogEntry {
		return aclTestLogEntry(aclTestPrefixRules(repoId), bridge.SignedType_SIGNED_REPO_PREFIX_RULES, signer, at, false)
	}
	others := []AclAccessLogEntry{
		aclTestLogEntry(&protocol.RepoCreate{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}, bridge.SignedType_SIGNED_REPO_CREATE, creator, 2, false),
		aclTestLogEntry(&protocol.RepoAdmin{RepoId: repoId.Bytes(), SidecarId: admin.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD}, bridge.SignedType_SIGNED_REPO_ADMIN, creator, 4, false),
		aclTestLogEntry(&protocol.RepoGrant{RepoId: repoId.Bytes(), Subject: NewId().Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_READER}, bridge.SignedType_SIGNED_REPO_GRANT, admin, 6, false),
		aclTestLogEntry(&protocol.RepoVersioning{RepoId: repoId.Bytes(), Lock: protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED}, bridge.SignedType_SIGNED_REPO_VERSIONING, writer, 8, true),
	}
	entries := []AclAccessLogEntry{others[0], prefixRules(creator, 3), others[1], prefixRules(admin, 5), others[2], others[3], prefixRules(writer, 9), prefixRules(admin, 11)}
	repos, err := FoldAclRepos(nil, entries)
	if err != nil {
		t.Fatal(err)
	}
	want := []*protocol.AclRepoPrefixRulesRow{
		{Signer: creator.Bytes(), At: 3}, {Signer: admin.Bytes(), At: 5}, {Signer: writer.Bytes(), At: 9}, {Signer: admin.Bytes(), At: 11},
	}
	got := repos[0].GetPrefixRules()
	if len(got) != len(want) {
		t.Fatalf("%d rows, want %d", len(got), len(want))
	}
	for i := range want {
		if !proto.Equal(got[i], want[i]) {
			t.Errorf("row %d: %v, want %v", i, got[i], want[i])
		}
	}

	// the same log without its sets folds to the same row but for the list
	without, err := FoldAclRepos(nil, others)
	if err != nil {
		t.Fatal(err)
	}
	stripped := proto.Clone(repos[0]).(*protocol.AclRepo)
	stripped.PrefixRules = nil
	if !proto.Equal(stripped, without[0]) {
		t.Errorf("a set moved something else: %v, want %v", stripped, without[0])
	}

	// folding on: the rows given stay as they were
	before := proto.Clone(repos[0]).(*protocol.AclRepo)
	next, err := FoldAclRepos(repos, []AclAccessLogEntry{prefixRules(writer, 12)})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(repos[0], before) || len(next[0].GetPrefixRules()) != len(want)+1 {
		t.Errorf("the fold changed its input or appended nothing: %d rows", len(next[0].GetPrefixRules()))
	}
	// a set on a repo the rows do not hold folds nothing
	if _, err := FoldAclRepos(repos, []AclAccessLogEntry{aclTestLogEntry(aclTestPrefixRules(NewId()), bridge.SignedType_SIGNED_REPO_PREFIX_RULES, admin, 13, false)}); !errors.Is(err, ErrAclAccessLogFold) {
		t.Errorf("a set on no repo: %v", err)
	}
}

// 16.2.2's effect row: a set changes no right, holder or key, so every subject's rights on the repo, holders_shrunk_at
// and the rest of the rows stand, and its effect on §7's rows is none; ReapplyStatement, with the verdict a re-application
// takes from the body alone, appends the same row ApplyStatement did (DESIGN-DETAILS 5.2.2).
func TestAclRepoPrefixRulesMovesNoRightAndReappliesAlike(t *testing.T) {
	cast := newAclStatementCast()
	fixture := cast.fixture
	repoId, row := cast.generalRepo()
	row.HoldersShrunkAt = 1
	row.Grants = []*protocol.AclRepoGrantRow{{Subject: cast.phone.Bytes(), Role: protocol.RepoGrantRole_REPO_GRANT_ROLE_WRITER, Signer: cast.laptop.Bytes(), At: 1}}
	state := fixture.state(t)
	statement := fixture.statement(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, aclTestPrefixRules(repoId), cast.adminDevice)
	verdict, err := state.CheckStatement(statement, nil)
	if err != nil {
		t.Fatal(err)
	}
	applied, effect, err := state.ApplyStatement(statement, verdict)
	if err != nil {
		t.Fatal(err)
	}
	if effect.OwnerConfirmed != nil || len(effect.SuspendedSubjectIds) != 0 || len(effect.UnsuspendedSubjectIds) != 0 {
		t.Errorf("a set's effect on §7's rows: %+v", effect)
	}
	next, err := NewAclState(applied, fixture.view)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []Id{cast.laptop, cast.phone, cast.adminDevice, cast.stranger, cast.agent} {
		for _, audience := range []AclTokenAudience{AclTokenAudienceEvs, AclTokenAudienceGkm} {
			if before, after := aclTestRights(state, subject, repoId, audience), aclTestRights(next, subject, repoId, audience); before != after {
				t.Errorf("%s at %v: %b to %b", subject, audience, before, after)
			}
		}
	}
	stripped := proto.Clone(next.Repo(repoId)).(*protocol.AclRepo)
	if rows := stripped.GetPrefixRules(); len(rows) != 1 || !bytes.Equal(rows[0].GetSigner(), cast.adminDevice.Bytes()) || rows[0].GetAt() != statement.N {
		t.Fatalf("the rows %v", rows)
	}
	stripped.PrefixRules = nil
	if !proto.Equal(stripped, state.Repo(repoId)) || stripped.GetHoldersShrunkAt() != 1 {
		t.Errorf("a set moved the row: %v", stripped)
	}

	// a re-application's verdict is the body's first signer and nothing the check found (config_base.go's
	// configAclBodyVerdict), and it appends the same row
	reapplied, _, err := state.ReapplyStatement(statement, &AclStatementVerdict{Signer: cast.adminDevice})
	if err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(reapplied, applied) {
		t.Error("ReapplyStatement's rows differ from ApplyStatement's")
	}
}

// A general repo the owner's device creates through the log, becoming its admin.
func (self *testConfigNet) createGeneralRepo(label string) Id {
	self.t.Helper()
	repoId := testConfigId(label)
	self.mustPost(self.owner, bridge.SignedType_SIGNED_REPO_CREATE, &protocol.RepoCreate{
		Header: self.header(), RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL,
	})
	return repoId
}

// A RepoPrefixRules at the tip.
func (self *testConfigNet) prefixRules(repoId Id) *protocol.RepoPrefixRules {
	statement := aclTestPrefixRules(repoId)
	statement.Header = self.header()
	return statement
}

// The repo's prefix_rules in rows, nil when the rows hold no such repo.
func aclTestPrefixRows(rows *protocol.AclRows, repoId Id) []*protocol.AclRepoPrefixRulesRow {
	for _, repo := range rows.GetRepos() {
		if Id(repo.GetRepoId()) == repoId {
			return repo.GetPrefixRules()
		}
	}
	return nil
}

// A log's AclRows at its state.
func aclTestLogRows(t testing.TB, log *ConfigLog) *protocol.AclRows {
	t.Helper()
	acl, err := log.State().Acl()
	if err != nil {
		t.Fatal(err)
	}
	return acl.Rows()
}

// Whether rows hold exactly want, in order.
func aclTestPrefixRowsEqual(got []*protocol.AclRepoPrefixRulesRow, want []*protocol.AclRepoPrefixRulesRow) bool {
	return slices.EqualFunc(got, want, func(a *protocol.AclRepoPrefixRulesRow, b *protocol.AclRepoPrefixRulesRow) bool {
		return proto.Equal(a, b)
	})
}

// 16.2.12's trap on TEAM's log: a set is taken as the access-log statement it is, never refused as an unknown type,
// one carrying a field this release does not know among them (§6.4), so no reader forks at a repo's first set; a
// refused set folds nothing. The rows then agree everywhere 5.2.2 says they are written: the reader's ApplyStatement,
// its re-application over a base whose fold stops before the sets, a new device starting at that base, the compile of
// a base folding through them, and a rows-only reader starting there.
func TestAclRepoPrefixRulesRowsAgreeAcrossBases(t *testing.T) {
	net := newTestConfigNet(t)
	phone := net.admitMemberDevice("prefix rules admin")
	stranger := net.admitMemberDevice("prefix rules stranger")
	repoId := net.createGeneralRepo("prefix rules repo")
	net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
		Header: net.header(), RepoId: repoId.Bytes(), SidecarId: phone.sidecarId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
	})
	beforeSets := net.n
	want := []*protocol.AclRepoPrefixRulesRow{}
	file := func(signer testConfigDevice, statement *protocol.RepoPrefixRules) {
		t.Helper()
		at := net.mustPost(signer, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, statement).Pin.GetVersion()
		want = append(want, &protocol.AclRepoPrefixRulesRow{Signer: signer.sidecarId.Bytes(), At: at})
	}
	file(phone, net.prefixRules(repoId))
	net.mustRefuse(stranger, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, net.prefixRules(repoId), ErrConfigAuthority)
	// a later release's field: kept as unknown, never refused (§6.4)
	newer := net.prefixRules(repoId)
	newer.ProtoReflect().SetUnknown(protowire.AppendVarint(protowire.AppendTag(nil, 99, protowire.VarintType), 1))
	file(net.owner, newer)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("between the sets"))
	file(phone, net.prefixRules(repoId))
	holdsTheSets := func(name string, rows *protocol.AclRows) {
		t.Helper()
		if got := aclTestPrefixRows(rows, repoId); !aclTestPrefixRowsEqual(got, want) {
			t.Errorf("%s holds %v, want %v", name, got, want)
		}
	}
	holdsTheSets("the reader at the entries", aclTestLogRows(t, net.log))

	configVersion := net.log.State().Base().GetConfigVersion()
	// a base whose fold stops before the sets: each reader re-applies them over the base's rows
	configVersion += 1
	net.fold(net.owner, beforeSets, configVersion)
	holdsTheSets("the reader past a base whose tail holds the sets", aclTestLogRows(t, net.log))
	for i, reader := range net.everyReader() {
		holdsTheSets(fmt.Sprintf("reader %d starting at that base", i), aclTestLogRows(t, reader))
	}

	// a base folding through the sets: what its head check compiled from, and readers starting there
	configVersion += 1
	net.fold(net.owner, net.n, configVersion)
	if len(net.source.checks) == 0 {
		t.Fatal("no head check")
	}
	holdsTheSets("the base compile", net.source.checks[len(net.source.checks)-1].CompileRows.AclStatements)
	for i, reader := range net.everyReader() {
		holdsTheSets(fmt.Sprintf("reader %d at the base", i), aclTestLogRows(t, reader))
	}
	// past the retention point, after a base folding nothing new
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("after the sets"))
	configVersion += 1
	net.fold(net.owner, net.n, configVersion)
	if point := net.log.State().RetentionPoint(); point <= want[len(want)-1].GetAt() {
		t.Fatalf("the retention point %d has not passed the sets", point)
	}
	for i, reader := range net.everyReader() {
		holdsTheSets(fmt.Sprintf("reader %d past the retention point", i), aclTestLogRows(t, reader))
	}
	net.everyReaderAgrees()
}

// One RepoPrefixRules a generated log took, with what its own verdict says the row is.
type aclTestPrefixSet struct {
	repoId Id
	row    *protocol.AclRepoPrefixRulesRow
}

// A generated log of general repos, their admins and RepoDeletes, sets filed by admins, config writers and devices that
// are neither, and bases folding at random points between the previous base's position and the tip, from a seed; it
// returns the repos and every set the log took, from the verdicts it reached.
func (self *testConfigNet) generatePrefixRules(seed uint64, count int) ([]Id, []aclTestPrefixSet) {
	self.t.Helper()
	random := rand.New(rand.NewPCG(seed, seed^0x2545f4914f6cdd1d))
	pick := func(count int) int { return random.IntN(count) }
	devices := []testConfigDevice{self.owner}
	for i := range 3 {
		devices = append(devices, self.admitMemberDevice(fmt.Sprintf("prefix generated %d %d", seed, i)))
	}
	repoIds := []Id{self.createGeneralRepo(fmt.Sprintf("prefix generated repo %d", seed))}
	sets := []aclTestPrefixSet{}
	configVersion := self.log.State().Base().GetConfigVersion()
	for i := range count {
		repoId := repoIds[pick(len(repoIds))]
		switch op := pick(10); {
		case op == 0:
			repoIds = append(repoIds, self.createGeneralRepo(fmt.Sprintf("prefix generated repo %d %d", seed, i)))
		case op == 1:
			self.post(self.owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
				Header: self.header(), RepoId: repoId.Bytes(), SidecarId: devices[pick(len(devices))].sidecarId.Bytes(),
				Change: protocol.RepoAdminChange(1 + pick(2)),
			})
		case op <= 5:
			// half by the owner's config writer, the rest by any device, an admin of the repo or not
			signer := self.owner
			if pick(2) == 0 {
				signer = devices[pick(len(devices))]
			}
			if verdict := self.post(signer, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, self.prefixRules(repoId)); verdict.Accepted() {
				sets = append(sets, aclTestPrefixSet{repoId: repoId, row: &protocol.AclRepoPrefixRulesRow{Signer: signer.sidecarId.Bytes(), At: verdict.Pin.GetVersion()}})
			}
		case op == 6 && pick(4) == 0:
			self.post(self.owner, bridge.SignedType_SIGNED_REPO_DELETE, &protocol.RepoDelete{
				Header: self.header(), RepoId: repoId.Bytes(), DeletionId: testConfigId(fmt.Sprintf("prefix deletion %d %d", seed, i)).Bytes(),
			})
		case op == 7:
			// a fold anywhere from the previous base's position to the tip
			base := self.log.State().Base().GetVersion()
			configVersion += 1
			self.fold(self.owner, base+uint64(pick(int(self.n-base)+1)), configVersion)
		default:
			self.mustPost(self.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, self.memberAdmitStatement(fmt.Sprintf("prefix filler %d %d", seed, i)))
		}
	}
	return repoIds, sets
}

// The rows half of 16.6's base-independence test, on generated logs: the long-running reader, another that replays
// every entry, a new device and a rows-only reader each started at the newest base hold, for every repo, exactly the
// sets the log's verdicts took, in position order, and so do the rows each base's compile carried at its fold; as the
// rows advance across bases folding sets and past their retention point.
func TestAclPrefixRulesRowsAreBaseIndependentOverGeneratedLogs(t *testing.T) {
	// the sets taken, and the bases whose compile carried at least one
	setCount, baseCount := 0, 0
	for seed := uint64(1); seed <= 4; seed += 1 {
		net := newTestConfigNet(t)
		checksBefore := len(net.source.checks)
		repoIds, sets := net.generatePrefixRules(seed, 120)
		setCount += len(sets)
		wantAt := func(repoId Id, through uint64) []*protocol.AclRepoPrefixRulesRow {
			want := []*protocol.AclRepoPrefixRulesRow{}
			for _, set := range sets {
				if set.repoId == repoId && set.row.GetAt() <= through {
					want = append(want, set.row)
				}
			}
			return want
		}
		everyReaderHoldsTheSets := func(when string) {
			t.Helper()
			readers := append([]*ConfigLog{net.log}, net.everyReader()...)
			for i, reader := range readers {
				rows := aclTestLogRows(t, reader)
				for _, repoId := range repoIds {
					if got, want := aclTestPrefixRows(rows, repoId), wantAt(repoId, math.MaxUint64); !aclTestPrefixRowsEqual(got, want) {
						t.Fatalf("seed %d %s, reader %d, repo %s: %v, want %v", seed, when, i, repoId, got, want)
					}
				}
			}
		}
		// where the generated log ends, the newest base's tail may hold sets that a new device re-applies
		everyReaderHoldsTheSets("at the generated tip")
		// then two bases folding the tip, so the retention point passes every set
		for i := range 2 {
			net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
			net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("prefix after %d %d", seed, i)))
		}
		everyReaderHoldsTheSets("past the retention point")
		// each base's compile carried the sets through its fold, at the net's reader and at the reader replaying every
		// entry alike; a reader starting at a base checks no compile
		carried := map[uint64]bool{}
		for _, check := range net.source.checks[checksBefore:] {
			if check.CompileRows == nil {
				continue
			}
			foldedThrough := check.Header.GetFoldedThrough()
			for _, repoId := range repoIds {
				got, want := aclTestPrefixRows(check.CompileRows.AclStatements, repoId), wantAt(repoId, foldedThrough)
				if !aclTestPrefixRowsEqual(got, want) {
					t.Fatalf("seed %d, the base folding through %d, repo %s: %v, want %v", seed, foldedThrough, repoId, got, want)
				}
				if len(want) != 0 {
					carried[check.Header.GetVersion()] = true
				}
			}
		}
		baseCount += len(carried)
		if point := net.log.State().RetentionPoint(); len(sets) != 0 && point <= sets[len(sets)-1].row.GetAt() {
			t.Errorf("seed %d: the retention point %d has not passed the last set at %d", seed, point, sets[len(sets)-1].row.GetAt())
		}
		net.everyReaderAgrees()
	}
	if setCount < 40 || baseCount < 12 {
		t.Errorf("the generated logs took %d sets, carried by %d bases", setCount, baseCount)
	}
}

// 16.2.3's arithmetic and §8.8's 4 MiB: a repo's sets are bytes of the ProjectionRows that AclRowsCheckLimits holds to
// the limit. At the cap a repo's 256 rows take 24 B each below position 2^21 and 31 B at the largest, 6 KiB and at
// most 7.75 KiB; rows filled to the limit with them pass, and one more set's row puts them over. And the compile a base
// carries holds them: a state's sets reach CompileProjectionRows' acl part.
func TestAclRowsCheckLimitsCountsThePrefixRuleRows(t *testing.T) {
	repoRows := func(at uint64, count int) *protocol.AclRepo {
		repo := &protocol.AclRepo{RepoId: NewId().Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL}
		for i := range count {
			repo.PrefixRules = append(repo.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: NewId().Bytes(), At: at - uint64(i)})
		}
		return repo
	}
	setMaxCount := DefaultAclPrefixSettings().SetMaxCount
	for _, c := range []struct {
		at        uint64
		byteCount int
	}{
		{at: 1<<21 - 1, byteCount: 24 * setMaxCount},
		{at: math.MaxUint64, byteCount: 31 * setMaxCount},
	} {
		bare := repoRows(c.at, 0)
		if got := proto.Size(repoRows(c.at, setMaxCount)) - proto.Size(bare); got != c.byteCount {
			t.Errorf("256 rows at %d take %d bytes, want %d", c.at, got, c.byteCount)
		}
	}

	// a projection whose rows hold the repo's 256 sets and filler to exactly 4 MiB
	rows := &protocol.AclRows{Repos: []*protocol.AclRepo{repoRows(1<<21-1, setMaxCount)}}
	projectionByteCount := func() int {
		return proto.Size(&bridge.ProjectionRows{Acl: testConfigMarshal(t, rows)})
	}
	rows.Bridge = make([]byte, configRowsMaxByteCount-projectionByteCount())
	for projectionByteCount() != configRowsMaxByteCount {
		rows.Bridge = rows.Bridge[:len(rows.Bridge)-1]
	}
	if err := AclRowsCheckLimits(rows, projectionByteCount(), nil); err != nil {
		t.Fatalf("4 MiB with the sets: %v", err)
	}
	rows.Repos[0].PrefixRules = append(rows.Repos[0].PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: NewId().Bytes(), At: 1 << 21})
	if err := AclRowsCheckLimits(rows, projectionByteCount(), nil); !errors.Is(err, ErrAclRowsTooLarge) {
		t.Errorf("one more set's row past 4 MiB: %v", err)
	}

	// the compile a base carries: a state's sets reach CompileProjectionRows' acl part, which is what a writer counts
	net := newTestConfigNet(t)
	repoId := net.createGeneralRepo("counted repo")
	for range 3 {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, net.prefixRules(repoId))
	}
	compiled, err := CompileProjectionRows(testConfigHead(t, net), ConfigCompileRowsOf(net.log.State()))
	if err != nil {
		t.Fatal(err)
	}
	projection := &bridge.ProjectionRows{}
	compiledAcl := &protocol.AclRows{}
	if err := proto.Unmarshal(compiled, projection); err != nil {
		t.Fatal(err)
	}
	if err := proto.Unmarshal(projection.GetAcl(), compiledAcl); err != nil {
		t.Fatal(err)
	}
	if got, want := aclTestPrefixRows(compiledAcl, repoId), aclTestPrefixRows(aclTestLogRows(t, net.log), repoId); len(want) != 3 || !aclTestPrefixRowsEqual(got, want) {
		t.Errorf("the compiled rows hold %v, the state %v", got, want)
	}
}

// ACL-M6-04's fixtures.

// RK_g of a test repo, its GenRotate signed at timeMs.
func aclTestPrefixRepoKey(repoId Id, generation uint64, timeMs int64) *EvsRepoKey {
	return &EvsRepoKey{repoId: repoId, generation: generation, timeMs: timeMs, repoKey: bytes.Repeat([]byte{byte(generation) ^ 0x6c}, gkmRepoKeyByteCount)}
}

// A repo's keys as a device holds them, which a test adds to; counts what it is asked.
type aclTestPrefixKeys struct {
	stateLock sync.Mutex
	keys      map[uint64]*EvsRepoKey
	askCount  int
}

func newAclTestPrefixKeys(keys ...*EvsRepoKey) *aclTestPrefixKeys {
	self := &aclTestPrefixKeys{keys: map[uint64]*EvsRepoKey{}}
	for _, key := range keys {
		self.add(key)
	}
	return self
}

func (self *aclTestPrefixKeys) add(key *EvsRepoKey) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.keys[key.Generation()] = key
}

func (self *aclTestPrefixKeys) asked() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.askCount
}

func (self *aclTestPrefixKeys) RepoKeyAt(generation uint64) *EvsRepoKey {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.askCount += 1
	return self.keys[generation]
}

func (self *aclTestPrefixKeys) PathKeyAt(epoch uint64) *EvsPathKey {
	key := self.RepoKeyAt(epoch)
	if key == nil {
		return nil
	}
	pathKey, err := NewEvsPathKey(key)
	if err != nil {
		return nil
	}
	return pathKey
}

func (self *aclTestPrefixKeys) GenRotateTimeAt(generation uint64) (int64, bool) {
	key := self.RepoKeyAt(generation)
	if key == nil {
		return 0, false
	}
	return key.Time().UnixMilli(), true
}

// A RepoPrefixRules' seal context with a nonce of one repeated byte.
func aclTestPrefixContext(nonce byte) *ConfigSealContext {
	return &ConfigSealContext{
		SignedType: bridge.SignedType_SIGNED_REPO_PREFIX_RULES,
		NetworkId:  testConfigId("network").Bytes(),
		Nonce:      bytes.Repeat([]byte{nonce}, configNonceByteCount),
	}
}

// A path's raw names from its / form; "" has none.
func aclTestNames(path string) [][]byte {
	if path == "" {
		return nil
	}
	names := [][]byte{}
	for _, name := range strings.Split(path, "/") {
		names = append(names, []byte(name))
	}
	return names
}

// A write rule of subject over a path in / form, "" for every path.
func aclTestPrefixRule(subject Id, path string) *protocol.PrefixRule {
	return &protocol.PrefixRule{Subject: subject.Bytes(), Path: aclTestNames(path), Action: protocol.PrefixAction_PREFIX_ACTION_WRITE}
}

// An opened set at a position, its rules sorted, with no seal: what PrefixVerdict reads.
func aclTestOpenedSet(at uint64, signer Id, rules ...*protocol.PrefixRule) *AclPrefixRuleSet {
	return &AclPrefixRuleSet{At: at, Signer: signer, State: AclPrefixSetOpened, Generation: 1, Rules: AclPrefixSortRules(rules)}
}

// The plaintext's seal under key in context with no padding: an AEAD that passes over a plaintext whose pad marker is
// missing, which only a hand-built body has.
func aclTestSealUnpadded(t *testing.T, key *EvsRepoKey, context *ConfigSealContext, body proto.Message) []byte {
	t.Helper()
	derived, err := key.DeriveKey(EvsKeyPurposeStatement, nil)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := chacha20poly1305.NewX(derived)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := testConfigMarshal(t, body)
	plaintext = append(plaintext, make([]byte, configSealPadByteCount-len(plaintext)%configSealPadByteCount)...)
	nonce := bytes.Repeat([]byte{0x42}, chacha20poly1305.NonceSizeX)
	sealed := append(binary64(key.Generation()), nonce...)
	return aead.Seal(sealed, nonce, plaintext, context.aad(key.Generation()))
}

// u64be(value).
func binary64(value uint64) []byte {
	encoded := make([]byte, 8)
	for i := range 8 {
		encoded[7-i] = byte(value >> (8 * i))
	}
	return encoded
}

// 16.6's second bullet: a set's states. Opened; each void cause in turn (a wrong key, a flipped byte, bad padding,
// rules out of order, a rule twice, a 15 B subject, a 33-component path, an empty component, a slash, a NUL, 257 rules,
// an action of 0); newer (an unknown field on the set and on a rule, an action of 2); and a body sealed for another
// repo, for another statement type or to generation 0, which opens in none.
func TestOpenPrefixRuleSetSaysWhatEachBodyIs(t *testing.T) {
	repoId := testConfigId("prefix states repo")
	key := aclTestPrefixRepoKey(repoId, 2, testConfigStartMs)
	context := aclTestPrefixContext(1)
	entryMs := testConfigStartMs + 1000
	member, other := testConfigId("states member device"), testConfigId("states other device")
	good := &protocol.PrefixRuleSet{Rules: AclPrefixSortRules([]*protocol.PrefixRule{
		aclTestPrefixRule(member, "agents/build"), aclTestPrefixRule(other, "docs"), aclTestPrefixRule(other, ""),
	})}
	seal := func(sealKey *EvsRepoKey, sealContext *ConfigSealContext, set *protocol.PrefixRuleSet) []byte {
		t.Helper()
		sealed, err := SealConfigBody(sealKey, sealContext, set, nil)
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	open := func(sealed []byte) *AclPrefixRuleSet {
		return OpenPrefixRuleSet(sealed, context, testConfigSealKeyAt(key), func(generation uint64) (int64, bool) {
			return key.Time().UnixMilli(), generation == key.Generation()
		}, entryMs, nil)
	}
	edited := func(edit func(set *protocol.PrefixRuleSet)) []byte {
		set := proto.Clone(good).(*protocol.PrefixRuleSet)
		edit(set)
		return seal(key, context, set)
	}

	opened := open(seal(key, context, good))
	if opened.State != AclPrefixSetOpened || opened.VoidCause != AclPrefixVoidNone || opened.Generation != 2 ||
		!proto.Equal(&protocol.PrefixRuleSet{Rules: opened.Rules}, good) {
		t.Fatalf("a good set: %+v", opened)
	}

	flipped := seal(key, context, good)
	flipped[len(flipped)-20] ^= 0x01
	wrongKey := &EvsRepoKey{repoId: repoId, generation: 2, repoKey: bytes.Repeat([]byte{0x99}, gkmRepoKeyByteCount)}
	otherRepoKey := &EvsRepoKey{repoId: testConfigId("another repo"), generation: 2, repoKey: bytes.Clone(key.repoKey)}
	otherType := aclTestPrefixContext(1)
	otherType.SignedType = bridge.SignedType_SIGNED_REPO_VERSIONING
	generationZero := seal(key, context, good)
	copy(generationZero[:8], binary64(0))
	manyRules := []*protocol.PrefixRule{}
	for i := range 257 {
		manyRules = append(manyRules, aclTestPrefixRule(member, fmt.Sprintf("r%03d", i)))
	}
	deep := strings.Repeat("d/", 32) + "d"
	for _, c := range []struct {
		name   string
		sealed []byte
		cause  AclPrefixVoidCause
	}{
		{name: "a wrong key", sealed: seal(wrongKey, context, good), cause: AclPrefixVoidSeal},
		{name: "a flipped byte", sealed: flipped, cause: AclPrefixVoidSeal},
		{name: "bad padding", sealed: aclTestSealUnpadded(t, key, context, good), cause: AclPrefixVoidSeal},
		{name: "another repo's key", sealed: seal(otherRepoKey, context, good), cause: AclPrefixVoidSeal},
		{name: "another statement type", sealed: seal(key, otherType, good), cause: AclPrefixVoidSeal},
		{name: "generation 0", sealed: generationZero, cause: AclPrefixVoidSeal},
		{name: "rules out of order", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0], set.Rules[1] = set.Rules[1], set.Rules[0] }), cause: AclPrefixVoidOrder},
		{name: "a rule twice", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules = append(set.Rules[:1], set.Rules...) }), cause: AclPrefixVoidOrder},
		{name: "a 15 B subject", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Subject = set.Rules[0].Subject[:15] }), cause: AclPrefixVoidSubject},
		{name: "a 33-component path", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Path = aclTestNames(deep) }), cause: AclPrefixVoidPath},
		{name: "an empty component", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Path = [][]byte{[]byte("agents"), {}} }), cause: AclPrefixVoidPath},
		{name: "a slash", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Path = [][]byte{[]byte("agents/build")} }), cause: AclPrefixVoidPath},
		{name: "a NUL", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Path = [][]byte{[]byte("agents\x00")} }), cause: AclPrefixVoidPath},
		{name: "257 rules", sealed: seal(key, context, &protocol.PrefixRuleSet{Rules: manyRules}), cause: AclPrefixVoidRuleCount},
		{name: "an action of 0", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Action = 0 }), cause: AclPrefixVoidAction},
	} {
		if got := open(c.sealed); got.State != AclPrefixSetVoid || got.VoidCause != c.cause || got.Rules != nil {
			t.Errorf("%s: %s (%s), want void (%s)", c.name, got.State, got.VoidCause, c.cause)
		}
	}
	// the 256th rule is the cap, not past it
	if got := open(seal(key, context, &protocol.PrefixRuleSet{Rules: manyRules[:256]})); got.State != AclPrefixSetOpened {
		t.Errorf("256 rules: %s (%s)", got.State, got.VoidCause)
	}
	// 32 components are a token path's most
	if got := open(edited(func(set *protocol.PrefixRuleSet) { set.Rules[0].Path = aclTestNames(strings.TrimSuffix(deep, "/d")) })); got.State != AclPrefixSetOpened {
		t.Errorf("32 components: %s (%s)", got.State, got.VoidCause)
	}

	unknown := protowire.AppendVarint(protowire.AppendTag(nil, 9, protowire.VarintType), 1)
	for _, c := range []struct {
		name   string
		sealed []byte
	}{
		{name: "an unknown field on the set", sealed: edited(func(set *protocol.PrefixRuleSet) { set.ProtoReflect().SetUnknown(unknown) })},
		{name: "an unknown field on a rule", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[1].ProtoReflect().SetUnknown(unknown) })},
		{name: "an action of 2", sealed: edited(func(set *protocol.PrefixRuleSet) { set.Rules[2].Action = 2 })},
	} {
		if got := open(c.sealed); got.State != AclPrefixSetNewer || got.Rules != nil {
			t.Errorf("%s: %s (%s), want newer", c.name, got.State, got.VoidCause)
		}
	}
}

// The rest of 16.6's second bullet: a set sealed to a generation this device does not hold is pending; it opens when
// the generation arrives within the grace, and is void when the generation's GenRotate was signed past it, exactly
// past it and not at it.
func TestOpenPrefixRuleSetPendingThenOpenedOrLate(t *testing.T) {
	repoId := testConfigId("prefix pending repo")
	context := aclTestPrefixContext(2)
	entryMs := testConfigStartMs
	set := &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{aclTestPrefixRule(testConfigId("pending device"), "docs")}}
	grace := DefaultAclPrefixSettings().GenerationFormGrace.Milliseconds()
	sealed, err := SealPrefixRuleSet(aclTestPrefixRepoKey(repoId, 3, entryMs+grace), context, set, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := newAclTestPrefixKeys(aclTestPrefixRepoKey(repoId, 1, entryMs), aclTestPrefixRepoKey(repoId, 2, entryMs))
	open := func() *AclPrefixRuleSet {
		return OpenPrefixRuleSet(sealed, context, keys.RepoKeyAt, keys.GenRotateTimeAt, entryMs, nil)
	}
	if got := open(); got.State != AclPrefixSetPending || got.Generation != 3 {
		t.Fatalf("before generation 3 arrives: %s at %d", got.State, got.Generation)
	}
	// generation 3 arrives, signed exactly the grace after the entry: opened
	keys.add(aclTestPrefixRepoKey(repoId, 3, entryMs+grace))
	if got := open(); got.State != AclPrefixSetOpened || len(got.Rules) != 1 {
		t.Fatalf("generation 3 at the grace: %s (%s)", got.State, got.VoidCause)
	}
	// the same generation signed 1 ms later is past the grace: void before the seal is opened
	keys.add(aclTestPrefixRepoKey(repoId, 3, entryMs+grace+1))
	if got := open(); got.State != AclPrefixSetVoid || got.VoidCause != AclPrefixVoidLateGeneration {
		t.Fatalf("generation 3 past the grace: %s (%s)", got.State, got.VoidCause)
	}
	// a key of another generation answered for 3 opens nothing and waits
	if got := OpenPrefixRuleSet(sealed, context, func(generation uint64) *EvsRepoKey { return aclTestPrefixRepoKey(repoId, 2, entryMs) }, nil, entryMs, nil); got.State != AclPrefixSetPending {
		t.Errorf("a key of generation 2 for 3: %s", got.State)
	}
}

// SealPrefixRuleSet runs the readers' validator first, so no design device files a void or newer set, nor one past
// SealedMaxByteCount, nor one bound to another statement; what it seals opens to the same rules.
func TestSealPrefixRuleSetRefusesWhatNoReaderOpens(t *testing.T) {
	repoId := testConfigId("prefix sealer repo")
	key := aclTestPrefixRepoKey(repoId, 1, testConfigStartMs)
	context := aclTestPrefixContext(3)
	device := testConfigId("sealer device")
	good := &protocol.PrefixRuleSet{Rules: AclPrefixSortRules([]*protocol.PrefixRule{aclTestPrefixRule(device, "a/b"), aclTestPrefixRule(device, "a")})}
	sealed, err := SealPrefixRuleSet(key, context, good, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !DefaultAclPrefixSettings().SealedByteCountFits(len(sealed)) {
		t.Errorf("a sealed set of %d bytes does not fit the id-level rule", len(sealed))
	}
	if got := OpenPrefixRuleSet(sealed, context, testConfigSealKeyAt(key), nil, testConfigStartMs, nil); got.State != AclPrefixSetOpened ||
		!proto.Equal(&protocol.PrefixRuleSet{Rules: got.Rules}, good) {
		t.Fatalf("the sealed set opens as %s", got.State)
	}
	otherType := aclTestPrefixContext(3)
	otherType.SignedType = bridge.SignedType_SIGNED_REPO_VERSIONING
	small := DefaultAclPrefixSettings()
	small.SealedMaxByteCount = 48 + 256
	long := &protocol.PrefixRuleSet{}
	for i := range 20 {
		long.Rules = append(long.Rules, aclTestPrefixRule(device, fmt.Sprintf("a/long-component-%02d", i)))
	}
	for _, c := range []struct {
		name     string
		context  *ConfigSealContext
		set      *protocol.PrefixRuleSet
		settings *AclPrefixSettings
	}{
		{name: "out of order", context: context, set: &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{good.Rules[1], good.Rules[0]}}},
		{name: "a rule twice", context: context, set: &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{good.Rules[0], good.Rules[0]}}},
		{name: "an action of 0", context: context, set: &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{{Subject: device.Bytes()}}}},
		{name: "an action of 2, newer", context: context, set: &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{{Subject: device.Bytes(), Action: 2}}}},
		{name: "a 15 B subject", context: context, set: &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{{Subject: device.Bytes()[:15], Action: 1}}}},
		{name: "bound to another statement", context: otherType, set: good},
		{name: "past SealedMaxByteCount", context: context, set: long, settings: small},
		{name: "no set", context: context},
	} {
		if _, err := SealPrefixRuleSet(key, c.context, c.set, nil, c.settings); !errors.Is(err, ErrAclPrefixSetInvalid) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// the empty set is opened, and binds everyone to nothing (16.2.2)
	if _, err := SealPrefixRuleSet(key, context, &protocol.PrefixRuleSet{}, nil, nil); err != nil {
		t.Errorf("the empty set: %v", err)
	}
}

// 16.6's third bullet: names' table of the seven subject forms against a member device, an ephemeral one, a tagged
// one and a tombstone of each (and a tagged ephemeral one, and a tagged row that also carries a member id, which a
// user subject does not name). A group's atom, a role's, the derived user and sidecar atoms and every other autogroup,
// autogroup:admin among them, name nobody: nothing resolves an atom through the state's atoms.
func TestAclPrefixNamesBySubjectForm(t *testing.T) {
	memberId := testConfigId("names member")
	ci := testConfigId("names tag ci")
	memberDevice := &bridge.SidecarRow{SidecarId: testConfigId("names member device").Bytes(), MemberId: memberId.Bytes()}
	ephemeral := &bridge.SidecarRow{SidecarId: testConfigId("names ephemeral").Bytes(), MemberId: memberId.Bytes(), Ephemeral: true}
	tagged := &bridge.SidecarRow{SidecarId: testConfigId("names tagged").Bytes(), TagIds: [][]byte{ci.Bytes()}}
	taggedEphemeral := &bridge.SidecarRow{SidecarId: testConfigId("names tagged ephemeral").Bytes(), TagIds: [][]byte{ci.Bytes()}, Ephemeral: true}
	taggedWithMember := &bridge.SidecarRow{SidecarId: testConfigId("names tagged with member").Bytes(), TagIds: [][]byte{ci.Bytes()}, MemberId: memberId.Bytes()}
	rows := []*bridge.SidecarRow{memberDevice, ephemeral, tagged, taggedEphemeral, taggedWithMember}
	for _, row := range slices.Clone(rows) {
		tombstone := proto.Clone(row).(*bridge.SidecarRow)
		tombstone.RevokedAt, tombstone.NotAfter = 99, testConfigStartMs
		rows = append(rows, tombstone)
	}
	autogroup := func(value protocol.AclAutogroup) []byte { return AclAutogroupAtom(value).Bytes() }
	// by row, in rows' order before the tombstones: member device, ephemeral, tagged, tagged ephemeral, tagged with a
	// member id
	cases := []struct {
		name    string
		subject []byte
		names   [5]bool
	}{
		{name: "sidecar:<member device>", subject: memberDevice.SidecarId, names: [5]bool{true, false, false, false, false}},
		{name: "sidecar:<ephemeral>", subject: ephemeral.SidecarId, names: [5]bool{false, true, false, false, false}},
		{name: "sidecar:<tagged>", subject: tagged.SidecarId, names: [5]bool{false, false, true, false, false}},
		{name: "user:<member>", subject: memberId.Bytes(), names: [5]bool{true, true, false, false, false}},
		{name: "tag:ci", subject: ci.Bytes(), names: [5]bool{false, false, true, true, true}},
		{name: "autogroup:sidecar", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR), names: [5]bool{true, true, true, true, true}},
		{name: "autogroup:tagged", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), names: [5]bool{false, false, true, true, true}},
		{name: "autogroup:member", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), names: [5]bool{true, false, false, false, false}},
		{name: "autogroup:ephemeral", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL), names: [5]bool{false, true, false, false, false}},
		{name: "a group's atom", subject: testConfigId("names group").Bytes()},
		{name: "a role's atom", subject: AclDerivedAtom(AclDerivedAtomRole, []byte("admin")).Bytes()},
		{name: "the member's derived user atom", subject: AclDerivedAtom(AclDerivedAtomMember, memberId.Bytes()).Bytes()},
		{name: "the member device's derived sidecar atom", subject: AclDerivedAtom(AclDerivedAtomSidecar, memberDevice.SidecarId).Bytes()},
		{name: "autogroup:admin", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN)},
		{name: "autogroup:owner", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_OWNER)},
		{name: "autogroup:auditor", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_AUDITOR)},
		{name: "autogroup:untagged", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_UNTAGGED)},
		{name: "autogroup:network", subject: autogroup(protocol.AclAutogroup_ACL_AUTOGROUP_NETWORK)},
		{name: "a fixed form of no autogroup", subject: append(make([]byte, 15), 200)},
		{name: "a subject of 15 bytes", subject: memberDevice.SidecarId[:15]},
	}
	for _, c := range cases {
		for i, row := range rows {
			if got, want := aclPrefixNames(c.subject, row), c.names[i%5]; got != want {
				t.Errorf("%s names row %d: %t, want %t", c.name, i, got, want)
			}
		}
	}
	if aclPrefixNames(memberDevice.SidecarId, nil) {
		t.Error("a subject names no row at all")
	}
}

// A reader's judge of one repo in one path epoch: the rows of a member device, a tagged agent and an admin's device.
type aclTestVerdictWorld struct {
	t       *testing.T
	pathKey *EvsPathKey
	ci      Id
	member  *bridge.SidecarRow
	agent   *bridge.SidecarRow
	admin   *bridge.SidecarRow
}

func newAclTestVerdictWorld(t *testing.T, epoch uint64) *aclTestVerdictWorld {
	pathKey, err := NewEvsPathKey(aclTestPrefixRepoKey(testConfigId("verdict repo"), epoch, testConfigStartMs))
	if err != nil {
		t.Fatal(err)
	}
	ci := testConfigId("verdict tag ci")
	return &aclTestVerdictWorld{
		t: t, pathKey: pathKey, ci: ci,
		member: &bridge.SidecarRow{SidecarId: testConfigId("verdict member device").Bytes(), MemberId: testConfigId("verdict member").Bytes()},
		agent:  &bridge.SidecarRow{SidecarId: testConfigId("verdict agent").Bytes(), TagIds: [][]byte{ci.Bytes()}},
		admin:  &bridge.SidecarRow{SidecarId: testConfigId("verdict admin device").Bytes(), MemberId: testConfigId("verdict admin").Bytes()},
	}
}

// A row's sidecar id.
func aclTestRowId(row *bridge.SidecarRow) Id {
	return Id(row.GetSidecarId())
}

// T of a path in / form in the world's epoch, "" the root's empty token path.
func (self *aclTestVerdictWorld) tokens(path string) EvsTokenPath {
	self.t.Helper()
	tokenPath, err := EvsPathTokens(self.pathKey, aclTestNames(path))
	if err != nil {
		self.t.Fatal(err)
	}
	return tokenPath
}

// The rows that list sets, in position order.
func aclTestRowsOf(sets ...*AclPrefixRuleSet) []*protocol.AclRepoPrefixRulesRow {
	rows := []*protocol.AclRepoPrefixRulesRow{}
	for _, set := range sets {
		rows = append(rows, &protocol.AclRepoPrefixRulesRow{Signer: set.Signer.Bytes(), At: set.At})
	}
	return rows
}

// The args of a change by signer pinned at pin over sets, on a file-mode shared ref of a general repo, every set a row.
func (self *aclTestVerdictWorld) args(signer *bridge.SidecarRow, pin uint64, change *AclPrefixChange, sets ...*AclPrefixRuleSet) *AclPrefixVerdictArgs {
	return &AclPrefixVerdictArgs{
		RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		RefName: []byte("main"), PinVersion: pin, Signer: signer, Rows: aclTestRowsOf(sets...), Sets: sets,
		TokenTable: AclPrefixTokenTableOf(self.pathKey), Change: change,
	}
}

// A file change at path, a version or a removal.
func (self *aclTestVerdictWorld) file(path string, removal bool) *AclPrefixChange {
	return &AclPrefixChange{TokenPath: self.tokens(path), Removal: removal}
}

// 16.6's fourth bullet, 16.2.4's lines with their twins. Line 1: each of the seven flags outside the rules beside
// three flags that are not, an owned, a deposit and an erasure ref beside a shared one, the erasure ref, ur/index and
// ur/lfs by name beside others, each repo kind but general. Line 2: a pin below the one set and at it. Line 3: no table,
// and a table of another set, wait. Line 4: .ur-index/ on a file-mode ref, and the same name on a git-mode ref, where it
// is a path like any other. Line 5: a file change at, under, beside and above a prefix, a prefix that names a file, the
// empty prefix, two rules for one signer, a removal of a directory under and above. A push of no change is allowed.
func TestPrefixVerdictLineByLine(t *testing.T) {
	world := newAclTestVerdictWorld(t, 1)
	set := aclTestOpenedSet(10, aclTestRowId(world.admin),
		aclTestPrefixRule(world.ci, "agents/build"),
		aclTestPrefixRule(aclTestRowId(world.member), "docs/guide.md"),
		aclTestPrefixRule(aclTestRowId(world.member), "src/app"),
		aclTestPrefixRule(aclTestRowId(world.admin), ""),
	)
	outsideFile := world.file("src/main.go", false)
	verdict := func(args *AclPrefixVerdictArgs) AclPrefixVerdict { return PrefixVerdict(args) }
	want := func(name string, got AclPrefixVerdict, outcome AclPrefixOutcome, reason AclPrefixReason) {
		t.Helper()
		if got.Outcome != outcome || got.Reason != reason {
			t.Errorf("%s: %s (%s), want %s (%s)", name, got.Outcome, got.Reason, outcome, reason)
		}
	}
	base := func() *AclPrefixVerdictArgs { return world.args(world.agent, 12, outsideFile, set) }
	want("the agent outside its prefix", verdict(base()), AclPrefixIgnored, AclPrefixReasonNotUnder)

	// line 1
	for _, flag := range []protocol.EvsPushFlag{
		protocol.EvsPushFlag_EVS_PUSH_FORCE, protocol.EvsPushFlag_EVS_PUSH_DELETE, protocol.EvsPushFlag_EVS_PUSH_BASE, protocol.EvsPushFlag_EVS_PUSH_DROP,
		protocol.EvsPushFlag_EVS_PUSH_ERASE, protocol.EvsPushFlag_EVS_PUSH_CUT, protocol.EvsPushFlag_EVS_PUSH_CLOSURE,
	} {
		args := base()
		args.Flags = uint32(flag) | uint32(protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE)
		want(flag.String(), verdict(args), AclPrefixAllowed, AclPrefixReasonScope)
	}
	for _, flag := range []protocol.EvsPushFlag{protocol.EvsPushFlag_EVS_PUSH_IMMUTABLE, protocol.EvsPushFlag_EVS_PUSH_CONSUME, protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH} {
		args := base()
		args.Flags = uint32(flag)
		want(flag.String()+", inside the rules", verdict(args), AclPrefixIgnored, AclPrefixReasonNotUnder)
	}
	for _, refKind := range []protocol.EvsRefKind{protocol.EvsRefKind_EVS_REF_OWNED, protocol.EvsRefKind_EVS_REF_DEPOSIT, protocol.EvsRefKind_EVS_REF_ERASURE, protocol.EvsRefKind_EVS_REF_KIND_UNSPECIFIED} {
		args := base()
		args.RefKind = refKind
		want(refKind.String(), verdict(args), AclPrefixAllowed, AclPrefixReasonScope)
	}
	for _, name := range []string{"erasure", "ur/index", "ur/lfs"} {
		args := base()
		args.RefName = []byte(name)
		want("the ref "+name, verdict(args), AclPrefixAllowed, AclPrefixReasonScope)
	}
	for _, name := range []string{"ur/indexes", "ur", "release"} {
		args := base()
		args.RefName = []byte(name)
		want("the ref "+name, verdict(args), AclPrefixIgnored, AclPrefixReasonNotUnder)
	}
	for kind := range protocol.RepoKind_name {
		if protocol.RepoKind(kind) == protocol.RepoKind_REPO_KIND_GENERAL {
			continue
		}
		args := base()
		args.RepoKind = protocol.RepoKind(kind)
		want(protocol.RepoKind(kind).String(), verdict(args), AclPrefixAllowed, AclPrefixReasonScope)
	}

	// line 2
	args := base()
	args.PinVersion = 9
	want("a pin below the one set", verdict(args), AclPrefixAllowed, AclPrefixReasonNoSet)
	args.PinVersion = 10
	want("a pin at the set", verdict(args), AclPrefixIgnored, AclPrefixReasonNotUnder)

	// line 3
	args = base()
	args.TokenTable = nil
	want("no token table", verdict(args), AclPrefixWait, AclPrefixReasonTokens)
	other := aclTestOpenedSet(11, aclTestRowId(world.admin), set.Rules...)
	otherTable, err := NewAclPrefixTokenTable(other, world.pathKey)
	if err != nil {
		t.Fatal(err)
	}
	args.TokenTable = func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) { return otherTable, nil }
	want("another set's table", verdict(args), AclPrefixWait, AclPrefixReasonTokens)
	args.TokenTable = func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) { return nil, ErrEvsKeyMissing }
	want("a table that cannot be built", verdict(args), AclPrefixWait, AclPrefixReasonTokens)

	// line 4
	args = world.args(world.agent, 12, world.file(".ur-index/i1/shard", false), set)
	want(".ur-index/ on a file-mode ref", verdict(args), AclPrefixAllowed, AclPrefixReasonIndex)
	args.RefMode = protocol.EvsRefMode_EVS_REF_GIT
	want(".ur-index/ on a git-mode ref", verdict(args), AclPrefixIgnored, AclPrefixReasonNotUnder)

	// line 5, files
	for _, c := range []struct {
		name    string
		signer  *bridge.SidecarRow
		path    string
		removal bool
		outcome AclPrefixOutcome
	}{
		{name: "at the prefix", signer: world.agent, path: "agents/build", outcome: AclPrefixAllowed},
		{name: "under the prefix", signer: world.agent, path: "agents/build/out/x.bin", outcome: AclPrefixAllowed},
		{name: "beside the prefix", signer: world.agent, path: "agents/buildx", outcome: AclPrefixIgnored},
		{name: "beside the prefix, a sibling", signer: world.agent, path: "agents/deploy/run.sh", outcome: AclPrefixIgnored},
		{name: "above the prefix", signer: world.agent, path: "agents", outcome: AclPrefixIgnored},
		{name: "a prefix that names a file", signer: world.member, path: "docs/guide.md", outcome: AclPrefixAllowed},
		{name: "beside a prefix that names a file", signer: world.member, path: "docs/other.md", outcome: AclPrefixIgnored},
		{name: "the empty prefix", signer: world.admin, path: "anything/at/all", outcome: AclPrefixAllowed},
		{name: "two rules for one signer, the second", signer: world.member, path: "src/app/main.go", outcome: AclPrefixAllowed},
		{name: "two rules for one signer, neither", signer: world.member, path: "src/lib/main.go", outcome: AclPrefixIgnored},
		{name: "a removal of a directory under", signer: world.agent, path: "agents/build/cache", removal: true, outcome: AclPrefixAllowed},
		{name: "a removal of a directory above", signer: world.agent, path: "agents", removal: true, outcome: AclPrefixIgnored},
		{name: "a removal at the root", signer: world.agent, path: "", removal: true, outcome: AclPrefixIgnored},
		{name: "a signer the set names nowhere", signer: &bridge.SidecarRow{SidecarId: testConfigId("verdict stranger").Bytes()}, path: "agents/build/x", outcome: AclPrefixIgnored},
	} {
		got := verdict(world.args(c.signer, 12, world.file(c.path, c.removal), set))
		if got.Outcome != c.outcome || got.SetAt != 10 {
			t.Errorf("%s: %s (%s) under the set at %d", c.name, got.Outcome, got.Reason, got.SetAt)
		}
	}
	// a directory created beside the way is ignored even with no row; on the way, with none, it is allowed
	created := func(path string) *AclPrefixChange {
		return &AclPrefixChange{TokenPath: world.tokens(path), Directory: true, Creates: true}
	}
	want("an empty directory beside the way", verdict(world.args(world.agent, 12, created("tools"), set)), AclPrefixIgnored, AclPrefixReasonNotUnder)
	want("an empty directory on the way", verdict(world.args(world.agent, 12, created("agents"), set)), AclPrefixAllowed, AclPrefixReasonOnTheWay)
	// a push of no change: the pin push
	want("no change", verdict(world.args(world.agent, 12, nil, set)), AclPrefixAllowed, AclPrefixReasonNoChange)
}

// 16.6's fourth bullet, the set in force by position: pins below, at and above each of three opened sets with a void
// one between them; pending and newer sets above an opened one; a row this reader holds no set for, or one whose
// signer is not the row's; rows out of position order.
func TestPrefixVerdictTakesTheSetInForceAtThePin(t *testing.T) {
	world := newAclTestVerdictWorld(t, 1)
	adminId := aclTestRowId(world.admin)
	first := aclTestOpenedSet(10, adminId, aclTestPrefixRule(world.ci, "a"))
	void := &AclPrefixRuleSet{At: 20, Signer: adminId, State: AclPrefixSetVoid, VoidCause: AclPrefixVoidSeal}
	second := aclTestOpenedSet(30, adminId, aclTestPrefixRule(world.ci, "b"))
	third := aclTestOpenedSet(40, adminId, aclTestPrefixRule(world.ci, "c"))
	sets := []*AclPrefixRuleSet{first, void, second, third}
	// the agent's file under a, b or c: the set in force is the one whose prefix allows it
	judge := func(pin uint64, path string, sets ...*AclPrefixRuleSet) AclPrefixVerdict {
		return PrefixVerdict(world.args(world.agent, pin, world.file(path+"/x", false), sets...))
	}
	for _, c := range []struct {
		pin     uint64
		inForce uint64
		allowed string
	}{
		{pin: 9}, {pin: 10, inForce: 10, allowed: "a"}, {pin: 11, inForce: 10, allowed: "a"},
		{pin: 20, inForce: 10, allowed: "a"}, {pin: 29, inForce: 10, allowed: "a"},
		{pin: 30, inForce: 30, allowed: "b"}, {pin: 39, inForce: 30, allowed: "b"},
		{pin: 40, inForce: 40, allowed: "c"}, {pin: 1000, inForce: 40, allowed: "c"},
	} {
		for _, path := range []string{"a", "b", "c"} {
			got := judge(c.pin, path, sets...)
			switch {
			case c.inForce == 0:
				if got.Outcome != AclPrefixAllowed || got.Reason != AclPrefixReasonNoSet {
					t.Errorf("pin %d, %s: %s (%s), want no set", c.pin, path, got.Outcome, got.Reason)
				}
			case got.SetAt != c.inForce || (got.Outcome == AclPrefixAllowed) != (path == c.allowed):
				t.Errorf("pin %d, %s: %s under %d, want the set at %d allowing %s", c.pin, path, got.Outcome, got.SetAt, c.inForce, c.allowed)
			}
		}
	}
	// void alone: no set in force
	if got := judge(25, "a", void); got.Reason != AclPrefixReasonNoSet {
		t.Errorf("a void set alone: %s (%s)", got.Outcome, got.Reason)
	}
	pending := &AclPrefixRuleSet{At: 20, Signer: adminId, State: AclPrefixSetPending, Generation: 7}
	newer := &AclPrefixRuleSet{At: 20, Signer: adminId, State: AclPrefixSetNewer, Generation: 1}
	for _, c := range []struct {
		name    string
		set     *AclPrefixRuleSet
		outcome AclPrefixOutcome
	}{
		{name: "pending", set: pending, outcome: AclPrefixWait},
		{name: "newer", set: newer, outcome: AclPrefixUpdate},
	} {
		if got := judge(25, "a", first, c.set); got.Outcome != c.outcome || got.SetAt != 20 {
			t.Errorf("%s above an opened set: %s at %d", c.name, got.Outcome, got.SetAt)
		}
		if got := judge(15, "a", first, c.set); got.Outcome != AclPrefixAllowed || got.SetAt != 10 {
			t.Errorf("%s above the pin: %s at %d", c.name, got.Outcome, got.SetAt)
		}
		// never allowed, whatever the change: an outside one waits too
		if got := judge(25, "z", first, c.set); got.Outcome != c.outcome {
			t.Errorf("%s, a path no set allows: %s", c.name, got.Outcome)
		}
	}
	// a row with no set here waits, and so does one whose set has another signer
	args := world.args(world.agent, 25, world.file("a/x", false), first, second)
	args.Rows = append(args.Rows[:1], &protocol.AclRepoPrefixRulesRow{Signer: adminId.Bytes(), At: 20})
	if got := PrefixVerdict(args); got.Outcome != AclPrefixWait || got.Reason != AclPrefixReasonPending || got.SetAt != 20 {
		t.Errorf("a row with no set: %s (%s) at %d", got.Outcome, got.Reason, got.SetAt)
	}
	args = world.args(world.agent, 15, world.file("a/x", false), first)
	args.Rows[0].Signer = testConfigId("not the filer").Bytes()
	if got := PrefixVerdict(args); got.Outcome != AclPrefixWait {
		t.Errorf("a set of another signer than its row's: %s", got.Outcome)
	}
	args = world.args(world.agent, 50, world.file("a/x", false), first, second)
	args.Rows[0], args.Rows[1] = args.Rows[1], args.Rows[0]
	if got := PrefixVerdict(args); got.Outcome != AclPrefixWait || got.Reason != AclPrefixReasonRows {
		t.Errorf("rows out of order: %s (%s)", got.Outcome, got.Reason)
	}
}

// A ref's tree as a reader holds it: plaintext paths, each a file or a directory, the root implied.
type aclTestTree map[string]protocol.EvsEntryKind

// One child row a planned delta adds.
type aclTestTreeRow struct {
	name string
	kind protocol.EvsEntryKind
}

// A change as a design planner sends it, in plaintext.
type aclTestPlannedChange struct {
	path      string
	removal   bool
	directory bool
	creates   bool
	added     []aclTestTreeRow
	removed   []string
}

// A path's parent and its last name; a top-level path's parent is the root, "".
func aclTestParent(path string) (string, string) {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path
	}
	return path[:i], path[i+1:]
}

// The changes evs_directory.go's planner sends to write the file at path: the file's version, and for each directory
// on the way that does not stand, its creation with the row of the child below it, up to the first that stands, which
// takes a delta with that row; the root stands once anything does. Nil where a file stands on the way or a directory
// at the path, which the planner refuses before any push (ErrEvsPathKind).
func (self aclTestTree) planWrite(path string) []aclTestPlannedChange {
	kind, stands := self[path]
	if stands && kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
		return nil
	}
	changes := []aclTestPlannedChange{{path: path, creates: !stands}}
	if stands {
		return changes
	}
	child, childKind := path, protocol.EvsEntryKind_EVS_ENTRY_FILE
	for {
		parent, name := aclTestParent(child)
		row := []aclTestTreeRow{{name: name, kind: childKind}}
		if parent == "" {
			return append(changes, aclTestPlannedChange{path: "", directory: true, creates: len(self) == 0, added: row})
		}
		parentKind, parentStands := self[parent]
		if parentStands && parentKind == protocol.EvsEntryKind_EVS_ENTRY_FILE {
			return nil
		}
		if parentStands {
			return append(changes, aclTestPlannedChange{path: parent, directory: true, added: row})
		}
		changes = append(changes, aclTestPlannedChange{path: parent, directory: true, creates: true, added: row})
		child, childKind = parent, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
	}
}

// The removal of path, a file or a directory, and its parent's delta removing its row.
func (self aclTestTree) planRemove(path string) []aclTestPlannedChange {
	parent, name := aclTestParent(path)
	return []aclTestPlannedChange{{path: path, removal: true}, {path: parent, directory: true, removed: []string{name}}}
}

// The tree after a write or a removal.
func (self aclTestTree) apply(changes []aclTestPlannedChange) {
	for _, change := range changes {
		switch {
		case change.removal:
			for path := range self {
				if path == change.path || strings.HasPrefix(path, change.path+"/") {
					delete(self, path)
				}
			}
		case change.directory:
			if change.path != "" {
				self[change.path] = protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
			}
		default:
			self[change.path] = protocol.EvsEntryKind_EVS_ENTRY_FILE
		}
	}
}

// The change as PrefixVerdict reads it, in the world's epoch, its table the tree's rows under its path.
func (self *aclTestVerdictWorld) change(tree aclTestTree, planned aclTestPlannedChange) *AclPrefixChange {
	child := func(name string) []byte {
		path := name
		if planned.path != "" {
			path = planned.path + "/" + name
		}
		tokenPath := self.tokens(path)
		return tokenPath[len(tokenPath)-1].Bytes()
	}
	change := &AclPrefixChange{TokenPath: self.tokens(planned.path), Removal: planned.removal, Directory: planned.directory, Creates: planned.creates}
	if !planned.directory || planned.removal {
		return change
	}
	change.Names = &protocol.EvsNameTable{}
	for _, row := range planned.added {
		change.Names.Names = append(change.Names.Names, &protocol.EvsName{Token: child(row.name), Kind: uint32(row.kind)})
	}
	for _, name := range planned.removed {
		change.Names.RemovedTokens = append(change.Names.RemovedTokens, child(name))
	}
	held := map[EvsToken]protocol.EvsEntryKind{}
	for path, kind := range tree {
		if parent, name := aclTestParent(path); parent == planned.path {
			held[EvsToken(child(name))] = kind
		}
	}
	change.Table = func(token EvsToken) (protocol.EvsEntryKind, bool) {
		kind, ok := held[token]
		return kind, ok
	}
	return change
}

// 16.6's fifth bullet: the delta rule against a generated corpus. Random trees and random sets that hold the agent to
// one or two prefixes; every change of a design planner's writes and removals the set allows the agent is allowed, its
// deltas above the prefixes and its creations on the way included (16.3's P2); and each single mutation of a delta above
// every prefix is ignored: a file row on the way, a row beside the way, a removal on the way, a row over a file's row.
func TestPrefixVerdictDeltaRuleOverAGeneratedCorpus(t *testing.T) {
	world := newAclTestVerdictWorld(t, 1)
	alphabet := []string{"a", "b", "c", "d"}
	planned, mutated := 0, map[string]int{}
	for seed := uint64(1); seed <= 80; seed += 1 {
		random := rand.New(rand.NewPCG(seed, seed^0x51ed270b))
		randomPath := func(minDepth int, maxDepth int) string {
			names := []string{}
			for range minDepth + random.IntN(maxDepth-minDepth+1) {
				names = append(names, alphabet[random.IntN(len(alphabet))])
			}
			return strings.Join(names, "/")
		}
		tree := aclTestTree{}
		for range 2 + random.IntN(8) {
			if changes := tree.planWrite(randomPath(1, 4)); changes != nil {
				tree.apply(changes)
			}
		}
		// prefixes of one to three components, deep ones most often, so deltas meet directories on the way
		prefixes := []string{randomPath(1+random.IntN(2), 3)}
		if random.IntN(2) == 0 {
			prefixes = append(prefixes, randomPath(1, 3))
		}
		rules := []*protocol.PrefixRule{aclTestPrefixRule(aclTestRowId(world.admin), "")}
		for _, prefix := range prefixes {
			rules = append(rules, aclTestPrefixRule(world.ci, prefix))
		}
		set := aclTestOpenedSet(5, aclTestRowId(world.admin), rules...)
		table, err := NewAclPrefixTokenTable(set, world.pathKey)
		if err != nil {
			t.Fatal(err)
		}
		agentPrefixes := table.Prefixes(set, world.agent)
		judge := func(change *AclPrefixChange) AclPrefixVerdict {
			return PrefixVerdict(world.args(world.agent, 9, change, set))
		}
		for range 30 {
			prefix := prefixes[random.IntN(len(prefixes))]
			path := prefix
			if suffix := randomPath(0, 2); suffix != "" {
				path += "/" + suffix
			}
			var changes []aclTestPlannedChange
			if _, stands := tree[path]; stands && random.IntN(3) == 0 {
				changes = tree.planRemove(path)
			} else {
				changes = tree.planWrite(path)
			}
			if changes == nil {
				continue
			}
			planned += 1
			for _, change := range changes {
				if got := judge(world.change(tree, change)); got.Outcome != AclPrefixAllowed {
					t.Fatalf("seed %d: the planner's change at %q (%+v) for a write of %q under %v: %s (%s)", seed, change.path, change, path, prefixes, got.Outcome, got.Reason)
				}
			}
			// the mutations of each delta above every prefix
			for _, change := range changes {
				if !change.directory || change.removal || AclPrefixUnder(agentPrefixes, world.tokens(change.path)) {
					continue
				}
				mutate := func(name string, edit func(mutant *aclTestPlannedChange) bool, overFile bool) {
					t.Helper()
					mutant := change
					mutant.added = slices.Clone(change.added)
					mutant.removed = slices.Clone(change.removed)
					if !edit(&mutant) {
						return
					}
					prefixChange := world.change(tree, mutant)
					if overFile {
						token := EvsToken(prefixChange.Names.Names[0].Token)
						prefixChange.Table = func(asked EvsToken) (protocol.EvsEntryKind, bool) {
							return protocol.EvsEntryKind_EVS_ENTRY_FILE, asked == token
						}
					}
					if got := judge(prefixChange); got.Outcome != AclPrefixIgnored || got.Reason != AclPrefixReasonDeltaRow {
						t.Errorf("seed %d: %s at %q: %s (%s)", seed, name, change.path, got.Outcome, got.Reason)
					}
					mutated[name] += 1
				}
				mutate("a file row on the way", func(mutant *aclTestPlannedChange) bool {
					for i, row := range mutant.added {
						rowPath := strings.TrimPrefix(change.path+"/"+row.name, "/")
						if row.kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY && !slices.Contains(prefixes, rowPath) {
							mutant.added[i].kind = protocol.EvsEntryKind_EVS_ENTRY_FILE
							return true
						}
					}
					return false
				}, false)
				mutate("a row beside the way", func(mutant *aclTestPlannedChange) bool {
					mutant.added = append(mutant.added, aclTestTreeRow{name: "beside", kind: protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY})
					return true
				}, false)
				mutate("a removal on the way", func(mutant *aclTestPlannedChange) bool {
					for _, row := range mutant.added {
						rowPath := strings.TrimPrefix(change.path+"/"+row.name, "/")
						if !slices.Contains(prefixes, rowPath) {
							mutant.added = nil
							mutant.removed = append(mutant.removed, row.name)
							return true
						}
					}
					return false
				}, false)
				mutate("a row over a file's row", func(mutant *aclTestPlannedChange) bool {
					return !mutant.creates && len(mutant.added) != 0
				}, true)
			}
			tree.apply(changes)
		}
	}
	t.Logf("%d plans, mutations %v", planned, mutated)
	if planned < 400 {
		t.Errorf("only %d plans", planned)
	}
	for _, name := range []string{"a file row on the way", "a row beside the way", "a removal on the way", "a row over a file's row"} {
		if mutated[name] < 20 {
			t.Errorf("%q mutated only %d deltas", name, mutated[name])
		}
	}
}

// 16.6's sixth bullet: under computed in plaintext equals under computed on token paths, for random paths and
// prefixes in two epochs; and a change in epoch 2 is judged with epoch 2's table, which epoch 1's would not allow.
func TestAclPrefixUnderInTokensIsUnderInPlaintext(t *testing.T) {
	repoId := testConfigId("tokens repo")
	pathKeys := []*EvsPathKey{}
	for _, epoch := range []uint64{1, 2} {
		pathKey, err := NewEvsPathKey(aclTestPrefixRepoKey(repoId, epoch, testConfigStartMs))
		if err != nil {
			t.Fatal(err)
		}
		pathKeys = append(pathKeys, pathKey)
	}
	random := rand.New(rand.NewPCG(7, 11))
	alphabet := []string{"a", "b", "ab", "b.txt"}
	randomNames := func(maxDepth int) []string {
		names := []string{}
		for range random.IntN(maxDepth + 1) {
			names = append(names, alphabet[random.IntN(len(alphabet))])
		}
		return names
	}
	underCount := 0
	for range 2000 {
		path, prefix := randomNames(5), randomNames(3)
		rule := aclTestPrefixRule(testConfigId("tokens device"), strings.Join(prefix, "/"))
		plaintext := aclPrefixRulesCoverNames([]*protocol.PrefixRule{rule}, path)
		if plaintext {
			underCount += 1
		}
		for _, pathKey := range pathKeys {
			tokenPath, err := EvsPathTokens(pathKey, aclTestNames(strings.Join(path, "/")))
			if err != nil {
				t.Fatal(err)
			}
			prefixTokens, err := EvsPathTokens(pathKey, rule.GetPath())
			if err != nil {
				t.Fatal(err)
			}
			if AclPrefixUnder([]EvsTokenPath{prefixTokens}, tokenPath) != plaintext {
				t.Fatalf("epoch %d: %v under %v is %t in plaintext", pathKey.Epoch(), path, prefix, plaintext)
			}
		}
	}
	if underCount < 200 || 1800 < underCount {
		t.Errorf("%d of 2000 under: the corpus does not exercise both answers", underCount)
	}

	world := newAclTestVerdictWorld(t, 2)
	set := aclTestOpenedSet(3, aclTestRowId(world.admin), aclTestPrefixRule(world.ci, "agents/build"))
	change := world.file("agents/build/x", false)
	args := world.args(world.agent, 5, change, set)
	if got := PrefixVerdict(args); got.Outcome != AclPrefixAllowed {
		t.Fatalf("epoch 2's change with epoch 2's table: %s", got.Outcome)
	}
	args.TokenTable = AclPrefixTokenTableOf(pathKeys[0])
	if got := PrefixVerdict(args); got.Outcome != AclPrefixIgnored {
		t.Errorf("epoch 2's change with epoch 1's table: %s", got.Outcome)
	}
}

// A sequence of paths that counts how many were drawn.
func aclTestCountedPaths(paths ...string) (iter.Seq[string], *int) {
	drawn := 0
	return func(yield func(string) bool) {
		for _, path := range paths {
			drawn += 1
			if !yield(path) {
				return
			}
		}
	}, &drawn
}

// An engine of one sidecar with a state holding general repos whose rows list sets, at pin 100.
type aclTestPrefixEngineWorld struct {
	engine   *AclEngine
	deviceId Id
	adminId  Id
	ci       Id
}

func newAclTestPrefixEngineWorld(t *testing.T, tagged bool, repos map[string][]uint64) (*aclTestPrefixEngineWorld, map[string]Id) {
	fixture := newAclTestFixture()
	fixture.view.pin = &bridge.AuthPin{Version: 100, Chain: make([]byte, 32)}
	memberId := fixture.member(bridge.MemberRole_MEMBER_ROLE_MEMBER)
	world := &aclTestPrefixEngineWorld{ci: fixture.tag(memberId)}
	world.deviceId = fixture.device(memberId)
	if tagged {
		row := fixture.admission(world.deviceId)
		row.MemberId, row.TagIds = Id{}, []Id{world.ci}
		row.Row.TagIds = [][]byte{world.ci.Bytes()}
	} else {
		fixture.admission(world.deviceId).Row.MemberId = memberId.Bytes()
	}
	world.adminId = fixture.device(fixture.member(bridge.MemberRole_MEMBER_ROLE_ADMIN))
	repoIds := map[string]Id{}
	for name, positions := range repos {
		kind := protocol.RepoKind_REPO_KIND_GENERAL
		if name == "vault" {
			kind = protocol.RepoKind_REPO_KIND_VAULT
		}
		repoId, row := fixture.repo(kind, Id{})
		if kind == protocol.RepoKind_REPO_KIND_VAULT {
			row.OwnerMemberId = memberId.Bytes()
		}
		for _, at := range positions {
			row.PrefixRules = append(row.PrefixRules, &protocol.AclRepoPrefixRulesRow{Signer: world.adminId.Bytes(), At: at})
		}
		repoIds[name] = repoId
	}
	world.engine = NewAclEngine(world.deviceId, nil, nil, nil)
	if err := world.engine.Install(fixture.state(t), nil); err != nil {
		t.Fatal(err)
	}
	return world, repoIds
}

// 16.6's QD-801 bullet: AllowPrefixWrite draws no path for a sidecar that a rule names with no path, stops at the first
// refused path of a sequence, and answers the path of no component: allowed exactly where such a rule names the
// sidecar, where no set is in force and where the ref is outside the rules, refused with no path where it is held.
// And 16.2.7's other lines: a pending set refused with detail pending and a newer one with update before a path is
// drawn, .ur-index/ outside the rules on a file-mode ref only, a path beside a prefix refused, a write past an
// installed state or for a repo it does not hold refused, and the refusal's error naming no path.
func TestAllowPrefixWriteDrawsItsPathsAsQD801Says(t *testing.T) {
	world, repoIds := newAclTestPrefixEngineWorld(t, true, map[string][]uint64{
		"held": {10}, "everywhere": {10}, "none": {}, "later": {200}, "pending": {10, 20}, "newer": {10, 20}, "vault": {},
	})
	held := aclTestOpenedSet(10, world.adminId, aclTestPrefixRule(world.ci, "agents/build"), aclTestPrefixRule(world.adminId, ""))
	everywhere := aclTestOpenedSet(10, world.adminId, aclTestPrefixRule(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED), ""))
	setsOf := map[string][]*AclPrefixRuleSet{
		"held": {held}, "everywhere": {everywhere}, "later": {aclTestOpenedSet(200, world.adminId)},
		"pending": {held, {At: 20, Signer: world.adminId, State: AclPrefixSetPending, Generation: 4}},
		"newer":   {held, {At: 20, Signer: world.adminId, State: AclPrefixSetNewer, Generation: 1}},
	}
	ask := func(repo string, refKind protocol.EvsRefKind, refMode protocol.EvsRefMode, paths ...string) (AclPrefixWriteDecision, int) {
		sequence, drawn := aclTestCountedPaths(paths...)
		decision := world.engine.AllowPrefixWrite(&AclPrefixWrite{
			RepoId: repoIds[repo], RefKind: refKind, RefMode: refMode, RefName: []byte("main"), Paths: sequence, Sets: setsOf[repo],
		})
		return decision, *drawn
	}
	shared, file, git := protocol.EvsRefKind_EVS_REF_SHARED, protocol.EvsRefMode_EVS_REF_FILE, protocol.EvsRefMode_EVS_REF_GIT
	many := []string{"agents/build/a", "src/main.go", "agents/build/b", "docs/x"}

	// a rule with no path names the sidecar: allowed before any path is drawn
	if decision, drawn := ask("everywhere", shared, file, many...); !decision.Allowed || drawn != 0 || decision.Reason != AclReasonPrefixRule || decision.At != 10 {
		t.Errorf("named for every path: %+v, %d drawn", decision, drawn)
	}
	// the first refused path stops the drawing, and is named
	decision, drawn := ask("held", shared, file, many...)
	if decision.Allowed || drawn != 2 || decision.Path != "src/main.go" || decision.Detail != AclPrefixDetailRefused || decision.Reason != AclReasonPrefixRule {
		t.Errorf("a sequence with a refused second path: %+v, %d drawn", decision, drawn)
	}
	var ruleError *AclPrefixRuleError
	if err := decision.Err(); !errors.As(err, &ruleError) || !errors.Is(err, ErrAclPrefixRule) || ruleError.Path != "src/main.go" || strings.Contains(err.Error(), "src") {
		t.Errorf("the refusal's error: %v", err)
	}
	if decision, drawn := ask("held", shared, file, "agents/build/a", "agents/build", "agents/build/c/d"); !decision.Allowed || drawn != 3 || decision.Err() != nil {
		t.Errorf("every path under the prefix: %+v, %d drawn", decision, drawn)
	}
	for _, path := range []string{"agents", "agents/buildx", "agents/deploy/x"} {
		if decision, _ := ask("held", shared, file, path); decision.Allowed || decision.Path != path {
			t.Errorf("%s beside or above the prefix: %+v", path, decision)
		}
	}
	// the path of no component
	for _, c := range []struct {
		name    string
		repo    string
		refKind protocol.EvsRefKind
		allowed bool
	}{
		{name: "named for every path", repo: "everywhere", refKind: shared, allowed: true},
		{name: "held", repo: "held", refKind: shared},
		{name: "no set in force", repo: "none", refKind: shared, allowed: true},
		{name: "a set above the installed pin only", repo: "later", refKind: shared, allowed: true},
		{name: "an owned ref", repo: "held", refKind: protocol.EvsRefKind_EVS_REF_OWNED, allowed: true},
		{name: "a repo that is not general", repo: "vault", refKind: shared, allowed: true},
	} {
		decision, drawn := ask(c.repo, c.refKind, git, "")
		if decision.Allowed != c.allowed || (!c.allowed && (decision.Path != "" || decision.Detail != AclPrefixDetailRefused || drawn != 1)) {
			t.Errorf("the path of no component, %s: %+v, %d drawn", c.name, decision, drawn)
		}
	}
	// a ref outside the rules by name or by flag
	if decision := world.engine.AllowPrefixWrite(&AclPrefixWrite{RepoId: repoIds["held"], RefKind: shared, RefMode: git, RefName: []byte("ur/lfs"), Paths: slices.Values([]string{"x"}), Sets: setsOf["held"]}); !decision.Allowed {
		t.Errorf("ur/lfs: %+v", decision)
	}
	if decision := world.engine.AllowPrefixWrite(&AclPrefixWrite{RepoId: repoIds["held"], RefKind: shared, RefMode: git, RefName: []byte("main"), Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE), Paths: slices.Values([]string{"x"}), Sets: setsOf["held"]}); !decision.Allowed {
		t.Errorf("a FORCE update: %+v", decision)
	}
	// a pending or newer set is refused before a path is drawn
	for _, c := range []struct {
		repo   string
		detail AclPrefixDetail
	}{{repo: "pending", detail: AclPrefixDetailPending}, {repo: "newer", detail: AclPrefixDetailUpdate}} {
		if decision, drawn := ask(c.repo, shared, file, "agents/build/x"); decision.Allowed || decision.Detail != c.detail || drawn != 0 || decision.At != 20 {
			t.Errorf("%s: %+v, %d drawn", c.repo, decision, drawn)
		}
	}
	// a row this device holds no set for is pending
	if decision := world.engine.AllowPrefixWrite(&AclPrefixWrite{RepoId: repoIds["held"], RefKind: shared, RefMode: file, Paths: slices.Values([]string{"agents/build/x"})}); decision.Allowed || decision.Detail != AclPrefixDetailPending {
		t.Errorf("no sets: %+v", decision)
	}
	// .ur-index/ on a file-mode ref only
	if decision, _ := ask("held", shared, file, ".ur-index/i1"); !decision.Allowed {
		t.Errorf(".ur-index/ on a file-mode ref: %+v", decision)
	}
	if decision, _ := ask("held", shared, git, ".ur-index/i1"); decision.Allowed {
		t.Errorf(".ur-index/ on a git-mode ref: %+v", decision)
	}
	// no repo, and no state
	if decision := world.engine.AllowPrefixWrite(&AclPrefixWrite{RepoId: NewId(), RefKind: shared}); decision.Allowed || decision.Reason != AclReasonNoRepo {
		t.Errorf("a repo the state does not hold: %+v", decision)
	}
	if decision := NewAclEngine(world.deviceId, nil, nil, nil).AllowPrefixWrite(&AclPrefixWrite{RepoId: repoIds["held"], RefKind: shared}); decision.Allowed || decision.Reason != AclReasonNoState || decision.Detail != AclPrefixDetailPending {
		t.Errorf("no state installed: %+v", decision)
	}

	// an untagged member device the held set names nowhere writes nothing, and the path of no component says so
	member, memberRepos := newAclTestPrefixEngineWorld(t, false, map[string][]uint64{"held": {10}})
	memberSet := aclTestOpenedSet(10, member.adminId, aclTestPrefixRule(member.ci, "agents/build"))
	for _, path := range []string{"", "agents/build/x"} {
		if decision := member.engine.AllowPrefixWrite(&AclPrefixWrite{RepoId: memberRepos["held"], RefKind: shared, RefMode: file, Paths: slices.Values([]string{path}), Sets: []*AclPrefixRuleSet{memberSet}}); decision.Allowed {
			t.Errorf("a device no rule names, %q: %+v", path, decision)
		}
	}
}

// Posts a RepoPrefixRules of set sealed under key by signer at the net's tip; the verdict and the statement.
func (self *testConfigNet) postPrefixSet(signer testConfigDevice, repoId Id, key *EvsRepoKey, set *protocol.PrefixRuleSet) ConfigVerdict {
	self.t.Helper()
	statement := &protocol.RepoPrefixRules{Header: self.header(), RepoId: repoId.Bytes()}
	sealed, err := SealConfigBody(key, NewConfigSealContext(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, statement.Header), set, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	statement.SealedRules = sealed
	return self.post(signer, bridge.SignedType_SIGNED_REPO_PREFIX_RULES, statement)
}

// A head reader that counts its reads.
type aclTestCountingHeads struct {
	heads     ConfigHeadReader
	stateLock sync.Mutex
	readCount int
}

func (self *aclTestCountingHeads) ReadConfigHead(ctx context.Context, configVersion uint64, configHeadSha256 []byte) (*ConfigHead, error) {
	self.stateLock.Lock()
	self.readCount += 1
	self.stateLock.Unlock()
	return self.heads.ReadConfigHead(ctx, configVersion, configHeadSha256)
}

func (self *aclTestCountingHeads) reads() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.readCount
}

// The states of sets, in order.
func aclTestSetStates(sets []*AclPrefixRuleSet) []string {
	states := []string{}
	for _, set := range sets {
		states = append(states, fmt.Sprintf("%d:%s:%s", set.At, set.State, set.VoidCause))
	}
	return states
}

// 16.2.3 through AclPrefixSets on TEAM's log: a repo's sets by position, one per row: one opened, one pending on a
// generation the device does not hold, one void under a wrong key, each body from the log's entry; the final ones kept
// in the sealed store and opened by no later call or restart, which asks no key and reads no head; the pending one
// opened when its generation arrives. Past the retention point a new device reads every body from the head's fold
// records alike. An entry at a set's position that is not that set is ErrAclPrefixRecord, and no set is judged.
func TestAclPrefixSetsOpensEachSetOnceAndKeepsItSealed(t *testing.T) {
	ctx := context.Background()
	net := newTestConfigNet(t)
	repoId := net.createGeneralRepo("sets repo")
	keyOne, keyTwo := aclTestPrefixRepoKey(repoId, 1, net.timeMs), aclTestPrefixRepoKey(repoId, 2, net.timeMs)
	device := testConfigId("sets device")
	ruleSet := &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{aclTestPrefixRule(device, "docs")}}
	opened := net.postPrefixSet(net.owner, repoId, keyOne, ruleSet).Pin.GetVersion()
	pending := net.postPrefixSet(net.owner, repoId, keyTwo, ruleSet).Pin.GetVersion()
	void := net.postPrefixSet(net.owner, repoId, &EvsRepoKey{repoId: repoId, generation: 1, repoKey: bytes.Repeat([]byte{0x77}, gkmRepoKeyByteCount)}, ruleSet).Pin.GetVersion()

	store := newTestBridgeFileStore()
	keys := newAclTestPrefixKeys(keyOne)
	args := &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, EntryAt: AclPrefixLogEntries(net.log), Keys: keys}
	sets := NewAclPrefixSets(store, nil)
	got, err := sets.Sets(ctx, args)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{fmt.Sprintf("%d:opened:none", opened), fmt.Sprintf("%d:pending:none", pending), fmt.Sprintf("%d:void:seal", void)}
	if !slices.Equal(aclTestSetStates(got), want) || got[0].Signer != net.owner.sidecarId || !proto.Equal(&protocol.PrefixRuleSet{Rules: got[0].Rules}, ruleSet) {
		t.Fatalf("the sets: %v, want %v", aclTestSetStates(got), want)
	}
	if names := store.names(aclPrefixStoreDirectory); !slices.Equal(names, []string{aclPrefixStoreName(repoId)}) {
		t.Fatalf("the store holds %v", names)
	}

	// generation 2 arrives: the pending set opens, and the store keeps all three
	keys.add(keyTwo)
	if got, err = sets.Sets(ctx, args); err != nil || got[1].State != AclPrefixSetOpened {
		t.Fatalf("after generation 2: %v, %v", aclTestSetStates(got), err)
	}
	// a restart over the same store opens nothing again: no key asked, no entry or head read
	asked := keys.asked()
	restarted := NewAclPrefixSets(store, nil)
	noSource := &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, Keys: keys}
	again, err := restarted.Sets(ctx, noSource)
	if err != nil || !slices.Equal(aclTestSetStates(again), aclTestSetStates(got)) || keys.asked() != asked {
		t.Fatalf("after a restart: %v, %v, %d keys asked", aclTestSetStates(again), err, keys.asked()-asked)
	}
	// and a set the store does not hold, with no source, stays pending
	empty, err := NewAclPrefixSets(newTestBridgeFileStore(), nil).Sets(ctx, noSource)
	if err != nil || len(empty) != 3 || empty[0].State != AclPrefixSetPending {
		t.Fatalf("no store and no source: %v, %v", aclTestSetStates(empty), err)
	}

	// two bases fold past the sets: a new device starting at the newest reads each body from the head's fold records
	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("sets filler"))
	net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
	if point := net.log.State().RetentionPoint(); point <= void {
		t.Fatalf("the retention point %d has not passed the sets", point)
	}
	restored, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
	if err != nil {
		t.Fatal(err)
	}
	heads := &aclTestCountingHeads{heads: newTestConfigHeadReader(net)}
	fromHead, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: restored.State(), RepoId: repoId, EntryAt: AclPrefixLogEntries(restored), Heads: heads, Keys: keys})
	if err != nil || !slices.Equal(aclTestSetStates(fromHead), aclTestSetStates(got)) || heads.reads() != 1 {
		t.Fatalf("from the head: %v, %v, %d head reads", aclTestSetStates(fromHead), err, heads.reads())
	}

	// an entry at a set's position that is another statement is section 5's alarm
	forged := func(n uint64) (*bridge.AuthEntry, bool) {
		entry := &bridge.AuthEntry{N: n, Kind: bridge.AuthEntryKindStatement, Body: net.sign(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("forged"))}
		return entry, true
	}
	if _, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, EntryAt: forged, Keys: keys}); !errors.Is(err, ErrAclPrefixRecord) {
		t.Errorf("a forged entry: %v", err)
	}
	otherRepo := net.createGeneralRepo("sets other repo")
	otherAt := net.postPrefixSet(net.owner, otherRepo, keyOne, ruleSet).Pin.GetVersion()
	misplaced := func(n uint64) (*bridge.AuthEntry, bool) {
		return AclPrefixLogEntries(net.log)(otherAt)
	}
	if _, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, EntryAt: misplaced, Keys: keys}); !errors.Is(err, ErrAclPrefixRecord) {
		t.Errorf("another repo's set at the position: %v", err)
	}
}

// 16.2.3's pending rule: a set sealed to a generation that never forms stays pending until the log holds an entry
// timed past GenerationFormGrace plus PendingVoidMargin after it and a whole read of gkm made after that entry names
// no such generation; then it is void, unformed, and the set below it is in force again. Each twin keeps it pending:
// the wait not past, a read cut short, a read with a fork, a read that failed, a read naming the generation, a read
// made before the entry past the wait.
func TestAclPrefixSetsVoidsASetWhoseGenerationNeverForms(t *testing.T) {
	ctx := context.Background()
	net := newTestConfigNet(t)
	repoId := net.createGeneralRepo("unformed repo")
	keyOne := aclTestPrefixRepoKey(repoId, 1, net.timeMs)
	device := testConfigId("unformed device")
	below := net.postPrefixSet(net.owner, repoId, keyOne, &protocol.PrefixRuleSet{Rules: []*protocol.PrefixRule{aclTestPrefixRule(device, "docs")}}).Pin.GetVersion()
	unformed := net.postPrefixSet(net.owner, repoId, aclTestPrefixRepoKey(repoId, 5, net.timeMs), &protocol.PrefixRuleSet{}).Pin.GetVersion()
	keys := newAclTestPrefixKeys(keyOne)
	settings := DefaultAclPrefixSettings()
	wait := settings.GenerationFormGrace + settings.PendingVoidMargin
	statesWith := func(read *AclPrefixGenerationRead) []string {
		t.Helper()
		sets, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, EntryAt: AclPrefixLogEntries(net.log), Keys: keys, Generations: read})
		if err != nil {
			t.Fatal(err)
		}
		return aclTestSetStates(sets)
	}
	pendingStates := []string{fmt.Sprintf("%d:opened:none", below), fmt.Sprintf("%d:pending:none", unformed)}
	whole := func() *AclPrefixGenerationRead {
		return &AclPrefixGenerationRead{AppliedThrough: net.n, Whole: true, Newest: 1}
	}
	if got := statesWith(whole()); !slices.Equal(got, pendingStates) {
		t.Fatalf("before the wait: %v", got)
	}
	// an entry exactly at the wait is not past it
	net.timeMs += wait.Milliseconds() - 1000
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("unformed at the wait"))
	if got := statesWith(whole()); !slices.Equal(got, pendingStates) {
		t.Fatalf("at the wait: %v", got)
	}
	readBefore := whole()
	net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement("unformed past the wait"))
	for _, c := range []struct {
		name string
		read *AclPrefixGenerationRead
	}{
		{name: "no read"},
		{name: "a read cut short", read: &AclPrefixGenerationRead{AppliedThrough: net.n, Newest: 1}},
		{name: "a read with a fork", read: &AclPrefixGenerationRead{AppliedThrough: net.n, Whole: true, Forked: true, Newest: 1}},
		{name: "a read that failed", read: &AclPrefixGenerationRead{AppliedThrough: net.n, Whole: true, Newest: 1, Err: errors.New("the sync failed")}},
		{name: "a read naming generation 5", read: &AclPrefixGenerationRead{AppliedThrough: net.n, Whole: true, Newest: 5}},
		{name: "a read made before the entry past the wait", read: readBefore},
		{name: "a read made after an entry this state does not hold", read: &AclPrefixGenerationRead{AppliedThrough: net.n + 1, Whole: true, Newest: 1}},
	} {
		if got := statesWith(c.read); !slices.Equal(got, pendingStates) {
			t.Errorf("%s: %v", c.name, got)
		}
	}
	got := statesWith(whole())
	if want := []string{pendingStates[0], fmt.Sprintf("%d:void:unformed", unformed)}; !slices.Equal(got, want) {
		t.Fatalf("past the wait: %v, want %v", got, want)
	}
	// the set below is in force again for a push pinned at or above the void one
	world := newAclTestVerdictWorld(t, 1)
	sets, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: net.log.State(), RepoId: repoId, EntryAt: AclPrefixLogEntries(net.log), Keys: keys, Generations: whole()})
	if err != nil {
		t.Fatal(err)
	}
	args := world.args(&bridge.SidecarRow{SidecarId: device.Bytes()}, net.n, world.file("docs/x", false), sets...)
	args.Rows = net.log.State().Repo(repoId).GetPrefixRules()
	if verdict := PrefixVerdict(args); verdict.Outcome != AclPrefixAllowed || verdict.SetAt != below {
		t.Errorf("past the void set: %s under %d", verdict.Outcome, verdict.SetAt)
	}
}

// 16.6's seventh bullet, base independence on real code (16.3's P1): a generated log of sets sealed to the repo's
// generation, a void set between them, admissions, bases folding anywhere and filler; readers started at every base
// along the way, a reader replaying every entry, a new device and a rows-only gate at the newest base, each opening
// its sets from its own entries or the head's fold records, give PrefixVerdict the long-running log's answer for every
// push pinned anywhere since the repo's creation, by the owner's device, a member device and a tagged agent, at paths
// under, beside and above the rules' prefixes. The verdict takes no state at the pin: the rows-only gate retains
// nothing below its tip, as StateAt says, and judges the oldest pins alike. A hook that keeps only the newest row, as
// one value in AclRepo would (16.1's B), breaks the agreement, which the test asserts.
func TestPrefixVerdictIsBaseIndependentOnRealCode(t *testing.T) {
	ctx := context.Background()
	judgedCount, outcomeCounts, hookDisagreements := 0, map[AclPrefixOutcome]int{}, 0
	for seed := uint64(1); seed <= 3; seed += 1 {
		net, ci, _ := newTestConfigTagNet(t)
		random := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
		day := int64(24 * 60 * 60 * 1000)
		delegation := net.delegate(net.owner, fmt.Sprintf("p1 ci %d", seed), []Id{ci}, 5, net.timeMs+30*day)
		agent := net.device(fmt.Sprintf("p1 agent %d", seed), Id{})
		if verdict := net.postByDelegation(delegation, bridge.SignedType_SIGNED_SIDECAR_ADMIT, net.agentAdmission(delegation, agent, false, delegation.notAfter)); !verdict.Accepted() {
			t.Fatal(verdict.Refusal)
		}
		laptop := net.admitMemberDevice(fmt.Sprintf("p1 laptop %d", seed))
		repoId := net.createGeneralRepo(fmt.Sprintf("p1 repo %d", seed))
		created := net.n
		key := aclTestPrefixRepoKey(repoId, 1, net.timeMs)
		keys := newAclTestPrefixKeys(key)
		subjects := []Id{
			laptop.sidecarId, laptop.memberId, ci, agent.sidecarId, AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR),
			AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER), AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED),
		}
		prefixes := []string{"", "a", "a/b", "c"}
		// readers that start at each base along the way, fed every entry after it at the end
		starters := []*ConfigLog{}
		starterFrom := []int{}
		for i := range 70 {
			switch op := random.IntN(10); {
			case op <= 3:
				rules := []*protocol.PrefixRule{}
				for range 1 + random.IntN(3) {
					rules = append(rules, aclTestPrefixRule(subjects[random.IntN(len(subjects))], prefixes[random.IntN(len(prefixes))]))
				}
				if verdict := net.postPrefixSet(net.owner, repoId, key, &protocol.PrefixRuleSet{Rules: AclPrefixSortRules(rules)}); !verdict.Accepted() {
					t.Fatal(verdict.Refusal)
				}
			case op == 4:
				wrongKey := &EvsRepoKey{repoId: repoId, generation: 1, repoKey: bytes.Repeat([]byte{0x31}, gkmRepoKeyByteCount)}
				net.postPrefixSet(net.owner, repoId, wrongKey, &protocol.PrefixRuleSet{})
			case op <= 6:
				base := net.log.State().Base().GetVersion()
				net.fold(net.owner, base+uint64(random.IntN(int(net.n-base)+1)), net.log.State().Base().GetConfigVersion()+1)
				starter, err := RestoreConfigLog(testConfigLogSettings(), net.log.Retained(), net.source)
				if err != nil {
					t.Fatal(err)
				}
				starters, starterFrom = append(starters, starter), append(starterFrom, len(net.entries))
			case op == 7:
				net.admitMemberDevice(fmt.Sprintf("p1 other %d %d", seed, i))
			default:
				net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("p1 filler %d %d", seed, i)))
			}
		}
		// two bases past everything, so the newest base's readers retain nothing of the sets' entries
		for i := range 2 {
			net.fold(net.owner, net.n, net.log.State().Base().GetConfigVersion()+1)
			net.mustPost(net.owner, bridge.SignedType_SIGNED_MEMBER_ADMIT, net.memberAdmitStatement(fmt.Sprintf("p1 after %d %d", seed, i)))
		}
		for i, starter := range starters {
			for _, entryBytes := range net.entries[starterFrom[i]:] {
				if _, err := starter.Apply(entryBytes, net.source); err != nil {
					t.Fatal(err)
				}
			}
		}
		readers := append(net.everyReader(), starters...)
		gate := readers[2]
		if !gate.RowsOnly() {
			t.Fatal("the third reader is no rows-only gate")
		}
		if _, err := gate.StateAt(net.statesAt[created].Pin()); !errors.Is(err, ErrConfigPinNotRetained) {
			t.Fatalf("the gate's StateAt at the repo's creation: %v", err)
		}

		world := newAclTestVerdictWorld(t, 1)
		pathKey, err := NewEvsPathKey(key)
		if err != nil {
			t.Fatal(err)
		}
		world.pathKey = pathKey
		heads := newTestConfigHeadReader(net)
		signerIds := []Id{net.owner.sidecarId, laptop.sidecarId, agent.sidecarId}
		paths := []string{"a/x", "a/b/y", "a/bb", "c/z", "d", "a"}
		verdictsOf := func(name string, log *ConfigLog, hook func(rows []*protocol.AclRepoPrefixRulesRow) []*protocol.AclRepoPrefixRulesRow) []AclPrefixVerdict {
			t.Helper()
			state := log.State()
			sets, err := NewAclPrefixSets(nil, nil).Sets(ctx, &AclPrefixSetsArgs{State: state, RepoId: repoId, EntryAt: AclPrefixLogEntries(log), Heads: heads, Keys: keys})
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			rows := state.Repo(repoId).GetPrefixRules()
			if hook != nil {
				rows = hook(rows)
			}
			verdicts := []AclPrefixVerdict{}
			for pin := created; pin <= net.n; pin += 1 {
				for _, signerId := range signerIds {
					row := state.Sidecar(signerId).Row
					for _, path := range paths {
						args := world.args(row, pin, world.file(path, false), sets...)
						args.Rows = rows
						verdicts = append(verdicts, PrefixVerdict(args))
					}
				}
			}
			return verdicts
		}
		want := verdictsOf("the long-running reader", net.log, nil)
		setCount := len(net.log.State().Repo(repoId).GetPrefixRules())
		if setCount < 8 {
			t.Fatalf("seed %d filed only %d sets", seed, setCount)
		}
		for i, reader := range readers {
			got := verdictsOf(fmt.Sprintf("reader %d", i), reader, nil)
			if !slices.Equal(got, want) {
				t.Fatalf("seed %d: reader %d disagrees with the long-running reader", seed, i)
			}
		}
		for _, verdict := range want {
			judgedCount += 1
			outcomeCounts[verdict.Outcome] += 1
		}
		newestOnly := func(rows []*protocol.AclRepoPrefixRulesRow) []*protocol.AclRepoPrefixRulesRow {
			return rows[len(rows)-1:]
		}
		// the hook shows another file: an outcome that differs, not only the set it names
		hooked := verdictsOf("the newest-only reader", readers[1], newestOnly)
		for i := range want {
			if hooked[i].Outcome != want[i].Outcome {
				hookDisagreements += 1
			}
		}
	}
	t.Logf("judged %d pushes, %v; the newest-only hook disagreed on %d", judgedCount, outcomeCounts, hookDisagreements)
	if judgedCount < 3000 || outcomeCounts[AclPrefixAllowed] < 300 || outcomeCounts[AclPrefixIgnored] < 300 {
		t.Errorf("judged %d: %v", judgedCount, outcomeCounts)
	}
	if hookDisagreements == 0 {
		t.Error("a reader that keeps only the newest row agreed with the long-running one on every push")
	}
}

// A sidecar whose acts post onto the net's log, admitted as the owner's member device with its own identity key, and
// the net's api, which counts posts.
func newAclTestPrefixFilerSidecar(t *testing.T, net *testConfigNet, sidecarId Id) (*Sidecar, *testBridgeFileApi) {
	t.Helper()
	sidecar := newTestBridgeFileSidecar(t, net.networkId, sidecarId)
	admit := net.admission(testConfigDevice{sidecarId: sidecarId, memberId: net.ownerMemberId, key: testConfigDeviceKey("prefix filer host")}, nil, false, 0, 0)
	admit.IdentityPublicKey = bytes.Clone(sidecar.currentIdentity().IdentityPublicKey)
	net.mustPost(net.owner, bridge.SignedType_SIGNED_SIDECAR_ADMIT, admit)
	clock := newIdentityTestClock()
	clock.current = time.UnixMilli(net.timeMs)
	sidecar.clock = clock
	api := &testBridgeFileApi{net: net}
	sidecarApi, err := newSidecarApi(sidecar.settings, api, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	sidecarApi.SetByJwt("a-synthetic-client-token-for-the-prefix-filer")
	sidecarApi.setDpopSigner(func(method string, url string, ath string) (string, error) {
		return "a-synthetic-proof", nil
	})
	sidecar.sidecarApi = sidecarApi
	t.Cleanup(sidecar.InstallAuthority(&testBridgeFileAuthority{testActAuthority: newTestActAuthority(), net: net}))
	return sidecar, api
}

// The net's state as the filer reads it.
type aclTestPrefixFilerConfig struct {
	net *testConfigNet
}

func (self aclTestPrefixFilerConfig) State() *ConfigState {
	return self.net.log.State()
}

// The set the log's entry at n carries, opened with key.
func aclTestFiledSet(t *testing.T, net *testConfigNet, n uint64, key *EvsRepoKey) *AclPrefixRuleSet {
	t.Helper()
	entry, ok := AclPrefixLogEntries(net.log)(n)
	if !ok {
		t.Fatalf("no entry at %d", n)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(entry.GetBody(), signed); err != nil {
		t.Fatal(err)
	}
	statement := &protocol.RepoPrefixRules{}
	if err := proto.Unmarshal(signed.GetBody(), statement); err != nil {
		t.Fatal(err)
	}
	return OpenPrefixRuleSet(statement.GetSealedRules(), NewConfigSealContext(bridge.SignedType_SIGNED_REPO_PREFIX_RULES, statement.GetHeader()), testConfigSealKeyAt(key), nil, entry.GetTimeMs(), nil)
}

// 16.2.9 through AclPrefixRulesFiler and a real Sidecar's act on the test log (QD-792): an Allow builds the next set from
// the none in force with each standing admin written in for every path, sealed to the repo's own generation and folded
// at the position it answers; a Deny takes a subject's rules from the set in force; a Lift files the one rule naming
// autogroup:sidecar, which already names every admin; a Set --as-written files its rules alone and names the admins it
// leaves unable to write. Refused before anything is posted: a subject that names nobody (a group's atom, a role's,
// autogroup:admin, an unknown id), a repo that is not general, an MCP origin, a set no reader would open, and an Allow
// where the device holds the set in force pending.
func TestAclPrefixRulesFilerFilesTheNextSetWithTheAdmins(t *testing.T) {
	ctx := context.Background()
	net, ci, _ := newTestConfigTagNet(t)
	hostId := testConfigId("prefix filer host")
	sidecar, api := newAclTestPrefixFilerSidecar(t, net, hostId)
	laptop := net.admitMemberDevice("prefix filer laptop")
	repoId := net.createGeneralRepo("prefix filer repo")
	for _, adminId := range []Id{hostId, laptop.sidecarId} {
		net.mustPost(net.owner, bridge.SignedType_SIGNED_REPO_ADMIN, &protocol.RepoAdmin{
			Header: net.header(), RepoId: repoId.Bytes(), SidecarId: adminId.Bytes(), Change: protocol.RepoAdminChange_REPO_ADMIN_CHANGE_ADD,
		})
	}
	key := aclTestPrefixRepoKey(repoId, 1, net.timeMs)
	keys := newAclTestPrefixKeys(key)
	sets := NewAclPrefixSets(nil, nil)
	pendingSets := false
	filer := NewAclPrefixRulesFiler(&AclPrefixRulesFilerArgs{
		Sidecar: sidecar,
		Config:  aclTestPrefixFilerConfig{net: net},
		RepoKey: func(ctx context.Context, repoId Id) (*EvsRepoKey, error) { return key, nil },
		Sets: func(ctx context.Context, state *ConfigState, repoId Id) ([]*AclPrefixRuleSet, error) {
			if pendingSets {
				return nil, nil
			}
			return sets.Sets(ctx, &AclPrefixSetsArgs{State: state, RepoId: repoId, EntryAt: AclPrefixLogEntries(net.log), Keys: keys})
		},
	})
	admins := []Id{net.owner.sidecarId, hostId, laptop.sidecarId}
	adminRules := func() []*protocol.PrefixRule {
		rules := []*protocol.PrefixRule{}
		for _, adminId := range admins {
			rules = append(rules, aclTestPrefixRule(adminId, ""))
		}
		return rules
	}
	file := func(request *AclPrefixRulesRequest, want []*protocol.PrefixRule) *AclPrefixRulesFiled {
		t.Helper()
		filed, err := filer.File(ctx, request, SidecarActConfirmed, nil)
		if err != nil {
			t.Fatal(err)
		}
		rows := net.log.State().Repo(repoId).GetPrefixRules()
		if row := rows[len(rows)-1]; filed.Pin.GetVersion() != net.n || row.GetAt() != net.n || !bytes.Equal(row.GetSigner(), hostId.Bytes()) {
			t.Fatalf("filed at %d, the newest row %v, the tip %d", filed.Pin.GetVersion(), row, net.n)
		}
		opened := aclTestFiledSet(t, net, net.n, key)
		wantSet := &protocol.PrefixRuleSet{Rules: AclPrefixSortRules(want)}
		if opened.State != AclPrefixSetOpened || !proto.Equal(&protocol.PrefixRuleSet{Rules: opened.Rules}, wantSet) || !proto.Equal(filed.Set, wantSet) {
			t.Fatalf("filed %s: %v, want %v", opened.State, opened.Rules, wantSet.GetRules())
		}
		return filed
	}

	// an Allow over no set: the admins written in
	filed := file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: ci, Paths: [][][]byte{aclTestNames("agents/build")}},
		append(adminRules(), aclTestPrefixRule(ci, "agents/build")))
	if len(filed.UnnamedAdmins) != 0 {
		t.Errorf("an Allow leaves admins unnamed: %v", filed.UnnamedAdmins)
	}
	// a second Allow builds on the set in force
	file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: laptop.memberId, Paths: [][][]byte{aclTestNames("docs"), nil}},
		append(adminRules(), aclTestPrefixRule(ci, "agents/build"), aclTestPrefixRule(laptop.memberId, "docs"), aclTestPrefixRule(laptop.memberId, "")))
	// a Deny takes the tag's rule away
	file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesDeny, Subject: ci},
		append(adminRules(), aclTestPrefixRule(laptop.memberId, "docs"), aclTestPrefixRule(laptop.memberId, "")))
	// a Lift is the one rule
	file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesLift}, []*protocol.PrefixRule{aclTestPrefixRule(AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR), "")})
	// a Set as written: its rules alone, every admin unnamed
	filed = file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesSet, AsWritten: true, Rules: []*protocol.PrefixRule{aclTestPrefixRule(ci, "docs")}},
		[]*protocol.PrefixRule{aclTestPrefixRule(ci, "docs")})
	if !slices.Equal(filed.UnnamedAdmins, slices.SortedFunc(slices.Values(admins), Id.Cmp)) {
		t.Errorf("as written, the unnamed admins %v", filed.UnnamedAdmins)
	}
	// a Set not as written gains the admins
	file(&AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesSet, Rules: []*protocol.PrefixRule{aclTestPrefixRule(ci, "docs")}},
		append(adminRules(), aclTestPrefixRule(ci, "docs")))

	posts := api.postCount()
	group := testConfigId("prefix filer group")
	net.withAclRows(func(rows *protocol.AclRows) {
		rows.Atoms = append(rows.Atoms, &protocol.AclAtom{Atom: group.Bytes(), MemberIds: [][]byte{laptop.memberId.Bytes()}})
	})
	for _, c := range []struct {
		name    string
		request *AclPrefixRulesRequest
		origin  SidecarActOrigin
		refusal error
	}{
		{name: "a group's atom", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: group, Paths: [][][]byte{nil}}, refusal: ErrAclPrefixSetInvalid},
		{name: "a role's atom", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: AclDerivedAtom(AclDerivedAtomRole, []byte("admin")), Paths: [][][]byte{nil}}, refusal: ErrAclPrefixSetInvalid},
		{name: "autogroup:admin", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: AclAutogroupAtom(protocol.AclAutogroup_ACL_AUTOGROUP_ADMIN), Paths: [][][]byte{nil}}, refusal: ErrAclPrefixSetInvalid},
		{name: "an unknown id", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: testConfigId("nobody at all"), Paths: [][][]byte{nil}}, refusal: ErrAclPrefixSetInvalid},
		{name: "a path with a slash", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: ci, Paths: [][][]byte{{[]byte("a/b")}}}, refusal: ErrAclPrefixSetInvalid},
		{name: "the config repo", request: &AclPrefixRulesRequest{RepoId: net.configRepoId(), Change: AclPrefixRulesLift}, refusal: ErrAclPrefixRepo},
		{name: "a repo the state does not hold", request: &AclPrefixRulesRequest{RepoId: testConfigId("no such repo"), Change: AclPrefixRulesLift}, refusal: ErrAclPrefixRepo},
		{name: "an MCP origin", request: &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesLift}, origin: SidecarActMcp, refusal: ErrSidecarActMode},
	} {
		origin := c.origin
		if origin == 0 {
			origin = SidecarActConfirmed
		}
		if _, err := filer.File(ctx, c.request, origin, nil); !errors.Is(err, c.refusal) {
			t.Errorf("%s: %v, want %v", c.name, err, c.refusal)
		}
	}
	// an Allow where this device cannot read the set in force
	pendingSets = true
	var ruleError *AclPrefixRuleError
	if _, err := filer.File(ctx, &AclPrefixRulesRequest{RepoId: repoId, Change: AclPrefixRulesAllow, Subject: ci, Paths: [][][]byte{nil}}, SidecarActConfirmed, nil); !errors.As(err, &ruleError) || ruleError.Detail != AclPrefixDetailPending {
		t.Errorf("an Allow over a pending set: %v", err)
	}
	if api.postCount() != posts {
		t.Errorf("a refused filing posted %d statements", api.postCount()-posts)
	}
}
