// DESIGN-DETAILS 16.6's first bullet, ACL-M2-18's half of section 16 (QD-212). RepoPrefixRules' id-level rule on the
// fake view, one case for each row of 16.2.2's table beside its positive twin: the signer, each refused repo kind and a
// deleted repo, a body of 47, 48, 303 and 304 B and one past the cap, the 256th and 257th set. The fold: a row per set
// in position order and nothing else moved, ReapplyStatement giving the rows ApplyStatement gave. Then through TEAM's
// ConfigLog: a set no format-1 reader refuses as unknown, a base's tail re-applied, the base's compile, a new device and
// a rows-only reader holding one list, and the rows half of the base-independence test on generated logs, against the
// list the log's own verdicts give; and AclRowsCheckLimits counting the rows. Pure, on every leg.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

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
