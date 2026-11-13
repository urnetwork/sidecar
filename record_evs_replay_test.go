//go:build !ios_extension

// QD-722 at a stream's replaying reader (record_evs.go's replay row): the stream's directories as its pushes leave them,
// each push held to the creates-only rule, with its payload's entry versions, against them.

package sidecar

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One stream's replay under test: its repo, owner and verifier, and the stream's path key.
type recordReplayTest struct {
	t        *testing.T
	repoId   Id
	refId    Id
	ownerId  Id
	verifier *EvsVerifier
	pathKey  *EvsPathKey
	counters *recordStreamCounters
}

func newRecordReplayTest(t *testing.T) *recordReplayTest {
	repoId := evsTestId("record replay repo")
	ownerId := evsTestId("record replay owner")
	config := &evsTestConfig{
		writers: []Id{ownerId},
		repo:    &protocol.AclRepo{RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_VAULT},
	}
	pathKey := evsTestPathKey(t, repoId, 1)
	counters, err := newRecordStreamCounters(pathKey)
	if err != nil {
		t.Fatal(err)
	}
	return &recordReplayTest{
		t:        t,
		repoId:   repoId,
		refId:    evsTestId("record replay stream"),
		ownerId:  ownerId,
		verifier: newEvsVerifier(&EvsClient{args: &EvsClientArgs{Config: func() GkmAuthView { return config }}}),
		pathKey:  pathKey,
		counters: counters,
	}
}

// path's token path, "" the root's.
func (self *recordReplayTest) tokens(path string) EvsTokenPath {
	names := [][]byte{}
	if path != "" {
		for _, name := range strings.Split(path, "/") {
			names = append(names, []byte(name))
		}
	}
	tokenPath, err := EvsPathTokens(self.pathKey, names)
	if err != nil {
		self.t.Fatal(err)
	}
	return tokenPath
}

// A change writing path at version on base: a directory adding no row and removing the tokens of removed, or a file.
func (self *recordReplayTest) write(path string, kind protocol.EvsEntryKind, base uint64, version uint64, removed ...string) *EvsCheckedChange {
	entry := &protocol.EvsEntryVersion{Version: version, Kind: uint32(kind)}
	if kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
		entry.Names = &protocol.EvsNameTable{}
		for _, name := range removed {
			entry.Names.RemovedTokens = append(entry.Names.RemovedTokens, self.tokens(path+"/"+name).Last().Bytes())
		}
	}
	entryBytes, err := proto.Marshal(entry)
	if err != nil {
		self.t.Fatal(err)
	}
	digest := sha256.Sum256(entryBytes)
	tokenPath := self.tokens(path)
	return &EvsCheckedChange{
		Change:       &protocol.EvsChange{TokenPath: tokenPath.Components(), BaseEntryVersion: base, EntrySha256: digest[:]},
		TokenPath:    tokenPath,
		EntryVersion: entryBytes,
	}
}

func (self *recordReplayTest) directory(path string, base uint64, version uint64, removed ...string) *EvsCheckedChange {
	return self.write(path, protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY, base, version, removed...)
}

func (self *recordReplayTest) file(path string, base uint64, version uint64) *EvsCheckedChange {
	return self.write(path, protocol.EvsEntryKind_EVS_ENTRY_FILE, base, version)
}

// Applies a push of changes at version, signed by the stream's owner with flags.
func (self *recordReplayTest) apply(replay *recordStreamReplay, version uint64, flags protocol.EvsPushFlag, changes ...*EvsCheckedChange) error {
	push := &protocol.EvsPush{
		RefKind: uint32(protocol.EvsRefKind_EVS_REF_OWNED), OwnerSidecarId: self.ownerId.Bytes(), SignerSidecarId: self.ownerId.Bytes(),
		Flags: uint32(flags), PathEpoch: 1,
	}
	statement := &EvsVerifiedStatement{Version: version, Statement: &EvsStatement{Push: push}, Chain: sha256.Sum256([]byte(fmt.Sprint("chain ", version)))}
	return replay.apply(self.verifier, self.repoId, self.refId, statement, &EvsCheckedPayload{Changes: changes}, self.counters, 3584)
}

// An honest stream's pushes pass: its first creating the root, e, e/0, e/0/0 and a file, its next adding to e/0/0 by
// its delta on the newest version, and one starting e/0/1 by e/0's delta; each directory then stands at its newest
// version, the replay through the last push with its chain. A replay resumed from a clone continues alike.
func TestRecordStreamReplayTakesAStreamsAddOnlyDeltas(t *testing.T) {
	test := newRecordReplayTest(t)
	replay := newRecordStreamReplay(test.repoId, test.refId)
	pushes := [][]*EvsCheckedChange{
		{test.directory("", 0, 1), test.directory("e", 0, 1), test.directory("e/0", 0, 1), test.directory("e/0/0", 0, 1), test.file("e/0/0/1", 0, 1)},
		{test.directory("e/0/0", 1, 2), test.file("e/0/0/2", 0, 2)},
		{test.directory("e/0/0", 2, 3), test.file("e/0/0/2047", 0, 3), test.directory("e/0", 1, 2), test.directory("e/0/1", 0, 3), test.file("e/0/1/2048", 0, 3)},
	}
	for i, changes := range pushes {
		if err := test.apply(replay, uint64(i+1), 0, changes...); err != nil {
			t.Fatalf("push %d: %v", i+1, err)
		}
	}
	want := map[string]uint64{"": 1, "e": 1, "e/0": 2, "e/0/0": 3, "e/0/1": 3}
	if len(replay.pathDirectories) != len(want) {
		t.Fatalf("the replay holds %d directories", len(replay.pathDirectories))
	}
	for path, version := range want {
		if directory := replay.pathDirectories[path]; directory == nil || directory.removed || directory.version != version {
			t.Errorf("%q held as %+v, want version %d", path, directory, version)
		}
	}
	if replay.through != 3 || replay.chain != sha256.Sum256([]byte("chain 3")) {
		t.Errorf("the replay holds through %d", replay.through)
	}
	resumed := replay.clone()
	if err := test.apply(resumed, 4, 0, test.directory("e/0/1", 3, 4), test.file("e/0/1/2049", 0, 4)); err != nil {
		t.Fatalf("a resumed replay's next push: %v", err)
	}
	if replay.pathDirectories["e/0/1"].version != 3 || resumed.pathDirectories["e/0/1"].version != 4 {
		t.Errorf("a clone shares its directories with the replay it copied")
	}
}

// Each push the creates-only rule refuses, on a replay holding e/0/0 at version 2 and the file e/0/0/1: a delta
// removing a token, a delta on an older version, a file's write on a base, a delta on a stream file's path, a delta of
// a directory removed, a file where the stream keeps a directory, and a second creation of a standing directory; and a
// BASE's removal of a directory, which a repo admin's statement may make, ends it and what lies below it.
func TestRecordStreamReplayRefusesWhatTheRuleRefuses(t *testing.T) {
	test := newRecordReplayTest(t)
	replay := newRecordStreamReplay(test.repoId, test.refId)
	if err := test.apply(replay, 1, 0, test.directory("", 0, 1), test.directory("e", 0, 1), test.directory("e/0", 0, 1), test.directory("e/0/0", 0, 1), test.file("e/0/0/1", 0, 1)); err != nil {
		t.Fatal(err)
	}
	if err := test.apply(replay, 2, 0, test.directory("e/0/0", 1, 2), test.file("e/0/0/2", 0, 2)); err != nil {
		t.Fatal(err)
	}
	refused := ErrEvsStatementRefused
	cases := []struct {
		name    string
		changes []*EvsCheckedChange
		want    error
		reason  string
	}{
		{name: "a delta removing a token", changes: []*EvsCheckedChange{test.directory("e/0/0", 2, 3, "1"), test.file("e/0/0/3", 0, 3)},
			want: refused, reason: "a directory delta removing a name"},
		{name: "a delta on an older version", changes: []*EvsCheckedChange{test.directory("e/0/0", 1, 2), test.file("e/0/0/3", 0, 3)},
			want: refused, reason: "a directory delta off the directory's newest version"},
		{name: "a file's write on a base", changes: []*EvsCheckedChange{test.file("e/0/0/1", 1, 2)}, want: refused, reason: "a file's write on a base"},
		{name: "a delta on a stream file's path", changes: []*EvsCheckedChange{test.directory("e/0/0/1", 1, 2)},
			want: refused, reason: "a directory delta on a path that does not stand as a directory"},
		{name: "a delta of a directory never created", changes: []*EvsCheckedChange{test.directory("e/0/5", 1, 2)},
			want: refused, reason: "a directory delta on a path that does not stand as a directory"},
		{name: "a file where the stream keeps a directory", changes: []*EvsCheckedChange{test.file("e/0/1", 0, 3)},
			want: refused, reason: `a file where a stream keeps its directory "e/0/1"`},
		{name: "a second creation of a standing directory", changes: []*EvsCheckedChange{test.directory("e/0/0", 0, 3), test.file("e/0/0/3", 0, 3)},
			want: ErrEvsVersionRule, reason: `a creation of the stream directory "e/0/0", which stands`},
		{name: "a removal", changes: []*EvsCheckedChange{{Change: &protocol.EvsChange{TokenPath: test.tokens("e/0/0/1").Components(), BaseEntryVersion: 1}, TokenPath: test.tokens("e/0/0/1")}},
			want: refused, reason: "a removal"},
	}
	for _, c := range cases {
		tried := replay.clone()
		if err := test.apply(tried, 3, 0, c.changes...); !errors.Is(err, c.want) || !strings.HasSuffix(err.Error(), c.reason) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
	// a BASE of e/0/0 by a repo admin, which its statement's rule takes, ends e/0/0: a later delta of it is refused
	adminId := evsTestId("record replay admin")
	test.verifier.client.args.Config().Repo(test.repoId).Admins = []*protocol.AclRepoAdminRow{{SidecarId: adminId.Bytes()}}
	removal := &EvsCheckedChange{Change: &protocol.EvsChange{TokenPath: test.tokens("e/0").Components(), BaseEntryVersion: 1}, TokenPath: test.tokens("e/0")}
	push := &protocol.EvsPush{
		RefKind: uint32(protocol.EvsRefKind_EVS_REF_OWNED), OwnerSidecarId: test.ownerId.Bytes(), SignerSidecarId: adminId.Bytes(),
		Flags: uint32(protocol.EvsPushFlag_EVS_PUSH_BASE), PathEpoch: 1,
	}
	statement := &EvsVerifiedStatement{Version: 3, Statement: &EvsStatement{Push: push}, Chain: sha256.Sum256([]byte("chain 3"))}
	if err := replay.apply(test.verifier, test.repoId, test.refId, statement, &EvsCheckedPayload{Changes: []*EvsCheckedChange{removal}}, test.counters, 3584); err != nil {
		t.Fatalf("an admin's BASE: %v", err)
	}
	for _, path := range []string{"e/0", "e/0/0"} {
		if directory := replay.pathDirectories[path]; directory == nil || !directory.removed {
			t.Errorf("%q stands after the BASE removed e/0", path)
		}
	}
	if directory := replay.pathDirectories["e"]; directory == nil || directory.removed {
		t.Errorf("e went with e/0")
	}
	if err := test.apply(replay, 4, 0, test.directory("e/0/0", 2, 3), test.file("e/0/0/3", 0, 4)); !errors.Is(err, ErrEvsStatementRefused) {
		t.Errorf("a delta of a directory a BASE removed: %v", err)
	}
}
