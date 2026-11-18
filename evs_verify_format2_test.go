//go:build !ios_extension

// The verifying reader in format 2 against a server that lies (EVS2-M10-17; FS-68's reader clauses, FS-72's format-1
// mode, FI-17): versions refused and ignored where they sit, a forged citation in a replay, the statements a format-2
// reader walks, `collected` where it may and may not be answered, and the window's hint bits.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A kind-5 locator of one record in the segment label names.
func evsTestKind5Locator(label string) *protocol.EvsLocator {
	return &protocol.EvsLocator{
		Kind: uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT), Id: evsTestBytes("kind 5 "+label, sha256.Size),
		Offset: uint32(EvsKind5SegmentHeaderByteCount), Length: uint32(EvsRecordByteCount(0)),
	}
}

// A change's format2 hook that writes its file versionless at versioning, its one record in the kind-5 segment label
// names.
func evsTestVersionless(versioning protocol.EvsVersioning, label string) func(entry *protocol.EvsEntryVersion) {
	return func(entry *protocol.EvsEntryVersion) {
		entry.Versioning = uint32(versioning)
		entry.Chain = []*protocol.EvsLocator{evsTestKind5Locator(label)}
	}
}

// A change's format2 hook that sets versioning alone, keeping the version's inline or kind-1 chain.
func evsTestVersioningOnly(versioning protocol.EvsVersioning) func(entry *protocol.EvsEntryVersion) {
	return func(entry *protocol.EvsEntryVersion) {
		entry.Versioning = uint32(versioning)
	}
}

// The reader's verified reply for path on the ref refName names (nil the main ref) at version, 0 the newest, read
// fresh.
func evsTestVerifiedPath(t *testing.T, reader *evsTestClient, world *evsTestWorld, refName []byte, path string, version uint64) (*EvsVerifiedPath, error) {
	t.Helper()
	ctx := context.Background()
	repo := reader.client.Repo(world.repoId)
	refId, err := repo.resolveRefId(ctx, refName, nil)
	if err != nil {
		t.Fatal(err)
	}
	result, err := repo.read(ctx, refId, []string{path}, version, true)
	if err != nil {
		return nil, err
	}
	defer result.objects.close()
	return result.replies[0], nil
}

// The version_rule alarms a reader raised, each naming signerId.
func evsTestVersionRuleAlarms(t *testing.T, reader *evsTestClient, signerId Id) int {
	t.Helper()
	count := 0
	for _, event := range reader.eventsOf(SidecarEventEvsAlarm) {
		if event.EvsAlarm != SidecarEvsAlarmVersionRule {
			t.Errorf("an alarm of %s", event.EvsAlarm)
			continue
		}
		if event.SidecarId == nil || *event.SidecarId != signerId {
			t.Errorf("a version_rule alarm naming %v", event.SidecarId)
		}
		count += 1
	}
	return count
}

// A reader of the world with format 2's reader installed, as a composition installs it.
func evsTestFormat2Reader(t *testing.T, world *evsTestWorld) *evsTestClient {
	t.Helper()
	reader := world.reader(t, evsTestId("reader"))
	reader.client.EnableFormat2Reader()
	return reader
}

// The readers of format 1 alone: one made with no format-2 reader, and one whose settings hold it to format 1.
func evsTestFormat1Readers(t *testing.T, world *evsTestWorld) map[string]*evsTestClient {
	t.Helper()
	held := world.reader(t, evsTestId("format 1 reader"))
	held.client.EnableFormat2Reader()
	held.client.settings.MaxFormat = 1
	return map[string]*evsTestClient{
		"no format-2 reader": world.reader(t, evsTestId("plain reader")),
		"MaxFormat 1":        held,
	}
}

// A format-2 reader takes a versionless version on kind-5 records, with no alarm; a reader of format 1 alone, made
// with no format-2 reader or held to format 1 by its settings, answers FORMAT_UNSUPPORTED for it, never a fork,
// tampering or a missing segment (D-EVS-39).
func TestEvsFormat2ReaderTakesAVersionlessVersion(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "big.bin", content: []byte("one"), segment: true,
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, "one")})
	reader := evsTestFormat2Reader(t, world)
	verified, err := evsTestVerifiedPath(t, reader, world, nil, "big.bin", 0)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Entry == nil || verified.Entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) ||
		verified.Ignored || verified.Collected || verified.Absent {
		t.Errorf("verified %+v", verified)
	}
	if alarms := len(reader.eventsOf(SidecarEventEvsAlarm)) + len(reader.eventsOf(SidecarEventHeadAlarm)); alarms != 0 {
		t.Errorf("%d alarms on a versionless version", alarms)
	}

	for name, format1 := range evsTestFormat1Readers(t, world) {
		_, err = evsTestVerifiedPath(t, format1, world, nil, "big.bin", 0)
		if !errors.Is(err, ErrEvsFormatUnsupported) || EvsRefusalCodeOf(err) != protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED {
			t.Fatalf("%s: %v", name, err)
		}
		if alarms := len(format1.eventsOf(SidecarEventEvsAlarm)) + len(format1.eventsOf(SidecarEventHeadAlarm)); alarms != 0 {
			t.Errorf("%s: %d alarms", name, alarms)
		}
	}
}

// FS-68's lock clause: a versionless version in a push whose auth pin includes the repo's lock is refused and alarms,
// naming its signer, while one written before the lock's position stands, and the index's 2 stands under the lock.
func TestEvsFormat2VersionlessPastTheLockIsRefused(t *testing.T) {
	world := newEvsTestWorld(t)
	// the newest state holds the lock; auth version 1 is before it
	before := &evsTestConfig{
		identityKeys: world.config.identityKeys, writers: world.config.writers, readers: world.config.readers,
		repo: &protocol.AclRepo{RepoId: world.repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_GENERAL},
	}
	world.config.states = map[uint64]GkmAuthView{1: before}
	world.config.repo.Lock = protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED

	world.push(&evsTestChange{path: "before.bin", content: []byte("one"),
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, "before")})
	world.authVersion = 2
	world.push(&evsTestChange{path: "after.bin", content: []byte("two"),
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS, "after")})
	world.push(&evsTestChange{path: ".ur-index/i1/a/0", content: []byte("shard"),
		format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_INDEX, "shard")})
	world.push(&evsTestChange{path: "kept.txt", content: []byte("kept")})

	reader := evsTestFormat2Reader(t, world)
	if _, err := evsTestVerifiedPath(t, reader, world, nil, "before.bin", 0); err != nil {
		t.Fatalf("a versionless version before the lock: %v", err)
	}
	if _, err := evsTestVerifiedPath(t, reader, world, nil, ".ur-index/i1/a/0", 0); err != nil {
		t.Fatalf("an index file under the lock: %v", err)
	}
	if _, err := evsTestVerifiedPath(t, reader, world, nil, "kept.txt", 0); err != nil {
		t.Fatalf("a kept version under the lock: %v", err)
	}
	if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 0 {
		t.Fatalf("%d alarms before the refused read", count)
	}
	_, err := evsTestVerifiedPath(t, reader, world, nil, "after.bin", 0)
	if !errors.Is(err, ErrEvsVersioningRefused) || !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a versionless version past the lock: %v", err)
	}
	if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 1 {
		t.Errorf("%d alarms for the refused version", count)
	}
}

// FS-68's index clauses on a file-mode ref: a 2 outside an index root is ignored with an alarm, as is any version under
// an index root that is not 2, the root's settings file aside, and any path there that is none of the index's.
func TestEvsFormat2IndexRootsOnAFileModeRef(t *testing.T) {
	index := protocol.EvsVersioning_EVS_VERSIONING_INDEX
	versionless := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
	cases := []struct {
		path    string
		format2 func(entry *protocol.EvsEntryVersion)
		ignored bool
	}{
		{path: "notes.txt", format2: evsTestVersionless(index, "outside"), ignored: true},
		{path: "docs/.ur-index/i1/a/0", format2: evsTestVersionless(index, "nested"), ignored: true},
		{path: ".ur-index/i1/a/0", format2: evsTestVersionless(index, "shard"), ignored: false},
		{path: ".ur-index/i1/a/1", format2: nil, ignored: true},
		{path: ".ur-index/i1/a/2", format2: evsTestVersionless(versionless, "versionless shard"), ignored: true},
		{path: ".ur-index/i1/settings", format2: nil, ignored: false},
		{path: ".ur-index/i1/settings", format2: evsTestVersionless(index, "settings"), ignored: true},
		{path: ".ur-index/x", format2: evsTestVersionless(index, "erasure set"), ignored: false},
		{path: ".ur-index/notes.txt", format2: evsTestVersionless(index, "stranger"), ignored: true},
		{path: ".ur-index/i0/a/0", format2: evsTestVersionless(index, "root zero"), ignored: true},
	}
	for i, test := range cases {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: test.path, content: []byte(fmt.Sprint("content ", i)), format2: test.format2})
		reader := evsTestFormat2Reader(t, world)
		verified, err := evsTestVerifiedPath(t, reader, world, nil, test.path, 0)
		if err != nil {
			t.Fatalf("%d %s: %v", i, test.path, err)
		}
		alarms := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId)
		if test.ignored {
			if !verified.Ignored || !verified.Absent || verified.Entry != nil || alarms != 1 {
				t.Errorf("%d %s: ignored %t absent %t, %d alarms", i, test.path, verified.Ignored, verified.Absent, alarms)
			}
			// the path reads as holding none
			out := &bytes.Buffer{}
			_, err := reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: test.path, Fresh: true}, out)
			if err == nil || out.Len() != 0 {
				t.Errorf("%d %s: an ignored version read %q, %v", i, test.path, out.Bytes(), err)
			}
			continue
		}
		if verified.Ignored || verified.Entry == nil || alarms != 0 {
			t.Errorf("%d %s: ignored %t, %d alarms", i, test.path, verified.Ignored, alarms)
		}
	}
}

// The same on the repo's ur/index ref, whose every path is under the index root, and on ur/lfs, whose objects are
// versionless and whose settings file is kept (plan-EVS2-lfs-settings).
func TestEvsFormat2ReservedRefs(t *testing.T) {
	index := protocol.EvsVersioning_EVS_VERSIONING_INDEX
	versionless := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
	cases := []struct {
		refName []byte
		path    string
		format2 func(entry *protocol.EvsEntryVersion)
		ignored bool
	}{
		{refName: EvsIndexRefName, path: "i1/a/0", format2: evsTestVersionless(index, "shard"), ignored: false},
		{refName: EvsIndexRefName, path: "i1/a/1", format2: evsTestVersionless(versionless, "versionless shard"), ignored: true},
		{refName: EvsIndexRefName, path: "i1/a/2", format2: nil, ignored: true},
		{refName: EvsIndexRefName, path: "i1/settings", format2: nil, ignored: false},
		{refName: EvsIndexRefName, path: "notes.txt", format2: evsTestVersionless(index, "stranger"), ignored: true},
		{refName: EvsLfsRefName, path: "ab/cd/object", format2: evsTestVersionless(versionless, "object"), ignored: false},
		{refName: EvsLfsRefName, path: "ab/cd/kept", format2: nil, ignored: true},
		{refName: EvsLfsRefName, path: "ab/cd/index", format2: evsTestVersionless(index, "index"), ignored: true},
		{refName: EvsLfsRefName, path: "settings", format2: nil, ignored: false},
		{refName: EvsLfsRefName, path: "settings", format2: evsTestVersionless(versionless, "lfs settings"), ignored: true},
	}
	for i, test := range cases {
		world := newEvsTestWorld(t)
		// the main ref holds a file of its own, so the reader resolves both refs
		world.push(&evsTestChange{path: "a.txt", content: []byte("main")})
		ref := world.otherRef(test.refName)
		ref.push(&evsTestChange{path: test.path, content: []byte(fmt.Sprint("content ", i)), format2: test.format2})
		reader := evsTestFormat2Reader(t, world)
		verified, err := evsTestVerifiedPath(t, reader, world, test.refName, test.path, 0)
		if err != nil {
			t.Fatalf("%d %s %s: %v", i, test.refName, test.path, err)
		}
		alarms := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId)
		if verified.Ignored != test.ignored || (alarms == 1) != test.ignored {
			t.Errorf("%d %s %s: ignored %t, %d alarms", i, test.refName, test.path, verified.Ignored, alarms)
		}
	}
}

// §11.7's refused row and the lfs rows as the pure rule holds them: versioning past 2, 1 or 2 in a config or mailcfg
// repo, on a git-mode ref and on creates-only refs, 1 under the lock, and ur/lfs's 0 only in a locked repo.
func TestEvsCheckVersioningTable(t *testing.T) {
	general := func(change func(context *EvsVersioningContext)) *EvsVersioningContext {
		context := &EvsVersioningContext{
			RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
		}
		if change != nil {
			change(context)
		}
		return context
	}
	names := func(path ...string) [][]byte {
		out := [][]byte{}
		for _, name := range path {
			out = append(out, []byte(name))
		}
		return out
	}
	file := func(versioning uint32) *protocol.EvsEntryVersion {
		return &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE), Versioning: versioning}
	}
	directory := func(versioning uint32) *protocol.EvsEntryVersion {
		return &protocol.EvsEntryVersion{Kind: uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY), Versioning: versioning}
	}
	cases := []struct {
		name    string
		context *EvsVersioningContext
		names   [][]byte
		entry   *protocol.EvsEntryVersion
		want    error
	}{
		{name: "kept", context: general(nil), names: names("a.txt"), entry: file(0), want: nil},
		{name: "versionless", context: general(nil), names: names("a.txt"), entry: file(1), want: nil},
		{name: "past 2", context: general(nil), names: names("a.txt"), entry: file(3), want: ErrEvsVersioningRefused},
		{name: "a versionless directory", context: general(nil), names: names("docs"), entry: directory(1), want: ErrEvsVersioningRefused},
		{name: "a directory", context: general(nil), names: names("docs"), entry: directory(0), want: nil},
		{name: "the index directory", context: general(nil), names: names(".ur-index"), entry: directory(0), want: nil},
		{name: "config 1", context: general(func(c *EvsVersioningContext) { c.RepoKind = protocol.RepoKind_REPO_KIND_CONFIG }), names: names("a.txt"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "config 2", context: general(func(c *EvsVersioningContext) { c.RepoKind = protocol.RepoKind_REPO_KIND_CONFIG }), names: names(".ur-index", "i1", "a", "0"), entry: file(2), want: ErrEvsVersioningRefused},
		{name: "config 0", context: general(func(c *EvsVersioningContext) { c.RepoKind = protocol.RepoKind_REPO_KIND_CONFIG }), names: names("a.txt"), entry: file(0), want: nil},
		{name: "mailcfg 1", context: general(func(c *EvsVersioningContext) { c.RepoKind = protocol.RepoKind_REPO_KIND_MAILCFG }), names: names("a.txt"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "git 1", context: general(func(c *EvsVersioningContext) { c.RefMode = protocol.EvsRefMode_EVS_REF_GIT }), names: names("a.txt"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "git 2", context: general(func(c *EvsVersioningContext) { c.RefMode = protocol.EvsRefMode_EVS_REF_GIT }), names: names(".ur-index", "i1", "a", "0"), entry: file(2), want: ErrEvsVersioningRefused},
		{name: "git 0", context: general(func(c *EvsVersioningContext) { c.RefMode = protocol.EvsRefMode_EVS_REF_GIT }), names: names("a.txt"), entry: file(0), want: nil},
		{name: "deposit 1", context: general(func(c *EvsVersioningContext) { c.RefKind = protocol.EvsRefKind_EVS_REF_DEPOSIT }), names: nil, entry: file(1), want: ErrEvsVersioningRefused},
		{name: "erasure 1", context: general(func(c *EvsVersioningContext) { c.RefKind = protocol.EvsRefKind_EVS_REF_ERASURE }), names: nil, entry: file(1), want: ErrEvsVersioningRefused},
		{name: "a record stream 1", context: general(func(c *EvsVersioningContext) {
			c.RepoKind, c.RefKind = protocol.RepoKind_REPO_KIND_RECORD, protocol.EvsRefKind_EVS_REF_OWNED
		}), names: names("a"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "an owned ref of a general repo", context: general(func(c *EvsVersioningContext) { c.RefKind = protocol.EvsRefKind_EVS_REF_OWNED }), names: names("a"), entry: file(1), want: nil},
		{name: "locked 1", context: general(func(c *EvsVersioningContext) { c.Locked = true }), names: names("a.txt"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "locked 0", context: general(func(c *EvsVersioningContext) { c.Locked = true }), names: names("a.txt"), entry: file(0), want: nil},
		{name: "locked 2 under a root", context: general(func(c *EvsVersioningContext) { c.Locked = true }), names: names(".ur-index", "i1", "a", "0"), entry: file(2), want: nil},
		{name: "2 outside a root", context: general(nil), names: names("a.txt"), entry: file(2), want: ErrEvsVersionIgnored},
		{name: "2 at a path of no names", context: general(nil), names: nil, entry: file(2), want: nil},
		{name: "2 of no names on ur/lfs", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: nil, entry: file(2), want: ErrEvsVersionIgnored},
		{name: "0 under a root", context: general(nil), names: names(".ur-index", "i1", "a", "0"), entry: file(0), want: ErrEvsVersionIgnored},
		{name: "1 under a root", context: general(nil), names: names(".ur-index", "i1", "a", "0"), entry: file(1), want: ErrEvsVersionIgnored},
		{name: "settings under a root", context: general(nil), names: names(".ur-index", "i1", "settings"), entry: file(0), want: nil},
		{name: "a stranger under a root", context: general(nil), names: names(".ur-index", "readme"), entry: file(2), want: ErrEvsVersionIgnored},
		{name: "ur/index 2", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefIndex }), names: names("i1", "a", "0"), entry: file(2), want: nil},
		{name: "ur/index 0", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefIndex }), names: names("i1", "a", "0"), entry: file(0), want: ErrEvsVersionIgnored},
		{name: "ur/index's own .ur-index", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefIndex }), names: names(".ur-index", "i1", "a", "0"), entry: file(2), want: ErrEvsVersionIgnored},
		{name: "lfs 1", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: names("ab", "cd"), entry: file(1), want: nil},
		{name: "lfs 0", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: names("ab", "cd"), entry: file(0), want: ErrEvsVersionIgnored},
		{name: "lfs 0 locked", context: general(func(c *EvsVersioningContext) { c.Reserved, c.Locked = EvsReservedRefLfs, true }), names: names("ab", "cd"), entry: file(0), want: nil},
		{name: "lfs 1 locked", context: general(func(c *EvsVersioningContext) { c.Reserved, c.Locked = EvsReservedRefLfs, true }), names: names("ab", "cd"), entry: file(1), want: ErrEvsVersioningRefused},
		{name: "lfs settings 0", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: names("settings"), entry: file(0), want: nil},
		{name: "lfs settings 1", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: names("settings"), entry: file(1), want: ErrEvsVersionIgnored},
		{name: "lfs .ur-index", context: general(func(c *EvsVersioningContext) { c.Reserved = EvsReservedRefLfs }), names: names(".ur-index", "i1", "a", "0"), entry: file(2), want: ErrEvsVersionIgnored},
	}
	for _, test := range cases {
		err := EvsCheckVersioning(test.context, test.names, test.entry)
		if test.want == nil && err != nil || test.want != nil && !errors.Is(err, test.want) {
			t.Errorf("%s: %v", test.name, err)
		}
	}
}

// What one version shows alone of the content row: a kind-5 locator in a kept version and an inline record in a
// versionless one are refused, with an alarm, where a head reader meets them.
func TestEvsFormat2VersionShapeIsRefused(t *testing.T) {
	cases := map[string]func(entry *protocol.EvsEntryVersion){
		"a kind-5 locator in a kept version": func(entry *protocol.EvsEntryVersion) {
			entry.Chain = []*protocol.EvsLocator{evsTestKind5Locator("kept")}
		},
		"an inline record in a versionless version": evsTestVersioningOnly(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS),
	}
	for name, format2 := range cases {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: "a.bin", content: []byte("one"), format2: format2})
		reader := evsTestFormat2Reader(t, world)
		_, err := evsTestVerifiedPath(t, reader, world, nil, "a.bin", 0)
		if !errors.Is(err, ErrEvsVersioningRefused) || !errors.Is(err, ErrEvsVersioning) {
			t.Fatalf("%s: %v", name, err)
		}
		if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 1 {
			t.Errorf("%s: %d alarms", name, count)
		}
	}
}

// One committed push of the world as a replaying reader holds it: its statement, its changes and each written
// change's entry version.
func evsTestReplayPush(t *testing.T, world *evsTestWorld, version uint64) (*EvsVerifiedStatement, []*EvsCheckedChange, map[string][]byte) {
	t.Helper()
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	commit := world.commits[version-1]
	entriesBySha256 := map[[sha256.Size]byte][]byte{}
	for _, path := range world.paths {
		for _, held := range path.versions {
			entriesBySha256[sha256.Sum256(held.entryBytes)] = held.entryBytes
		}
	}
	entries := map[string][]byte{}
	for _, change := range commit.parsed.Changes {
		if !change.WritesEntry() {
			continue
		}
		entryBytes, ok := entriesBySha256[[sha256.Size]byte(change.Change.GetEntrySha256())]
		if !ok {
			t.Fatalf("version %d: an entry the world does not hold", version)
		}
		entries[change.TokenPath.KeyString()] = entryBytes
	}
	return &EvsVerifiedStatement{Version: version, Statement: commit.parsed, Chain: commit.chain}, commit.parsed.Changes, entries
}

// The ids of the kind-5 segments labels name, as a push's versionless uploads.
func evsTestKind5Ids(labels ...string) map[[sha256.Size]byte]bool {
	ids := map[[sha256.Size]byte]bool{}
	for _, label := range labels {
		ids[[sha256.Size]byte(evsTestKind5Locator(label).GetId())] = true
	}
	return ids
}

// FI-17's forged citation with evs bypassed: a writer's signed push whose versionless version names another path's
// kind-5 segment, which evs's 5h refuses and a malicious evs commits. A replaying reader refuses the push by the
// citation rule and alarms, naming the signer; the honest twin, citing its own upload and then its own base, passes.
func TestEvsFormat2ReplayRefusesAForgedCitation(t *testing.T) {
	versionless := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.bin", content: []byte("a one"), format2: evsTestVersionless(versionless, "a one")})
	// honest: a.bin again on a new upload, then keeping its base's segment
	world.push(&evsTestChange{path: "a.bin", content: []byte("a two"), format2: evsTestVersionless(versionless, "a two")})
	world.push(&evsTestChange{path: "a.bin", content: []byte("a two"), format2: evsTestVersionless(versionless, "a two")})
	// forged: b.bin created naming a.bin's segment, no upload of its own
	world.push(&evsTestChange{path: "b.bin", content: []byte("b one"), format2: evsTestVersionless(versionless, "a two")})

	reader := evsTestFormat2Reader(t, world)
	replay := NewEvsReplayPaths(0)
	uploads := []map[[sha256.Size]byte]bool{evsTestKind5Ids("a one"), evsTestKind5Ids("a two"), nil, nil}
	for version := uint64(1); version <= 3; version += 1 {
		statement, changes, entries := evsTestReplayPush(t, world, version)
		ignored, err := reader.client.verifier.ReplayFormat2(world.repoId, world.refId, replay, EvsReservedRefNone, statement, changes, entries,
			&EvsReplayFormat2{VersionlessUploads: uploads[version-1]})
		if err != nil || len(ignored) != 0 {
			t.Fatalf("version %d: %v, %d ignored", version, err, len(ignored))
		}
	}
	if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 0 {
		t.Fatalf("%d alarms on honest pushes", count)
	}
	statement, changes, entries := evsTestReplayPush(t, world, 4)
	_, err := reader.client.verifier.ReplayFormat2(world.repoId, world.refId, replay, EvsReservedRefNone, statement, changes, entries,
		&EvsReplayFormat2{})
	if !errors.Is(err, ErrEvsVersioning) || EvsRefusalCodeOf(err) != protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING {
		t.Fatalf("a forged citation: %v", err)
	}
	if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 1 {
		t.Errorf("%d alarms for the forged citation", count)
	}
}

// A replay that began above version 0 holds no base for a path it never saw: its citations go unjudged, so the push
// fails closed unless the caller supplies the base, and then the rule runs on it.
func TestEvsFormat2ReplayNeedsTheBaseItCites(t *testing.T) {
	versionless := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.bin", content: []byte("a one"), format2: evsTestVersionless(versionless, "a one")})
	world.push(&evsTestChange{path: "a.bin", content: []byte("a one"), format2: evsTestVersionless(versionless, "a one")})
	statement, changes, entries := evsTestReplayPush(t, world, 2)
	context := &EvsVersioningContext{
		RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_FILE,
	}

	_, err := NewEvsReplayPaths(1).ApplyFormat2(statement, changes, entries, &EvsReplayFormat2{RefId: world.refId, Context: context})
	if !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("a base the replay does not hold: %v", err)
	}

	_, _, firstEntries := evsTestReplayPush(t, world, 1)
	base := &protocol.EvsEntryVersion{}
	for _, entryBytes := range firstEntries {
		if err := proto.Unmarshal(entryBytes, base); err != nil {
			t.Fatal(err)
		}
	}
	asked := 0
	supplied := &EvsReplayFormat2{RefId: world.refId, Context: context, Base: func(tokenPath EvsTokenPath, entryVersion uint64) *protocol.EvsEntryVersion {
		asked += 1
		if !tokenPath.Equal(world.tokens("a.bin")) || entryVersion != 1 {
			t.Errorf("asked for %v at %d", tokenPath, entryVersion)
		}
		return base
	}}
	if _, err := NewEvsReplayPaths(1).ApplyFormat2(statement, changes, entries, supplied); err != nil || asked != 1 {
		t.Fatalf("with its base supplied: %v, asked %d", err, asked)
	}

	// a base naming another segment: the version's kind-5 locator is neither an upload nor its base's
	other := proto.Clone(base).(*protocol.EvsEntryVersion)
	other.Chain = []*protocol.EvsLocator{evsTestKind5Locator("another")}
	supplied.Base = func(tokenPath EvsTokenPath, entryVersion uint64) *protocol.EvsEntryVersion { return other }
	if _, err := NewEvsReplayPaths(1).ApplyFormat2(statement, changes, entries, supplied); !errors.Is(err, ErrEvsVersioning) {
		t.Fatalf("a base that does not hold the segment: %v", err)
	}
}

// A replaying reader refuses a version where it sits and reports the versions it ignores, the push's other versions
// standing.
func TestEvsFormat2ReplayRefusesAndIgnores(t *testing.T) {
	index := protocol.EvsVersioning_EVS_VERSIONING_INDEX
	world := newEvsTestWorld(t)
	world.push(
		&evsTestChange{path: "notes.txt", content: []byte("notes")},
		&evsTestChange{path: "stray.bin", content: []byte("stray"), format2: evsTestVersionless(index, "stray")},
	)
	names := func(tokenPath EvsTokenPath) [][]byte {
		for _, path := range []string{"notes.txt", "stray.bin"} {
			if tokenPath.Equal(world.tokens(path)) {
				return [][]byte{[]byte(path)}
			}
		}
		return nil
	}
	reader := evsTestFormat2Reader(t, world)
	statement, changes, entries := evsTestReplayPush(t, world, 1)
	ignored, err := reader.client.verifier.ReplayFormat2(world.repoId, world.refId, NewEvsReplayPaths(0), EvsReservedRefNone, statement, changes, entries,
		&EvsReplayFormat2{Names: names, VersionlessUploads: evsTestKind5Ids("stray")})
	if err != nil || len(ignored) != 1 || !ignored[0].Equal(world.tokens("stray.bin")) {
		t.Fatalf("ignored %v: %v", ignored, err)
	}
	if count := evsTestVersionRuleAlarms(t, reader, world.signer.sidecarId); count != 1 {
		t.Errorf("%d alarms for the ignored version", count)
	}

	// the same push on a git-mode ref is refused whole
	gitContext := &EvsVersioningContext{
		RepoKind: protocol.RepoKind_REPO_KIND_GENERAL, RefKind: protocol.EvsRefKind_EVS_REF_SHARED, RefMode: protocol.EvsRefMode_EVS_REF_GIT,
	}
	_, err = NewEvsReplayPaths(0).ApplyFormat2(statement, changes, entries,
		&EvsReplayFormat2{RefId: world.refId, Context: gitContext, Names: names, VersionlessUploads: evsTestKind5Ids("stray")})
	if !errors.Is(err, ErrEvsVersioningRefused) {
		t.Fatalf("a versionless version on a git-mode ref: %v", err)
	}
}

// A format-2 reader walks a CUT its repo's admin signed, and a head naming its index_epoch; a CUT by a writer that is
// no admin is refused as any statement off the refs table is, with an alarm; a reader held to format 1 answers
// FORMAT_UNSUPPORTED for the ref, quietly (FS-72).
func TestEvsFormat2StatementsWalk(t *testing.T) {
	cut := func(world *evsTestWorld) {
		world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
		world.nextFlags = uint32(protocol.EvsPushFlag_EVS_PUSH_CUT)
		world.push(&evsTestChange{path: ".ur-index/i1/a/0", content: []byte("shard"),
			format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_INDEX, "shard")})
		world.nextIndexEpoch = 2
		world.push(&evsTestChange{path: ".ur-index/i1/a/1", content: []byte("shard"),
			format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_INDEX, "next shard")})
	}

	world := newEvsTestWorld(t)
	world.config.repo.Admins = []*protocol.AclRepoAdminRow{{SidecarId: world.signer.sidecarId.Bytes()}}
	cut(world)
	reader := evsTestFormat2Reader(t, world)
	content, _, err := evsTestRead(t, reader, world, "a.txt")
	if err != nil || string(content) != "one" {
		t.Fatalf("a ref holding a CUT: %q %v", content, err)
	}
	if _, err := evsTestVerifiedPath(t, reader, world, nil, ".ur-index/i1/a/1", 0); err != nil {
		t.Fatalf("an index file past the CUT: %v", err)
	}
	if alarms := len(reader.eventsOf(SidecarEventEvsAlarm)) + len(reader.eventsOf(SidecarEventHeadAlarm)); alarms != 0 {
		t.Errorf("%d alarms walking a CUT", alarms)
	}
	for name, format1 := range evsTestFormat1Readers(t, world) {
		if _, _, err := evsTestRead(t, format1, world, "a.txt"); !errors.Is(err, ErrEvsFormatUnsupported) {
			t.Fatalf("%s over a CUT: %v", name, err)
		}
		if alarms := len(format1.eventsOf(SidecarEventEvsAlarm)) + len(format1.eventsOf(SidecarEventHeadAlarm)); alarms != 0 {
			t.Errorf("%s: %d alarms", name, alarms)
		}
	}

	forged := newEvsTestWorld(t)
	cut(forged)
	reader = evsTestFormat2Reader(t, forged)
	if _, _, err := evsTestRead(t, reader, forged, "a.txt"); !errors.Is(err, ErrEvsStatementRefused) {
		t.Fatalf("a CUT by a non-admin: %v", err)
	}
	tamper := 0
	for _, event := range reader.eventsOf(SidecarEventEvsAlarm) {
		if event.EvsAlarm == SidecarEvsAlarmTamper && event.SidecarId != nil && *event.SidecarId == forged.signer.sidecarId {
			tamper += 1
		}
	}
	if tamper == 0 {
		t.Errorf("a CUT by a non-admin raised no alarm naming its signer")
	}
}

// `collected` is evs's unsigned word. For a replaced versionless version asked for by number it stands, with no alarm,
// and its content reads ErrEvsCollected; for a path's newest version, and for a version that keeps its content, it
// alarms as a missing segment does (§11.9's collected row; FI-16).
func TestEvsFormat2CollectedVerdicts(t *testing.T) {
	versionless := protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS
	collected := func(reply *protocol.EvsReadPathReply) {
		if reply.GetVersion() != nil {
			reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
		}
	}
	missingSegmentAlarms := func(reader *evsTestClient) int {
		count := 0
		for _, event := range reader.eventsOf(SidecarEventEvsAlarm) {
			if event.EvsAlarm != SidecarEvsAlarmMissingSegment {
				t.Errorf("an alarm of %s", event.EvsAlarm)
			}
			count += 1
		}
		return count
	}

	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "big.bin", content: []byte("one"), format2: evsTestVersionless(versionless, "one")})
	world.push(&evsTestChange{path: "big.bin", content: []byte("two"), format2: evsTestVersionless(versionless, "two")})
	world.push(&evsTestChange{path: "kept.txt", content: []byte("one")})
	world.push(&evsTestChange{path: "kept.txt", content: []byte("two")})
	// evs as it is: the replaced version alone answers collected, and the fresh read the reader's gone row makes
	// (evs_read_versionless.go) finds the path's newest version served
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		if reply.GetVersion().GetCommitVersion() == 1 {
			reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
		}
	}

	// the replaced version, by number
	reader := evsTestFormat2Reader(t, world)
	verified, err := evsTestVerifiedPath(t, reader, world, nil, "big.bin", 1)
	if err != nil || !verified.Collected || verified.Entry.GetVersion() != 1 {
		t.Fatalf("a replaced versionless version: %+v %v", verified, err)
	}
	out := &bytes.Buffer{}
	_, err = reader.client.Repo(world.repoId).ReadHead(context.Background(), &EvsReadArgs{Path: "big.bin", Version: 1}, out)
	if !errors.Is(err, ErrEvsCollected) || out.Len() != 0 {
		t.Fatalf("its content: %q %v", out.Bytes(), err)
	}
	if count := missingSegmentAlarms(reader); count != 0 {
		t.Errorf("%d alarms on a collected version", count)
	}

	// the path's newest version
	world.mutatePath = collected
	reader = evsTestFormat2Reader(t, world)
	if _, err := evsTestVerifiedPath(t, reader, world, nil, "big.bin", 0); !errors.Is(err, ErrEvsObjectMissing) {
		t.Fatalf("collected for a newest version: %v", err)
	}
	if count := missingSegmentAlarms(reader); count != 1 {
		t.Errorf("%d alarms for a newest version answered collected", count)
	}

	// a kept version, by number: kept.txt was created at ref version 3, so its first version is 3
	reader = evsTestFormat2Reader(t, world)
	if _, err := evsTestVerifiedPath(t, reader, world, nil, "kept.txt", 3); !errors.Is(err, ErrEvsObjectMissing) {
		t.Fatalf("collected for a kept version: %v", err)
	}
	if count := missingSegmentAlarms(reader); count != 1 {
		t.Errorf("%d alarms for a kept version answered collected", count)
	}

	// collected with no version to speak for
	world.mutatePath = func(reply *protocol.EvsReadPathReply) {
		reply.State = protocol.EvsReadPathState_EVS_READ_PATH_COLLECTED
	}
	reader = evsTestFormat2Reader(t, world)
	if _, err := evsTestVerifiedPath(t, reader, world, nil, "never.txt", 0); !errors.Is(err, ErrEvsEntryRefused) {
		t.Fatalf("collected for an absent path: %v", err)
	}
}

// A drop's read states on a path's newest version are refused with a tamper alarm, since a drop never takes the head
// (EVS2-M10-22's H0, evs_drop_verify.go), and a drop id with no state answers FORMAT_UNSUPPORTED for the path, with no
// alarm; nothing is shown dropped either way.
func TestEvsFormat2DropStatesOnTheNewestVersionRefused(t *testing.T) {
	mutations := map[string]func(reply *protocol.EvsReadPathReply){
		"drop_pending": func(reply *protocol.EvsReadPathReply) {
			reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROP_PENDING
			reply.DropId = make([]byte, 16)
		},
		"dropped": func(reply *protocol.EvsReadPathReply) {
			reply.State = protocol.EvsReadPathState_EVS_READ_PATH_DROPPED
			reply.DropId = make([]byte, 16)
		},
	}
	for name, mutate := range mutations {
		world := newEvsTestWorld(t)
		world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
		world.mutatePath = mutate
		reader := evsTestFormat2Reader(t, world)
		if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsEntryRefused) {
			t.Fatalf("%s: %v", name, err)
		}
		if alarms := reader.eventsOf(SidecarEventEvsAlarm); len(alarms) != 1 || alarms[0].EvsAlarm != SidecarEvsAlarmTamper {
			t.Errorf("%s: alarms %v", name, alarms)
		}
	}
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	world.mutatePath = func(reply *protocol.EvsReadPathReply) { reply.DropId = make([]byte, 16) }
	reader := evsTestFormat2Reader(t, world)
	if _, _, err := evsTestRead(t, reader, world, "a.txt"); !errors.Is(err, ErrEvsFormatUnsupported) {
		t.Fatalf("a drop id with no state: %v", err)
	}
	if alarms := len(reader.eventsOf(SidecarEventEvsAlarm)) + len(reader.eventsOf(SidecarEventHeadAlarm)); alarms != 0 {
		t.Errorf("a drop id with no state: %d alarms", alarms)
	}
}

// The window's bits 4 and 5 are evs's hints: an entry with either set, or cleared, decodes to the same facts a reader
// could check, so a hostile bit changes nothing.
func TestEvsFormat2WindowHintBitsChangeNothing(t *testing.T) {
	world := newEvsTestWorld(t)
	world.push(&evsTestChange{path: "a.txt", content: []byte("one")})
	commit := world.commits[0]
	entry := NewEvsWindowEntry(commit.parsed.Sha256, commit.parsed.Push, []EvsTokenPath{world.tokens("a.txt")}, nil, true, nil)
	plain, err := DecodeEvsWindowEntry(entry.Encode())
	if err != nil {
		t.Fatal(err)
	}
	for _, hint := range []protocol.EvsWindowFlag{protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED, protocol.EvsWindowFlag_EVS_WINDOW_DROP} {
		hostile := *entry
		hostile.Flags |= uint32(hint)
		decoded, err := DecodeEvsWindowEntry(hostile.Encode())
		if err != nil {
			t.Fatalf("bit %d: %v", hint, err)
		}
		pushId := Id(commit.parsed.Push.GetPushId())
		if decoded.CreatesPath() != plain.CreatesPath() || decoded.ChangesInPayload() != plain.ChangesInPayload() ||
			decoded.PathEpoch() != plain.PathEpoch() || decoded.RewritesHistory() != plain.RewritesHistory() ||
			decoded.ChangeCount() != plain.ChangeCount() || decoded.PathsDigest != plain.PathsDigest ||
			!decoded.Names(pushId, commit.parsed.Sha256) {
			t.Errorf("bit %d changed what the entry says", hint)
		}
	}
	// and a reader's verdict on the ref never reads the window: the head it verifies carries none
	reader := evsTestFormat2Reader(t, world)
	if content, _, err := evsTestRead(t, reader, world, "a.txt"); err != nil || string(content) != "one" {
		t.Fatalf("read %q %v", content, err)
	}
}

// §11.15's head read 100 versions behind its pin, in format 2: each statement names an index_epoch, so each parses and
// verifies as format 2, and the walk holds the pins and the chain. The target is 20 ms on mobile.
func BenchmarkEvsFormat2Walk100Versions(b *testing.B) {
	world := newEvsTestWorld(b)
	statements := []*protocol.EvsReadStatement{}
	for version := uint64(1); version <= 100; version += 1 {
		world.nextIndexEpoch = 1
		world.push(&evsTestChange{path: fmt.Sprint(".ur-index/i1/a/", version%64), content: []byte(fmt.Sprint("shard ", version)),
			format2: evsTestVersionless(protocol.EvsVersioning_EVS_VERSIONING_INDEX, fmt.Sprint("shard ", version))})
		statements = append(statements, &protocol.EvsReadStatement{Version: version, Statement: world.commits[version-1].statement})
	}
	// the walk reads the config and the settings alone, so a bare client carries it
	client := &EvsClient{
		args: &EvsClientArgs{Config: func() GkmAuthView { return world.config }}, settings: DefaultEvsSettings(), log: NewNoopLogger(),
	}
	client.EnableFormat2Reader()
	verifier := newEvsVerifier(client)
	start := EvsChainStart(world.repoId, world.refId)
	b.ResetTimer()
	for b.Loop() {
		walked, err := verifier.walk(world.repoId, world.refId, 0, start, statements, 100)
		if err != nil || len(walked) != 100 {
			b.Fatalf("walked %d: %v", len(walked), err)
		}
	}
}
