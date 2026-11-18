//go:build !sidecar_http

// RECORD-M6-28 on T2: sidecar.DirectoryEvsCards against an evsservice.EvsEngine on record_evs_test.go's world, a
// repo of kind directory whose writers push their own record-class streams through RecordEvsStreams and write notices
// on the shared cards ref, every device its own EvsClient. The moved listing names each ref by its id; up to 64
// streams are read in one request, each version's entries named by their counters and its slot's rows opened; a stream
// past one reply's budget answers more and one past the window behind, which the log pages; a read verifies from the
// chain this binding kept, the client's pin, or a walk of the log; the cards ref's statements come back in commit
// order with their signers, pins and plaintext paths, from delta rows, the copy's paths or a listing; writes and
// removals take path CAS, as the directory's own writer, refusing what is no directory path or names a pin the client
// does not hold; and leases land only on notice paths, each change under one calling back. RECORD-M6-13's sync runs
// through the binding in directory_sync_test.go.

package sidecar_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The world's directory: a repo of kind directory whose group the world's owner device holds from its creation, as
// team-create's first Owner device files it (§16.11's creation row).
func newRecordEvsWorldDirectory(world *recordEvsWorld) (sidecar.Id, error) {
	ctx := world.ctx
	repoId := sidecar.NewId()
	func() {
		world.stateLock.Lock()
		defer world.stateLock.Unlock()
		world.repoIds = append(world.repoIds, repoId)
		world.repos[repoId] = &recordEvsWorldRepo{
			kind:   protocol.RepoKind_REPO_KIND_DIRECTORY,
			grants: map[sidecar.Id]sidecartest.RecordStreamsScope{world.ownerId: {Read: true, Write: true, Admin: true}},
			admins: []sidecar.Id{world.ownerId},
		}
		world.publishWithLock(true)
	}()
	if _, err := world.gkmClient(world.ownerId).CreateGroup(ctx, &sidecar.GkmCreateGroupArgs{RepoId: repoId, Kind: protocol.RepoKind_REPO_KIND_DIRECTORY}); err != nil {
		return sidecar.Id{}, err
	}
	placeBytes, err := (&sidecar.EvsRepoPlace{ClusterId: "meta-1", CreatorSidecarId: world.ownerId}).Marshal()
	if err != nil {
		return sidecar.Id{}, err
	}
	if _, err := world.cluster.PutIfNoneMatch(ctx, sidecar.EvsPlaceKey(repoId), placeBytes, nil); err != nil {
		return sidecar.Id{}, err
	}
	repoBytes, err := proto.Marshal(&protocol.EvsRepoObject{
		RepoId: repoId.Bytes(), Kind: protocol.RepoKind_REPO_KIND_DIRECTORY, State: protocol.EvsRepoState_EVS_REPO_ACTIVE,
		Format: sidecar.EvsRepoFormat1, NetworkId: world.networkId.Bytes(),
	})
	if err != nil {
		return sidecar.Id{}, err
	}
	if _, err := world.cluster.PutIfNoneMatch(ctx, evsservice.RepoKey(repoId), repoBytes, nil); err != nil {
		return sidecar.Id{}, err
	}
	return repoId, nil
}

// §20.4's limits the world's network runs under: the receipt budget, and the subscription caps a lease is held to.
func setRecordEvsWorldDirectoryLimits(world *recordEvsWorld) {
	world.host.Quota.SetLimits(connect.Id(world.networkId), &sidecar.QuotaLimits{Limits: map[string]int64{
		"evs_read_receipts_per_repo_day": 256,
		"config_admissions":              256,
		"evs_subscribers_per_repo":       256,
		"evs_repos_per_client":           256,
	}})
}

// A directory on the world, with writers and a reader, each a member device with rw on it.
type directoryEvsWorld struct {
	world       *recordEvsWorld
	directoryId sidecar.Id
	writers     []sidecar.Id
	readerId    sidecar.Id
	reader      *sidecar.EvsClient
	cards       *sidecar.DirectoryEvsCards
}

func newDirectoryEvsWorld(t *testing.T, writerCount int, adjust ...func(settings *evsservice.EvsSettings)) *directoryEvsWorld {
	t.Helper()
	world := newRecordEvsWorld(t, adjust...)
	setRecordEvsWorldDirectoryLimits(world)
	directoryId, err := newRecordEvsWorldDirectory(world)
	if err != nil {
		t.Fatal(err)
	}
	directory := &directoryEvsWorld{world: world, directoryId: directoryId}
	for range writerCount {
		directory.writers = append(directory.writers, directory.member(t, sidecartest.RecordStreamsScope{Read: true, Write: true}))
	}
	directory.readerId = directory.member(t, sidecartest.RecordStreamsScope{Read: true, Write: true})
	directory.reader = directory.client(directory.readerId)
	directory.cards = directory.binding(t, directory.reader, nil)
	return directory
}

// A new member device with scope on the directory.
func (self *directoryEvsWorld) member(t *testing.T, scope sidecartest.RecordStreamsScope) sidecar.Id {
	t.Helper()
	sidecarId := sidecar.NewId()
	if err := self.world.Grant(self.directoryId, sidecarId, scope); err != nil {
		t.Fatal(err)
	}
	return sidecarId
}

// sidecarId's evs client, made with its record binding on first use.
func (self *directoryEvsWorld) client(sidecarId sidecar.Id) *sidecar.EvsClient {
	self.world.For(sidecarId)
	self.world.stateLock.Lock()
	defer self.world.stateLock.Unlock()
	return self.world.clients[sidecarId]
}

// A binding over client.
func (self *directoryEvsWorld) binding(t *testing.T, client *sidecar.EvsClient, settings *sidecar.DirectoryEvsCardsSettings) *sidecar.DirectoryEvsCards {
	t.Helper()
	cards, err := sidecar.NewDirectoryEvsCards(&sidecar.DirectoryEvsCardsArgs{Client: client, Settings: settings})
	if err != nil {
		t.Fatal(err)
	}
	return cards
}

// One push of count entries to writer's stream, its counters from first, answering the push's slot rows.
func (self *directoryEvsWorld) append(t *testing.T, writer sidecar.Id, first uint64, count int) []*sidecar.RecordSlotRow {
	t.Helper()
	paths := []string{}
	for n := first; n < first+uint64(count); n += 1 {
		path, err := sidecar.RecordStreamPath(n)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	push := recordEvsWorldPush(self.world, writer, paths...)
	if _, err := self.world.For(writer).Append(t.Context(), self.directoryId, push); err != nil {
		t.Fatalf("writer's push: %v", err)
	}
	return push.SlotRows
}

// A notice's path to a fresh repo target, and another request's to the same target.
func directoryEvsNoticePaths(t *testing.T, count int) []string {
	t.Helper()
	target := &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}
	paths := []string{}
	for range count {
		path, err := sidecar.DirectoryNoticePath(target, sidecar.NewId())
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

// Writes content at path by writer's own binding, from ifVersion.
func (self *directoryEvsWorld) put(t *testing.T, writer sidecar.Id, path string, ifVersion uint64, content string) uint64 {
	t.Helper()
	version, err := self.binding(t, self.client(writer), nil).PutCard(t.Context(), self.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: path, IfVersion: ifVersion, Content: []byte(content), AuthPin: self.world.Pin(),
	})
	if err != nil {
		t.Fatalf("a card write: %v", err)
	}
	return version
}

// The reads (POST .../read) and log pages the devices sent so far.
func (self *directoryEvsWorld) requestCounts() (reads int, logs int, writes int) {
	for _, request := range self.world.sent() {
		switch {
		case strings.HasSuffix(request, "/read"):
			reads += 1
		case strings.HasSuffix(request, "/log"):
			logs += 1
		case strings.HasSuffix(request, "/push"):
			writes += 1
		}
	}
	return reads, logs, writes
}

// The moved listing names each ref by its id: every ref with no value, a writer's stream with its writer, the cards
// ref and the repo's push sequence; with the last listing's sequence, only the stream a later push moved; with a value
// evs cannot place, as one from before a restart, or once its head cache lost a ref, every ref again.
func TestDirectoryEvsCardsRefsNamesEachRef(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 3)
	ctx := t.Context()
	for i, writer := range directory.writers {
		directory.append(t, writer, 1, i+1)
	}
	notice := directoryEvsNoticePaths(t, 1)[0]
	directory.put(t, directory.writers[0], notice, 0, "a notice")
	listing, err := directory.cards.Refs(ctx, directory.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !listing.All || listing.Sequence == 0 || listing.Format != 1 {
		t.Fatalf("every ref: all %v, sequence %d, format %d", listing.All, listing.Sequence, listing.Format)
	}
	streams := map[sidecar.Id]uint64{}
	cardsRefs := 0
	for _, ref := range listing.Refs {
		switch ref.Kind {
		case sidecar.DirectoryRefStream:
			streams[ref.WriterSidecarId] = ref.Version
		case sidecar.DirectoryRefCards:
			cardsRefs += 1
			if ref.Version != 1 || ref.Sequence == 0 {
				t.Errorf("the cards ref at %d, sequence %d", ref.Version, ref.Sequence)
			}
		default:
			t.Errorf("a ref of kind %d", ref.Kind)
		}
	}
	if len(streams) != 3 || cardsRefs != 1 {
		t.Fatalf("streams %v, %d cards refs", streams, cardsRefs)
	}
	for _, writer := range directory.writers {
		if streams[writer] != 1 {
			t.Errorf("writer %s's stream at %d", writer, streams[writer])
		}
	}

	sequence := listing.Sequence
	directory.append(t, directory.writers[1], 3, 1)
	moved, err := directory.cards.Refs(ctx, directory.directoryId, sequence)
	if err != nil {
		t.Fatal(err)
	}
	if moved.All || len(moved.Refs) != 1 || moved.Refs[0].Kind != sidecar.DirectoryRefStream ||
		moved.Refs[0].WriterSidecarId != directory.writers[1] || moved.Refs[0].Version != 2 || moved.Sequence <= sequence {
		t.Fatalf("moved after %d: all %v, %d refs, sequence %d", sequence, moved.All, len(moved.Refs), moved.Sequence)
	}
	above, err := directory.cards.Refs(ctx, directory.directoryId, moved.Sequence+1000)
	if err != nil || !above.All || len(above.Refs) != 4 {
		t.Fatalf("a value evs cannot place: %+v %v", above, err)
	}
	if err := directory.world.host.Redis.Delete(ctx, []string{evsservice.HeadCacheKey(directory.directoryId)}); err != nil {
		t.Fatal(err)
	}
	lost, err := directory.cards.Refs(ctx, directory.directoryId, moved.Sequence)
	if err != nil || !lost.All || len(lost.Refs) != 4 {
		t.Fatalf("a lost head cache: %+v %v", lost, err)
	}
}

// Three streams in one request: each version's entries at their counters' paths with the bytes pushed, the push's own
// slot opened to the rows pushed, its chain and pin; again from those versions, nothing, by chains this binding kept;
// a new binding reads from the client's pins, and a new device with neither walks the log to the version it holds.
func TestDirectoryEvsCardsReadStreamsInOneRequest(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 3)
	ctx := t.Context()
	pushedRows := map[sidecar.Id][][]*sidecar.RecordSlotRow{}
	for i, writer := range directory.writers {
		for n := 1; n <= i+1; n += 1 {
			pushedRows[writer] = append(pushedRows[writer], directory.append(t, writer, uint64(n), 1))
		}
	}
	reads := []*sidecar.DirectoryStreamRead{}
	for _, writer := range directory.writers {
		reads = append(reads, &sidecar.DirectoryStreamRead{WriterSidecarId: writer})
	}
	before, beforeLogs, _ := directory.requestCounts()
	answers, err := directory.cards.ReadStreams(ctx, directory.directoryId, reads)
	if err != nil {
		t.Fatal(err)
	}
	if after, afterLogs, _ := directory.requestCounts(); after-before != 1 || afterLogs != beforeLogs {
		t.Fatalf("three streams in %d reads and %d log pages", after-before, afterLogs-beforeLogs)
	}
	pin := directory.world.Pin()
	for i, answer := range answers {
		writer := directory.writers[i]
		if answer.WriterSidecarId != writer || answer.HeadVersion != uint64(i+1) || len(answer.Versions) != i+1 || answer.More || answer.Behind != 0 || answer.ByteCount == 0 {
			t.Fatalf("stream %d: head %d, %d versions, more %v, behind %d", i, answer.HeadVersion, len(answer.Versions), answer.More, answer.Behind)
		}
		for n, version := range answer.Versions {
			path, _ := sidecar.RecordStreamPath(uint64(n + 1))
			if version.Version.Version != uint64(n+1) || len(version.Version.Entries) != 1 || version.Version.Entries[0].Path != path ||
				!bytes.Equal(version.Version.Entries[0].Entry, []byte("entry "+path)) {
				t.Fatalf("stream %d version %d: %+v", i, n+1, version.Version)
			}
			if len(version.Version.Chain) != 32 || version.Version.AuthPin.GetVersion() == 0 || pin.GetVersion() < version.Version.AuthPin.GetVersion() {
				t.Fatalf("stream %d version %d: chain of %d bytes, pin %d", i, n+1, len(version.Version.Chain), version.Version.AuthPin.GetVersion())
			}
			rows := pushedRows[writer][n]
			if version.Slot == nil || version.Slot.SlotId != version.Version.SlotId || len(version.Slot.Rows) != len(rows) {
				t.Fatalf("stream %d version %d's slot: %+v", i, n+1, version.Slot)
			}
			for k, row := range rows {
				if version.Slot.Rows[k].KeyIndex != row.KeyIndex || !bytes.Equal(version.Slot.Rows[k].Row, row.Row) {
					t.Fatalf("stream %d version %d: row %d differs", i, n+1, k)
				}
			}
		}
		reads[i].PinVersion = answer.HeadVersion
	}
	before, _, _ = directory.requestCounts()
	again, err := directory.cards.ReadStreams(ctx, directory.directoryId, reads)
	if err != nil {
		t.Fatal(err)
	}
	for i, answer := range again {
		if len(answer.Versions) != 0 || answer.More || answer.HeadVersion != uint64(i+1) {
			t.Fatalf("stream %d read again from its head: %d versions", i, len(answer.Versions))
		}
	}
	if after, _, _ := directory.requestCounts(); after-before != 1 {
		t.Errorf("a read from the kept chains made %d reads", after-before)
	}

	// a new binding on the same device: the client's pins stand at each head
	before, beforeLogs, _ = directory.requestCounts()
	if _, err := directory.binding(t, directory.reader, nil).ReadStreams(ctx, directory.directoryId, reads); err != nil {
		t.Fatal(err)
	}
	if after, afterLogs, _ := directory.requestCounts(); after-before != 1 || afterLogs != beforeLogs {
		t.Errorf("a read from the pins made %d reads and %d log pages", after-before, afterLogs-beforeLogs)
	}

	// a new device holding version 1 of the third stream, with no pin: its log walked to version 1, then read on
	freshId := directory.member(t, sidecartest.RecordStreamsScope{Read: true})
	fresh := directory.binding(t, directory.world.newClient(freshId, sidecartest.NewFakeStore().Root()), nil)
	_, beforeLogs, _ = directory.requestCounts()
	from, err := fresh.ReadStreams(ctx, directory.directoryId, []*sidecar.DirectoryStreamRead{{WriterSidecarId: directory.writers[2], PinVersion: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if len(from[0].Versions) != 2 || from[0].Versions[0].Version.Version != 2 {
		t.Fatalf("read from version 1: %d versions", len(from[0].Versions))
	}
	if _, afterLogs, _ := directory.requestCounts(); afterLogs-beforeLogs != 1 {
		t.Errorf("the walk to version 1 read %d log pages", afterLogs-beforeLogs)
	}
}

// A stream past one reply's budget answers more, and the next read goes on from where it stopped; the bounds refuse
// before anything is sent.
func TestDirectoryEvsCardsReadStreamsFollowsMore(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 2, func(settings *evsservice.EvsSettings) {
		settings.ReadStreamMaxByteCount = 1
	})
	ctx := t.Context()
	for _, writer := range directory.writers {
		directory.append(t, writer, 1, 1)
		directory.append(t, writer, 2, 1)
	}
	reads := []*sidecar.DirectoryStreamRead{{WriterSidecarId: directory.writers[0]}, {WriterSidecarId: directory.writers[1]}}
	held := map[sidecar.Id]uint64{}
	for request := 0; request < 8 && (held[directory.writers[0]] < 2 || held[directory.writers[1]] < 2); request += 1 {
		answers, err := directory.cards.ReadStreams(ctx, directory.directoryId, reads)
		if err != nil {
			t.Fatal(err)
		}
		for i, answer := range answers {
			for _, version := range answer.Versions {
				if version.Version.Version != held[answer.WriterSidecarId]+1 {
					t.Fatalf("stream %d: version %d after %d", i, version.Version.Version, held[answer.WriterSidecarId])
				}
				held[answer.WriterSidecarId] = version.Version.Version
			}
			if answer.More != (held[answer.WriterSidecarId] < 2) {
				t.Fatalf("stream %d at %d: more %v", i, held[answer.WriterSidecarId], answer.More)
			}
			reads[i].PinVersion = held[answer.WriterSidecarId]
		}
	}
	if held[directory.writers[0]] != 2 || held[directory.writers[1]] != 2 {
		t.Fatalf("read through %v", held)
	}
	tooMany := []*sidecar.DirectoryStreamRead{}
	for range sidecar.DefaultEvsFormatSettings().ReadStreamMaxRefCount + 1 {
		tooMany = append(tooMany, &sidecar.DirectoryStreamRead{WriterSidecarId: sidecar.NewId()})
	}
	before, _, _ := directory.requestCounts()
	for _, refused := range [][]*sidecar.DirectoryStreamRead{nil, tooMany} {
		if _, err := directory.cards.ReadStreams(ctx, directory.directoryId, refused); func() bool {
			code, ok := sidecar.RecordStreamRefusalCode(err)
			return !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
		}() {
			t.Errorf("a read of %d streams: %v", len(refused), err)
		}
	}
	if after, _, _ := directory.requestCounts(); after != before {
		t.Errorf("refused reads sent %d", after-before)
	}
}

// A stream whose pin is older than evs's window answers behind, and the log pages it to its head a page at a time,
// each version as the streams read gives it, the pin raised as far as each page reaches.
func TestDirectoryEvsCardsReadStreamLogPagesBehind(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	writer := directory.writers[0]
	// past the head's 255-entry window
	const pushCount = 260
	for n := 1; n <= pushCount; n += 1 {
		directory.append(t, writer, uint64(n), 1)
	}
	settings := sidecar.DefaultDirectoryEvsCardsSettings()
	settings.LogPageVersionCount = 100
	cards := directory.binding(t, directory.reader, settings)
	answers, err := cards.ReadStreams(ctx, directory.directoryId, []*sidecar.DirectoryStreamRead{{WriterSidecarId: writer}})
	if err != nil {
		t.Fatal(err)
	}
	if answers[0].Behind == 0 || len(answers[0].Versions) != 0 || answers[0].HeadVersion != pushCount {
		t.Fatalf("a pin older than the window: behind %d, %d versions, head %d", answers[0].Behind, len(answers[0].Versions), answers[0].HeadVersion)
	}
	held := uint64(0)
	pages := 0
	for {
		page, err := cards.ReadStreamLog(ctx, directory.directoryId, writer, held)
		if err != nil {
			t.Fatal(err)
		}
		pages += 1
		for _, version := range page.Versions {
			path, _ := sidecar.RecordStreamPath(held + 1)
			if version.Version.Version != held+1 || len(version.Version.Entries) != 1 || version.Version.Entries[0].Path != path ||
				!bytes.Equal(version.Version.Entries[0].Entry, []byte("entry "+path)) || version.Slot == nil || len(version.Slot.Rows) != 1 {
				t.Fatalf("version %d from the log: %+v", held+1, version.Version)
			}
			held = version.Version.Version
		}
		if !page.More {
			if page.HeadVersion != pushCount {
				t.Fatalf("the last page's head %d", page.HeadVersion)
			}
			break
		}
		if page.HeadVersion <= held {
			t.Fatalf("a page ending at %d with more and head %d", held, page.HeadVersion)
		}
	}
	if held != pushCount || pages != 3 {
		t.Fatalf("paged to %d in %d pages", held, pages)
	}
	// the pin stands at the head: a new binding reads on from it with no walk
	_, beforeLogs, _ := directory.requestCounts()
	again, err := directory.binding(t, directory.reader, nil).ReadStreams(ctx, directory.directoryId, []*sidecar.DirectoryStreamRead{{WriterSidecarId: writer, PinVersion: pushCount}})
	if err != nil || len(again[0].Versions) != 0 || again[0].Behind != 0 {
		t.Fatalf("read on from the paged head: %+v %v", again, err)
	}
	if _, afterLogs, _ := directory.requestCounts(); afterLogs != beforeLogs {
		t.Errorf("reading on from the pin read %d log pages", afterLogs-beforeLogs)
	}
}

// The cards ref's statements after a version, in commit order, each file with its path's version, its plaintext
// path and content, and its push's version, signer, pin and time; a removal with the version past the one it removed;
// a page of CardsPageVersionCount statements answering more.
func TestDirectoryEvsCardsReadCardsInCommitOrder(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 2)
	ctx := t.Context()
	writerA, writerB := directory.writers[0], directory.writers[1]
	notices := directoryEvsNoticePaths(t, 2)
	// a path's versions never restart: a creation takes the push's base version + 1 (§11.7's versions row)
	pending := directory.put(t, writerA, notices[0], 0, "pending")
	directory.world.Advance(time.Second)
	decided := directory.put(t, writerA, notices[0], pending, "decided")
	another := directory.put(t, writerA, notices[1], 0, "another")
	if pending != 1 || decided != 2 || another != 3 {
		t.Fatalf("path versions %d, %d, %d", pending, decided, another)
	}
	if err := directory.binding(t, directory.client(writerB), nil).RemoveCard(ctx, directory.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: notices[0], IfVersion: decided, AuthPin: directory.world.Pin(),
	}); err != nil {
		t.Fatal(err)
	}
	changes, err := directory.cards.ReadCards(ctx, directory.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	if changes.HeadVersion != 4 || changes.ThroughVersion != 4 || changes.More || len(changes.Files) != 4 {
		t.Fatalf("head %d, through %d, more %v, %d files", changes.HeadVersion, changes.ThroughVersion, changes.More, len(changes.Files))
	}
	want := []struct {
		path    string
		version uint64
		content string
		removed bool
		signer  sidecar.Id
	}{
		{path: notices[0], version: pending, content: "pending", signer: writerA},
		{path: notices[0], version: decided, content: "decided", signer: writerA},
		{path: notices[1], version: another, content: "another", signer: writerA},
		{path: notices[0], version: decided + 1, removed: true, signer: writerB},
	}
	pin := directory.world.Pin()
	for i, file := range changes.Files {
		if file.Path != want[i].path || file.Version != want[i].version || file.Removed != want[i].removed ||
			string(file.Content) != want[i].content || file.SignerSidecarId != want[i].signer || file.PushVersion != uint64(i+1) {
			t.Fatalf("file %d: %s v%d removed %v %q by %s at %d", i, file.Path, file.Version, file.Removed, file.Content, file.SignerSidecarId, file.PushVersion)
		}
		if file.AuthPin.GetVersion() == 0 || pin.GetVersion() < file.AuthPin.GetVersion() || file.TimeMillis == 0 {
			t.Fatalf("file %d: pin %d, time %d", i, file.AuthPin.GetVersion(), file.TimeMillis)
		}
	}
	if changes.Files[1].TimeMillis <= changes.Files[0].TimeMillis {
		t.Errorf("a later push at %d, the first at %d", changes.Files[1].TimeMillis, changes.Files[0].TimeMillis)
	}
	none, err := directory.cards.ReadCards(ctx, directory.directoryId, 4)
	if err != nil || len(none.Files) != 0 || none.ThroughVersion != 4 || none.More {
		t.Fatalf("after the head: %+v %v", none, err)
	}

	settings := sidecar.DefaultDirectoryEvsCardsSettings()
	settings.CardsPageVersionCount = 3
	paged := directory.binding(t, directory.reader, settings)
	first, err := paged.ReadCards(ctx, directory.directoryId, 0)
	if err != nil || first.ThroughVersion != 3 || !first.More || len(first.Files) != 3 {
		t.Fatalf("a page of three: %+v %v", first, err)
	}
	second, err := paged.ReadCards(ctx, directory.directoryId, 3)
	if err != nil || second.ThroughVersion != 4 || second.More || len(second.Files) != 1 || !second.Files[0].Removed {
		t.Fatalf("the page after: %+v %v", second, err)
	}
}

// A statement rewriting a path created before the version read names it from the copy's paths, handed over before
// the read, else from the listing of the directory above it at the head; a path neither shows, rewritten and removed
// since, is left out, as no file the copy holds.
func TestDirectoryEvsCardsReadCardsNamesWhatNoRowNames(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	writer := directory.writers[0]
	notices := directoryEvsNoticePaths(t, 2)
	first := directory.put(t, writer, notices[0], 0, "first")
	second := directory.put(t, writer, notices[1], 0, "second")
	directory.put(t, writer, notices[1], second, "second, rewritten")
	firstRewritten := directory.put(t, writer, notices[0], first, "first, rewritten")
	if err := directory.binding(t, directory.client(writer), nil).RemoveCard(ctx, directory.directoryId, &sidecar.DirectoryCardWrite{
		PushId: sidecar.NewId(), Path: notices[0], IfVersion: firstRewritten, AuthPin: directory.world.Pin(),
	}); err != nil {
		t.Fatal(err)
	}
	// a copy at version 2 holds both notices; each new binding has learned no row
	seeded := directory.binding(t, directory.reader, nil)
	seeded.KnowCopyPaths(directory.directoryId, notices)
	if !seeded.CopyPathsKnown(directory.directoryId) {
		t.Fatal("the copy's paths are not known")
	}
	before, _, _ := directory.requestCounts()
	fromCopy, err := seeded.ReadCards(ctx, directory.directoryId, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromCopy.Files) != 3 || fromCopy.Files[0].Path != notices[1] || fromCopy.Files[1].Path != notices[0] ||
		!fromCopy.Files[2].Removed || fromCopy.Files[2].Path != notices[0] {
		t.Fatalf("from the copy's paths: %+v", fromCopy.Files)
	}
	// the head and window, the push records, and the slots: no listing
	if after, _, _ := directory.requestCounts(); after-before != 3 {
		t.Errorf("a read from the copy's paths made %d reads", after-before)
	}

	listed := directory.binding(t, directory.reader, nil)
	if listed.CopyPathsKnown(directory.directoryId) {
		t.Fatal("a new binding holds the copy's paths")
	}
	fromListing, err := listed.ReadCards(ctx, directory.directoryId, 2)
	if err != nil {
		t.Fatal(err)
	}
	// the second notice stands at the head, so its directory's listing names it; the first is gone
	if len(fromListing.Files) != 1 || fromListing.Files[0].Path != notices[1] || string(fromListing.Files[0].Content) != "second, rewritten" {
		t.Fatalf("from a listing: %+v", fromListing.Files)
	}
}

// Writes take path CAS as the directory's own writer: a creation over a standing path, a rewrite or removal from a
// version that moved and a removal of nothing are each PATH_CONFLICT; several removals go in one push or not at all;
// a path that is no directory file, and a pin the client does not hold, refuse before anything is sent; and a
// read-only device's write is evs's SCOPE.
func TestDirectoryEvsCardsWritesByPathCas(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	writer := directory.writers[0]
	cards := directory.binding(t, directory.client(writer), nil)
	notices := directoryEvsNoticePaths(t, 3)
	conflict := func(err error) bool {
		code, ok := sidecar.RecordStreamRefusalCode(err)
		return ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT
	}
	write := func(path string, ifVersion uint64, content string) *sidecar.DirectoryCardWrite {
		return &sidecar.DirectoryCardWrite{PushId: sidecar.NewId(), Path: path, IfVersion: ifVersion, Content: []byte(content), AuthPin: directory.world.Pin()}
	}
	created, err := cards.PutCard(ctx, directory.directoryId, write(notices[0], 0, "a"))
	if err != nil || created != 1 {
		t.Fatalf("a creation: %d %v", created, err)
	}
	if _, err := cards.PutCard(ctx, directory.directoryId, write(notices[0], 0, "b")); !conflict(err) {
		t.Errorf("a creation over a standing path: %v", err)
	}
	rewritten, err := cards.PutCard(ctx, directory.directoryId, write(notices[0], created, "c"))
	if err != nil || rewritten != created+1 {
		t.Fatalf("a rewrite: %d %v", rewritten, err)
	}
	if _, err := cards.PutCard(ctx, directory.directoryId, write(notices[0], created, "d")); !conflict(err) {
		t.Errorf("a rewrite from a version that moved: %v", err)
	}
	if err := cards.RemoveCard(ctx, directory.directoryId, write(notices[0], created, "")); !conflict(err) {
		t.Errorf("a removal from a version that moved: %v", err)
	}
	if err := cards.RemoveCard(ctx, directory.directoryId, write(notices[1], 0, "")); !conflict(err) {
		t.Errorf("a removal of nothing: %v", err)
	}
	second := directory.put(t, writer, notices[1], 0, "e")
	third := directory.put(t, writer, notices[2], 0, "f")
	// one stale removal holds back the rest
	if err := cards.RemoveCards(ctx, directory.directoryId, []*sidecar.DirectoryCardWrite{write(notices[1], second, ""), write(notices[2], third+1, "")}); !conflict(err) {
		t.Errorf("removals with one stale: %v", err)
	}
	if err := cards.RemoveCards(ctx, directory.directoryId, []*sidecar.DirectoryCardWrite{write(notices[1], second, ""), write(notices[2], third, "")}); err != nil {
		t.Fatalf("two removals: %v", err)
	}
	changes, err := directory.cards.ReadCards(ctx, directory.directoryId, 0)
	if err != nil {
		t.Fatal(err)
	}
	last := changes.Files[len(changes.Files)-2:]
	if !last[0].Removed || !last[1].Removed || last[0].PushVersion != last[1].PushVersion || last[0].PushVersion != changes.HeadVersion {
		t.Fatalf("the removals' push: %+v", last)
	}

	_, _, before := directory.requestCounts()
	behind := directory.world.Pin()
	ahead := &bridge.AuthPin{Version: behind.GetVersion() + 1, Chain: behind.GetChain()}
	offChain := &bridge.AuthPin{Version: behind.GetVersion(), Chain: bytes.Repeat([]byte{7}, 32)}
	for _, pin := range []*bridge.AuthPin{ahead, offChain} {
		refused := write(directoryEvsNoticePaths(t, 1)[0], 0, "g")
		refused.AuthPin = pin
		if _, err := cards.PutCard(ctx, directory.directoryId, refused); !errors.Is(err, sidecar.ErrEvsStreamPinBehind) {
			t.Errorf("a pin at %d the client does not hold: %v", pin.GetVersion(), err)
		}
	}
	for _, path := range []string{"x/y", ".ur-index/i1/z", "q/ab", ""} {
		if _, err := cards.PutCard(ctx, directory.directoryId, write(path, 0, "h")); func() bool {
			code, ok := sidecar.RecordStreamRefusalCode(err)
			return !ok || code != protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
		}() {
			t.Errorf("a write at %q: %v", path, err)
		}
	}
	if _, _, after := directory.requestCounts(); after != before {
		t.Errorf("refused writes sent %d pushes", after-before)
	}

	// a device that only reads: gkm holds no writable generation for it, so nothing is sealed or sent
	readOnlyId := directory.member(t, sidecartest.RecordStreamsScope{Read: true})
	readOnly := directory.binding(t, directory.client(readOnlyId), nil)
	_, _, before = directory.requestCounts()
	if _, err := readOnly.PutCard(ctx, directory.directoryId, write(directoryEvsNoticePaths(t, 1)[0], 0, "i")); err == nil {
		t.Error("a read-only device's write landed")
	}
	if _, _, after := directory.requestCounts(); after != before {
		t.Errorf("a read-only device's write sent %d pushes", after-before)
	}
}

// Leases land only on a notice prefix or a notice's own path, never on the cards ref, its root, d/ or r/; a lease is
// evs's on the cards ref with that one prefix, and a notice written under it calls back, while one under another
// target in another shard raises no change. evs matches a lease against every change on its branch of the tree, the
// directories above it included (§11.10's match row), so both targets' directories stand before the lease.
func TestDirectoryEvsCardsLeasesNoticePathsOnly(t *testing.T) {
	directory := newDirectoryEvsWorld(t, 1)
	ctx := t.Context()
	writer := directory.writers[0]
	target := &protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}
	prefix, err := sidecar.DirectoryNoticePrefix(target)
	if err != nil {
		t.Fatal(err)
	}
	var otherPrefix string
	for otherPrefix == "" || otherPrefix[:4] == prefix[:4] {
		if otherPrefix, err = sidecar.DirectoryNoticePrefix(&protocol.RequestTarget{RepoId: sidecar.NewId().Bytes()}); err != nil {
			t.Fatal(err)
		}
	}
	directory.put(t, writer, prefix+"00000000000000000000000000000001", 0, "before the lease")
	directory.put(t, writer, otherPrefix+"00000000000000000000000000000001", 0, "before the lease, elsewhere")
	called := make(chan sidecar.Id, 16)
	callback := func(repoId sidecar.Id) { called <- repoId }
	before := directory.world.sent()
	for _, refused := range []string{"", "cards", "q/", "d/", "r/", strings.TrimSuffix(prefix, "/"), prefix + "x/y", sidecar.DirectoryCardPath(writer), "d/ab/" + prefix[5:37]} {
		if _, err := directory.cards.Lease(directory.directoryId, refused, callback); !errors.Is(err, sidecar.ErrDirectoryLeaseRefused) {
			t.Errorf("a lease on %q: %v", refused, err)
		}
	}
	if after := directory.world.sent(); len(after) != len(before) {
		t.Fatalf("refused leases sent %v", after[len(before):])
	}

	// the subscriber's rounds wait on the world's clock itself, which a device clock's waits would move on
	reader := directory.world.newClient(directory.readerId, sidecartest.NewFakeStore().Root(), func(args *sidecar.EvsClientArgs) {
		args.Clock = directory.world.clock
	})
	cards := directory.binding(t, reader, nil)
	directory.world.host.Push.BindSidecar(connect.Id(directory.readerId), connect.Id(directory.world.clientId))
	if err := reader.StartSubscriptions(); err != nil {
		t.Fatal(err)
	}
	changes := make(chan *sidecar.EvsRepoChange, 16)
	removeListener := reader.AddRepoChangeListener(&directory.directoryId, func(change *sidecar.EvsRepoChange) { changes <- change })
	defer removeListener()
	release, err := cards.Lease(directory.directoryId, prefix, callback)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	leases, err := evsservice.ReadLeases(ctx, directory.world.host.Redis, directory.directoryId)
	if err != nil {
		t.Fatal(err)
	}
	cardsRefId, err := reader.Repo(directory.directoryId).RefIdOf(ctx, sidecar.DirectoryCardsRefName())
	if err != nil {
		t.Fatal(err)
	}
	if len(leases) != 1 || leases[0].RefId != cardsRefId || len(leases[0].Prefix) != 3 {
		t.Fatalf("evs's leases: %+v", leases)
	}

	// hints as evs sends them to the reader's client, each delivered once
	delivered := 0
	deliver := func() {
		topic := sidecar.PushTopicEvs(directory.directoryId)
		hints := directory.world.host.Push.Hints(connect.Id(directory.world.clientId))
		for ; delivered < len(hints); delivered += 1 {
			if hints[delivered].Topic == topic {
				reader.ReceiveHint(directory.directoryId, hints[delivered].Version, hints[delivered].Body)
			}
		}
	}
	directory.world.Advance(time.Second)
	directory.put(t, writer, otherPrefix+"00000000000000000000000000000002", 0, "elsewhere")
	directory.world.Advance(time.Second)
	notice, err := sidecar.DirectoryNoticePath(target, sidecar.NewId())
	if err != nil {
		t.Fatal(err)
	}
	directory.put(t, writer, notice, 0, "under the prefix")
	deliver()
	select {
	case repoId := <-called:
		if repoId != directory.directoryId {
			t.Fatalf("a callback for %s", repoId)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no callback for a notice under the prefix")
	}
	// a read raises the changes it brings in version order, so the notice elsewhere, at version 3, raised none: the
	// first change is version 4's, under the prefix, and a read for the second hint may raise it again
	underPrefix := func(change *sidecar.EvsRepoChange) bool {
		return change.RefId == cardsRefId && change.Version == 4 && len(change.Paths) == 1 && change.Paths[0] == strings.TrimSuffix(prefix, "/")
	}
	select {
	case change := <-changes:
		if !underPrefix(change) {
			t.Fatalf("the first change %+v", change)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no change raised")
	}
	for drained := false; !drained; {
		select {
		case change := <-changes:
			if !underPrefix(change) {
				t.Errorf("a later change %+v", change)
			}
		default:
			drained = true
		}
	}
	release()
	release()
}
