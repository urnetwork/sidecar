//go:build !sidecar_http

// EVS1-M6-01 on T2: EvsRepo.ReadStreams and ListRefs against evsservice's POST .../read {refs} and GET
// .../refs?moved_after= on record_evs_test.go's world, every device its own EvsClient. Three writers' streams are read
// in one request, each version's files rebuilt and its new slot carried; a second read from the pins answers nothing;
// a stream past the window answers behind and one past the reply's budget answers more, the next read going on from
// there; a stream whose head does not extend the reader's pin is refused; the moved listing names only the streams a
// commit raised past the value, and every ref for a value before a restart or a head cache that lost a ref. FS-86's
// scale case and its DirectoryCostOracle run are the review phase's (RECORD-M6-24); FS-99's evs half is erase's.

package sidecar_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// A vault with writers, each a member device with rw, and a reader that writes it too, as the directory's daemons are
// writers of their own streams.
type evsStreamsWorld struct {
	world    *recordEvsWorld
	repoId   sidecar.Id
	writers  []sidecar.Id
	readerId sidecar.Id
	reader   *sidecar.EvsClient
}

func newEvsStreamsWorld(t *testing.T, writerCount int, adjust ...func(settings *evsservice.EvsSettings)) *evsStreamsWorld {
	t.Helper()
	world := newRecordEvsWorld(t, adjust...)
	repoId, err := world.NewRepo(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	streams := &evsStreamsWorld{world: world, repoId: repoId}
	for range writerCount {
		writerId := sidecar.NewId()
		if err := world.Grant(repoId, writerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
			t.Fatal(err)
		}
		streams.writers = append(streams.writers, writerId)
	}
	readerId := sidecar.NewId()
	if err := world.Grant(repoId, readerId, sidecartest.RecordStreamsScope{Read: true, Write: true}); err != nil {
		t.Fatal(err)
	}
	streams.readerId = readerId
	streams.reader = world.newClient(readerId, sidecartest.NewFakeStore().Root())
	return streams
}

// Appends one push of count entries to writer's stream, its counters from first. A stream takes one push into each
// directory until question record-m3-12-stream-directory-rows is answered, so each stream here takes one push.
func (self *evsStreamsWorld) append(t *testing.T, writer sidecar.Id, first uint64, count int) {
	t.Helper()
	paths := []string{}
	for n := first; n < first+uint64(count); n += 1 {
		path, err := sidecar.RecordStreamPath(n)
		if err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	if _, err := self.world.For(writer).Append(t.Context(), self.repoId, recordEvsWorldPush(self.world, writer, paths...)); err != nil {
		t.Fatalf("writer's push: %v", err)
	}
}

// The reads of every writer's stream from no pin.
func (self *evsStreamsWorld) reads() []*sidecar.EvsStreamRead {
	reads := []*sidecar.EvsStreamRead{}
	for _, writer := range self.writers {
		reads = append(reads, &sidecar.EvsStreamRead{RefName: sidecar.RecordStreamRefName(writer)})
	}
	return reads
}

// How many streams reads the reader sent.
func (self *evsStreamsWorld) readCount() int {
	count := 0
	for _, request := range self.world.sent() {
		if strings.HasSuffix(request, "/read") {
			count += 1
		}
	}
	return count
}

// Three writers' streams in one request: each stream's version after no pin, each file rebuilt with its entry's
// bytes and the push's own slot carried; read again from those pins, nothing more.
func TestEvsReadStreamsReadsSeveralStreamsInOneRequest(t *testing.T) {
	world := newEvsStreamsWorld(t, 3)
	for i, writer := range world.writers {
		world.append(t, writer, 1, i+1)
	}
	reads := world.reads()
	before := world.readCount()
	answers, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), reads)
	if err != nil {
		t.Fatal(err)
	}
	if world.readCount()-before != 1 {
		t.Fatalf("%d reads for three streams", world.readCount()-before)
	}
	for i, answer := range answers {
		if len(answer.Versions) != 1 || answer.More != 0 || answer.Behind != 0 || answer.Head.GetVersion() != 1 || answer.ByteCount == 0 {
			t.Fatalf("stream %d: %d versions, more %d, behind %d, head %d", i, len(answer.Versions), answer.More, answer.Behind, answer.Head.GetVersion())
		}
		version := answer.Versions[0]
		if len(version.Files) != i+1 {
			t.Fatalf("stream %d: %d files", i, len(version.Files))
		}
		contents := map[string]bool{}
		for _, file := range version.Files {
			contents[string(file.Content)] = true
		}
		for n := 1; n <= i+1; n += 1 {
			path, _ := sidecar.RecordStreamPath(uint64(n))
			if !contents["entry "+path] {
				t.Fatalf("stream %d holds no entry %s", i, path)
			}
		}
		// each entry's chain in a slot of its own, and the push's own slot beside them
		if len(version.Slots) != i+2 {
			t.Fatalf("stream %d: %d slots", i, len(version.Slots))
		}
		reads[i].PinVersion, reads[i].PinChain = version.Version, version.Statement.Chain
	}
	again, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), reads)
	if err != nil {
		t.Fatal(err)
	}
	for i, answer := range again {
		if len(answer.Versions) != 0 || answer.More != 0 {
			t.Fatalf("stream %d read again from its pin: %d versions", i, len(answer.Versions))
		}
	}
}

// Past the reply's budget a stream answers more with its next version, and every stream after it too; reading on from
// there gets the rest, a request serving at least one version whatever its size.
func TestEvsReadStreamsAnswersMoreAtTheBudget(t *testing.T) {
	world := newEvsStreamsWorld(t, 3, func(settings *evsservice.EvsSettings) {
		settings.ReadStreamMaxByteCount = 1
	})
	for _, writer := range world.writers {
		world.append(t, writer, 1, 1)
	}
	reads := world.reads()
	for request := 0; request < len(reads); request += 1 {
		answers, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), reads)
		if err != nil {
			t.Fatal(err)
		}
		for i, answer := range answers {
			switch {
			case i < request:
				if len(answer.Versions) != 0 || answer.More != 0 {
					t.Fatalf("request %d, stream %d read before: %d versions, more %d", request, i, len(answer.Versions), answer.More)
				}
			case i == request:
				if len(answer.Versions) != 1 || answer.More != 0 {
					t.Fatalf("request %d, stream %d: %d versions, more %d", request, i, len(answer.Versions), answer.More)
				}
				reads[i].PinVersion, reads[i].PinChain = answer.Versions[0].Version, answer.Versions[0].Statement.Chain
			default:
				if len(answer.Versions) != 0 || answer.More != 1 {
					t.Fatalf("request %d, stream %d past the budget: %d versions, more %d", request, i, len(answer.Versions), answer.More)
				}
			}
		}
	}
}

// A pin whose chain is not the stream's is refused: the stream does not extend what the reader holds.
func TestEvsReadStreamsRefusesAForkFromThePin(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	world.append(t, world.writers[0], 1, 2)
	reads := world.reads()
	reads[0].PinVersion, reads[0].PinChain = 1, [32]byte{1, 2, 3}
	if _, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), reads); !errors.Is(err, sidecar.ErrEvsChainBroken) && !errors.Is(err, sidecar.ErrEvsHeadForked) {
		t.Fatalf("a forked pin: %v", err)
	}
}

// A request past the bound, or naming a stream twice, is refused before anything is sent.
func TestEvsReadStreamsRefusesItsBounds(t *testing.T) {
	world := newEvsStreamsWorld(t, 1)
	reads := []*sidecar.EvsStreamRead{}
	for range sidecar.DefaultEvsFormatSettings().ReadStreamMaxRefCount + 1 {
		reads = append(reads, &sidecar.EvsStreamRead{RefId: sidecar.NewId()})
	}
	if _, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), reads); !errors.Is(err, sidecar.ErrEvsWriteInvalid) {
		t.Fatalf("past the bound: %v", err)
	}
	twice := world.reads()
	twice = append(twice, twice[0])
	if _, err := world.reader.Repo(world.repoId).ReadStreams(t.Context(), twice); !errors.Is(err, sidecar.ErrEvsWriteInvalid) {
		t.Fatalf("a stream named twice: %v", err)
	}
}

// The moved listing: with no value every ref and All; after another writer's first push, only its stream past the
// sequence the last listing gave; a value above the sequence now, as one from before a restart that went lower, and a
// head cache that lost its hash, each answer every ref.
func TestEvsListRefsMovedAfter(t *testing.T) {
	world := newEvsStreamsWorld(t, 4)
	for _, writer := range world.writers[:3] {
		world.append(t, writer, 1, 1)
	}
	repo := world.reader.Repo(world.repoId)
	listing, err := repo.ListRefs(t.Context(), nil)
	if err != nil || !listing.All || len(listing.Refs) != 3 || listing.PushSequence == 0 {
		t.Fatalf("every ref: %+v %v", listing, err)
	}
	sequence := listing.PushSequence
	world.append(t, world.writers[3], 1, 1)
	moved, err := repo.ListRefs(t.Context(), &sidecar.EvsListRefsArgs{MovedAfter: &sequence})
	if err != nil || moved.All || len(moved.Refs) != 1 || moved.Refs[0].GetPushSequence() <= sequence {
		t.Fatalf("moved after %d: %+v %v", sequence, moved, err)
	}
	streamRefId, err := repo.RefIdOf(t.Context(), sidecar.RecordStreamRefName(world.writers[3]))
	if err != nil || !bytes.Equal(moved.Refs[0].GetRefId(), streamRefId.Bytes()) {
		t.Fatalf("the moved ref is not the last writer's stream: %v", err)
	}
	above := moved.PushSequence + 1000
	all, err := repo.ListRefs(t.Context(), &sidecar.EvsListRefsArgs{MovedAfter: &above})
	if err != nil || !all.All || len(all.Refs) != 4 {
		t.Fatalf("a value past the sequence: %+v %v", all, err)
	}
	latest := moved.PushSequence
	none, err := repo.ListRefs(t.Context(), &sidecar.EvsListRefsArgs{MovedAfter: &latest})
	if err != nil || none.All || len(none.Refs) != 0 {
		t.Fatalf("nothing moved: %+v %v", none, err)
	}
	// the head cache loses its hash: every ref, since evs cannot tell which moved
	if err := world.world.host.Redis.Delete(t.Context(), []string{evsservice.HeadCacheKey(world.repoId)}); err != nil {
		t.Fatal(err)
	}
	lost, err := repo.ListRefs(t.Context(), &sidecar.EvsListRefsArgs{MovedAfter: &latest})
	if err != nil || !lost.All || len(lost.Refs) != 4 {
		t.Fatalf("a lost head cache: %+v %v", lost, err)
	}
}
