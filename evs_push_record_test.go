// A push's record as a replaying reader takes it (evs_push_record.go; QD-839, QD-702): a sealed push's parts are read
// in rounds of EvsSettings.PushPartReadCount, the checked payload the same whatever the round's size, and a count the
// settings leave non-positive reads a part a round; a replayed tree's key and its prefix test, which the config head
// reader names paths by.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The parts each read of the world named, by read, of the reads that named a part.
type evsTestPartRounds struct {
	stateLock sync.Mutex
	rounds    [][]uint32
}

func (self *evsTestPartRounds) see(read *protocol.EvsReadRequest) {
	parts := []uint32{}
	for _, push := range read.GetPushes() {
		if push.GetPart() != 0 {
			parts = append(parts, push.GetPart())
		}
	}
	if len(parts) == 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.rounds = append(self.rounds, parts)
}

func (self *evsTestPartRounds) take() [][]uint32 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	rounds := self.rounds
	self.rounds = nil
	return rounds
}

// 64 parts a read by default; and a push in parts read whole by rounds of the setting, each part asked once and in
// order, the payload equal for every round size.
func TestEvsPushContentReadsPartsInRoundsOfTheSetting(t *testing.T) {
	if count := DefaultEvsSettings().PushPartReadCount; count != 64 {
		t.Fatalf("the default reads %d parts a round, not §11.9's 64", count)
	}
	world := newEvsTestWorld(t)
	// sealed metadata past two parts' room, so the push goes in at least three
	metadata := bytes.Repeat(evsTestBytes("a push in parts", 32), (2*1024*1024+512*1024)/32)
	world.stateLock.Lock()
	world.nextMetadata = metadata
	world.stateLock.Unlock()
	version := world.push(&evsTestChange{path: "a.txt", content: []byte("a\n")})
	world.stateLock.Lock()
	partCount := len(world.commits[version-1].built.Parts)
	world.stateLock.Unlock()
	if partCount < 3 {
		t.Fatalf("CONTROL FAILED: the push went in %d parts", partCount)
	}
	rounds := &evsTestPartRounds{}
	world.stateLock.Lock()
	world.beforeRead = rounds.see
	world.stateLock.Unlock()

	var first *EvsCheckedPayload
	for _, readCount := range []int{64, 2, 1, 0, -3, 1 << 40} {
		reader := world.reader(t, evsTestId("part reader"))
		reader.client.settings.PushPartReadCount = readCount
		repo := reader.client.Repo(world.repoId)
		ctx := context.Background()
		head, err := repo.pinnedHead(ctx, world.refId)
		if err != nil {
			t.Fatal(err)
		}
		statements, err := reader.client.Verifier().Walk(ctx, world.repoId, world.refId, 0, EvsChainStart(world.repoId, world.refId), head.Version)
		if err != nil || uint64(len(statements)) != version {
			t.Fatalf("the walk to %d: %d statements, %v", head.Version, len(statements), err)
		}
		rounds.take()
		payload, err := repo.pushContent(ctx, head, statements[version-1])
		if err != nil {
			t.Fatalf("%d parts a round: %v", readCount, err)
		}
		// what a round may name: the setting, a part a round where it is not positive, never more than the push holds
		roundSize := min(max(1, readCount), partCount)
		asked := []uint32{}
		taken := rounds.take()
		for _, round := range taken {
			if roundSize < len(round) {
				t.Errorf("%d parts a round: a read named %d parts", readCount, len(round))
			}
			asked = append(asked, round...)
		}
		want := []uint32{}
		for part := 1; part <= partCount; part += 1 {
			want = append(want, uint32(part))
		}
		if !slices.Equal(asked, want) || len(taken) != (partCount+roundSize-1)/roundSize {
			t.Errorf("%d parts a round: %d reads asked for parts %v of %d", readCount, len(taken), asked, partCount)
		}
		if !bytes.Equal(payload.SealedMetadata, metadata) {
			t.Errorf("%d parts a round: the payload's sealed metadata is not the push's", readCount)
		}
		if first == nil {
			first = payload
		} else if len(payload.Changes) != len(first.Changes) || len(payload.Changes) != 1 || !bytes.Equal(payload.Changes[0].EntryVersion, first.Changes[0].EntryVersion) {
			t.Errorf("%d parts a round: the payload's changes differ from a whole read's", readCount)
		}
	}
}

// A part evs leaves out of a round is missing, never read as an empty part.
func TestEvsPushContentRefusesAPushWhosePartIsNotServed(t *testing.T) {
	world := newEvsTestWorld(t)
	world.stateLock.Lock()
	world.nextMetadata = bytes.Repeat(evsTestBytes("a push in parts", 32), (2*1024*1024+512*1024)/32)
	world.stateLock.Unlock()
	version := world.push(&evsTestChange{path: "a.txt", content: []byte("a\n")})
	reader := world.reader(t, evsTestId("part reader"))
	repo := reader.client.Repo(world.repoId)
	ctx := context.Background()
	head, err := repo.pinnedHead(ctx, world.refId)
	if err != nil {
		t.Fatal(err)
	}
	statements, err := reader.client.Verifier().Walk(ctx, world.repoId, world.refId, 0, EvsChainStart(world.repoId, world.refId), head.Version)
	if err != nil {
		t.Fatal(err)
	}
	// the statement naming one part more than the push holds, which evs serves no record for
	statement := *statements[version-1]
	signed := *statement.Statement
	push := proto.Clone(signed.Push).(*protocol.EvsPush)
	push.PartCount += 1
	signed.Push = push
	statement.Statement = &signed
	if _, err := repo.pushContent(ctx, head, &statement); !errors.Is(err, ErrEvsObjectMissing) {
		t.Fatalf("a push one of whose parts evs did not serve answered %v", err)
	}
}

// A replayed tree names a path by its names joined with a NUL, and a path is under another when its names begin with
// the other's, name by name, never by a shared prefix of bytes.
func TestEvsExportKeyAndItsPrefix(t *testing.T) {
	names := func(values ...string) [][]byte {
		out := [][]byte{}
		for _, value := range values {
			out = append(out, []byte(value))
		}
		return out
	}
	if key := evsExportKey(names("a", "b")); key != "a\x00b" {
		t.Errorf("the key %q", key)
	}
	if evsExportKey(names("ab")) == evsExportKey(names("a", "b")) || evsExportKey(nil) != "" {
		t.Error("two paths share a key, or the root's is not empty")
	}
	for _, test := range []struct {
		names  [][]byte
		prefix [][]byte
		under  bool
	}{
		{names: names("a", "b"), prefix: names("a"), under: true},
		{names: names("a", "b"), prefix: names("a", "b"), under: true},
		{names: names("a", "b"), prefix: nil, under: true},
		{names: names("a"), prefix: names("a", "b"), under: false},
		{names: names("ab", "c"), prefix: names("a"), under: false},
		{names: names("a", "b"), prefix: names("b"), under: false},
	} {
		if under := evsNamesHavePrefix(test.names, test.prefix); under != test.under {
			t.Errorf("%q under %q: %t", test.names, test.prefix, under)
		}
	}
}
