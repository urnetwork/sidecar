//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-112 on T2 (§11.13's wait row; §11.14's bound and limit rows; §11.12's rekey and reconcile rows; §5.4's erasure
// event; D-EVS-67, FI-13c, FI-19; SEARCH-M10-37): an erasure's wait at the exact storage limit and spent, the eraser
// at evs_closure_bytes_floor, stated from its rekey objects, on the search world under a slot-keyed repo's keys
// (search_erase_testhooks.go), the index's own eraser cutting, rewriting, waiting and estimating.
//
//	message   one admitted message with 5 MiB of text, so five chunk documents, its in-ref push merging them into its
//	          bucket's shards past DirectBytes, each wide chunk in a shard of its own; one chunk copied again a window
//	          later by a late companion push into its writer's large entry, the narrow one left in a slot a merge
//	          absorbed, and the shards' older versions a hold keeps
//	wait      its CUT and first ERASE land at once and its body no longer opens; the eraser counts every closure byte
//	          and upload; the erasure event's finish, from its remaining bytes, its allowance and its 429's
//	          retry_after_ms, names the UTC day and turn at which the last ERASE commits, within one turn of the fake
//	          clock's, the run starting 10 min before 00:00 UTC and the eraser restarting mid-run
//	one       a one-document message with no copy, its eraser's allowance spent that day, completes after the next
//	          00:00 UTC within two turns; below the limit, at once
//	masked    across the run the message stays masked in search from its CUT, and its postings open to key holders only
//	          until their part's ERASE
//
// Not here: the mailbox case, at the later of M10-out and M7-out (the world is a file-mode ref's index under a
// slot-keyed repo's keys, and mail's i/ segment is MAIL-M10-02's); a real backfill's copy of a chunk (the copy here is
// a late companion push's, the other source §11.13's wait row names, since the world's backfill takes every chunk of
// an unindexed push); and FI-13c's stored bytes after the nightly pass, evs's usage (T3).

import (
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/urnetwork/sidecar"
)

// A text of byteCount bytes at most, of BMP letters from the first count two-byte and count three-byte letters,
// two- and three-byte ones with equal odds, drawn from seed: the more letters, the wider a chunk's key set and the
// longer its shard, 4,500 of each filling most of a shard and 6,000 one past it, which D6 skips.
func fs112Text(seed int64, byteCount int, count int) []byte {
	two, three := []rune{}, []rune{}
	for letter := rune(0x80); letter <= 0xFFFF && (len(two) < count || len(three) < count); letter += 1 {
		switch {
		case !unicode.IsLetter(letter):
		case utf8.RuneLen(letter) == 2 && len(two) < count:
			two = append(two, letter)
		case utf8.RuneLen(letter) == 3 && len(three) < count:
			three = append(three, letter)
		}
	}
	random := rand.New(rand.NewSource(seed))
	text := make([]byte, 0, byteCount)
	for {
		letters := three
		if random.Intn(2) == 0 {
			letters = two
		}
		letter := letters[random.Intn(len(letters))]
		if byteCount < len(text)+utf8.RuneLen(letter) {
			return text
		}
		text = utf8.AppendRune(text, letter)
	}
}

// A message of one chunk's worth of text for each of counts' letter counts: five counts, 5 MiB.
func fs112Message(counts []int) []byte {
	chunk := 1024*1024 - 4*1024
	parts := [][]byte{}
	for index, count := range counts {
		parts = append(parts, fs112Text(int64(index+1), chunk, count))
	}
	return bytes.Join(parts, nil)
}

// A phrase that finds chunk index of a message of counts: its first letters.
func fs112Phrase(counts []int, index int) string {
	text := fs112Text(int64(index+1), 64, counts[index])
	phrase := []rune{}
	for _, letter := range string(text) {
		if len(phrase) < 6 {
			phrase = append(phrase, letter)
		}
	}
	return string(phrase)
}

// The run's start: 10 min before the second 00:00 UTC after now, past every staged batch of what came before.
func fs112Start(now time.Time) time.Time {
	return now.UTC().Truncate(24 * time.Hour).Add(48*time.Hour - 10*time.Minute)
}

// writer fills its head with count small documents a push, each its own word, sealing slot after slot: what a merge
// absorbs. They stay out of the ledger: the schedule's searches ask for the message alone.
func (self *fsEraseWorld) fillUnrecorded(t *testing.T, writer sidecar.Id, label string, count int) {
	t.Helper()
	for index := range count {
		document := &sidecar.SearchTestDocument{
			Path: fmt.Sprintf("mail/%s-%d.eml", label, index), Version: 1, Title: "Fill",
			Text: fmt.Sprintf("filler %s marker%04d with enough words to take room in a slot", label, index), Time: self.clock.Now(),
		}
		if err := self.index.PushDocuments(t.Context(), writer, self.clock.Now(), []*sidecar.SearchTestDocument{document}); err != nil {
			t.Fatal(err)
		}
	}
}

// A search for phrase on device finds nothing: the message is masked.
func (self *fsEraseWorld) masked(t *testing.T, device *sidecar.SearchTestDevice, phrase string) {
	t.Helper()
	if hits := self.searchOn(t, device, phrase); 0 < len(hits) {
		t.Fatalf("a search for the erased message's %q found %v", phrase, hits)
	}
}

// FS-112's wait clause, the row's base case on T2: see the file header's message, wait and masked rows.
func TestFs112(t *testing.T) {
	world := newFsEraseWorld(t, "fs112 message", nil)
	ctx := t.Context()
	hooks := newFsEraseHooks(t)
	path := "mail/expedition.eml"
	counts := []int{4500, 4500, 4500, 4500, 3}
	message := fs112Message(counts)
	if chunks, err := world.index.ChunkCount(path, message); err != nil || chunks != 5 {
		t.Fatalf("the 5 MiB message is %d chunk documents, %v", chunks, err)
	}
	w, x, y := searchId("writer w"), searchId("writer x"), searchId("writer y")
	commit, err := world.index.CommitIndexedMerging(ctx, w, world.clock.Now(), []*sidecar.SearchTestChange{{Path: path, Content: message}})
	if err != nil {
		t.Fatal(err)
	}
	version := commit.Versions[path]
	erased := []*fsErased{}
	for chunk := range uint32(5) {
		key, err := world.index.DocKeyOf(path, chunk)
		if err != nil {
			t.Fatal(err)
		}
		erased = append(erased, &fsErased{path: path, key: key, version: version})
	}
	live, err := world.index.LiveDocKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for chunk, document := range erased {
		if live[document.key] != version {
			t.Fatalf("chunk %d of the message is not in the index: D6 skipped it", chunk)
		}
	}
	shards := 0
	for _, file := range world.index.Files() {
		if fsIndexPathIsMerged(file.Path) && !strings.HasSuffix(file.Path, "/m") {
			shards += 1
		}
	}
	if shards < 4 {
		t.Fatalf("the message's push wrote %d shards, not one a wide chunk", shards)
	}

	// a hold keeps the shards as they stand; the narrow chunk's copy in a slot a merge absorbs, which rewrites them
	world.erasure.SetHold(true)
	if _, err := world.index.PushChunks(ctx, y, world.clock.Now(), path, version, message, []uint32{4}); err != nil {
		t.Fatal(err)
	}
	world.fillUnrecorded(t, y, "seal", 160)
	if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	// a window later, a late companion push copies chunk 0 into its writer's large entry
	world.clock.Advance(31 * 24 * time.Hour)
	if _, err := world.index.PushChunks(ctx, x, world.clock.Now(), path, version, message, []uint32{0}); err != nil {
		t.Fatal(err)
	}
	holding, err := world.erasure.Holding(fsCutDocuments(erased))
	if err != nil {
		t.Fatal(err)
	}
	standing, held, slotted := 0, 0, 0
	for _, version := range holding {
		switch {
		case version.Live && strings.Contains(version.Path, "/w/"):
			slotted += 1
		case version.Live:
			standing += 1
		case version.Held:
			held += 1
		}
	}
	// the bucket's shards, a shard a wide chunk; the narrow chunk's absorbed slot and chunk 0's copy in its writer's
	// large entry; the shards' versions the hold kept
	if standing < 4 || held == 0 || slotted < 2 {
		t.Fatalf("the message's copies: %d live shards, %d held versions, %d writers' files", standing, held, slotted)
	}

	// the run starts 10 min before 00:00 UTC, the network at the limit and spent
	world.clock.Advance(fs112Start(world.clock.Now()).Sub(world.clock.Now()))
	phrases := []string{fs112Phrase(counts, 0), fs112Phrase(counts, 2), fs112Phrase(counts, 4)}
	daemon := world.syncedDevice(t, "desktop")
	world.atTheLimit()
	start := world.clock.Now()
	erasureId := searchId("fs112 erasure")
	world.cut(t, world.eraser(t, sidecar.Id{}, nil), erasureId, erased)
	if err := world.erasure.EraseOwnKeys(ctx, world.index.AdminId(), erasureId, []string{path}, false); err != nil {
		t.Fatal(err)
	}
	if world.erasure.ContentOpens(path) || !world.clock.Now().Equal(start) {
		t.Fatal("the CUT and the first ERASE did not land at once")
	}
	for _, phrase := range phrases {
		world.masked(t, daemon, phrase)
	}

	parts := newFs78Parts(hooks, world.erasure)
	events := []sidecar.SidecarErasure{}
	waits := world.rewriteAtTheLimit(t, sidecar.Id{}, erasureId, 1, &events, func(waiting sidecar.SidecarErasure) {
		for _, phrase := range phrases {
			world.masked(t, daemon, phrase)
		}
	})
	hooks.onBarrier = nil
	if err := parts.err(); err != nil {
		t.Fatal(err)
	}
	if len(waits) == 0 {
		byteCount, uploads, staged := world.erasure.ClosureCounts()
		t.Fatalf("the erasure at the floor never waited: %d B, %d uploads, %d staged, %v", byteCount, uploads, staged, world.erasure.Rewritten())
	}
	erases := world.erasure.Erases()
	last := erases[len(erases)-1].At
	turn := sidecar.DefaultIndexEraseSettings().PacingTurn
	for index, waiting := range waits {
		if waiting.Finish.IsZero() || turn < last.Sub(waiting.Finish).Abs() {
			t.Fatalf("wait %d's finish %v, the last ERASE at %v", index, waiting.Finish, last)
		}
	}
	if !last.After(start.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)) {
		t.Fatalf("the last ERASE at %v did not wait for the 00:00 UTC after %v", last, start)
	}

	// the eraser counted every closure byte and upload the store took
	byteCount, uploads, staged := world.erasure.ClosureCounts()
	t.Logf("%d closure bytes in %d uploads and %d staged records from %v, %d waits, the first's finish %v, the last ERASE at %v", byteCount, uploads, staged, start, len(waits), waits[0].Finish, last)
	first := events[0]
	if first.State != sidecar.SidecarErasureRewriting || first.BytesLeft != byteCount || first.ObjectsLeft != int64(uploads+staged) {
		t.Fatalf("the first event %+v; the CLOSUREs took %d B in %d uploads and %d staged records", first, byteCount, uploads, staged)
	}

	if err := fsEraseSweep(world.erasure, erased, true); err != nil {
		t.Fatal(err)
	}
	for _, phrase := range phrases {
		world.masked(t, daemon, phrase)
	}
	world.fsEraseFreshDevice(t, world.erasure, erased, phrases)
}

// A one-document message with no copy, in its writer's slot and its bucket's shard: its erasure at the limit, its
// eraser's allowance spent that day, completes after the next 00:00 UTC within two turns; below the limit, at once.
func TestFs112AOneDocumentMessageCompletesAfterTheNextMidnight(t *testing.T) {
	for _, atLimit := range []bool{true, false} {
		world := newFsEraseWorld(t, fmt.Sprintf("fs112 one %t", atLimit), nil)
		ctx := t.Context()
		w := searchId("writer w")
		message := fsIndexDocument("mail/kite.eml", 1, "kite", world.clock.Now())
		world.fillUnrecorded(t, searchId("writer s"), "seal", 160)
		world.push(t, w, message)
		if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
			t.Fatalf("the merge: %d, %v", merged, err)
		}
		world.clock.Advance(fs112Start(world.clock.Now()).Sub(world.clock.Now()))
		if atLimit {
			world.atTheLimit()
			// the eraser's allowance is spent today
			world.erasure.SpendClosureAllowance(sidecar.Id{}, fs78ClosureBytesFloor)
		}
		start := world.clock.Now()
		erased := []*fsErased{fsErasedOf(t, world.searchWorld, message.Path, 1)}
		erasureId := searchId("fs112 one erasure")
		world.cut(t, world.eraser(t, sidecar.Id{}, nil), erasureId, erased)
		if err := world.erasure.EraseOwnKeys(ctx, world.index.AdminId(), erasureId, []string{message.Path}, false); err != nil {
			t.Fatal(err)
		}
		waits := world.rewriteAtTheLimit(t, sidecar.Id{}, erasureId, 0, nil, nil)
		erases := world.erasure.Erases()
		last := erases[len(erases)-1].At
		midnight := start.UTC().Truncate(24 * time.Hour).Add(24 * time.Hour)
		turn := sidecar.DefaultIndexEraseSettings().PacingTurn
		switch {
		case atLimit && (len(waits) != 1 || last.Before(midnight) || midnight.Add(2*turn).Before(last)):
			t.Fatalf("at the limit the last ERASE at %v after %d waits, not within two turns of %v", last, len(waits), midnight)
		case !atLimit && (0 < len(waits) || !last.Equal(start)):
			t.Fatalf("below the limit the last ERASE at %v after %d waits, not at once at %v", last, len(waits), start)
		}
		if err := fsEraseSweep(world.erasure, erased, false); err != nil {
			t.Fatal(err)
		}
		world.checkSearch(t, "kite")
	}
}
