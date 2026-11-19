//go:build sidecar_testhooks && !js && !ios && !android && !sdk_mobile_bind

package fault

// FS-108 on T2 (§11.14's tombstones, merges, roll-up and newest rows; owner decision 385's promotion; FI-18, FI-20,
// FI-22; DESIGN-DETAILS 1.8's FS-108; SEARCH-M10-36): deletion masks, searched from a fresh cache on the search world,
// whose store keeps a replaced index version unreadable at once, as the purge leaves it, every search on a fresh phone
// and a fresh desktop holding the world's text held to SearchOracle's set (fs107_test.go's hold).
//
//	removal   D's old version rolled into all; D removed in the current bucket, its head sealed, merged into the
//	          bucket's shards and its slot reused: a fresh phone and desktop find no hit for D's old text before, at
//	          each barrier of and after that bucket's roll-up, which drops all's row and then the tombstone, nothing of
//	          D left in the index
//	variants  the same for a rename, a version turning binary, a version D6's shard test skips and a large file losing
//	          a chunk, each old document's text found nowhere and the renamed one found at its new path
//	skew      two writers' clocks 10 min apart at a bucket boundary leave a newer version, and then a tombstone, in the
//	          older bucket: searches mask the newer bucket's older entry; the older bucket's roll-up writes the
//	          tombstone into the newer bucket's shards, where it masks that entry until that bucket rolls, and then
//	          nothing of the document is left
//	decoder   every file passes the canonical decoder (FI-22 after every step), which refuses a tombstone table out of
//	          order, a key in both of a shard's tables and a tombstone in an all shard, as the index's own decoder does
//	masked    a search returning a removed document's old version fails FI-18
//
// The removal clause also runs on real engines as the row's registered case (fs108.go): an in-ref removal's tombstone
// and a bucket's roll-up through EvsRepo, on T2 here (TestFs108) and on T3 through server's evshost
// (server/fs107_t3_test.go).
//
// Not here, each named for what it waits on: a git ref DELETE's ref tombstone masking every older document of its ref,
// a re-created ref's documents staying, and a late companion entry dropped at the pin with the tombstone's bucket
// already rolled up (the search world is a file-mode ref: both need a companion world over ur/index beside a git-mode
// content ref, with SEARCH-M10-14's journal; IndexCompanion's own tests, TestCompanionDropsASupersededUnit and
// TestCompanionRefDeleteDropsALateEntry, hold the pin's drop on the root's fake); the clauses on real engines past the
// removal (merges, slot reuse, promotion and a device's search over EvsRepo, SEARCH-M10-19's source); and the real
// purge between steps (EVSB-M10-01's PurgeSink.Certain is unwired; the registered case runs evacuation's sweep with
// format2.purge on).

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

// The roll-up's barriers, at each of which a schedule here searches.
func fs108RollUpBarriers() []string {
	return slices.Clone(fs75Barriers)
}

// Steps: runner's roll-up of the oldest expired bucket, which must commit, held at each of its barriers while check
// runs there, and check again once it committed. actor must name no other roll-up of the schedule, since the barriers'
// holds are armed by actor.
func fs108RollUpChecked(world *fsResultsWorld, actor string, runner sidecar.Id, label string, check func(label string) func(ctx context.Context, net *Net) error) []*Step {
	steps := []*Step{{Actor: actor, Action: func(ctx context.Context, net *Net) error {
		result, err := world.index.RollUpResult(ctx, runner)
		if err == nil && result.Version == 0 {
			err = fmt.Errorf("%s: the roll-up committed nothing: %+v", label, result)
		}
		return err
	}, Background: true}}
	for _, barrier := range fs108RollUpBarriers() {
		steps = append(steps,
			&Step{Actor: actor, Await: barrier},
			&Step{Actor: "check", Action: check(label + " at " + barrier)},
			&Step{Release: []string{barrier}},
		)
	}
	return append(steps, &Step{Actor: actor, Join: true}, &Step{Actor: "check", Action: check(label + " after it")})
}

// The world's clock past the expiry of the bucket starting on startDay: past its window and the one after it.
func fs108PastExpiry(world *fsResultsWorld, startDay uint32, days uint32) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		expiry := time.UnixMilli(int64(startDay+2*days) * 24 * 60 * 60 * 1000)
		if now := world.clock.Now(); now.Before(expiry) {
			world.clock.Advance(expiry.Sub(now) + time.Hour)
		}
		return nil
	}
}

// One deletion of FS-108's removal and variants clauses: a path's first version, and the change that masks it.
type fs108Deletion struct {
	path string
	// the first version's text and a term only it holds
	first []byte
	term  string
	// the later change at path, nil for a removal; and a rename's target and text, which holds the term again
	later        []byte
	renamed      string
	renamedText  []byte
	chunkOneTerm string
}

// FS-108's deletions: a removal, a rename, a version turning binary, one D6 skips and a large file losing its second
// chunk. Each first version holds a term of its own, which no later state of the world holds but a rename's target.
func fs108Deletions() []*fs108Deletion {
	const mebibyte = 1024 * 1024
	sentence := "the long tide runs over the flats "
	long := []byte(strings.Repeat(sentence, (3*mebibyte/2)/len(sentence)+1))[:3*mebibyte/2]
	copy(long[mebibyte+100*1024:], " curlewsecond ")
	short := []byte(strings.Repeat(sentence, (mebibyte/2)/len(sentence)+1))[:mebibyte/2]
	return []*fs108Deletion{
		{path: "notes/marten.md", first: []byte("Marten\nmarten martenold\n"), term: "martenold"},
		{
			path: "notes/heron.md", first: []byte("Heron\nheron heronold\n"), term: "heronold",
			renamed: "notes/heron-moved.md", renamedText: []byte("Heron\nheron heronold\n"),
		},
		{
			path: "notes/bittern.md", first: []byte("Bittern\nbittern bitternold\n"), term: "bitternold",
			later: append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte{0, 1, 2, 'b', 'i', 't'}, 400)...),
		},
		{path: "notes/skua.txt", first: []byte("Skua\nskua skuaold\n"), term: "skuaold", later: fs79MixedScriptLetters(7, mebibyte)},
		{path: "notes/curlew.txt", first: long, term: "curlewsecond", later: short, chunkOneTerm: "curlewsecond"},
	}
}

// The changes that mask each deletion's first version.
func fs108Masking(deletions []*fs108Deletion) []*sidecar.SearchTestChange {
	changes := []*sidecar.SearchTestChange{}
	for _, deletion := range deletions {
		switch {
		case deletion.renamed != "":
			changes = append(changes,
				&sidecar.SearchTestChange{Path: deletion.path},
				&sidecar.SearchTestChange{Path: deletion.renamed, Content: deletion.renamedText},
			)
		default:
			changes = append(changes, &sidecar.SearchTestChange{Path: deletion.path, Content: deletion.later})
		}
	}
	return changes
}

// A step: the files at the head hold nothing of a deletion's first version: no entry, row or tombstone of a masked
// document, or of a dropped chunk, but a rename's target's.
func fs108NothingLeft(world *fsResultsWorld, deletions []*fs108Deletion, label string) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		for _, deletion := range deletions {
			chunk := uint32(0)
			if deletion.chunkOneTerm != "" {
				chunk = 1
			}
			held, err := world.index.FilesHolding(deletion.path, chunk)
			if err != nil {
				return err
			}
			if 0 < len(held) {
				return fmt.Errorf("%s: %s's chunk %d is still held: %v", label, deletion.path, chunk, held)
			}
		}
		return nil
	}
}

// FS-108's removal and variants schedule (see the file header), FI-18, FI-20 and FI-22 read after every step.
func fs108RemovalSchedule(t *testing.T, label string) (*Schedule, *fsResultsWorld) {
	world := newFsResultsWorld(t, "fs108 "+label, protocol.RepoKind_REPO_KIND_GENERAL)
	source := world.source("the fs108 world's ref")
	a := searchId("writer a")
	deletions := fs108Deletions()
	queries := []string{"tide"}
	for _, deletion := range deletions {
		queries = append(queries, deletion.term)
	}
	check := func(label string) func(ctx context.Context, net *Net) error {
		return world.checkStep(source, label, queries...)
	}
	var first, current struct {
		startDay, days uint32
	}
	var sealed string
	steps := []*Step{
		{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(source)
			return nil
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			changes := []*sidecar.SearchTestChange{}
			for _, deletion := range deletions {
				changes = append(changes, &sidecar.SearchTestChange{Path: deletion.path, Content: deletion.first})
			}
			_, err := world.commit(ctx, a, changes...)
			return err
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			windows, err := world.index.BucketWindows(ctx)
			if err != nil || len(windows) != 1 {
				return fmt.Errorf("the first push made buckets %v: %v", windows, err)
			}
			first.startDay, first.days = windows[0].StartDay, windows[0].Days
			return nil
		}},
		{Actor: "check", Action: check("the first versions")},
		// the first versions rolled into all
		{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
			return fs108PastExpiry(world, first.startDay, first.days)(ctx, net)
		}},
		{Actor: "indexer", Action: func(ctx context.Context, net *Net) error {
			result, err := world.index.RollUpResult(ctx, searchId("indexer"))
			if err == nil && result.Version == 0 {
				err = fmt.Errorf("the first bucket's roll-up committed nothing: %+v", result)
			}
			if err == nil {
				err = world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), first.startDay)
			}
			return err
		}},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			for _, deletion := range deletions {
				held, err := world.index.FilesHolding(deletion.path, 0)
				if err != nil {
					return err
				}
				if len(held) != 1 || !strings.Contains(held[0].Path, "/a/") || !held[0].Live {
					return fmt.Errorf("after the roll-up %s's first version is in %v, not all alone", deletion.path, held)
				}
			}
			return nil
		}},
		{Actor: "check", Action: check("the first versions in all")},
		// each masked in the current bucket: removed, renamed, binary, skipped, shortened
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			if _, err := world.commit(ctx, a, fs108Masking(deletions)...); err != nil {
				return err
			}
			windows, err := world.index.BucketWindows(ctx)
			if err != nil || len(windows) != 1 || windows[0].StartDay == first.startDay {
				return fmt.Errorf("the masking push made buckets %v: %v", windows, err)
			}
			current.startDay, current.days = windows[0].StartDay, windows[0].Days
			for _, deletion := range deletions {
				chunk := uint32(0)
				if deletion.chunkOneTerm != "" {
					chunk = 1
				}
				held, err := world.index.FilesHolding(deletion.path, chunk)
				if err != nil {
					return err
				}
				tombstone := slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool {
					return !file.Live && strings.Contains(file.Path, "/w/")
				})
				if !tombstone {
					return fmt.Errorf("the masking push left %s's chunk %d without a tombstone in its writer's head: %v", deletion.path, chunk, held)
				}
			}
			return nil
		}},
		{Actor: "check", Action: check("masked in the current bucket's head")},
		// the head sealed, merged into the bucket's shards, and its slot reused
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			var err error
			sealed, err = world.fillUntilSealed(ctx, a, "seal")
			return err
		}},
		{Actor: "check", Action: check("masked in a sealed slot")},
		{Actor: "merger", Action: func(ctx context.Context, net *Net) error {
			merged, err := world.index.Merge(ctx, searchId("merger"), 0)
			if err == nil && merged == 0 {
				err = errors.New("the merge committed nothing")
			}
			if err != nil {
				return err
			}
			held, err := world.index.FilesHolding(deletions[0].path, 0)
			if err != nil {
				return err
			}
			if !slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return !file.Live && strings.Contains(file.Path, "/s/") }) {
				return fmt.Errorf("the merge left the tombstone out of the bucket's shards: %v", held)
			}
			return nil
		}},
		{Actor: "check", Action: check("masked from the bucket's shards")},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			for index := 0; index < 8; index += 1 {
				files, err := world.index.WriterFiles(ctx, a, 0)
				if err != nil {
					return err
				}
				if files.Head == sealed {
					held, err := world.index.FilesHolding(deletions[0].path, 0)
					if err != nil {
						return err
					}
					if slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return file.Path == sealed }) {
						return fmt.Errorf("the reused slot %s still holds the tombstone", sealed)
					}
					return nil
				}
				if _, err := world.fillUntilSealed(ctx, a, fmt.Sprintf("reuse%d", index)); err != nil {
					return err
				}
			}
			return fmt.Errorf("no seal reused the absorbed slot %s", sealed)
		}},
		{Actor: "check", Action: check("masked after the slot's reuse")},
		// the current bucket's roll-up, searched at each barrier
		{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
			return fs108PastExpiry(world, current.startDay, current.days)(ctx, net)
		}},
	}
	steps = append(steps, fs108RollUpChecked(world, "roller", searchId("indexer"), "the masking bucket's roll-up", check)...)
	steps = append(steps,
		&Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			return world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), current.startDay)
		}},
		&Step{Actor: "check", Action: fs108NothingLeft(world, deletions, "after the masking bucket's roll-up")},
		&Step{Actor: "check", Action: check("after the masking bucket's roll-up")},
	)
	schedule := &Schedule{Id: "fs108-" + label, Steps: steps}
	for _, n := range []int{18, 20, 22} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return schedule, world
}

// FS-108's removal and variants clauses: see the file header.
func TestFs108RemovalsUnderTheSearchInvariants(t *testing.T) {
	schedule, _ := fs108RemovalSchedule(t, "removals")
	wantPass(t, runFresh(t, schedule))
}

// FS-108's skew clause (R4's promotion; DESIGN-DETAILS 1.7): writer b's clock 10 min behind writer a's at a bucket
// boundary, b's version 2 and then its tombstone of E, each planned in the older bucket before a's version 1 opened the
// newer one, commit after it; searches mask the newer bucket's older entry; the older bucket's roll-up writes the
// tombstone into the newer bucket's shards, where it masks a's entry until that bucket rolls, after which nothing of E
// is left. FI-18, FI-20 and FI-22 are read after every step.
func fs108SkewSchedule(t *testing.T, label string) *Schedule {
	world := newFsResultsWorld(t, "fs108 "+label, protocol.RepoKind_REPO_KIND_GENERAL)
	world.indexOnly = true
	source := world.source("the fs108 skew world's ref")
	a, b := searchId("writer a"), searchId("writer b")
	const path = "notes/tern.md"
	var older, newer uint32
	var behind, ahead time.Time
	var planned *sidecar.SearchTestPlannedPush
	queries := []string{"tern", "ternone", "terntwo", "filler"}
	check := func(label string) func(ctx context.Context, net *Net) error {
		return world.checkStep(source, label, queries...)
	}
	// the ledger's commits of the index-only pushes here, at its own rising ref versions
	refVersion := uint64(0)
	record := func(at time.Time, writer sidecar.Id, changed string, version uint64, content []byte) error {
		refVersion += 1
		return world.ledger.Commit(&sidecartest.SearchCommit{
			RepoId: world.index.RepoId(), RefId: world.index.RefId(), RefVersion: refVersion, Time: at, WriterId: writer,
			Changes: []*sidecartest.SearchChange{{Path: changed, Version: version, Content: content}}, Indexed: true,
		})
	}
	document := func(version uint64, term string, at time.Time) *sidecar.SearchTestDocument {
		return &sidecar.SearchTestDocument{Path: path, Version: version, Title: "Tern", Text: "tern " + term, Time: at}
	}
	steps := []*Step{
		{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
			SearchRecordOf(net).AddIndex(source)
			return nil
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			now := world.clock.Now()
			filler := &sidecar.SearchTestDocument{Path: "notes/filler.md", Version: 1, Title: "Filler", Text: "filler of the older bucket", Time: now}
			if err := world.index.PushDocuments(ctx, a, now, []*sidecar.SearchTestDocument{filler}); err != nil {
				return err
			}
			if err := record(now, a, filler.Path, 1, []byte(filler.Title+"\n"+filler.Text)); err != nil {
				return err
			}
			older = sidecar.SearchTestBucketStartDay(now)
			boundary := time.UnixMilli(int64(older+30) * 24 * 60 * 60 * 1000)
			world.clock.Advance(boundary.Sub(now) + 5*time.Minute)
			ahead = world.clock.Now()
			behind = ahead.Add(-10 * time.Minute)
			return nil
		}},
		// b's version 2 lands in the older bucket, by b's clock, before any newer bucket stands; the content committed
		// version 1 first, a's, and then 2, so the ledger holds them in that order while their entries race
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			two := document(2, "terntwo", behind)
			if err := world.index.PushDocuments(ctx, b, behind, []*sidecar.SearchTestDocument{two}); err != nil {
				return err
			}
			one := document(1, "ternone", ahead)
			if err := record(ahead, a, path, 1, []byte(one.Title+"\n"+one.Text)); err != nil {
				return err
			}
			return record(behind, b, path, 2, []byte(two.Title+"\n"+two.Text))
		}},
		// b's tombstone of version 3 planned there too, and a's version 1 opening the newer bucket before it commits
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			var err error
			planned, err = world.index.PlanRemovals(ctx, b, behind, []*sidecar.SearchTestDocument{{Path: path, Version: 3}})
			return err
		}},
		{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
			one := document(1, "ternone", ahead)
			return world.index.PushDocuments(ctx, a, ahead, []*sidecar.SearchTestDocument{one})
		}},
		{Actor: "writerB", Action: func(ctx context.Context, net *Net) error {
			if _, err := planned.Commit(ctx); err != nil {
				return err
			}
			if err := record(behind, b, path, 3, nil); err != nil {
				return err
			}
			windows, err := world.index.BucketWindows(ctx)
			if err != nil || len(windows) != 2 {
				return fmt.Errorf("the skewed pushes made buckets %v: %v", windows, err)
			}
			newer = windows[1].StartDay
			held, err := world.index.FilesHolding(path, 0)
			if err != nil {
				return err
			}
			inOlder := fmt.Sprintf("/b/%d/", older)
			inNewer := fmt.Sprintf("/b/%d/", newer)
			if !slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return !file.Live && strings.Contains(file.Path, inOlder) }) ||
				!slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool {
					return file.Live && file.Version == 1 && strings.Contains(file.Path, inNewer)
				}) {
				return fmt.Errorf("the skewed pushes left E in %v", held)
			}
			return nil
		}},
		{Actor: "check", Action: check("a newer version and a tombstone in the older bucket")},
		// the older bucket's roll-up, and not yet the newer one's
		{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
			return fs108PastExpiry(world, older, 30)(ctx, net)
		}},
	}
	steps = append(steps, fs108RollUpChecked(world, "roller", searchId("indexer"), "the older bucket's roll-up", check)...)
	steps = append(steps,
		&Step{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			if err := world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), older); err != nil {
				return err
			}
			held, err := world.index.FilesHolding(path, 0)
			if err != nil {
				return err
			}
			promoted := fmt.Sprintf("/b/%d/s/", newer)
			if !slices.ContainsFunc(held, func(file sidecar.SearchTestHeld) bool { return !file.Live && strings.Contains(file.Path, promoted) }) {
				return fmt.Errorf("the older bucket's roll-up left the tombstone out of the newer bucket's shards: %v", held)
			}
			return nil
		}},
		&Step{Actor: "check", Action: check("the tombstone promoted into the newer bucket")},
		&Step{Actor: "clock", Action: func(ctx context.Context, net *Net) error {
			return fs108PastExpiry(world, newer, 30)(ctx, net)
		}},
		&Step{Actor: "indexer", Action: func(ctx context.Context, net *Net) error {
			result, err := world.index.RollUpResult(ctx, searchId("indexer"))
			if err == nil && result.Version == 0 {
				err = fmt.Errorf("the newer bucket's roll-up committed nothing: %+v", result)
			}
			if err != nil {
				return err
			}
			if err := world.ledger.RolledThrough(world.index.RepoId(), world.index.RefId(), newer); err != nil {
				return err
			}
			held, err := world.index.FilesHolding(path, 0)
			if err != nil {
				return err
			}
			if 0 < len(held) {
				return fmt.Errorf("after the newer bucket's roll-up E is still held: %v", held)
			}
			return nil
		}},
		&Step{Actor: "check", Action: check("after the newer bucket's roll-up")},
	)
	schedule := &Schedule{Id: "fs108-" + label, Steps: steps}
	for _, n := range []int{18, 20, 22} {
		schedule.Check = append(schedule.Check, FI(n))
	}
	return schedule
}

// FS-108's skew clause: see fs108SkewSchedule.
func TestFs108ASkewedTombstoneIsPromotedUnderTheSearchInvariants(t *testing.T) {
	wantPass(t, runFresh(t, fs108SkewSchedule(t, "skew")))
}

// FS-108's decoder clause: SearchOracle's canonical decoder refuses a bucket shard whose tombstone table is out of
// order, one holding a key in both of its tables, and an all shard holding a tombstone, each built from a real shard of
// the world with the oracle's own encoder, and the index's own decoder refuses each too; the real shards pass both.
func TestFs108TheCanonicalDecoderRefusesForgedTables(t *testing.T) {
	world := newFsResultsWorld(t, "fs108 decoder", protocol.RepoKind_REPO_KIND_GENERAL)
	ctx := t.Context()
	a := searchId("writer a")
	settings := DefaultOracleIndexFormatSettings()
	for _, note := range []string{"plover", "dunlin", "sanderling"} {
		if _, err := world.commit(ctx, a, fs79Change("notes/"+note+".md", "Shore\n"+note+" at the tideline")); err != nil {
			t.Fatal(err)
		}
	}
	windows, err := world.index.BucketWindows(ctx)
	if err != nil || len(windows) != 1 {
		t.Fatalf("buckets %v: %v", windows, err)
	}
	if err := fs108PastExpiry(world, windows[0].StartDay, windows[0].Days)(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if rolled, err := world.index.RollUp(ctx, searchId("indexer")); err != nil || rolled == 0 {
		t.Fatalf("the roll-up: %d, %v", rolled, err)
	}
	removed := []*sidecar.SearchTestChange{{Path: "notes/plover.md"}, {Path: "notes/dunlin.md"}}
	if _, err := world.commit(ctx, a, removed...); err != nil {
		t.Fatal(err)
	}
	if _, err := world.fillUntilSealed(ctx, a, "decoder"); err != nil {
		t.Fatal(err)
	}
	if merged, err := world.index.Merge(ctx, searchId("merger"), 0); err != nil || merged == 0 {
		t.Fatalf("the merge: %d, %v", merged, err)
	}
	// the head's newest plaintext of each shard path
	plaintexts := map[string][]byte{}
	for _, push := range world.index.IndexHistory(0) {
		for _, file := range push.Written {
			plaintexts[file.Path] = file.Plaintext
		}
		for _, path := range push.Removed {
			delete(plaintexts, path)
		}
	}
	var bucketPath, allPath string
	var bucketShard, allShard *oracleIndexFile
	for path, plaintext := range plaintexts {
		parsed, ok := oracleIndexParsePath(path, settings)
		if !ok || (parsed.kind != oracleIndexPathBucketShard && parsed.kind != oracleIndexPathAllShard) {
			continue
		}
		decoded, err := oracleIndexDecode(path, plaintext, settings)
		if err != nil {
			t.Fatalf("a real shard does not decode: %v", err)
		}
		if err := sidecar.SearchTestValidateIndexFile(path, plaintext); err != nil {
			t.Fatalf("the index's decoder refuses a real shard %s: %v", path, err)
		}
		switch {
		case parsed.kind == oracleIndexPathBucketShard && 2 <= len(decoded.tombstones) && 0 < len(decoded.documents):
			bucketPath, bucketShard = path, decoded
		case parsed.kind == oracleIndexPathAllShard && 0 < len(decoded.documents):
			allPath, allShard = path, decoded
		}
	}
	if bucketShard == nil || allShard == nil {
		t.Fatalf("no bucket shard with two tombstones and a document, or all shard: %v", slices.Sorted(func(yield func(string) bool) {
			for path := range plaintexts {
				if !yield(path) {
					return
				}
			}
		}))
	}
	frame := func(file *oracleIndexFile, body []byte, documents int, tombstones int) []byte {
		header := proto.CloneOf(file.header)
		header.Count = uint32(documents)
		header.Tombstones = uint32(tombstones)
		framed, err := oracleIndexFrame(header, body, 0)
		if err != nil {
			t.Fatal(err)
		}
		return framed
	}
	tombstoneBytes := func(tombstone *oracleIndexEntry) []byte {
		encoded := append([]byte{tombstone.kind}, tombstone.key[:]...)
		encoded = oracleIndexAppendVByte(encoded, tombstone.version)
		return oracleIndexAppendVByte(encoded, tombstone.timeSeconds)
	}
	// tombstones out of order: no document, so the dictionary is its empty block count
	ordered := slices.Clone(bucketShard.tombstones)
	outOfOrder := append(tombstoneBytes(ordered[1]), tombstoneBytes(ordered[0])...)
	outOfOrder = oracleIndexAppendVByte(outOfOrder, 0)
	// a key in both tables: a document's key as a tombstone beside it
	both, err := oracleIndexShardBody(bucketShard.documents[:1], []*oracleIndexEntry{{
		kind: oracleIndexEntryTombstone, key: bucketShard.documents[0].key, version: bucketShard.documents[0].version + 1,
		timeSeconds: bucketShard.documents[0].timeSeconds,
	}}, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	// a tombstone in an all shard
	inAll, err := oracleIndexShardBody(allShard.documents, []*oracleIndexEntry{ordered[0]}, nil, settings)
	if err != nil {
		t.Fatal(err)
	}
	for _, forged := range []struct {
		name      string
		path      string
		plaintext []byte
		refusal   string
	}{
		{name: "a tombstone table out of order", path: bucketPath, plaintext: frame(bucketShard, outOfOrder, 0, 2), refusal: "tombstones out of order"},
		{name: "a key in both tables", path: bucketPath, plaintext: frame(bucketShard, both, 1, 1), refusal: "a key in both of its tables"},
		{name: "a tombstone in an all shard", path: allPath, plaintext: frame(allShard, inAll, len(allShard.documents), 1), refusal: "not an all shard's"},
	} {
		if _, err := oracleIndexDecode(forged.path, forged.plaintext, settings); err == nil || !strings.Contains(err.Error(), forged.refusal) {
			t.Fatalf("the canonical decoder on %s: %v", forged.name, err)
		}
		if err := sidecar.SearchTestValidateIndexFile(forged.path, forged.plaintext); err == nil {
			t.Fatalf("the index's decoder took %s", forged.name)
		}
	}
}

// FS-108's FI-18 clause: a search on a fresh device that returns the removed document's old version, which the oracle
// holds no live version of, fails FI-18; the honest search beside it passes.
func TestFs108Fi18CatchesARemovedDocumentFound(t *testing.T) {
	for _, mutate := range []bool{false, true} {
		world := newFsResultsWorld(t, fmt.Sprintf("fs108 masked %v", mutate), protocol.RepoKind_REPO_KIND_GENERAL)
		source := world.source("the fs108 masked world's ref")
		a := searchId("writer a")
		var hit sidecar.SearchHit
		steps := []*Step{
			{Actor: "oracle", Action: func(ctx context.Context, net *Net) error {
				SearchRecordOf(net).AddIndex(source)
				return nil
			}},
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				_, err := world.commit(ctx, a, fs79Change("notes/marten.md", "Marten\nmarten martenold"))
				return err
			}},
			{Actor: "phone", Action: func(ctx context.Context, net *Net) error {
				device, err := world.fresh(ctx, searchHostNamed("ios32"), nil)
				if err != nil {
					return err
				}
				defer device.Close()
				found, err := fsResultsRun(ctx, device, "ios32", "martenold", sidecar.SearchAll)
				if err != nil || len(found.all) != 1 {
					return fmt.Errorf("before the removal: %v, %v", found, err)
				}
				hit = found.all[0]
				return nil
			}},
			{Actor: "writerA", Action: func(ctx context.Context, net *Net) error {
				_, err := world.commit(ctx, a, &sidecar.SearchTestChange{Path: "notes/marten.md"})
				return err
			}},
			{Actor: "phone", Action: func(ctx context.Context, net *Net) error {
				device, err := world.fresh(ctx, searchHostNamed("ios32"), nil)
				if err != nil {
					return err
				}
				defer device.Close()
				found, err := fsResultsRun(ctx, device, "ios32", "martenold", sidecar.SearchAll)
				if err != nil {
					return err
				}
				if mutate {
					// the old version returned, as a device that lost the tombstone would
					found.all = append(found.all, hit)
				}
				world.record(net, source, found, "after the removal")
				return nil
			}},
		}
		schedule := &Schedule{Id: "fs108-masked", Steps: steps, Check: []Invariant{FI(18)}}
		result := runFresh(t, schedule)
		if mutate {
			wantFailure(t, result, "the scope holds no live version of it")
		} else {
			wantPass(t, result)
		}
	}
}

// FS-108's registered case on real engines (fs108.go), under every rule §22.8 gives the row.
func TestFs108(t *testing.T) {
	RunRow(t, "FS-108", "", nil)
}
