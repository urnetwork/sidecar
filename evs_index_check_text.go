//go:build !ios_extension

// Checks by hosts with the text (§11.14's coverage row; D-EVS-56; DESIGN-DETAILS 1.2.8, 1.5's deleted-document row and
// 1.7's note for SEARCH-M10-21; QD-209; SEARCH-M10-21): a host holding a ref's text re-extracts each document version a
// writer's push adds, in its own files or in the shards a push past DirectBytes merges them into, and checks each
// tombstone against its path's history; on a mismatch it uses its own result, which its local layer serves in the
// entry's place, and raises index_mismatch {repo, ref, path, signer: the push's}. Indexers do so for every repo they
// read. Every writer of a ref writes its index, so without this an agent could hide a document or plant hits.
//
//	added      an entry of a slot or large entry the push wrote that the version it replaced did not hold, and a row
//	           or tombstone of a shard it wrote that no shard of its partition at its base held as it stands: a push
//	           past DirectBytes merges its entries into the bucket's shards in the push (§11.14's seal row), and its
//	           head holds none of them; what a merge carried over is not judged again
//	live       a full entry of a path's chunk at version v: the path's text at v, extracted as every writer extracts
//	           it, must give that chunk's key set and row, else the host's own entry stands for it
//	deleted    a live entry whose path the content ref holds removed, or at a higher version, at the pin, with no
//	           tombstone or newer entry of it above in the index, is a deleted document indexed (1.5): it alarms, and
//	           the path goes to a backfill, which writes the tombstone or the newer version
//	tombstone  a tombstone of a path's chunk at version v: the path at v must be removed, binary, skipped by D6 or
//	           without that chunk; a chunk the text keeps live is a document hidden, and the host's own entry stands
//	           for it; a version the path never held passes, as a directory removal's or one this device ignores
//	           (DESIGN-DETAILS 16.2.5) may be, but for one above the bound
//	bound      no path version exceeds the effective ref version it commits at (§11.7's versions row, which evs and
//	           replaying readers hold), so an entry of a path's chunk above the effective ref version at the pin is
//	           never honest (QD-1153): a tombstone there over a chunk the text keeps live at the pin is a document
//	           hidden, and a live one is planted as the live row finds it; a content ref that does not give the bound
//	           (indexContentVersionBound) is read as no overlay, its pin the bound
//	omitted    a push that changed its signer's head enters every document the content push beside it changed
//	           (QD-1098): each doc_key the path's text gives at the push's version, extracted as the writer extracts
//	           it (a binary version, a path under the never row and a chunk D6 skips give none) and the erasure set's
//	           documents left out, stands at that version or above, and a path's chunk at or below the bound, in the
//	           signer's files or the buckets' shards; a missing one is a document left out, the host's own entry
//	           stands for it, the path goes to a backfill, and the event names the head the push wrote
//	unknown    a doc_key that no path the host walks names (a registered class's derived document, a chunk of a removed
//	           path past its first) is not judged here
//
// The path in an event is the index file's, which reaches the sink and is never logged (I-13). Not safe for concurrent
// use.
//
// Memory and reads: this draft walks every push of the content ref to its pin and every standing path's doc_keys in
// RAM for each check, the omitted row reads every bucket's entries, its shards decoded, and the added row holds each
// shard the push wrote and the base's shards it is compared with decoded, where an indexer's steady state wants them
// kept between checks and streamed from storage (QD-641).

package sidecar

import (
	"bytes"
	"context"
	"slices"
)

// What a host with the text checks of one writer's push.
type indexTextCheckArgs struct {
	// The index at the push's version, the push's own files among the view's: heads are always fetched.
	view *indexView
	push *indexReproducePush
	// The versions the push replaced, decoded, by path: entries carried over from them are not judged again. Nil
	// judges every entry of the push's files.
	replaced map[string]*indexSlot
	// The shards at the push's base, decoded, by path, of every partition whose shards it wrote, those it replaced or
	// removed among them: a row or tombstone one of them held as it stands is one a merge inside the push carried over,
	// and is not judged again. Nil judges every row and tombstone of each shard the push wrote.
	baseShards map[string]*indexShard
	// The content ref whose documents the entries are of, and the version they are checked at: an in-ref push's own,
	// a companion push's coverage pin.
	content indexContentRef
	pin     uint64
	// K_ref, which every doc_key is a MAC under.
	refKey     []byte
	groupInbox bool
	// index_mismatch's sink; nil drops. The outcome carries each event too.
	events func(event SidecarEvent)
}

// One entry the text did not bear out.
type indexTextMismatch struct {
	// The index file holding the entry.
	path    string
	key     [indexIdByteCount]byte
	version uint64
}

// What one check found.
type indexTextCheckOutcome struct {
	mismatches []*indexTextMismatch
	// The host's own entries for the documents mismatched: its local layer serves them in the entries' place.
	own []*indexEntry
	// Paths whose deleted document a backfill repairs, with its tombstone or newer version.
	repairs []string
	events  []SidecarEvent
	// Entries judged.
	checked int
}

// One added entry and the index file holding it: a slot or large entry of the signer's, or a shard.
type indexTextAdded struct {
	entry *indexEntry
	path  string
}

// A path's chunk.
type indexTextPlace struct {
	path  string
	chunk uint32
}

// What a content ref tells a host with the text of §11.7's bound on its path versions (QD-1153), where it holds an
// overlay: an EvsRepo-backed ref knows its chain of EvsOverlay bases.
type indexContentVersionBound interface {
	// The effective ref version at refVersion, which no path version committed at or below it exceeds: refVersion
	// plus, on an overlay, the base versions along its chain of EvsOverlay bases.
	EffectiveVersion(ctx context.Context, refVersion uint64) (uint64, error)
}

// The entries a push's own files add: every entry of each slot and large entry it wrote that the version it replaced
// did not hold at the same key, version and kind; and every row and tombstone of each shard it wrote that no shard at
// its base held as it stands, the entries a push past DirectBytes merged into its bucket's shards.
func indexTextAddedEntries(ctx context.Context, args *indexTextCheckArgs) ([]*indexTextAdded, error) {
	view, push := args.view, args.push
	written := map[string]bool{}
	for _, file := range push.files {
		written[file.file.path] = true
	}
	type held struct {
		key     [indexIdByteCount]byte
		version uint64
		kind    indexEntryKind
	}
	added := []*indexTextAdded{}
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			writer := bucket.writer(push.signer)
			if writer == nil {
				continue
			}
			for _, file := range slices.Concat(writer.slots, writer.large) {
				if !written[file.file.path] {
					continue
				}
				before := map[held]bool{}
				if slot := args.replaced[file.file.path]; slot != nil {
					for _, entry := range slot.entries {
						before[held{key: entry.key, version: entry.version, kind: entry.kind}] = true
					}
				}
				for _, entry := range file.slot.entries {
					if !before[held{key: entry.key, version: entry.version, kind: entry.kind}] {
						added = append(added, &indexTextAdded{entry: entry, path: file.file.path})
					}
				}
			}
		}
	}

	// a merge carries a row over as it stood, its time, key set and row unchanged, and moves it between the shards of
	// its partition; a row that differs in any of them is the push's own
	carried := map[held][]*indexEntry{}
	for _, shard := range args.baseShards {
		for _, entry := range indexShardEntries(shard) {
			at := held{key: entry.key, version: entry.version, kind: entry.kind}
			carried[at] = append(carried[at], entry)
		}
	}
	carriedOver := func(entry *indexEntry) bool {
		if args.baseShards == nil {
			return false
		}
		for _, before := range carried[held{key: entry.key, version: entry.version, kind: entry.kind}] {
			if before.timeSeconds == entry.timeSeconds && slices.Equal(before.keys, entry.keys) && indexRowsEqual(before.row, entry.row, view.companion) {
				return true
			}
		}
		return false
	}
	for _, root := range view.roots {
		shards := slices.Clone(root.allShards)
		for _, bucket := range root.buckets {
			shards = append(shards, bucket.shards...)
		}
		for _, shard := range shards {
			if !written[shard.file.path] {
				continue
			}
			decoded, err := view.shard(ctx, shard)
			if err != nil {
				return nil, err
			}
			if decoded == nil {
				// a shard that breaks its format, which the view alarms naming its signer
				continue
			}
			for _, entry := range indexShardEntries(decoded) {
				if !carriedOver(entry) {
					added = append(added, &indexTextAdded{entry: entry, path: shard.file.path})
				}
			}
		}
	}
	return added, nil
}

// A shard's rows as full entries and its tombstones as entries of their kinds, as a merge takes them.
func indexShardEntries(shard *indexShard) []*indexEntry {
	entries := make([]*indexEntry, 0, len(shard.documents)+len(shard.tombstones))
	for _, document := range shard.documents {
		entries = append(entries, &indexEntry{
			kind: indexEntryFull, key: document.key, version: document.version, timeSeconds: document.timeSeconds,
			row: document.row, keys: document.keys,
		})
	}
	for _, tombstone := range shard.tombstones {
		entries = append(entries, &indexEntry{kind: tombstone.kind, key: tombstone.key, version: tombstone.version, timeSeconds: tombstone.timeSeconds})
	}
	return entries
}

// Checks push's added entries against the host's text: see the file header.
func indexCheckWithText(ctx context.Context, args *indexTextCheckArgs) (*indexTextCheckOutcome, error) {
	view := args.view
	outcome := &indexTextCheckOutcome{}
	added, err := indexTextAddedEntries(ctx, args)
	if err != nil {
		return nil, err
	}
	committed, err := indexTextContentPush(ctx, args)
	if err != nil {
		return nil, err
	}
	if len(added) == 0 && committed == nil {
		return outcome, nil
	}
	refId := args.content.RefId()
	pushes, err := args.content.Pushes(ctx, 0, args.pin)
	if err != nil {
		return nil, err
	}
	// §11.7's bound on every path version at the pin (QD-1153): a ref that does not give it has no overlay
	bound := args.pin
	if bounded, ok := args.content.(indexContentVersionBound); ok {
		if bound, err = bounded.EffectiveVersion(ctx, args.pin); err != nil {
			return nil, err
		}
	}
	// every doc_key the host can name: each standing path's chunks up to four times its bytes over ChunkByteCount
	// (R3), and chunk 0 of every path a push changed
	places := map[[indexIdByteCount]byte]indexTextPlace{}
	placed := map[string]bool{}
	addPlace := func(path string, chunkCount uint64) error {
		placed[path] = true
		for chunk := uint64(0); chunk < chunkCount; chunk += 1 {
			key, err := indexDocKey(args.refKey, refId, []byte(path), uint32(chunk))
			if err != nil {
				return err
			}
			places[key] = indexTextPlace{path: path, chunk: uint32(chunk)}
		}
		return nil
	}
	err = args.content.Paths(ctx, args.pin, func(path string, byteCount uint64) error {
		return addPlace(path, 4*byteCount/uint64(view.settings.ChunkByteCount)+2)
	})
	if err != nil {
		return nil, err
	}
	pathPushes := map[string][]uint64{}
	for _, push := range pushes {
		for _, change := range push.changes {
			if change.path == "" {
				continue
			}
			pathPushes[change.path] = append(pathPushes[change.path], push.version)
			if !placed[change.path] {
				if err := addPlace(change.path, 1); err != nil {
					return nil, err
				}
			}
		}
	}
	normalizer, err := indexNewNormalizer(indexLinkedTables())
	if err != nil {
		return nil, err
	}
	// a path's state at its entry version v, from the pushes that changed it; nil where it never held v
	stateAt := func(path string, version uint64) (*indexContentState, error) {
		for _, refVersion := range pathPushes[path] {
			state, err := args.content.State(ctx, path, refVersion)
			if err != nil {
				return nil, err
			}
			if state.version == version {
				return state, nil
			}
		}
		return nil, nil
	}
	// the chunks the host's own text gives at a state, keyed: full entries, erased or not
	extract := func(path string, state *indexContentState, timeMs int64) (map[[indexIdByteCount]byte]*indexEntry, error) {
		extractor := &indexBuildExtractor{view: view, normalizer: normalizer, refId: refId, refKey: args.refKey, groupInbox: args.groupInbox, keepErased: true}
		if !state.removed && !state.unopenable {
			if err := extractor.extract(path, state, timeMs); err != nil {
				return nil, err
			}
		}
		entries := map[[indexIdByteCount]byte]*indexEntry{}
		for _, entry := range extractor.entries {
			entries[entry.key] = entry
		}
		return entries, nil
	}
	var held *indexHeldKeys
	// one own entry a document, which two rows may each find mismatched
	ownKeys := map[[indexIdByteCount]byte]bool{}
	mismatchAt := func(filePath string, key [indexIdByteCount]byte, version uint64, own *indexEntry) {
		outcome.mismatches = append(outcome.mismatches, &indexTextMismatch{path: filePath, key: key, version: version})
		if own != nil && !ownKeys[own.key] {
			ownKeys[own.key] = true
			outcome.own = append(outcome.own, own)
		}
		for _, event := range outcome.events {
			if event.Path == filePath {
				return
			}
		}
		repoId, refIdOfView, signer := view.repoId, view.refId, args.push.signer
		event := SidecarEvent{Kind: SidecarEventIndexMismatch, RepoId: &repoId, RefId: &refIdOfView, Path: filePath, SidecarId: &signer}
		outcome.events = append(outcome.events, event)
		if args.events != nil {
			args.events(event)
		}
	}

	mismatch := func(added *indexTextAdded, own *indexEntry) {
		mismatchAt(added.path, added.entry.key, added.entry.version, own)
	}

	for _, one := range added {
		entry := one.entry
		place, named := places[entry.key]
		if !named || entry.kind == indexEntryRefTombstone {
			continue
		}
		outcome.checked += 1
		state, err := stateAt(place.path, entry.version)
		if err != nil {
			return nil, err
		}
		pinState, err := args.content.State(ctx, place.path, args.pin)
		if err != nil {
			return nil, err
		}
		timeMs := int64(entry.timeSeconds) * 1000
		switch entry.kind {
		case indexEntryFull:
			if state == nil || state.removed {
				// the path never held this version live: the entry is planted
				var own *indexEntry
				if pinState.version != 0 && !pinState.removed {
					entries, err := extract(place.path, pinState, timeMs)
					if err != nil {
						return nil, err
					}
					own = entries[entry.key]
				}
				mismatch(one, own)
				continue
			}
			entries, err := extract(place.path, state, timeMs)
			if err != nil {
				return nil, err
			}
			expected := entries[entry.key]
			if expected == nil || !slices.Equal(expected.keys, entry.keys) || !indexRowsEqual(expected.row, entry.row, view.companion) {
				mismatch(one, expected)
				continue
			}
			// a deleted document indexed: removed or newer at the pin, and nothing above this entry in the index
			if pinState.removed || entry.version < pinState.version {
				if held == nil {
					if held, err = indexLoadHeldKeys(ctx, view, view.writeRoot()); err != nil {
						return nil, err
					}
				}
				if newest, ok := held.keyNewests[entry.key]; ok && newest.version <= entry.version {
					mismatch(one, nil)
					outcome.repairs = append(outcome.repairs, place.path)
				}
			}
		case indexEntryTombstone:
			if bound < entry.version {
				// above every version the path can hold at the pin: over a chunk the text keeps live there, a document
				// hidden until the path's version passes it
				if pinState.version == 0 || pinState.removed || pinState.unopenable {
					continue
				}
				entries, err := extract(place.path, pinState, timeMs)
				if err != nil {
					return nil, err
				}
				if live := entries[entry.key]; live != nil {
					mismatch(one, live)
				}
				continue
			}
			if state == nil || state.removed || state.unopenable {
				continue
			}
			entries, err := extract(place.path, state, timeMs)
			if err != nil {
				return nil, err
			}
			if live := entries[entry.key]; live != nil {
				// the text keeps this chunk live at the tombstone's version: a document hidden
				mismatch(one, live)
			}
		}
	}
	// omitted: each document the content push changed, which rode with its signer's head, held to an entry
	if committed != nil {
		entered, enteredWithin, err := indexTextEntered(ctx, view, view.writeRoot(), args.push.signer, bound)
		if err != nil {
			return nil, err
		}
		writtenPath := indexTextWrittenHead(view, args.push)
		for _, change := range committed.changes {
			if change.path == "" || indexCoverageExcluded(view, args.groupInbox, change) {
				continue
			}
			state, err := args.content.State(ctx, change.path, committed.version)
			if err != nil {
				return nil, err
			}
			if state.version == 0 || state.removed || state.unopenable {
				continue
			}
			// as the writer extracts it: what the erasure set lists is left out, as a writer must leave it
			extractor := &indexBuildExtractor{view: view, normalizer: normalizer, refId: refId, refKey: args.refKey, groupInbox: args.groupInbox}
			if err := extractor.extract(change.path, state, args.push.signedTimeMs); err != nil {
				return nil, err
			}
			// a path's chunk is held only by an entry at or below the bound; a registered class's document keeps its
			// own versions, which the bound does not reach
			newests := enteredWithin
			if state.documents != nil {
				newests = entered
			}
			for _, expected := range extractor.entries {
				if version, ok := newests[expected.key]; ok && expected.version <= version {
					continue
				}
				mismatchAt(writtenPath, expected.key, expected.version, expected)
				outcome.repairs = append(outcome.repairs, change.path)
			}
		}
	}
	slices.Sort(outcome.repairs)
	outcome.repairs = slices.Compact(outcome.repairs)
	return outcome, nil
}

// The content push an index push rode with, where it wrote its signer's head in the ref's own index in the same
// statement: the push every document of which the head must enter. Nil for a companion push, whose content is another
// ref's, and for a push that carried no content beside its head.
func indexTextContentPush(ctx context.Context, args *indexTextCheckArgs) (*indexContentPush, error) {
	if args.view.companion || args.push.version == 0 {
		return nil, nil
	}
	pushes, err := args.content.Pushes(ctx, args.push.version-1, args.push.version)
	if err != nil {
		return nil, err
	}
	for _, push := range pushes {
		if push.version == args.push.version && push.changesHead && push.signer == args.push.signer {
			return push, nil
		}
	}
	return nil, nil
}

// The path of the head the push wrote, which a document it left out is named against: its signer's head in a bucket,
// among the files the push wrote, the last bucket's where it wrote several; the first file it wrote where the view
// holds no such head.
func indexTextWrittenHead(view *indexView, push *indexReproducePush) string {
	written := map[string]bool{}
	first := ""
	for _, file := range push.files {
		written[file.file.path] = true
		if first == "" || file.file.path < first {
			first = file.file.path
		}
	}
	head := first
	for _, root := range view.roots {
		for _, bucket := range root.buckets {
			writer := bucket.writer(push.signer)
			if writer == nil {
				continue
			}
			if slot := writer.head(); slot != nil && written[slot.file.path] {
				head = slot.file.path
			}
		}
	}
	return head
}

// The newest version of each doc_key that signer's own files and the buckets' shards hold, live or tombstone, and the
// newest of those at or below bound: where a push's entries stand once it lands, a push past DirectBytes merging its
// own into the shards in the same push.
func indexTextEntered(ctx context.Context, view *indexView, root *indexViewRoot, signer Id, bound uint64) (map[[indexIdByteCount]byte]uint64, map[[indexIdByteCount]byte]uint64, error) {
	entered := map[[indexIdByteCount]byte]uint64{}
	enteredWithin := map[[indexIdByteCount]byte]uint64{}
	for _, bucket := range root.buckets {
		documents, err := view.bucketDocuments(ctx, bucket)
		if err != nil {
			return nil, nil, err
		}
		for key, entries := range documents.entries {
			for _, entry := range entries {
				if entry.kind == indexEntryRefTombstone || !entry.shard && entry.writer != signer {
					continue
				}
				entered[key] = max(entered[key], entry.version)
				if entry.version <= bound {
					enteredWithin[key] = max(enteredWithin[key], entry.version)
				}
			}
		}
	}
	return entered, enteredWithin, nil
}

// Whether two rows encode alike.
func indexRowsEqual(a *indexRow, b *indexRow, companion bool) bool {
	if a == nil || b == nil {
		return a == b
	}
	aBytes, aErr := a.appendEncoded(nil, companion)
	bBytes, bErr := b.appendEncoded(nil, companion)
	return aErr == nil && bErr == nil && bytes.Equal(aBytes, bBytes)
}
