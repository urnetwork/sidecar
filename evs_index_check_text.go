//go:build !ios_extension

// Checks by hosts with the text (§11.14's coverage row; D-EVS-56; DESIGN-DETAILS 1.5's deleted-document row and 1.7's
// note for SEARCH-M10-21; QD-209; SEARCH-M10-21): a host holding a ref's text re-extracts each document version a
// writer's push adds and checks each tombstone against its path's history; on a mismatch it uses its own result, which
// its local layer serves in the entry's place, and raises index_mismatch {repo, ref, path, signer: the push's}.
// Indexers do so for every repo they read. Every writer of a ref writes its index, so without this an agent could hide
// a document or plant hits.
//
//	live       a full entry, or a diff composed onto its base in the writer's own files, of a path's chunk at version
//	           v: the path's text at v, extracted as every writer extracts it, must give that chunk's key set and row,
//	           else the host's own entry stands for it
//	deleted    a live entry whose path the content ref holds removed, or at a higher version, at the pin, with no
//	           tombstone or newer entry of it above in the index, is a deleted document indexed (1.5): it alarms, and
//	           the path goes to a backfill, which writes the tombstone or the newer version
//	tombstone  a tombstone of a path's chunk at version v: the path at v must be removed, binary, skipped by D6 or
//	           without that chunk; a chunk the text keeps live is a document hidden, and the host's own entry stands
//	           for it
//	unknown    a doc_key that no path the host walks names (a registered class's derived document, a chunk of a removed
//	           path past its first) is not judged here
//
// The path in an event is the index file's, which reaches the sink and is never logged (I-13). Not safe for concurrent
// use.
//
// Memory and reads: this draft walks every push of the content ref to its pin and every standing path's doc_keys in
// RAM for each check, where an indexer's steady state wants them kept between checks (QD-641).

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

// One added entry and the file of the signer's holding it.
type indexTextAdded struct {
	entry  *indexEntry
	file   *indexViewSlot
	writer *indexViewWriter
}

// A path's chunk.
type indexTextPlace struct {
	path  string
	chunk uint32
}

// The entries a push's own files add: every entry of each slot and large entry it wrote that the version it replaced
// did not hold at the same key, version and kind.
func indexTextAddedEntries(view *indexView, push *indexReproducePush, replaced map[string]*indexSlot) []*indexTextAdded {
	written := map[string]bool{}
	for _, file := range push.files {
		written[file.file.path] = true
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
				type held struct {
					key     [indexIdByteCount]byte
					version uint64
					kind    indexEntryKind
				}
				before := map[held]bool{}
				if slot := replaced[file.file.path]; slot != nil {
					for _, entry := range slot.entries {
						before[held{key: entry.key, version: entry.version, kind: entry.kind}] = true
					}
				}
				for _, entry := range file.slot.entries {
					if !before[held{key: entry.key, version: entry.version, kind: entry.kind}] {
						added = append(added, &indexTextAdded{entry: entry, file: file, writer: writer})
					}
				}
			}
		}
	}
	return added
}

// Checks push's added entries against the host's text: see the file header.
func indexCheckWithText(ctx context.Context, args *indexTextCheckArgs) (*indexTextCheckOutcome, error) {
	view := args.view
	outcome := &indexTextCheckOutcome{}
	added := indexTextAddedEntries(view, args.push, args.replaced)
	if len(added) == 0 {
		return outcome, nil
	}
	refId := args.content.RefId()
	pushes, err := args.content.Pushes(ctx, 0, args.pin)
	if err != nil {
		return nil, err
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
	mismatch := func(added *indexTextAdded, own *indexEntry) {
		outcome.mismatches = append(outcome.mismatches, &indexTextMismatch{path: added.file.file.path, key: added.entry.key, version: added.entry.version})
		if own != nil {
			outcome.own = append(outcome.own, own)
		}
		for _, event := range outcome.events {
			if event.Path == added.file.file.path {
				return
			}
		}
		repoId, refIdOfView, signer := view.repoId, view.refId, args.push.signer
		event := SidecarEvent{Kind: SidecarEventIndexMismatch, RepoId: &repoId, RefId: &refIdOfView, Path: added.file.file.path, SidecarId: &signer}
		outcome.events = append(outcome.events, event)
		if args.events != nil {
			args.events(event)
		}
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
		case indexEntryFull, indexEntryDiff:
			keys := entry.keys
			if entry.kind == indexEntryDiff {
				_, base := indexResolveBase(one.writer, entry.key, entry.baseVersion, one.file)
				if base == nil {
					// a diff with no base is index_malformed's, and a backfill re-enters it (§11.14's chains row)
					continue
				}
				if keys, err = entry.delta.applyTo(base.keys); err != nil {
					continue
				}
			}
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
			if expected == nil || !slices.Equal(expected.keys, keys) || !indexRowsEqual(expected.row, entry.row, view.companion) {
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
	slices.Sort(outcome.repairs)
	outcome.repairs = slices.Compact(outcome.repairs)
	return outcome, nil
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
