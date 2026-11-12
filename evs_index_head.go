//go:build !ios_extension

// Writer heads (§11.14's slot, seal, large and version rows; D-EVS-46; DESIGN-DETAILS 1.2.3; SEARCH-M10-09 and
// SEARCH-M10-45): what one writer's push writes to the index, a pure function of the writer's own files in each bucket
// it writes, the bucket's manifest row for it, the erasure set, the bucket windows, the push's signed time and the
// documents it carries. It reads no other writer's file and no shard of a bucket it writes.
//
// Each writer appends to a head of its own, its slot with the highest seq, never shared. A head keeps one entry per
// doc_key, a newer one replacing the writer's older one there. When the head cannot take an entry within
// SlotMaxByteCount, the head is sealed as it stands and the next slot becomes the head: the lowest k that is absorbed,
// not the head and not kept, else the lowest unused k. A writer holds at most KeepSlotCount kept slots, for the diffs
// that rest on them, and RingSlotCount others: at a ninth other slot it merges first, or, unable to, takes it and
// alarms; with all 16 in use (the slot paths' k 0 to 15) nothing is written. An entry past SlotEntryMaxByteCount is a
// large entry, alone in a file of its own, and a push whose entries pass PushDirectByteCount puts them straight into
// the bucket's shards, a merge inside that push, and writes its head without them.
//
// The head rule (R2): every push that writes a file of a writer's in a bucket replaces that writer's head there at the
// version the push's base showed, a head sealed as it stood written again with its own bytes, and a writer with no slot
// there given slot 0, empty when every entry is a large entry. So a writer's pushes in a bucket commit one at a time,
// and each finds every file of the writer's as it read them, which is what lets a diff rest on the writer's own files
// (evs_index_dependency.go). The plan removes each of the writer's absorbed large entries that no diff rests on.
//
// One counter a writer a bucket numbers its slots and large entries, so the manifest's absorbed watermark reads as one
// number; a push that numbers anything renumbers the head above it, so the head always holds its writer's highest seq
// and no watermark a merge sets can cover a slot no merge read. Documents go in doc_key order, so a plan is a function
// of its inputs: two devices with one base and one set of documents write the same plaintext, and a 409 replans
// against what it reread.

package sidecar

import (
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// The ref's erasure set was written and does not read, so no builder can know what it may not write: nothing is
	// written until it reads (§11.14's epoch row, fail closed).
	errIndexErasureSetUnreadable = errors.New("index erasure set unreadable")
	// A writer that may not merge holds every one of its slots in the bucket: its entries are not written, and its push
	// stays unindexed until a backfill covers it (§11.14's coverage row).
	errIndexNoFreeSlot = errors.New("index writer has no free slot")
)

// What one writer's push asks of its head.
type indexHeadPlanArgs struct {
	// The index at the push's base, and the root the push writes. The view's settings bound the plan.
	view *indexView
	root *indexViewRoot
	// This writer.
	writer Id
	// The push's signed time_ms, which places its entries and is their time.
	signedTimeMs int64
	// The tables the headers name.
	tables indexTables
	// The documents the push changes, in any order.
	pending []*indexPendingDocument
	// Whether the writer may merge now: desktops, the daemon and indexers; phones only on Wi-Fi while charging
	// (§11.14's devices row).
	mayMerge bool
	// What every slot the push writes carries as coverage: a companion head's, a backfill's or a roll-up runner's. Nil
	// keeps the head's. With no document pending, the head is written for it alone.
	coverage []*protocol.IndexCoverage
}

// A slot or large entry a push writes.
type indexPlannedFile struct {
	path indexPath
	slot *indexSlot
	// Its plaintext.
	file []byte
	// The version it replaces, which its CAS names: 0 creates the path.
	replaces uint64
}

// What a push writes into one bucket.
type indexHeadPlanBucket struct {
	window indexBucketWindow
	// The push opens the bucket, as the first writer into a window does.
	created bool
	// The writer's head after the push.
	head *indexPlannedFile
	// Slots the push writes and leaves sealed: the head it sealed, written again, and slots filled in between.
	sealed []*indexPlannedFile
	// Every slot the push seals, by k.
	sealedSlots []uint32
	large       []*indexPlannedFile
	// The writer's absorbed large entries no diff rests on, which the push removes.
	removed []*indexPushRemoval
	// The entries a merge inside the push takes into the bucket's shards, as full entries, when the plan's
	// mergeInPush is set.
	direct []*indexEntry
}

// What one writer's push writes to the index.
type indexHeadPlan struct {
	// By start day.
	buckets []*indexHeadPlanBucket
	// The push's entries pass PushDirectByteCount: every one goes straight into its bucket's shards as a full entry, a
	// merge inside the push (SEARCH-M10-10's), and the writer's heads there are written without them.
	mergeInPush bool
	// The writer has no free slot and may merge: it merges first, then plans again. Nothing else is set.
	mergeFirst bool
	// The writer took a slot past its RingSlotCount others, unable to merge, which alarms.
	pastRing bool
	// Documents the ref's erasure set lists at or above the version pending, left out.
	erased [][indexIdByteCount]byte
}

// The files the push writes, in path order, each under its path's CAS.
func (self *indexHeadPlan) files() []*indexPushFile {
	files := []*indexPushFile{}
	for _, bucket := range self.buckets {
		planned := slices.Concat(bucket.sealed, bucket.large)
		if bucket.head != nil {
			planned = append(planned, bucket.head)
		}
		for _, file := range planned {
			files = append(files, &indexPushFile{path: file.path.String(), plaintext: file.file, replaces: file.replaces})
		}
	}
	slices.SortFunc(files, func(a *indexPushFile, b *indexPushFile) int {
		return cmp.Compare(a.path, b.path)
	})
	return files
}

// The files the push removes, in path order, each at the version its base showed.
func (self *indexHeadPlan) removals() []*indexPushRemoval {
	removals := []*indexPushRemoval{}
	for _, bucket := range self.buckets {
		removals = append(removals, bucket.removed...)
	}
	slices.SortFunc(removals, func(a *indexPushRemoval, b *indexPushRemoval) int {
		return cmp.Compare(a.path, b.path)
	})
	return removals
}

// One bucket's share of a push: the writer's own files there and its keep set, the documents placed there, and their
// entries as choose made them.
type indexHeadBucketWork struct {
	window  indexBucketWindow
	created bool
	bucket  *indexViewBucket
	// The writer's files in the bucket at the base, nil for none, and its manifest watermark there.
	writer   *indexViewWriter
	absorbed uint32
	keep     map[*indexViewSlot]bool
	pending  []*indexPendingDocument
	entries  []*indexEntry
}

// Plans what one writer's push writes to its root's index at the view's version. Documents the erasure set lists at or
// above their version are left out; an index that is off plans nothing.
func indexPlanHead(ctx context.Context, args *indexHeadPlanArgs) (*indexHeadPlan, error) {
	view, root := args.view, args.root
	settings := view.settings
	if view.erasureSetUnreadable {
		return nil, errIndexErasureSetUnreadable
	}
	plan := &indexHeadPlan{}
	if root.off() {
		return plan, nil
	}
	pushWindow, created := indexBucketFor(root.bucketWindows(), root.windowDays(view.repoKind), args.signedTimeMs)
	timeSeconds := indexEntrySeconds(args.signedTimeMs)

	pending := slices.Clone(args.pending)
	slices.SortFunc(pending, func(a *indexPendingDocument, b *indexPendingDocument) int {
		return cmp.Or(compareIndexKeys(a.key, b.key), cmp.Compare(a.kind, b.kind))
	})
	// A push changes a document once: one entry a key.
	for index := 1; index < len(pending); index += 1 {
		if pending[index].key == pending[index-1].key {
			return nil, indexMalformed("a document twice in one push")
		}
	}

	// D-EVS-45's move: an entry of a document a newer bucket holds goes to the newest of them. No invariant needs it
	// (DESIGN-DETAILS 1.3), so it reads only the newer buckets the view holds.
	newer := []*indexBucketDocuments{}
	for _, bucket := range slices.Backward(root.buckets) {
		if bucket.window.startDay <= pushWindow.startDay {
			break
		}
		documents, err := view.bucketDocuments(ctx, bucket)
		if err != nil {
			return nil, err
		}
		newer = append(newer, documents)
	}
	works := map[uint32]*indexHeadBucketWork{}
	for _, document := range pending {
		if document.kind == indexEntryRefTombstone && !view.companion {
			return nil, indexMalformed("a ref tombstone outside ur/index")
		}
		if view.erased(document.key, document.version) {
			plan.erased = append(plan.erased, document.key)
			continue
		}
		window, windowCreated := pushWindow, created
		for _, documents := range newer {
			if 0 < len(documents.of(document.key)) {
				window, windowCreated = documents.bucket.window, false
				break
			}
		}
		work := works[window.startDay]
		if work == nil {
			work = &indexHeadBucketWork{window: window, created: windowCreated, bucket: root.bucket(window.startDay)}
			if work.bucket != nil {
				work.writer = work.bucket.writer(args.writer)
				work.absorbed = work.bucket.absorbedSeq(args.writer)
			}
			works[window.startDay] = work
		}
		work.pending = append(work.pending, document)
	}
	// A push with no document that carries coverage writes its writer's head in the bucket of its signed time alone:
	// a roll-up's carried horizon rows (DESIGN-DETAILS 1.2.5's step 5) and a companion push that only raises coverage
	// (QD-689's reading 11). The head is written again with its entries and the push's coverage, or slot 0 opens where
	// the writer has none there.
	if len(pending) == 0 && args.coverage != nil {
		work := &indexHeadBucketWork{window: pushWindow, created: created, bucket: root.bucket(pushWindow.startDay)}
		if work.bucket != nil {
			work.writer = work.bucket.writer(args.writer)
			work.absorbed = work.bucket.absorbedSeq(args.writer)
		}
		works[pushWindow.startDay] = work
	}

	starts := []uint32{}
	for start := range works {
		starts = append(starts, start)
	}
	slices.Sort(starts)
	totalByteCount := 0
	for _, start := range starts {
		work := works[start]
		// the keep set as this plan leaves the writer's unabsorbed slots: a head entry the push replaces, or the erasure
		// set drops, no longer counts, and each diff chosen below adds its base
		replaced := map[[indexIdByteCount]byte]bool{}
		for _, document := range work.pending {
			replaced[document.key] = true
		}
		work.keep = map[*indexViewSlot]bool{}
		if work.writer != nil {
			head := work.writer.head()
			work.keep = work.writer.kept(work.absorbed, func(slot *indexViewSlot, entry *indexEntry) bool {
				return slot != head || !(replaced[entry.key] || view.erased(entry.key, entry.version))
			})
		}
		for _, document := range work.pending {
			entry := &indexEntry{kind: document.kind, key: document.key, version: document.version, timeSeconds: timeSeconds}
			if document.kind == indexEntryFull {
				entry.row = document.row
				choice, err := indexChooseEntry(work.writer, work.keep, document, timeSeconds, view.companion, view.erased, settings)
				if err != nil {
					return nil, err
				}
				if choice.diff {
					entry.kind, entry.baseVersion, entry.delta = indexEntryDiff, choice.baseVersion, choice.delta
					work.keep[choice.baseFile] = true
				} else {
					entry.keys = document.keys
				}
			}
			encoded, err := entry.appendEncoded(nil, view.companion)
			if err != nil {
				return nil, err
			}
			totalByteCount += len(encoded)
			work.entries = append(work.entries, entry)
		}
	}

	if settings.PushDirectByteCount < totalByteCount {
		// the push merges its documents itself, as full entries, and writes each head it has without the keys it
		// carried (1.2.3); the merge is SEARCH-M10-10's
		plan.mergeInPush = true
		for _, start := range starts {
			work := works[start]
			planned := &indexHeadPlanBucket{window: work.window, created: work.created}
			plan.buckets = append(plan.buckets, planned)
			for _, document := range work.pending {
				entry := &indexEntry{kind: document.kind, key: document.key, version: document.version, timeSeconds: timeSeconds}
				if document.kind == indexEntryFull {
					entry.row, entry.keys = document.row, document.keys
				}
				planned.direct = append(planned.direct, entry)
			}
			if work.writer == nil || work.writer.head() == nil {
				continue
			}
			head := work.writer.head()
			carried := map[[indexIdByteCount]byte]bool{}
			for _, document := range work.pending {
				carried[document.key] = true
			}
			entries := []*indexEntry{}
			for _, entry := range head.slot.entries {
				if !carried[entry.key] && !view.erased(entry.key, entry.version) {
					entries = append(entries, entry)
				}
			}
			coverage := args.coverage
			if coverage == nil {
				coverage = head.slot.header.Coverage
			}
			header := proto.CloneOf(head.slot.header)
			header.Coverage = coverage
			file, err := indexEncodePlanned(&indexSlot{header: header, entries: entries}, view.companion, settings)
			if err != nil {
				return nil, err
			}
			planned.head = &indexPlannedFile{path: head.path, slot: file.slot, file: file.file, replaces: head.file.version}
		}
		return plan, nil
	}

	for _, start := range starts {
		work := works[start]
		planned := &indexHeadPlanBucket{window: work.window, created: work.created}
		plan.buckets = append(plan.buckets, planned)
		if err := indexPlaceEntries(args, root, work, planned, plan); err != nil {
			return nil, err
		}
		if plan.mergeFirst {
			return &indexHeadPlan{mergeFirst: true}, nil
		}
	}
	return plan, nil
}

// Byte order of two keys.
func compareIndexKeys(a [indexIdByteCount]byte, b [indexIdByteCount]byte) int {
	for index := range a {
		if a[index] != b[index] {
			return cmp.Compare(a[index], b[index])
		}
	}
	return 0
}

// One slot a push fills: its place and what it holds.
type indexOpenSlot struct {
	k        uint32
	replaces uint64
	// The writer's head at the push's base, which keeps its seq unless the push numbers anything.
	old     *indexViewSlot
	entries []*indexEntry
	// The entries' encoded bytes.
	bodyByteCount int
	// It took or lost entries in this push.
	changed bool
}

// Places one bucket's entries: large entries alone, the rest into the writer's head in doc_key order, sealing the head
// as it stands when the next does not fit and opening the next slot, and the head rule over all of it. Sets
// plan.mergeFirst, writing nothing, when no slot is free and the writer may merge.
func indexPlaceEntries(args *indexHeadPlanArgs, root *indexViewRoot, work *indexHeadBucketWork, planned *indexHeadPlanBucket, plan *indexHeadPlan) error {
	view := args.view
	settings := view.settings
	writer, keep := work.writer, work.keep
	pushed := map[[indexIdByteCount]byte]bool{}
	sizes := map[*indexEntry]int{}
	small, large := []*indexEntry{}, []*indexEntry{}
	for _, entry := range work.entries {
		pushed[entry.key] = true
		encoded, err := entry.appendEncoded(nil, view.companion)
		if err != nil {
			return err
		}
		sizes[entry] = len(encoded)
		if settings.SlotEntryMaxByteCount < len(encoded) {
			large = append(large, entry)
		} else {
			small = append(small, entry)
		}
	}

	var head *indexViewSlot
	nextSeq := uint32(1)
	usedSlots := map[uint32]bool{}
	reusable := []*indexViewSlot{}
	// slots in use that no diff rests on, which the ring bounds
	othersInUse := 0
	if writer != nil {
		head = writer.head()
		nextSeq = writer.highestSeq() + 1
		for _, slot := range writer.slots {
			usedSlots[slot.path.slotIndex] = true
			if !keep[slot] {
				othersInUse += 1
			}
			if slot != head && slot.seq() <= work.absorbed && !keep[slot] {
				reusable = append(reusable, slot)
			}
		}
		slices.SortFunc(reusable, func(a *indexViewSlot, b *indexViewSlot) int {
			return cmp.Compare(a.path.slotIndex, b.path.slotIndex)
		})
		for _, file := range writer.large {
			if file.seq() <= work.absorbed && !keep[file] {
				planned.removed = append(planned.removed, &indexPushRemoval{path: file.path.String(), version: file.file.version})
			}
		}
	}
	takeSlot := func() (*indexOpenSlot, error) {
		if 0 < len(reusable) {
			slot := reusable[0]
			reusable = reusable[1:]
			return &indexOpenSlot{k: slot.path.slotIndex, replaces: slot.file.version}, nil
		}
		for k := uint32(0); k < indexWriterSlotCount; k += 1 {
			if usedSlots[k] {
				continue
			}
			if settings.RingSlotCount <= othersInUse {
				if args.mayMerge {
					plan.mergeFirst = true
					return nil, nil
				}
				plan.pastRing = true
			}
			usedSlots[k] = true
			othersInUse += 1
			return &indexOpenSlot{k: k}, nil
		}
		if args.mayMerge {
			plan.mergeFirst = true
			return nil, nil
		}
		return nil, errIndexNoFreeSlot
	}

	coverage := args.coverage
	if coverage == nil && head != nil {
		coverage = head.slot.header.Coverage
	}
	// The widest seq this push can give, so a fill never passes the cap once the real seqs are set.
	probeSeq := nextSeq + uint32(len(work.entries)) + indexWriterSlotCount
	header := func(fileType uint32, seq uint32, coverage []*protocol.IndexCoverage) *protocol.IndexFileHeader {
		header := indexNewFileHeader(fileType, args.tables)
		header.BucketStartDay = planned.window.startDay
		header.BucketDays = planned.window.days
		header.WriterSidecarId = args.writer.Bytes()
		header.Seq = seq
		header.Coverage = coverage
		return header
	}
	// Whether open takes entry within a slot's cap, its header at the widest seq the push can give.
	fits := func(open *indexOpenSlot, entry *indexEntry) (bool, error) {
		byteCount, err := indexSlotByteCount(header(indexFileSlot, probeSeq, coverage), len(open.entries)+1, open.bodyByteCount+sizes[entry])
		if err != nil {
			return false, err
		}
		return byteCount <= settings.SlotMaxByteCount, nil
	}

	var current *indexOpenSlot
	if head != nil {
		current = &indexOpenSlot{k: head.path.slotIndex, replaces: head.file.version, old: head}
		for _, entry := range head.slot.entries {
			if pushed[entry.key] || view.erased(entry.key, entry.version) {
				current.changed = true
				continue
			}
			encoded, err := entry.appendEncoded(nil, view.companion)
			if err != nil {
				return err
			}
			current.entries = append(current.entries, entry)
			current.bodyByteCount += len(encoded)
		}
	}
	sealed := []*indexOpenSlot{}
	for _, entry := range small {
		if current == nil {
			opened, err := takeSlot()
			if err != nil || opened == nil {
				return err
			}
			current = opened
		}
		ok, err := fits(current, entry)
		if err != nil {
			return err
		}
		if !ok {
			sealed = append(sealed, current)
			opened, err := takeSlot()
			if err != nil || opened == nil {
				return err
			}
			current = opened
		}
		current.entries = append(current.entries, entry)
		current.bodyByteCount += sizes[entry]
		current.changed = true
	}
	// the head rule: a writer with no slot in the bucket gets one, empty when every entry is a large entry
	if current == nil {
		opened, err := takeSlot()
		if err != nil || opened == nil {
			return err
		}
		current = opened
	}

	// Seqs: large entries, then slots sealed past the head, then the head above them all. A head the push does not
	// renumber keeps its seq.
	seq := nextSeq
	for _, entry := range large {
		path, err := root.paths.largeEntry(planned.window.startDay, [indexIdByteCount]byte(args.writer), seq)
		if err != nil {
			return err
		}
		file, err := indexEncodePlanned(&indexSlot{header: header(indexFileLargeEntry, seq, nil), entries: []*indexEntry{entry}}, view.companion, settings)
		if err != nil {
			return err
		}
		parsed, _ := indexParsePath(path, view.companion)
		planned.large = append(planned.large, &indexPlannedFile{path: parsed, slot: file.slot, file: file.file})
		seq += 1
	}
	write := func(open *indexOpenSlot, seq uint32) (*indexPlannedFile, error) {
		path, err := root.paths.slot(planned.window.startDay, [indexIdByteCount]byte(args.writer), open.k)
		if err != nil {
			return nil, err
		}
		var slot *indexSlot
		if open.old != nil && !open.changed && seq == open.old.seq() && args.coverage == nil {
			// sealed as it stood: its own bytes again, under its CAS (R2)
			slot = &indexSlot{header: open.old.slot.header, entries: open.old.slot.entries, padByteCount: open.old.slot.padByteCount}
		} else {
			slot = &indexSlot{header: header(indexFileSlot, seq, coverage), entries: open.entries}
		}
		file, err := indexEncodePlanned(slot, view.companion, settings)
		if err != nil {
			return nil, err
		}
		parsed, _ := indexParsePath(path, view.companion)
		return &indexPlannedFile{path: parsed, slot: file.slot, file: file.file, replaces: open.replaces}, nil
	}
	for _, open := range sealed {
		planned.sealedSlots = append(planned.sealedSlots, open.k)
		openSeq := seq
		if open.old != nil {
			openSeq = open.old.seq()
		} else {
			seq += 1
		}
		file, err := write(open, openSeq)
		if err != nil {
			return err
		}
		planned.sealed = append(planned.sealed, file)
	}
	renumbered := seq != nextSeq || len(sealed) != 0 || current.old == nil
	headSeq := seq
	if current.old != nil && !renumbered {
		headSeq = current.old.seq()
	}
	file, err := write(current, headSeq)
	if err != nil {
		return err
	}
	planned.head = file
	return nil
}

// A slot or large entry encoded, and the slot as a reader decodes it.
type indexEncodedSlot struct {
	slot *indexSlot
	file []byte
}

// Encodes a planned slot and decodes it back, so a plan never writes what a reader would refuse, and a caller reads
// the slot as written, its header's count and length set.
func indexEncodePlanned(slot *indexSlot, companion bool, settings *IndexFormatSettings) (*indexEncodedSlot, error) {
	file, err := indexEncodeSlot(slot, companion, settings)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(file)
	written, err := indexDecodeSlot(file, sum[:], companion, settings)
	if err != nil {
		return nil, err
	}
	return &indexEncodedSlot{slot: written, file: file}, nil
}

// The bytes a slot of count entries whose encodings take bodyByteCount comes to under header: the magic, the header's
// length and the header with its count and body length set, and the body.
func indexSlotByteCount(header *protocol.IndexFileHeader, count int, bodyByteCount int) (int, error) {
	header = proto.CloneOf(header)
	header.Count = uint32(count)
	header.BodyLength = uint32(bodyByteCount)
	encoded, err := indexMarshalHeader(header)
	if err != nil {
		return 0, err
	}
	return len(indexFileMagic) + indexVByteLength(uint64(len(encoded))) + len(encoded) + bodyByteCount, nil
}
