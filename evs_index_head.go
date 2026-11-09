// Writer heads (§11.14's slot, seal, large and version rows; D-EVS-46; SEARCH-M10-09): what one writer's push writes to
// the index, as a pure function of the index at the push's base. Each writer appends to a head of its own, its slot
// with the highest seq, never shared, so disjoint pushes never meet on one file. A head keeps one entry per doc_key, a
// newer one replacing the writer's older one there. When the head cannot take an entry within 16,208 B, the head is
// sealed as it stands and the next slot becomes the head: the lowest k whose seq the bucket's manifest shows absorbed,
// else a new k up to 8; with none free the writer merges first or, unable to, takes up to 16 slots and alarms. An entry
// over 8 KiB is a large entry, alone in a file of its own, and a push whose entries pass 256 KiB puts them straight
// into the bucket's shards, a merge inside that push. Sealing happens only there, never on idle.
//
// One counter a writer a bucket numbers its slots and large entries, so the manifest's absorbed watermark reads as one
// number; a push that numbers anything renumbers the head above it, so the head always holds its writer's highest seq
// and no watermark a merge sets can cover a slot no merge read.
//
// Entries are chosen against the bucket at the push's base (evs_index_dependency.go), documents in doc_key order, so a
// plan is a function of its inputs: two devices with one base and one set of documents write the same plaintext, and
// a 409 replans against what it reread.

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

// A push's entries past this go straight into the bucket's shards (§11.14's seal row).
const indexPushDirectByteCount = 256 * 1024

// Slots a writer holds in a bucket before it must merge (§11.14's seal row); past them, a writer that cannot merge
// takes up to indexWriterSlotCount and alarms.
const indexWriterRingSlotCount = 8

var (
	// The ref's erasure set was written and does not read, so no builder can know what it may not write: nothing is
	// written until it reads (§11.14's epoch row, fail closed).
	errIndexErasureSetUnreadable = errors.New("index erasure set unreadable")
	// A writer that may not merge holds all 16 of its slots in the bucket: its entries are not written, and its push
	// stays unindexed until a backfill covers it (§11.14's coverage row).
	errIndexNoFreeSlot = errors.New("index writer has no free slot")
)

// What one writer's push asks of its head.
type indexHeadPlanArgs struct {
	// The index at the push's base, and the root the push writes.
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
	// What every slot the push writes carries as coverage: a companion head's or a backfill's. Nil keeps the head's.
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
	// The writer's head after the push, nil where the push leaves it as it was.
	head *indexPlannedFile
	// Slots the push writes and leaves sealed: a head that took entries before it filled, and slots filled in between.
	sealed []*indexPlannedFile
	// Every slot the push seals, by k, whether it rewrites it or a new head above it is all the seal writes.
	sealedSlots []uint32
	large       []*indexPlannedFile
	// The entries a merge inside the push takes into the bucket's shards, when the plan's mergeInPush is set.
	direct []*indexEntry
}

// What one writer's push writes to the index.
type indexHeadPlan struct {
	// By start day.
	buckets []*indexHeadPlanBucket
	// The push's entries pass 256 KiB: every one goes straight into its bucket's shards, a merge inside the push, and
	// no slot is written.
	mergeInPush bool
	// The writer has no free slot and may merge: it merges first, then plans again. Nothing else is set.
	mergeFirst bool
	// The writer took a slot past its 8, unable to merge, which alarms.
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

// Plans what one writer's push writes to its root's index at the view's version. Documents the erasure set lists at or
// above their version are left out; an index that is off plans nothing.
func indexPlanHead(ctx context.Context, args *indexHeadPlanArgs) (*indexHeadPlan, error) {
	view, root := args.view, args.root
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

	// Buckets newer than the push's own, newest first, each with its documents: an entry of a document one of them
	// holds goes to the newest of them.
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
	type bucketWork struct {
		window  indexBucketWindow
		created bool
		bucket  *indexViewBucket
		pending []*indexPendingDocument
		entries []*indexEntry
	}
	works := map[uint32]*bucketWork{}
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
			work = &bucketWork{window: window, created: windowCreated, bucket: root.bucket(window.startDay)}
			works[window.startDay] = work
		}
		work.pending = append(work.pending, document)
	}

	starts := []uint32{}
	for start := range works {
		starts = append(starts, start)
	}
	slices.Sort(starts)
	newest := root.newestBucket()
	totalByteCount := 0
	for _, start := range starts {
		work := works[start]
		var documents *indexBucketDocuments
		if work.bucket != nil {
			var err error
			if documents, err = view.bucketDocuments(ctx, work.bucket); err != nil {
				return nil, err
			}
		}
		current := work.created || (newest != nil && work.bucket == newest)
		for _, document := range work.pending {
			entry := &indexEntry{kind: document.kind, key: document.key, version: document.version, timeSeconds: timeSeconds}
			if document.kind == indexEntryFull {
				entry.row = document.row
				choice := indexChooseEntry(documents, current, args.writer, document, view.erased)
				if choice.diff {
					entry.kind, entry.baseVersion, entry.delta = indexEntryDiff, choice.baseVersion, choice.delta
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

	for _, start := range starts {
		work := works[start]
		planned := &indexHeadPlanBucket{window: work.window, created: work.created}
		plan.buckets = append(plan.buckets, planned)
		if indexPushDirectByteCount < totalByteCount {
			plan.mergeInPush = true
			planned.direct = work.entries
			continue
		}
		var writer *indexViewWriter
		if work.bucket != nil {
			writer = work.bucket.writer(args.writer)
		}
		if err := indexPlaceEntries(args, root, work.bucket, writer, planned, work.entries, plan); err != nil {
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
	// It took or lost entries in this push, so it is written.
	changed bool
}

// Places one bucket's entries: large entries alone, the rest into the writer's head in doc_key order, sealing the head
// as it stands when the next does not fit and opening the next slot. Sets plan.mergeFirst, writing nothing, when no
// slot is free and the writer may merge.
func indexPlaceEntries(args *indexHeadPlanArgs, root *indexViewRoot, bucket *indexViewBucket, writer *indexViewWriter, planned *indexHeadPlanBucket, entries []*indexEntry, plan *indexHeadPlan) error {
	view := args.view
	pushed := map[[indexIdByteCount]byte]bool{}
	sizes := map[*indexEntry]int{}
	small, large := []*indexEntry{}, []*indexEntry{}
	for _, entry := range entries {
		pushed[entry.key] = true
		encoded, err := entry.appendEncoded(nil, view.companion)
		if err != nil {
			return err
		}
		sizes[entry] = len(encoded)
		if indexSlotEntryMaxByteCount < len(encoded) {
			large = append(large, entry)
		} else {
			small = append(small, entry)
		}
	}

	var head *indexViewSlot
	nextSeq := uint32(1)
	absorbed := uint32(0)
	usedSlots := map[uint32]bool{}
	reusable := []*indexViewSlot{}
	if writer != nil {
		head = writer.head()
		nextSeq = writer.highestSeq() + 1
		absorbed = bucket.absorbedSeq(args.writer)
		for _, slot := range writer.slots {
			usedSlots[slot.path.slotIndex] = true
			if slot != head && slot.seq() <= absorbed {
				reusable = append(reusable, slot)
			}
		}
		slices.SortFunc(reusable, func(a *indexViewSlot, b *indexViewSlot) int {
			return cmp.Compare(a.path.slotIndex, b.path.slotIndex)
		})
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
			if indexWriterRingSlotCount <= k {
				if args.mayMerge {
					plan.mergeFirst = true
					return nil, nil
				}
				plan.pastRing = true
			}
			usedSlots[k] = true
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
	probeSeq := nextSeq + uint32(len(entries)) + indexWriterSlotCount
	header := func(fileType uint32, seq uint32, coverage []*protocol.IndexCoverage) *protocol.IndexFileHeader {
		header := indexNewFileHeader(fileType, args.tables)
		header.BucketStartDay = planned.window.startDay
		header.BucketDays = planned.window.days
		header.WriterSidecarId = args.writer.Bytes()
		header.Seq = seq
		header.Coverage = coverage
		return header
	}
	// Whether open takes entry within a slot's 16,208 B, its header at the widest seq the push can give.
	fits := func(open *indexOpenSlot, entry *indexEntry) (bool, error) {
		byteCount, err := indexSlotByteCount(header(indexFileSlot, probeSeq, coverage), len(open.entries)+1, open.bodyByteCount+sizes[entry])
		if err != nil {
			return false, err
		}
		return byteCount <= indexSlotMaxByteCount, nil
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

	// Seqs: large entries, then slots sealed past the head, then the head above them all. A head the push does not
	// fill keeps its seq unless the push numbers anything else.
	seq := nextSeq
	for _, entry := range large {
		path, err := root.paths.largeEntry(planned.window.startDay, [indexIdByteCount]byte(args.writer), seq)
		if err != nil {
			return err
		}
		file, err := indexEncodePlanned(&indexSlot{header: header(indexFileLargeEntry, seq, nil), entries: []*indexEntry{entry}}, view.companion)
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
		file, err := indexEncodePlanned(&indexSlot{header: header(indexFileSlot, seq, coverage), entries: open.entries}, view.companion)
		if err != nil {
			return nil, err
		}
		parsed, _ := indexParsePath(path, view.companion)
		return &indexPlannedFile{path: parsed, slot: file.slot, file: file.file, replaces: open.replaces}, nil
	}
	for _, open := range sealed {
		planned.sealedSlots = append(planned.sealedSlots, open.k)
		if open.old != nil && !open.changed {
			// Sealed as it stood: a new head above it is all sealing writes.
			continue
		}
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
	if current == nil {
		return nil
	}
	renumbered := seq != nextSeq || len(sealed) != 0
	if current.old != nil && !current.changed && !renumbered {
		return nil
	}
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
func indexEncodePlanned(slot *indexSlot, companion bool) (*indexEncodedSlot, error) {
	file, err := indexEncodeSlot(slot, companion)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(file)
	written, err := indexDecodeSlot(file, sum[:], companion)
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
