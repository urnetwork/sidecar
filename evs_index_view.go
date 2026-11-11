//go:build !ios_extension

// The index view (§11.14's head, settings, Files and Buckets rows; SEARCH-M10-08): one ref's index at a ref version,
// read from its listing, since no single index head exists. A view holds the roots (.ur-index/i1 on a file-mode ref, i1
// on ur/index, and i2 beside it during a rebuild), each root's settings, lock, all partition and buckets, and the ref's
// erasure set. A bucket holds its manifest, which it has only from its first merge, its shards, and each writer's slots
// and large entries; a writer's head is its slot with the highest seq. Writers, merges, roll-ups and erasures read the
// index through a view at their push's base, so each decides on the state its push's CAS will hold it to.
//
// Settings are the one versioned file, and a version counts only if one of the repo's admins signed it (§8.8); a newer
// version that does not count is skipped and alarmed, and with none the index is on with the kind's default window.
// Every other file is checked by indexValidateFile as it is read: one that breaks its format is dropped and alarmed,
// naming its signer, and a path under a root that is none of §11.14's own is ignored and alarmed (FI-17). A file in a
// newer format is no malformation: the view says so, and search reads status update. Shards are read only when asked
// for, since a bucket's slots and manifest carry its window and every writer's state.
//
// A view is a snapshot: it never changes after loading but for the shards it decodes on first use. Not safe for
// concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A view loaded without the format's settings, which every read and plan needs.
var errIndexViewSettings = errors.New("index view without its format settings")

// What loading a view reads.
type indexViewArgs struct {
	store    indexRefStore
	repoId   Id
	refId    Id
	repoKind protocol.RepoKind
	// ur/index, rather than a file-mode ref's .ur-index/.
	companion bool
	// 0 reads the head.
	refVersion uint64
	// Whether a settings version's signer was one of the repo's admins (§8.8) when it signed. Nil counts no version,
	// so only the defaults hold.
	isAdmin func(file *indexFileVersion) bool
	// The format's limits the view reads its files under, and that a plan from it writes under. Required.
	settings *IndexFormatSettings
}

// Why a view alarmed.
type indexViewAlarmReason int

const (
	// A file broke its format, or a bucket's files disagree on its window.
	indexViewAlarmMalformed indexViewAlarmReason = iota + 1
	// A path under an index root that is none of §11.14's own (FI-17).
	indexViewAlarmUnknownPath
	// A settings version no repo admin signed, or one the repo's kind refuses.
	indexViewAlarmSettings
)

// One alarm, naming the file and the signer of the version it is about.
type indexViewAlarm struct {
	reason          indexViewAlarmReason
	path            string
	signerSidecarId Id
}

// One ref's index at a ref version.
type indexView struct {
	store     indexRefStore
	repoId    Id
	refId     Id
	repoKind  protocol.RepoKind
	companion bool
	// As of the listed version.
	head  *indexRefHead
	roots []*indexViewRoot
	// The ref's erasure set beside its roots, nil where none is written.
	erasureSet     *protocol.IndexErasureSet
	erasureSetFile *indexFileVersion
	// An erasure set was written and does not read, so no builder may trust what it lists.
	erasureSetUnreadable bool
	// A file in a newer format: search reads status update for the ref.
	newerFormat bool
	alarms      []*indexViewAlarm
	// What the view was loaded under.
	settings *IndexFormatSettings
}

// One index root, i<n>.
type indexViewRoot struct {
	number uint32
	paths  indexPaths
	// The newest version a repo admin signed, nil where none counts.
	settings     *protocol.IndexSettings
	settingsFile *indexFileVersion
	// Nil where no lock is written, or where it does not read.
	lock     *protocol.IndexLock
	lockFile *indexFileVersion
	// a/m, nil until the first roll-up.
	allManifest     *protocol.IndexManifest
	allManifestFile *indexFileVersion
	// The all shards a/m names, by n.
	allShards []*indexViewShard
	// Ascending by start day.
	buckets []*indexViewBucket
}

// One shard, decoded on first use.
type indexViewShard struct {
	file    *indexFileVersion
	path    indexPath
	decoded *indexShard
}

// One bucket.
type indexViewBucket struct {
	window indexBucketWindow
	// From the bucket's first merge.
	manifest     *protocol.IndexManifest
	manifestFile *indexFileVersion
	// The shards its manifest names, by n.
	shards []*indexViewShard
	// By sidecar_id.
	writers []*indexViewWriter
}

// One writer's files in a bucket.
type indexViewWriter struct {
	sidecarId Id
	// By k.
	slots []*indexViewSlot
	// By seq.
	large []*indexViewSlot
}

// A slot or large entry, decoded.
type indexViewSlot struct {
	file *indexFileVersion
	path indexPath
	slot *indexSlot
}

// The slot's or large entry's seq, from its header.
func (self *indexViewSlot) seq() uint32 {
	return self.slot.header.Seq
}

// Reads the index at args.refVersion: the listing, every root's settings, lock and manifests, the erasure set, and
// every bucket's slots and large entries. A store's failure fails the load; a file that breaks its format is dropped
// and alarmed instead.
func indexLoadView(ctx context.Context, args *indexViewArgs) (*indexView, error) {
	if args.settings == nil {
		return nil, errIndexViewSettings
	}
	listing, err := args.store.List(ctx, args.refVersion)
	if err != nil {
		return nil, err
	}
	view := &indexView{
		store:     args.store,
		repoId:    args.repoId,
		refId:     args.refId,
		repoKind:  args.repoKind,
		companion: args.companion,
		head:      listing.head,
		settings:  args.settings,
	}
	refVersion := listing.head.version

	type rootFiles struct {
		settings    *indexFileVersion
		lock        *indexFileVersion
		allManifest *indexFileVersion
		allShards   map[uint32]*indexFileVersion
		buckets     map[uint32][]*indexFileVersion
	}
	rootFileSets := map[uint32]*rootFiles{}
	for _, file := range listing.files {
		path, ok := indexParsePath(file.path, args.companion)
		if !ok {
			view.alarm(indexViewAlarmUnknownPath, file)
			continue
		}
		if path.kind == indexPathErasureSet {
			view.erasureSetFile = file
			continue
		}
		files := rootFileSets[path.rootNumber]
		if files == nil {
			files = &rootFiles{allShards: map[uint32]*indexFileVersion{}, buckets: map[uint32][]*indexFileVersion{}}
			rootFileSets[path.rootNumber] = files
		}
		switch path.kind {
		case indexPathSettings:
			files.settings = file
		case indexPathLock:
			files.lock = file
		case indexPathAllManifest:
			files.allManifest = file
		case indexPathAllShard:
			files.allShards[path.shardNumber] = file
		default:
			files.buckets[path.bucketStartDay] = append(files.buckets[path.bucketStartDay], file)
		}
	}

	if view.erasureSetFile != nil {
		validated, err := view.readValidated(ctx, view.erasureSetFile)
		if err != nil {
			return nil, err
		}
		if validated == nil {
			view.erasureSetUnreadable = true
		} else {
			view.erasureSet = validated.message.(*protocol.IndexErasureSet)
		}
	}

	rootNumbers := []uint32{}
	for number := range rootFileSets {
		rootNumbers = append(rootNumbers, number)
	}
	slices.Sort(rootNumbers)
	for _, number := range rootNumbers {
		files := rootFileSets[number]
		root := &indexViewRoot{number: number, paths: indexNewPaths(args.companion, number)}
		if files.settings != nil {
			if err := view.loadSettings(ctx, root, refVersion, args.isAdmin); err != nil {
				return nil, err
			}
		}
		if files.lock != nil {
			validated, err := view.readValidated(ctx, files.lock)
			if err != nil {
				return nil, err
			}
			root.lockFile = files.lock
			if validated != nil {
				root.lock = validated.message.(*protocol.IndexLock)
			}
		}
		if files.allManifest != nil {
			validated, err := view.readValidated(ctx, files.allManifest)
			if err != nil {
				return nil, err
			}
			if validated != nil {
				root.allManifestFile = files.allManifest
				root.allManifest = validated.message.(*protocol.IndexManifest)
				root.allShards = view.manifestShards(root.allManifest, files.allManifest, files.allShards, func(n uint32) string {
					return root.paths.allShard(n)
				})
			}
		}
		startDays := []uint32{}
		for startDay := range files.buckets {
			startDays = append(startDays, startDay)
		}
		slices.Sort(startDays)
		for _, startDay := range startDays {
			bucket, err := view.loadBucket(ctx, root, startDay, files.buckets[startDay])
			if err != nil {
				return nil, err
			}
			if bucket != nil {
				root.buckets = append(root.buckets, bucket)
			}
		}
		view.dropOverlappingBuckets(root)
		view.roots = append(view.roots, root)
	}
	return view, nil
}

// Records an alarm about file.
func (self *indexView) alarm(reason indexViewAlarmReason, file *indexFileVersion) {
	self.alarms = append(self.alarms, &indexViewAlarm{reason: reason, path: file.path, signerSidecarId: file.signerSidecarId})
}

// Reads one file and checks it as §11.14's verify row does. A file that breaks its format answers nil and is alarmed;
// one in a newer format answers nil and marks the view; a store's failure is the error.
func (self *indexView) readValidated(ctx context.Context, file *indexFileVersion) (*indexValidatedFile, error) {
	path, ok := indexParsePath(file.path, self.companion)
	if !ok {
		self.alarm(indexViewAlarmUnknownPath, file)
		return nil, nil
	}
	plaintext, err := self.store.Read(ctx, file)
	if err != nil {
		return nil, err
	}
	validated, err := indexValidateFile(path, indexBytesFrames(plaintext), file.contentSha256[:], self.settings)
	switch {
	case errors.Is(err, errIndexNewerFormat):
		self.newerFormat = true
		return nil, nil
	case errors.Is(err, errIndexMalformed):
		self.alarm(indexViewAlarmMalformed, file)
		return nil, nil
	case err != nil:
		return nil, err
	}
	return validated, nil
}

// The settings that count: the newest version, at or below refVersion, that one of the repo's admins signed and that
// the repo's kind takes. Each newer version is skipped and alarmed; with none, the root keeps no settings.
func (self *indexView) loadSettings(ctx context.Context, root *indexViewRoot, refVersion uint64, isAdmin func(file *indexFileVersion) bool) error {
	versions, err := self.store.History(ctx, root.paths.settings(), refVersion)
	if err != nil {
		return err
	}
	for _, file := range versions {
		validated, err := self.readValidated(ctx, file)
		if err != nil {
			return err
		}
		if validated == nil {
			continue
		}
		settings := validated.message.(*protocol.IndexSettings)
		if indexCheckSettingsForKind(settings, self.repoKind) != nil || isAdmin == nil || !isAdmin(file) {
			self.alarm(indexViewAlarmSettings, file)
			continue
		}
		root.settings = settings
		root.settingsFile = file
		return nil
	}
	return nil
}

// The shards a manifest names, from those listed. A named shard that is not listed breaks the manifest, and a listed
// one it does not name is no shard of the partition: each is alarmed.
func (self *indexView) manifestShards(manifest *protocol.IndexManifest, manifestFile *indexFileVersion, listed map[uint32]*indexFileVersion, pathOf func(n uint32) string) []*indexViewShard {
	shards := []*indexViewShard{}
	named := map[uint32]bool{}
	for _, shard := range manifest.Shards {
		named[shard.N] = true
		file, ok := listed[shard.N]
		if !ok {
			self.alarm(indexViewAlarmMalformed, manifestFile)
			continue
		}
		path, _ := indexParsePath(pathOf(shard.N), self.companion)
		shards = append(shards, &indexViewShard{file: file, path: path})
	}
	for n, file := range listed {
		if !named[n] {
			self.alarm(indexViewAlarmUnknownPath, file)
		}
	}
	slices.SortFunc(shards, func(a *indexViewShard, b *indexViewShard) int {
		return int(a.path.shardNumber) - int(b.path.shardNumber)
	})
	return shards
}

// One bucket from its listed files: its manifest, every slot and large entry read and checked, and its shards as the
// manifest names them. Its window is its manifest's, else the one most of its slots and large entries carry in their
// headers (a bucket needs no manifest until its first merge); a file disagreeing is dropped and alarmed. A bucket none
// of whose files read is no bucket.
func (self *indexView) loadBucket(ctx context.Context, root *indexViewRoot, startDay uint32, files []*indexFileVersion) (*indexViewBucket, error) {
	bucket := &indexViewBucket{window: indexBucketWindow{startDay: startDay}}
	listedShards := map[uint32]*indexFileVersion{}
	writerSlots := map[Id]*indexViewWriter{}
	slots := []*indexViewSlot{}
	slices.SortFunc(files, func(a *indexFileVersion, b *indexFileVersion) int {
		return bytes.Compare([]byte(a.path), []byte(b.path))
	})
	for _, file := range files {
		path, _ := indexParsePath(file.path, self.companion)
		switch path.kind {
		case indexPathBucketManifest:
			validated, err := self.readValidated(ctx, file)
			if err != nil {
				return nil, err
			}
			if validated != nil {
				bucket.manifest = validated.message.(*protocol.IndexManifest)
				bucket.manifestFile = file
				bucket.window.days = bucket.manifest.Days
			}
		case indexPathBucketShard:
			listedShards[path.shardNumber] = file
		case indexPathSlot, indexPathLargeEntry:
			validated, err := self.readValidated(ctx, file)
			if err != nil {
				return nil, err
			}
			if validated != nil {
				slots = append(slots, &indexViewSlot{file: file, path: path, slot: validated.slot})
			}
		}
	}
	slices.SortFunc(slots, func(a *indexViewSlot, b *indexViewSlot) int {
		return bytes.Compare([]byte(a.file.path), []byte(b.file.path))
	})
	if bucket.window.days == 0 {
		bucket.window.days = indexMajorityWindowDays(slots)
	}
	for _, slot := range slots {
		if slot.slot.header.BucketDays != bucket.window.days {
			self.alarm(indexViewAlarmMalformed, slot.file)
			continue
		}
		writer := writerSlots[slot.path.writerSidecarId]
		if writer == nil {
			writer = &indexViewWriter{sidecarId: slot.path.writerSidecarId}
			writerSlots[slot.path.writerSidecarId] = writer
			bucket.writers = append(bucket.writers, writer)
		}
		if slot.path.kind == indexPathSlot {
			writer.slots = append(writer.slots, slot)
		} else {
			writer.large = append(writer.large, slot)
		}
	}
	if bucket.window.days == 0 {
		// Nothing read gives the window: shards come only with a manifest, so nothing here is searchable.
		for _, file := range listedShards {
			self.alarm(indexViewAlarmMalformed, file)
		}
		return nil, nil
	}
	if bucket.manifest != nil {
		bucket.shards = self.manifestShards(bucket.manifest, bucket.manifestFile, listedShards, func(n uint32) string {
			return root.paths.bucketShard(startDay, n)
		})
	} else {
		for _, file := range listedShards {
			self.alarm(indexViewAlarmUnknownPath, file)
		}
	}
	slices.SortFunc(bucket.writers, func(a *indexViewWriter, b *indexViewWriter) int {
		return a.sidecarId.Cmp(b.sidecarId)
	})
	for _, writer := range bucket.writers {
		self.dropRepeatedSeqs(writer)
	}
	return bucket, nil
}

// The window a bucket without a manifest takes from its slots and large entries, which every one of them should carry
// alike: the one most of them carry, ties to the shorter, so no single file decides it for the rest and every device
// takes the same. 0 for none.
func indexMajorityWindowDays(slots []*indexViewSlot) uint32 {
	counts := map[uint32]int{}
	for _, slot := range slots {
		counts[slot.slot.header.BucketDays] += 1
	}
	chosen := uint32(0)
	for days, count := range counts {
		if chosen == 0 || counts[chosen] < count || (counts[chosen] == count && days < chosen) {
			chosen = days
		}
	}
	return chosen
}

// A writer numbers slots and large entries from one counter a bucket, so two files of one seq break the format: the
// one at the lower slot, or the large entry, stays, and the other is dropped and alarmed.
func (self *indexView) dropRepeatedSeqs(writer *indexViewWriter) {
	seen := map[uint32]bool{}
	for _, large := range writer.large {
		seen[large.seq()] = true
	}
	kept := []*indexViewSlot{}
	for _, slot := range writer.slots {
		if seen[slot.seq()] {
			self.alarm(indexViewAlarmMalformed, slot.file)
			continue
		}
		seen[slot.seq()] = true
		kept = append(kept, slot)
	}
	writer.slots = kept
}

// Buckets are disjoint windows; one overlapping an older bucket breaks the format, and the newer is dropped and
// alarmed, file by file, so every device computes the same buckets from the same listing.
func (self *indexView) dropOverlappingBuckets(root *indexViewRoot) {
	kept := []*indexViewBucket{}
	for _, bucket := range root.buckets {
		if 0 < len(kept) && bucket.window.startDay < kept[len(kept)-1].window.endDay() {
			for _, file := range bucket.files() {
				self.alarm(indexViewAlarmMalformed, file)
			}
			continue
		}
		kept = append(kept, bucket)
	}
	root.buckets = kept
}

// Every file the bucket holds, manifest first.
func (self *indexViewBucket) files() []*indexFileVersion {
	files := []*indexFileVersion{}
	if self.manifestFile != nil {
		files = append(files, self.manifestFile)
	}
	for _, shard := range self.shards {
		files = append(files, shard.file)
	}
	for _, writer := range self.writers {
		for _, slot := range writer.slots {
			files = append(files, slot.file)
		}
		for _, large := range writer.large {
			files = append(files, large.file)
		}
	}
	return files
}

// The root numbered number, or nil.
func (self *indexView) root(number uint32) *indexViewRoot {
	for _, root := range self.roots {
		if root.number == number {
			return root
		}
	}
	return nil
}

// The root format 1 writes, as an empty one where nothing is written yet, so a first writer has paths to write.
func (self *indexView) writeRoot() *indexViewRoot {
	if root := self.root(indexRootNumber); root != nil {
		return root
	}
	return &indexViewRoot{number: indexRootNumber, paths: indexNewPaths(self.companion, indexRootNumber)}
}

// Whether the index is off: the counted settings say so. Absent, it is on (§11.14's settings row).
func (self *indexViewRoot) off() bool {
	return self.settings != nil && self.settings.Off
}

// The W a new bucket takes.
func (self *indexViewRoot) windowDays(repoKind protocol.RepoKind) uint32 {
	return indexEffectiveWindowDays(self.settings, repoKind)
}

// The buckets' windows, ascending.
func (self *indexViewRoot) bucketWindows() []indexBucketWindow {
	windows := make([]indexBucketWindow, 0, len(self.buckets))
	for _, bucket := range self.buckets {
		windows = append(windows, bucket.window)
	}
	return windows
}

// The bucket starting on startDay, or nil.
func (self *indexViewRoot) bucket(startDay uint32) *indexViewBucket {
	for _, bucket := range self.buckets {
		if bucket.window.startDay == startDay {
			return bucket
		}
	}
	return nil
}

// The newest bucket, or nil.
func (self *indexViewRoot) newestBucket() *indexViewBucket {
	if len(self.buckets) == 0 {
		return nil
	}
	return self.buckets[len(self.buckets)-1]
}

// The writer's files in the bucket, or nil.
func (self *indexViewBucket) writer(sidecarId Id) *indexViewWriter {
	for _, writer := range self.writers {
		if writer.sidecarId == sidecarId {
			return writer
		}
	}
	return nil
}

// The highest seq the bucket's shards hold of the writer's slots and large entries, from its manifest: 0 until a
// merge absorbs one.
func (self *indexViewBucket) absorbedSeq(sidecarId Id) uint32 {
	if self.manifest == nil {
		return 0
	}
	for _, watermark := range self.manifest.Absorbed {
		if bytes.Equal(watermark.WriterSidecarId, sidecarId.Bytes()) {
			return watermark.Seq
		}
	}
	return 0
}

// The writer's head: its slot with the highest seq, or nil where it has none in the bucket.
func (self *indexViewWriter) head() *indexViewSlot {
	var head *indexViewSlot
	for _, slot := range self.slots {
		if head == nil || head.seq() < slot.seq() {
			head = slot
		}
	}
	return head
}

// The slot at k, or nil.
func (self *indexViewWriter) slotAt(k uint32) *indexViewSlot {
	for _, slot := range self.slots {
		if slot.path.slotIndex == k {
			return slot
		}
	}
	return nil
}

// The writer's unabsorbed files (DESIGN-DETAILS 1.2.1): its head, and every other slot and large entry whose seq is
// above absorbed, the bucket's manifest watermark for it.
func (self *indexViewWriter) unabsorbed(absorbed uint32) []*indexViewSlot {
	head := self.head()
	files := []*indexViewSlot{}
	for _, slot := range self.slots {
		if slot == head || absorbed < slot.seq() {
			files = append(files, slot)
		}
	}
	for _, large := range self.large {
		if absorbed < large.seq() {
			files = append(files, large)
		}
	}
	return files
}

// The writer's kept files (1.2.1): each file but its head that holds the base of a diff in one of its unabsorbed
// slots, which the writer neither reuses nor removes. counts says whether a diff counts, which a plan uses to leave out
// the head entries its push replaces; nil counts every one.
func (self *indexViewWriter) kept(absorbed uint32, counts func(slot *indexViewSlot, entry *indexEntry) bool) map[*indexViewSlot]bool {
	kept := map[*indexViewSlot]bool{}
	for _, file := range self.unabsorbed(absorbed) {
		if file.path.kind != indexPathSlot {
			continue
		}
		for _, entry := range file.slot.entries {
			if entry.kind != indexEntryDiff || (counts != nil && !counts(file, entry)) {
				continue
			}
			if baseFile, _ := indexResolveBase(self, entry.key, entry.baseVersion, file); baseFile != nil {
				kept[baseFile] = true
			}
		}
	}
	return kept
}

// The highest seq of the writer's slots and large entries in the bucket, 0 for none: its next file takes one more.
func (self *indexViewWriter) highestSeq() uint32 {
	highest := uint32(0)
	for _, slot := range self.slots {
		highest = max(highest, slot.seq())
	}
	for _, large := range self.large {
		highest = max(highest, large.seq())
	}
	return highest
}

// A shard decoded, read and checked on first use. A shard that breaks its format answers nil and is alarmed.
func (self *indexView) shard(ctx context.Context, shard *indexViewShard) (*indexShard, error) {
	if shard.decoded != nil {
		return shard.decoded, nil
	}
	plaintext, err := self.store.Read(ctx, shard.file)
	if err != nil {
		return nil, err
	}
	decoded, err := indexDecodeShard(plaintext, shard.file.contentSha256[:], self.companion)
	switch {
	case errors.Is(err, errIndexNewerFormat):
		self.newerFormat = true
		return nil, nil
	case errors.Is(err, errIndexMalformed):
		self.alarm(indexViewAlarmMalformed, shard.file)
		return nil, nil
	case err != nil:
		return nil, err
	}
	if header := decoded.header; shard.path.kind == indexPathBucketShard &&
		(header.Type != indexFileBucketShard || header.BucketStartDay != shard.path.bucketStartDay) ||
		shard.path.kind == indexPathAllShard && header.Type != indexFileAllShard {
		self.alarm(indexViewAlarmMalformed, shard.file)
		return nil, nil
	}
	shard.decoded = decoded
	return decoded, nil
}

// Whether the ref's erasure set lists docKey at or above version: every indexed version of it up to the listed one is
// erased (§11.14's epoch row), so no builder writes an entry, posting or field of it there.
func (self *indexView) erased(docKey [indexIdByteCount]byte, version uint64) bool {
	if self.erasureSet == nil {
		return false
	}
	for _, erasure := range self.erasureSet.Erasures {
		for _, erased := range erasure.Docs {
			if bytes.Equal(erased.DocKey, docKey[:]) && version <= erased.Version {
				return true
			}
		}
	}
	return false
}

// The view's alarms as §5.4's events: index_malformed for each, naming the repo, the ref, the path and the signer of
// the version alarmed. A settings version no admin signed is the index's rules broken too, so it reads the same.
func (self *indexView) events() []SidecarEvent {
	events := make([]SidecarEvent, 0, len(self.alarms))
	for _, alarm := range self.alarms {
		repoId, refId, signerId := self.repoId, self.refId, alarm.signerSidecarId
		events = append(events, SidecarEvent{
			Kind:      SidecarEventIndexMalformed,
			SidecarId: &signerId,
			RepoId:    &repoId,
			RefId:     &refId,
			Path:      alarm.path,
		})
	}
	return events
}

// An isAdmin for a view, from the repo's ACL state: a version counts when its signer holds admin on the repo in state
// at the version's signed time. state is the one the caller holds, not the version's own auth pin.
func indexAclAdmins(state *AclState, repoId Id) func(file *indexFileVersion) bool {
	if state == nil {
		return nil
	}
	return func(file *indexFileVersion) bool {
		access := state.EvsAccess(AclSidecarSubject(file.signerSidecarId), repoId, AclTokenAudienceEvs, time.UnixMilli(file.signedTimeMs))
		return access.Rights.Has(AclEvsAdmin)
	}
}
