// §16.11's M6 carrier, folded (RECORD-M6-14): until the directory reaches format 2, every run, worker and repo item
// rides announce entries, body Announcement, in its writer's own stream, and DirectoryFold turns the entries a reader
// verified (RecordReader.Entries over RECORD-M6-13's copy) into the current items readers show and List filters,
// locally, with no index and no history (§16.11's tools row).
//
//	key        a run or worker item is its writer's, (kind, writer, announcement_id), so a second writer's use of an id
//	           is a second item, each showing under its own writer, neither voiding the other, and both raising
//	           id_reuse (plan-RECORD-small-readings #2); a repo item is its repo's, (repo, announcement_id), which every
//	           admin of the repo writes
//	order      the highest (version, renewed_millis) wins, the writer's sidecar_id breaking a tie, then seq and leaf, so
//	           one set of entries folds to one state whatever order its streams arrived in (FS-84); a renewal is a new
//	           entry at the same version
//	rules      a version counts only once its rules accept it: a run's or worker's by the card rules
//	           (directory_rules.go), a repo item's by the repo file's (directory_repo.go); a refused version is
//	           ignored and alarms once, and a pending one, whose pin the reader's state has not reached, waits unshown
//	withdrawn  an accepted withdrawal (state 4) hides its item at once, as stale or ended too, and nothing above it
//	           counts, since it is terminal (plan-RECORD-m6-carrier #1)
//	show       a run or worker item is active until expires_millis and never after, then stale for 24 h; ended or
//	           handed off for 24 h from its renewal; a repo item while its repo lives, its private marker apart
//
// What the fold holds is a function of the entries it was last given: Update replaces them, and View judges them at the
// state and the time it is given. A verdict that rests only on history that never changes (a version's signer and
// stream, its signer's standing at its pin, D-MCP-35's right found at a position) is kept once reached, so a later
// view asks the state only what can still change: the pin's distance, a revocation or cascade since, a repo's
// deletion. A lost read starts a new fold.
//
// Safe for concurrent use. No lock is held across a call into the state or the alarm sink.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"slices"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One item's identity in the fold.
type DirectoryItemKey struct {
	Kind DirectoryAnnouncementKind
	// A run's or a worker's writer; zero for a repo item, which folds across its admins.
	WriterSidecarId Id
	AnnouncementId  Id
}

// How an item shows.
type DirectoryItemDisplay string

const (
	DirectoryItemActive DirectoryItemDisplay = "active"
	// A run or worker item past its expires_millis, for 24 h: never shown as active.
	DirectoryItemStale     DirectoryItemDisplay = "stale"
	DirectoryItemEnded     DirectoryItemDisplay = "ended"
	DirectoryItemHandedOff DirectoryItemDisplay = "handed_off"
	// A repo's private marker: its id, kind and requests alone.
	DirectoryItemPrivate DirectoryItemDisplay = "private"
)

// One current item, as a reader's fold shows it.
type DirectoryItem struct {
	Key DirectoryItemKey
	// The version that stands, as its entry carried it.
	Announcement *protocol.Announcement
	Display      DirectoryItemDisplay
	// The version's signer, whose own stream carried it, and where.
	SignerSidecarId Id
	EntryId         Id
	Seq             uint64
	PushPin         *bridge.AuthPin
	PushTimeMillis  int64
	// Whose the item is in the reader's state: its signer's member, or a tagged or ephemeral signer's sponsor; nil
	// where there is none, shown as autogroup:admin (§16.11's who row).
	MemberId       *Id
	AutogroupAdmin bool
	// The signer is a member device, untagged: what §16.11's identifiers row reads beside the taint.
	MemberDevice bool
	// The writing run's taint, or the entry's flag: its prose is untrusted either way (D-MCP-29).
	Tainted bool
	// The fields a List query matched, by name, for a stub's match label (RECORD-M6-22); empty without a query.
	Matches []string
}

// One announce entry as the fold holds it.
type directoryVersion struct {
	key     DirectoryItemKey
	leaf    [sha256.Size]byte
	entryId Id
	// the header's writer_sidecar_id, whose identity key signed it
	writerId Id
	seq      uint64
	// the header's tainted
	flagged bool
	// the copy in its signer's own stream: its push's pin and evs's time for that push; a nil pin when no copy sits
	// there, so another sidecar pushed it
	pushPin        *bridge.AuthPin
	pushTimeMillis int64
	item           *protocol.Announcement
}

// What one judgement of a version found.
type directoryVerdict int

const (
	// It counts.
	directoryVerdictAccepted directoryVerdict = iota + 1
	// Not judged yet: its pin is ahead of the reader's state, or no state is bound. Neither shown nor alarmed.
	directoryVerdictPending
	// Ignored, alarming as the judgement says.
	directoryVerdictRefused
)

// A verdict, with the alarm a refusal raises: none for a version masked by a revocation since, or one no rule refused
// but that has aged out of what is judged.
type directoryJudgement struct {
	verdict directoryVerdict
	alarm   SidecarRecordAlarm
	// refused for a pin past the card rule's 4,096 positions: alarmed only while nothing accepted stands above it, since
	// an honest item's older versions age past the bound beside its renewals
	aged bool
}

var (
	directoryAccepted = directoryJudgement{verdict: directoryVerdictAccepted}
	directoryPending  = directoryJudgement{verdict: directoryVerdictPending}
)

// A refusal raising alarm, "" for none.
func directoryRefused(alarm SidecarRecordAlarm) directoryJudgement {
	return directoryJudgement{verdict: directoryVerdictRefused, alarm: alarm}
}

// One alarm, raised once.
type directoryAlarmKey struct {
	leaf   [sha256.Size]byte
	reason SidecarRecordAlarm
}

// One writer's use of a run or worker id another writer also uses.
type directoryReuseKey struct {
	kind           DirectoryAnnouncementKind
	announcementId Id
	writerId       Id
}

// The fold of one directory's announce entries.
type DirectoryFold struct {
	directoryId Id
	alarm       func(alarm *RecordAlarm)

	stateLock sync.Mutex
	// every announce entry folded, by leaf, and each item's, highest first
	leafVersions map[[sha256.Size]byte]*directoryVersion
	keyVersions  map[DirectoryItemKey][]*directoryVersion
	// verdicts resting on fixed history alone, by leaf: never pending
	leafFixed map[[sha256.Size]byte]directoryJudgement
	// each repo item version's 10 min check, by leaf: the reader pin at which no ending entry was found
	leafNotEndedAt map[[sha256.Size]byte]uint64
	alarmed        map[directoryAlarmKey]bool
	reused         map[directoryReuseKey]bool
}

// A fold of directoryId's entries, raising its alarms through alarm, nil for none.
func NewDirectoryFold(directoryId Id, alarm func(alarm *RecordAlarm)) *DirectoryFold {
	return &DirectoryFold{
		directoryId:    directoryId,
		alarm:          alarm,
		leafVersions:   map[[sha256.Size]byte]*directoryVersion{},
		keyVersions:    map[DirectoryItemKey][]*directoryVersion{},
		leafFixed:      map[[sha256.Size]byte]directoryJudgement{},
		leafNotEndedAt: map[[sha256.Size]byte]uint64{},
		alarmed:        map[directoryAlarmKey]bool{},
		reused:         map[directoryReuseKey]bool{},
	}
}

// The directory folded.
func (self *DirectoryFold) DirectoryId() Id {
	return self.directoryId
}

// Highest first: (version, renewed_millis), then the writer's sidecar_id, which breaks a repo item's tie across its
// admins, then seq and leaf, so equal inputs give one order wherever they came from.
func directoryVersionCompare(a *directoryVersion, b *directoryVersion) int {
	return cmp.Or(
		cmp.Compare(b.item.GetVersion(), a.item.GetVersion()),
		cmp.Compare(b.item.GetRenewedMillis(), a.item.GetRenewedMillis()),
		b.writerId.Cmp(a.writerId),
		cmp.Compare(b.seq, a.seq),
		bytes.Compare(b.leaf[:], a.leaf[:]),
	)
}

// An announce entry as the fold holds it, false for one whose body does not decode, which the reader already showed
// invalid and alarmed over_cap.
func directoryVersionOf(entry *RecordReadEntry) (*directoryVersion, bool) {
	item, err := DirectoryDecodeAnnouncement(entry.Body)
	if err != nil {
		return nil, false
	}
	writerId := recordIdOf(entry.Header.Header.GetWriterSidecarId())
	version := &directoryVersion{
		leaf:     entry.Leaf,
		entryId:  entry.EntryId,
		writerId: writerId,
		seq:      entry.Header.Header.GetSeq(),
		flagged:  entry.Flagged,
		item:     item,
	}
	for _, entryCopy := range entry.Copies {
		if entryCopy.StreamSidecarId == writerId && entryCopy.AuthPin != nil {
			version.pushPin = &bridge.AuthPin{Version: entryCopy.AuthPin.GetVersion(), Chain: bytes.Clone(entryCopy.AuthPin.GetChain())}
			version.pushTimeMillis = entryCopy.TimeMillis
			break
		}
	}
	kind := DirectoryAnnouncementKind(item.GetKind())
	version.key = DirectoryItemKey{Kind: kind, AnnouncementId: recordIdOf(item.GetAnnouncementId())}
	if kind != DirectoryAnnouncementKindRepo {
		version.key.WriterSidecarId = writerId
	}
	return version, true
}

// Replaces what the fold holds with entries' announce entries: live, a body that decodes, forked and erased ones
// left out. A leaf already held keeps its decoding, so an update decodes only what is new.
func (self *DirectoryFold) Update(entries []*RecordReadEntry) {
	hookKey := recordChainIdText(self.directoryId)
	testHookBarrier("directory.fold.before", hookKey)
	defer testHookBarrier("directory.fold.after", hookKey)
	held := func() map[[sha256.Size]byte]*directoryVersion {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.leafVersions
	}()
	leafVersions := map[[sha256.Size]byte]*directoryVersion{}
	for _, entry := range entries {
		if entry == nil || entry.Header == nil || entry.Kind() != RecordKindAnnounce || entry.State != RecordEntryLive || entry.Body == nil {
			continue
		}
		if version, ok := held[entry.Leaf]; ok {
			leafVersions[entry.Leaf] = version
			continue
		}
		if version, ok := directoryVersionOf(entry); ok {
			leafVersions[entry.Leaf] = version
		}
	}
	keyVersions := map[DirectoryItemKey][]*directoryVersion{}
	for _, version := range leafVersions {
		keyVersions[version.key] = append(keyVersions[version.key], version)
	}
	for _, versions := range keyVersions {
		slices.SortFunc(versions, directoryVersionCompare)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.leafVersions = leafVersions
	self.keyVersions = keyVersions
}

// How many announce entries the fold holds.
func (self *DirectoryFold) VersionCount() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return len(self.leafVersions)
}

// One view's judging: the state and time it judges at, what it asked of the state already, and the alarms it found,
// raised once it is done.
type directoryJudge struct {
	fold      *DirectoryFold
	auth      DirectoryAuthView
	readerPin *bridge.AuthPin
	nowMillis int64
	// each signer's standing in the reader's state, asked once a view
	standingNow map[Id]DirectoryStanding
	alarms      []*RecordAlarm
}

// The current items at the state auth holds and at nowMillis, in List's order (directory_view.go): every item that
// shows, private markers included. Alarms what it refuses, once each.
func (self *DirectoryFold) View(auth DirectoryAuthView, nowMillis int64) []*DirectoryItem {
	if auth == nil {
		auth = DirectoryAuthUnavailable{}
	}
	keyVersions := func() map[DirectoryItemKey][]*directoryVersion {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.keyVersions
	}()
	judge := &directoryJudge{fold: self, auth: auth, readerPin: auth.Pin(), nowMillis: nowMillis, standingNow: map[Id]DirectoryStanding{}}
	items := []*DirectoryItem{}
	// writers with an accepted version of each run or worker id
	idWriters := map[DirectoryItemKey][]Id{}
	keys := make([]DirectoryItemKey, 0, len(keyVersions))
	for key := range keyVersions {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, directoryItemKeyCompare)
	for _, key := range keys {
		var item *DirectoryItem
		accepted := false
		if key.Kind == DirectoryAnnouncementKindRepo {
			item, accepted = judge.repoItem(keyVersions[key])
		} else {
			item, accepted = judge.cardItem(keyVersions[key])
		}
		if accepted && key.Kind != DirectoryAnnouncementKindRepo {
			idKey := DirectoryItemKey{Kind: key.Kind, AnnouncementId: key.AnnouncementId}
			idWriters[idKey] = append(idWriters[idKey], key.WriterSidecarId)
		}
		if item != nil {
			items = append(items, item)
		}
	}
	for idKey, writerIds := range idWriters {
		if len(writerIds) < 2 {
			continue
		}
		for _, writerId := range writerIds {
			judge.reuse(idKey, writerId)
		}
	}
	for _, alarm := range judge.alarms {
		if self.alarm != nil {
			self.alarm(alarm)
		}
	}
	slices.SortFunc(items, directoryItemCompare)
	return items
}

// Keys in id order: kind, writer, announcement_id.
func directoryItemKeyCompare(a DirectoryItemKey, b DirectoryItemKey) int {
	return cmp.Or(cmp.Compare(a.Kind, b.Kind), a.WriterSidecarId.Cmp(b.WriterSidecarId), a.AnnouncementId.Cmp(b.AnnouncementId))
}

// The order List answers in: by kind, active items first, then the latest renewed, then the key.
func directoryItemCompare(a *DirectoryItem, b *DirectoryItem) int {
	rank := func(display DirectoryItemDisplay) int {
		switch display {
		case DirectoryItemActive:
			return 0
		case DirectoryItemPrivate:
			return 1
		case DirectoryItemStale:
			return 2
		}
		return 3
	}
	return cmp.Or(
		cmp.Compare(a.Key.Kind, b.Key.Kind),
		cmp.Compare(rank(a.Display), rank(b.Display)),
		cmp.Compare(b.Announcement.GetRenewedMillis(), a.Announcement.GetRenewedMillis()),
		directoryItemKeyCompare(a.Key, b.Key),
	)
}

// Queues an alarm for version's refusal, once a leaf and reason.
func (self *directoryJudge) alarm(version *directoryVersion, judgement directoryJudgement) {
	if judgement.verdict != directoryVerdictRefused || judgement.alarm == "" {
		return
	}
	key := directoryAlarmKey{leaf: version.leaf, reason: judgement.alarm}
	raise := func() bool {
		self.fold.stateLock.Lock()
		defer self.fold.stateLock.Unlock()
		if self.fold.alarmed[key] {
			return false
		}
		self.fold.alarmed[key] = true
		return true
	}()
	if raise {
		signerId := version.writerId
		self.alarms = append(self.alarms, &RecordAlarm{Reason: judgement.alarm, LogId: self.fold.directoryId, SidecarId: &signerId})
	}
}

// Queues id_reuse for one writer of an id another writer also uses, once.
func (self *directoryJudge) reuse(idKey DirectoryItemKey, writerId Id) {
	key := directoryReuseKey{kind: idKey.Kind, announcementId: idKey.AnnouncementId, writerId: writerId}
	raise := func() bool {
		self.fold.stateLock.Lock()
		defer self.fold.stateLock.Unlock()
		if self.fold.reused[key] {
			return false
		}
		self.fold.reused[key] = true
		return true
	}()
	if raise {
		self.alarms = append(self.alarms, &RecordAlarm{Reason: SidecarRecordAlarmIdReuse, LogId: self.fold.directoryId, SidecarId: &writerId})
	}
}

// The verdict kept for a leaf, false while none is.
func (self *directoryJudge) fixed(version *directoryVersion) (directoryJudgement, bool) {
	self.fold.stateLock.Lock()
	defer self.fold.stateLock.Unlock()
	judgement, ok := self.fold.leafFixed[version.leaf]
	return judgement, ok
}

// Keeps a verdict resting on fixed history alone; a pending one is not kept.
func (self *directoryJudge) keepFixed(version *directoryVersion, judgement directoryJudgement) {
	if judgement.verdict == directoryVerdictPending {
		return
	}
	self.fold.stateLock.Lock()
	defer self.fold.stateLock.Unlock()
	self.fold.leafFixed[version.leaf] = judgement
}

// The signer's standing in the reader's state, asked once a view: unjudged when the state cannot say.
func (self *directoryJudge) standing(signerId Id) DirectoryStanding {
	if standing, ok := self.standingNow[signerId]; ok {
		return standing
	}
	standing := DirectoryStandingUnjudged
	if self.readerPin != nil {
		if judged, err := self.auth.SignerStanding(signerId, self.readerPin); err == nil {
			standing = judged
		}
	}
	self.standingNow[signerId] = standing
	return standing
}

// version shown as display: who in the reader's state, and a copy of what the fold holds.
func (self *directoryJudge) itemOf(version *directoryVersion, display DirectoryItemDisplay) *DirectoryItem {
	item := &DirectoryItem{
		Key:             version.key,
		Announcement:    proto.Clone(version.item).(*protocol.Announcement),
		Display:         display,
		SignerSidecarId: version.writerId,
		EntryId:         version.entryId,
		Seq:             version.seq,
		PushPin:         &bridge.AuthPin{Version: version.pushPin.GetVersion(), Chain: bytes.Clone(version.pushPin.GetChain())},
		PushTimeMillis:  version.pushTimeMillis,
		Tainted:         version.item.GetTainted() || version.flagged,
	}
	_, item.MemberDevice = self.auth.MemberOf(version.writerId)
	if memberId, ok := DirectoryWhoMember(self.auth, version.writerId); ok {
		item.MemberId = &memberId
	} else {
		item.AutogroupAdmin = true
	}
	return item
}
