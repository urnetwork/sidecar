// The drop job's independent oracle (§11.13's verify row; D-EVS-64, D-TEST-18, I-EVS-15, FI-27; DESIGN-DETAILS 10.2.8;
// EVSB-M10-05): two implementations must agree before any DELETE, so this one is written apart from mark (EVSB-M10-04)
// and shares none of its scan code. It is a child package of evsservice that evsservice cannot import, so server injects
// it behind evsservice.DropVerifier (server/taskworker/evs_drop.go). It reads the clusters through sidecar.BlobCluster
// and the formats through the root's and protocol's decoders alone, and holds its own readers of the dropscan/ files,
// the batches, containers, log pages and payloads it needs.
//
// One verify, after mark took round r's snapshot M_r:
//
//	D        the round's unmarked candidates: every cand file's ids less every mark file's (dropscan/<repo>/<job>/)
//	live     a version is not live when a list file of the repo (any job's) holds its entry hash under a drop that
//	         Request.Executed says executed: covered by this job and not refused, done or held, or gone from the
//	         table with no void record (10.2.8's live row)
//	refs     after mark, LIST head/<repo>/ again and read every head again from the cluster: V_r[ref], each head's own
//	         version, a placeholder's 0 scanning nothing; a ref created since mark is read from version 1
//	scan     every push of each ref from version 1 in round 1, after V_{r-1}[ref] in a later round: its record at its
//	         window entry's place (the head's window or the ref's log page, the batch or, once evacuated, the
//	         container pidx/ names), and what it names (Names): for each live entry version, every segment id of a
//	         kind-1 or kind-5 locator and every slot id, and on a git-mode ref every segment id of the push's new-objects
//	         list, which names a git push's history segments as nothing else does (G11)
//	hits     an id of D a push names: at or below its ref's M_r the scans disagree, refused {verify}, which pages; above
//	         it a late mark, marked, counted and kept
//	cancels  a DROP of action 2 on a covered drop's ref after the drop, naming it: that drop is cancelled
//	lock     the repo's lock in the newest verified state (Request.LockStanding): standing refuses the job {locked}
//
// It decrypts nothing and writes nothing: the job records what it found. A store read that fails is an error, and the
// job's round restarts at its horizon.
//
// Package-level functions are safe for concurrent use.

package dropverify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The barriers verify holds (evsservice's barriers.go names them for mark too): around its LIST of head/, keyed by the
// repo, and around each head's read, keyed by <repo>:<ref>.
const (
	barrierRefsBefore = "evs.drop.refs.before"
	barrierRefsAfter  = "evs.drop.refs.after"
	barrierHeadBefore = "evs.drop.head.before"
	barrierHeadAfter  = "evs.drop.head.after"
)

// The formats this package reads, as EVS-FORMAT.md and DESIGN-DETAILS 10.2.2 and 10.2.9 give them. Format values, not
// tunables.
const (
	dropFileMagic               = "URds"
	dropFileFormat1        byte = 1
	dropFileKindCand       byte = 2
	dropFileKindList       byte = 3
	dropFileKindMark       byte = 4
	dropFileHeaderLength        = 48
	dropFileIdRowLength         = 33
	listDropLength              = 56
	listRowLength               = 35
	listTailLength              = 8
	trailerLength               = sha256.Size
	windowEntryLength           = 64
	placeLength                 = 20
	logPageVersionCount         = 64
	keyNumberDigitCount         = 20
	payloadSectionHeader        = 5
	locatorKindSegment          = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT)
	locatorKindVersionless      = uint32(protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT)
	newObjectSegment            = byte(protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT)
	newObjectStagedSegment      = byte(protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT)
	newObjectSegmentLength      = 1 + 32 + 8 + 4
	sectionEntryVersions        = 1
	sectionNewObjects           = 6
	sectionDropBody             = 9
	windowFlagDrop              = uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP)
	dropActionCancel            = 2
	containerPack               = protocol.EvsContainerKind_EVS_CONTAINER_PACK
)

// An id a candidate's kind holds.
const (
	IdKindSegment uint8 = 1
	IdKindSlot    uint8 = 2
)

// A candidate: a segment's 32 B id, or a slot's 16 B id zero-filled on the right.
type Id struct {
	Id   [32]byte
	Kind uint8
}

// Tunables of one verify.
type Settings struct {
	// Keys a LIST page asks for.
	ListLimit int
	// What one read may take at most: a head, a log page, a pidx/ entry, a dropscan/ file, a record.
	ObjectMaxByteCount int64
}

// A fresh value each call.
func DefaultSettings() *Settings {
	return &Settings{
		ListLimit:          1000,
		ObjectMaxByteCount: 64 * 1024 * 1024,
	}
}

// One covered drop not refused.
type Drop struct {
	DropId  sidecar.Id
	RefId   sidecar.Id
	Version uint64
}

// One verify's input, which server builds from evsservice.DropVerifyRequest.
type Request struct {
	// The repo's metadata cluster, and the segment cluster that holds dropscan/ and packs.
	Cluster        sidecar.BlobCluster
	SegmentCluster sidecar.BlobCluster
	RepoId         sidecar.Id
	JobId          sidecar.Id
	Round          uint32
	// Each ref's M_r.
	Marked map[sidecar.Id]uint64
	// Each ref's V_{r-1}; empty in round 1.
	Since map[sidecar.Id]uint64
	Drops []*Drop
	// Whether versions a list file holds under dropId are not live.
	Executed func(dropId sidecar.Id) bool
	// Whether a lock stands on the repo; an error when it cannot tell.
	LockStanding func(ctx context.Context) (bool, error)
	// Waits out the job's read rate for byteCount bytes read. nil waits nothing.
	Pace func(ctx context.Context, byteCount int64) error
	// nil: the defaults.
	Settings *Settings
}

// What one verify found.
type Result struct {
	// Each ref's V_r.
	Snapshot map[sidecar.Id]uint64
	// A hit at or below its ref's M_r, and what it was.
	Disagree bool
	Detail   string
	// Hits above M_r.
	LateMarks []Id
	// Covered drops a committed cancel names.
	Cancelled []sidecar.Id
	Locked    bool
	// Bytes read.
	ScanByteCount int64
}

// A store object this package cannot parse, or a reference it cannot follow: verify stops, deleting nothing.
var ErrVerifyState = errors.New("evs drop verify cannot read the repo")

// One verify's state.
type verifier struct {
	request  *Request
	settings *Settings
	result   *Result
	// D
	unmarked map[Id]bool
	// entry hashes no version may mark for: listed under an executed drop
	executed map[[32]byte]bool
	// pidx/ entries of a ref, read once
	pidxEntries map[sidecar.Id][]*protocol.EvsPidxEntry
}

// See the file header.
func Verify(ctx context.Context, request *Request) (*Result, error) {
	settings := request.Settings
	if settings == nil {
		settings = DefaultSettings()
	}
	if settings.ListLimit <= 0 || settings.ObjectMaxByteCount <= 0 {
		return nil, fmt.Errorf("%w: settings with a bound that is not positive", ErrVerifyState)
	}
	if request.Cluster == nil || request.SegmentCluster == nil || request.Executed == nil || request.LockStanding == nil {
		return nil, fmt.Errorf("%w: a request missing its clusters, liveness or lock", ErrVerifyState)
	}
	self := &verifier{
		request:     request,
		settings:    settings,
		result:      &Result{Snapshot: map[sidecar.Id]uint64{}},
		unmarked:    map[Id]bool{},
		executed:    map[[32]byte]bool{},
		pidxEntries: map[sidecar.Id][]*protocol.EvsPidxEntry{},
	}
	if err := self.readUnmarked(ctx); err != nil {
		return nil, err
	}
	if err := self.readListed(ctx); err != nil {
		return nil, err
	}
	repoKey := sidecar.EvsKeyId(request.RepoId)
	testHookBarrier(barrierRefsBefore, repoKey)
	refIds, err := self.listRefs(ctx)
	testHookBarrier(barrierRefsAfter, repoKey)
	if err != nil {
		return nil, err
	}
	dropsOfRef := map[sidecar.Id][]*Drop{}
	for _, drop := range request.Drops {
		dropsOfRef[drop.RefId] = append(dropsOfRef[drop.RefId], drop)
	}
	lateMarked := map[Id]bool{}
	cancelled := map[sidecar.Id]bool{}
	for _, refId := range refIds {
		refKey := repoKey + ":" + sidecar.EvsKeyId(refId)
		testHookBarrier(barrierHeadBefore, refKey)
		head, err := self.readHead(ctx, refId)
		testHookBarrier(barrierHeadAfter, refKey)
		if err != nil {
			return nil, err
		}
		if head == nil {
			continue
		}
		self.result.Snapshot[refId] = head.GetVersion()
		drops := dropsOfRef[refId]
		if len(self.unmarked) == 0 && len(drops) == 0 {
			continue
		}
		gitMode := protocol.EvsRefMode(head.GetRefMode()) == protocol.EvsRefMode_EVS_REF_GIT
		window, err := decodeWindow(head.GetWindow())
		if err != nil {
			return nil, err
		}
		windowFirst := head.GetVersion() + 1 - uint64(len(window))
		marked := request.Marked[refId]
		for version := request.Since[refId] + 1; version <= head.GetVersion(); version += 1 {
			var entry *windowEntry
			if windowFirst <= version {
				entry = window[version-windowFirst]
			} else if entry, err = self.logPageEntry(ctx, refId, version); err != nil {
				return nil, err
			}
			push, err := self.readPush(ctx, refId, entry.place)
			if err != nil {
				return nil, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(refId), err)
			}
			names, err := self.names(push, gitMode)
			if err != nil {
				return nil, fmt.Errorf("version %d of ref %s: %w", version, sidecar.EvsKeyId(refId), err)
			}
			for _, name := range names {
				if !self.unmarked[name] {
					continue
				}
				if version <= marked {
					self.result.Disagree = true
					self.result.Detail = fmt.Sprintf("version %d of ref %s, at or below mark's %d, names candidate %x of kind %d",
						version, sidecar.EvsKeyId(refId), marked, name.Id, name.Kind)
					return self.result, nil
				}
				if !lateMarked[name] {
					lateMarked[name] = true
					self.result.LateMarks = append(self.result.LateMarks, name)
				}
			}
			if entry.flags&windowFlagDrop != 0 {
				for _, drop := range drops {
					if version <= drop.Version || cancelled[drop.DropId] {
						continue
					}
					body, err := self.dropBody(push)
					if err != nil {
						return nil, err
					}
					if body != nil && body.GetAction() == dropActionCancel && bytes.Equal(body.GetCancelsDropId(), drop.DropId[:]) &&
						body.GetCancelsVersion() == drop.Version {
						cancelled[drop.DropId] = true
						self.result.Cancelled = append(self.result.Cancelled, drop.DropId)
					}
				}
			}
		}
	}
	locked, err := request.LockStanding(ctx)
	if err != nil {
		return nil, err
	}
	self.result.Locked = locked
	return self.result, nil
}

// Counts and paces a read of byteCount bytes.
func (self *verifier) read(ctx context.Context, byteCount int) error {
	self.result.ScanByteCount += int64(byteCount)
	if self.request.Pace == nil {
		return nil
	}
	return self.request.Pace(ctx, int64(byteCount))
}

// An object's bytes whole, nil for none.
func (self *verifier) get(ctx context.Context, cluster sidecar.BlobCluster, key string) ([]byte, error) {
	object, err := cluster.Get(ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	body, err := io.ReadAll(io.LimitReader(object.Body, self.settings.ObjectMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if self.settings.ObjectMaxByteCount < int64(len(body)) {
		return nil, fmt.Errorf("%w: %s past %d bytes", ErrVerifyState, key, self.settings.ObjectMaxByteCount)
	}
	return body, self.read(ctx, len(body))
}

// byteCount bytes of an object from offset, nil for none.
func (self *verifier) getRange(ctx context.Context, cluster sidecar.BlobCluster, key string, offset int64, byteCount int64) ([]byte, error) {
	if byteCount <= 0 || self.settings.ObjectMaxByteCount < byteCount {
		return nil, fmt.Errorf("%w: a range of %d bytes", ErrVerifyState, byteCount)
	}
	object, err := cluster.GetRange(ctx, key, offset, byteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	body, err := io.ReadAll(io.LimitReader(object.Body, byteCount+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) != byteCount {
		return nil, fmt.Errorf("%w: %s gave %d of %d bytes", ErrVerifyState, key, len(body), byteCount)
	}
	return body, self.read(ctx, len(body))
}

// Every key under prefix.
func (self *verifier) list(ctx context.Context, cluster sidecar.BlobCluster, prefix string) ([]string, error) {
	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := cluster.List(ctx, prefix, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
		}
		if !more || len(objects) == 0 {
			return keys, nil
		}
		startAfter = objects[len(objects)-1].Key
	}
}

// The repo's dropscan/ prefix, and a job's.
func (self *verifier) dropscanPrefix() string {
	return "dropscan/" + sidecar.EvsKeyId(self.request.RepoId) + "/"
}

// A dropscan/ file's rows, held to its envelope: its magic, format, kind, repo, job and trailer.
func (self *verifier) dropFileRows(encoded []byte, kind byte, jobId sidecar.Id) ([]byte, uint32, error) {
	if len(encoded) < dropFileHeaderLength+trailerLength {
		return nil, 0, fmt.Errorf("%w: a drop file of %d bytes", ErrVerifyState, len(encoded))
	}
	body := encoded[:len(encoded)-trailerLength]
	if digest := sha256.Sum256(body); !bytes.Equal(digest[:], encoded[len(body):]) {
		return nil, 0, fmt.Errorf("%w: a drop file's trailer", ErrVerifyState)
	}
	if string(body[0:4]) != dropFileMagic || body[4] != dropFileFormat1 || body[5] != kind || !bytes.Equal(body[8:24], self.request.RepoId[:]) ||
		!bytes.Equal(body[24:40], jobId[:]) {
		return nil, 0, fmt.Errorf("%w: a drop file's header", ErrVerifyState)
	}
	return body[dropFileHeaderLength:], binary.BigEndian.Uint32(body[44:48]), nil
}

// Rows of ids, cand's and mark's after its cursor row.
func idRows(rows []byte) ([]Id, error) {
	if len(rows)%dropFileIdRowLength != 0 {
		return nil, fmt.Errorf("%w: id rows of %d bytes", ErrVerifyState, len(rows))
	}
	ids := make([]Id, 0, len(rows)/dropFileIdRowLength)
	for offset := 0; offset < len(rows); offset += dropFileIdRowLength {
		id := Id{Id: [32]byte(rows[offset : offset+32]), Kind: rows[offset+32]}
		if id.Kind != IdKindSegment && id.Kind != IdKindSlot {
			return nil, fmt.Errorf("%w: an id of kind %d", ErrVerifyState, id.Kind)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// D: the job's cand files' ids less its mark files'.
func (self *verifier) readUnmarked(ctx context.Context) error {
	jobPrefix := self.dropscanPrefix() + sidecar.EvsKeyId(self.request.JobId) + "/"
	keys, err := self.list(ctx, self.request.SegmentCluster, jobPrefix)
	if err != nil {
		return err
	}
	marked := map[Id]bool{}
	for _, key := range keys {
		name := strings.TrimPrefix(key, jobPrefix)
		var kind byte
		switch {
		case strings.HasPrefix(name, "cand-"):
			kind = dropFileKindCand
		case strings.HasPrefix(name, "mark-"):
			kind = dropFileKindMark
		default:
			continue
		}
		encoded, err := self.get(ctx, self.request.SegmentCluster, key)
		if err != nil {
			return err
		}
		if encoded == nil {
			return fmt.Errorf("%w: %s listed and gone", ErrVerifyState, key)
		}
		rows, rowCount, err := self.dropFileRows(encoded, kind, self.request.JobId)
		if err != nil {
			return err
		}
		if kind == dropFileKindMark {
			if rowCount < 1 || len(rows) < dropFileIdRowLength {
				return fmt.Errorf("%w: a mark file with no cursor", ErrVerifyState)
			}
			rows = rows[dropFileIdRowLength:]
			rowCount -= 1
		}
		ids, err := idRows(rows)
		if err != nil {
			return err
		}
		if uint32(len(ids)) != rowCount {
			return fmt.Errorf("%w: %s's row count", ErrVerifyState, key)
		}
		for _, id := range ids {
			if kind == dropFileKindCand {
				self.unmarked[id] = true
			} else {
				marked[id] = true
			}
		}
	}
	for id := range marked {
		delete(self.unmarked, id)
	}
	return nil
}

// The entry hashes every list file of the repo holds under an executed drop (DESIGN-DETAILS 10.2.9's rows).
func (self *verifier) readListed(ctx context.Context) error {
	prefix := self.dropscanPrefix()
	keys, err := self.list(ctx, self.request.SegmentCluster, prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		rest := strings.TrimPrefix(key, prefix)
		slash := strings.IndexByte(rest, '/')
		if slash < 0 || !strings.HasPrefix(rest[slash+1:], "list-") {
			continue
		}
		jobId, err := sidecar.ParseId(rest[:slash])
		if err != nil {
			continue
		}
		encoded, err := self.get(ctx, self.request.SegmentCluster, key)
		if err != nil {
			return err
		}
		if encoded == nil {
			return fmt.Errorf("%w: %s listed and gone", ErrVerifyState, key)
		}
		rows, rowCount, err := self.dropFileRows(encoded, dropFileKindList, jobId)
		if err != nil {
			return err
		}
		if len(rows) < 4+listTailLength {
			return fmt.Errorf("%w: %s is short", ErrVerifyState, key)
		}
		dropCount := int(binary.BigEndian.Uint16(rows[0:2]))
		if rows[2] != 0 || rows[3] != 0 {
			return fmt.Errorf("%w: %s's drop header", ErrVerifyState, key)
		}
		dropsEnd := 4 + dropCount*listDropLength
		rowsEnd := dropsEnd + int(rowCount)*listRowLength
		if len(rows) < rowsEnd+listTailLength {
			return fmt.Errorf("%w: %s's rows pass its end", ErrVerifyState, key)
		}
		executed := make([]bool, dropCount)
		for i := range dropCount {
			executed[i] = self.request.Executed(sidecar.Id(rows[4+i*listDropLength : 4+i*listDropLength+16]))
		}
		for offset := dropsEnd; offset < rowsEnd; offset += listRowLength {
			dropIndex := int(binary.BigEndian.Uint16(rows[offset+32 : offset+34]))
			if dropCount <= dropIndex {
				return fmt.Errorf("%w: %s names drop %d of %d", ErrVerifyState, key, dropIndex, dropCount)
			}
			if executed[dropIndex] {
				self.executed[[32]byte(rows[offset:offset+32])] = true
			}
		}
	}
	return nil
}

// The repo's refs, by one LIST of head/<repo>/.
func (self *verifier) listRefs(ctx context.Context) ([]sidecar.Id, error) {
	prefix := "head/" + sidecar.EvsKeyId(self.request.RepoId) + "/"
	keys, err := self.list(ctx, self.request.Cluster, prefix)
	if err != nil {
		return nil, err
	}
	refIds := make([]sidecar.Id, 0, len(keys))
	for _, key := range keys {
		refId, err := sidecar.ParseId(strings.TrimPrefix(key, prefix))
		if err != nil || sidecar.EvsKeyId(refId) != strings.TrimPrefix(key, prefix) {
			continue
		}
		refIds = append(refIds, refId)
	}
	return refIds, nil
}

// A ref's head from the cluster, nil for none.
func (self *verifier) readHead(ctx context.Context, refId sidecar.Id) (*protocol.EvsHead, error) {
	headBytes, err := self.get(ctx, self.request.Cluster, "head/"+sidecar.EvsKeyId(self.request.RepoId)+"/"+sidecar.EvsKeyId(refId))
	if err != nil || headBytes == nil {
		return nil, err
	}
	head := &protocol.EvsHead{}
	if err := proto.Unmarshal(headBytes, head); err != nil {
		return nil, fmt.Errorf("%w: a head that does not parse", ErrVerifyState)
	}
	return head, nil
}

// One window entry, as this package reads its 64 bytes: push_id 16 | statement_sha256[0:16] | place 20 | paths_digest
// u64 | flags u32.
type windowEntry struct {
	pushId sidecar.Id
	place  *protocol.EvsPlace
	flags  uint32
}

// A window's entries, oldest first.
func decodeWindow(window []byte) ([]*windowEntry, error) {
	if len(window)%windowEntryLength != 0 {
		return nil, fmt.Errorf("%w: a window of %d bytes", ErrVerifyState, len(window))
	}
	entries := make([]*windowEntry, 0, len(window)/windowEntryLength)
	for offset := 0; offset < len(window); offset += windowEntryLength {
		raw := window[offset : offset+windowEntryLength]
		place := raw[32 : 32+placeLength]
		entries = append(entries, &windowEntry{
			pushId: sidecar.Id(raw[0:16]),
			place: &protocol.EvsPlace{
				Minute: binary.BigEndian.Uint32(place[0:4]), Instance: binary.BigEndian.Uint32(place[4:8]),
				Seq: binary.BigEndian.Uint32(place[8:12]), Offset: binary.BigEndian.Uint32(place[12:16]),
				Length: binary.BigEndian.Uint32(place[16:20]),
			},
			flags: binary.BigEndian.Uint32(raw[60:64]),
		})
	}
	return entries, nil
}

// A key's 20-digit number.
func keyNumber(number uint64) string {
	text := strconv.FormatUint(number, 10)
	return strings.Repeat("0", keyNumberDigitCount-len(text)) + text
}

// Version's window entry from its ref's log page: log/<repo>/<ref>/<n>, or once packed its pack through pidx/.
func (self *verifier) logPageEntry(ctx context.Context, refId sidecar.Id, version uint64) (*windowEntry, error) {
	page := version / logPageVersionCount
	pageBytes, err := self.get(ctx, self.request.Cluster, "log/"+sidecar.EvsKeyId(self.request.RepoId)+"/"+sidecar.EvsKeyId(refId)+"/"+keyNumber(page))
	if err != nil {
		return nil, err
	}
	if pageBytes == nil {
		if pageBytes, err = self.packedLogPage(ctx, refId, page); err != nil {
			return nil, err
		}
	}
	logPage := &protocol.EvsLogPage{}
	if err := proto.Unmarshal(pageBytes, logPage); err != nil || logPage.GetPage() != page {
		return nil, fmt.Errorf("%w: log page %d of ref %s", ErrVerifyState, page, sidecar.EvsKeyId(refId))
	}
	entries, err := decodeWindow(logPage.GetWindow())
	if err != nil {
		return nil, err
	}
	first := page * logPageVersionCount
	if page == 0 {
		first = 1
	}
	if version < first || first+uint64(len(entries)) <= version {
		return nil, fmt.Errorf("%w: log page %d lacks version %d", ErrVerifyState, page, version)
	}
	return entries[version-first], nil
}

// A ref's pidx/ entries, read once a verify.
func (self *verifier) pidx(ctx context.Context, refId sidecar.Id) ([]*protocol.EvsPidxEntry, error) {
	if entries, ok := self.pidxEntries[refId]; ok {
		return entries, nil
	}
	keys, err := self.list(ctx, self.request.Cluster, "pidx/"+sidecar.EvsKeyId(self.request.RepoId)+"/"+sidecar.EvsKeyId(refId)+"/")
	if err != nil {
		return nil, err
	}
	entries := []*protocol.EvsPidxEntry{}
	for _, key := range keys {
		entryBytes, err := self.get(ctx, self.request.Cluster, key)
		if err != nil {
			return nil, err
		}
		if entryBytes == nil {
			continue
		}
		entry := &protocol.EvsPidxEntry{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, fmt.Errorf("%w: %s does not parse", ErrVerifyState, key)
		}
		entries = append(entries, entry)
	}
	self.pidxEntries[refId] = entries
	return entries, nil
}

// The container an entry names: a pack on the segment cluster, a parcel on the repo's.
func (self *verifier) container(entry *protocol.EvsPidxEntry) (sidecar.BlobCluster, string, error) {
	containerId, err := sidecar.IdFromBytes(entry.GetContainerId())
	if err != nil {
		return nil, "", fmt.Errorf("%w: a container id of %d bytes", ErrVerifyState, len(entry.GetContainerId()))
	}
	if entry.GetContainerKind() == containerPack {
		return self.request.SegmentCluster, "pack/" + sidecar.EvsKeyId(self.request.RepoId) + "/" + sidecar.EvsKeyId(containerId), nil
	}
	return self.request.Cluster, "hp/" + sidecar.EvsKeyId(self.request.RepoId) + "/" + sidecar.EvsKeyId(containerId), nil
}

// A log page a pack holds.
func (self *verifier) packedLogPage(ctx context.Context, refId sidecar.Id, page uint64) ([]byte, error) {
	entries, err := self.pidx(ctx, refId)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		for _, logPage := range entry.GetLogPages() {
			if logPage.GetPage() != page {
				continue
			}
			cluster, key, err := self.container(entry)
			if err != nil {
				return nil, err
			}
			pageBytes, err := self.getRange(ctx, cluster, key, int64(logPage.GetOffset()), int64(logPage.GetLength()))
			if err != nil || pageBytes != nil {
				return pageBytes, err
			}
		}
	}
	return nil, fmt.Errorf("%w: no log page %d of ref %s", ErrVerifyState, page, sidecar.EvsKeyId(refId))
}

// pb/<yyyymmddhh>/<mm>/<instance>-<seq>, the batch a place names.
func batchKey(place *protocol.EvsPlace) string {
	at := time.Unix(int64(place.GetMinute())*60, 0).UTC()
	return fmt.Sprintf("pb/%s/%s/%08x-%08x", at.Format("2006010215"), at.Format("04"), place.GetInstance(), place.GetSeq())
}

// The record bytes at place: its batch's range, or once evacuated its container's through pidx/.
func (self *verifier) recordBytes(ctx context.Context, refId sidecar.Id, place *protocol.EvsPlace) ([]byte, error) {
	recordBytes, err := self.getRange(ctx, self.request.Cluster, batchKey(place), int64(place.GetOffset()), int64(place.GetLength()))
	if err != nil || recordBytes != nil {
		return recordBytes, err
	}
	entries, err := self.pidx(ctx, refId)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		for _, record := range entry.GetRecords() {
			at := record.GetPlace()
			if at.GetMinute() != place.GetMinute() || at.GetInstance() != place.GetInstance() || at.GetSeq() != place.GetSeq() ||
				at.GetOffset() != place.GetOffset() || at.GetLength() != place.GetLength() {
				continue
			}
			cluster, key, err := self.container(entry)
			if err != nil {
				return nil, err
			}
			recordBytes, err := self.getRange(ctx, cluster, key, int64(record.GetOffset()), int64(record.GetLength()))
			if err != nil || recordBytes != nil {
				return recordBytes, err
			}
		}
	}
	return nil, fmt.Errorf("%w: no batch or container holds the record at minute %d", ErrVerifyState, place.GetMinute())
}

// One committed push as verify reads it: its entry versions, its new objects and its DROP body, a seal's joined over
// its parts in part order.
type push struct {
	statement     *sidecar.EvsStatement
	entryVersions [][]byte
	newObjects    []byte
	dropBody      []byte
}

// A payload's sections by type: type u8 | length u32 | bytes, ascending.
func payloadSections(payload []byte) (map[byte][]byte, error) {
	sections := map[byte][]byte{}
	for at := 0; at < len(payload); {
		if len(payload)-at < payloadSectionHeader {
			return nil, fmt.Errorf("%w: a section header cut short", ErrVerifyState)
		}
		sectionType := payload[at]
		length := int(binary.BigEndian.Uint32(payload[at+1 : at+payloadSectionHeader]))
		at += payloadSectionHeader
		if len(payload)-at < length {
			return nil, fmt.Errorf("%w: section %d past the payload's end", ErrVerifyState, sectionType)
		}
		sections[sectionType] = append(sections[sectionType], payload[at:at+length]...)
		at += length
	}
	return sections, nil
}

// The push committed at a window entry's place: a push's or reseed's record, or a seal's with its parts'.
func (self *verifier) readPush(ctx context.Context, refId sidecar.Id, place *protocol.EvsPlace) (*push, error) {
	recordBytes, err := self.recordBytes(ctx, refId, place)
	if err != nil {
		return nil, err
	}
	record, _, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: a record: %v", ErrVerifyState, err)
	}
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		statementBytes, payload, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: a push record: %v", ErrVerifyState, err)
		}
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a statement: %v", ErrVerifyState, err)
		}
		sections, err := payloadSections(payload)
		if err != nil {
			return nil, err
		}
		entryVersions, err := sidecar.EvsPayloadItems(sections[sectionEntryVersions])
		if err != nil {
			return nil, fmt.Errorf("%w: entry versions: %v", ErrVerifyState, err)
		}
		return &push{statement: statement, entryVersions: entryVersions, newObjects: sections[sectionNewObjects], dropBody: sections[sectionDropBody]}, nil
	case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
		statementBytes, parts, err := sidecar.ParseEvsSealRecordBody(record.Body)
		if err != nil {
			return nil, fmt.Errorf("%w: a seal record: %v", ErrVerifyState, err)
		}
		statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: a statement: %v", ErrVerifyState, err)
		}
		joined := &push{statement: statement}
		for _, part := range parts {
			partRecordBytes, err := self.recordBytes(ctx, refId, part.Place)
			if err != nil {
				return nil, err
			}
			partRecord, _, err := sidecar.ParseEvsBatchRecordFormat2(partRecordBytes)
			if err != nil || partRecord.Type != protocol.EvsBatchRecordType_EVS_BATCH_PART {
				return nil, fmt.Errorf("%w: a seal's part is no part record", ErrVerifyState)
			}
			_, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(partRecord.Body)
			if err != nil {
				return nil, fmt.Errorf("%w: a part record: %v", ErrVerifyState, err)
			}
			onePart := &protocol.EvsPushPart{}
			if err := proto.Unmarshal(partBytes, onePart); err != nil {
				return nil, fmt.Errorf("%w: a part does not parse", ErrVerifyState)
			}
			joined.entryVersions = append(joined.entryVersions, onePart.GetEntryVersions()...)
			sections, err := payloadSections(onePart.GetSections())
			if err != nil {
				return nil, err
			}
			joined.newObjects = append(joined.newObjects, sections[sectionNewObjects]...)
			joined.dropBody = append(joined.dropBody, sections[sectionDropBody]...)
		}
		return joined, nil
	}
	return nil, fmt.Errorf("%w: a window entry at a record of type %d", ErrVerifyState, record.Type)
}

// Names(P), 10.2.8's: for each live entry version, every segment id of a kind-1 or kind-5 locator and every slot id;
// on a git-mode ref, every segment id of the new-objects list.
func (self *verifier) names(committed *push, gitMode bool) ([]Id, error) {
	names := []Id{}
	for _, entryBytes := range committed.entryVersions {
		if self.executed[sha256.Sum256(entryBytes)] {
			// listed by an executed drop: not live, marks nothing
			continue
		}
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(entryBytes, entry); err != nil {
			return nil, fmt.Errorf("%w: an entry version does not parse", ErrVerifyState)
		}
		for _, locator := range entry.GetChain() {
			if (locator.GetKind() == locatorKindSegment || locator.GetKind() == locatorKindVersionless) && len(locator.GetId()) == 32 {
				names = append(names, Id{Id: [32]byte(locator.GetId()), Kind: IdKindSegment})
			}
		}
		for _, slotId := range entry.GetSlotIds() {
			if len(slotId) != 16 {
				return nil, fmt.Errorf("%w: a slot id of %d bytes", ErrVerifyState, len(slotId))
			}
			name := Id{Kind: IdKindSlot}
			copy(name.Id[:], slotId)
			names = append(names, name)
		}
	}
	if gitMode && len(committed.newObjects) != 0 {
		items, err := sidecar.EvsPayloadItems(committed.newObjects)
		if err != nil {
			return nil, fmt.Errorf("%w: new objects: %v", ErrVerifyState, err)
		}
		for _, item := range items {
			if len(item) == newObjectSegmentLength && (item[0] == newObjectSegment || item[0] == newObjectStagedSegment) {
				names = append(names, Id{Id: [32]byte(item[1:33]), Kind: IdKindSegment})
			}
		}
	}
	return names, nil
}

// A DROP push's body, nil for any other push.
func (self *verifier) dropBody(committed *push) (*protocol.EvsDropHistory, error) {
	if committed.statement.Push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 || len(committed.dropBody) == 0 {
		return nil, nil
	}
	body := &protocol.EvsDropHistory{}
	if err := proto.Unmarshal(committed.dropBody, body); err != nil {
		return nil, fmt.Errorf("%w: a DROP body does not parse", ErrVerifyState)
	}
	return body, nil
}
