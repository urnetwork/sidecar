// The sealed mirror layout (§11.4's "sealed mirror of evs objects", §11.11, §11.13's durability rows): the evs objects
// this device holds of a repo, in the evs component's sealed directory (§5.9's <component>/) under mirror/<repo>/,
// each family named after the evs object family it copies, so nothing a mirror holds reaches the disk in the clear and
// a re-seed (§19.10) finds history by evs's own names. evs's objects are ciphertext already; the store seals them
// again under the evs class's key, path in the AAD, so a file moved between names fails to open.
//
// On a desktop that mounts the repo (evs_local_mount.go), its plaintext bare repository sits beside the sealed tree,
// never inside it, so no sealed listing walks git's files, and inside the network's directory, so leaving the network
// (§5.9's forget) takes the plaintext with the sealed state:
//
//	<state>/net/<network_id>/
//	  evs/                                  the evs component's sealed directory
//	    mirror/<repo>/                      one repo's mirror
//	      refs/<ref>                        how far the mirror holds the ref: version, C_v and when
//	      stmt/<ref>/<version>              a version's Signed EvsPush, as received
//	      log/<ref>/<page>                  an EvsLogPage, as evs's log/<repo>/<ref>/<n>
//	      rec/<push>/<part>                 a push or seal record (part 0) or a part's record, as §11.9's reads name them
//	      seg/<segment>                     a whole segment, as evs's seg/<repo>/<segment_id>
//	      slot/<slot>                       a slot object, as evs's slot/<repo>/<slot_id>
//	      pmap/<ref>/<epoch>/<map>/<part>   a Signed EvsPathMap part, as evs's pmap/<repo>/<ref>/<p>/<map>/<part>/_
//	    mounts/<repo>                       a mount's record
//	  git/                                  the local tier's plaintext (owner decision 47), desktop legs only
//	    <repo>.git                          a mount's bare repository
//	    <repo>.hooks                        its core.hooksPath
//
// Ids are as evs's object keys hold them (plan-EVS1-format-bytes#9): 32 lowercase hex characters for repo, ref, push
// and slot ids, 64 for segment ids and map hashes. Versions, pages, epochs and parts are 20 decimal digits, so a
// listing sorts by number.
//
// What a family holds (§11.13's contents row) and how it changes:
//   - every family but slot/ is immutable, as evs's are: written once, a second put of equal bytes is success and of
//     other bytes is refused, so a mirror never rewrites history it holds;
//   - a segment's name is its SHA-256, checked as it is written; anything else a put stores is what its caller
//     verified (§11.9's reader checks), the mirror holding each body only to its family's bound;
//   - slot/ follows evs's object, which evs rewrites only to drop erased keys, so a put replaces it, and an ERASE,
//     CONSUME or executed drop applied removes it (§11.12's after row, §11.11's drops);
//   - refs/ moves only forward: a lower version, or the same version on another chain, is refused (I-16);
//   - removal is the caller's: a drop's listed content, an erased slot copy, or the whole mirror once this device no
//     longer reads the repo (§5.9's delete row).
//
// EvsMirror (EVSB-M2-19) decides what a full mirror holds, its coverage and its hash checks, and keeps any state of its
// own under mirror/<repo>/ beside these families. On every leg, since head-mode devices mirror too (§11.13's iOS-only
// row). Safe for concurrent use; EvsClient.Mirror keeps one per repo, so a repo's puts serialize.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The mirrors' directory in the evs component's store, and the families' directories in a mirror.
const (
	evsMirrorDirectory    = "mirror"
	evsMirrorRefDirectory = "refs"
)

// §11.8's log page bound: versions 64n to 64n+63, their window entries, statements and chain ends.
const EvsLogPageMaxByteCount = 70 * 1024

// A number's digits in a mirror name: a u64 at its widest.
const evsMirrorNumberDigitCount = 20

var (
	// An immutable mirror object put again with other bytes. The mirror keeps what it holds.
	ErrEvsMirrorConflict = errors.New("evs: mirror object conflicts with the one held")
	// A mirror key or body that does not fit its family: a wrong id length, a version 0, an empty body, one past the
	// family's bound, or a segment whose SHA-256 is not its id.
	ErrEvsMirrorObjectInvalid = errors.New("evs: mirror object invalid")
	// A mirrored ref raised below the version the mirror holds.
	ErrEvsMirrorRefLower = errors.New("evs: mirrored ref below the one held")
	// A mirrored ref raised at the version the mirror holds, on another chain: a fork.
	ErrEvsMirrorRefFork = errors.New("evs: mirrored ref forks from the one held")
)

// A family of a repo's mirror, by its directory there.
type EvsMirrorFamily string

const (
	// A version's Signed EvsPush, by ref and version.
	EvsMirrorStatements EvsMirrorFamily = "stmt"
	// An EvsLogPage, by ref and page.
	EvsMirrorLogPages EvsMirrorFamily = "log"
	// A batch record, by push id and part.
	EvsMirrorRecords EvsMirrorFamily = "rec"
	// A whole segment, by its SHA-256.
	EvsMirrorSegments EvsMirrorFamily = "seg"
	// A slot object, by slot id.
	EvsMirrorSlots EvsMirrorFamily = "slot"
	// A Signed EvsPathMap part, by ref, path epoch, path_map_sha256 and part.
	EvsMirrorMapParts EvsMirrorFamily = "pmap"
)

// The bound evs holds the family's objects to, 0 for no family.
func (self EvsMirrorFamily) maxByteCount() int64 {
	switch self {
	case EvsMirrorStatements:
		return EvsStatementMaxByteCount
	case EvsMirrorLogPages:
		return EvsLogPageMaxByteCount
	case EvsMirrorRecords:
		return EvsBatchMaxRecordByteCount
	case EvsMirrorSegments:
		return EvsSegmentMaxByteCount
	case EvsMirrorSlots:
		return evsSlotMaxByteCount
	case EvsMirrorMapParts:
		return EvsPathMapMaxByteCount
	}
	return 0
}

// Whether the family's objects never change once written.
func (self EvsMirrorFamily) immutable() bool {
	return self != EvsMirrorSlots
}

// One object of a repo's mirror: its family and the ids evs's reads name it by (EvsReadObject, EvsReadStatement).
type EvsMirrorKey struct {
	Family EvsMirrorFamily
	// A statement's, log page's or map part's ref.
	RefId Id
	// A record's push id, a segment's or slot's id, or a map part's path_map_sha256.
	ObjectId []byte
	// A statement's version, a log page's number, or a record's or map part's part.
	Number uint64
	// A map part's path epoch.
	PathEpoch uint64
}

// The statement of refId at version.
func EvsMirrorStatementKey(refId Id, version uint64) EvsMirrorKey {
	return EvsMirrorKey{Family: EvsMirrorStatements, RefId: refId, Number: version}
}

// Log page page of refId: versions 64 page to 64 page + 63.
func EvsMirrorLogPageKey(refId Id, page uint64) EvsMirrorKey {
	return EvsMirrorKey{Family: EvsMirrorLogPages, RefId: refId, Number: page}
}

// A push's record: part 0 its push or seal record, else that part's.
func EvsMirrorRecordKey(pushId Id, part uint32) EvsMirrorKey {
	return EvsMirrorKey{Family: EvsMirrorRecords, ObjectId: pushId.Bytes(), Number: uint64(part)}
}

// The segment whose SHA-256 is segmentId.
func EvsMirrorSegmentKey(segmentId []byte) EvsMirrorKey {
	return EvsMirrorKey{Family: EvsMirrorSegments, ObjectId: bytes.Clone(segmentId)}
}

// A slot object.
func EvsMirrorSlotKey(slotId []byte) EvsMirrorKey {
	return EvsMirrorKey{Family: EvsMirrorSlots, ObjectId: bytes.Clone(slotId)}
}

// One part of refId's path map for pathEpoch.
func EvsMirrorMapPartKey(refId Id, pathEpoch uint64, mapSha256 []byte, part uint32) EvsMirrorKey {
	return EvsMirrorKey{
		Family:    EvsMirrorMapParts,
		RefId:     refId,
		ObjectId:  bytes.Clone(mapSha256),
		Number:    uint64(part),
		PathEpoch: pathEpoch,
	}
}

// A number as a mirror name holds it.
func evsMirrorNumber(number uint64) string {
	return fmt.Sprintf("%0*d", evsMirrorNumberDigitCount, number)
}

// The name inside a repo's mirror directory, or ErrEvsMirrorObjectInvalid for a key its family does not fit.
func (self EvsMirrorKey) Name() (string, error) {
	objectId := func(byteCount int) (string, error) {
		if len(self.ObjectId) != byteCount {
			return "", fmt.Errorf("%w: a %s id of %d bytes", ErrEvsMirrorObjectInvalid, self.Family, len(self.ObjectId))
		}
		return hex.EncodeToString(self.ObjectId), nil
	}
	part := func() (string, error) {
		if math.MaxUint32 < self.Number {
			return "", fmt.Errorf("%w: a %s part past 32 bits", ErrEvsMirrorObjectInvalid, self.Family)
		}
		return evsMirrorNumber(self.Number), nil
	}
	family := string(self.Family)
	switch self.Family {
	case EvsMirrorStatements:
		// versions start at 1: version 0 is the empty ref, which no statement made
		if self.Number == 0 {
			return "", fmt.Errorf("%w: a statement at version 0", ErrEvsMirrorObjectInvalid)
		}
		return family + "/" + evsUrlId(self.RefId) + "/" + evsMirrorNumber(self.Number), nil
	case EvsMirrorLogPages:
		return family + "/" + evsUrlId(self.RefId) + "/" + evsMirrorNumber(self.Number), nil
	case EvsMirrorRecords:
		pushId, err := objectId(16)
		if err != nil {
			return "", err
		}
		partName, err := part()
		if err != nil {
			return "", err
		}
		return family + "/" + pushId + "/" + partName, nil
	case EvsMirrorSegments:
		segmentId, err := objectId(sha256.Size)
		if err != nil {
			return "", err
		}
		return family + "/" + segmentId, nil
	case EvsMirrorSlots:
		slotId, err := objectId(16)
		if err != nil {
			return "", err
		}
		return family + "/" + slotId, nil
	case EvsMirrorMapParts:
		mapSha256, err := objectId(sha256.Size)
		if err != nil {
			return "", err
		}
		partName, err := part()
		if err != nil {
			return "", err
		}
		return family + "/" + evsUrlId(self.RefId) + "/" + evsMirrorNumber(self.PathEpoch) + "/" + mapSha256 + "/" + partName, nil
	}
	return "", fmt.Errorf("%w: no mirror family %q", ErrEvsMirrorObjectInvalid, self.Family)
}

// The key a name inside a repo's mirror directory stands for, refusing any name Name would not give.
func ParseEvsMirrorName(name string) (EvsMirrorKey, error) {
	refused := fmt.Errorf("%w: no mirror object is named %q", ErrEvsMirrorObjectInvalid, name)
	segments := strings.Split(name, "/")
	lowerHex := func(text string, byteCount int) ([]byte, bool) {
		decoded, err := hex.DecodeString(text)
		if err != nil || len(decoded) != byteCount || hex.EncodeToString(decoded) != text {
			return nil, false
		}
		return decoded, true
	}
	number := func(text string) (uint64, bool) {
		if len(text) != evsMirrorNumberDigitCount {
			return 0, false
		}
		for i := 0; i < len(text); i += 1 {
			if text[i] < '0' || '9' < text[i] {
				return 0, false
			}
		}
		value, err := strconv.ParseUint(text, 10, 64)
		return value, err == nil
	}
	refId := func(text string) (Id, bool) {
		idBytes, ok := lowerHex(text, 16)
		if !ok {
			return Id{}, false
		}
		return Id(idBytes), true
	}
	var key EvsMirrorKey
	ok := false
	switch EvsMirrorFamily(segments[0]) {
	case EvsMirrorStatements, EvsMirrorLogPages:
		if len(segments) == 3 {
			key.Family = EvsMirrorFamily(segments[0])
			var refOk, numberOk bool
			key.RefId, refOk = refId(segments[1])
			key.Number, numberOk = number(segments[2])
			ok = refOk && numberOk
		}
	case EvsMirrorRecords:
		if len(segments) == 3 {
			key.Family = EvsMirrorRecords
			var idOk, numberOk bool
			key.ObjectId, idOk = lowerHex(segments[1], 16)
			key.Number, numberOk = number(segments[2])
			ok = idOk && numberOk
		}
	case EvsMirrorSegments:
		if len(segments) == 2 {
			key.Family = EvsMirrorSegments
			key.ObjectId, ok = lowerHex(segments[1], sha256.Size)
		}
	case EvsMirrorSlots:
		if len(segments) == 2 {
			key.Family = EvsMirrorSlots
			key.ObjectId, ok = lowerHex(segments[1], 16)
		}
	case EvsMirrorMapParts:
		if len(segments) == 5 {
			key.Family = EvsMirrorMapParts
			var refOk, epochOk, idOk, numberOk bool
			key.RefId, refOk = refId(segments[1])
			key.PathEpoch, epochOk = number(segments[2])
			key.ObjectId, idOk = lowerHex(segments[3], sha256.Size)
			key.Number, numberOk = number(segments[4])
			ok = refOk && epochOk && idOk && numberOk
		}
	}
	if !ok {
		return EvsMirrorKey{}, refused
	}
	// the name a key gives is the only one it parses from: version 0, a part past 32 bits
	if again, err := key.Name(); err != nil || again != name {
		return EvsMirrorKey{}, refused
	}
	return key, nil
}

// How far a repo's mirror holds one ref: every object the ref's versions through Version name, as its caller
// verified them.
type EvsMirrorRef struct {
	RefId   Id
	Version uint64
	Chain   [sha256.Size]byte
	// When the mirror last reached a head of the ref, which §11.13's status row holds to the hour.
	MirroredAt time.Time
}

// A mirrored ref's stored form.
type evsMirrorRefRecord struct {
	RefId        string `json:"ref_id"`
	Version      uint64 `json:"version"`
	Chain        string `json:"chain"`
	MirroredAtMs int64  `json:"mirrored_at_ms"`
}

// One repo's sealed mirror.
type EvsMirrorStore struct {
	repoId Id
	// the evs component's directory narrowed to mirror/<repo>
	store SidecarStore

	// serializes each change's check and write, so two puts of one name cannot both find it absent
	writeLock sync.Mutex
}

// The mirror of repoId in component, the evs component's sealed directory. Nothing is written until a change.
func newEvsMirrorStore(component SidecarStore, repoId Id) (*EvsMirrorStore, error) {
	store, err := component.Directory(evsMirrorDirectory+"/"+evsUrlId(repoId), "")
	if err != nil {
		return nil, err
	}
	return &EvsMirrorStore{repoId: repoId, store: store}, nil
}

// The repo mirrored.
func (self *EvsMirrorStore) RepoId() Id {
	return self.repoId
}

// The SHA-256 of what name holds, nil when nothing is there.
func (self *EvsMirrorStore) heldSha256(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, reader); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// Keeps body under key by its family's rule: an immutable object once, a second put of equal bytes changing nothing
// and of other bytes refused (ErrEvsMirrorConflict); a slot copy replacing the one held. body streams, never held
// whole, and is read to its end or one byte past its family's bound; an empty one, one past the bound, and a segment
// whose SHA-256 is not its id are refused (ErrEvsMirrorObjectInvalid). A refused put leaves what was held.
func (self *EvsMirrorStore) Put(key EvsMirrorKey, body io.Reader) error {
	name, err := key.Name()
	if err != nil {
		return err
	}
	maxByteCount := key.Family.maxByteCount()
	// the body's SHA-256, after its bound and the segment rule
	check := func(byteCount int64, hash []byte) error {
		if byteCount == 0 {
			return fmt.Errorf("%w: an empty %s", ErrEvsMirrorObjectInvalid, key.Family)
		}
		if maxByteCount < byteCount {
			return fmt.Errorf("%w: a %s past %d bytes", ErrEvsMirrorObjectInvalid, key.Family, maxByteCount)
		}
		if key.Family == EvsMirrorSegments && !bytes.Equal(hash, key.ObjectId) {
			return fmt.Errorf("%w: a segment whose SHA-256 is not its id", ErrEvsMirrorObjectInvalid)
		}
		return nil
	}

	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	if key.Family.immutable() {
		heldHash, err := self.heldSha256(name)
		if err != nil {
			return err
		}
		if heldHash != nil {
			// held: the body is only compared, never written
			hash := sha256.New()
			byteCount, err := io.Copy(hash, io.LimitReader(body, maxByteCount+1))
			if err != nil {
				return err
			}
			sum := hash.Sum(nil)
			if err := check(byteCount, sum); err != nil {
				return err
			}
			if !bytes.Equal(sum, heldHash) {
				return fmt.Errorf("%w: %s", ErrEvsMirrorConflict, key.Family)
			}
			return nil
		}
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	// drops the file unless Commit took it
	defer writer.Close()
	hash := sha256.New()
	byteCount, err := io.Copy(io.MultiWriter(writer, hash), io.LimitReader(body, maxByteCount+1))
	if err != nil {
		return err
	}
	if err := check(byteCount, hash.Sum(nil)); err != nil {
		return err
	}
	return writer.Commit()
}

// Streams the object held under key, ErrSidecarStoreAbsent when none is. A file that fails its seal answers
// ErrSidecarStoreFailed from Read, as the store's do.
func (self *EvsMirrorStore) Open(key EvsMirrorKey) (io.ReadCloser, error) {
	name, err := key.Name()
	if err != nil {
		return nil, err
	}
	return self.store.Open(name)
}

// Whether a file is held under key. Whether it opens is Open's to say.
func (self *EvsMirrorStore) Has(key EvsMirrorKey) (bool, error) {
	reader, err := self.Open(key)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	reader.Close()
	return true, nil
}

// Takes the object under key away: a drop's listed content, or a slot copy an ERASE, CONSUME or drop removed.
// Nothing there is not an error.
func (self *EvsMirrorStore) Remove(key EvsMirrorKey) error {
	name, err := key.Name()
	if err != nil {
		return err
	}
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	return self.store.Remove(name)
}

// The keys family holds, in name order, so a ref's statements and pages come by number. refId narrows statements, log
// pages and map parts to one ref; nil lists every ref's. A file whose name no key gives is not an object, and is
// left out.
func (self *EvsMirrorStore) List(family EvsMirrorFamily, refId *Id) ([]EvsMirrorKey, error) {
	if family.maxByteCount() == 0 {
		return nil, fmt.Errorf("%w: no mirror family %q", ErrEvsMirrorObjectInvalid, family)
	}
	prefix := string(family) + "/"
	if refId != nil {
		switch family {
		case EvsMirrorStatements, EvsMirrorLogPages, EvsMirrorMapParts:
			prefix += evsUrlId(*refId) + "/"
		default:
			return nil, fmt.Errorf("%w: %s is not kept by ref", ErrEvsMirrorObjectInvalid, family)
		}
	}
	entries, err := self.store.List(prefix)
	if err != nil {
		return nil, err
	}
	keys := make([]EvsMirrorKey, 0, len(entries))
	for _, entry := range entries {
		key, err := ParseEvsMirrorName(entry.Name)
		if err != nil {
			continue
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// The name of refId's mirrored ref.
func evsMirrorRefName(refId Id) string {
	return evsMirrorRefDirectory + "/" + evsUrlId(refId)
}

// The ref a stored record gives.
func (self *evsMirrorRefRecord) ref() (*EvsMirrorRef, error) {
	refIdBytes, err := hex.DecodeString(self.RefId)
	if err != nil || len(refIdBytes) != 16 {
		return nil, fmt.Errorf("%w: a mirrored ref's id", ErrSidecarStoreFailed)
	}
	chainBytes, err := hex.DecodeString(self.Chain)
	if err != nil || len(chainBytes) != sha256.Size {
		return nil, fmt.Errorf("%w: a mirrored ref's chain", ErrSidecarStoreFailed)
	}
	ref := &EvsMirrorRef{RefId: Id(refIdBytes), Version: self.Version, MirroredAt: time.UnixMilli(self.MirroredAtMs).UTC()}
	copy(ref.Chain[:], chainBytes)
	return ref, nil
}

// How far the mirror holds refId, false when it holds nothing of it.
func (self *EvsMirrorStore) Ref(refId Id) (*EvsMirrorRef, bool, error) {
	reader, err := self.store.Open(evsMirrorRefName(refId))
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, false, err
	}
	record := &evsMirrorRefRecord{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, false, fmt.Errorf("%w: a mirrored ref that does not parse", ErrSidecarStoreFailed)
	}
	ref, err := record.ref()
	if err != nil {
		return nil, false, err
	}
	if ref.RefId != refId {
		return nil, false, fmt.Errorf("%w: a mirrored ref under another ref's name", ErrSidecarStoreFailed)
	}
	return ref, true, nil
}

// Every ref the mirror holds, by ref id.
func (self *EvsMirrorStore) Refs() ([]*EvsMirrorRef, error) {
	entries, err := self.store.List(evsMirrorRefDirectory + "/")
	if err != nil {
		return nil, err
	}
	refs := make([]*EvsMirrorRef, 0, len(entries))
	for _, entry := range entries {
		refIdBytes, err := hex.DecodeString(strings.TrimPrefix(entry.Name, evsMirrorRefDirectory+"/"))
		if err != nil || len(refIdBytes) != 16 {
			continue
		}
		ref, ok, err := self.Ref(Id(refIdBytes))
		if err != nil {
			return nil, err
		}
		if ok {
			refs = append(refs, ref)
		}
	}
	return refs, nil
}

// Records that the mirror holds ref through its version, durably, once every object those versions name is put.
// Refuses a lower version (ErrEvsMirrorRefLower) and the same version on another chain (ErrEvsMirrorRefFork); the same
// ref again only moves its time.
func (self *EvsMirrorStore) RaiseRef(ref *EvsMirrorRef) error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	held, ok, err := self.Ref(ref.RefId)
	if err != nil {
		return err
	}
	if ok {
		if ref.Version < held.Version {
			return ErrEvsMirrorRefLower
		}
		if ref.Version == held.Version && ref.Chain != held.Chain {
			return ErrEvsMirrorRefFork
		}
	}
	data, err := json.Marshal(&evsMirrorRefRecord{
		RefId:        evsUrlId(ref.RefId),
		Version:      ref.Version,
		Chain:        hex.EncodeToString(ref.Chain[:]),
		MirroredAtMs: ref.MirroredAt.UnixMilli(),
	})
	if err != nil {
		return err
	}
	writer, err := self.store.Create(evsMirrorRefName(ref.RefId))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(data); err != nil {
		return err
	}
	return writer.Commit()
}

// Takes the whole mirror away: every family and every file kept beside them, as when this device no longer reads the
// repo, or it is deleted or shredded (§5.9's delete row).
func (self *EvsMirrorStore) Forget() error {
	self.writeLock.Lock()
	defer self.writeLock.Unlock()
	entries, err := self.store.List("")
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if err := self.store.Remove(entry.Name); err != nil {
			return err
		}
	}
	return nil
}
