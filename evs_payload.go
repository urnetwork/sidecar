// A push's payload and §11.6's checks row, one codec for the client that builds a push, evs that checks it at 5b, and
// readers that replay it. A payload is sections of type u8 | length u32 | bytes, ascending, each at most once and
// absent when empty (plan-EVS1-format-bytes#7); a section's repeated items are u32 length | bytes, but for part
// hashes, which are bare 32 B values; each *_sha256 field of the statement hashes its section's bytes as received.
// EVS-FORMAT.md's payload table gives every section.
//
// The checks run over a statement already parsed (ParseEvsStatement) and the payload's received bytes, and touch no
// store: each entry version hashes to its change's entry_sha256, the change list matches changes_root and change_count
// and is strictly sorted by token path, changed_prefixes cover it, each listed section matches its statement hash,
// and every item parses to what format 1 writes. What needs the head or the store (5a and 5c to 5h) is evs's. A push
// in parts is checked part by part as each arrives (EvsCheckPart), and whole at its seal (EvsCheckSeal), which joins
// the parts' slices into the one-part payload they spell.
//
// Two answers wait on open questions and fail closed meanwhile: section 3 and EvsPushPart.inline_records, which
// questions/evs1-m2-01-inline-record-home leaves to the locators, are refused if set; and no section carries a ref's
// sealed name or an overlay's base (questions/evs1-m2-01-ref-creation-fields). Format 2's DROP sections and staged
// segments are refused as FORMAT_UNSUPPORTED.
//
// Format 2 (EVS-FORMAT.md's format 2 chapter) runs the same checks through EvsCheckPayloadFormat2, EvsCheckPartFormat2
// and EvsCheckSealFormat2, which take what format 1 refuses as needing format 2: versioning 1 and 2, kind-5 and staged
// locators, staged new objects with their staged bytes, which each must match (evs_staged.go), and versionless
// receipts. Its DROP sections are evs_drop_payload.go's. Whether a version may cite what it names is §11.7's citation
// rule, EvsCheckCitation's, which needs the versions step 4 reads.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// §11.6's and §11.8's payload, part and statement bounds.
const (
	// a signed statement, as received
	EvsStatementMaxByteCount = 1024
	// a one-part push's payload, and a part: past either a push goes in parts
	EvsPayloadMaxByteCount = 1024 * 1024
	EvsPartMaxByteCount    = 1024 * 1024
	// the entry writes one part, or a one-part push, carries
	EvsPartMaxEntryWriteCount = 1024
	// changed_prefixes' token bytes in all
	EvsChangedPrefixesMaxByteCount = 512

	evsPayloadSectionHeaderByteCount = 5
	evsPayloadMaxSectionType         = 14
	evsNewSegmentItemByteCount       = 1 + 32 + 8 + 4
	evsNewSlotItemByteCount          = 1 + 16 + 8 + 4
	evsErasedItemByteCount           = 16 + 2
)

// The sections that ride in an EvsPushPart's own fields, never in its sections: entry versions, sealed metadata,
// inline records and the change list.
var evsPartFieldSections = []protocol.EvsPayloadSection{
	protocol.EvsPayloadSection_EVS_PAYLOAD_ENTRY_VERSIONS, protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA,
	protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS, protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST,
}

// A payload's sections by type, each as received.
type EvsPayload struct {
	sections [evsPayloadMaxSectionType + 1][]byte
}

// The sections of a payload's bytes: ascending types 1 to 14, each once and none empty, nothing after the last.
// Format 2's DROP sections are ErrEvsFormatUnsupported.
func ParseEvsPayload(payloadBytes []byte) (*EvsPayload, error) {
	return parseEvsPayload(payloadBytes, false)
}

// The sections of a payload's bytes as ParseEvsPayload reads them, a format-2 payload's DROP sections taken.
func parseEvsPayload(payloadBytes []byte, format2 bool) (*EvsPayload, error) {
	payload := &EvsPayload{}
	last := 0
	for at := 0; at < len(payloadBytes); {
		if len(payloadBytes)-at < evsPayloadSectionHeaderByteCount {
			return nil, fmt.Errorf("%w: a section header cut short", ErrEvsPushInvalid)
		}
		sectionType := int(payloadBytes[at])
		length := int(binary.BigEndian.Uint32(payloadBytes[at+1 : at+5]))
		at += evsPayloadSectionHeaderByteCount
		if sectionType <= last || evsPayloadMaxSectionType < sectionType {
			return nil, fmt.Errorf("%w: section %d after %d", ErrEvsPushInvalid, sectionType, last)
		}
		if length == 0 || len(payloadBytes)-at < length {
			return nil, fmt.Errorf("%w: section %d of %d bytes", ErrEvsPushInvalid, sectionType, length)
		}
		switch protocol.EvsPayloadSection(sectionType) {
		case protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY, protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS:
			if !format2 {
				return nil, fmt.Errorf("%w: a DROP section", ErrEvsFormatUnsupported)
			}
		}
		payload.sections[sectionType] = payloadBytes[at : at+length]
		at += length
		last = sectionType
	}
	return payload, nil
}

// A section's bytes, nil when absent.
func (self *EvsPayload) Section(sectionType protocol.EvsPayloadSection) []byte {
	if sectionType <= 0 || evsPayloadMaxSectionType < sectionType {
		return nil
	}
	return self.sections[sectionType]
}

// Sets a section, absent when sectionBytes is empty.
func (self *EvsPayload) SetSection(sectionType protocol.EvsPayloadSection, sectionBytes []byte) {
	if 0 < sectionType && sectionType <= evsPayloadMaxSectionType {
		self.sections[sectionType] = sectionBytes
	}
}

// The payload's bytes, sections ascending.
func (self *EvsPayload) Encode() []byte {
	encoded := []byte{}
	for sectionType, sectionBytes := range self.sections {
		if len(sectionBytes) == 0 {
			continue
		}
		encoded = append(encoded, byte(sectionType))
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(sectionBytes)))
		encoded = append(encoded, sectionBytes...)
	}
	return encoded
}

// A section's items, each u32 length | bytes, nothing after the last.
func EvsPayloadItems(sectionBytes []byte) ([][]byte, error) {
	items := [][]byte{}
	for at := 0; at < len(sectionBytes); {
		if len(sectionBytes)-at < 4 {
			return nil, fmt.Errorf("%w: an item's length cut short", ErrEvsPushInvalid)
		}
		length := int(binary.BigEndian.Uint32(sectionBytes[at : at+4]))
		at += 4
		if len(sectionBytes)-at < length {
			return nil, fmt.Errorf("%w: an item of %d bytes past its section", ErrEvsPushInvalid, length)
		}
		items = append(items, sectionBytes[at:at+length])
		at += length
	}
	return items, nil
}

// items as a section: each u32 length | bytes.
func evsJoinItems(items [][]byte) []byte {
	joined := []byte{}
	for _, item := range items {
		joined = binary.BigEndian.AppendUint32(joined, uint32(len(item)))
		joined = append(joined, item...)
	}
	return joined
}

// A segment or slot a push introduces (§11.6's payload row).
type EvsNewObject struct {
	Kind protocol.EvsNewObjectKind
	// a segment's 32 B id or a slot's 16 B
	Id         []byte
	PaddedSize uint64
	// days since the Unix epoch of its receipt's upload, 0 for a slot
	UploadDay uint32
}

// kind u8 | id | padded_size u64 | upload_day u32.
func (self *EvsNewObject) encode() []byte {
	encoded := append([]byte{byte(self.Kind)}, self.Id...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.PaddedSize)
	return binary.BigEndian.AppendUint32(encoded, self.UploadDay)
}

// One new-objects item held to format 1: a segment of a Padmé size within 8 MiB uploaded on a day, or a slot.
// Format 2's staged segment is ErrEvsFormatUnsupported.
func decodeEvsNewObject(item []byte) (*EvsNewObject, error) {
	return decodeEvsNewObjectOf(item, false)
}

// One new-objects item as decodeEvsNewObject holds it, format 2 adding a staged segment: a 32 B id, a Padmé size of
// at most 16 KiB that holds a kind-5 header and a record header, and upload day 0.
func decodeEvsNewObjectOf(item []byte, format2 bool) (*EvsNewObject, error) {
	if len(item) == 0 {
		return nil, fmt.Errorf("%w: an empty new-objects item", ErrEvsPushInvalid)
	}
	kind := protocol.EvsNewObjectKind(item[0])
	switch kind {
	case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
		if len(item) != evsNewSegmentItemByteCount {
			return nil, fmt.Errorf("%w: a segment item of %d bytes", ErrEvsPushInvalid, len(item))
		}
	case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT:
		if len(item) != evsNewSlotItemByteCount {
			return nil, fmt.Errorf("%w: a slot item of %d bytes", ErrEvsPushInvalid, len(item))
		}
	case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
		if !format2 {
			return nil, fmt.Errorf("%w: a staged segment", ErrEvsFormatUnsupported)
		}
		if len(item) != evsNewSegmentItemByteCount {
			return nil, fmt.Errorf("%w: a staged item of %d bytes", ErrEvsPushInvalid, len(item))
		}
	default:
		return nil, fmt.Errorf("%w: new object kind %d", ErrEvsPushInvalid, kind)
	}
	idLength := len(item) - 1 - 8 - 4
	object := &EvsNewObject{
		Kind:       kind,
		Id:         bytes.Clone(item[1 : 1+idLength]),
		PaddedSize: binary.BigEndian.Uint64(item[1+idLength : 9+idLength]),
		UploadDay:  binary.BigEndian.Uint32(item[9+idLength:]),
	}
	switch kind {
	case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT:
		if !EvsIsPadme(object.PaddedSize) || EvsSegmentMaxByteCount < object.PaddedSize || object.UploadDay == 0 {
			return nil, fmt.Errorf("%w: a segment of %d bytes on day %d", ErrEvsPushInvalid, object.PaddedSize, object.UploadDay)
		}
	case protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT:
		if !EvsIsPadme(object.PaddedSize) || EvsStagedSegmentMaxByteCount < object.PaddedSize ||
			object.PaddedSize < EvsKind5SegmentHeaderByteCount+EvsRecordHeaderByteCount || object.UploadDay != 0 {
			return nil, fmt.Errorf("%w: a staged segment of %d bytes on day %d", ErrEvsPushInvalid, object.PaddedSize, object.UploadDay)
		}
	default:
		if object.PaddedSize != 0 || object.UploadDay != 0 {
			return nil, fmt.Errorf("%w: a slot with a size or day", ErrEvsPushInvalid)
		}
	}
	return object, nil
}

// A key an ERASE or CLOSURE names (§11.12).
type EvsErasedKey struct {
	SlotId   Id
	KeyIndex uint16
}

// A committed version whose segments a new version cites (§11.8's 5h), which the reuse list points evs at.
type EvsReuse struct {
	RefId        Id
	EntryVersion uint64
	TokenPath    EvsTokenPath
}

// ref_id 16 | entry version u64 | its token path.
func (self *EvsReuse) encode() []byte {
	encoded := append(self.RefId.Bytes(), make([]byte, 0, 8)...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.EntryVersion)
	return append(encoded, self.TokenPath.Bytes()...)
}

// One reuse item.
func decodeEvsReuse(item []byte) (*EvsReuse, error) {
	if len(item) < 16+8+EvsTokenByteCount || (len(item)-24)%EvsTokenByteCount != 0 {
		return nil, fmt.Errorf("%w: a reuse item of %d bytes", ErrEvsPushInvalid, len(item))
	}
	components := [][]byte{}
	for at := 24; at < len(item); at += EvsTokenByteCount {
		components = append(components, item[at:at+EvsTokenByteCount])
	}
	tokenPath, err := ParseEvsChangedTokenPath(components)
	if err != nil {
		return nil, err
	}
	return &EvsReuse{RefId: Id(item[0:16]), EntryVersion: binary.BigEndian.Uint64(item[16:24]), TokenPath: tokenPath}, nil
}

// A change of a push as checked: its message, its leaf as listed (nil when the list is inline), its path, its entry
// version as received (nil for a removal) and its source paths' encodings.
type EvsCheckedChange struct {
	Change       *protocol.EvsChange
	Leaf         []byte
	TokenPath    EvsTokenPath
	EntryVersion []byte
	SourcePaths  [][]byte
}

// Whether it writes an entry version, rather than removing the path.
func (self *EvsCheckedChange) WritesEntry() bool {
	return len(self.Change.GetEntrySha256()) != 0
}

// What the checks found, for the steps after them: the changes in their order and each section's items.
type EvsCheckedPayload struct {
	Changes        []*EvsCheckedChange
	SealedMetadata []byte
	NewObjects     []*EvsNewObject
	SlotBodies     [][]byte
	Erased         []*EvsErasedKey
	TailMoves      [][]byte
	ReuseList      []*EvsReuse
	// a change creating a path, or a directory delta adding a name: the window's bit 0
	CreatesPath bool
	// format 2: the staged segments, one per kind-2 new-objects item and in that order
	Staged []*EvsStagedSegment
	// format 2: a DROP's body and lists, as EvsCheckDropPayload checked them; nil for any other push
	Drop *EvsCheckedDrop
}

// Each change's token path, for the window's digest.
func (self *EvsCheckedPayload) ChangedPaths() []EvsTokenPath {
	paths := make([]EvsTokenPath, len(self.Changes))
	for i, change := range self.Changes {
		paths[i] = change.TokenPath
	}
	return paths
}

// One change message held to format 1: a path, a base, and an entry hash of 32 bytes or none.
func checkEvsChange(change *protocol.EvsChange) (EvsTokenPath, error) {
	tokenPath, err := ParseEvsChangedTokenPath(change.GetTokenPath())
	if err != nil {
		return nil, err
	}
	if entryHash := change.GetEntrySha256(); len(entryHash) != 0 && len(entryHash) != sha256.Size {
		return nil, fmt.Errorf("%w: an entry hash of %d bytes", ErrEvsPushInvalid, len(entryHash))
	}
	return tokenPath, nil
}

// An entry version held to format 1 for its push: written by this push at its base, a file with sealed fields and a
// chain of segment or inline locators, or a directory with neither.
// Format 2's versioning, kind-5 locators and staged segments are ErrEvsFormatUnsupported; locator kinds 3 and 4 and
// any layout but 0 are reserved, so refused. Whether it adds a name, for the window's bit 0.
func checkEvsEntryVersion(entryBytes []byte, push *protocol.EvsPush) (bool, error) {
	return checkEvsEntryVersionOf(entryBytes, push, false)
}

// An entry version as checkEvsEntryVersion holds it, format 2 adding versioning 1 and 2 on a file, past 2 malformed,
// and kind-5 and staged locators. Which versions may carry which locators is EvsCheckCitation's, answering 409.
func checkEvsEntryVersionOf(entryBytes []byte, push *protocol.EvsPush, format2 bool) (bool, error) {
	entry := &protocol.EvsEntryVersion{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return false, fmt.Errorf("%w: an entry version that does not parse", ErrEvsPushInvalid)
	}
	if entry.GetVersioning() != 0 {
		if !format2 {
			return false, fmt.Errorf("%w: versioning %d", ErrEvsFormatUnsupported, entry.GetVersioning())
		}
		if uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX) < entry.GetVersioning() ||
			entry.GetKind() != uint32(protocol.EvsEntryKind_EVS_ENTRY_FILE) {
			return false, fmt.Errorf("%w: versioning %d on kind %d", ErrEvsPushInvalid, entry.GetVersioning(), entry.GetKind())
		}
	}
	// the version rule is 5g's, which answers 409 on the head it reads, so it is not checked here
	if !bytes.Equal(entry.GetPushId(), push.GetPushId()) || entry.GetBaseVersion() != push.GetBaseVersion() {
		return false, fmt.Errorf("%w: an entry version of another push or base", ErrEvsPushInvalid)
	}
	for _, slotId := range entry.GetSlotIds() {
		if len(slotId) != 16 {
			return false, fmt.Errorf("%w: a slot id of %d bytes", ErrEvsPushInvalid, len(slotId))
		}
	}
	if entry.GetLayout() != 0 {
		return false, fmt.Errorf("%w: directory layout %d is reserved", ErrEvsPushInvalid, entry.GetLayout())
	}
	switch protocol.EvsEntryKind(entry.GetKind()) {
	case protocol.EvsEntryKind_EVS_ENTRY_FILE:
		if len(entry.GetSealedFields()) == 0 || len(entry.GetChain()) == 0 || entry.GetNames() != nil {
			return false, fmt.Errorf("%w: a file without sealed fields or a chain, or with names", ErrEvsPushInvalid)
		}
		for _, locator := range entry.GetChain() {
			if err := checkEvsLocatorOf(locator, format2); err != nil {
				return false, err
			}
		}
		return false, nil
	case protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY:
		if len(entry.GetSealedFields()) != 0 || len(entry.GetChain()) != 0 {
			return false, fmt.Errorf("%w: a directory with sealed fields or a chain", ErrEvsPushInvalid)
		}
		return 0 < len(entry.GetNames().GetNames()), nil
	default:
		return false, fmt.Errorf("%w: entry kind %d", ErrEvsPushInvalid, entry.GetKind())
	}
}

// A locator format 1 writes: a segment by its 32 B id and a record's place in it, or a record inline of at most
// 16 KiB.
func checkEvsLocator(locator *protocol.EvsLocator) error {
	return checkEvsLocatorOf(locator, false)
}

// A locator as checkEvsLocator holds it, format 2 adding kind 5, a versionless segment by its 32 B id and the place
// of its one record after the kind-5 header, staged only on kind 5 and then within 16 KiB.
func checkEvsLocatorOf(locator *protocol.EvsLocator, format2 bool) error {
	if locator.GetStaged() {
		if !format2 {
			return fmt.Errorf("%w: a staged locator", ErrEvsFormatUnsupported)
		}
		if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT ||
			EvsStagedSegmentMaxByteCount < uint64(locator.GetOffset())+uint64(locator.GetLength()) {
			return fmt.Errorf("%w: a staged locator out of shape", ErrEvsPushInvalid)
		}
	}
	switch protocol.EvsLocatorKind(locator.GetKind()) {
	case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
		if len(locator.GetId()) != sha256.Size || len(locator.GetInline()) != 0 ||
			uint64(locator.GetLength()) < EvsRecordByteCount(0) ||
			EvsSegmentMaxByteCount < uint64(locator.GetOffset())+uint64(locator.GetLength()) {
			return fmt.Errorf("%w: a segment locator out of shape", ErrEvsPushInvalid)
		}
	case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
		if len(locator.GetInline()) == 0 || EvsInlineMaxByteCount < len(locator.GetInline()) || len(locator.GetId()) != 0 {
			return fmt.Errorf("%w: an inline locator out of shape", ErrEvsPushInvalid)
		}
	case protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
		if !format2 {
			return fmt.Errorf("%w: a versionless segment's locator", ErrEvsFormatUnsupported)
		}
		if len(locator.GetId()) != sha256.Size || len(locator.GetInline()) != 0 ||
			uint64(locator.GetOffset()) < EvsKind5SegmentHeaderByteCount ||
			uint64(locator.GetLength()) < EvsRecordByteCount(0) ||
			EvsSegmentMaxByteCount < uint64(locator.GetOffset())+uint64(locator.GetLength()) {
			return fmt.Errorf("%w: a versionless segment locator out of shape", ErrEvsPushInvalid)
		}
	default:
		return fmt.Errorf("%w: locator kind %d is reserved", ErrEvsPushInvalid, locator.GetKind())
	}
	return nil
}

// Whether every change lies under a covering prefix.
func evsPrefixesCover(changedPrefixes []EvsTokenPath, changes []*EvsCheckedChange) bool {
	for _, change := range changes {
		covered := false
		for _, prefix := range changedPrefixes {
			if change.TokenPath.HasPrefix(prefix) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// A hashed section matches its statement field: present exactly when the field is set, and hashing to it.
func checkEvsHashedSection(name string, sectionBytes []byte, statementHash []byte) error {
	if len(statementHash) == 0 {
		if len(sectionBytes) != 0 {
			return fmt.Errorf("%w: %s with no hash in the statement", ErrEvsPushInvalid, name)
		}
		return nil
	}
	digest := sha256.Sum256(sectionBytes)
	if len(sectionBytes) == 0 || !bytes.Equal(digest[:], statementHash) {
		return fmt.Errorf("%w: %s does not match its hash", ErrEvsPushInvalid, name)
	}
	return nil
}

// Attaches entry versions, in change order, to the changes writing one, each hashing to its change's entry_sha256.
func attachEvsEntryVersions(push *protocol.EvsPush, changes []*EvsCheckedChange, entryVersions [][]byte) (bool, error) {
	return attachEvsEntryVersionsOf(push, changes, entryVersions, false)
}

// Attaches entry versions as attachEvsEntryVersions does, of either format.
func attachEvsEntryVersionsOf(push *protocol.EvsPush, changes []*EvsCheckedChange, entryVersions [][]byte, format2 bool) (bool, error) {
	createsPath := false
	next := 0
	for _, change := range changes {
		if !change.WritesEntry() {
			if change.Change.GetBaseEntryVersion() == 0 {
				return false, fmt.Errorf("%w: a removal of a path it names absent", ErrEvsPushInvalid)
			}
			continue
		}
		if len(entryVersions) <= next {
			return false, fmt.Errorf("%w: fewer entry versions than writes", ErrEvsPushInvalid)
		}
		entryBytes := entryVersions[next]
		next += 1
		digest := sha256.Sum256(entryBytes)
		if !bytes.Equal(digest[:], change.Change.GetEntrySha256()) {
			return false, fmt.Errorf("%w: an entry version that does not hash to its change's entry_sha256", ErrEvsPushInvalid)
		}
		addsName, err := checkEvsEntryVersionOf(entryBytes, push, format2)
		if err != nil {
			return false, err
		}
		change.EntryVersion = entryBytes
		if change.Change.GetBaseEntryVersion() == 0 || addsName {
			createsPath = true
		}
	}
	if next != len(entryVersions) {
		return false, fmt.Errorf("%w: more entry versions than writes", ErrEvsPushInvalid)
	}
	return createsPath, nil
}

// The sections past the change list, checked against the statement, into checked: sealed metadata, new objects and
// their slot bodies, the erased list, tail moves, source paths (an item per change), the reuse list, and each entry
// version's Merkle proof when the change list is not inline. partRoots gives each change's root and its tree's size
// for the proofs: the statement's for one part, its part's for several.
func checkEvsSections(statement *EvsStatement, payload *EvsPayload, checked *EvsCheckedPayload, partRoots func(change int) ([]byte, uint64)) error {
	return checkEvsSectionsOf(statement, payload, checked, partRoots, false)
}

// The sections past the change list as checkEvsSections checks them, of either format: format 2 takes staged
// new-objects items. A DROP's sections are the callers', through evsCheckDropSlices.
func checkEvsSectionsOf(statement *EvsStatement, payload *EvsPayload, checked *EvsCheckedPayload, partRoots func(change int) ([]byte, uint64), format2 bool) error {
	push := statement.Push
	if len(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_INLINE_RECORDS)) != 0 {
		return fmt.Errorf("%w: inline records in the payload, which questions/evs1-m2-01-inline-record-home holds to the locators", ErrEvsPushInvalid)
	}
	sealedMetadata := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA)
	if err := checkEvsHashedSection("sealed metadata", sealedMetadata, push.GetSealedMetadataSha256()); err != nil {
		return err
	}
	checked.SealedMetadata = sealedMetadata

	newObjectsBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_NEW_OBJECTS)
	if err := checkEvsHashedSection("the new-objects list", newObjectsBytes, push.GetNewObjectsSha256()); err != nil {
		return err
	}
	newObjectItems, err := EvsPayloadItems(newObjectsBytes)
	if err != nil {
		return err
	}
	slotCount := 0
	for _, item := range newObjectItems {
		object, err := decodeEvsNewObjectOf(item, format2)
		if err != nil {
			return err
		}
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT {
			slotCount += 1
		}
		checked.NewObjects = append(checked.NewObjects, object)
	}
	slotBodies, err := EvsPayloadItems(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SLOT_BODIES))
	if err != nil {
		return err
	}
	if len(slotBodies) != slotCount {
		return fmt.Errorf("%w: %d slot bodies for %d new slots", ErrEvsPushInvalid, len(slotBodies), slotCount)
	}
	for _, slotBody := range slotBodies {
		slot, err := EvsDecodeSlotObject(slotBody)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
		}
		if len(slot.GetKeys()) == 0 {
			return fmt.Errorf("%w: a new slot with no key", ErrEvsPushInvalid)
		}
	}
	checked.SlotBodies = slotBodies

	erasedBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_ERASED_LIST)
	if err := checkEvsHashedSection("the erased list", erasedBytes, push.GetErasedSha256()); err != nil {
		return err
	}
	erasedItems, err := EvsPayloadItems(erasedBytes)
	if err != nil {
		return err
	}
	for _, item := range erasedItems {
		if len(item) != evsErasedItemByteCount || EvsSlotMaxKeyCount <= binary.BigEndian.Uint16(item[16:18]) {
			return fmt.Errorf("%w: an erased item out of shape", ErrEvsPushInvalid)
		}
		checked.Erased = append(checked.Erased, &EvsErasedKey{SlotId: Id(item[0:16]), KeyIndex: binary.BigEndian.Uint16(item[16:18])})
	}

	tailBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_TAIL_MOVES)
	if err := checkEvsHashedSection("the tail's moves", tailBytes, push.GetPathTailSha256()); err != nil {
		return err
	}
	tailItems, err := EvsPayloadItems(tailBytes)
	if err != nil {
		return err
	}
	for _, item := range tailItems {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, move); err != nil {
			return fmt.Errorf("%w: a tail move that does not parse", ErrEvsPushInvalid)
		}
		if err := checkEvsPathMove(move, push.GetPathEpoch()); err != nil {
			return err
		}
	}
	checked.TailMoves = tailItems

	sourceBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_SOURCE_PATHS)
	if err := checkEvsHashedSection("the source paths", sourceBytes, push.GetSourcePathsSha256()); err != nil {
		return err
	}
	if len(sourceBytes) != 0 {
		sourceItems, err := EvsPayloadItems(sourceBytes)
		if err != nil {
			return err
		}
		if len(sourceItems) != len(checked.Changes) {
			return fmt.Errorf("%w: %d source path items for %d changes", ErrEvsPushInvalid, len(sourceItems), len(checked.Changes))
		}
		for i, item := range sourceItems {
			sourcePaths, err := EvsPayloadItems(item)
			if err != nil {
				return err
			}
			for _, encoded := range sourcePaths {
				sourcePath := &protocol.EvsSourcePath{}
				if err := proto.Unmarshal(encoded, sourcePath); err != nil {
					return fmt.Errorf("%w: a source path that does not parse", ErrEvsPushInvalid)
				}
				if sourcePath.GetEpoch() == 0 || push.GetPathEpoch() <= sourcePath.GetEpoch() {
					return fmt.Errorf("%w: a source path of epoch %d", ErrEvsPushInvalid, sourcePath.GetEpoch())
				}
				if _, err := ParseEvsChangedTokenPath(sourcePath.GetTokenPath()); err != nil {
					return err
				}
			}
			checked.Changes[i].SourcePaths = sourcePaths
		}
	}

	reuseItems, err := EvsPayloadItems(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_REUSE_LIST))
	if err != nil {
		return err
	}
	for _, item := range reuseItems {
		reuse, err := decodeEvsReuse(item)
		if err != nil {
			return err
		}
		checked.ReuseList = append(checked.ReuseList, reuse)
	}

	proofBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_MERKLE_PROOFS)
	if len(push.GetChangesRoot()) == 0 {
		if len(proofBytes) != 0 {
			return fmt.Errorf("%w: Merkle proofs beside an inline change list", ErrEvsPushInvalid)
		}
		return nil
	}
	proofItems, err := EvsPayloadItems(proofBytes)
	if err != nil {
		return err
	}
	next := 0
	for i, change := range checked.Changes {
		if !change.WritesEntry() {
			continue
		}
		if len(proofItems) <= next {
			return fmt.Errorf("%w: an entry version with no Merkle proof", ErrEvsPushInvalid)
		}
		proof := &protocol.EvsMerkleProof{}
		if err := proto.Unmarshal(proofItems[next], proof); err != nil {
			return fmt.Errorf("%w: a Merkle proof that does not parse", ErrEvsPushInvalid)
		}
		next += 1
		root, size := partRoots(i)
		if !bytes.Equal(proof.GetLeaf(), change.Leaf) || proof.GetSize() != size {
			return fmt.Errorf("%w: a Merkle proof of another change or tree", ErrEvsPushInvalid)
		}
		if err := EvsVerifyMerkleProof(root, proof); err != nil {
			return err
		}
	}
	if next != len(proofItems) {
		return fmt.Errorf("%w: more Merkle proofs than entry versions", ErrEvsPushInvalid)
	}
	return nil
}

// A path move held to format 1: a new token path, sources of older epochs each with a token path, and a sealed
// name.
func checkEvsPathMove(move *protocol.EvsPathMove, pathEpoch uint64) error {
	if _, err := ParseEvsChangedTokenPath(move.GetNewTokenPath()); err != nil {
		return err
	}
	if len(move.GetSealedName()) == 0 {
		return fmt.Errorf("%w: a move with no sealed name", ErrEvsPushInvalid)
	}
	for _, source := range move.GetSources() {
		if source.GetEpoch() == 0 || pathEpoch <= source.GetEpoch() {
			return fmt.Errorf("%w: a move's source of epoch %d", ErrEvsPushInvalid, source.GetEpoch())
		}
		if _, err := ParseEvsChangedTokenPath(source.GetTokenPath()); err != nil {
			return err
		}
	}
	return nil
}

// §11.6's checks row over a one-part push: its statement, already parsed, and its payload's bytes as received. The
// change list is the statement's own, or under changes_root in section 4; every section matches its statement
// hash; nothing the statement does not state rides along.
func EvsCheckPayload(statement *EvsStatement, payloadBytes []byte) (*EvsCheckedPayload, error) {
	return evsCheckPayloadOf(statement, payloadBytes, false)
}

// EvsCheckPayload's checks over a format-2 one-part push and its staged bytes as received, which ride outside every
// hash: format 2's values taken, a DROP's sections checked, and the staged segments matched to the kind-2 new-objects
// items, one each and in order (§11.6's checks row, EVS-FORMAT.md).
func EvsCheckPayloadFormat2(statement *EvsStatement, payloadBytes []byte, stagedBytes []byte) (*EvsCheckedPayload, error) {
	checked, err := evsCheckPayloadOf(statement, payloadBytes, true)
	if err != nil {
		return nil, err
	}
	segments, err := EvsDecodeStaged(stagedBytes)
	if err != nil {
		return nil, err
	}
	if checked.Staged, err = evsMatchStaged(statement.Push, checked.NewObjects, segments); err != nil {
		return nil, err
	}
	return checked, nil
}

// A one-part push's checks, of either format.
func evsCheckPayloadOf(statement *EvsStatement, payloadBytes []byte, format2 bool) (*EvsCheckedPayload, error) {
	push := statement.Push
	if push.GetPartCount() != 0 {
		return nil, fmt.Errorf("%w: a push in parts has no one-part payload", ErrEvsPushInvalid)
	}
	if EvsPayloadMaxByteCount < len(payloadBytes) {
		return nil, fmt.Errorf("%w: a payload of %d bytes", ErrEvsPushInvalid, len(payloadBytes))
	}
	payload, err := parseEvsPayload(payloadBytes, format2)
	if err != nil {
		return nil, err
	}
	if len(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_PART_HASHES)) != 0 {
		return nil, fmt.Errorf("%w: part hashes in a one-part push", ErrEvsPushInvalid)
	}
	checked := &EvsCheckedPayload{}
	changeListBytes := payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_CHANGE_LIST)
	var root []byte
	if len(push.GetChangesRoot()) == 0 {
		if len(changeListBytes) != 0 {
			return nil, fmt.Errorf("%w: a change list beside inline changes", ErrEvsPushInvalid)
		}
		checked.Changes = statement.Changes
	} else {
		leaves, err := EvsPayloadItems(changeListBytes)
		if err != nil {
			return nil, err
		}
		if uint64(len(leaves)) != uint64(push.GetChangeCount()) {
			return nil, fmt.Errorf("%w: %d changes listed, %d signed", ErrEvsPushInvalid, len(leaves), push.GetChangeCount())
		}
		tree, err := NewEvsChangeTree(leaves)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
		}
		treeRoot := tree.Root()
		if !bytes.Equal(treeRoot[:], push.GetChangesRoot()) {
			return nil, fmt.Errorf("%w: the change list does not match changes_root", ErrEvsPushInvalid)
		}
		root = treeRoot[:]
		for _, leaf := range leaves {
			change, tokenPath, err := parseEvsChangeLeaf(leaf)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
			}
			if _, err := checkEvsChange(change); err != nil {
				return nil, err
			}
			checked.Changes = append(checked.Changes, &EvsCheckedChange{Change: change, Leaf: leaf, TokenPath: tokenPath})
		}
		if !evsPrefixesCover(statement.ChangedPrefixes, checked.Changes) {
			return nil, fmt.Errorf("%w: changed_prefixes do not cover every change", ErrEvsPushInvalid)
		}
	}
	entryVersions, err := EvsPayloadItems(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_ENTRY_VERSIONS))
	if err != nil {
		return nil, err
	}
	if EvsPartMaxEntryWriteCount < len(entryVersions) {
		return nil, fmt.Errorf("%w: %d entry writes in one part", ErrEvsPushInvalid, len(entryVersions))
	}
	if checked.CreatesPath, err = attachEvsEntryVersionsOf(push, checked.Changes, entryVersions, format2); err != nil {
		return nil, err
	}
	changeCount := uint64(len(checked.Changes))
	if err := checkEvsSectionsOf(statement, payload, checked, func(int) ([]byte, uint64) { return root, changeCount }, format2); err != nil {
		return nil, err
	}
	if format2 {
		lists := [][]byte{payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS)}
		if checked.Drop, err = evsCheckDropSlices(statement, payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY), lists); err != nil {
			return nil, err
		}
	}
	return checked, nil
}

// An EvsPushPart's message and its changes' bytes as listed, which its Merkle leaves are; a re-marshal could differ.
func parseEvsPushPart(partBytes []byte) (*protocol.EvsPushPart, [][]byte, error) {
	part := &protocol.EvsPushPart{}
	if err := proto.Unmarshal(partBytes, part); err != nil {
		return nil, nil, fmt.Errorf("%w: a part that does not parse", ErrEvsPushInvalid)
	}
	leaves := [][]byte{}
	for rest := partBytes; 0 < len(rest); {
		number, wireType, n := protowire.ConsumeTag(rest)
		if n < 0 {
			return nil, nil, fmt.Errorf("%w: a part's field tag", ErrEvsPushInvalid)
		}
		rest = rest[n:]
		if number == 3 && wireType == protowire.BytesType {
			value, n := protowire.ConsumeBytes(rest)
			if n < 0 {
				return nil, nil, fmt.Errorf("%w: a part's change", ErrEvsPushInvalid)
			}
			leaves = append(leaves, value)
			rest = rest[n:]
			continue
		}
		n = protowire.ConsumeFieldValue(number, wireType, rest)
		if n < 0 {
			return nil, nil, fmt.Errorf("%w: a part's field", ErrEvsPushInvalid)
		}
		rest = rest[n:]
	}
	return part, leaves, nil
}

// One part as checked when it arrives: its number, its changes with their entry versions, its root, and its slices
// of sealed metadata and of the other sections, which only the seal can join and check.
type EvsCheckedPart struct {
	Part        uint32
	Changes     []*EvsCheckedChange
	Root        [sha256.Size]byte
	Sha256      [sha256.Size]byte
	CreatesPath bool
	// format 2: its staged segments, each checked alone; the seal matches them to the new-objects items
	Staged       []*EvsStagedSegment
	metadata     []byte
	sections     *EvsPayload
	changeLeaves [][]byte
}

// A part of statement's push as it arrives (§11.8's parts row): at most 1 MiB and 1,024 entry writes, of this push
// and a part number it has, its changes non-empty and strictly sorted, each entry version hashing to its change,
// changes_root over its changes, and its sections slice framed as a payload holding no section its fields carry.
func EvsCheckPart(statement *EvsStatement, partBytes []byte) (*EvsCheckedPart, error) {
	return evsCheckPartOf(statement, partBytes, false)
}

// EvsCheckPart's checks over a part of a format-2 push and its staged bytes as received: format 2's values taken, and
// each staged segment a kind-5 segment of this repo naming this push within 16 KiB. Which items they are is the
// seal's, which reads every part.
func EvsCheckPartFormat2(statement *EvsStatement, partBytes []byte, stagedBytes []byte) (*EvsCheckedPart, error) {
	checked, err := evsCheckPartOf(statement, partBytes, true)
	if err != nil {
		return nil, err
	}
	segments, err := EvsDecodeStaged(stagedBytes)
	if err != nil {
		return nil, err
	}
	for _, segment := range segments {
		staged, err := EvsStagedSegmentOf(segment, Id(statement.Push.GetRepoId()), Id(statement.Push.GetPushId()))
		if err != nil {
			return nil, err
		}
		checked.Staged = append(checked.Staged, staged)
	}
	return checked, nil
}

// A part's checks, of either format.
func evsCheckPartOf(statement *EvsStatement, partBytes []byte, format2 bool) (*EvsCheckedPart, error) {
	push := statement.Push
	if push.GetPartCount() == 0 {
		return nil, fmt.Errorf("%w: a part of a one-part push", ErrEvsPushInvalid)
	}
	if EvsPartMaxByteCount < len(partBytes) {
		return nil, fmt.Errorf("%w: a part of %d bytes", ErrEvsPushInvalid, len(partBytes))
	}
	part, leaves, err := parseEvsPushPart(partBytes)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(part.GetPushId(), push.GetPushId()) || part.GetPart() == 0 || push.GetPartCount() < part.GetPart() {
		return nil, fmt.Errorf("%w: part %d of another push or past its count", ErrEvsPushInvalid, part.GetPart())
	}
	if len(part.GetInlineRecords()) != 0 {
		return nil, fmt.Errorf("%w: inline records in a part, which questions/evs1-m2-01-inline-record-home holds to the locators", ErrEvsPushInvalid)
	}
	if len(leaves) == 0 {
		return nil, fmt.Errorf("%w: a part with no change", ErrEvsPushInvalid)
	}
	tree, err := NewEvsChangeTree(leaves)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
	}
	root := tree.Root()
	if !bytes.Equal(part.GetChangesRoot(), root[:]) {
		return nil, fmt.Errorf("%w: the part's changes_root is not over its changes", ErrEvsPushInvalid)
	}
	checked := &EvsCheckedPart{
		Part: part.GetPart(), Root: root, Sha256: sha256.Sum256(partBytes), metadata: part.GetSealedMetadata(),
		changeLeaves: leaves,
	}
	for _, leaf := range leaves {
		change, tokenPath, err := parseEvsChangeLeaf(leaf)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
		}
		if _, err := checkEvsChange(change); err != nil {
			return nil, err
		}
		checked.Changes = append(checked.Changes, &EvsCheckedChange{Change: change, Leaf: leaf, TokenPath: tokenPath})
	}
	if EvsPartMaxEntryWriteCount < len(part.GetEntryVersions()) {
		return nil, fmt.Errorf("%w: %d entry writes in a part", ErrEvsPushInvalid, len(part.GetEntryVersions()))
	}
	if checked.CreatesPath, err = attachEvsEntryVersionsOf(push, checked.Changes, part.GetEntryVersions(), format2); err != nil {
		return nil, err
	}
	sections, err := parseEvsPayload(part.GetSections(), format2)
	if err != nil {
		return nil, err
	}
	for _, sectionType := range evsPartFieldSections {
		if len(sections.Section(sectionType)) != 0 {
			return nil, fmt.Errorf("%w: section %d in a part's sections", ErrEvsPushInvalid, sectionType)
		}
	}
	if len(sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_PART_HASHES)) != 0 {
		return nil, fmt.Errorf("%w: part hashes inside a part", ErrEvsPushInvalid)
	}
	checked.sections = sections
	return checked, nil
}

// The first change's token path, which a seal record keeps per part.
func (self *EvsCheckedPart) FirstTokenPath() EvsTokenPath {
	return self.Changes[0].TokenPath
}

// §11.8's seal over every part of statement's push, in part order, as their records hold them: each part checks,
// parts_sha256 binds them, their changes ascend strictly across parts, changes_root is over the parts' roots and
// change_count their total, changed_prefixes cover every change, and the parts' slices joined in order are a one-part
// payload whose sections match their hashes, each entry version's proof reaching its part's root.
func EvsCheckSeal(statement *EvsStatement, parts [][]byte) (*EvsCheckedPayload, []*EvsCheckedPart, error) {
	return evsCheckSealOf(statement, parts, nil, false)
}

// EvsCheckSeal's checks over every part of a format-2 push and each part's staged bytes, in part order as their
// records hold them: format 2's values taken, a DROP's sections checked over the parts' slices, and the staged
// segments, joined in part order, matched to the joined new-objects list's kind-2 items, one each and in order.
func EvsCheckSealFormat2(statement *EvsStatement, parts [][]byte, partStaged [][]byte) (*EvsCheckedPayload, []*EvsCheckedPart, error) {
	if len(partStaged) != len(parts) {
		return nil, nil, fmt.Errorf("%w: staged bytes for %d of %d parts", ErrEvsPushInvalid, len(partStaged), len(parts))
	}
	return evsCheckSealOf(statement, parts, partStaged, true)
}

// A seal's checks, of either format.
func evsCheckSealOf(statement *EvsStatement, parts [][]byte, partStaged [][]byte, format2 bool) (*EvsCheckedPayload, []*EvsCheckedPart, error) {
	push := statement.Push
	if push.GetPartCount() == 0 || uint32(len(parts)) != push.GetPartCount() {
		return nil, nil, fmt.Errorf("%w: %d parts for a count of %d", ErrEvsPushInvalid, len(parts), push.GetPartCount())
	}
	checkedParts := make([]*EvsCheckedPart, len(parts))
	partHashes := make([]byte, 0, len(parts)*sha256.Size)
	partLeaves := make([][][]byte, len(parts))
	for i, partBytes := range parts {
		var checkedPart *EvsCheckedPart
		var err error
		if format2 {
			checkedPart, err = EvsCheckPartFormat2(statement, partBytes, partStaged[i])
		} else {
			checkedPart, err = EvsCheckPart(statement, partBytes)
		}
		if err != nil {
			return nil, nil, err
		}
		if checkedPart.Part != uint32(i+1) {
			return nil, nil, fmt.Errorf("%w: part %d where %d belongs", ErrEvsPushInvalid, checkedPart.Part, i+1)
		}
		checkedParts[i] = checkedPart
		partHashes = append(partHashes, checkedPart.Sha256[:]...)
		partLeaves[i] = checkedPart.changeLeaves
	}
	partsDigest := sha256.Sum256(partHashes)
	if !bytes.Equal(partsDigest[:], push.GetPartsSha256()) {
		return nil, nil, fmt.Errorf("%w: the parts do not match parts_sha256", ErrEvsPushInvalid)
	}
	tree, err := NewEvsPartedChangeTree(partLeaves)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
	}
	treeRoot := tree.Root()
	if !bytes.Equal(treeRoot[:], push.GetChangesRoot()) || uint64(tree.ChangeCount()) != uint64(push.GetChangeCount()) {
		return nil, nil, fmt.Errorf("%w: the parts do not match changes_root and change_count", ErrEvsPushInvalid)
	}

	checked := &EvsCheckedPayload{}
	joined := &EvsPayload{}
	metadata := []byte{}
	changeParts := []int{}
	stagedSegments := [][]byte{}
	for i, checkedPart := range checkedParts {
		checked.Changes = append(checked.Changes, checkedPart.Changes...)
		checked.CreatesPath = checked.CreatesPath || checkedPart.CreatesPath
		metadata = append(metadata, checkedPart.metadata...)
		for range checkedPart.Changes {
			changeParts = append(changeParts, i)
		}
		for sectionType := range joined.sections {
			// a DROP's lists are streamed from each part's slice by evsCheckDropSlices, never joined
			if sectionType == int(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS) {
				continue
			}
			if slice := checkedPart.sections.sections[sectionType]; len(slice) != 0 {
				joined.sections[sectionType] = append(joined.sections[sectionType], slice...)
			}
		}
		for _, staged := range checkedPart.Staged {
			stagedSegments = append(stagedSegments, staged.Bytes)
		}
	}
	if !evsPrefixesCover(statement.ChangedPrefixes, checked.Changes) {
		return nil, nil, fmt.Errorf("%w: changed_prefixes do not cover every change", ErrEvsPushInvalid)
	}
	joined.sections[protocol.EvsPayloadSection_EVS_PAYLOAD_SEALED_METADATA] = metadata
	partRoots := func(change int) ([]byte, uint64) {
		part := checkedParts[changeParts[change]]
		return part.Root[:], uint64(len(part.Changes))
	}
	if format2 {
		listSlices := [][]byte{}
		for _, checkedPart := range checkedParts {
			listSlices = append(listSlices, checkedPart.sections.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_LISTS))
		}
		if err := checkEvsSectionsOf(statement, joined, checked, partRoots, true); err != nil {
			return nil, nil, err
		}
		var err error
		if checked.Drop, err = evsCheckDropSlices(statement, joined.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_DROP_BODY), listSlices); err != nil {
			return nil, nil, err
		}
		if checked.Staged, err = evsMatchStaged(push, checked.NewObjects, stagedSegments); err != nil {
			return nil, nil, err
		}
		return checked, checkedParts, nil
	}
	if err := checkEvsSections(statement, joined, checked, partRoots); err != nil {
		return nil, nil, err
	}
	return checked, checkedParts, nil
}

// A path map part's bound (§11.6's EvsPathMap).
const EvsPathMapMaxByteCount = 8 * 1024 * 1024

// An upload receipt's bytes as a push carries one back (§11.13), held to its shape: a repo and uploader id, a 32 B
// segment id, a Padmé size within 8 MiB, an upload time and a 16 B MAC. The MAC itself is evs's to check with its
// receipt keys (EVSB-M2-09); format 2's versionless receipt is ErrEvsFormatUnsupported.
func DecodeEvsUploadReceipt(receiptBytes []byte) (*protocol.EvsUploadReceipt, error) {
	return decodeEvsUploadReceiptOf(receiptBytes, false)
}

// A receipt held to its shape as DecodeEvsUploadReceipt holds it, format 2 taking a versionless one: its segment's
// header is a kind-5 header naming the receipt's push, and the MAC covers the mark (§11.13's receipt row).
func DecodeEvsUploadReceiptFormat2(receiptBytes []byte) (*protocol.EvsUploadReceipt, error) {
	return decodeEvsUploadReceiptOf(receiptBytes, true)
}

// A receipt's shape, of either format.
func decodeEvsUploadReceiptOf(receiptBytes []byte, format2 bool) (*protocol.EvsUploadReceipt, error) {
	receipt := &protocol.EvsUploadReceipt{}
	if err := proto.Unmarshal(receiptBytes, receipt); err != nil {
		return nil, fmt.Errorf("%w: a receipt that does not parse", ErrEvsPushInvalid)
	}
	if receipt.GetVersionless() && !format2 {
		return nil, fmt.Errorf("%w: a versionless receipt", ErrEvsFormatUnsupported)
	}
	if len(receipt.GetRepoId()) != 16 || len(receipt.GetUploaderSidecarId()) != 16 || len(receipt.GetSegmentId()) != sha256.Size ||
		len(receipt.GetMac()) != 16 || receipt.GetUploadMs() <= 0 ||
		!EvsIsPadme(receipt.GetPaddedSize()) || EvsSegmentMaxByteCount < receipt.GetPaddedSize() {
		return nil, fmt.Errorf("%w: a receipt out of shape", ErrEvsPushInvalid)
	}
	return receipt, nil
}

// A Signed EvsPathMap part's bytes held to its shape (§11.6's map row): at most 8 MiB, an identity key's statement of
// type SIGNED_EVS_PATH_MAP, for a repo and ref, a new epoch past 1, a part within its count, a source head, and moves
// each with a new token path, sources of older epochs and a sealed name. Its signature is the caller's to check.
func ParseEvsPathMap(signedBytes []byte) (*bridge.Signed, *protocol.EvsPathMap, error) {
	if EvsPathMapMaxByteCount < len(signedBytes) {
		return nil, nil, fmt.Errorf("%w: a map part of %d bytes", ErrEvsPushInvalid, len(signedBytes))
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil || signed.GetType() != uint32(bridge.SignedType_SIGNED_EVS_PATH_MAP) {
		return nil, nil, fmt.Errorf("%w: not a signed path map", ErrEvsPushInvalid)
	}
	pathMap := &protocol.EvsPathMap{}
	if err := proto.Unmarshal(signed.GetBody(), pathMap); err != nil {
		return nil, nil, fmt.Errorf("%w: a path map that does not parse", ErrEvsPushInvalid)
	}
	if len(pathMap.GetRepoId()) != 16 || len(pathMap.GetRefId()) != 16 || pathMap.GetPathEpoch() < 2 ||
		pathMap.GetPart() == 0 || pathMap.GetParts() < pathMap.GetPart() || len(pathMap.GetSourceChain()) != sha256.Size {
		return nil, nil, fmt.Errorf("%w: a path map out of shape", ErrEvsPushInvalid)
	}
	for _, move := range pathMap.GetMoves() {
		if err := checkEvsPathMove(move, pathMap.GetPathEpoch()); err != nil {
			return nil, nil, err
		}
	}
	return signed, pathMap, nil
}
