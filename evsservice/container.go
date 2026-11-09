// Packs and parcels (§11.13's move and index rows; D-EVS-32, EVSB-M2-10): a container is a repo's aged records, and
// for a pack its log pages, in one deterministic order, so a rerun over the same inputs gives equal bytes, and its
// id, the pack_id or parcel_id, is the first 16 B of SHA-256 over those bytes (§20.14 relies on that). A pack lives
// at pack/<repo>/<pack_id> on the segment cluster, a parcel at hp/<repo>/<parcel_id> on the repo's metadata cluster;
// parcels hold records only, and log pages wait for a pack (plan-EVSB-parcel-log-pages).
//
// Bytes, defined here and in EVS-FORMAT.md's stored objects:
//
//	header, 16 B   "URpk" for a pack or "URhp" for a parcel | format u8 (1) | 3 zero bytes | item_count u32 | 4 zero bytes
//	item           kind u8 (1 record, 2 log page) | 3 zero bytes | ref_id 16 | number u64 | length u32 | bytes
//
// A record item's number is the version it committed, a part's its seal's, and its bytes are the batch record's as
// its batch held them, so a range read of them parses as a read at its place did. A log page's number is its page.
// Items go records first, by ref, version and place, then log pages by ref and page.
//
// WriteContainer writes the container and then one create-only pidx/ entry per ref (pidx.go), in that order, so a
// container precedes its entries, and the caller deletes what they replace only after both (I-EVS-7).

package evsservice

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Container format values.
const (
	containerHeaderByteCount     = 16
	containerItemHeaderByteCount = 32
	containerFormat1             = 1
	containerItemRecord          = 1
	containerItemLogPage         = 2
)

var (
	containerPackMagic   = []byte("URpk")
	containerParcelMagic = []byte("URhp")
)

// A container's inputs break a rule: a parcel given log pages, two items of one key, an empty container.
var ErrEvsContainerInvalid = errors.New("evs container invalid")

// One record to hold: its ref, the version it committed (a part its seal's), its place in its batch and its bytes
// as read there.
type ContainerRecord struct {
	RefId   sidecar.Id
	Version uint64
	Place   *protocol.EvsPlace
	Bytes   []byte
	// The segments it introduces, 32 B ids.
	SegmentIds [][32]byte
}

// One log page to hold in a pack.
type ContainerLogPage struct {
	RefId sidecar.Id
	Page  uint64
	Bytes []byte
}

// A built container: its kind, id and bytes, and its pidx/ entries by ref.
type Container struct {
	Kind       protocol.EvsContainerKind
	Id         sidecar.Id
	Bytes      []byte
	RefEntries map[sidecar.Id]*protocol.EvsPidxEntry
}

// Compares two places by minute, instance, seq and offset.
func comparePlaces(a *protocol.EvsPlace, b *protocol.EvsPlace) int {
	return cmp.Or(
		cmp.Compare(a.GetMinute(), b.GetMinute()),
		cmp.Compare(a.GetInstance(), b.GetInstance()),
		cmp.Compare(a.GetSeq(), b.GetSeq()),
		cmp.Compare(a.GetOffset(), b.GetOffset()),
	)
}

// Builds a container of kind from records and log pages, whatever order they come in. See the file header.
func BuildContainer(kind protocol.EvsContainerKind, records []*ContainerRecord, logPages []*ContainerLogPage) (*Container, error) {
	var magic []byte
	switch kind {
	case protocol.EvsContainerKind_EVS_CONTAINER_PACK:
		magic = containerPackMagic
	case protocol.EvsContainerKind_EVS_CONTAINER_PARCEL:
		magic = containerParcelMagic
		if 0 < len(logPages) {
			return nil, fmt.Errorf("%w: a parcel holds records only", ErrEvsContainerInvalid)
		}
	default:
		return nil, fmt.Errorf("%w: kind %d", ErrEvsContainerInvalid, kind)
	}
	if len(records) == 0 && len(logPages) == 0 {
		return nil, fmt.Errorf("%w: nothing to hold", ErrEvsContainerInvalid)
	}
	records = slices.Clone(records)
	slices.SortFunc(records, func(a *ContainerRecord, b *ContainerRecord) int {
		return cmp.Or(bytes.Compare(a.RefId[:], b.RefId[:]), cmp.Compare(a.Version, b.Version), comparePlaces(a.Place, b.Place))
	})
	logPages = slices.Clone(logPages)
	slices.SortFunc(logPages, func(a *ContainerLogPage, b *ContainerLogPage) int {
		return cmp.Or(bytes.Compare(a.RefId[:], b.RefId[:]), cmp.Compare(a.Page, b.Page))
	})
	for i := 1; i < len(records); i += 1 {
		if records[i].RefId == records[i-1].RefId && comparePlaces(records[i].Place, records[i-1].Place) == 0 {
			return nil, fmt.Errorf("%w: one place twice", ErrEvsContainerInvalid)
		}
	}
	for i := 1; i < len(logPages); i += 1 {
		if logPages[i].RefId == logPages[i-1].RefId && logPages[i].Page == logPages[i-1].Page {
			return nil, fmt.Errorf("%w: one log page twice", ErrEvsContainerInvalid)
		}
	}

	encoded := make([]byte, 0, containerHeaderByteCount)
	encoded = append(encoded, magic...)
	encoded = append(encoded, containerFormat1, 0, 0, 0)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(records)+len(logPages)))
	encoded = append(encoded, 0, 0, 0, 0)
	refEntries := map[sidecar.Id]*protocol.EvsPidxEntry{}
	entry := func(refId sidecar.Id) *protocol.EvsPidxEntry {
		refEntry, ok := refEntries[refId]
		if !ok {
			refEntry = &protocol.EvsPidxEntry{ContainerKind: kind}
			refEntries[refId] = refEntry
		}
		return refEntry
	}
	appendItem := func(itemKind byte, refId sidecar.Id, number uint64, itemBytes []byte) uint64 {
		encoded = append(encoded, itemKind, 0, 0, 0)
		encoded = append(encoded, refId[:]...)
		encoded = binary.BigEndian.AppendUint64(encoded, number)
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(itemBytes)))
		offset := uint64(len(encoded))
		encoded = append(encoded, itemBytes...)
		return offset
	}
	for _, record := range records {
		if record.Place == nil || uint32(len(record.Bytes)) != record.Place.GetLength() {
			return nil, fmt.Errorf("%w: a record's bytes are not its place's length", ErrEvsContainerInvalid)
		}
		recordType, err := containerRecordType(record.Bytes)
		if err != nil {
			return nil, err
		}
		offset := appendItem(containerItemRecord, record.RefId, record.Version, record.Bytes)
		refEntry := entry(record.RefId)
		refEntry.Records = append(refEntry.Records, &protocol.EvsPidxRecord{
			Version: record.Version,
			Type:    recordType,
			Offset:  offset,
			Length:  uint32(len(record.Bytes)),
			Place: &protocol.EvsPlace{
				Minute:   record.Place.GetMinute(),
				Instance: record.Place.GetInstance(),
				Seq:      record.Place.GetSeq(),
				Offset:   record.Place.GetOffset(),
				Length:   record.Place.GetLength(),
			},
		})
		for _, segmentId := range record.SegmentIds {
			if !slices.ContainsFunc(refEntry.SegmentIds, func(id []byte) bool { return bytes.Equal(id, segmentId[:]) }) {
				refEntry.SegmentIds = append(refEntry.SegmentIds, bytes.Clone(segmentId[:]))
			}
		}
	}
	for _, logPage := range logPages {
		if len(logPage.Bytes) == 0 {
			return nil, fmt.Errorf("%w: an empty log page", ErrEvsContainerInvalid)
		}
		offset := appendItem(containerItemLogPage, logPage.RefId, logPage.Page, logPage.Bytes)
		refEntry := entry(logPage.RefId)
		refEntry.LogPages = append(refEntry.LogPages, &protocol.EvsPidxLogPage{Page: logPage.Page, Offset: offset, Length: uint32(len(logPage.Bytes))})
	}

	sum := sha256.Sum256(encoded)
	containerId := sidecar.Id(sum[:16])
	for _, refEntry := range refEntries {
		refEntry.ContainerId = bytes.Clone(containerId[:])
		// the versions its records commit and its log pages hold, 64 a page
		first, last := uint64(math.MaxUint64), uint64(0)
		for _, record := range refEntry.Records {
			first = min(first, record.GetVersion())
			last = max(last, record.GetVersion())
		}
		for _, logPage := range refEntry.LogPages {
			first = min(first, logPage.GetPage()*EvsLogPageVersionCount)
			last = max(last, logPage.GetPage()*EvsLogPageVersionCount+EvsLogPageVersionCount-1)
		}
		refEntry.FirstVersion = first
		refEntry.LastVersion = last
		if err := validateEvsPidxEntry(refEntry); err != nil {
			return nil, err
		}
	}
	return &Container{Kind: kind, Id: containerId, Bytes: encoded, RefEntries: refEntries}, nil
}

// A record's type, read from its bytes' first byte, which its batch's codec checked.
func containerRecordType(recordBytes []byte) (protocol.EvsBatchRecordType, error) {
	if len(recordBytes) < sidecar.EvsBatchRecordHeaderByteCount {
		return 0, fmt.Errorf("%w: a record of %d bytes", ErrEvsContainerInvalid, len(recordBytes))
	}
	recordType := protocol.EvsBatchRecordType(recordBytes[0])
	if recordType < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < recordType {
		return 0, fmt.Errorf("%w: record type %d", ErrEvsContainerInvalid, recordType)
	}
	return recordType, nil
}

// pack/<repo>/<pack_id> or hp/<repo>/<parcel_id>.
func (self *Container) Key(repoId sidecar.Id) string {
	if self.Kind == protocol.EvsContainerKind_EVS_CONTAINER_PACK {
		return PackKey(repoId, self.Id)
	}
	return ParcelKey(repoId, self.Id)
}

// Each ref's pidx/ key and entry bytes, in ref order.
func (self *Container) EntryKeys(repoId sidecar.Id) (keys []string, entryBytes [][]byte, err error) {
	for _, refId := range slices.SortedFunc(func(yield func(sidecar.Id) bool) {
		for refId := range self.RefEntries {
			if !yield(refId) {
				return
			}
		}
	}, func(a sidecar.Id, b sidecar.Id) int { return bytes.Compare(a[:], b[:]) }) {
		refEntry := self.RefEntries[refId]
		encoded, err := encodeEvsPidxEntry(refEntry)
		if err != nil {
			return nil, nil, err
		}
		keys = append(keys, PidxKey(repoId, refId, refEntry.GetFirstVersion(), self.Id))
		entryBytes = append(entryBytes, encoded)
	}
	return keys, entryBytes, nil
}

// Writes the container, then its pidx/ entries, each create-only, as the file header says. A pack goes to the
// segment cluster as a streamed PUT with its SHA-256 (plan-EVSB-pack-put), a parcel to metadataCluster through
// PutImmutable; a 412 on a pack is its own bytes, since its key names them. Each write runs under ctx's class,
// which the caller's P2 grant set. An error leaves the caller to resume: entries are create-only, and a container
// with equal bytes is reused.
func WriteContainer(ctx context.Context, blobs sidecar.BlobStore, metadataCluster sidecar.BlobCluster, repoId sidecar.Id, container *Container) error {
	sum := sha256.Sum256(container.Bytes)
	key := container.Key(repoId)
	switch container.Kind {
	case protocol.EvsContainerKind_EVS_CONTAINER_PACK:
		segmentCluster, err := blobs.SegmentCluster()
		if err != nil {
			return err
		}
		_, err = segmentCluster.PutStream(ctx, key, bytes.NewReader(container.Bytes), int64(len(container.Bytes)), sum[:])
		if err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			return err
		}
	default:
		if _, err := sidecar.PutImmutable(ctx, metadataCluster, key, container.Bytes, &sidecar.BlobPutOptions{Sha256: sum[:]}); err != nil {
			return err
		}
	}
	keys, entryBytes, err := container.EntryKeys(repoId)
	if err != nil {
		return err
	}
	for i, entryKey := range keys {
		if _, err := sidecar.PutImmutable(ctx, metadataCluster, entryKey, entryBytes[i], nil); err != nil {
			return err
		}
	}
	return nil
}
