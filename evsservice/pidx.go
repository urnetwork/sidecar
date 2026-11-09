// pidx/<repo>/<ref>/<v_first>-<id> (§11.13's index row; EVSB-M2-10): one container's records and log pages for one
// ref, an EvsPidxEntry. The key carries v_first zero-padded to 20 digits and the container's id, so every key under
// a ref has one length and none prefixes another, and a container's entries never share a key with another's.
// Entries are created once, after their container and before what they replace is deleted, and never change, so a
// reader caches them for good (locate.go).
//
// Decoding is total and bounded: any bytes give an entry that keeps every rule below, or an error, and nothing past
// EvsPidxEntryMaxByteCount is parsed.

package evsservice

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Format bounds of one entry. A pack holds a repo's aged material for one run, at most a week of one ref's
// records, so these hold any entry evacuation writes with room to spare.
const (
	// The most bytes an entry may be: 4 MiB.
	EvsPidxEntryMaxByteCount = 4 * 1024 * 1024
	// The most records, log pages and introduced segments one entry lists.
	evsPidxEntryMaxRecordCount  = 65536
	evsPidxEntryMaxLogPageCount = 65536
	evsPidxEntryMaxSegmentCount = 65536
)

// An entry, a key or a container that breaks the format: the store holds something no writer of it wrote.
var ErrEvsPidxInvalid = errors.New("evs pidx entry invalid")

// The entry's bytes, deterministic for equal entries.
func encodeEvsPidxEntry(entry *protocol.EvsPidxEntry) ([]byte, error) {
	if err := validateEvsPidxEntry(entry); err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(entry)
}

// An entry from its bytes, checked. See the file header.
func DecodeEvsPidxEntry(entryBytes []byte) (*protocol.EvsPidxEntry, error) {
	if EvsPidxEntryMaxByteCount < len(entryBytes) {
		return nil, fmt.Errorf("%w: %d bytes", ErrEvsPidxInvalid, len(entryBytes))
	}
	entry := &protocol.EvsPidxEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsPidxInvalid, err)
	}
	if err := validateEvsPidxEntry(entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// The rules every entry keeps: a container of a known kind with a 16 B id, versions in order, every record of a
// known type, inside those versions, with a place and a length a record can have, log pages only in a pack, and
// 32 B segment ids, each list within its bound.
func validateEvsPidxEntry(entry *protocol.EvsPidxEntry) error {
	invalid := func(format string, args ...any) error {
		return fmt.Errorf("%w: %s", ErrEvsPidxInvalid, fmt.Sprintf(format, args...))
	}
	kind := entry.GetContainerKind()
	if kind != protocol.EvsContainerKind_EVS_CONTAINER_PACK && kind != protocol.EvsContainerKind_EVS_CONTAINER_PARCEL {
		return invalid("container kind %d", kind)
	}
	if len(entry.GetContainerId()) != 16 {
		return invalid("a container id of %d bytes", len(entry.GetContainerId()))
	}
	if entry.GetLastVersion() < entry.GetFirstVersion() {
		return invalid("versions %d..%d", entry.GetFirstVersion(), entry.GetLastVersion())
	}
	if len(entry.GetRecords()) == 0 && len(entry.GetLogPages()) == 0 {
		return invalid("an entry naming nothing")
	}
	if evsPidxEntryMaxRecordCount < len(entry.GetRecords()) || evsPidxEntryMaxLogPageCount < len(entry.GetLogPages()) || evsPidxEntryMaxSegmentCount < len(entry.GetSegmentIds()) {
		return invalid("past its bounds")
	}
	for _, record := range entry.GetRecords() {
		if record.GetType() < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < record.GetType() {
			return invalid("record type %d", record.GetType())
		}
		if record.GetVersion() < entry.GetFirstVersion() || entry.GetLastVersion() < record.GetVersion() {
			return invalid("a record of version %d", record.GetVersion())
		}
		if record.GetLength() < sidecar.EvsBatchRecordHeaderByteCount || sidecar.EvsBatchMaxRecordByteCount < record.GetLength() {
			return invalid("a record of %d bytes", record.GetLength())
		}
		place := record.GetPlace()
		if place == nil || place.GetOffset() < sidecar.EvsBatchHeaderByteCount || place.GetLength() != record.GetLength() {
			return invalid("a record with no place its batch could hold")
		}
	}
	if 0 < len(entry.GetLogPages()) && kind != protocol.EvsContainerKind_EVS_CONTAINER_PACK {
		return invalid("log pages in a parcel")
	}
	for _, logPage := range entry.GetLogPages() {
		if logPage.GetLength() == 0 {
			return invalid("an empty log page")
		}
	}
	for _, segmentId := range entry.GetSegmentIds() {
		if len(segmentId) != 32 {
			return invalid("a segment id of %d bytes", len(segmentId))
		}
	}
	return nil
}

// The v_first and container id a pidx/ key under refPrefix names. ok is false for a key of another shape.
func parsePidxKey(refPrefix string, key string) (firstVersion uint64, containerId sidecar.Id, ok bool) {
	rest, found := strings.CutPrefix(key, refPrefix)
	if !found || len(rest) != 20+1+32 || rest[20] != '-' {
		return 0, sidecar.Id{}, false
	}
	firstVersion, err := strconv.ParseUint(rest[:20], 10, 64)
	if err != nil {
		return 0, sidecar.Id{}, false
	}
	containerId, err = sidecar.ParseId(rest[21:])
	if err != nil || sidecar.EvsKeyId(containerId) != rest[21:] {
		return 0, sidecar.Id{}, false
	}
	return firstVersion, containerId, true
}
