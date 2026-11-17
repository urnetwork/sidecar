// evs's push history for a production (§21.9; ABUSE-M5-17; D-ABUSE-6, D-ABUSE-7, R-ABUSE-5, I-1): what a legal order
// can reach of a repo while it is retained, "who, when, which token paths and how many versions", read through the
// record readers and nothing else.
//
// ExportPushHistory lists the repo's refs (head/<repo>/), and for each walks versions 1 to the head's: a version the
// window holds from its record at the entry's place, an older one from its log page (log/<repo>/<ref>/<n>, or the
// pack pidx/ names once it was evacuated). Of each version it keeps the cleartext a Signed EvsPush shows evs already
// (evs-12, evs-14): the push id, its signer, owner and client, its time, kind, mode and flags, its base version, its
// part and change counts and the token paths it names, each change's when the changes are inline and the covering
// prefixes when they are not. From the record of a one-part push it adds the padded sizes and upload days of the
// segments the push introduced (evs-4); a push in parts, or one whose record a reader cannot reach, says its sizes
// were not read rather than guessing.
//
// It never reads a key and never decrypts: no slot/ object, no segment's bytes, no gen/ record and no GKM object is
// fetched, and of a payload nothing is kept but those sizes. Sealed metadata, entry versions' sealed fields, inline
// records and slot bodies are never part of a row, so sealed commit metadata stays sealed (§2.5). DROP pushes are
// pushes here like any other, their flag saying so. Statements of either format are read as stored.
//
// The caller writes each row where counsel's file goes; nothing here logs a repo, a ref or a token. Safe for
// concurrent use: each call keeps its own caches.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// Tunables of one export.
type EvsPushHistorySettings struct {
	// The most head keys one LIST of a repo's refs asks for.
	RefPageCount int
	// The most refs one export reads; a repo past it is cut and says so (EvsPushHistoryExport.Truncated). 4096: far
	// past what a repo's devices make, so a cut is a fault to look at, never a routine answer.
	RefMaxCount int
	// The most versions one export reads of one ref; a ref past it is cut, newest left out, and says so. 1,048,576:
	// years of pushes at any rate a quota allows.
	RefVersionMaxCount uint64
}

// The defaults, each with its field's reason.
func DefaultEvsPushHistorySettings() *EvsPushHistorySettings {
	return &EvsPushHistorySettings{
		RefPageCount:       1000,
		RefMaxCount:        4096,
		RefVersionMaxCount: 1 << 20,
	}
}

// What an export reads: the repo's metadata cluster, and the host's blobs, whose packs hold evacuated records and log
// pages.
type EvsPushHistoryStores struct {
	Blobs   sidecar.BlobStore
	Cluster sidecar.BlobCluster
}

// One segment a push introduced, as its record lists it (evs-4).
type EvsPushHistorySegment struct {
	// the segment's id, SHA-256 of its bytes, in hex
	SegmentId  string `json:"segment_id"`
	PaddedSize uint64 `json:"padded_size"`
	// days since the Unix epoch of its upload
	UploadDay uint32 `json:"upload_day"`
}

// One version of one ref, the cleartext of its statement (evs-12, evs-14) and its segments' sizes (evs-4).
type EvsPushHistoryRow struct {
	RepoId          sidecar.Id `json:"repo_id"`
	RefId           sidecar.Id `json:"ref_id"`
	Version         uint64     `json:"version"`
	PushId          sidecar.Id `json:"push_id"`
	SignerSidecarId sidecar.Id `json:"signer_sidecar_id"`
	OwnerSidecarId  sidecar.Id `json:"owner_sidecar_id"`
	ClientId        sidecar.Id `json:"client_id"`
	TimeMs          int64      `json:"time_ms"`
	RefKind         uint32     `json:"ref_kind"`
	RefMode         uint32     `json:"ref_mode"`
	// the statement's flags: FORCE, DELETE, BASE, ... DROP (256), CUT (512), as evs.proto numbers them
	Flags       uint32 `json:"flags"`
	BaseVersion uint64 `json:"base_version"`
	// 0 for a one-part push
	PartCount   uint32 `json:"part_count"`
	ChangeCount uint32 `json:"change_count"`
	// each change's token path when the changes are inline, else the covering prefixes; components in the 26
	// character base32 form object keys hold, joined by /
	TokenPaths []string `json:"token_paths"`
	// whether TokenPaths holds covering prefixes rather than each change's path
	TokenPrefixes bool `json:"token_prefixes"`
	// the segments it introduced; nil when SizesRead is false
	Segments []*EvsPushHistorySegment `json:"segments,omitempty"`
	// false for a push in parts, whose parts this export does not open, or a record no reader could reach
	SizesRead bool `json:"sizes_read"`
}

// What an export read.
type EvsPushHistoryExport struct {
	RefCount     int `json:"ref_count"`
	VersionCount int `json:"version_count"`
	// a bound cut a ref list or a ref's versions: the export is not whole
	Truncated bool `json:"truncated"`
}

// The bytes at a key that should hold a part of the history do not: a fault that stops the export, never a row
// left out quietly.
var ErrEvsPushHistoryInvalid = errors.New("evs push history invalid")

// One export's readers, each its own.
type evsPushHistoryReader struct {
	stores   *EvsPushHistoryStores
	records  *RecordCache
	pages    *LogPageCache
	locator  *RecordLocator
	settings *EvsPushHistorySettings
}

// Writes the repo's push history, ref by ref in key order and each ref's versions oldest first, through write. See
// the file header. An error from write stops the export and is returned.
func ExportPushHistory(
	ctx context.Context,
	stores *EvsPushHistoryStores,
	repoId sidecar.Id,
	settings *EvsPushHistorySettings,
	write func(row *EvsPushHistoryRow) error,
) (*EvsPushHistoryExport, error) {
	if stores == nil || stores.Cluster == nil || stores.Blobs == nil {
		return nil, fmt.Errorf("%w: no stores", ErrEvsPushHistoryInvalid)
	}
	if settings == nil {
		settings = DefaultEvsPushHistorySettings()
	}
	evsSettings := DefaultEvsSettings()
	reader := &evsPushHistoryReader{
		stores:   stores,
		records:  NewRecordCache(evsSettings),
		pages:    NewLogPageCache(evsSettings),
		locator:  NewRecordLocator(stores.Blobs, nil),
		settings: settings,
	}
	export := &EvsPushHistoryExport{}
	prefix := HeadRepoPrefix(repoId)
	startAfter := ""
	for {
		objects, more, err := stores.Cluster.List(ctx, prefix, startAfter, max(settings.RefPageCount, 1))
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			startAfter = object.Key
			if settings.RefMaxCount <= export.RefCount {
				export.Truncated = true
				return export, nil
			}
			refId, err := parseEvsHexId(strings.TrimPrefix(object.Key, prefix))
			if err != nil {
				return nil, fmt.Errorf("%w: a head key that names no ref", ErrEvsPushHistoryInvalid)
			}
			export.RefCount += 1
			if err := reader.exportRef(ctx, repoId, refId, export, write); err != nil {
				return nil, err
			}
		}
		if !more || len(objects) == 0 {
			return export, nil
		}
	}
}

// Writes one ref's versions, oldest first.
func (self *evsPushHistoryReader) exportRef(
	ctx context.Context,
	repoId sidecar.Id,
	refId sidecar.Id,
	export *EvsPushHistoryExport,
	write func(row *EvsPushHistoryRow) error,
) error {
	object, err := self.stores.Cluster.Get(ctx, HeadKey(repoId, refId))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		// the ref was deleted between the LIST and the read
		return nil
	}
	if err != nil {
		return err
	}
	headBytes, err := io.ReadAll(io.LimitReader(object.Body, EvsHeadMaxByteCount+1))
	object.Body.Close()
	if err != nil {
		return err
	}
	head, err := ParseEvsHead(headBytes)
	if err != nil {
		return err
	}
	window, err := EvsHeadWindow(head)
	if err != nil {
		return err
	}
	windowFirst := EvsHeadWindowFirstVersion(head)
	last := head.GetVersion()
	if self.settings.RefVersionMaxCount < last {
		last = self.settings.RefVersionMaxCount
		export.Truncated = true
	}
	for version := uint64(1); version <= last; version += 1 {
		var entry *sidecar.EvsWindowEntry
		var statementBytes []byte
		if windowFirst <= version {
			entry = window[version-windowFirst]
		} else {
			page, err := self.readPage(ctx, repoId, refId, EvsLogPageOf(version))
			if err != nil {
				return err
			}
			var ok bool
			entry, statementBytes, ok = page.At(version)
			if !ok {
				return fmt.Errorf("%w: a log page lacks a version it covers", ErrEvsPushHistoryInvalid)
			}
		}
		row, err := self.readVersion(ctx, repoId, refId, version, entry, statementBytes)
		if err != nil {
			return err
		}
		if err := write(row); err != nil {
			return err
		}
		export.VersionCount += 1
	}
	return nil
}

// Page n of the ref, from log/ or, once evacuated, from the pack pidx/ names.
func (self *evsPushHistoryReader) readPage(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, page uint64) (*LogPage, error) {
	logPage, err := ReadLogPage(ctx, self.pages, self.stores.Cluster, repoId, refId, page)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return logPage, err
	}
	pageBytes, err := self.locator.ReadLogPage(ctx, self.stores.Cluster, repoId, refId, page)
	if err != nil {
		return nil, err
	}
	return ParseLogPage(repoId, refId, page, pageBytes)
}

// The record at place: its batch, else the container pidx/ names.
func (self *evsPushHistoryReader) readRecord(ctx context.Context, repoId sidecar.Id, refId sidecar.Id, place *protocol.EvsPlace) (*sidecar.EvsBatchRecord, error) {
	record, err := ReadRecord(ctx, self.records, self.stores.Cluster, place)
	if !errors.Is(err, ErrEvsRecordEvacuated) {
		return record, err
	}
	recordBytes, err := self.locator.ReadRecord(ctx, self.stores.Cluster, repoId, refId, place)
	if err != nil {
		return nil, err
	}
	return self.records.parseRecord(recordBytes)
}

// One version's row: its statement from the page when given, else from its record, held to the window entry, and the
// segments a one-part push's record introduced.
func (self *evsPushHistoryReader) readVersion(
	ctx context.Context,
	repoId sidecar.Id,
	refId sidecar.Id,
	version uint64,
	entry *sidecar.EvsWindowEntry,
	statementBytes []byte,
) (*EvsPushHistoryRow, error) {
	var record *sidecar.EvsBatchRecord
	recordErr := error(nil)
	if entry.Place != nil && 0 < entry.Place.GetLength() {
		record, recordErr = self.readRecord(ctx, repoId, refId, entry.Place)
	} else {
		recordErr = errors.New("no place")
	}
	var payloadBytes []byte
	if record != nil {
		if record.PushId != entry.PushId || record.RepoId != repoId || record.RefId != refId {
			return nil, fmt.Errorf("%w: another push's record at a version's place", ErrEvsPushHistoryInvalid)
		}
		switch record.Type {
		case protocol.EvsBatchRecordType_EVS_BATCH_PUSH, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
			recordStatement, recordPayload, err := sidecar.ParseEvsPushRecordBody(record.Body)
			if err != nil {
				return nil, err
			}
			if statementBytes == nil {
				statementBytes = recordStatement
			}
			payloadBytes = recordPayload
		case protocol.EvsBatchRecordType_EVS_BATCH_SEAL:
			recordStatement, _, err := sidecar.ParseEvsSealRecordBody(record.Body)
			if err != nil {
				return nil, err
			}
			if statementBytes == nil {
				statementBytes = recordStatement
			}
		default:
			return nil, fmt.Errorf("%w: a record of type %d at a version's place", ErrEvsPushHistoryInvalid, record.Type)
		}
	}
	if statementBytes == nil {
		// a window version's statement is in its record alone
		return nil, fmt.Errorf("%w: version %d's record: %v", ErrEvsPushHistoryInvalid, version, recordErr)
	}
	statement, err := sidecar.ParseEvsStatementFormat2(statementBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEvsPushHistoryInvalid, err)
	}
	if !entry.Names(sidecar.Id(statement.Push.GetPushId()), statement.Sha256) {
		return nil, fmt.Errorf("%w: a statement its entry does not name", ErrEvsPushHistoryInvalid)
	}
	push := statement.Push
	row := &EvsPushHistoryRow{
		RepoId:          repoId,
		RefId:           refId,
		Version:         version,
		PushId:          sidecar.Id(push.GetPushId()),
		SignerSidecarId: evsPushHistoryId(push.GetSignerSidecarId()),
		OwnerSidecarId:  evsPushHistoryId(push.GetOwnerSidecarId()),
		ClientId:        evsPushHistoryId(push.GetClientId()),
		TimeMs:          push.GetTimeMs(),
		RefKind:         push.GetRefKind(),
		RefMode:         push.GetRefMode(),
		Flags:           push.GetFlags(),
		BaseVersion:     push.GetBaseVersion(),
		PartCount:       push.GetPartCount(),
		ChangeCount:     uint32(len(statement.Changes)),
		TokenPaths:      []string{},
	}
	if len(push.GetChangesRoot()) != 0 {
		row.ChangeCount = push.GetChangeCount()
		row.TokenPrefixes = true
		for _, prefix := range statement.ChangedPrefixes {
			row.TokenPaths = append(row.TokenPaths, evsPushHistoryTokenPath(prefix))
		}
	} else {
		for _, change := range statement.Changes {
			row.TokenPaths = append(row.TokenPaths, evsPushHistoryTokenPath(change.TokenPath))
		}
	}
	if payloadBytes != nil && push.GetPartCount() == 0 {
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrEvsPushHistoryInvalid, err)
		}
		row.SizesRead = true
		row.Segments = []*EvsPushHistorySegment{}
		for _, object := range payload.NewObjects {
			if object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT && object.Kind != protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT {
				// a slot is a key's place, which the history leaves out
				continue
			}
			row.Segments = append(row.Segments, &EvsPushHistorySegment{
				SegmentId:  fmt.Sprintf("%x", object.Id),
				PaddedSize: object.PaddedSize,
				UploadDay:  object.UploadDay,
			})
		}
	}
	return row, nil
}

// An id field of 16 bytes as an id, the zero id for any other width.
func evsPushHistoryId(idBytes []byte) sidecar.Id {
	if len(idBytes) != 16 {
		return sidecar.Id{}
	}
	return sidecar.Id(idBytes)
}

// A token path as object keys write its components, joined by /.
func evsPushHistoryTokenPath(tokenPath sidecar.EvsTokenPath) string {
	components := make([]string, len(tokenPath))
	for index, token := range tokenPath {
		components[index] = token.String()
	}
	return strings.Join(components, "/")
}
