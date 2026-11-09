// Reading a record once its batch is gone (§11.8's read row, §11.13's readers and negative rows; EVSB-M2-10):
// RecordLocator reads a record at its place in its batch, and when the batch answers 404, finds it in pidx/: LIST
// pidx/<repo>/<ref>/, GET each entry it has not yet read (entries never change, so each is read once and kept), take
// a pack's entry over a parcel's for a record both name, and range-read the container. evsservice's reads and
// EVS1-M2-14's go through it.
//
// The negative rule: a cached list that misses, or a 404 on the container an entry names, drops the ref's cached
// list and lists once more. A container precedes its entries, and both precede the deletion of what they replace
// (I-EVS-7), so one relist finds a record that has moved, wherever a reader was paused. Past that, ErrBlobNotFound.
//
// Safe for concurrent use. No lock is held across a store call.

package evsservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

type RecordLocatorSettings struct {
	// How many refs' entry lists are kept, the oldest read dropped first: 4,096.
	CacheRefCount int
	// Keys a LIST page: 1,000.
	ListLimit int
	// The most entries one ref's list reads before it fails, bounding a read's work: 100,000.
	MaxEntryCount int
}

func DefaultRecordLocatorSettings() *RecordLocatorSettings {
	return &RecordLocatorSettings{
		CacheRefCount: 4096,
		ListLimit:     1000,
		MaxEntryCount: 100000,
	}
}

// A cached ref: its pidx/ entries by key, as of its last list.
type locatorRef struct {
	keys    []string
	entries map[string]*protocol.EvsPidxEntry
}

// See the file header.
type RecordLocator struct {
	blobs    sidecar.BlobStore
	settings *RecordLocatorSettings

	stateLock sync.Mutex
	refs      map[string]*locatorRef
	// ref keys, oldest listed first
	order []string
}

// A locator over blobs, whose segment cluster holds packs. settings may be nil for the defaults.
func NewRecordLocator(blobs sidecar.BlobStore, settings *RecordLocatorSettings) *RecordLocator {
	if settings == nil {
		settings = DefaultRecordLocatorSettings()
	}
	return &RecordLocator{
		blobs:    blobs,
		settings: settings,
		refs:     map[string]*locatorRef{},
	}
}

// The record at place on repo's ref, in metadataCluster, its bytes as its batch held them: from the batch while it
// stands, else from the container pidx/ names. ErrBlobNotFound when neither holds it.
func (self *RecordLocator) ReadRecord(ctx context.Context, metadataCluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, place *protocol.EvsPlace) ([]byte, error) {
	if place == nil || place.GetLength() == 0 {
		return nil, fmt.Errorf("%w: no place", ErrEvsPidxInvalid)
	}
	recordBytes, err := readBlobRange(ctx, metadataCluster, BatchKey(place.GetMinute(), place.GetInstance(), place.GetSeq()), int64(place.GetOffset()), int64(place.GetLength()))
	if !errors.Is(err, sidecar.ErrBlobNotFound) {
		return recordBytes, err
	}
	refKey := PidxRefPrefix(repoId, refId)
	for attempt := range 2 {
		fresh := 0 < attempt
		ref, err := self.ref(ctx, metadataCluster, refKey, fresh)
		if err != nil {
			return nil, err
		}
		entry, record := locateRecord(ref, place)
		if entry == nil {
			if fresh {
				return nil, fmt.Errorf("%w: no container holds the record", sidecar.ErrBlobNotFound)
			}
			continue
		}
		recordBytes, err := self.readContainer(ctx, metadataCluster, repoId, entry, int64(record.GetOffset()), int64(record.GetLength()))
		if errors.Is(err, sidecar.ErrBlobNotFound) && !fresh {
			continue
		}
		return recordBytes, err
	}
	return nil, fmt.Errorf("%w: no container holds the record", sidecar.ErrBlobNotFound)
}

// The log page of repo's ref from the pack that holds it, ErrBlobNotFound when none does. A reader asks this once
// log/ has answered 404.
func (self *RecordLocator) ReadLogPage(ctx context.Context, metadataCluster sidecar.BlobCluster, repoId sidecar.Id, refId sidecar.Id, page uint64) ([]byte, error) {
	refKey := PidxRefPrefix(repoId, refId)
	for attempt := range 2 {
		fresh := 0 < attempt
		ref, err := self.ref(ctx, metadataCluster, refKey, fresh)
		if err != nil {
			return nil, err
		}
		for _, key := range ref.keys {
			entry := ref.entries[key]
			for _, logPage := range entry.GetLogPages() {
				if logPage.GetPage() != page {
					continue
				}
				pageBytes, err := self.readContainer(ctx, metadataCluster, repoId, entry, int64(logPage.GetOffset()), int64(logPage.GetLength()))
				if errors.Is(err, sidecar.ErrBlobNotFound) && !fresh {
					break
				}
				return pageBytes, err
			}
		}
	}
	return nil, fmt.Errorf("%w: no pack holds the log page", sidecar.ErrBlobNotFound)
}

// The entry and record naming place, a pack's over a parcel's, nil when none does.
func locateRecord(ref *locatorRef, place *protocol.EvsPlace) (*protocol.EvsPidxEntry, *protocol.EvsPidxRecord) {
	var found *protocol.EvsPidxEntry
	var foundRecord *protocol.EvsPidxRecord
	for _, key := range ref.keys {
		entry := ref.entries[key]
		for _, record := range entry.GetRecords() {
			if comparePlaces(record.GetPlace(), place) != 0 || record.GetPlace().GetLength() != place.GetLength() {
				continue
			}
			if found == nil || (found.GetContainerKind() != protocol.EvsContainerKind_EVS_CONTAINER_PACK && entry.GetContainerKind() == protocol.EvsContainerKind_EVS_CONTAINER_PACK) {
				found = entry
				foundRecord = record
			}
		}
	}
	return found, foundRecord
}

// Bytes [offset, offset+byteCount) of the container entry names.
func (self *RecordLocator) readContainer(ctx context.Context, metadataCluster sidecar.BlobCluster, repoId sidecar.Id, entry *protocol.EvsPidxEntry, offset int64, byteCount int64) ([]byte, error) {
	containerId := sidecar.Id(entry.GetContainerId())
	if entry.GetContainerKind() == protocol.EvsContainerKind_EVS_CONTAINER_PACK {
		segmentCluster, err := self.blobs.SegmentCluster()
		if err != nil {
			return nil, err
		}
		return readBlobRange(ctx, segmentCluster, PackKey(repoId, containerId), offset, byteCount)
	}
	return readBlobRange(ctx, metadataCluster, ParcelKey(repoId, containerId), offset, byteCount)
}

// The ref's entries: the cached list unless fresh, else a new LIST, reading only entries not yet read.
func (self *RecordLocator) ref(ctx context.Context, metadataCluster sidecar.BlobCluster, refKey string, fresh bool) (*locatorRef, error) {
	cacheKey := metadataCluster.ClusterId() + "\x00" + refKey
	var cached *locatorRef
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached = self.refs[cacheKey]
	}()
	if cached != nil && !fresh {
		return cached, nil
	}
	keys := []string{}
	startAfter := ""
	for {
		objects, more, err := metadataCluster.List(ctx, refKey, startAfter, self.settings.ListLimit)
		if err != nil {
			return nil, err
		}
		for _, object := range objects {
			keys = append(keys, object.Key)
			startAfter = object.Key
		}
		if self.settings.MaxEntryCount < len(keys) {
			return nil, fmt.Errorf("%w: past %d entries under %s", ErrEvsPidxInvalid, self.settings.MaxEntryCount, refKey)
		}
		if !more {
			break
		}
	}
	ref := &locatorRef{entries: map[string]*protocol.EvsPidxEntry{}}
	for _, key := range keys {
		if cached != nil {
			if entry, ok := cached.entries[key]; ok {
				ref.keys = append(ref.keys, key)
				ref.entries[key] = entry
				continue
			}
		}
		firstVersion, containerId, ok := parsePidxKey(refKey, key)
		if !ok {
			return nil, fmt.Errorf("%w: key %s", ErrEvsPidxInvalid, key)
		}
		entryBytes, err := readBlob(ctx, metadataCluster, key)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// deleted since the LIST, as the nightly pass deletes a replaced parcel's entries
			continue
		}
		if err != nil {
			return nil, err
		}
		entry, err := DecodeEvsPidxEntry(entryBytes)
		if err != nil {
			return nil, err
		}
		if entry.GetFirstVersion() != firstVersion || !bytes.Equal(entry.GetContainerId(), containerId[:]) {
			return nil, fmt.Errorf("%w: %s holds another container's entry", ErrEvsPidxInvalid, key)
		}
		ref.keys = append(ref.keys, key)
		ref.entries[key] = entry
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if _, ok := self.refs[cacheKey]; !ok {
		self.order = append(self.order, cacheKey)
	}
	self.refs[cacheKey] = ref
	for self.settings.CacheRefCount < len(self.order) {
		delete(self.refs, self.order[0])
		self.order = slices.Delete(self.order, 0, 1)
	}
	return ref, nil
}

// The whole object at key.
func readBlob(ctx context.Context, cluster sidecar.BlobCluster, key string) ([]byte, error) {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	return io.ReadAll(io.LimitReader(object.Body, EvsPidxEntryMaxByteCount+1))
}

// Exactly byteCount bytes from offset of key: a range past the object's end is the store holding something other
// than what its index says.
func readBlobRange(ctx context.Context, cluster sidecar.BlobCluster, key string, offset int64, byteCount int64) ([]byte, error) {
	object, err := cluster.GetRange(ctx, key, offset, byteCount)
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	rangeBytes, err := io.ReadAll(io.LimitReader(object.Body, byteCount+1))
	if err != nil {
		return nil, err
	}
	if int64(len(rangeBytes)) != byteCount {
		return nil, fmt.Errorf("%w: %s held %d bytes at %d, not %d", ErrEvsPidxInvalid, key, len(rangeBytes), offset, byteCount)
	}
	return rangeBytes, nil
}
