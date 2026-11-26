// The model routes' settings (DESIGN-COMPUTE §14.3, §6.5; CO-49; QD-702): each route's per-address window and count,
// apart, the cache lifetime of what they answer, the bounds of what they read from the mirror, and the served files
// they keep in memory.

package handler

import (
	"time"
)

// Read by ComputeModelRoutes; DefaultComputeModelRouteSettings is the only place a default is set.
type ComputeModelRouteSettings struct {
	// The index route's per-address limit: IndexAddressCount requests from one caller address's /29 or /56 in each
	// fixed, epoch-aligned window of IndexAddressWindow, every request counted before anything is read, a malformed or
	// refused one included. 60 a minute: a device fetches a file's index once a download, and the devices behind one
	// exit start a few downloads a minute at most. Past it the route answers 429 with the rest of the window as its
	// Retry-After. A non-positive count refuses every request; a window under a millisecond cannot be counted, so every
	// request answers 503.
	IndexAddressWindow time.Duration
	IndexAddressCount  int64
	// The chunk route's per-address limit, counted apart from the index route's: 600 a minute, ten 16 MiB chunks a
	// second, about 1.3 Gbit/s, so one device fetching four chunks at a time (§6.5) runs at its link's full speed and
	// the devices behind one exit share that rate; a 16 GB file, about a thousand chunks, takes under two windows at
	// the cap. As the index route's for a non-positive count or a window under a millisecond.
	ChunkAddressWindow time.Duration
	ChunkAddressCount  int64

	// Cache-Control's max-age of a served answer: 365 days, the usual bound for an immutable answer. A file's index and
	// chunks never change under its SHA-256, so the caches before the api may keep them as long as they like (§14.8).
	// Non-positive sends max-age=0, which still marks the answer immutable.
	CacheMaxAge time.Duration
	// The Retry-After of an answer the mirror's store or the limit's count could not give: 5 seconds, a retry soon
	// enough that a download barely waits, and late enough that a store in trouble is not asked again at once. Below a
	// second it is sent as one second.
	UnavailableRetryAfter time.Duration

	// The largest index the routes read from the mirror: 1 MiB. An index is about 70 bytes a chunk (QD-1408), so this
	// holds a 64 GiB file's at 16 MiB chunks nearly four times over; a larger stored index answers 500 and is not
	// served. INFER-M11-10's ModelIndexMaxByteCount is the format's own bound, and once it lands this default is that
	// one, so the routes never refuse an index the format allows.
	IndexMaxByteCount int64
	// The largest chunk a served index may name, in bytes: 64 MiB, four times §6.5's 16 MiB, so a chunk's answer stays
	// within ChunkWriteTimeout on a slow link. An index naming more answers 500. As IndexMaxByteCount, INFER-M11-10's
	// ModelChunkMaxByteCount once it lands.
	ChunkMaxByteCount int64
	// How long a chunk's answer may take to write: 5 minutes, a 16 MiB chunk to a client reading under half a megabit a
	// second, past the api's own 30 s write timeout, which a chunk's answer replaces. Non-positive keeps the server's.
	ChunkWriteTimeout time.Duration

	// The served files kept in memory, each with its index's bytes and its chunks' hashes, so a chunk's answer is the
	// one object read of its bytes: 64, many times the handful of local files a release serves (§6.5's launch files),
	// at most 64 indexes of IndexMaxByteCount. Past it the file kept longest is dropped. Non-positive keeps none, and
	// every answer reads the file's state and index again.
	ServedFileCacheCount int
	// How long a kept file is answered from memory before its state is read again: 5 minutes, so a file a release
	// stops serving leaves the routes within that, while a download's thousand chunk requests read its state once.
	// Non-positive keeps none.
	ServedFileCacheTimeout time.Duration
}

// The routes' defaults.
func DefaultComputeModelRouteSettings() *ComputeModelRouteSettings {
	return &ComputeModelRouteSettings{
		IndexAddressWindow:     time.Minute,
		IndexAddressCount:      60,
		ChunkAddressWindow:     time.Minute,
		ChunkAddressCount:      600,
		CacheMaxAge:            365 * 24 * time.Hour,
		UnavailableRetryAfter:  5 * time.Second,
		IndexMaxByteCount:      1024 * 1024,
		ChunkMaxByteCount:      64 * 1024 * 1024,
		ChunkWriteTimeout:      5 * time.Minute,
		ServedFileCacheCount:   64,
		ServedFileCacheTimeout: 5 * time.Minute,
	}
}
