// The index format's limits (protocol/INDEX-FORMAT.md; DESIGN-DETAILS 11.2.1 and 1.2.1): extractor 1's bounds, which
// make it one pass in fixed memory, how a text is cut into documents, what a writer's files hold, how a merge lays out
// a partition's shards, and the times every index builder and the roll-up's lock keep. They are format bytes and
// protocol values, and changing one is another format or extractor, so no device sets them on its own; this one object
// holds them and its defaults stay here (QD-702).
// Every function that extracts, plans a head or reads a slot reads the instance it is given; a view carries the one it
// was loaded with. It links on every leg, since the slot codec does, and imports nothing.

package sidecar

import (
	"time"
)

// What extractor 1 holds at most, and how it cuts a text into documents.
type IndexFormatSettings struct {
	// A logical header line, and the joined values of one field name, past which bytes are dropped: 16,384 B (H4, H6;
	// QD-691).
	HeaderMaxByteCount int
	// The longest multipart delimiter line, and the longest blank run inside a quoted-printable soft line break:
	// 1,024 B (B1, T3; QD-691). A longer one is text.
	LineWindowByteCount int
	// The multipart levels entered: 16 (M2). A multipart deeper gives nothing.
	MimeMaxDepth int
	// A document's share of its source's text: 1,048,576 B (D4).
	ChunkByteCount int
	// What a document repeats of the next, so a query of up to this across a boundary is found: 256 B (D4).
	OverlapByteCount int
	// The bytes that decide text or binary: 8,000, git's (S2).
	SniffByteCount int
	// A file's title, cut on a code point: 80 B (S4).
	TitleMaxByteCount int
	// A slot, its header and entries: 16,208 B, so its record is 16 KiB with 11.6's 160 B header and one 16 B frame
	// tag inside it (SlotMax).
	SlotMaxByteCount int
	// An entry in a slot: 8,192 B; a full entry past it is a large entry, and a diff past it is written full
	// (EntryMax).
	SlotEntryMaxByteCount int
	// A large entry, header and entry: 1,048,576 B (LargeMax).
	LargeMaxByteCount int
	// A push's encoded entries past which they go straight into the bucket's shards as full entries, a merge inside
	// the push: 262,144 B (DirectBytes).
	PushDirectByteCount int
	// Slots a writer holds in a bucket that no diff rests on, before it must merge: 8 (RingSlots).
	RingSlotCount int
	// Slots a writer keeps in a bucket for the diffs of its unabsorbed slots that rest on them: 8 (KeepSlots). A diff
	// that would keep a ninth is written full.
	KeepSlotCount int
	// Two adjacent shards of a partition that come to fewer bytes than this before their pads become one under the
	// lower n: 524,288 B (ShardJoin). It decides a merge's and a roll-up's bytes, so every device lays out alike.
	ShardJoinByteCount int
	// A bucket's sealed slots and unabsorbed large entries, in plaintext bytes, at which a merge is due: 131,072 B
	// (MergeBytes).
	MergeDueByteCount int
	// A roll-up lock's term, from the taking push's signed time: 30 min (LockTerm). Its holder renews it at half the
	// term while it works.
	LockTerm time.Duration
	// How far past a held lock's until_ms a taker's signed time must be before the lock is free to take: 10 min
	// (LockGrace), evs's bound on a push's time, so two honest runners never both hold it.
	LockGrace time.Duration
	// From an index push's signed time, taken before its first read, to the last moment it may be sent, on the
	// monotonic and the wall clock both: 5 min (IndexPushLife; R5). A push past it is built again, never sent. A push
	// in parts (11.8) lives 25 min, which its builder adds when parts land.
	PushLife time.Duration
}

// DESIGN-DETAILS 11.2.1's and 1.2.1's values, the only source of their defaults. A fresh value each call, sharing nothing
// mutable with any other.
func DefaultIndexFormatSettings() *IndexFormatSettings {
	return &IndexFormatSettings{
		HeaderMaxByteCount:    16 * 1024,
		LineWindowByteCount:   1024,
		MimeMaxDepth:          16,
		ChunkByteCount:        1024 * 1024,
		OverlapByteCount:      256,
		SniffByteCount:        8000,
		TitleMaxByteCount:     80,
		SlotMaxByteCount:      16208,
		SlotEntryMaxByteCount: 8 * 1024,
		LargeMaxByteCount:     1024 * 1024,
		PushDirectByteCount:   256 * 1024,
		RingSlotCount:         8,
		KeepSlotCount:         8,
		ShardJoinByteCount:    512 * 1024,
		MergeDueByteCount:     128 * 1024,
		LockTerm:              30 * time.Minute,
		LockGrace:             10 * time.Minute,
		PushLife:              5 * time.Minute,
	}
}
