// evs's format limits (§11.6, §11.7, §11.8; EVS-FORMAT.md; DESIGN-DETAILS 10.2.2): what a statement, a payload, a
// part, a path map and a DROP hold at most, and how a builder lays a DROP out in parts. They are the protocol's
// values, and changing one is a protocol change that no deployment makes on one side alone, so the client's builder,
// evs's checks and every reader read this one object and its defaults stay here (QD-702). The codecs that take no
// instance yet read DefaultEvsFormatSettings() where they need a value; threading each side's own instance through
// them is the review phase's settings sweep (QD-706). Identifiers and fixed layouts stay constants beside their
// formats: section types and their header, the new-objects items' sizes, flag bits, actions and boundaries.
//
// On every leg. A fresh value each call, sharing nothing mutable.

package sidecar

import (
	"time"
)

// evs's format limits. See the file header.
type EvsFormatSettings struct {
	// A signed statement, as received: 1,024 B (§11.6). A statement past it is refused, never trimmed.
	StatementMaxByteCount int
	// The paths one read names: 64 (§11.9's request row), past which a writer or a mirror reads in batches.
	ReadMaxPathCount int
	// A one-part push's payload: 1 MiB, past which a push goes in parts (§11.8's parts row).
	PayloadMaxByteCount int
	// One part of a push in parts, as sent: 1 MiB.
	PartMaxByteCount int
	// The entry writes one part, or a one-part push, carries: 1,024.
	PartMaxEntryWriteCount int
	// changed_prefixes' token bytes in all: 512 B (D-EVS-20).
	ChangedPrefixesMaxByteCount int
	// The room a builder keeps in each part for its fixed fields and their framing, past its changes and slices:
	// 4 KiB. A builder's margin, not a bound evs checks.
	PartFieldsByteCount int
	// A path map's part, signed: 8 MiB; and a map's parts: 1,024 (§11.6's EvsPathMap; DESIGN-DETAILS 9.2.2).
	PathMapMaxByteCount int
	PathMapMaxPartCount int
	// The ids a record's purge list names at most, past which it is marked instead: 2,048 (§11.13's purge row).
	PurgeListMaxIdCount int
	// A DROP's paths: 1 to 1,024 (§11.7's action row).
	DropMaxPathCount int
	// A DROP path's listed versions, and a DROP's listed versions over all its paths: 1,048,576, 2^20 (QD-700), so
	// section 10 is at most 32 MiB; past either, 409 DROP_LIST.
	DropMaxListedCount int
	// A DROP's body, EvsDropHistory's bytes: 262,144 B (QD-700), checked on the received length before any hashing;
	// past it, INVALID.
	DropMaxBodyByteCount int
	// A drop's window: not_before_ms is time_ms plus this, or time_ms with now (owner decision 183): 7 days.
	DropWindow time.Duration
	// The listed values a builder puts in a part that holds no change: 32,000, 1,024,000 B (DESIGN-DETAILS 10.2.5). A
	// checker takes a slice cut anywhere.
	DropListPartValueCount int
	// One read reply frame, as encoded: 1 MiB + 64 KiB, an object's 1 MiB slice (EvsReadObject spans frames past it)
	// with room for its fields, a path with its proofs, or a statement (plan-EVS1-format-bytes#8). evs writes none
	// past it and a reader refuses one, so evs cannot make a reader buffer more.
	ReadFrameMaxByteCount int
	// The deltas one path's reply carries, a frame each after its path frame (QD-662): 255, a head window's entries,
	// since each delta is a window version past names_through. A reader refuses a path past it.
	ReadPathDeltaMaxCount int
}

// The protocol's values, the only source of their defaults.
func DefaultEvsFormatSettings() *EvsFormatSettings {
	return &EvsFormatSettings{
		StatementMaxByteCount:       1024,
		ReadMaxPathCount:            64,
		PayloadMaxByteCount:         1024 * 1024,
		PartMaxByteCount:            1024 * 1024,
		PartMaxEntryWriteCount:      1024,
		ChangedPrefixesMaxByteCount: 512,
		PartFieldsByteCount:         4 * 1024,
		PathMapMaxByteCount:         8 * 1024 * 1024,
		PathMapMaxPartCount:         1024,
		PurgeListMaxIdCount:         2048,
		DropMaxPathCount:            1024,
		DropMaxListedCount:          1024 * 1024,
		DropMaxBodyByteCount:        256 * 1024,
		DropWindow:                  7 * 24 * time.Hour,
		DropListPartValueCount:      32000,
		ReadFrameMaxByteCount:       1024*1024 + 64*1024,
		ReadPathDeltaMaxCount:       255,
	}
}

// The window in milliseconds, as not_before_ms counts it.
func (self *EvsFormatSettings) DropWindowMs() int64 {
	return self.DropWindow.Milliseconds()
}
