//go:build !ios_extension && !sidecar_http

// The support skill's settings, DESIGN-COMPUTE §28's: the support log's ring and bundles (§28.7), and the support
// client's checks, outbox and limits (§28.6, §28.14). Every limit, size, count, time, interval, threshold, retry or
// budget either reads is a field here, its default set only in DefaultSupportSettings, format limits included; only
// identifiers stay constants (QD-702). SidecarSettings holds it, and DefaultSidecarSettings sets it from
// DefaultSupportSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §28, the support skill: the support log and the support client.
type SupportSettings struct {
	// The ring (§28.7): the most bytes its segments hold together, 8 MiB. The oldest segment goes first once they
	// pass it, so the ring holds at most this, a segment's worth of writes aside while one rotates.
	RingMaxByteCount int64
	// The ring keeps 7 days of events, whichever bound comes first: an older event is never read into a bundle, and
	// a segment whose successor began before it is removed.
	RingMaxAge time.Duration
	// One segment's most bytes before a new one begins: 512 KiB, a sixteenth of the ring, so pruning drops at most
	// that much at a time.
	SegmentMaxByteCount int64
	// One segment's longest span before a new one begins: 1 day, so the age bound removes old events within a day of
	// their passing it.
	SegmentMaxAge time.Duration
	// The encoded events Event holds for the writer: 64 KiB. Event never waits on the disk; past this it drops and
	// counts, and the count goes into the ring as events_dropped.
	PendingMaxByteCount int
	// How often the writer flushes held events to the ring: 1 s. A bundle and Close flush first.
	FlushInterval time.Duration
	// The most fields one event carries: 16, past every code the registry declares. A format limit: the ring's
	// reader refuses a record with more.
	EventMaxFieldCount int
	// The longest version a version field holds, in bytes: 32, room for yyyy.m.d+code and a harness's semver. A
	// longer one is held as invalid, never cut.
	VersionMaxByteCount int
	// The longest record the ring's reader takes, in bytes: 4 KiB, far past the largest event the registry allows. A
	// longer one ends its segment's reading, as a truncated record does.
	RecordMaxByteCount int
	// The ring's token key, in bytes: 32, HMAC-SHA256's block-safe key size.
	RingKeyByteCount int
	// A token as the ring holds it, in bytes: 16 of HMAC-SHA256 under the ring's key.
	RingTokenByteCount int

	// A bundle (§28.7): compressed, at most 4 MiB. Past it the oldest events are left out, and the header says how
	// many.
	BundleMaxByteCount int64
	// The window a message without an item takes: the last 24 hours.
	BundleDefaultWindow time.Duration
	// The longest window any bundle takes: 7 days.
	BundleMaxWindow time.Duration
	// A token as a bundle holds it, in bytes: 8, the first of HMAC-SHA256 under the bundle's salt (§28.7).
	BundleTokenByteCount int
	// A bundle's salt, in bytes: 32, drawn for each bundle and kept in none.
	BundleSaltByteCount int
	// The most times a bundle halves its events to fit BundleMaxByteCount before it gives up: 24, past the ring's
	// most events.
	BundleFitAttemptCount int
}

// The component's defaults, the only place one is set.
func DefaultSupportSettings() *SupportSettings {
	return &SupportSettings{
		RingMaxByteCount:      8 * 1024 * 1024,
		RingMaxAge:            7 * 24 * time.Hour,
		SegmentMaxByteCount:   512 * 1024,
		SegmentMaxAge:         24 * time.Hour,
		PendingMaxByteCount:   64 * 1024,
		FlushInterval:         1 * time.Second,
		EventMaxFieldCount:    16,
		VersionMaxByteCount:   32,
		RecordMaxByteCount:    4 * 1024,
		RingKeyByteCount:      32,
		RingTokenByteCount:    16,
		BundleMaxByteCount:    4 * 1024 * 1024,
		BundleDefaultWindow:   24 * time.Hour,
		BundleMaxWindow:       7 * 24 * time.Hour,
		BundleTokenByteCount:  8,
		BundleSaltByteCount:   32,
		BundleFitAttemptCount: 24,
	}
}
