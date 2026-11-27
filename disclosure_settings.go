//go:build !ios_extension && !sidecar_http

// Compute disclosures' settings, DESIGN-COMPUTE §2.8's, which CTRUST's tasks fill. Every limit, size, count, time,
// interval, threshold, retry or budget the component reads is a field here, its default set only in
// DefaultComputeDisclosureSettings, protocol and format limits included; only identifiers stay constants (QD-702). The
// struct is created empty by the compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go:
// SidecarSettings holds it, and DefaultSidecarSettings sets it from DefaultComputeDisclosureSettings.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §2.8, the disclosures and their acknowledgments.
type ComputeDisclosureSettings struct {
	// The longest slug an id takes after its family's colon, in bytes: 63, a reading, a DNS label's bound, which a
	// provider's or a service's slug fits with room (§2.8's ids, CTRUST-M11-01). The whole id stays within ATTEST's
	// PolicyMaxIdByteCount, which the policy's parse holds it to. A longer slug is refused, never cut; non-positive
	// refuses every id.
	IdSlugMaxByteCount int
	// The longest locale tag a person's locale is read from, in bytes: 35, RFC 5646's length every implementation
	// keeps a tag to. A longer one, or one that is no tag, reads as none, so the English text shows.
	LocaleMaxByteCount int

	// The acknowledgment and the check (CTRUST-M12-01). How often a wait for an acknowledgment reads the member's
	// harness config again while nothing on this device told it of a change: 15 s, a reading, so an acknowledgment
	// made on another of the member's devices lands in a waiting run within a sync and a read; only the store's key
	// ends a wait, never an answer to the request. Non-positive reads again only when told.
	AwaitRecheckInterval time.Duration
	// How long a read of the member's harness config may take for a caller that passes no context, the support
	// client's disclosure state: 30 s, a reading, a vault read over a slow link. Past it the read fails, and the caller
	// refuses.
	SourceReadTimeout time.Duration
	// The most ids whose "changed" mark state the sidecar's own store keeps (§2.8's new version row): 256, a reading,
	// some twenty times §2.8's ids. Past it, the ids the newest verified policy no longer carries go first, then the
	// least recently touched; a forgotten id is listed anew, so its lines show changed only where the person
	// acknowledged an older version.
	MarksMaxCount int
	// The largest marks file the store reads back, in bytes: 64 KiB, room for MarksMaxCount ids with their versions.
	// A larger one reads as no marks, and each id is listed anew.
	MarksMaxByteCount int
}

// The component's defaults, the only place one is set.
func DefaultComputeDisclosureSettings() *ComputeDisclosureSettings {
	return &ComputeDisclosureSettings{
		IdSlugMaxByteCount:   63,
		LocaleMaxByteCount:   35,
		AwaitRecheckInterval: 15 * time.Second,
		SourceReadTimeout:    30 * time.Second,
		MarksMaxCount:        256,
		MarksMaxByteCount:    64 * 1024,
	}
}
