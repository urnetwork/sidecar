//go:build !ios_extension && !sidecar_http

// The recURd skill's settings, DESIGN-COMPUTE §20's, which SKILL's tasks fill. Every limit, size, count, time,
// interval, threshold, retry or budget the component reads is a field here, its default set only in
// DefaultSkillSettings, protocol and format limits included; only identifiers stay constants (QD-702). The struct is
// created empty by the compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go:
// SidecarSettings holds it, and DefaultSidecarSettings sets it from DefaultSkillSettings.
//
// The format limits here, a name's length, a card's fields and size, are §20.5's: every device of a member reads and
// writes the same cards, so changing one is a format change no deployment makes on one side alone.
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §20, the recURd skill: agent names, cards, status, summaries and inboxes.
type SkillSettings struct {
	// The longest agent name, §20.5's [a-z0-9][a-z0-9-]{0,47}: 48 bytes, within DESIGN §5.5's 64-byte label, so a name
	// is a label as it stands. A format limit. Positive.
	NameMaxByteCount int
	// How many words of a task a name is derived from when neither the launch nor the harness config names one (§20.5's
	// step 1): 4, enough to tell tasks apart in a list. Positive.
	NameDerivedWordCount int
	// The highest suffix registration tries for a taken name, <name>-2 to <name>-NameSuffixMax (§20.5's step 2): 99, so
	// a member's agents rarely run out of one name's suffixes and a registration's reads stay bounded. At least 2.
	NameSuffixMax int
	// How long a card waits with no status before any device of its member retires it (§20.5): 30 days. Positive.
	RetireAfterIdle time.Duration
	// How long after a card is retired its name may be taken by another agent (§20.5, as an overlay address's tombstone
	// is, DESIGN §17.4): 30 days. Not negative.
	NameReuseAfter time.Duration
	// The largest card a reader opens: 4 KiB, a card's fields bounded below with room for a later version's. A format
	// limit. Positive.
	CardMaxByteCount int
	// The longest of a card's free fields, its harness and model (§20.5): 128 bytes, a canonical model name's or a
	// harness's name and version with room to spare. A format limit. Positive.
	CardFieldMaxByteCount int
	// How many versions of one card path a reader walks to judge it (agentsReaderCheck): 256, past which the path reads
	// as withheld rather than walked without bound. Positive.
	CardHistoryMaxCount int
	// How many cards one listing reads (AgentsClient.Cards): 1,024, a member's agents with room to spare. Positive.
	CardListMaxCount int
	// How many times a card's write is tried when another write lands first, each try on a fresh read: 3, since only
	// the member's own devices and agents write the repo. Positive.
	CardWriteAttemptCount int
	// How many parents a message's landing walks up for a child with no repo of its own (AgentsClient.AgentRepo): 16,
	// deeper than any launch tree a Harness's eight concurrent agents make. Positive.
	AncestorWalkMaxCount int
	// The most words a rendering of the skill's text holds (§20.9): 1,500, for every profile. Positive.
	TextWordCount int
}

// The component's defaults, the only place one is set.
func DefaultSkillSettings() *SkillSettings {
	return &SkillSettings{
		NameMaxByteCount:      48,
		NameDerivedWordCount:  4,
		NameSuffixMax:         99,
		RetireAfterIdle:       30 * 24 * time.Hour,
		NameReuseAfter:        30 * 24 * time.Hour,
		CardMaxByteCount:      4 * 1024,
		CardFieldMaxByteCount: 128,
		CardHistoryMaxCount:   256,
		CardListMaxCount:      1024,
		CardWriteAttemptCount: 3,
		AncestorWalkMaxCount:  16,
		TextWordCount:         1500,
	}
}
