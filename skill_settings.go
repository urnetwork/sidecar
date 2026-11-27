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

	// Status and summaries (§20.6; SKILL-M11-03). A turn's start and end and a tool call past the Harness's
	// HarnessSettings.ToolCallSlowAfter (10 s) note a status; HARN's setting alone says when a call is slow, so the
	// threshold has one place.

	// The least time between two of an agent's status writes (§20.6's "at most once a minute"): a minute, one P2 write
	// a minute for a busy run (DESIGN §11.13). Positive.
	StatusMinInterval time.Duration
	// How often an open run's status is written again with nothing new, so a reader tells an idle agent from a gone
	// one: 5 minutes, well within OfflineAfter. Positive.
	StatusRefreshInterval time.Duration
	// How old a status reads offline (§20.6): 15 minutes, the clearly intended reading of "whose sidecar holds no live
	// client", since no reader sees another sidecar's clients. Positive.
	OfflineAfter time.Duration
	// The longest activity a status carries, in characters (§20.6): 200. A format limit. Positive.
	StatusActivityCharCount int
	// The longest task a status carries, in characters (§20.6): 120. A format limit. Positive.
	StatusTaskCharCount int
	// The largest status file a reader opens: 2 KiB, the fields' bounds in UTF-8 with room for the names. A format
	// limit. Positive.
	StatusMaxByteCount int
	// The largest summary (§20.6): 8 KiB. A format limit. Positive.
	SummaryByteCount int
	// The minutes of active work between summaries (§20.6, Q-SKILL-3, QD-1353): 15, which the harness config's
	// skill.summary_minutes sets within SummaryMinutesMin to SummaryMinutesMax.
	SummaryMinutes int
	// The bounds of skill.summary_minutes (§20.6's "5-60"): 5 and 60.
	SummaryMinutesMin int
	SummaryMinutesMax int
	// How many reminders an agent leaves unanswered before the Harness writes a mechanical summary for it (§20.6): 2.
	// Positive.
	SummaryReminderCount int
	// How many files and how many commands a mechanical summary lists: 16 of each, the newest. Positive.
	SummaryFactCount int
	// How many versions of a status or summary path a reader walks for the newest one its writer pushed: 256, past
	// which the path reads as withheld. Positive.
	SummaryHistoryMaxCount int
	// The most bytes of other writers' identifier fields one result carries (§20.6): 4 KiB, further agents counted,
	// not listed, with a cursor. Positive.
	StubByteCount int

	// Messages and threads (§20.7; SKILL-M11-04). Each is a format limit every device of a network shares.

	// The longest subject, in characters (§20.7): 120. Positive.
	SubjectCharCount int
	// The largest body, markdown (§20.7): 32 KiB. Positive.
	BodyByteCount int
	// The most refs a message carries: 16. Positive.
	MessageRefMaxCount int
	// The longest path a ref names: 1,024 bytes. Positive.
	MessageRefPathByteCount int
	// The largest message file a reader opens: 40 KiB, a body and subject at their bounds and its refs. Positive.
	MessageMaxByteCount int
	// How many versions of a message path a reader walks to find its first: 64, past which the message is withheld.
	// Positive.
	MessageHistoryMaxCount int
	// How many times a message's create-only write is tried when its write fails without an answer: 3, each try
	// reading the path first, so a lost answer writes no second file. Positive.
	MessageWriteAttemptCount int
	// How many messages the device's sealed outbox holds unsent: 256, past which a send is refused until some land.
	// Positive.
	OutboxMaxCount int
	// How many thread directories, and how many messages in one, a read lists: 1,024. Positive.
	ThreadListMaxCount int

	// Delivery (§20.7's notify, where agents wait and loops rows; SKILL-M11-05).

	// The most wakes an agent takes for inbox messages in WakeWindow without a person's input (§20.7,
	// skill.max_wakes_per_hour): 20. Positive.
	MaxWakesPerHour int
	// The most of those wakes one sending sidecar makes (skill.max_wakes_per_sender): 5, support counting as one
	// sender (Q-SUP-11). Positive.
	MaxWakesPerSender int
	// The window the wake limits count over: an hour. Positive.
	WakeWindow time.Duration
	// The most messages a thread holds (§20.7): 200, past which the delivery stops queuing it. Positive.
	ThreadMessageMax int
	// The least time between two of a watch's reads of its inboxes, however often their leases fire: a second, so a
	// burst of changes costs one read. Positive.
	WatchPassMinInterval time.Duration
	// How long a watch waits before reading again after a read failed: 30 seconds. Positive.
	WatchRetryWait time.Duration
	// How many messages one take of untaken threads hands over at once: 1,024, the rest at the next. Positive.
	UntakenMaxCount int
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

		StatusMinInterval:       time.Minute,
		StatusRefreshInterval:   5 * time.Minute,
		OfflineAfter:            15 * time.Minute,
		StatusActivityCharCount: 200,
		StatusTaskCharCount:     120,
		StatusMaxByteCount:      2 * 1024,
		SummaryByteCount:        8 * 1024,
		SummaryMinutes:          15,
		SummaryMinutesMin:       5,
		SummaryMinutesMax:       60,
		SummaryReminderCount:    2,
		SummaryFactCount:        16,
		SummaryHistoryMaxCount:  256,
		StubByteCount:           4 * 1024,

		SubjectCharCount:         120,
		BodyByteCount:            32 * 1024,
		MessageRefMaxCount:       16,
		MessageRefPathByteCount:  1024,
		MessageMaxByteCount:      40 * 1024,
		MessageHistoryMaxCount:   64,
		MessageWriteAttemptCount: 3,
		OutboxMaxCount:           256,
		ThreadListMaxCount:       1024,

		MaxWakesPerHour:      20,
		MaxWakesPerSender:    5,
		WakeWindow:           time.Hour,
		ThreadMessageMax:     200,
		WatchPassMinInterval: time.Second,
		WatchRetryWait:       30 * time.Second,
		UntakenMaxCount:      1024,
	}
}
