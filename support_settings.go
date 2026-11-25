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

	// The support client (§28.6, §28.14). The release's support switch, off until G-SUP-service passes (§28.21): while
	// it is off every surface answers ErrSupportUnavailable, no MCP session lists the tools, and nothing is posted. A
	// test turns it on.
	ServiceEnabled bool
	// A message's text, in bytes: the format's 16 KiB, whose one default is CanonicalActionSettings'
	// SupportTextMaxByteCount, since field 80 carries the same text.
	MessageMaxByteCount int
	// A message's files: 3, CanonicalActionSettings' SupportFileMaxCount (§28.7).
	FileMaxCount int
	// One file's bytes: 10 MiB (§28.7, FB section 9).
	FileMaxByteCount int64
	// An agent's messages: 5 an hour and 20 a day (§28.14).
	AgentHourMaxCount int
	AgentDayMaxCount  int
	// The network's agents' messages a day, as this device counts them: 50 (§28.14); the service counts the network's
	// across its devices.
	NetworkDayMaxCount int
	// The person's messages: FB's 10 an hour and 50 a day (§28.14).
	PersonHourMaxCount int
	PersonDayMaxCount  int
	// Messages waiting in the outbox: 10 an agent and 50 the device (§28.14), past which a send is support_queue_full.
	OutboxAgentMaxCount  int
	OutboxDeviceMaxCount int
	// One bundle a network every 5 minutes, the server's rule today (§28.14).
	BundleMinInterval time.Duration
	// The outbox's retries: after 1 minute, then twice as long each time up to an hour, for 7 days, FB's retry window,
	// under one client_ref; then it gives up (§28.14).
	RetryFirstInterval time.Duration
	RetryMaxInterval   time.Duration
	RetryWindow        time.Duration
	// How long a sent message's bundle and files stay on the device for the person to read: 7 days (§28.7).
	SentBundleRetention time.Duration
	// How often the client's loop looks at its outbox and the member's events with no wake: 30 s.
	LoopInterval time.Duration
	// One call to the feedback service: 30 s.
	PostTimeout time.Duration
	// The most of one answer the client reads: 1 MiB, past any entry or lookup the service answers.
	ResponseMaxByteCount int64
	// The most of one event stream the client reads before it reads again from its cursor: 16 MiB.
	EventStreamMaxByteCount int64
	// One event's data: 64 KiB, a note or body of 16 KiB with room for its fields.
	EventMaxByteCount int
	// The most events one read takes: 1,000.
	EventsMaxCount int
	// The conversation's items this device keeps in its view: 1,000, the oldest updated first out.
	ConversationMaxItemCount int
	// The client's state file, and one outbox message's: 64 MiB, a full view of 16 KiB messages.
	StateMaxByteCount int64
	// How long one call of ur support watch waits for an update before it answers none and is called again: 25 s,
	// inside a control session's request timeout.
	WatchWait time.Duration
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

		MessageMaxByteCount:      DefaultCanonicalActionSettings().SupportTextMaxByteCount,
		FileMaxCount:             DefaultCanonicalActionSettings().SupportFileMaxCount,
		FileMaxByteCount:         10 * 1024 * 1024,
		AgentHourMaxCount:        5,
		AgentDayMaxCount:         20,
		NetworkDayMaxCount:       50,
		PersonHourMaxCount:       10,
		PersonDayMaxCount:        50,
		OutboxAgentMaxCount:      10,
		OutboxDeviceMaxCount:     50,
		BundleMinInterval:        5 * time.Minute,
		RetryFirstInterval:       1 * time.Minute,
		RetryMaxInterval:         1 * time.Hour,
		RetryWindow:              7 * 24 * time.Hour,
		SentBundleRetention:      7 * 24 * time.Hour,
		LoopInterval:             30 * time.Second,
		PostTimeout:              30 * time.Second,
		ResponseMaxByteCount:     1024 * 1024,
		EventStreamMaxByteCount:  16 * 1024 * 1024,
		EventMaxByteCount:        64 * 1024,
		EventsMaxCount:           1000,
		ConversationMaxItemCount: 1000,
		StateMaxByteCount:        64 * 1024 * 1024,
		WatchWait:                25 * time.Second,
	}
}
