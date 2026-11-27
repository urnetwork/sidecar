//go:build !ios_extension && !sidecar_http

// Context history's settings, DESIGN-COMPUTE §24's, which CTXH's tasks fill. Every limit, size, count, time, interval,
// threshold, retry or budget the component reads is a field here, its default set only in DefaultSessionSettings,
// protocol and format limits included; only identifiers stay constants (QD-702). The struct is created empty by the
// compute skeleton (CARCH-M11-01, CONTRACTS C-38), so no later task edits settings.go: SidecarSettings holds it, and
// DefaultSidecarSettings sets it from DefaultSessionSettings.
//
// The caps both ends of the record share, a node's item and parts and a blob's piece, are the record's format values,
// which every reader checks at step 5 (RECORD.md section 5.5): they live in RecordBodySettings, the format's own
// object, and Body carries it here, so its defaults stay in one place (CTXH-M11-01).
//
// Only the legs that run compute build this file. The forwarding leg, which runs only IP and port forwarding (owner
// decision 197), and the page Worker's sidecar_http leg, which gets no compute surface (DESIGN-COMPUTE §15.4), declare
// an empty stand-in instead (sidecar_compute_leg.go).

package sidecar

import (
	"time"
)

// DESIGN-COMPUTE §24, context history in EVS: a run's session entries and blobs, its journal, rebuilds and storage.
type SessionSettings struct {
	// How long a session entry journaled at a call waits for a push of its writer's that would carry it, before it
	// leaves in one of its own (§24.5's pushes row, D-CTXH-12): 60 s. Session entries make no push of their own at a
	// call; they leave in the push that carries their call's model_call, at the turn's end, or this long after the
	// oldest of them was journaled. The harness config's record.session_push_secs sets it within PushIntervalMin and
	// PushIntervalMax (PushIntervalFor).
	PushInterval time.Duration
	// record.session_push_secs' bounds: 30 s and 300 s (§24.5).
	PushIntervalMin time.Duration
	PushIntervalMax time.Duration
	// How long the gateway's index keeps a run's chain hashes after its last call, so a later request finds its prefix
	// (§24.8's index row): 24 h. A run continued after this rebuilds its index from its nodes.
	GatewayIndexWindow time.Duration
	// The bytes of recorded forms the gateway's recorder keeps in memory for one run, by the item's own hash, so a long
	// session's requests, which carry its whole history at every call, are redacted and hashed only for their new
	// items (session_gateway.go): 32 MiB. Past it the run's forms are dropped and taken again; 0 keeps none.
	GatewayFormByteCount int
	// The most runs one request's prefix is looked for in: its own, the runs it continues and the runs its binding
	// names as resumed (§24.8's resume row): 8.
	GatewayResumeRunCount int
	// History stops leaving the device at this fraction of the network's storage (§24.10's caps row, Q-CTXH-13): 0.9.
	NetworkCapFraction float64
	// The storage view warns at this fraction of the network's storage, or of a member's share of it, naming the largest
	// runs (§24.10's see row): 0.8.
	WarningFraction float64
	// The warning's one tap expires the oldest blobs until history is under this fraction of the cap it warned at: 0.7.
	ExpiryTargetFraction float64
	// A member's share of the network's history storage, which a Team's Owner or Admin sets within these, the compute
	// block's history.member_share (§16.4, Q-CTXH-16): 0.05 and 1. auto, the default, is all of it for a network of one
	// member and 2/n for one of n.
	MemberShareMin float64
	MemberShareMax float64
	// The largest runs the storage view's warning names (§24.10's see row): 5.
	WarningRunCount int
	// How long the caps take the network's storage limit as last read before they read GET /sidecar/limits again: 1 h.
	LimitReadInterval time.Duration
	// How often a Sidecar checks the caps, and expires at a cap where the person's switch is on (session_component.go):
	// 5 min. 0 checks only at a storage view, an expiry and a prune.
	CapCheckInterval time.Duration
	// The fewest hex characters of a node's id that name it, where a person gives a prefix of one (`ur harness continue
	// --at`, CTXH-M11-05): 8, the short form `ur harness show` prints.
	NodePrefixMinCount int
	// The record's caps a node, a part and a blob are held to, which every reader checks too (RECORD.md section 5.5's
	// step 5): RecordBodySettings' own, carried rather than copied.
	Body *RecordBodySettings
}

// The component's defaults, the only place one is set.
func DefaultSessionSettings() *SessionSettings {
	return &SessionSettings{
		PushInterval:          60 * time.Second,
		PushIntervalMin:       30 * time.Second,
		PushIntervalMax:       300 * time.Second,
		GatewayIndexWindow:    24 * time.Hour,
		GatewayFormByteCount:  32 * 1024 * 1024,
		GatewayResumeRunCount: 8,
		NetworkCapFraction:    0.9,
		WarningFraction:       0.8,
		ExpiryTargetFraction:  0.7,
		MemberShareMin:        0.05,
		MemberShareMax:        1,
		WarningRunCount:       5,
		CapCheckInterval:      5 * time.Minute,
		LimitReadInterval:     1 * time.Hour,
		NodePrefixMinCount:    8,
		Body:                  DefaultRecordBodySettings(),
	}
}

// The push interval the harness config's record.session_push_secs gives, within PushIntervalMin and PushIntervalMax:
// a value below the bound takes the bound, one above it the other, and a non-positive one, no setting, PushInterval.
func (self *SessionSettings) PushIntervalFor(pushSecs int) time.Duration {
	if pushSecs <= 0 {
		return self.PushInterval
	}
	interval := time.Duration(pushSecs) * time.Second
	return min(max(interval, self.PushIntervalMin), self.PushIntervalMax)
}

// The record's caps: Body, or RecordBodySettings' defaults where it is nil.
func (self *SessionSettings) body() *RecordBodySettings {
	if self.Body != nil {
		return self.Body
	}
	return DefaultRecordBodySettings()
}
