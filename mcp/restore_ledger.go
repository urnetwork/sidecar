//go:build !js && !ios && !android && !sdk_mobile_bind

// §16.7's edit ledger (D-MCP-15): per path, a chain of observations in the order they were made:
//
//	edit    edit{run, hook event hash, before_sha256, after_sha256}, hashed at the file-edit hook at once: the
//	        after is the file as the PostToolUse finds it, and the before is known only from bytes the edit was
//	        checked against (restore_hold.go), else unknown
//	scan    scan{interval, before_sha256, after_sha256, attribution}, at each hook (restore_attribute.go): a scan's
//	        interval runs from the previous scan to it by the registry's activity numbers, so a slow scan's
//	        interval merges with the next, and none is skipped
//
// Observations are numbered by the registry's sequence, never by the clock, so two hooks at one instant still
// order. The ledger is written whole to the point's store after each change, so a restart reads it back and the
// interval spanning the restart reads foreign. Every path is relative to the worktree's root.

package mcp

import (
	"bytes"
	"slices"

	"github.com/urnetwork/sidecar"
)

// What an observation is.
type RestoreObservationKind string

const (
	RestoreObservationEdit RestoreObservationKind = "edit"
	RestoreObservationScan RestoreObservationKind = "scan"
)

// §16.7's attribution of a change a scan finds, as ChangedPath.attribution numbers it.
type RestoreAttribution uint32

const (
	RestoreAttributionUnknown RestoreAttribution = 0
	RestoreAttributionEdit    RestoreAttribution = 1
	RestoreAttributionShell   RestoreAttribution = 2
	RestoreAttributionForeign RestoreAttribution = 3
)

// The attribution's name in results.
func (self RestoreAttribution) String() string {
	switch self {
	case RestoreAttributionEdit:
		return "edit"
	case RestoreAttributionShell:
		return "shell"
	case RestoreAttributionForeign:
		return "foreign"
	}
	return "unknown"
}

// One observation of a path.
type RestoreObservation struct {
	Kind RestoreObservationKind `json:"kind"`
	// The run whose hook made it: an edit's run, or the scanning run.
	RunId sidecar.Id `json:"run_id"`
	// The registry's activity number of the hook: an edit's, or a scan's interval end.
	Seq uint64 `json:"seq"`
	// A scan's interval start, the previous scan's Seq; 0 from the base.
	FromSeq uint64 `json:"from_seq,omitempty"`
	// The daemon's clock at the hook, Unix milliseconds, for display alone.
	AtMillis int64 `json:"at_millis"`
	// An edit's hook event hash: SHA-256 over the harness, session, tool_use_id and arguments hash.
	EventSha256 []byte `json:"event_sha256,omitempty"`
	// Whether the before is known: an edit's held bytes matched, or a scan's last state was seen.
	BeforeKnown bool              `json:"before_known"`
	Before      *RestoreFileState `json:"before,omitempty"`
	After       *RestoreFileState `json:"after"`
	// A scan's attribution of the change.
	Attribution RestoreAttribution `json:"attribution,omitempty"`
}

// The ledger as the point's file holds it.
type restoreLedgerState struct {
	Version int `json:"version"`
	// Each path's observations, in order.
	Paths map[string][]*RestoreObservation `json:"paths"`
	// The last scan's number, the next scan's interval start.
	LastScanSeq uint64 `json:"last_scan_seq"`
	// HEAD at the last scan, for the commits the next one lists.
	LastHead string `json:"last_head"`
	// The last scan's time, Unix milliseconds.
	LastScanMillis int64 `json:"last_scan_millis"`
}

func newRestoreLedgerState() *restoreLedgerState {
	return &restoreLedgerState{Version: restoreLedgerVersion, Paths: map[string][]*RestoreObservation{}}
}

// A path's observations, oldest first, copied. Nil for a path never observed.
func (self *RestorePoint) Observations(path string) []*RestoreObservation {
	path = self.relativePath(path)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	observations := self.ledger.Paths[path]
	if observations == nil {
		return nil
	}
	copied := make([]*RestoreObservation, 0, len(observations))
	for _, observation := range observations {
		cloned := *observation
		cloned.EventSha256 = bytes.Clone(observation.EventSha256)
		cloned.Before = observation.Before.clone()
		cloned.After = observation.After.clone()
		copied = append(copied, &cloned)
	}
	return copied
}

// Every path the ledger holds an observation of, sorted.
func (self *RestorePoint) LedgerPaths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := make([]string, 0, len(self.ledger.Paths))
	for path := range self.ledger.Paths {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// The last state a scan knew for a path: its newest scan observation's after, since an edit observation is the
// hook's claim, which the next scan checks rather than trusts. False for none.
func (self *RestorePoint) lastKnownWithLock(path string) (*RestoreFileState, bool) {
	observations := self.ledger.Paths[path]
	for i := len(observations) - 1; 0 <= i; i -= 1 {
		if observations[i].Kind == RestoreObservationScan {
			return observations[i].After, true
		}
	}
	return nil, false
}

// Appends an observation to a path's chain, in memory.
func (self *RestorePoint) appendObservationWithLock(path string, observation *RestoreObservation) {
	self.ledger.Paths[path] = append(self.ledger.Paths[path], observation)
}

// Writes the ledger as it stands.
func (self *RestorePoint) saveLedger() error {
	ledger := func() *restoreLedgerState {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.ledger
	}()
	return writeRestoreJson(self.store, restoreLedgerName, ledger)
}

// Records one edit observation (§16.7's edit row) for the run's hook: before known only when held bytes matched.
func (self *RestorePoint) recordEdit(seq uint64, atMillis int64, eventSha256 []byte, path string, beforeKnown bool, before *RestoreFileState, after *RestoreFileState) {
	path = self.relativePath(path)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	observation := &RestoreObservation{
		Kind:        RestoreObservationEdit,
		RunId:       self.runId,
		Seq:         seq,
		AtMillis:    atMillis,
		EventSha256: bytes.Clone(eventSha256),
		BeforeKnown: beforeKnown,
		After:       after.clone(),
	}
	if beforeKnown {
		observation.Before = before.clone()
	}
	self.appendObservationWithLock(path, observation)
}

// Whether a run's edits in an interval chain from before to after: the first's before is before, each next's
// before is the previous after, and the last's after is after. Every edit's before must be known.
func restoreEditsChain(edits []*RestoreObservation, before *RestoreFileState, after *RestoreFileState) bool {
	if len(edits) == 0 {
		return false
	}
	last := before
	for _, edit := range edits {
		if !edit.BeforeKnown || !edit.Before.Equal(last) {
			return false
		}
		last = edit.After
	}
	return last.Equal(after)
}
