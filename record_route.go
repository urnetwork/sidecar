// RECORD.md section 4.2's routing at M3, and section 5.2's stream path, on every leg.
//
// M3 routes every kind to its author's vault (§16.8's table): the author is the member a sidecar's admission names, or
// a tagged sidecar's sponsor (§7.10); the member's vault is its live vault repo with the lowest RepoCreate position
// (plan-RECORD-small-readings#3), which RecordAuthView answers. A consented device writes its own stream there, and the
// author's other sidecars deposit (§8.5). A sidecar with no author, an author with no vault yet, or a sidecar the vault
// takes neither a stream nor a deposit from, routes nowhere: the writer keeps the capture in the spool and the run's
// coverage names no_vault (section 4.2's no author row). RecordVault.Ensure, which files the vault's RepoCreate, is
// RECORD-M3-12's.
//
// Team mode, which sends T's kinds to the team record as well and D's to the directory, is RECORD-M6-01's: until it
// lands, a kind no personal network holds is refused here rather than written anywhere (section 6.3's Personal none),
// and a network whose config names a team record still routes as personal, so the team record misses entries and
// nothing reaches a log it should not. A read receipt never routes here: it is deposited to the repo read, through
// RECORD-M3-05's RecordReceipts, and awaits evs before its read runs.
//
// The stream path is plan-RECORD-stream-names#4's, in one function, RecordStreamPath. The stream's ref name, ur/<id>/
// record, is the binding's (RECORD-M3-12), and which text of the id it carries is question record-m3-01-owned-ref-id-
// text's; RecordStreams takes no ref name.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Section 5.2's stream path layout, which is a format value: 2,048 entries to a leaf directory and 2,048 leaves to the
// level above.
const (
	recordStreamLeafEntryCount  = 2048
	recordStreamLevelEntryCount = recordStreamLeafEntryCount * recordStreamLeafEntryCount
	recordStreamPathPrefix      = "e/"
)

var (
	// A kind section 6.3 sends to no personal network's log: D's own, a copy of a T entry, and T's and R's upkeep.
	// Team mode is RECORD-M6-01's, so nothing writes one yet.
	ErrRecordRouteTeamOnly = errors.New("record kind is for a team log")
	// A read receipt, which is deposited to the repo read before the read (RECORD-M3-05), never appended.
	ErrRecordRouteReceipt = errors.New("record read receipts are deposited, not appended")
	// No log takes this sidecar's entries now: no author, no vault, or no right there. The writer spools and the
	// coverage names no_vault.
	errRecordUnrouted = errors.New("record has no log to write")
)

// Section 6.3's kinds whose Personal column is none.
var recordKindsTeamOnly = []RecordKind{
	RecordKindAnnounce,
	RecordKindRequest,
	RecordKindDecision,
	RecordKindErasureRequest,
	RecordKindCopy,
	RecordKindLogSettings,
	RecordKindCheckpoint,
	RecordKindLedgerScope,
}

// How this sidecar reaches one log.
type recordRoute struct {
	logId Id
	// The author's other sidecars deposit; a consented device writes its own stream.
	deposit bool
}

// The log a kind goes to from this sidecar, by auth's answers: a route, errRecordUnrouted when none takes it now, or
// a refusal for a kind M3 writes nowhere.
func recordRouteFor(auth RecordAuthView, sidecarId Id, kind RecordKind) (*recordRoute, error) {
	if kind == RecordKindRead {
		return nil, ErrRecordRouteReceipt
	}
	if slices.Contains(recordKindsTeamOnly, kind) {
		return nil, fmt.Errorf("%w: %s", ErrRecordRouteTeamOnly, kind)
	}
	return recordVaultRoute(auth, sidecarId)
}

// This sidecar's author's vault, and whether it deposits there: errRecordUnrouted when it has no author, the author
// has no vault, or the vault takes neither its stream nor its deposits.
func recordVaultRoute(auth RecordAuthView, sidecarId Id) (*recordRoute, error) {
	authorId, ok := auth.Member(sidecarId)
	if !ok {
		authorId, ok = auth.Sponsor(sidecarId)
	}
	if !ok {
		return nil, fmt.Errorf("%w: no author", errRecordUnrouted)
	}
	vaultId, ok := auth.Vault(authorId)
	if !ok {
		return nil, fmt.Errorf("%w: the author has no vault", errRecordUnrouted)
	}
	if auth.Consented(vaultId, sidecarId) && auth.Writes(vaultId, sidecarId) {
		return &recordRoute{logId: vaultId}, nil
	}
	if auth.Deposits(vaultId, sidecarId) && !auth.ReceiptOnly(vaultId, sidecarId) {
		return &recordRoute{logId: vaultId, deposit: true}, nil
	}
	return nil, fmt.Errorf("%w: the vault takes nothing from this sidecar", errRecordUnrouted)
}

// Section 5.2's path of a stream's nth entry, n from 1 (plan-RECORD-stream-names#4): e/<n div 4,194,304>/<(n div
// 2,048) mod 2,048>/<n>, each part decimal. In a stream that holds no ingested entry n is the header's seq.
func RecordStreamPath(n uint64) (string, error) {
	if n == 0 {
		return "", fmt.Errorf("%w: stream counter 0", ErrRecordStoredInvalid)
	}
	return fmt.Sprintf("%s%d/%d/%d", recordStreamPathPrefix, n/recordStreamLevelEntryCount, (n/recordStreamLeafEntryCount)%recordStreamLeafEntryCount, n), nil
}

// The counter a stream path names, and false for any path RecordStreamPath would not make from it.
func RecordStreamPathCounter(path string) (uint64, bool) {
	rest, ok := strings.CutPrefix(path, recordStreamPathPrefix)
	if !ok {
		return 0, false
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 3 {
		return 0, false
	}
	n, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil || n == 0 {
		return 0, false
	}
	if want, err := RecordStreamPath(n); err != nil || want != path {
		return 0, false
	}
	return n, true
}
