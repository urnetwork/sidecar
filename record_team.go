// RECORD.md section 4.2's team mode, on every leg (RECORD-M6-01): which logs a draft's entries go to, by section 6.3's
// Team column, once the config this sidecar holds names a live repo of the kind's log.
//
//	mode       team mode for T's kinds once RecordAuthView.Logs names the team record, for D's once it names the
//	           directory; routing reads the config, never the plan (D-RECORD-4); a team record no RepoCreate made yet
//	           routes as personal, which record-md-team-record-creation's interim and its decided rule both keep
//	twice      context, change, permission, restore and coverage: the vault's entry sealed first, holding the body
//	           whole, then T's: RecordProjectForTeam's projection, every V: field empty and the project too where the
//	           run's repo may be private, with one ContentRef to the vault entry, whose salt stays in its slot row
//	same       the approval family copied to T with the same stored bytes (§16.8), and route, publish, reach, model and
//	           inventory to T alone, their bodies holding no run text
//	T alone    a tagged sidecar with no sponsor has no author and so no vault (§7.10): its kinds bound for T go there
//	           alone, a projection carrying no ContentRef; an approval whose approver reads only the team record, an
//	           admin's, goes there alone too (RecordDraft.TeamOnly)
//	copy       each entry this sidecar deposits to T also lands in its author's vault in a copy entry holding its
//	           Opening (§16.8's "authors keep copies"), which a team-record erasure does not reach (section 8); a
//	           sidecar writing T's stream itself, a log admin's device, deposits nothing there and copies nothing
//	D          ask, answer, check and note go to the directory, its own stream; announce, request, decision and
//	           erasure_request only there; a claim or handoff is state of the run's announcement (§16.11), which
//	           RECORD-M6-16 changes, so Append refuses it in team mode rather than write a coordination entry
//	vault      every other kind as in a personal network, capture kinds always; cost stays in the vault until
//	           ServiceSettings.record_cost exists to turn the owner's team default off (record-md-run-cost-in-team-
//	           record), and membership and key keep the vault mirror, T's copy waiting on the statement's signer
//
// T's ingest is RECORD-M3-04's, run by a device that writes T's stream: a log admin's device, or a designated indexer
// with rw there (§11.12). Package-level functions are safe for concurrent use.

package sidecar

import (
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

var (
	// In team mode a claim or handoff is state of the calling run's announcement (§16.11): RECORD-M6-16 changes it,
	// and the tool answers FAILED_PRECONDITION for a session no run binds; no entry is written.
	ErrRecordRouteAnnouncement = errors.New("record claim or handoff is state of the run's announcement in team mode")
	// A draft names a log that takes no entry from this sidecar: not written, and never spooled for later.
	ErrRecordRouteNoLog = errors.New("record draft names a log this sidecar cannot write")
	// A draft for T alone in a network with no team record: an admin's approval, which no personal log takes.
	ErrRecordRouteNoTeamRecord = errors.New("record draft for the team record in a network with none")
)

// What T's entry of a kind holds.
type recordTeamBody int

const (
	// The vault's body whole, or the stored bytes.
	recordTeamBodySame recordTeamBody = iota + 1
	// RecordProjectForTeam's projection, with a ContentRef to the vault entry.
	recordTeamBodyProjection
)

// The logs one draft's entries go to, in the order Append seals them: the vault's, T's, the copy, or D's.
type recordRoutes struct {
	// The author's vault: its entry of the body when vaultEntry, and the copy's home when copy.
	vault      *recordRoute
	vaultEntry bool
	// T's entry, and what it holds.
	team     *recordRoute
	teamBody recordTeamBody
	// A copy of T's entry in the vault: T takes this sidecar's entries by deposit.
	copy bool
	// The directory's, this sidecar's own stream there.
	directory *recordRoute
}

// The network's team logs this sidecar's config names: T, D, or neither.
func recordTeamLogs(auth RecordAuthView) (*Id, *Id) {
	logs := auth.Logs()
	if logs == nil {
		return nil, nil
	}
	return logs.TeamRecordId, logs.DirectoryId
}

// Whether logId is a team log, T or D: no owner, so neither consent nor a vault's rules apply.
func recordIsTeamLog(auth RecordAuthView, logId Id) bool {
	teamRecordId, directoryId := recordTeamLogs(auth)
	return (teamRecordId != nil && *teamRecordId == logId) || (directoryId != nil && *directoryId == logId)
}

// Whether this sidecar ingests logId's deposits: for a team log, a device writing its stream (a log admin's, or a
// designated indexer with rw); for a vault, a consented device of its author that writes there (§11.12).
func recordIngests(auth RecordAuthView, sidecarId Id, logId Id) bool {
	if recordIsTeamLog(auth, logId) {
		return auth.Writes(logId, sidecarId)
	}
	return auth.Consented(logId, sidecarId) && auth.Writes(logId, sidecarId)
}

// Section 6.3's kinds whose Team column is V and T, T's entry a projection.
func recordKindTeamProjected(kind RecordKind) bool {
	return slices.Contains(recordKindsProjected, kind)
}

// Section 6.3's approval family, whose route is the approver's log, copied to any team record with the same bytes.
func recordKindApprovalFamily(kind RecordKind) bool {
	switch kind {
	case RecordKindApproval, RecordKindApprovalDecision, RecordKindApprovalCancel, RecordKindApprovalUse:
		return true
	}
	return false
}

// Section 6.3's kinds whose Team column is T alone, their bodies holding no run text.
func recordKindTeamOnlyInTeamMode(kind RecordKind) bool {
	switch kind {
	case RecordKindRoute, RecordKindPublish, RecordKindReach, RecordKindModel, RecordKindInventory:
		return true
	}
	return false
}

// Section 6.3's kinds the directory takes in a team network with one; the coordination ones go to the vault without.
func recordKindDirectory(kind RecordKind) (directoryOnly bool, coordination bool) {
	switch kind {
	case RecordKindAnnounce, RecordKindRequest, RecordKindDecision, RecordKindErasureRequest:
		return true, false
	case RecordKindAsk, RecordKindAnswer, RecordKindCheck, RecordKindNote:
		return false, true
	}
	return false, false
}

// The routes of a draft of kind from this sidecar, by section 6.3 in this network's mode: errRecordUnrouted, wrapped,
// when its vault takes nothing now and the kind needs it, so the writer spools; a refusal for a kind no log here takes.
func recordRoutesFor(auth RecordAuthView, sidecarId Id, kind RecordKind, teamOnly bool) (*recordRoutes, error) {
	if kind == RecordKindRead {
		return nil, ErrRecordRouteReceipt
	}
	teamRecordId, directoryId := recordTeamLogs(auth)
	_, hasAuthor := auth.Member(sidecarId)
	if !hasAuthor {
		_, hasAuthor = auth.Sponsor(sidecarId)
	}
	teamRoute := func() *recordRoute {
		deposit, _ := recordLogMode(auth, sidecarId, *teamRecordId)
		return &recordRoute{logId: *teamRecordId, deposit: deposit}
	}
	vaultRoute := func() (*recordRoute, error) {
		return recordVaultRoute(auth, sidecarId)
	}

	if directoryOnly, coordination := recordKindDirectory(kind); directoryOnly || coordination {
		if directoryId != nil {
			return &recordRoutes{directory: &recordRoute{logId: *directoryId}}, nil
		}
		if directoryOnly {
			return nil, fmt.Errorf("%w: %s with no directory", ErrRecordRouteTeamOnly, kind)
		}
	}
	switch kind {
	case RecordKindClaim, RecordKindHandoff:
		if directoryId != nil {
			return nil, fmt.Errorf("%w: %s", ErrRecordRouteAnnouncement, kind)
		}
	case RecordKindCopy:
		// a copy lands only in a team network's author's vault (section 6.3's copy row)
		if teamRecordId == nil && directoryId == nil {
			return nil, fmt.Errorf("%w: %s in a personal network", ErrRecordRouteTeamOnly, kind)
		}
		vault, err := vaultRoute()
		if err != nil {
			return nil, err
		}
		return &recordRoutes{vault: vault, vaultEntry: true}, nil
	case RecordKindLogSettings, RecordKindCheckpoint:
		if teamRecordId == nil {
			return nil, fmt.Errorf("%w: %s with no team record", ErrRecordRouteTeamOnly, kind)
		}
		return &recordRoutes{team: teamRoute(), teamBody: recordTeamBodySame}, nil
	}
	if slices.Contains(recordKindsTeamOnly, kind) {
		return nil, fmt.Errorf("%w: %s", ErrRecordRouteTeamOnly, kind)
	}

	teamKind := recordKindTeamProjected(kind) || recordKindApprovalFamily(kind) || recordKindTeamOnlyInTeamMode(kind)
	if teamRecordId == nil || !teamKind {
		if teamOnly {
			return nil, fmt.Errorf("%w: %s", ErrRecordRouteNoTeamRecord, kind)
		}
		vault, err := vaultRoute()
		if err != nil {
			return nil, err
		}
		return &recordRoutes{vault: vault, vaultEntry: true}, nil
	}
	routes := &recordRoutes{team: teamRoute(), teamBody: recordTeamBodySame}
	if recordKindTeamProjected(kind) {
		routes.teamBody = recordTeamBodyProjection
	}
	if !hasAuthor {
		// a tagged sidecar with no sponsor: T alone, no vault to reference or copy into
		return routes, nil
	}
	routes.copy = !auth.Writes(*teamRecordId, sidecarId)
	routes.vaultEntry = !teamOnly && !recordKindTeamOnlyInTeamMode(kind)
	if !routes.vaultEntry && !routes.copy {
		// T alone from a sidecar writing T itself, a log admin's device: nothing lands in the vault
		return routes, nil
	}
	vault, err := vaultRoute()
	if err != nil {
		// the author's vault takes nothing yet: the whole draft waits in the spool, so T's entry never names an
		// entry that was not sealed and no copy is lost
		return nil, err
	}
	routes.vault = vault
	return routes, nil
}

// Section 6.3's kinds whose row is the log they are about, which a draft names by RecordDraft.LogId.
func recordKindNamesItsLog(kind RecordKind) bool {
	return kind == RecordKindDisclosure
}

// The route of a draft that names its log (RecordDraft.LogId): the team record, by this sidecar's stream or its
// deposits, or its author's vault. A receipt-only depositor files no such entry, since ingest takes only read from
// it (RECORD.md section 5.4's class step), and a log this sidecar neither writes nor deposits to takes none.
func recordRoutesToLog(auth RecordAuthView, sidecarId Id, kind RecordKind, logId Id) (*recordRoutes, error) {
	if !recordKindNamesItsLog(kind) {
		return nil, fmt.Errorf("%w: %s names no log of its own", ErrRecordDraftInvalid, kind)
	}
	teamRecordId, _ := recordTeamLogs(auth)
	if teamRecordId != nil && *teamRecordId == logId {
		deposit, ok := recordLogMode(auth, sidecarId, logId)
		if !ok {
			return nil, fmt.Errorf("%w: the team record takes nothing from this sidecar", ErrRecordRouteNoLog)
		}
		return &recordRoutes{team: &recordRoute{logId: logId, deposit: deposit}, teamBody: recordTeamBodySame}, nil
	}
	vault, err := recordVaultRoute(auth, sidecarId)
	if err != nil || vault.logId != logId {
		return nil, fmt.Errorf("%w: log %s is neither the team record nor this author's vault", ErrRecordRouteNoLog, logId)
	}
	return &recordRoutes{vault: vault, vaultEntry: true}, nil
}

// T's body of a vault body: the projection, or the same bytes. repoPrivate clears ContextBody's and ChangeBody's
// project, the closed reading while nothing here knows which repos the directory announces.
func recordTeamBodyBytes(kind RecordKind, how recordTeamBody, vaultBody []byte, projection []byte) ([]byte, error) {
	if how == recordTeamBodySame {
		return vaultBody, nil
	}
	if projection != nil {
		return projection, nil
	}
	body, ok := kind.NewBody()
	if !ok {
		return nil, fmt.Errorf("%w: %s has no body message", ErrRecordProjectionNone, kind)
	}
	if err := proto.Unmarshal(vaultBody, body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordDraftInvalid, err)
	}
	projected, err := RecordProjectForTeam(kind, body, recordProjectionRepoPrivate(body))
	if err != nil {
		return nil, err
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(projected)
}

// Whether the run's repo may be private: a body naming an evs repo, until the directory's fold says which repos it
// announces (RECORD-M6-14, -15), so T never holds a private repo's project label.
func recordProjectionRepoPrivate(body proto.Message) bool {
	switch typed := body.(type) {
	case *protocol.ContextBody:
		return len(typed.GetRepoId()) != 0
	case *protocol.ChangeBody:
		return len(typed.GetRepoId()) != 0
	}
	return false
}

// A caller's projection as T may hold it: the kind's message, every V: field already empty, as RecordProjectForTeam
// would leave it, marshaled once.
func recordCheckedProjection(kind RecordKind, projection proto.Message) ([]byte, error) {
	if projection == nil {
		return nil, nil
	}
	stripped, err := RecordProjectForTeam(kind, projection, false)
	if err != nil {
		return nil, fmt.Errorf("%w: projection: %v", ErrRecordDraftInvalid, err)
	}
	if !proto.Equal(stripped, projection) {
		return nil, fmt.Errorf("%w: a projection holding a field record.proto marks V:", ErrRecordDraftInvalid)
	}
	return proto.MarshalOptions{Deterministic: true}.Marshal(projection)
}
