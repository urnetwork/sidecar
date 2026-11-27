//go:build !ios_extension && !sidecar_http

// DESIGN-COMPUTE §24.10's caps (CTXH-M11-06; R-CTXH-8, D-CTXH-8, Q-CTXH-13, Q-CTXH-16): context history stops leaving the
// device at NetworkCapFraction of the network's storage and at the member's share of it, while every call is still
// journaled first (IC-19) and mail, repos and the record's other kinds keep writing.
//
//	read      the network's storage limit from GET /sidecar/limits, through quotaLocalLimit, so the caps ship dark while
//	          enforce_sidecar_limits is off as every local pre-check does; the network's stored bytes as api reports them
//	          (compute-plan-ctxh-stored-count, decided: a field on that route), and until a route reports them the
//	          vault's totals as this device's sync lists them, an underestimate (SessionCapState.NetworkUsedEstimated);
//	          the member's history from the same sync, headers and the padded sizes of their bodies
//	share     the compute block's history.member_share (§16.4; CACL-M12-03 reads it), auto until it does: all of it for a
//	          network of one member and 2/n for one of n; a set share within MemberShareMin and MemberShareMax
//	at a cap  the record holds the vault's session bodies back (SidecarRecord.SetBodyHold): every header leaves in
//	          order, so readers see a body withheld, never a gap; the journal keeps a part that would need a blob by
//	          hash and size, the run's gap oversize; a body waits in the device's spool budget,
//	          SidecarIngestSettings.SpoolByteCount shared with §16.7's spool, and past it the oldest held bodies are
//	          dropped, each named in bodies_dropped of a coverage entry the writer files for its run at the drop, gap
//	          spool_drop; once there is room the hold lifts and each held body leaves in a later push
//	warning   at WarningFraction of the network's storage or of the member's share: the largest runs named, and the bytes
//	          the one tap must free to bring history under ExpiryTargetFraction of that cap (SessionStorage's expiry)
//
// Check runs at each CapCheckInterval on a Sidecar (session_component.go), reading the vault as its reader holds it,
// and after a storage view and an expiry, each syncing it first; the storage limit is read again past
// LimitReadInterval. A run made past a cap continues only on its own device until its bodies leave, since its newest nodes are
// withheld (session_continue.go's tip row).
//
// Safe for concurrent use.

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/urnetwork/sidecar/protocol"
)

// Which cap a warning names.
const (
	SessionCapNetwork = "network"
	SessionCapMember  = "member"
)

// The compute block's history.member_share (§16.4): auto, or a share an Owner or Admin set.
type SessionMemberShare struct {
	Auto     bool
	Fraction float64
}

// A member's share of the network's storage (Q-CTXH-16): auto is all of it for a network of one member and 2/n for one
// of n; a set share is held within MemberShareMin and MemberShareMax. Nil reads auto.
func SessionMemberShareOf(share *SessionMemberShare, memberCount int, settings *SessionSettings) float64 {
	if share == nil || share.Auto {
		if memberCount <= 2 {
			return 1
		}
		return 2 / float64(memberCount)
	}
	return min(max(share.Fraction, settings.MemberShareMin), settings.MemberShareMax)
}

// What the caps read, each at its check.
type SessionCapSources struct {
	// The network's storage limit in bytes, -1 for none: QuotaLimits' storage through quotaLocalLimit.
	StorageLimit func(ctx context.Context) (int64, error)
	// The network's stored bytes as api reports them; false while no route reports them.
	NetworkStored func(ctx context.Context) (int64, bool, error)
	// The network's members, for auto's 2/n.
	MemberCount func() (int, error)
	// The compute block's history.member_share; nil reads auto.
	MemberShare func(ctx context.Context) (*SessionMemberShare, error)
}

// The caps as their last check found them: what the storage view's warning shows (§24.10's see row).
type SessionCapState struct {
	// The network's storage, -1 for none, and the network's cap at NetworkCapFraction of it.
	StorageLimit int64 `json:"storage_limit"`
	NetworkCap   int64 `json:"network_cap"`
	// The network's stored bytes, or the vault's totals where no route reports them.
	NetworkUsed          int64 `json:"network_used"`
	NetworkUsedEstimated bool  `json:"network_used_estimated,omitempty"`
	// The member's share, its cap in bytes (-1 for none), and the member's history in the vault.
	MemberShare float64 `json:"member_share"`
	MemberCap   int64   `json:"member_cap"`
	MemberUsed  int64   `json:"member_used"`
	// History stops leaving the device at either.
	AtNetworkCap bool `json:"at_network_cap,omitempty"`
	AtMemberCap  bool `json:"at_member_cap,omitempty"`
	// At WarningFraction of a cap: which, and the bytes the one tap frees to bring history under ExpiryTargetFraction
	// of it; empty and 0 where none warns.
	Warning    string `json:"warning,omitempty"`
	ExpiryNeed int64  `json:"expiry_need,omitempty"`
	// The person's switch that expires the oldest blobs again at each cap.
	AutoExpire bool `json:"auto_expire,omitempty"`
	// Bodies this device holds back, waiting for room, and their bytes.
	HeldBodyCount int   `json:"held_body_count,omitempty"`
	HeldByteCount int64 `json:"held_byte_count,omitempty"`
	CheckedMillis int64 `json:"checked_millis"`
}

// Whether history stops leaving the device.
func (self *SessionCapState) Capped() bool {
	return self != nil && (self.AtNetworkCap || self.AtMemberCap)
}

// What SessionCaps runs on.
type SessionCapsArgs struct {
	Record  *SidecarRecord
	Journal *SessionJournal
	Sources *SessionCapSources
	// The spool whose bytes share the budget held bodies wait in; nil counts none.
	Spool    *Spool
	Settings *SessionSettings
	Ingest   *SidecarIngestSettings
	Clock    Clock
}

// The caps of one network's history. See the file header.
type SessionCaps struct {
	record   *SidecarRecord
	journal  *SessionJournal
	sources  *SessionCapSources
	spool    *Spool
	settings *SessionSettings
	ingest   *SidecarIngestSettings
	clock    Clock

	checkLock sync.Mutex
	stateLock sync.Mutex
	state     *SessionCapState
	vaultId   Id
	capped    bool
	// the person's switch, as the storage view last set it
	autoExpire bool
	// the storage limit as last read, and when, kept LimitReadInterval
	limit       int64
	limitMillis int64
}

// Caps over args, installed on the record's writer and the journal: their hold and cut read the caps' last check.
func NewSessionCaps(args *SessionCapsArgs) (*SessionCaps, error) {
	if args == nil || args.Record == nil || args.Sources == nil || args.Sources.StorageLimit == nil {
		return nil, errors.New("session caps need the record and the storage limit")
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultSessionSettings()
	}
	ingest := args.Ingest
	if ingest == nil {
		ingest = defaultSidecarIngestSettings()
	}
	caps := &SessionCaps{record: args.Record, journal: args.Journal, sources: args.Sources, spool: args.Spool, settings: settings,
		ingest: ingest, clock: clockOrReal(args.Clock)}
	args.Record.SetBodyHold(caps.holds)
	if args.Journal != nil {
		args.Journal.SetCapped(caps.Capped)
	}
	return caps, nil
}

// Whether history stops leaving now: the journal keeps parts by hash and size, the writer holds bodies.
func (self *SessionCaps) Capped() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.capped
}

// The record's hold: the vault's session bodies while capped.
func (self *SessionCaps) holds(logId Id) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.capped && logId == self.vaultId
}

// The last check's state, nil before the first.
func (self *SessionCaps) State() *SessionCapState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == nil {
		return nil
	}
	state := *self.state
	return &state
}

// Sets the person's switch, which the storage view keeps (SessionStorage.SetAutoExpire).
func (self *SessionCaps) setAutoExpire(on bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.autoExpire = on
	if self.state != nil {
		self.state.AutoExpire = on
	}
}

// The history and vault totals of logId as the reader holds it: a session entry's or blob's header and padded body,
// and every entry's, by the same reckoning, an inline body by its stored size.
func sessionVaultTotals(reader *RecordReader, logId Id) (history int64, vault int64) {
	for _, entry := range reader.Entries(logId) {
		size := sessionEntryByteCount(entry)
		vault += size
		if entry.Kind() == RecordKindSessionEntry || entry.Kind() == RecordKindSessionBlob {
			history += size
		}
	}
	return history, vault
}

// An entry's bytes in the vault: its signed header, and its body: a body filed apart by the padded size its listing
// states, none while it is withheld or dropped; an inline body by its stored size while held. An erased entry counts
// its header alone.
func sessionEntryByteCount(entry *RecordReadEntry) int64 {
	size := int64(len(entry.SignedBytes))
	if entry.State.KeyGone() {
		return size
	}
	if entry.BodyApart {
		for _, entryCopy := range entry.Copies {
			if entryCopy.BodyVersion != 0 {
				return size + int64(entryCopy.BodyByteCount)
			}
		}
		return size
	}
	return size + int64(len(entry.CommittedBody()))
}

// Reads the limits and the vault, sets the hold, and drops the oldest held bodies past the spool's budget: see the file
// header. A limit that cannot be read keeps the last check's caps.
func (self *SessionCaps) Check(ctx context.Context) (*SessionCapState, error) {
	return self.check(ctx, true)
}

// The storage limit: as last read where that was within LimitReadInterval, else read now.
func (self *SessionCaps) storageLimit(ctx context.Context) (int64, error) {
	nowMillis := self.clock.Now().UnixMilli()
	limit, at := func() (int64, int64) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.limit, self.limitMillis
	}()
	if at != 0 && nowMillis-at < self.settings.LimitReadInterval.Milliseconds() {
		return limit, nil
	}
	limit, err := self.sources.StorageLimit(ctx)
	if err != nil {
		return 0, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.limit, self.limitMillis = limit, nowMillis
	return limit, nil
}

// Check, the vault synced first where sync is set, else read as the reader holds it: the tick's, which leaves the
// record's syncs to their own schedule.
func (self *SessionCaps) check(ctx context.Context, sync bool) (*SessionCapState, error) {
	self.checkLock.Lock()
	defer self.checkLock.Unlock()
	reader := self.record.SessionReader()
	vaultId, err := reader.VaultId()
	if err != nil {
		return nil, err
	}
	if sync {
		if err := self.record.reader.Sync(ctx, vaultId); err != nil {
			return nil, err
		}
	}
	history, vault := sessionVaultTotals(self.record.reader, vaultId)
	limit, err := self.storageLimit(ctx)
	if err != nil {
		if last := self.State(); last != nil {
			return last, fmt.Errorf("session caps: the storage limit did not read, so the last check stands: %w", err)
		}
		return nil, err
	}
	state := &SessionCapState{StorageLimit: limit, NetworkCap: -1, MemberCap: -1, NetworkUsed: vault, NetworkUsedEstimated: true,
		MemberUsed: history, CheckedMillis: self.clock.Now().UnixMilli()}
	if self.sources.NetworkStored != nil {
		stored, ok, err := self.sources.NetworkStored(ctx)
		if err != nil {
			return nil, err
		}
		if ok {
			state.NetworkUsed, state.NetworkUsedEstimated = stored, false
		}
	}
	memberCount := 1
	if self.sources.MemberCount != nil {
		if memberCount, err = self.sources.MemberCount(); err != nil {
			return nil, err
		}
	}
	var share *SessionMemberShare
	if self.sources.MemberShare != nil {
		if share, err = self.sources.MemberShare(ctx); err != nil {
			return nil, err
		}
	}
	state.MemberShare = SessionMemberShareOf(share, memberCount, self.settings)
	if 0 <= limit {
		state.NetworkCap = int64(self.settings.NetworkCapFraction * float64(limit))
		state.MemberCap = int64(state.MemberShare * float64(limit))
		state.AtNetworkCap = state.NetworkCap <= state.NetworkUsed
		state.AtMemberCap = state.MemberCap <= state.MemberUsed
		// the warning names the network's storage where both warn, whose expiry frees the member's share too
		warns := []struct {
			name string
			used int64
			base int64
		}{
			{name: SessionCapNetwork, used: state.NetworkUsed, base: limit},
			{name: SessionCapMember, used: state.MemberUsed, base: state.MemberCap},
		}
		for _, warn := range warns {
			if float64(warn.used) < self.settings.WarningFraction*float64(warn.base) {
				continue
			}
			state.Warning = warn.name
			state.ExpiryNeed = max(warn.used-int64(self.settings.ExpiryTargetFraction*float64(warn.base)), 0)
			break
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.vaultId = vaultId
		self.capped = state.Capped()
		state.AutoExpire = self.autoExpire
		self.state = state
	}()
	// the hold reads the new state at the writer's next plan
	self.record.SetBodyHold(self.holds)
	if err := self.dropOverflow(ctx, vaultId, state); err != nil {
		return state, err
	}
	return state, nil
}

// The held bodies' budget: the spool's byte count, what §16.7's spool holds now, shared.
func (self *SessionCaps) heldBudget() int64 {
	budget := self.ingest.SpoolByteCount
	if self.spool != nil {
		budget -= self.spool.ByteCount()
	}
	return budget
}

// Drops the oldest bodies the writer holds past the budget, each run's named in bodies_dropped of a coverage entry its
// writer files for the run at the drop, gap spool_drop (§24.10's caps row); counts what is still held into state.
func (self *SessionCaps) dropOverflow(ctx context.Context, vaultId Id, state *SessionCapState) error {
	held, err := self.record.writer.heldBodies(vaultId)
	if err != nil {
		return err
	}
	total := int64(0)
	for _, body := range held {
		total += int64(len(body.SealedBody))
	}
	budget := self.heldBudget()
	dropping := []*recordHeldBody{}
	// held is by counter, oldest first
	for _, body := range held {
		if total <= budget {
			break
		}
		dropping = append(dropping, body)
		total -= int64(len(body.SealedBody))
	}
	state.HeldBodyCount = len(held) - len(dropping)
	state.HeldByteCount = total
	if len(dropping) == 0 {
		return nil
	}
	seqs := []uint64{}
	for _, body := range dropping {
		seqs = append(seqs, body.Seq)
	}
	dropped, err := self.record.DropHeldBodies(vaultId, seqs)
	if err != nil {
		return err
	}
	runSeqs := map[Id][]uint64{}
	runOrder := []Id{}
	for _, body := range dropping {
		if !slices.Contains(dropped, body.Seq) {
			continue
		}
		runId := self.heldRunId(vaultId, body)
		if _, ok := runSeqs[runId]; !ok {
			runOrder = append(runOrder, runId)
		}
		runSeqs[runId] = append(runSeqs[runId], body.Seq)
	}
	errs := []error{}
	for _, runId := range runOrder {
		seqs := runSeqs[runId]
		slices.Sort(seqs)
		gap := RecordCoverageGapSpoolDrop
		if 1 < len(seqs) {
			gap = fmt.Sprintf("%s:%d", RecordCoverageGapSpoolDrop, len(seqs))
		}
		coverage := &protocol.Coverage{RunId: runId.Bytes(), Gaps: []string{gap}, FirstSeq: seqs[0], LastSeq: seqs[len(seqs)-1],
			BodiesDropped: sessionSeqRanges(seqs)}
		run := runId
		if _, err := self.record.Writer().Append(&RecordDraft{Kind: RecordKindCoverage, Source: RecordSourceObserved, RunId: &run, Body: coverage}); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// The run a held body's entry is of: as the writer kept it, else as this device's reader holds its header.
func (self *SessionCaps) heldRunId(vaultId Id, body *recordHeldBody) Id {
	if len(body.RunId) == len(Id{}) {
		return recordIdOf(body.RunId)
	}
	sidecarId := self.record.writer.sidecarId
	for _, entry := range self.record.reader.Entries(vaultId) {
		header := entry.Header.Header
		if recordIdOf(header.GetWriterSidecarId()) == sidecarId && header.GetSeq() == body.Seq {
			return recordIdOf(header.GetRunId())
		}
	}
	return Id{}
}

// seqs, ascending, as bodies_dropped's ranges: each run of consecutive seqs one range.
func sessionSeqRanges(seqs []uint64) []*protocol.SeqRange {
	ranges := []*protocol.SeqRange{}
	for _, seq := range seqs {
		if last := len(ranges) - 1; 0 <= last && ranges[last].GetLast()+1 == seq {
			ranges[last].Last = seq
			continue
		}
		ranges = append(ranges, &protocol.SeqRange{First: seq, Last: seq})
	}
	return ranges
}
