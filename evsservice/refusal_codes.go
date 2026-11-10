// Step 5's refusals (§11.8, EVS1-M2-11): each reason a check refuses for, with its code from §11.8's fixed table
// (EVS-FORMAT.md's refusal codes, sidecar.EvsRefusalStatus) and how it lives under §11.8's refuse row:
//
//   - final: the head or a terminal repo/ state settles it for good, so it is answered and never recorded: 5c's
//     shredding and ref rules, 5d's pins, 5e's epoch and tail, 5f, and 5g's path and removal checks;
//   - recorded: evs first records it in the head by one CAS (EVS1-M2-12's refuse row), so no later attempt of the
//     push id commits: 5b's time, 5c's scope, keying, deleted state and storage limit, 5d's predicate, 5e's map parts,
//     EPOCH_SOURCES_FULL and a block's PATH_EPOCH_DUE, 5g's DIRECTORY_FULL, 5h, and FORMAT_UNSUPPORTED
//     (plan-EVS1-format-unsupported#2);
//   - nothing: a 400, 429 or 503 that refuses nothing, which the client retries with the same statement.
//
// A recorded reason's code lies in 1 to 63 and a reason that refuses nothing has one from 128; a final reason's lies
// below 128, since a recordable code is also final in a case the refuse row names (5d's GATE_CLOSED for a pin below
// the head's). This table is the one place a check chooses its code.
//
// Signature and identity failures refuse nothing: a recorded refusal is keyed by the push id, so recording one for a
// statement some other caller replayed with a bad signature would let that caller block the push.

package evsservice

import (
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// How a refusal lives (§11.8's refuse row).
type EvsRefusalFate int

const (
	// The head or a terminal repo/ state settles it: answered, never recorded.
	EvsRefusalFinal EvsRefusalFate = iota + 1
	// Recorded in the head by one CAS before it is answered.
	EvsRefusalRecorded
	// Refuses nothing: the client retries the same statement.
	EvsRefusalNothing
)

// Why a check refused.
type EvsCheckReason int

const (
	// 5b: a statement, payload or part that does not hold format 1's shape or its hashes.
	EvsCheckReasonInvalid EvsCheckReason = iota + 1
	// 5b: a format-2 construct, answered with needs_format 2.
	EvsCheckReasonFormatUnsupported
	// 5b: a statement of another repo than the route's.
	EvsCheckReasonRepoMismatch
	// 5b: signed by another sidecar or client than the token's.
	EvsCheckReasonSignerMismatch
	// 5b: no identity key for the signer, or a signature that does not verify.
	EvsCheckReasonSignature
	// 5b: time_ms older than its bound.
	EvsCheckReasonTimeStale
	// 5b: time_ms further ahead of evs's clock than its bound.
	EvsCheckReasonTimeAhead

	// 5c: repo/ keying.
	EvsCheckReasonRepoKeying
	// 5c: repo/ deleted.
	EvsCheckReasonRepoDeleted
	// 5c: repo/ shredding or shredded.
	EvsCheckReasonRepoShredding
	// 5c: a format-2 repo/ on this format-1 binary, answered 503 (plan-EVS1-format-unsupported#4).
	EvsCheckReasonRepoFormat
	// 5c: the token's rights on the repo do not cover the push.
	EvsCheckReasonScope
	// 5c: the refs table: a ref kind, mode, owner or id it may not have, a mode or kind other than the head's, an
	// overlay on a file-mode ref, an IMMUTABLE ref's non-DELETE, or a flag its ref kind does not take.
	EvsCheckReasonRefRule
	// 5c: a creates-only ref, or a BASE or CONSUME, whose change is not of its kind: answered naming the paths.
	EvsCheckReasonChangeShape
	// 5c: the storage limit (§11.13, §20.7).
	EvsCheckReasonQuota
	// 5c: a quota's rate, which refuses nothing.
	EvsCheckReasonQuotaRate
	// 5c: the storage limit while the repo's cluster stands at §19.9's cohort limit.
	EvsCheckReasonClusterFull

	// 5d: §10.6's gate predicate fails against the newest state.
	EvsCheckReasonGateClosed
	// 5d: a pin below the head's, or at the head's version under another chain or commitment.
	EvsCheckReasonPinBelowHead
	// 5d: a generation pin whose commitment or group is not gen/<g>'s, or an auth pin off evs's chain.
	EvsCheckReasonPinForked
	// 5d: the authorization state or the generation record is not held yet, or the push's pin is above the state.
	EvsCheckReasonGateUnknown

	// 5e: an epoch other than the head's current one.
	EvsCheckReasonPathEpoch
	// 5e: a creation while due_blocks_creation or before block_until_ms.
	EvsCheckReasonPathEpochDue

	// 5f: git mode, a base other than the head's version.
	EvsCheckReasonNonFastForward
	// 5f: file mode, a base below v - 63 or past v, or a base chain the history does not hold.
	EvsCheckReasonBaseStale
	// 5f: git mode, another push's live seal lease.
	EvsCheckReasonLeaseHeld

	// 5g: a changed path whose newest version is not its base_entry_version.
	EvsCheckReasonPathConflict
	// 5g: a new version off §11.7's versions rule.
	EvsCheckReasonVersionRule
	// 5g: §11.7's two-way check of a removed directory.
	EvsCheckReasonDirectoryRemoved
	// 5g: a directory past 4,096 children or 448 KiB of name table.
	EvsCheckReasonDirectoryFull

	// 5h: a receipt that does not verify, is another repo's or signer's, or is missing for a new segment.
	EvsCheckReasonReceiptInvalid
	// 5h: a receipt 24 h old or more.
	EvsCheckReasonSegmentGone
	// 5h: a segment a new version names that is neither this push's upload nor named by a version step 4 read.
	EvsCheckReasonSegmentUnknown
	// 5h: a slot a new version names that is neither this push's nor named by a version step 4 read.
	EvsCheckReasonSlotUnknown
	// Step 6: a new slot that exists past 23 h, or holds another push's bytes (§11.8 step 6).
	EvsCheckReasonSlotStale
	// 5h: an ERASE naming no key its slots still hold (§11.12).
	EvsCheckReasonNothingToErase
	// 5h: a CLOSURE that creates, removes or writes a directory, omits a replaced version's slot from its list, or
	// grows a chain past Padmé of the one it replaces (§11.12's rekey row): 409 naming the paths.
	EvsCheckReasonClosureShape

	// 5e, a PATH_EPOCH: three sources standing, or two for an epoch that does not block creation (§11.6).
	EvsCheckReasonEpochSourcesFull
	// 5e, a PATH_EPOCH: its map's parts not all standing under 24 h old.
	EvsCheckReasonMapParts
	// 5e, a PATH_EPOCH: its map's source outside the window or under another chain, which the window never comes back
	// to, so the mapper maps again; or a map part's key already holding another part.
	EvsCheckReasonMapSource
	// 5e, a PATH_EPOCH: creations after its map's source that its tail does not move: 409 naming them.
	EvsCheckReasonTailMissing

	// A rule another task owns and has not supplied (PushView's seams), or a read step 4 did not give: refused 503,
	// so nothing commits unchecked and nothing is settled against the push.
	EvsCheckReasonUnchecked
)

// One row of the table.
type evsCheckReasonRow struct {
	name string
	code protocol.EvsRefusalCode
	fate EvsRefusalFate
}

// The table. A reason whose code depends on what it carries (the storage limit's) names its usual code here, and the
// check that makes it picks among the codes evsQuotaRefusalReply does.
var evsCheckReasonRows = map[EvsCheckReason]evsCheckReasonRow{
	EvsCheckReasonInvalid:           {name: "invalid", code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID, fate: EvsRefusalNothing},
	EvsCheckReasonFormatUnsupported: {name: "format_unsupported", code: protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED, fate: EvsRefusalRecorded},
	EvsCheckReasonRepoMismatch:      {name: "repo_mismatch", code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID, fate: EvsRefusalNothing},
	EvsCheckReasonSignerMismatch:    {name: "signer_mismatch", code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID, fate: EvsRefusalNothing},
	EvsCheckReasonSignature:         {name: "signature", code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID, fate: EvsRefusalNothing},
	EvsCheckReasonTimeStale:         {name: "time_stale", code: protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE, fate: EvsRefusalRecorded},
	EvsCheckReasonTimeAhead:         {name: "time_ahead", code: protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD, fate: EvsRefusalNothing},

	EvsCheckReasonRepoKeying:    {name: "repo_keying", code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING, fate: EvsRefusalRecorded},
	EvsCheckReasonRepoDeleted:   {name: "repo_deleted", code: protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED, fate: EvsRefusalRecorded},
	EvsCheckReasonRepoShredding: {name: "repo_shredding", code: protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING, fate: EvsRefusalFinal},
	EvsCheckReasonRepoFormat:    {name: "repo_format", code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, fate: EvsRefusalNothing},
	EvsCheckReasonScope:         {name: "scope", code: protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE, fate: EvsRefusalRecorded},
	EvsCheckReasonRefRule:       {name: "ref_rule", code: protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE, fate: EvsRefusalFinal},
	EvsCheckReasonChangeShape:   {name: "change_shape", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},
	EvsCheckReasonQuota:         {name: "quota", code: protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT, fate: EvsRefusalRecorded},
	EvsCheckReasonQuotaRate:     {name: "quota_rate", code: protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED, fate: EvsRefusalNothing},
	EvsCheckReasonClusterFull:   {name: "cluster_full", code: protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL, fate: EvsRefusalRecorded},

	EvsCheckReasonGateClosed:   {name: "gate_closed", code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED, fate: EvsRefusalRecorded},
	EvsCheckReasonPinBelowHead: {name: "pin_below_head", code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED, fate: EvsRefusalFinal},
	EvsCheckReasonPinForked:    {name: "pin_forked", code: protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED, fate: EvsRefusalFinal},
	EvsCheckReasonGateUnknown:  {name: "gate_unknown", code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, fate: EvsRefusalNothing},

	EvsCheckReasonPathEpoch:    {name: "path_epoch", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH, fate: EvsRefusalFinal},
	EvsCheckReasonPathEpochDue: {name: "path_epoch_due", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE, fate: EvsRefusalRecorded},

	EvsCheckReasonNonFastForward: {name: "non_fast_forward", code: protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD, fate: EvsRefusalFinal},
	EvsCheckReasonBaseStale:      {name: "base_stale", code: protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE, fate: EvsRefusalFinal},
	EvsCheckReasonLeaseHeld:      {name: "lease_held", code: protocol.EvsRefusalCode_EVS_REFUSAL_WAIT, fate: EvsRefusalNothing},

	EvsCheckReasonPathConflict:     {name: "path_conflict", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},
	EvsCheckReasonVersionRule:      {name: "version_rule", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},
	EvsCheckReasonDirectoryRemoved: {name: "directory_removed", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},
	EvsCheckReasonDirectoryFull:    {name: "directory_full", code: protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL, fate: EvsRefusalRecorded},

	EvsCheckReasonReceiptInvalid: {name: "receipt_invalid", code: protocol.EvsRefusalCode_EVS_REFUSAL_INVALID, fate: EvsRefusalNothing},
	EvsCheckReasonSegmentGone:    {name: "segment_gone", code: protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE, fate: EvsRefusalRecorded},
	EvsCheckReasonSegmentUnknown: {name: "segment_unknown", code: protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE, fate: EvsRefusalRecorded},
	EvsCheckReasonSlotUnknown:    {name: "slot_unknown", code: protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN, fate: EvsRefusalRecorded},
	EvsCheckReasonSlotStale:      {name: "slot_stale", code: protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE, fate: EvsRefusalRecorded},
	EvsCheckReasonNothingToErase: {name: "nothing_to_erase", code: protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE, fate: EvsRefusalRecorded},
	EvsCheckReasonClosureShape:   {name: "closure_shape", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},

	EvsCheckReasonEpochSourcesFull: {name: "epoch_sources_full", code: protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL, fate: EvsRefusalRecorded},
	EvsCheckReasonMapParts:         {name: "map_parts", code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS, fate: EvsRefusalRecorded},
	EvsCheckReasonMapSource:        {name: "map_source", code: protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS, fate: EvsRefusalFinal},
	EvsCheckReasonTailMissing:      {name: "tail_missing", code: protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT, fate: EvsRefusalFinal},

	EvsCheckReasonUnchecked: {name: "unchecked", code: protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE, fate: EvsRefusalNothing},
}

// The reason's name, for the service log and metrics: a closed set.
func (self EvsCheckReason) String() string {
	if row, ok := evsCheckReasonRows[self]; ok {
		return row.name
	}
	return fmt.Sprintf("reason_%d", int(self))
}

// Every reason the table holds, in order.
func EvsCheckReasons() []EvsCheckReason {
	reasons := make([]EvsCheckReason, 0, len(evsCheckReasonRows))
	for reason := range evsCheckReasonRows {
		reasons = append(reasons, reason)
	}
	slices.Sort(reasons)
	return reasons
}

// What a check refused for, as the push route answers it. Its code and fate come from the table; the rest is what a
// reply carries beside them.
type EvsCheckRefusal struct {
	Reason EvsCheckReason
	Code   protocol.EvsRefusalCode
	Fate   EvsRefusalFate
	// What a 409 names, in the push's path epoch.
	Paths []sidecar.EvsTokenPath
	// A 429's or 503's wait, as retry_after_ms and Retry-After carry it. Zero leaves it to the route.
	RetryAfter time.Duration
	// FORMAT_UNSUPPORTED's needs_format.
	NeedsFormat uint32
	// The storage limit's, §20.7's QuotaRefusal.
	Quota *sidecar.QuotaRefusal
	// BASE_STALE on the caller's own deposit ref (plan-EVS1-deposit-head): the ref's head as the check read it.
	DepositHead *protocol.EvsDepositHead
	// What failed, for evs-7's line and the tests: no token path, name or id beyond what Paths already holds.
	Detail string
}

// The refusal reason makes, its code and fate from the table.
func newEvsCheckRefusal(reason EvsCheckReason, detail string) *EvsCheckRefusal {
	row, ok := evsCheckReasonRows[reason]
	if !ok {
		// a reason the table lacks fails closed as unchecked, refusing nothing
		row = evsCheckReasonRows[EvsCheckReasonUnchecked]
		reason = EvsCheckReasonUnchecked
	}
	return &EvsCheckRefusal{Reason: reason, Code: row.code, Fate: row.fate, Detail: detail}
}

// The reason, its code and what failed.
func (self *EvsCheckRefusal) Error() string {
	return fmt.Sprintf("evs check %s (%s): %s", self.Reason, self.Code, self.Detail)
}

// Whether the head must record it before it is answered.
func (self *EvsCheckRefusal) Recorded() bool {
	return self.Fate == EvsRefusalRecorded
}

// The EvsRefusalReply for pushId: its code, paths, wait, needs_format, quota and deposit head. recorded and outcome
// are the route's to set.
func (self *EvsCheckRefusal) Reply(pushId sidecar.Id) *protocol.EvsRefusalReply {
	reply := &protocol.EvsRefusalReply{
		PushId:      pushId.Bytes(),
		Code:        self.Code,
		NeedsFormat: self.NeedsFormat,
		DepositHead: self.DepositHead,
	}
	if 0 < self.RetryAfter {
		reply.RetryAfterMs = uint32(min(self.RetryAfter.Milliseconds(), int64(^uint32(0))))
		if self.RetryAfter%time.Millisecond != 0 {
			reply.RetryAfterMs += 1
		}
	}
	for _, path := range self.Paths {
		reply.Paths = append(reply.Paths, path.Proto())
	}
	if self.Quota != nil {
		quotaReply := evsQuotaRefusalReply(self.Quota)
		reply.Quota = quotaReply.GetQuota()
		if reply.RetryAfterMs == 0 {
			reply.RetryAfterMs = quotaReply.GetRetryAfterMs()
		}
	}
	return reply
}

// The refusal a codec error from the root's parse and payload checks makes: FORMAT_UNSUPPORTED with needs_format 2
// for a format-2 construct, else INVALID (EvsRefusalCodeOf's mapping).
func EvsCheckRefusalOfCodec(err error) *EvsCheckRefusal {
	if sidecar.EvsRefusalCodeOf(err) == protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED {
		refusal := newEvsCheckRefusal(EvsCheckReasonFormatUnsupported, "a format-2 construct")
		refusal.NeedsFormat = 2
		return refusal
	}
	return newEvsCheckRefusal(EvsCheckReasonInvalid, "the statement or payload's shape")
}
