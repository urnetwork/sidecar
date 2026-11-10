// Step 5 (§11.8), checks b to h, as pure functions over a push view: everything step 4 read for one attempt of a
// push, a part or a seal, gathered by the route (EVS1-M2-12, EVS1-M2-13) into a PushView, so a rerun after a 412 or an
// unknown outcome is a plain second call over the view step 4 reads again. Nothing here does I/O, reads a clock or
// writes anything; each answer is nil to pass or an *EvsCheckRefusal whose code and fate come from refusal_codes.go.
//
//	b  here: the statement's repo, its signature by the token's sidecar and client under the identity
//	   key the newest state admits, time_ms within 10 min (parts and seals 30), further ahead 429 TIME_AHEAD
//	c  check_refs.go: repo/ active, the refs table (scope, ref kind, mode, owner, IMMUTABLE, creates-only refs, the
//	   flags each ref kind takes), and the storage limit through QuotaGate
//	d  check_gate.go: §10.6's predicate against the newest state, and no pin below the head's
//	e  check_cas.go: the path epoch, and creation while it is due or blocked
//	f  check_cas.go: git mode b = v with no other live lease; file mode b >= v - 63 with C_b the history's
//	g  check_cas.go: each changed file's newest version is its base, each new version follows the versions rule,
//	   directory deltas merge but for the two-way check of a removed directory, and the directory bound
//	h  check_objects.go: receipts, segments and slots a new version names
//
// A part runs b to e, g and h over its own entries; a seal runs b to f and h's age check over every part's receipts,
// and then g again over the parts' joined payload against the head it commits on (push.go's check, EVS1-M2-13),
// which refuses a part whose path a statement after the version it was checked at changed. 5a, which needs the
// head's window and log pages, is EVS1-M2-12's, as is what a refusal does to the head.
//
// Rules other tasks own come through the view's seams, and a seam left nil refuses 503, refusing nothing: a
// PATH_EPOCH push's map, tail and fold rules (EVS1-M2-16) and an ERASE's or CLOSURE's slot rules (EVS1-M2-20). So
// nothing those rules guard commits on a check this file did not run.
//
// Package-level functions are safe for concurrent use; a PushView is read only.

package evsservice

import (
	"bytes"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's 5b time bounds: a one-part push's time_ms within 10 min of evs's clock, a part's and a seal's within 30.
const (
	evsPushTimeBound = 10 * time.Minute
	evsSealTimeBound = 30 * time.Minute
)

// Which request step 5 checks.
type PushStage int

const (
	// A one-part push: 5b to 5h.
	PushStageOnePart PushStage = iota + 1
	// One part of a push in parts: 5b to 5e, 5g and 5h over its own entries.
	PushStagePart
	// A push's seal: 5b to 5f, and 5h's age check over every part's receipts.
	PushStageSeal
)

// One changed path as step 4 read it.
type PathRead struct {
	// §11.7's newest at the head the view holds (Newest).
	Newest *EvsNewest
	// For a directory this push adds names to or removes names from: its listing at that head (Listing), whose rows
	// 5g's bound counts with the push's delta. nil for any other path.
	Listing *EvsListing
}

// A reuse source step 4 read: the committed version a reuse item names.
type ReuseRead struct {
	Reuse *sidecar.EvsReuse
	// The version committed in its ref's entry or window, nil when step 4 found none.
	EntryVersion *protocol.EvsEntryVersion
}

// Classifies a push against the storage limit: QuotaGate, or a test's stand-in. Answers from memory.
type EvsQuotaChecker interface {
	CheckPush(push *QuotaPush) *sidecar.QuotaRefusal
}

// What step 4 read for one attempt, and what step 5 checks it against. See the file header.
type PushView struct {
	Stage PushStage
	// The route's repo.
	RepoId sidecar.Id
	// The statement as received, parsed and held to format 1's shape (sidecar.ParseEvsStatement).
	Statement *sidecar.EvsStatement
	// What the stage checks, its hashes already held to the statement (sidecar.EvsCheckPayload, EvsCheckPart or
	// EvsCheckSeal): a one-part push's whole payload, a part's own changes and slices, or a seal's joined parts.
	Payload *sidecar.EvsCheckedPayload

	// The token: its sidecar and client (§5's binding, which the guard matched), and the rights the guard honored on
	// the repo, with what they imply.
	TokenSidecarId sidecar.Id
	TokenClientId  sidecar.Id
	Rights         sidecar.AclEvsRights

	// repo/ as step 4 read it, at most 5 s old.
	Repo *protocol.EvsRepoObject
	// The ref's head as step 4 read it; nil when the ref has none, and a placeholder (version 0, no kind or mode)
	// reads as none (§11.8's first row).
	Head *protocol.EvsHead
	// The flags of the push the head commits at its version, which say whether the ref is IMMUTABLE. 0 when the
	// head is absent.
	HeadFlags uint32
	// C at the push's base version as evs establishes it from the head (its chain at v, its window from
	// window_base_chain, or C_0 at 0); nil when step 4 could not, which refuses 503.
	BaseChain *[32]byte

	// evs's clock at the check.
	Now time.Time
	// The newest verified authorization state evs holds for the repo's network; nil while it is not loaded.
	Auth sidecar.GkmAuthView
	// gen/<g>'s GenRotate for the push's group and generation, from evs's caches (§10); nil when evs holds none.
	Generation *protocol.GenRotate

	// What step 4 read of each changed path, by its token path's KeyString.
	Paths map[string]*PathRead
	// The base versions along the ref's overlay chain (OverlayChains), empty for a ref that is no overlay.
	OverlayBaseVersions []uint64

	// The receipts the request carries, and evs's receipt keys to check them under.
	Receipts    []*protocol.EvsUploadReceipt
	ReceiptKeys *ReceiptKeys
	// Each reuse item's source as step 4 read it, in the payload's order.
	Reuses []*ReuseRead

	// The repo's network, whose storage limit and spent state count: what EvsAuthState.Repo gives, as the segment
	// route reads it.
	NetworkId sidecar.Id
	// The storage limit: QuotaGate. nil refuses 503, since no push may go unclassified.
	Quota EvsQuotaChecker
	// The repo's metadata cluster stands at §19.9's cohort limit, so the storage limit answers 507.
	ClusterFull bool

	// EVS1-M2-16's PATH_EPOCH commit rules: map parts, source binding, tail and fold (§11.6's commit row). nil refuses
	// every PATH_EPOCH push 503.
	PathEpochRules func(view *PushView) *EvsCheckRefusal
	// EVS1-M2-20's ERASE and CLOSURE rules: the slots step 4 read, NOTHING_TO_ERASE, the slots a CLOSURE lists and its
	// chains' bound (§11.12). nil refuses every ERASE and CLOSURE 503.
	ErasureRules func(view *PushView) *EvsCheckRefusal
}

// Whether the push's flags include flag.
func (self *PushView) has(flag protocol.EvsPushFlag) bool {
	return self.Statement.Push.GetFlags()&uint32(flag) != 0
}

// Whether the ref has a head that is not a placeholder: one some push committed, deleted or not.
func (self *PushView) headExists() bool {
	return self.Head != nil && (0 < self.Head.GetVersion() || self.Head.GetRefKind() != 0 || self.Head.GetRefMode() != 0)
}

// The head's version, 0 for none.
func (self *PushView) headVersion() uint64 {
	if !self.headExists() {
		return 0
	}
	return self.Head.GetVersion()
}

// Step 5 for the view's stage, b to h in order: nil passes, else the first refusal.
func CheckPush(view *PushView) *EvsCheckRefusal {
	if view == nil || view.Statement == nil || view.Payload == nil {
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "no statement or payload in the view")
	}
	checks := []func(view *PushView) *EvsCheckRefusal{CheckSignature, CheckRefs, CheckGate, CheckPathEpoch}
	switch view.Stage {
	case PushStageOnePart:
		checks = append(checks, CheckBase, CheckPaths, CheckObjects)
	case PushStagePart:
		checks = append(checks, CheckPaths, CheckObjects)
	case PushStageSeal:
		checks = append(checks, CheckBase, CheckObjects)
	default:
		return newEvsCheckRefusal(EvsCheckReasonUnchecked, "a view of no stage")
	}
	for _, check := range checks {
		if refusal := check(view); refusal != nil {
			return refusal
		}
	}
	return nil
}

// 5b: the statement names the route's repo; its signer and client are the token's; its signature verifies under the
// identity key the newest state admits for that sidecar (§5's binding); and time_ms lies within its bound of evs's
// clock, a later one getting 429 TIME_AHEAD with the wait until it would pass. The statement's size and the payload's
// hashes were held when the view was built.
func CheckSignature(view *PushView) *EvsCheckRefusal {
	push := view.Statement.Push
	if !bytes.Equal(push.GetRepoId(), view.RepoId.Bytes()) {
		return newEvsCheckRefusal(EvsCheckReasonRepoMismatch, "a statement of another repo")
	}
	if !bytes.Equal(push.GetSignerSidecarId(), view.TokenSidecarId.Bytes()) || !bytes.Equal(push.GetClientId(), view.TokenClientId.Bytes()) {
		return newEvsCheckRefusal(EvsCheckReasonSignerMismatch, "signed for another sidecar or client than the token's")
	}
	if view.Auth == nil {
		return newEvsCheckRefusal(EvsCheckReasonGateUnknown, "no authorization state")
	}
	identityKey := view.Auth.IdentityKey(view.TokenSidecarId)
	if len(identityKey) == 0 {
		return newEvsCheckRefusal(EvsCheckReasonSignature, "a signer the state admits no identity key for")
	}
	if err := view.Statement.Verify(identityKey); err != nil {
		return newEvsCheckRefusal(EvsCheckReasonSignature, "a signature that does not verify")
	}
	return checkTime(push.GetTimeMs(), view.Stage, view.Now)
}

// 5b's time: within the stage's bound behind or ahead of now.
func checkTime(timeMs int64, stage PushStage, now time.Time) *EvsCheckRefusal {
	bound := evsPushTimeBound
	if stage != PushStageOnePart {
		bound = evsSealTimeBound
	}
	statementTime := time.UnixMilli(timeMs)
	if statementTime.Before(now.Add(-bound)) {
		return newEvsCheckRefusal(EvsCheckReasonTimeStale, fmt.Sprintf("time_ms %s behind", now.Sub(statementTime)))
	}
	if ahead := statementTime.Sub(now.Add(bound)); 0 < ahead {
		refusal := newEvsCheckRefusal(EvsCheckReasonTimeAhead, fmt.Sprintf("time_ms %s past the bound", ahead))
		refusal.RetryAfter = ahead
		return refusal
	}
	return nil
}

// The wait from the view's now until untilMs, at least a millisecond.
func timeUntilMs(view *PushView, untilMs int64) time.Duration {
	return max(time.Millisecond, time.UnixMilli(untilMs).Sub(view.Now))
}

// The paths of changes, for a 409.
func evsChangePaths(changes []*sidecar.EvsCheckedChange) []sidecar.EvsTokenPath {
	paths := make([]sidecar.EvsTokenPath, len(changes))
	for i, change := range changes {
		paths[i] = change.TokenPath
	}
	return paths
}
