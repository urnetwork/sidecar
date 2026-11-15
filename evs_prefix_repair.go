//go:build !ios_extension

// The writers' background half of a ruled repo (EVS1-M6-05; DESIGN-DETAILS 16.2.8, 16.2.9): the repair runner, the
// repair form with no edit for one path, the filer's pin pushes with their journal, the status `ur evs rules show`
// reads, and the subjects `ur evs rules` names.
//
// The repair form with no edit is the effective state written back so that evs's newest event of a path is an allowed
// one again. A repair is an ordinary push, signed by its device and allowed by its rules, and it asserts nothing about
// the breach.
//
//	who     a device whose composition says it repairs (EvsPrefixRulesArgs.Repair: a desktop or the daemon, never a
//	        phone) and whose own admission is not ephemeral, that mirrors the ref, since only a mirror journals an
//	        ignored event, and that the rules allow every path the repair writes: the planner's AllowPrefixWrite
//	        refuses the rest before any request, so a device held to a prefix repairs only under it and keeps the
//	        other units
//	when    RepairDelay after the device journalled the event, plus a share of RepairJitter by
//	        SHA-256(sidecar_id || push id), so two candidates rarely send at once. A unit whose path's newest event
//	        is allowed by the time it is due was repaired by another device, or written over, and is dropped; one
//	        that loses 5g's CAS stays for the next pass, which finds that. The daemon's prefix timer
//	        (evs_component.go) runs a pass every RepairPassInterval
//	what    a path a breach created, effectively absent: its removal
//	        a file a breach removed: created again from the effective version's content, with its row
//	        a versionless file a breach replaced: its accepted content again
//	        a versioned file a breach replaced: nothing at once, since every reader walks back; one checkpoint once
//	        RepairDepth ignored versions lie over it
//	        each write goes through WritePaths held to the effective version (IfVersion), so the planner gives it
//	        the repair form: evs's newest as base_entry_version and prev_push_id, one checkpoint, the row again
//	bounds  RepairPushCount pushes in RepairPushWindow and RepairByteCount bytes in RepairByteWindow, for each repo
//	        on this device, kept in the sealed store under prefix_repair/<repo_id>; past either the units wait in
//	        the journal, which `ur status` lists
//	by hand ByHand runs the due and the undue units at once, with no delay, depth or bound; RepairPath does the same
//	        for one path with no journal unit, as EVS2-M10-20's DROP builder asks (16.2.7 and 10.2.4 as amended)
//
// Not built in this draft, and left in the journal: a directory's delta on its own (a names unit is dropped once no
// other unit of its push is left, its rows restated by its children's repairs), a removed directory's subtree, and
// content evs no longer serves: the effective content is read from evs through the reader's own walk, not from the
// mirror's sealed copy, so a versionless file whose replaced content evs purged, or a removal collected past the
// horizon, answers EVS_PREFIX_RULE unavailable and its unit waits.
//
// What a repair writes over (QD-833; DESIGN-DETAILS 16.2.7's metadata row): every write over an ignored event, the
// runner's and a caller's alike, names in its sealed written_over the push ids of the events it writes over. The
// planner takes them from the writeBase walk that found the effective version, or, where the read record answered
// with no walk, from writtenOverEvents, which reads the same events again; evs_plan.go orders them and evs_push.go
// seals them. History marks each version a later repair named (evs_history.go).
//
// The filer's pin pushes (16.2.9): once its own log holds a set it filed, a pin push (EvsRepo.PinPush) to each shared
// ref whose head's pin is below the set. A ref whose pin push fails, or every ref while the log does not hold the set,
// stays owed under prefix_pin/<repo_id>; the prefix timer sends it again at most once a PinPushRetryInterval, up to
// PinPushRetryCount sends, after which the next honest push on the ref binds it, as any push pinned at its writer's
// installed state does.
//
// A path is its device's own and goes into no log (I-13). Safe for concurrent use: one repair pass runs at a time.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// The sealed store's directory of each repo's repair spend.
const evsPrefixRepairDirectory = "prefix_repair/"

// This device's composition does not repair: a phone, an ephemeral sidecar, or a client with no prefix rules enabled.
var ErrEvsPrefixRepairOff = errors.New("evs: this device runs no prefix repair")

// What one pass of the runner is asked.
type EvsPrefixRepairArgs struct {
	RepoId Id
	// One path's units alone, its raw names joined by /; empty for every unit of the repo.
	Path string
	// `ur evs repair`: the same pushes at once, without the delay, RepairDepth and the bounds.
	ByHand bool
}

// What one pass did.
type EvsPrefixRepairResult struct {
	// The repair pushes it committed, and the plaintext bytes they carried.
	PushCount int
	ByteCount int64
	// The journal units it dropped: repaired here, or found allowed again.
	SettledCount int
	// The units it left: not due, under RepairDepth, past a bound, refused to this device, or of a class not built.
	WaitingCount int
}

// One repo's repair spend on this device, as the sealed store keeps it.
type evsPrefixRepairSpend struct {
	Pushes []int64                `json:"pushes"`
	Bytes  []*evsPrefixRepairByte `json:"bytes"`
}

// The bytes one repair push carried, and when.
type evsPrefixRepairByte struct {
	AtMs  int64 `json:"at_ms"`
	Count int64 `json:"count"`
}

// A unit's share of jitter: SHA-256(sidecar_id || push id)'s first 8 bytes over 2^64 of it.
func evsPrefixRepairJitter(sidecarId Id, pushId Id, jitter time.Duration) time.Duration {
	if jitter <= 0 {
		return 0
	}
	digest := sha256.Sum256(append(sidecarId.Bytes(), pushId.Bytes()...))
	share, _ := bits.Mul64(binary.BigEndian.Uint64(digest[:8]), uint64(jitter))
	return time.Duration(share)
}

// How a unit's repair ended.
type evsPrefixRepairOutcome int

const (
	evsPrefixRepairWaiting evsPrefixRepairOutcome = iota
	evsPrefixRepairSettled
	evsPrefixRepairPushed
)

// One pass of the repair runner over a repo's journal (the file header). The daemon calls it on its timer, `ur evs
// repair` by hand. ErrEvsPrefixRepairOff on a device that does not repair.
func (self *EvsClient) RepairPrefix(ctx context.Context, args *EvsPrefixRepairArgs) (*EvsPrefixRepairResult, error) {
	judge := self.prefixJudge()
	if judge == nil || !judge.repairs() {
		return nil, ErrEvsPrefixRepairOff
	}
	judge.repairLock.Lock()
	defer judge.repairLock.Unlock()
	units, err := func() ([]*EvsPrefixIgnored, error) {
		judge.storeLock.Lock()
		defer judge.storeLock.Unlock()
		return judge.journal(args.RepoId)
	}()
	if err != nil {
		return nil, err
	}
	repo := self.Repo(args.RepoId)
	sidecarId := self.args.Identity().SidecarId
	now := self.clock.Now()
	spend, err := judge.repairSpend(args.RepoId, now)
	if err != nil {
		return nil, err
	}
	result := &EvsPrefixRepairResult{}
	settled := []*EvsPrefixIgnored{}
	// each path once a pass: every unit of a path settles with its newest event
	outcomes := map[evsPrefixRepairPath]evsPrefixRepairOutcome{}
	var passErr error
	for _, unit := range units {
		if (args.Path != "" && unit.Path != args.Path) || unit.Kind == EvsPrefixIgnoredNames || !unit.Named {
			continue
		}
		key := evsPrefixRepairPath{refId: unit.RefId, path: unit.Path}
		outcome, seen := outcomes[key]
		if !seen && passErr == nil {
			due := time.UnixMilli(unit.AtMs).Add(judge.settings.RepairDelay + evsPrefixRepairJitter(sidecarId, unit.PushId, judge.settings.RepairJitter))
			if args.ByHand || !now.Before(due) {
				var byteCount int64
				outcome, byteCount, err = judge.repairPath(ctx, repo, unit.RefId, nil, unit.Path, unit.Versionless, args.ByHand, spend)
				var ruleErr *EvsPrefixRuleError
				var conflict *EvsPathConflictError
				switch {
				case err == nil:
				case errors.As(err, &ruleErr), errors.As(err, &conflict), errors.Is(err, ErrEvsPathMoved):
					// not this device's to repair, or another write landed first: the unit waits for the next pass
					outcome = evsPrefixRepairWaiting
				default:
					passErr = err
				}
				if outcome == evsPrefixRepairPushed {
					result.PushCount += 1
					result.ByteCount += byteCount
					spend.Pushes = append(spend.Pushes, now.UnixMilli())
					spend.Bytes = append(spend.Bytes, &evsPrefixRepairByte{AtMs: now.UnixMilli(), Count: byteCount})
				}
			}
			outcomes[key] = outcome
		}
		if outcome == evsPrefixRepairWaiting {
			result.WaitingCount += 1
			continue
		}
		settled = append(settled, unit)
	}
	// a directory's delta: dropped once no other unit of its push is left (the file header)
	left := map[Id]bool{}
	for _, unit := range units {
		if unit.Kind != EvsPrefixIgnoredNames && unit.Named && !evsPrefixRepairHolds(settled, unit) {
			left[unit.PushId] = true
		}
	}
	for _, unit := range units {
		if unit.Kind != EvsPrefixIgnoredNames && unit.Named {
			continue
		}
		if args.Path != "" || left[unit.PushId] || !unit.Named {
			result.WaitingCount += 1
			continue
		}
		settled = append(settled, unit)
	}
	result.SettledCount = len(settled)
	if 0 < result.PushCount {
		if err := judge.writeRepairSpend(args.RepoId, spend); err != nil && passErr == nil {
			passErr = err
		}
	}
	if err := judge.journalRemove(args.RepoId, settled); err != nil && passErr == nil {
		passErr = err
	}
	return result, passErr
}

// One path of one ref, which a pass repairs once.
type evsPrefixRepairPath struct {
	refId Id
	path  string
}

// Whether units holds unit.
func evsPrefixRepairHolds(units []*EvsPrefixIgnored, unit *EvsPrefixIgnored) bool {
	for _, held := range units {
		if held == unit {
			return true
		}
	}
	return false
}

// Repairs one path of a ref (the file header's what and bounds rows), refName its name where the caller holds it, nil
// to open it from the head; versionless where the event it repairs over replaced a versionless file, and byHand where
// RepairDepth and the bounds do not hold: settled where its newest event is allowed again, pushed with the bytes it
// carried, or waiting.
func (self *evsPrefixJudge) repairPath(ctx context.Context, repo *EvsRepo, refId Id, refName []byte, path string, versionless bool, byHand bool, spend *evsPrefixRepairSpend) (evsPrefixRepairOutcome, int64, error) {
	read, err := repo.readPaths(ctx, refId, []*evsReadPath{{path: path}}, true)
	if err != nil {
		return evsPrefixRepairWaiting, 0, err
	}
	newestRemoved := read.replies[0].Removal != nil
	base, err := self.writeBase(ctx, repo, read, 0)
	read.objects.close()
	if err != nil {
		return evsPrefixRepairWaiting, 0, err
	}
	if base == nil {
		// the newest event is an allowed one: repaired by another device, or written over
		return evsPrefixRepairSettled, 0, nil
	}
	if refName == nil {
		if refName, err = repo.prefixRefName(ctx, refId); err != nil {
			return evsPrefixRepairWaiting, 0, err
		}
	}
	if !byHand && self.settings.RepairPushCount <= len(spend.Pushes) {
		return evsPrefixRepairWaiting, 0, nil
	}
	write := &EvsPathWrite{Path: path, IfVersion: &base.version}
	byteCount := int64(0)
	if base.version == 0 {
		if newestRemoved {
			// a path a breach created and removed again: evs holds what this device follows
			return evsPrefixRepairSettled, 0, nil
		}
		// a path a breach created: its removal
		write.Remove = true
	} else {
		if !byHand && !newestRemoved && !versionless && base.ignoredAbove < self.settings.RepairDepth {
			// a versioned file a breach replaced: every reader walks back, so nothing yet
			return evsPrefixRepairWaiting, 0, nil
		}
		content := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
		defer content.close()
		info, err := repo.ReadHead(ctx, &EvsReadArgs{RefId: &refId, Path: path, Fresh: true}, content)
		if err != nil {
			return evsPrefixRepairWaiting, 0, err
		}
		if info.Version != base.version {
			// the path moved between the two reads: the next pass
			return evsPrefixRepairWaiting, 0, nil
		}
		byteCount = content.Size()
		spent := int64(0)
		for _, spentBytes := range spend.Bytes {
			spent += spentBytes.Count
		}
		if !byHand && self.settings.RepairByteCount < spent+byteCount {
			return evsPrefixRepairWaiting, 0, nil
		}
		write.Content, write.Mode = content, info.Mode
	}
	if _, err := repo.WritePaths(ctx, &EvsWritePathsArgs{RefName: refName, Writes: []*EvsPathWrite{write}}); err != nil {
		return evsPrefixRepairWaiting, 0, err
	}
	return evsPrefixRepairPushed, byteCount, nil
}

// The ignored events a write over newest writes over (QD-833), newest first: newest, the path's newest event at evs as
// the planner's read verified it, and each event below it this device ignores, read by number and held to what its
// successor names as effective's walk reads it, down to the first event it does not ignore, at most
// WalkBackVersionCount of them. writeBase runs it only where the read record answered with no walk, so it raises no
// prefix alarm, the read that noted the record having raised one, and notes nothing in the record. A version its
// successor does not name alarms as tampering and fails the write, as it fails the walk.
func (self *evsPrefixJudge) writtenOverEvents(ctx context.Context, repo *EvsRepo, refId Id, path string, newest *EvsVerifiedPath) ([]evsPrefixIgnoredPush, error) {
	events := []evsPrefixIgnoredPush{}
	verified := newest
	for {
		verdict, err := self.verdictOfPath(ctx, repo, refId, verified, nil)
		if err != nil {
			return nil, err
		}
		if verdict.Outcome != AclPrefixIgnored {
			// the effective version, or one this device cannot judge: the list ends above it
			return events, nil
		}
		pushId, _ := IdFromBytes(verified.Statement.Push.GetPushId())
		events = append(events, evsPrefixIgnoredPush{commitVersion: verified.CommitVersion, pushId: pushId})
		if self.settings.WalkBackVersionCount < len(events) {
			return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailDepth, Path: path}
		}
		below := &evsReadPath{path: path}
		var expectPushId []byte
		if verified.Removal != nil {
			if verified.Removal.GetPathVersion() <= 1 {
				return nil, fmt.Errorf("%w: a removal of no version", ErrEvsEntryRefused)
			}
			below.version = verified.Removal.GetPathVersion() - 1
		} else {
			entry := verified.Entry
			if len(entry.GetPrevPushId()) == 0 || entry.GetVersion() <= 1 {
				// the ignored version created the path
				return events, nil
			}
			below.version = entry.GetVersion() - 1
			below.commitVersion, below.prevPushId = entry.GetPrevCommitVersion(), entry.GetPrevPushId()
			expectPushId = entry.GetPrevPushId()
		}
		next, err := repo.readPaths(ctx, refId, []*evsReadPath{below}, false)
		if err != nil {
			return nil, err
		}
		next.objects.close()
		found := next.replies[0]
		switch {
		case found.Base != nil, found.Absent:
			// nothing below the ignored event: the list ends with it
			return events, nil
		case below.version < evsPrefixEventVersion(found),
			found.Entry != nil && found.Removal == nil && expectPushId != nil &&
				(!bytes.Equal(found.Entry.GetPushId(), expectPushId) || found.CommitVersion != below.commitVersion):
			self.client.alarm(repo.repoId, refId, SidecarEvsAlarmTamper, path, nil)
			return nil, fmt.Errorf("%w: a version its successor does not name", ErrEvsEntryRefused)
		}
		verified = found
	}
}

// A ref's name by its id: main's, else the name its head seals for the repo's readers.
func (self *EvsRepo) prefixRefName(ctx context.Context, refId Id) ([]byte, error) {
	mainId, err := self.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		return nil, err
	}
	if mainId == refId {
		return EvsMainRefName, nil
	}
	head, err := self.pinnedHead(ctx, refId)
	if err != nil {
		return nil, err
	}
	manifest, err := newEvsReadKeys(self).manifest(ctx, head.Head.GetGeneration())
	if err != nil {
		return nil, err
	}
	return EvsOpenRefName(manifest, refId, head.Head.GetSealedRefName())
}

// A repo's repair spend inside the bounds' windows at now.
func (self *evsPrefixJudge) repairSpend(repoId Id, now time.Time) (*evsPrefixRepairSpend, error) {
	spend := &evsPrefixRepairSpend{}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	if _, err := aclPrefixReadStoreJson(self.client.args.Store, evsPrefixRepairDirectory+repoId.String(), spend); err != nil {
		return nil, err
	}
	pushes := []int64{}
	for _, atMs := range spend.Pushes {
		if now.Sub(time.UnixMilli(atMs)) < self.settings.RepairPushWindow {
			pushes = append(pushes, atMs)
		}
	}
	byteSpends := []*evsPrefixRepairByte{}
	for _, spent := range spend.Bytes {
		if now.Sub(time.UnixMilli(spent.AtMs)) < self.settings.RepairByteWindow {
			byteSpends = append(byteSpends, spent)
		}
	}
	spend.Pushes, spend.Bytes = pushes, byteSpends
	return spend, nil
}

// Stores a repo's repair spend.
func (self *evsPrefixJudge) writeRepairSpend(repoId Id, spend *evsPrefixRepairSpend) error {
	data, err := json.Marshal(spend)
	if err != nil {
		return err
	}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	return aclPrefixWriteStoreFile(self.client.args.Store, evsPrefixRepairDirectory+repoId.String(), data)
}

// Whether this device repairs (DESIGN-DETAILS 16.2.8's who): its composition says so, a desktop's or the daemon's, and
// its own admission is not ephemeral, as the verified state's row for it says. A device with no state repairs nothing;
// one whose state holds no row for it signs nothing evs would take, so its row is not asked for more.
func (self *evsPrefixJudge) repairs() bool {
	if !self.args.Repair {
		return false
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return false
	}
	row := state.SidecarRow(self.client.args.Identity().SidecarId)
	return row == nil || !row.GetEphemeral()
}

// The repair form with no edit for one path (DESIGN-DETAILS 16.2.7 and 10.2.4 as amended): what EVS2-M10-20's DROP
// builder calls for a path whose newest version it ignores, before it builds a kept head on it. The effective state is
// written back whatever RepairDepth says and outside the bounds, as `ur evs repair` writes it: the effective content
// as one checkpoint with its row, or the removal where the effective state is absent. It keeps 16.2.8's who: a device
// that repairs and mirrors the ref, else ErrEvsPrefixRepairOff, which the builder answers as EVS_PREFIX_RULE with detail
// refused, naming `ur evs repair` on a device that mirrors the ref (10.2.4); and one the rules allow the path, else the
// planner's EVS_PREFIX_RULE before any request. A path whose newest event at evs is allowed already sends nothing, its
// SettledCount 1; one another write moves under it answers that write's conflict, which the caller reads again on.
func (self *EvsRepo) RepairPath(ctx context.Context, refName []byte, path string) (*EvsPrefixRepairResult, error) {
	judge := self.client.prefixJudge()
	if judge == nil || !judge.repairs() {
		return nil, ErrEvsPrefixRepairOff
	}
	if refName == nil {
		refName = EvsMainRefName
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	mirror, err := self.client.Mirror(self.repoId)
	if err != nil {
		return nil, err
	}
	if _, mirrored, err := mirror.Ref(refId); err != nil {
		return nil, err
	} else if !mirrored {
		return nil, fmt.Errorf("%w: this device does not mirror the ref", ErrEvsPrefixRepairOff)
	}
	judge.repairLock.Lock()
	defer judge.repairLock.Unlock()
	outcome, byteCount, err := judge.repairPath(ctx, self, refId, refName, path, false, true, &evsPrefixRepairSpend{})
	if err != nil {
		return nil, err
	}
	result := &EvsPrefixRepairResult{}
	switch outcome {
	case evsPrefixRepairPushed:
		result.PushCount, result.ByteCount = 1, byteCount
	case evsPrefixRepairSettled:
		result.SettledCount = 1
	default:
		result.WaitingCount = 1
	}
	return result, nil
}

// One pass of the daemon's prefix timer (evs_component.go): the runner over each repo whose mirror journalled an ignored
// event, then the pin pushes the journal owes. What fails is logged and waits for the next pass; no path is logged.
func (self *EvsClient) passPrefixRepair(ctx context.Context) {
	entries, err := self.args.Store.List(evsPrefixJournalDirectory)
	if err != nil {
		self.log.Warningf("[evs]the prefix journal does not list: %v", err)
	}
	for _, entry := range entries {
		repoId, err := ParseId(strings.TrimPrefix(entry.Name, evsPrefixJournalDirectory))
		if err != nil {
			continue
		}
		if _, err := self.RepairPrefix(ctx, &EvsPrefixRepairArgs{RepoId: repoId}); err != nil && !errors.Is(err, ErrEvsPrefixRepairOff) {
			self.log.Infof("[evs]the prefix repair of repo %s: %v", repoId, err)
		}
	}
	if err := self.RetryPrefixPinPushes(ctx); err != nil {
		self.log.Infof("[evs]the owed pin pushes: %v", err)
	}
}

// The sealed store's directory of each repo's pin pushes still owed: the position of the newest set this device filed
// whose pin pushes have not all landed.
const evsPrefixPinDirectory = "prefix_pin/"

// How one shared ref stands against a set's position (DESIGN-DETAILS 16.2.9's `ur evs rules show`; QD-802, QD-803).
type EvsPrefixBinding string

const (
	// The head's pin is at or above the set: every later push on the ref is judged under it or a later one.
	EvsPrefixBound EvsPrefixBinding = "bound"
	// The head's pin is below the set, and no pin push has landed on it yet: a writer that sends the head's older pin
	// still writes under the older set there (16.2.13).
	EvsPrefixUnbound EvsPrefixBinding = "unbound"
	// A deleted ref: evs holds its re-creating push's pin at or above the repo's newest set (QD-803).
	EvsPrefixDeleted EvsPrefixBinding = "deleted"
	// A git-mode tag ref, which holds no file and takes no second push.
	EvsPrefixTag EvsPrefixBinding = "tag"
	// A git-mode ref stopped on this device, which its recovery binds.
	EvsPrefixStopped EvsPrefixBinding = "stopped"
	// Its pin push failed; the journal sends it again.
	EvsPrefixFailed EvsPrefixBinding = "failed"
	// The filer's log does not hold the set yet, so no pin push can carry a pin at or above it; the journal sends it.
	EvsPrefixWaiting EvsPrefixBinding = "waiting"
)

// One shared ref of a repo against a set's position.
type EvsPrefixRef struct {
	RefId Id
	// Its name, opened from its head; nil where this device cannot open it.
	Name []byte
	Mode protocol.EvsRefMode
	// The head's auth pin as the refs listing gives it, unverified (§11.9's listing is evs's word).
	PinVersion uint64
	Binding    EvsPrefixBinding
	// The pin push sent now, nil for none, and the version it committed at.
	PushId  *Id
	Version uint64
	// Why its pin push failed, an error's text, which names no path.
	Err string
}

// A repo's prefix rules as this device holds them, for `ur evs rules show`.
type EvsPrefixRulesStatus struct {
	RepoId Id
	// The position of this device's verified state, which its writes pin.
	PinVersion uint64
	// Every row's set in position order, with its state here: an opened one carries its rules.
	Sets []*AclPrefixRuleSet
	// The set in force at PinVersion, nil for none; where a set this device cannot read stands above it, Unread is
	// that set, whose state says pending or newer, and the device writes nothing to the repo.
	InForce *AclPrefixRuleSet
	Unread  *AclPrefixRuleSet
	// The newest row's position, which each ref's binding compares with: 0 for a repo with no set.
	NewestAt uint64
	// Each shared ref the rules hold, by the refs listing: ur/index and ur/lfs, outside the rules, are left out.
	Refs []*EvsPrefixRef
}

// A repo's sets and refs as `ur evs rules show` prints them (DESIGN-DETAILS 16.2.9): each ref against the newest
// set's position, a deleted one as held at its re-creation, a tag and a ref stopped on this device apart. Nothing is
// sent.
func (self *EvsClient) PrefixRulesStatus(ctx context.Context, repoId Id) (*EvsPrefixRulesStatus, error) {
	judge := self.prefixJudge()
	if judge == nil {
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	state, err := self.verifier.config()
	if err != nil {
		return nil, err
	}
	repoRow := state.Repo(repoId)
	if repoRow == nil {
		return nil, fmt.Errorf("%w: a repo the state does not hold", ErrEvsNoConfig)
	}
	status := &EvsPrefixRulesStatus{RepoId: repoId, PinVersion: state.Pin().GetVersion(), Sets: []*AclPrefixRuleSet{}, Refs: []*EvsPrefixRef{}}
	rows := repoRow.GetPrefixRules()
	if len(rows) == 0 {
		return status, nil
	}
	sets, err := judge.setsOf(ctx, repoId, state)
	if err != nil {
		return nil, err
	}
	status.Sets = sets
	inForce, verdict, decided := aclPrefixSetInForce(rows, sets, status.PinVersion)
	switch {
	case !decided:
		status.InForce = inForce
	case verdict.Outcome == AclPrefixWait || verdict.Outcome == AclPrefixUpdate:
		status.Unread = aclPrefixSetAt(sets, verdict.SetAt)
		if status.Unread == nil {
			status.Unread = &AclPrefixRuleSet{At: verdict.SetAt, State: AclPrefixSetPending}
		}
	}
	status.NewestAt, _ = AclPrefixRulesNewestAt(repoRow)
	refs, err := self.prefixRefs(ctx, judge, repoId, status.NewestAt)
	if err != nil {
		return nil, err
	}
	status.Refs = refs
	return status, nil
}

// Each shared ref the rules hold, from the refs listing, against at: bound, unbound, deleted, a tag, or stopped on
// this device. ur/index and ur/lfs are left out, as 16.2.4's line 1 leaves them outside the rules.
func (self *EvsClient) prefixRefs(ctx context.Context, judge *evsPrefixJudge, repoId Id, at uint64) ([]*EvsPrefixRef, error) {
	repo := self.Repo(repoId)
	listing, err := repo.ListRefs(ctx, nil)
	if err != nil {
		return nil, err
	}
	mainId, err := repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		return nil, err
	}
	refs := []*EvsPrefixRef{}
	for _, head := range listing.Refs {
		refId, err := IdFromBytes(head.GetRefId())
		if err != nil || head.GetRefKind() != protocol.EvsRefKind_EVS_REF_SHARED {
			continue
		}
		if name, err := judge.refName(ctx, repo, refId); err != nil {
			return nil, err
		} else if name != nil {
			continue
		}
		ref := &EvsPrefixRef{RefId: refId, Mode: head.GetRefMode(), PinVersion: head.GetAuth().GetVersion()}
		if refId == mainId {
			ref.Name = EvsMainRefName
		} else if manifest, err := newEvsReadKeys(repo).manifest(ctx, head.GetGeneration()); err == nil {
			if name, err := EvsOpenRefName(manifest, refId, head.GetSealedRefName()); err == nil {
				ref.Name = name
			}
		}
		switch {
		case head.GetDeleted():
			ref.Binding = EvsPrefixDeleted
		case ref.Mode == protocol.EvsRefMode_EVS_REF_GIT && bytes.HasPrefix(ref.Name, []byte(evsGitTagRefPrefix)):
			ref.Binding = EvsPrefixTag
		case ref.Mode == protocol.EvsRefMode_EVS_REF_GIT && self.prefixRefStopped(repoId, refId):
			ref.Binding = EvsPrefixStopped
		case at <= ref.PinVersion:
			ref.Binding = EvsPrefixBound
		default:
			ref.Binding = EvsPrefixUnbound
		}
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a *EvsPrefixRef, b *EvsPrefixRef) int { return bytes.Compare(a.Name, b.Name) })
	return refs, nil
}

// Whether a git-mode ref is stopped on this device's mount of the repo: false where no mount holds it.
func (self *EvsClient) prefixRefStopped(repoId Id, refId Id) bool {
	pusher := func() evsLocalPinPusher {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		pusher, _ := self.localTier.(evsLocalPinPusher)
		return pusher
	}()
	return pusher != nil && pusher.pinStopped(repoId, refId)
}

// The filer's pin pushes after its set's 200 (DESIGN-DETAILS 16.2.9): once this device's verified state holds the
// set's position at, following the log once where it does not yet, a pin push to each shared ref whose head's pin is
// below at, a tag ref, a deleted ref and a ref stopped here excepted. A ref whose pin push fails, or every ref when the
// log does not hold the set yet, stays owed in the sealed store under prefix_pin/<repo_id>, which RetryPrefixPinPushes
// sends again. Each ref's outcome is answered.
func (self *EvsClient) PinPushRules(ctx context.Context, repoId Id, at uint64) ([]*EvsPrefixRef, error) {
	judge := self.prefixJudge()
	if judge == nil {
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	held := func() (bool, error) {
		state, err := self.verifier.config()
		if err != nil {
			return false, err
		}
		return at <= state.Pin().GetVersion(), nil
	}
	ok, err := held()
	if err != nil {
		return nil, err
	}
	if !ok && self.args.ConfigFollow != nil {
		if err := self.args.ConfigFollow(ctx); err != nil {
			self.log.Infof("[evs]the follow before the pin pushes of repo %s: %v", repoId, err)
		}
		if ok, err = held(); err != nil {
			return nil, err
		}
	}
	refs, err := self.prefixRefs(ctx, judge, repoId, at)
	if err != nil {
		if owedErr := judge.owePinPushes(repoId, at); owedErr != nil {
			return nil, owedErr
		}
		return nil, err
	}
	owed := false
	for _, ref := range refs {
		if ref.Binding != EvsPrefixUnbound {
			continue
		}
		if !ok {
			ref.Binding, owed = EvsPrefixWaiting, true
			continue
		}
		result, err := self.Repo(repoId).pinPushRef(ctx, ref.RefId, ref.Name)
		switch {
		case err != nil:
			ref.Binding, ref.Err, owed = EvsPrefixFailed, err.Error(), true
		case result.Skipped == EvsPinPushSkipDeleted || result.Skipped == EvsPinPushSkipNoHead:
			ref.Binding = EvsPrefixDeleted
		case result.Skipped == EvsPinPushSkipTag:
			ref.Binding = EvsPrefixTag
		case result.Skipped == EvsPinPushSkipStopped:
			ref.Binding = EvsPrefixStopped
		default:
			pushId := result.PushId
			ref.Binding, ref.PushId, ref.Version = EvsPrefixBound, &pushId, result.Version
		}
	}
	if owed {
		err = judge.owePinPushes(repoId, at)
	} else {
		err = judge.settlePinPushes(repoId, at)
	}
	return refs, err
}

// A repo's pin pushes still owed, as the sealed store keeps them: the newest set's position this device filed whose
// pin pushes have not all landed, how many sends of them failed, and when the last one ran.
type evsPrefixPinOwed struct {
	At       uint64 `json:"at"`
	Attempts int    `json:"attempts"`
	LastMs   int64  `json:"last_ms"`
}

// Notes one send of a repo's pin pushes up to at that left some owed: a later filing's position starts the count
// again; past PinPushRetryCount sends the debt is dropped, logged, and left to the next honest push on each ref, which
// binds it as any pin push does, while `ur evs rules show` keeps listing the ref as not bound.
func (self *evsPrefixJudge) owePinPushes(repoId Id, at uint64) error {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	name := evsPrefixPinDirectory + repoId.String()
	owed := &evsPrefixPinOwed{}
	if _, err := aclPrefixReadStoreJson(self.client.args.Store, name, owed); err != nil {
		return err
	}
	switch {
	case owed.At < at:
		owed.At, owed.Attempts = at, 1
	default:
		owed.Attempts += 1
	}
	owed.LastMs = self.client.clock.Now().UnixMilli()
	if self.settings.PinPushRetryCount <= owed.Attempts {
		self.client.log.Warningf("[evs]the pin pushes of repo %s for the set at %d failed %d times: left to the next push on each ref", repoId, owed.At, owed.Attempts)
		return self.client.args.Store.Remove(name)
	}
	data, err := json.Marshal(owed)
	if err != nil {
		return err
	}
	return aclPrefixWriteStoreFile(self.client.args.Store, name, data)
}

// Drops a repo's owed pin pushes once every ref is bound at or above at, unless a later filing owes more.
func (self *evsPrefixJudge) settlePinPushes(repoId Id, at uint64) error {
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	owed := &evsPrefixPinOwed{}
	found, err := aclPrefixReadStoreJson(self.client.args.Store, evsPrefixPinDirectory+repoId.String(), owed)
	if err != nil || !found || at < owed.At {
		return err
	}
	return self.client.args.Store.Remove(evsPrefixPinDirectory + repoId.String())
}

// Sends again every pin push the journal owes (16.2.9's retry row), repo by repo, each at most once a
// PinPushRetryInterval: what the daemon's prefix timer runs. A repo's failure is logged and left owed, up to
// PinPushRetryCount sends; the first error is answered.
func (self *EvsClient) RetryPrefixPinPushes(ctx context.Context) error {
	judge := self.prefixJudge()
	if judge == nil {
		return nil
	}
	entries, err := self.args.Store.List(evsPrefixPinDirectory)
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		repoId, err := ParseId(strings.TrimPrefix(entry.Name, evsPrefixPinDirectory))
		if err != nil {
			continue
		}
		owed := &evsPrefixPinOwed{}
		if _, err := func() (bool, error) {
			judge.storeLock.Lock()
			defer judge.storeLock.Unlock()
			return aclPrefixReadStoreJson(self.args.Store, entry.Name, owed)
		}(); err != nil {
			firstErr = cmp.Or(firstErr, err)
			continue
		}
		if self.clock.Now().Before(time.UnixMilli(owed.LastMs).Add(judge.settings.PinPushRetryInterval)) {
			// sent within the interval: the next pass
			continue
		}
		if _, err := self.PinPushRules(ctx, repoId, owed.At); err != nil {
			self.log.Infof("[evs]the owed pin pushes of repo %s: %v", repoId, err)
			firstErr = cmp.Or(firstErr, err)
		}
	}
	return firstErr
}

// A subject `ur evs rules` cannot name: not one of 16.2.9's forms, or a name this device's config head does not hold.
var ErrEvsPrefixSubject = errors.New("evs: no such prefix rule subject")

// A group named as a subject (16.2.9): a group's members change and a reader that holds no state at a push's pin
// cannot judge them (16.2.2), so the command files each member's user: subject instead, which Members lists.
type EvsPrefixGroupSubjectError struct {
	Group string
	// Each member's subject, user:<email>, or member:<id> for one the head names no email for; sorted.
	Members []string
}

// The group and that its members are filed instead, never the members themselves.
func (self *EvsPrefixGroupSubjectError) Error() string {
	return fmt.Sprintf("%s: group:%s names nobody in a prefix rule; file its %d members' user: subjects instead", ErrEvsPrefixSubject, self.Group, len(self.Members))
}

// ErrEvsPrefixSubject, so errors.Is finds it.
func (self *EvsPrefixGroupSubjectError) Unwrap() error {
	return ErrEvsPrefixSubject
}

// The autogroups a prefix rule's subject may name (16.2.2's names).
var evsPrefixAutogroups = map[string]protocol.AclAutogroup{
	"sidecar":   protocol.AclAutogroup_ACL_AUTOGROUP_SIDECAR,
	"member":    protocol.AclAutogroup_ACL_AUTOGROUP_MEMBER,
	"tagged":    protocol.AclAutogroup_ACL_AUTOGROUP_TAGGED,
	"ephemeral": protocol.AclAutogroup_ACL_AUTOGROUP_EPHEMERAL,
}

// The atom a subject's text names in a prefix rule (DESIGN-DETAILS 16.2.2, 16.2.9), read against a verified state's
// members and rows and the names its config head's tables give their atoms (AclLocalPolicy.Names, nil where this
// device opens no head): sidecar:<id>, user:<email> (the member's id, which names its untagged devices), tag:<name>
// (the tag's atom id, which its devices carry), or autogroup:sidecar, member, tagged or ephemeral. group:<name> is an
// *EvsPrefixGroupSubjectError listing its members' user: subjects. Any other form, and a name the head does not hold,
// is ErrEvsPrefixSubject.
func evsPrefixSubjectOf(state *ConfigState, local *AclLocalPolicy, text string) (Id, error) {
	kind, value, found := strings.Cut(text, ":")
	if !found || value == "" {
		return Id{}, fmt.Errorf("%w: a subject is sidecar:, user:, tag:, group: or autogroup: and a name", ErrEvsPrefixSubject)
	}
	switch kind {
	case "sidecar":
		sidecarId, err := ParseId(value)
		if err != nil {
			return Id{}, fmt.Errorf("%w: no sidecar id", ErrEvsPrefixSubject)
		}
		return sidecarId, nil
	case "autogroup":
		autogroup, ok := evsPrefixAutogroups[value]
		if !ok {
			return Id{}, fmt.Errorf("%w: a rule names autogroup:sidecar, member, tagged or ephemeral", ErrEvsPrefixSubject)
		}
		return AclAutogroupAtom(autogroup), nil
	case "user", "tag", "group":
	default:
		return Id{}, fmt.Errorf("%w: a subject of kind %q", ErrEvsPrefixSubject, kind)
	}
	if local == nil {
		return Id{}, fmt.Errorf("%w: this device opens no config head, so it reads no %s names", ErrEvsPrefixSubject, kind)
	}
	atomId, found := Id{}, false
	for _, name := range local.Names {
		if name.Text == text {
			atomId, found = name.Id, true
			break
		}
	}
	if !found {
		return Id{}, fmt.Errorf("%w: the config head names no %s", ErrEvsPrefixSubject, kind)
	}
	switch kind {
	case "tag":
		return atomId, nil
	case "user":
		for _, memberId := range state.MemberIds() {
			if AclDerivedAtom(AclDerivedAtomMember, memberId.Bytes()) == atomId {
				return memberId, nil
			}
		}
		return Id{}, fmt.Errorf("%w: a user the state admits no member for", ErrEvsPrefixSubject)
	}
	groupErr := &EvsPrefixGroupSubjectError{Group: value, Members: []string{}}
	acl, err := state.Acl()
	if err != nil {
		return Id{}, err
	}
	for _, atom := range acl.Rows().GetAtoms() {
		if !bytes.Equal(atom.GetAtom(), atomId.Bytes()) {
			continue
		}
		for _, memberBytes := range atom.GetMemberIds() {
			if memberId, err := IdFromBytes(memberBytes); err == nil {
				groupErr.Members = append(groupErr.Members, evsPrefixMemberText(local, memberId))
			}
		}
	}
	slices.Sort(groupErr.Members)
	return Id{}, groupErr
}

// A member's subject text: user:<email> where the head names one, else member:<id>.
func evsPrefixMemberText(local *AclLocalPolicy, memberId Id) string {
	derived := AclDerivedAtom(AclDerivedAtomMember, memberId.Bytes())
	if local != nil {
		for _, name := range local.Names {
			if name.Id == derived && strings.HasPrefix(name.Text, "user:") {
				return name.Text
			}
		}
	}
	return "member:" + memberId.String()
}

// A rule's subject as `ur evs rules show` prints it, the inverse of evsPrefixSubjectOf where the head names it:
// autogroup:<name>, sidecar:<id>, user:<email> (member:<id> with no email), tag:<name>, else id:<id>, which names
// nobody this state holds.
func evsPrefixSubjectText(state *ConfigState, local *AclLocalPolicy, subject Id) string {
	if autogroup, ok := aclAtomAutogroup(subject); ok {
		for name, value := range evsPrefixAutogroups {
			if value == autogroup {
				return "autogroup:" + name
			}
		}
		return "id:" + subject.String()
	}
	switch {
	case state.Sidecar(subject) != nil:
		return "sidecar:" + subject.String()
	case state.Member(subject) != nil:
		return evsPrefixMemberText(local, subject)
	}
	if local != nil {
		for _, name := range local.Names {
			if name.Id == subject && strings.HasPrefix(name.Text, "tag:") {
				return name.Text
			}
		}
	}
	return "id:" + subject.String()
}
