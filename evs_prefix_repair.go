//go:build !ios_extension

// The repair runner of a ruled repo (EVS1-M6-05; DESIGN-DETAILS 16.2.8): the repair form with no edit, the effective
// state written back so that evs's newest event of a path is an allowed one again. A repair is an ordinary push,
// signed by its device and allowed by its rules, and it asserts nothing about the breach.
//
//	who     a device whose composition says it repairs (EvsPrefixRulesArgs.Repair: a desktop or the daemon, never a
//	        phone or an ephemeral sidecar), that mirrors the ref, since only a mirror journals an ignored event, and
//	        that the rules allow every path the repair writes: the planner's AllowPrefixWrite refuses the rest
//	        before any request, so a device held to a prefix repairs only under it and keeps the other units
//	when    RepairDelay after the device journalled the event, plus a share of RepairJitter by
//	        SHA-256(sidecar_id || push id), so two candidates rarely send at once. A unit whose path's newest event
//	        is allowed by the time it is due was repaired by another device, or written over, and is dropped; one
//	        that loses 5g's CAS stays for the next pass, which finds that
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
//	by hand ByHand runs the due and the undue units at once, with no delay, depth or bound
//
// Not built in this draft, and left in the journal: a directory's delta on its own (a names unit is dropped once no
// other unit of its push is left, its rows restated by its children's repairs), and a removed directory's subtree.
//
// The effective content is read from evs through the reader's own walk, not from the mirror's sealed copy. A path is
// its device's own and goes into no log (I-13). Safe for concurrent use: one pass runs at a time.

package sidecar

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"math/bits"
	"time"
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
	if judge == nil || !judge.args.Repair {
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
				outcome, byteCount, err = judge.repairUnit(ctx, repo, unit, args.ByHand, spend)
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

// Repairs one unit's path (the file header's what and bounds rows): settled where its newest event is allowed again,
// pushed with the bytes it carried, or waiting.
func (self *evsPrefixJudge) repairUnit(ctx context.Context, repo *EvsRepo, unit *EvsPrefixIgnored, byHand bool, spend *evsPrefixRepairSpend) (evsPrefixRepairOutcome, int64, error) {
	read, err := repo.readPaths(ctx, unit.RefId, []*evsReadPath{{path: unit.Path}}, true)
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
	refName, err := repo.prefixRefName(ctx, unit.RefId)
	if err != nil {
		return evsPrefixRepairWaiting, 0, err
	}
	if !byHand && self.settings.RepairPushCount <= len(spend.Pushes) {
		return evsPrefixRepairWaiting, 0, nil
	}
	write := &EvsPathWrite{Path: unit.Path, IfVersion: &base.version}
	byteCount := int64(0)
	if base.version == 0 {
		if newestRemoved {
			// a path a breach created and removed again: evs holds what this device follows
			return evsPrefixRepairSettled, 0, nil
		}
		// a path a breach created: its removal
		write.Remove = true
	} else {
		if !byHand && !newestRemoved && !unit.Versionless && base.ignoredAbove < self.settings.RepairDepth {
			// a versioned file a breach replaced: every reader walks back, so nothing yet
			return evsPrefixRepairWaiting, 0, nil
		}
		content := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
		defer content.close()
		info, err := repo.ReadHead(ctx, &EvsReadArgs{RefId: &unit.RefId, Path: unit.Path, Fresh: true}, content)
		if err != nil {
			return evsPrefixRepairWaiting, 0, err
		}
		if info.Version != base.version {
			// the path moved between the two reads: the next pass
			return evsPrefixRepairWaiting, 0, nil
		}
		byteCount = content.Size()
		spent := int64(0)
		for _, bytes := range spend.Bytes {
			spent += bytes.Count
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
	bytes := []*evsPrefixRepairByte{}
	for _, spent := range spend.Bytes {
		if now.Sub(time.UnixMilli(spent.AtMs)) < self.settings.RepairByteWindow {
			bytes = append(bytes, spent)
		}
	}
	spend.Pushes, spend.Bytes = pushes, bytes
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
