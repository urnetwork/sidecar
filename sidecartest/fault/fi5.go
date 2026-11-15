// FI-5, lifecycle (§22.8; §11.12's deletion and erasure rows, §19.10's close row; D-TEST-10): restore and shred have
// one winner; a restored repo holds its whole key closure; a shredded or erased object never returns, a stale re-seed
// included, unless no surviving device holds the ERASE (§11.12's residual), which §19.10's close report names; and a
// dropped object never returns, a stale re-seed included, except as FI-27 bounds it.
//
// The oracle reads repo/ and the store FI-1's walk reads (fi1.go), the access log through the authorization states a
// schedule names (SetAuthorizationView), and the close report an incident hands it (RecordCloseReport). It keeps
// what it saw across checks, since "never returns" must hold across a later store write and across a site's loss,
// not in one snapshot:
//
//	one winner  repo/'s states as each check reads them follow §11.12's state line: keying, active, deleted{X},
//	            shredding{X}, shredded{X}, every move forward, a restore the only way back, and nothing after a shred's
//	            claim but its tombstone. A move a check did not see whole reads as the moves that compose it. Each
//	            deletion X then ends one way on the store, restored or shredded, never both, and as the log says: a
//	            restore only of an X the access log restores (log first), and a start (deleted{X} to shredding{X})
//	            only of an X the log never restores, no sooner than §11.12's 7 d 10 min after X's entry, past the
//	            7 d within which api takes a RepoRestore (Fi5Settings)
//	closure     a check that finds a repo deleted takes its key closure then: every slot and the keys it holds, its
//	            groups' gen/ objects and their newest generation's wraps. The check that finds it restored holds the
//	            store to that closure, but for keys an authorized ERASE in the history destroyed: nothing of it went
//	            while it was deleted, which no route but restore and DELETE with now may change (§11.12's refused row)
//	shredded    once a check finds a repo shredding, every object of it deleted from then on is a tombstone, and once
//	            it finds it shredded, the repo holds nothing but repo/'s tombstone and place/: no object of its
//	            families, nor of its groups' gkm objects, ever again, a site's loss and a stale re-seed included
//	erased      a slot key an authorized, committed ERASE names, once a check finds it gone, is a tombstone: a later
//	            check finding it in its slot again fails, unless the ERASE is no longer in the store's history (the
//	            site was lost, and no surviving device held it) and a close report names the repo as come back below a
//	            surviving reader's pin under an EvsReseed, where §19.10 says a lost ERASE may let a stale mirror's slot
//	            keys return. The residual is a named exception: an unnamed return fails, and so does a return the
//	            store's history still erases, close report or not
//	dropped     a format-2 drop table (drops/<repo>/_) means a drop ran, and its clause needs FI-27's bound
//	            (TEST-M10-01), so FI-5 fails closed on one rather than pass a returned dropped object
//
// Readings and gaps, each in TEST-M2-06's report: the restore's closure is held at the check that finds the restore,
// not after, since CONSUME, ERASE and rotation change a live repo's closure, which FI-1 holds from then on; a deletion
// the access log holds no RepoDelete for (§19.10's incident deletions) is judged only where the log decides, so its
// start is not refused here; Redis families a shred deletes are soft state ExpectShredded reads, not objects; a write
// that lands and is deleted again inside one step leaves no state a check can read; the close report's shape is the
// one this file reads until OPS-M3-05's close step hands it over.

package fault

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(5, func(ctx context.Context, oracle *Oracle) error {
	return checkFi5(ctx, oracle)
})

// The tunables FI-5 checks with: §11.12's and §8.8's values.
type Fi5Settings struct {
	// How long after its RepoDelete's entry a shred's start may first claim a deleted repo: §11.12's 7 d 10 min,
	// past the 7 d within which api takes a RepoRestore (§8.8), so a start and a restore never both win. Non-positive
	// holds a start to no time.
	ShredStartDelay time.Duration
}

func DefaultFi5Settings() *Fi5Settings {
	return &Fi5Settings{
		ShredStartDelay: 7*24*time.Hour + 10*time.Minute,
	}
}

// Names the settings FI-5 checks net's schedules with; until one is named it takes the defaults.
func SetFi5Settings(net *Net, settings *Fi5Settings) {
	memory := netMemoryOf(&fi5Memories, net, newFi5Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	memory.settings = settings
}

// §19.10's close report as FI-5 reads it: what admins learn when an incident's re-seed closes after its 30 days.
// OPS-M3-05's close step builds the report; its T3 schedule hands it to the oracle (RecordCloseReport), and a T2
// schedule standing in for a site's loss names one itself. An ERASE no surviving device saw leaves nothing to name,
// so no report covers one.
type CloseReport struct {
	// The recovery's identity (§19.10).
	IncidentId sidecar.Id
	// The repos that came back only below a surviving reader's pin, under an EvsReseed: where a lost ERASE may let a
	// stale mirror's slot keys return (§11.12's residual).
	BelowPin []*CloseReportBelowPin
}

// One repo's ref a close report names as come back below a surviving reader's pin.
type CloseReportBelowPin struct {
	RepoId sidecar.Id
	RefId  sidecar.Id
	// The version the EvsReseed lets readers accept (§11.6).
	Version uint64
}

// Hands FI-5 a close report for net's schedule. Reports add up: a repo any of them names is named.
func RecordCloseReport(net *Net, report *CloseReport) {
	memory := netMemoryOf(&fi5Memories, net, newFi5Memory)
	copied := &CloseReport{IncidentId: report.IncidentId}
	for _, belowPin := range report.BelowPin {
		belowPinCopy := *belowPin
		copied.BelowPin = append(copied.BelowPin, &belowPinCopy)
	}
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	memory.reports = append(memory.reports, copied)
}

var fi5Memories sync.Map

// What FI-5 keeps from one check to the next on one Net.
type fi5Memory struct {
	stateLock sync.Mutex
	settings  *Fi5Settings
	reports   []*CloseReport
	repos     map[sidecar.Id]*fi5Repo
	// each deletion id's ends on the store, whichever repo it is of
	deletions map[sidecar.Id]*fi5Deletion
}

func newFi5Memory() *fi5Memory {
	return &fi5Memory{
		settings:  DefaultFi5Settings(),
		repos:     map[sidecar.Id]*fi5Repo{},
		deletions: map[sidecar.Id]*fi5Deletion{},
	}
}

// One repo as FI-5 has seen it.
type fi5Repo struct {
	repoId    sidecar.Id
	networkId sidecar.Id
	// repo/ at the last check that read it, nil before any
	last *fi5RepoState
	// place/ stood at the last check
	placed bool
	// its groups, as every walk found them
	groupIds map[sidecar.Id]bool
	// its key closure as a check first found it deleted, nil when none was taken
	closure *fi5Closure
	// set from the first check that found it shredding or shredded
	shred *fi5Shred
	// the slot keys an authorized ERASE named that a check found gone, "<slot id hex>/<key index>"
	erasedGone map[string]bool
}

type fi5RepoState struct {
	state      protocol.EvsRepoState
	deletionId sidecar.Id
	stateMs    int64
}

func (self *fi5RepoState) String() string {
	name := strings.TrimPrefix(self.state.String(), "EVS_REPO_")
	name = strings.ToLower(name)
	if self.deletionId == (sidecar.Id{}) {
		return name
	}
	return fmt.Sprintf("%s{%s}", name, self.deletionId)
}

// How one deletion ended on the store.
type fi5Deletion struct {
	repoId sidecar.Id
	// a check found repo/ go from deleted under it back to active
	restored bool
	// a check found repo/ shredding or shredded under it
	shredded bool
	// a check found repo/ go from deleted under it to shredding under it: the start, not a delete with now
	started bool
}

// A deleted repo's key closure: what a restore must find.
type fi5Closure struct {
	deletionId sidecar.Id
	clusterId  string
	// each slot's key indexes, by slot id hex
	slotKeys map[string][]uint32
	// each group's gen/ keys and its newest generation's wraps, by group
	generationKeys map[sidecar.Id][]string
	newestWrapKeys map[sidecar.Id][]string
	newest         map[sidecar.Id]uint64
}

type fi5Shred struct {
	deletionId sidecar.Id
	// every object of the repo deleted since a check found it shredding, "<cluster id> <key>"
	deleted map[string]bool
	// a check found it shredded and read every family it holds
	tombstoneRead bool
}

func checkFi5(ctx context.Context, oracle *Oracle) error {
	memory := netMemoryOf(&fi5Memories, oracle.Net, newFi5Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	evsMemory := evsOracleMemoryOf(oracle.Net)
	// what the walk could not read is FI-1's to name; FI-5 reads each repo it found
	repos, _ := evsStoreWalkOf(ctx, oracle)
	errs := []error{}

	// this step's deletes of a repo under a shred, before its objects are read, so a delete and a return in one step
	// both count
	memory.noteShredDeletes(oracle)

	placed := map[sidecar.Id]bool{}
	for _, repo := range repos {
		placed[repo.repoId] = true
		errs = append(errs, memory.checkRepo(ctx, oracle, evsMemory, repo)...)
	}
	for repoId, known := range memory.repos {
		if !placed[repoId] {
			// lost with a site, or not placed again yet: what it was stays known
			known.placed = false
		}
	}
	errs = append(errs, memory.checkLog(evsMemory)...)
	return errors.Join(errs...)
}

func (self *fi5Memory) repo(repoId sidecar.Id) *fi5Repo {
	known := self.repos[repoId]
	if known == nil {
		known = &fi5Repo{repoId: repoId, groupIds: map[sidecar.Id]bool{}, erasedGone: map[string]bool{}}
		self.repos[repoId] = known
	}
	return known
}

func (self *fi5Memory) deletion(repoId sidecar.Id, deletionId sidecar.Id) *fi5Deletion {
	deletion := self.deletions[deletionId]
	if deletion == nil {
		deletion = &fi5Deletion{repoId: repoId}
		self.deletions[deletionId] = deletion
	}
	return deletion
}

// One placed repo at this check: repo/'s move since the last, its closure at a deletion and a restore, its shred's
// tombstones, its erased keys and its drop table.
func (self *fi5Memory) checkRepo(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, repo *evsStoreRepo) []error {
	known := self.repo(repo.repoId)
	returned := known.last != nil && !known.placed
	known.placed = true
	for groupId := range repo.groupIds {
		known.groupIds[groupId] = true
	}
	for _, ref := range repo.refs {
		if groupId, err := sidecar.IdFromBytes(ref.head.Head.GetGroupId()); err == nil && groupId != (sidecar.Id{}) {
			known.groupIds[groupId] = true
		}
	}
	errs := []error{}
	if repo.object != nil {
		if networkId := repo.networkId(); networkId != (sidecar.Id{}) {
			known.networkId = networkId
		}
		current := fi5StateOf(repo.object)
		if known.last == nil {
			errs = append(errs, self.enter(ctx, oracle, known, repo, nil, current)...)
		} else if *known.last != *current || returned {
			errs = append(errs, self.move(ctx, oracle, evsMemory, known, repo, *known.last, current, returned)...)
		}
		known.last = current
	}
	if known.shred != nil {
		errs = append(errs, self.checkShredded(ctx, oracle, known, repo, returned)...)
	}
	if repo.walkedBy == oracle {
		// nothing of a repo whose walk an earlier check made has changed since that check
		errs = append(errs, self.checkErased(ctx, oracle, evsMemory, known, repo)...)
		errs = append(errs, fi5CheckDrops(ctx, oracle, repo)...)
	}
	return errs
}

func fi5StateOf(object *protocol.EvsRepoObject) *fi5RepoState {
	state := &fi5RepoState{state: object.GetState(), stateMs: object.GetStateMs()}
	if deletionId, err := sidecar.IdFromBytes(object.GetDeletionId()); err == nil {
		state.deletionId = deletionId
	}
	return state
}

// What a state a check finds first, or reaches, begins: a deletion's closure, or a shred's tombstones.
func (self *fi5Memory) enter(ctx context.Context, oracle *Oracle, known *fi5Repo, repo *evsStoreRepo, previous *fi5RepoState, current *fi5RepoState) []error {
	errs := []error{}
	switch current.state {
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		if previous == nil || previous.state != protocol.EvsRepoState_EVS_REPO_DELETED || previous.deletionId != current.deletionId {
			closure, err := fi5TakeClosure(ctx, oracle, known, repo, current.deletionId)
			if err != nil {
				errs = append(errs, fmt.Errorf("repo %s: its key closure at %s: %w", known.repoId, current, err))
			}
			known.closure = closure
		}
	case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
		self.deletion(known.repoId, current.deletionId).shredded = true
		known.closure = nil
		if known.shred == nil {
			known.shred = &fi5Shred{deletionId: current.deletionId, deleted: map[string]bool{}}
			// the step that claimed it may have begun deleting
			known.noteShredDeletes(oracle)
		}
	}
	return errs
}

// repo/'s move from previous to current, which a check may not have seen whole: legal only as §11.12's state line
// composes, each deletion's end noted.
func (self *fi5Memory) move(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, known *fi5Repo, repo *evsStoreRepo, previous fi5RepoState, current *fi5RepoState, returned bool) []error {
	refuse := func(why string) []error {
		how := ""
		if returned {
			how = ", across a site's loss and its re-seed"
		}
		return []error{fmt.Errorf("repo %s: repo/ went from %s to %s%s: %s", known.repoId, &previous, current, how, why)}
	}
	sameDeletion := previous.deletionId == current.deletionId
	if previous.state == current.state && sameDeletion {
		// the same state written again, or read again across a site's loss: no move
		return nil
	}
	errs := []error{}
	switch previous.state {
	case protocol.EvsRepoState_EVS_REPO_SHREDDING:
		if !sameDeletion || (current.state != protocol.EvsRepoState_EVS_REPO_SHREDDING && current.state != protocol.EvsRepoState_EVS_REPO_SHREDDED) {
			return refuse("a shred's claim is final, and only its tombstone follows it (§11.12), so restore and shred have one winner")
		}
	case protocol.EvsRepoState_EVS_REPO_SHREDDED:
		if !sameDeletion || current.state != protocol.EvsRepoState_EVS_REPO_SHREDDED {
			return refuse("the shredded tombstone stays for the network's life (§11.12)")
		}
	case protocol.EvsRepoState_EVS_REPO_DELETED:
		switch current.state {
		case protocol.EvsRepoState_EVS_REPO_ACTIVE:
			self.deletion(known.repoId, previous.deletionId).restored = true
			errs = append(errs, self.checkRestoredClosure(ctx, oracle, evsMemory, known, repo, previous.deletionId)...)
		case protocol.EvsRepoState_EVS_REPO_DELETED:
			// restored, then deleted again under another RepoDelete, inside one step
			self.deletion(known.repoId, previous.deletionId).restored = true
			errs = append(errs, self.checkRestoredClosure(ctx, oracle, evsMemory, known, repo, previous.deletionId)...)
		case protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
			if sameDeletion {
				// the start: only the 7 d 10 min timer claims a deleted repo under its own deletion
				deletion := self.deletion(known.repoId, previous.deletionId)
				deletion.started = true
				errs = append(errs, self.checkStartTime(known, previous, current)...)
			}
			// under another deletion: a newer RepoDelete with now, so the earlier deletion ends neither way
		default:
			return refuse("a repo leaves deleted only by a restore or a shred")
		}
	case protocol.EvsRepoState_EVS_REPO_ACTIVE:
		switch current.state {
		case protocol.EvsRepoState_EVS_REPO_DELETED, protocol.EvsRepoState_EVS_REPO_SHREDDING, protocol.EvsRepoState_EVS_REPO_SHREDDED:
		case protocol.EvsRepoState_EVS_REPO_ACTIVE:
			// deleted and restored inside one step, or the same state re-read across a site's loss
		default:
			return refuse("an active repo moves only to deleted or shredding")
		}
	case protocol.EvsRepoState_EVS_REPO_KEYING:
		if current.state == protocol.EvsRepoState_EVS_REPO_STATE_UNSPECIFIED {
			return refuse("repo/ names no state")
		}
	default:
		if current.state != previous.state {
			return refuse("repo/ named no state before")
		}
	}
	return append(errs, self.enter(ctx, oracle, known, repo, &previous, current)...)
}

// A start's claim no sooner than ShredStartDelay after the deletion's entry, which deleted's state_ms carries: before
// it, a restore api takes within 7 d could still win. A check that finds the tombstone at once bounds the claim from
// above by its state_ms alone.
func (self *fi5Memory) checkStartTime(known *fi5Repo, previous fi5RepoState, current *fi5RepoState) []error {
	if self.settings.ShredStartDelay <= 0 {
		return nil
	}
	elapsed := time.Duration(current.stateMs-previous.stateMs) * time.Millisecond
	if self.settings.ShredStartDelay <= elapsed {
		return nil
	}
	return []error{fmt.Errorf("repo %s: the shred's start claimed deletion %s %v after its entry, before §11.12's %v: a restore api takes within its 7 d could still win", known.repoId, previous.deletionId, elapsed, self.settings.ShredStartDelay)}
}

// The access log's word on each deletion the store ended: a restore only of what the log restores, and no start nor
// shred of what it restores. Read from every authorization state named for the repo's network, in order, each
// state's AclRepo naming its newest RepoDelete.
func (self *fi5Memory) checkLog(evsMemory *evsOracleMemory) []error {
	errs := []error{}
	repoIds := []sidecar.Id{}
	for repoId := range self.repos {
		repoIds = append(repoIds, repoId)
	}
	slices.SortFunc(repoIds, func(a sidecar.Id, b sidecar.Id) int { return strings.Compare(a.String(), b.String()) })
	for _, repoId := range repoIds {
		known := self.repos[repoId]
		logged := fi5LogDeletions(evsMemory.authorizationHistoryOf(known.networkId), repoId)
		deletionIds := []sidecar.Id{}
		for deletionId, deletion := range self.deletions {
			if deletion.repoId == repoId {
				deletionIds = append(deletionIds, deletionId)
			}
		}
		slices.SortFunc(deletionIds, func(a sidecar.Id, b sidecar.Id) int { return strings.Compare(a.String(), b.String()) })
		for _, deletionId := range deletionIds {
			deletion := self.deletions[deletionId]
			row := logged[deletionId]
			switch {
			case deletion.restored && deletion.shredded:
				errs = append(errs, fmt.Errorf("repo %s: deletion %s was both restored and shredded on the store: restore and shred have one winner", repoId, deletionId))
			case deletion.restored && row == nil:
				errs = append(errs, fmt.Errorf("repo %s: repo/ restored deletion %s, which no authorization state named for its network holds: a restore follows its log (§11.12's log first)", repoId, deletionId))
			case deletion.restored && !row.restored:
				errs = append(errs, fmt.Errorf("repo %s: repo/ restored deletion %s, which the access log never restores: a restore follows its RepoRestore (§11.12's log first)", repoId, deletionId))
			case deletion.shredded && row != nil && row.restored:
				errs = append(errs, fmt.Errorf("repo %s: repo/ shows a shred of deletion %s, which the access log restores: exactly one of restore and start wins, as the log says (§11.12)", repoId, deletionId))
			}
		}
	}
	return errs
}

// One RepoDelete as the access log held it.
type fi5LoggedDeletion struct {
	now      bool
	timeMs   int64
	restored bool
}

// Every RepoDelete of the repo some named state held as its newest, and whether any state held it restored.
func fi5LogDeletions(history []*evsAuthorizationAt, repoId sidecar.Id) map[sidecar.Id]*fi5LoggedDeletion {
	logged := map[sidecar.Id]*fi5LoggedDeletion{}
	for _, at := range history {
		if at.view == nil {
			continue
		}
		row := at.view.Repo(repoId).GetDeletion()
		if row == nil {
			continue
		}
		deletionId, err := sidecar.IdFromBytes(row.GetDeletionId())
		if err != nil {
			continue
		}
		deletion := logged[deletionId]
		if deletion == nil {
			deletion = &fi5LoggedDeletion{now: row.GetNow(), timeMs: row.GetDeletedTimeMs()}
			logged[deletionId] = deletion
		}
		deletion.restored = deletion.restored || row.GetRestoredAt() != 0
	}
	return logged
}

// The key closure of a repo a check finds deleted: the keys of each slot its committed versions name, each group's
// gen/ objects and its newest generation's wraps. A slot no committed version names is a preparation's, which FI-6
// follows.
func fi5TakeClosure(ctx context.Context, oracle *Oracle, known *fi5Repo, repo *evsStoreRepo, deletionId sidecar.Id) (*fi5Closure, error) {
	closure := &fi5Closure{
		deletionId:     deletionId,
		clusterId:      repo.clusterId,
		slotKeys:       map[string][]uint32{},
		generationKeys: map[sidecar.Id][]string{},
		newestWrapKeys: map[sidecar.Id][]string{},
		newest:         map[sidecar.Id]uint64{},
	}
	for _, ref := range repo.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			for _, entryVersion := range version.entryVersions {
				for _, slotId := range entryVersion.GetSlotIds() {
					slotIdHex := hex.EncodeToString(slotId)
					if _, ok := closure.slotKeys[slotIdHex]; ok {
						continue
					}
					key := evsOracleSlotKey(known.repoId, slotId)
					object, err := oracle.View.Object(ctx, repo.clusterId, key)
					if err != nil {
						return closure, err
					}
					keyIndexes := []uint32{}
					if object != nil {
						slot, err := sidecar.EvsDecodeSlotObject(object.Body)
						if err != nil {
							return closure, fmt.Errorf("%s: %w", key, err)
						}
						for _, slotKey := range slot.GetKeys() {
							keyIndexes = append(keyIndexes, slotKey.GetKeyIndex())
						}
					}
					closure.slotKeys[slotIdHex] = keyIndexes
				}
			}
		}
	}
	firstClusterId, err := oracle.View.FirstClusterId()
	if err != nil {
		return closure, err
	}
	for groupId := range known.groupIds {
		generationInfos, err := oracle.View.List(ctx, firstClusterId, fi5GroupPrefix(groupId)+"gen/")
		if err != nil {
			return closure, err
		}
		newest := uint64(0)
		for _, info := range generationInfos {
			closure.generationKeys[groupId] = append(closure.generationKeys[groupId], info.Key)
			newest = max(newest, fi5GenerationOfKey(info.Key))
		}
		closure.newest[groupId] = newest
		if newest == 0 {
			continue
		}
		wrapInfos, err := oracle.View.List(ctx, firstClusterId, fi5WrapGenerationPrefix(groupId, newest))
		if err != nil {
			return closure, err
		}
		for _, info := range wrapInfos {
			closure.newestWrapKeys[groupId] = append(closure.newestWrapKeys[groupId], info.Key)
		}
	}
	return closure, nil
}

// A restored repo's key closure is the one the check that found it deleted took, but what an authorized ERASE in
// its history destroyed and the wraps of a generation no longer the newest.
func (self *fi5Memory) checkRestoredClosure(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, known *fi5Repo, repo *evsStoreRepo, deletionId sidecar.Id) []error {
	closure := known.closure
	known.closure = nil
	if closure == nil || closure.deletionId != deletionId {
		// no check found it deleted under this deletion: FI-1 holds its closure from here
		return nil
	}
	erased, _ := fi1ErasedKeys(repo, evsMemory.authorizationView(known.networkId))
	errs := []error{}
	slotIdHexes := []string{}
	for slotIdHex := range closure.slotKeys {
		slotIdHexes = append(slotIdHexes, slotIdHex)
	}
	slices.Sort(slotIdHexes)
	for _, slotIdHex := range slotIdHexes {
		key := evsOracleRepoPrefix("slot/", known.repoId) + slotIdHex
		object, err := oracle.View.Object(ctx, repo.clusterId, key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		var slot *protocol.EvsSlotObject
		if object != nil {
			if slot, err = sidecar.EvsDecodeSlotObject(object.Body); err != nil {
				errs = append(errs, fmt.Errorf("repo %s: %s: %w", known.repoId, key, err))
				continue
			}
		}
		for _, keyIndex := range closure.slotKeys[slotIdHex] {
			if slot != nil {
				if _, ok := sidecar.EvsSlotKeyAt(slot, keyIndex); ok {
					continue
				}
			}
			if erased[fmt.Sprintf("%s/%d", slotIdHex, keyIndex)] {
				continue
			}
			errs = append(errs, fmt.Errorf("repo %s: restored from deletion %s without key %d of %s, which it held when deleted: a restored repo holds its whole key closure", known.repoId, deletionId, keyIndex, key))
		}
	}
	firstClusterId, err := oracle.View.FirstClusterId()
	if err != nil {
		return append(errs, err)
	}
	groupIds := []sidecar.Id{}
	for groupId := range closure.generationKeys {
		groupIds = append(groupIds, groupId)
	}
	slices.SortFunc(groupIds, func(a sidecar.Id, b sidecar.Id) int { return strings.Compare(a.String(), b.String()) })
	for _, groupId := range groupIds {
		present := map[string]bool{}
		generationInfos, err := oracle.View.List(ctx, firstClusterId, fi5GroupPrefix(groupId)+"gen/")
		if err != nil {
			errs = append(errs, err)
			continue
		}
		newest := uint64(0)
		for _, info := range generationInfos {
			present[info.Key] = true
			newest = max(newest, fi5GenerationOfKey(info.Key))
		}
		for _, key := range closure.generationKeys[groupId] {
			if !present[key] {
				errs = append(errs, fmt.Errorf("repo %s: restored from deletion %s without %s, which it held when deleted: a restored repo holds its whole key closure", known.repoId, deletionId, key))
			}
		}
		if newest != closure.newest[groupId] {
			// a later generation's wraps are the readers' now
			continue
		}
		wrapInfos, err := oracle.View.List(ctx, firstClusterId, fi5WrapGenerationPrefix(groupId, newest))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, info := range wrapInfos {
			present[info.Key] = true
		}
		for _, key := range closure.newestWrapKeys[groupId] {
			if !present[key] {
				errs = append(errs, fmt.Errorf("repo %s: restored from deletion %s without %s, a wrap of its newest generation when deleted: a restored repo holds its whole key closure", known.repoId, deletionId, key))
			}
		}
	}
	return errs
}

// Every delete this step of an object of a repo a check found shredding: a tombstone from then on.
func (self *fi5Memory) noteShredDeletes(oracle *Oracle) {
	for _, known := range self.repos {
		if known.shred != nil {
			known.noteShredDeletes(oracle)
		}
	}
}

func (self *fi5Repo) noteShredDeletes(oracle *Oracle) {
	for _, entry := range oracle.Changed() {
		if entry.Op == sidecartest.BlobHistoryDelete && entry.Outcome == sidecartest.BlobOutcomeOk && self.owns(entry.Key) {
			self.shred.deleted[entry.ClusterId+" "+entry.Key] = true
		}
	}
}

// Whether key is an object of the repo's own families, but repo/ and place/, or a gkm object of one of its groups.
func (self *fi5Repo) owns(key string) bool {
	if strings.HasPrefix(key, "repo/") || strings.HasPrefix(key, "place/") {
		return false
	}
	if repoId, ok := fi5KeyRepo(key); ok {
		return repoId == self.repoId
	}
	if groupId, ok := fi5KeyGroup(key); ok {
		return self.groupIds[groupId]
	}
	return false
}

// A repo's shred: no object it deleted since the repo showed shredding returns, and once it shows shredded, the
// repo holds nothing but repo/ and place/. The first check that finds the tombstone, and the first that finds the
// repo placed again after a site's loss, read every family it may hold; later checks read the keys a step wrote.
func (self *fi5Memory) checkShredded(ctx context.Context, oracle *Oracle, known *fi5Repo, repo *evsStoreRepo, returned bool) []error {
	shred := known.shred
	tombstone := known.last != nil && known.last.state == protocol.EvsRepoState_EVS_REPO_SHREDDED
	errs := []error{}
	if (tombstone && !shred.tombstoneRead) || returned {
		shred.tombstoneRead = shred.tombstoneRead || tombstone
		keys, err := fi5RepoKeys(ctx, oracle, known)
		if err != nil {
			return []error{fmt.Errorf("repo %s: the objects its shred may have left: %w", known.repoId, err)}
		}
		for _, key := range keys {
			errs = append(errs, fmt.Errorf("repo %s: %s is stored after its shred (shredded under %s%s): a shredded object never returns", known.repoId, key, shred.deletionId, fi5ReturnedHow(returned)))
		}
		return errs
	}
	seen := map[string]bool{}
	for clusterId, keys := range oracle.ChangedKeys() {
		for _, key := range keys {
			objectKey := clusterId + " " + key
			if seen[objectKey] || !known.owns(key) || (!tombstone && !shred.deleted[objectKey]) {
				continue
			}
			seen[objectKey] = true
			object, err := oracle.View.Object(ctx, clusterId, key)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if object == nil {
				continue
			}
			if tombstone {
				errs = append(errs, fmt.Errorf("repo %s: %s on %s is written after its shred's tombstone (shredded under %s): a shredded object never returns", known.repoId, key, clusterId, shred.deletionId))
			} else {
				errs = append(errs, fmt.Errorf("repo %s: %s on %s, which was deleted while the repo showed shredding under %s, is stored again: a shredded object never returns", known.repoId, key, clusterId, shred.deletionId))
			}
		}
	}
	return errs
}

func fi5ReturnedHow(returned bool) string {
	if returned {
		return ", placed again after a site's loss"
	}
	return ""
}

// Every object of the repo's families on every cluster but repo/ and place/, and of its groups' gkm objects, each as
// "<key> on <cluster id>".
func fi5RepoKeys(ctx context.Context, oracle *Oracle, known *fi5Repo) ([]string, error) {
	clusterIds, err := oracle.View.ClusterIds()
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for _, clusterId := range clusterIds {
		for _, family := range fi5RepoFamilies {
			infos, err := oracle.View.List(ctx, clusterId, evsOracleRepoPrefix(family, known.repoId))
			if err != nil {
				return nil, err
			}
			for _, info := range infos {
				keys = append(keys, info.Key+" on "+clusterId)
			}
		}
	}
	firstClusterId, err := oracle.View.FirstClusterId()
	if err != nil {
		return nil, err
	}
	groupIds := []sidecar.Id{}
	for groupId := range known.groupIds {
		groupIds = append(groupIds, groupId)
	}
	slices.SortFunc(groupIds, func(a sidecar.Id, b sidecar.Id) int { return strings.Compare(a.String(), b.String()) })
	for _, groupId := range groupIds {
		infos, err := oracle.View.List(ctx, firstClusterId, fi5GroupPrefix(groupId))
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			keys = append(keys, info.Key+" on "+firstClusterId)
		}
	}
	for _, prefix := range []string{"gkm/recovery/", "gkm/welcome/"} {
		infos, err := oracle.View.List(ctx, firstClusterId, prefix)
		if err != nil {
			return nil, err
		}
		for _, info := range infos {
			if known.owns(info.Key) {
				keys = append(keys, info.Key+" on "+firstClusterId)
			}
		}
	}
	return keys, nil
}

// The families keyed by a repo that its shred deletes (§11.12's phases 2 and 5), which neither repo/'s tombstone nor
// place/ is.
var fi5RepoFamilies = []string{"head/", "log/", "idx/", "slot/", "seg/", "pack/", "hp/", "pidx/", "pmap/", "spidx/", "drops/", "dropscan/"}

// The repo a key of the repo-keyed families names, dropscan/ among them.
func fi5KeyRepo(key string) (sidecar.Id, bool) {
	if repoId, ok := evsOracleKeyRepo(key); ok {
		return repoId, true
	}
	rest, ok := strings.CutPrefix(key, "dropscan/")
	if !ok {
		return sidecar.Id{}, false
	}
	idHex, _, _ := strings.Cut(rest, "/")
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 16 {
		return sidecar.Id{}, false
	}
	return sidecar.Id(idBytes), true
}

// The group a gkm key belongs to: gkm/<group_id>/..., gkm/recovery/<member_id>/<group_id>/... and
// gkm/welcome/<sidecar_id>/<group_id>/<n> (sidecar/gkm_paths.go's forms).
func fi5KeyGroup(key string) (sidecar.Id, bool) {
	parts := strings.Split(key, "/")
	if len(parts) < 3 || parts[0] != "gkm" {
		return sidecar.Id{}, false
	}
	idHex := parts[1]
	if parts[1] == "recovery" || parts[1] == "welcome" {
		if len(parts) < 4 {
			return sidecar.Id{}, false
		}
		idHex = parts[3]
	}
	idBytes, err := hex.DecodeString(idHex)
	if err != nil || len(idBytes) != 16 {
		return sidecar.Id{}, false
	}
	return sidecar.Id(idBytes), true
}

func fi5GroupPrefix(groupId sidecar.Id) string {
	return "gkm/" + sidecar.EvsKeyId(groupId) + "/"
}

func fi5WrapGenerationPrefix(groupId sidecar.Id, generation uint64) string {
	return fi5GroupPrefix(groupId) + "wrap/" + evsOracleNumber(generation) + "/"
}

// The generation gkm/<group_id>/gen/<g> names, 0 for a key of another shape.
func fi5GenerationOfKey(key string) uint64 {
	_, digits, ok := strings.Cut(key, "/gen/")
	if !ok {
		return 0
	}
	generation := uint64(0)
	for _, digit := range digits {
		if digit < '0' || '9' < digit {
			return 0
		}
		generation = generation*10 + uint64(digit-'0')
	}
	return generation
}

// Erased keys: each a committed, authorized ERASE in the repo's history names becomes a tombstone once a check finds
// it gone, and a tombstone found in its slot again fails, unless the ERASE left the history with a site's loss and a
// close report names the repo (§11.12's residual).
func (self *fi5Memory) checkErased(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, known *fi5Repo, repo *evsStoreRepo) []error {
	// an ERASE whose authority does not hold is FI-1's violation and excuses nothing here
	erased, _ := fi1ErasedKeys(repo, evsMemory.authorizationView(known.networkId))
	slots := map[string]*protocol.EvsSlotObject{}
	holds := func(slotKey string) (bool, error) {
		slotIdHex, keyIndexText, _ := strings.Cut(slotKey, "/")
		slot, ok := slots[slotIdHex]
		if !ok {
			object, err := oracle.View.Object(ctx, repo.clusterId, evsOracleRepoPrefix("slot/", known.repoId)+slotIdHex)
			if err != nil {
				return false, err
			}
			if object != nil {
				if slot, err = sidecar.EvsDecodeSlotObject(object.Body); err != nil {
					return false, fmt.Errorf("repo %s: slot %s: %w", known.repoId, slotIdHex, err)
				}
			}
			slots[slotIdHex] = slot
		}
		if slot == nil {
			return false, nil
		}
		keyIndex := uint32(0)
		if _, err := fmt.Sscanf(keyIndexText, "%d", &keyIndex); err != nil {
			return false, err
		}
		_, held := sidecar.EvsSlotKeyAt(slot, keyIndex)
		return held, nil
	}
	errs := []error{}
	slotKeys := []string{}
	for slotKey := range erased {
		slotKeys = append(slotKeys, slotKey)
	}
	for slotKey := range known.erasedGone {
		if !erased[slotKey] {
			slotKeys = append(slotKeys, slotKey)
		}
	}
	slices.Sort(slotKeys)
	for _, slotKey := range slotKeys {
		held, err := holds(slotKey)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		switch {
		case !held:
			if erased[slotKey] {
				known.erasedGone[slotKey] = true
			}
		case !known.erasedGone[slotKey]:
			// committed and not yet rewritten out of its slot: the ERASE's retry or the reconciler finishes it
		case erased[slotKey]:
			errs = append(errs, fmt.Errorf("repo %s: slot key %s, which an ERASE in its history destroyed, is in its slot again: an erased object never returns, and evs applies every ERASE it holds before it serves a slot (§19.10)", known.repoId, slotKey))
		case self.closeReportNames(known.repoId):
			// §11.12's residual: the ERASE left with the site, no surviving device held it, and the close report names
			// the repo as come back below a surviving reader's pin
		default:
			errs = append(errs, fmt.Errorf("repo %s: slot key %s, which an ERASE destroyed, is in its slot again with no ERASE in its history, and no close report names the repo: an erased object never returns but as §19.10's close report names §11.12's residual", known.repoId, slotKey))
		}
	}
	return errs
}

// Whether a close report names the repo as come back below a surviving reader's pin.
func (self *fi5Memory) closeReportNames(repoId sidecar.Id) bool {
	for _, report := range self.reports {
		for _, belowPin := range report.BelowPin {
			if belowPin.RepoId == repoId {
				return true
			}
		}
	}
	return false
}

// A drop table means a format-2 drop ran, whose dropped objects FI-27 bounds (TEST-M10-01): fail closed until then.
func fi5CheckDrops(ctx context.Context, oracle *Oracle, repo *evsStoreRepo) []error {
	if repo.clusterId == "" {
		return nil
	}
	object, err := oracle.View.Object(ctx, repo.clusterId, evsOracleRepoPrefix("drops/", repo.repoId)+"_")
	if err != nil {
		return []error{err}
	}
	if object == nil {
		return nil
	}
	return []error{fmt.Errorf("repo %s holds a drop table, and FI-5's dropped-object clause needs FI-27's bound (TEST-M10-01): %w", repo.repoId, ErrInvariantUnbuilt)}
}
