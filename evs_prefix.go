//go:build !ios_extension

// Readers of a ruled repo (EVS1-M6-04; DESIGN-DETAILS 16.2.4, 16.2.5, 16.2.10; QD-212, QD-794, QD-795, QD-801): the
// prefix judge of an EvsClient, which asks ACL-M6-04's PrefixVerdict wherever a change is applied. evs_verify.go is
// not changed, and that is the point: VerifyStatement still answers whether a push is the repo's, and the prefix
// verdict can only take a change away after it.
//
//	judge      one per client. For a verified push it gathers what PrefixVerdict reads: the repo's rows and the
//	           signer's admission row from the client's own verified state, never a state at the push's pin; the
//	           repo's sets through AclPrefixSets (or the composition's source); and the token table of the set in
//	           force in the push's path epoch, built once for each (repo, set, epoch) from K_path of that epoch
//	effective  16.2.5's effective(X) over a head read: the newest event of the path as §11.9 served and verified it,
//	           walked back while the verdict says ignored, each step a read of the version the ignored one replaced
//	           (History's read at prev_commit_version with prev_push_id, or the version below a removal's marker), at
//	           most WalkBackVersionCount versions, to the newest allowed one. A path whose every version is ignored is
//	           absent. Past the depth, or where evs answers collected or holds nothing below an ignored version,
//	           EVS_PREFIX_RULE with detail depth or unavailable. Under a set this device cannot read, pending or a
//	           later release's, the record's accepted version is returned and nothing above it is shown
//	record     the read record's pin, floor and epoch are section 9's and move at every verified read, ignored or
//	           not, since they say what evs was shown. Beside them the record keeps Accepted and IgnoredThrough: a
//	           read whose newest version is at or below IgnoredThrough takes the accepted version from the record with
//	           no walk and no alarm
//	removal    an ignored removal at a directory above the path is found as 9.2.4's verifyPath finds it: the
//	           removal's own token path, a prefix of the path's, is what the verdict judges
//	listing    a directory's folded table is evs's word; each walked delta after it is judged against the table
//	           followed so far, and an ignored one is not applied; a row whose path the record holds as effectively
//	           absent is left out
//	events     a walked statement all of whose inline changes are ignored raises no change event (§11.10)
//	replay     a reader that holds a push whole, the mirror and export, judges each change with its entry, a
//	           directory's delta against the table its own fold holds
//	journal    the mirror's ignored events, {ref, path, version, kind}, in the evs component's sealed store under
//	           prefix_journal/<repo_id>, which EVS1-M6-05's repair consumes and `ur status` lists
//	alarm      evs_alarm with reason prefix_rule (16.2.10): one event for each (repo, ref, signer) in AlarmInterval,
//	           carrying the first path and the count of the changes it stands for. A batch judged inside the interval
//	           of an event already raised is counted into the next one. set_void and set_newer are raised once a set
//	           a device, kept in the sealed store under prefix_alarm/<repo_id>
//
// Head mode on a git-mode ref applies the same rule to the one change it reads, and follows no base: a path an
// overlay holds no entry for answers ErrEvsOverlayBase before anything here is asked (16.2.6; QD-801).
//
// Dark at launch (QD-1032): the rules moved to Later. A judge whose settings keep them off, the defaults every
// composition takes, is held but never asked: prefixJudge answers nil and EvsRepo.prefixRuled nothing, so every read
// shows evs's newest verified version, no write asks AllowPrefixWrite, the mirror journals nothing, and no alarm,
// repair or pin push is sent, whatever rows a state holds. The judge runs as written with EvsPrefixRulesArgs.Settings'
// Enabled on, which the rules' own tests set.
//
// A path's plaintext is its device's own: it goes into an event and the sealed journal, never a log or an error's
// text (I-13). No key is created, derived or unwrapped here but K_path through NewEvsPathKey, which calls
// testHookSecret itself. testHookBarrier runs around the journal's write.
//
// On every leg but ios_extension, whose forwarding role reads no evs repo (owner decision 197). Safe for concurrent
// use.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// The sealed store's layout under the evs component's directory.
const (
	evsPrefixJournalDirectory = "prefix_journal/"
	evsPrefixAlarmDirectory   = "prefix_alarm/"
)

// What the prefix judge of a client runs on.
type EvsPrefixRulesArgs struct {
	// The repo's rule sets for the rows the client's own state holds, in position order, one per row. Nil reads
	// them through an AclPrefixSets over the evs component's sealed store, from the client's verified state where
	// that is a *ConfigState; over any other state no set is held, so every verdict under a row waits.
	Sets func(ctx context.Context, repoId Id) ([]*AclPrefixRuleSet, error)
	// The config head reader the default source opens a set by whose entry this device no longer keeps (16.2.3);
	// nil leaves such a set pending.
	Heads func() ConfigHeadReader
	// The device's newest read of gkm's generation listing for a repo's group, which voids a pending set past its
	// margin (16.2.3); nil voids none.
	Generations func(repoId Id) *AclPrefixGenerationRead
	// AclEngine.AllowPrefixWrite on this device's installed state (16.2.7), which the planner asks before a write's
	// first round trip. Nil refuses every write to a ruled repo with EVS_PREFIX_RULE, detail pending: a device that
	// cannot ask does not write under the rules.
	AllowWrite func(write *AclPrefixWrite) AclPrefixWriteDecision
	// Whether this device repairs (DESIGN-DETAILS 16.2.8's who): true on a desktop or the daemon, never on a phone
	// or an ephemeral sidecar. False runs no repair, by timer or by hand.
	Repair bool
	// Nil: DefaultAclPrefixSettings, whose Enabled keeps the rules dark (QD-1032): the judge is held and never asked.
	Settings *AclPrefixSettings
}

// The class of one ignored event, which says what its repair writes (DESIGN-DETAILS 16.2.8's what rows).
type EvsPrefixIgnoredKind string

const (
	// A version written over a standing file.
	EvsPrefixIgnoredWrite EvsPrefixIgnoredKind = "write"
	// A path the push created.
	EvsPrefixIgnoredCreate EvsPrefixIgnoredKind = "create"
	// A removal of a file or a directory.
	EvsPrefixIgnoredRemove EvsPrefixIgnoredKind = "remove"
	// A directory's delta: rows added or removed.
	EvsPrefixIgnoredNames EvsPrefixIgnoredKind = "names"
)

// One ignored event as the mirror journals it (DESIGN-DETAILS 16.2.5's mirror row).
type EvsPrefixIgnored struct {
	RepoId Id `json:"repo_id"`
	RefId  Id `json:"ref_id"`
	// The path's raw names joined by /, this device's plaintext; empty for the root, and for a path no row this
	// mirror folded names.
	Path  string `json:"path"`
	Named bool   `json:"named"`
	// The path's version the change wrote, or the removal's; the ref version its push committed at; the push and
	// its signer.
	Version         uint64               `json:"version"`
	CommitVersion   uint64               `json:"commit_version"`
	PushId          Id                   `json:"push_id"`
	SignerSidecarId Id                   `json:"signer_sidecar_id"`
	Kind            EvsPrefixIgnoredKind `json:"kind"`
	// The ignored version is versionless, as its path's setting has it: its accepted content is written again at
	// once, where a versioned file's waits for RepairDepth (16.2.8).
	Versionless bool `json:"versionless,omitempty"`
	// When this device journalled it, ms since the epoch: what RepairDelay counts from.
	AtMs int64 `json:"at_ms"`
}

// The prefix judge of one client.
type evsPrefixJudge struct {
	client   *EvsClient
	args     *EvsPrefixRulesArgs
	settings *AclPrefixSettings
	sets     *AclPrefixSets

	// one journal or alarm file write at a time; held across I/O and never inside stateLock
	storeLock sync.Mutex
	// one repair pass at a time (evs_prefix_repair.go); taken before storeLock
	repairLock sync.Mutex

	stateLock sync.Mutex
	// a set's token table in one path epoch, by repo, set position and epoch
	tables map[evsPrefixTableKey]*AclPrefixTokenTable
	// the alarm's window for each (repo, ref, signer)
	alarms map[evsPrefixAlarmKey]*evsPrefixAlarmWindow
	// each repo's sets alarmed as void or newer, by position, loaded once from the sealed store
	setAlarms map[Id]map[uint64]bool
	// each repo's reserved ref ids, which line 1 leaves outside the rules
	reserved map[Id]*evsReservedRefIds
}

// A token table's key.
type evsPrefixTableKey struct {
	repoId Id
	setAt  uint64
	epoch  uint64
}

// An alarm window's key.
type evsPrefixAlarmKey struct {
	repoId   Id
	refId    Id
	signerId Id
}

// The alarm's state for one (repo, ref, signer): when its last event was raised, and what was judged since, which
// the next event carries.
type evsPrefixAlarmWindow struct {
	raisedAt time.Time
	held     *SidecarEvent
}

// A repo's sets alarmed as void or newer, as the sealed store keeps them.
type evsPrefixSetAlarms struct {
	Sets []uint64 `json:"sets"`
}

// Enables the repo's prefix write rules on this client's reads (DESIGN-DETAILS 16.2.5): from here a repo whose rows
// hold a rule set is read through the judge. args nil takes the defaults. A client no composition enables refuses
// every read of such a repo with EVS_PREFIX_RULE, so none shows a version its rules do not allow. With the settings'
// rules dark, the defaults (QD-1032), the judge is installed and asked nothing: see the file header.
func (self *EvsClient) EnablePrefixRules(args *EvsPrefixRulesArgs) {
	if args == nil {
		args = &EvsPrefixRulesArgs{}
	}
	settings := args.Settings
	if settings == nil {
		settings = DefaultAclPrefixSettings()
	}
	judge := &evsPrefixJudge{
		client:    self,
		args:      args,
		settings:  settings,
		sets:      NewAclPrefixSets(self.args.Store, settings),
		tables:    map[evsPrefixTableKey]*AclPrefixTokenTable{},
		alarms:    map[evsPrefixAlarmKey]*evsPrefixAlarmWindow{},
		setAlarms: map[Id]map[uint64]bool{},
		reserved:  map[Id]*evsReservedRefIds{},
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.prefixReads = judge
}

// The client's prefix judge while its rules run: nil for a client no composition enabled it on, and for one whose
// judge's settings keep the rules dark (QD-1032), so every caller asks it nothing.
func (self *EvsClient) prefixJudge() *evsPrefixJudge {
	judge := self.installedPrefixJudge()
	if judge == nil || !judge.settings.Enabled {
		return nil
	}
	return judge
}

// The judge a composition installed, whether or not its rules run: nil for a client none enabled it on.
func (self *EvsClient) installedPrefixJudge() *evsPrefixJudge {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	judge, _ := self.prefixReads.(*evsPrefixJudge)
	return judge
}

// evsPrefixReader's enabled: the judge's settings.
func (self *evsPrefixJudge) enabled() bool {
	return self.settings.Enabled
}

// The prefix judge of this repo's replays, as prefixRuled gives a read's: nil where the repo's rows hold no set.
func (self *EvsRepo) prefixJudge() (*evsPrefixJudge, error) {
	ruled, err := self.prefixRuled()
	if err != nil || ruled == nil {
		return nil, err
	}
	judge, _ := ruled.(*evsPrefixJudge)
	if judge == nil {
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	return judge, nil
}

// One repo's keys as AclPrefixSets reads them, through the client's GkmClient: a generation this device does not
// hold answers nil, which leaves a set pending.
type evsPrefixRepoKeys struct {
	ctx    context.Context
	client *EvsClient
	repoId Id
}

// The repo key of a generation, nil for one this device does not hold.
func (self *evsPrefixRepoKeys) RepoKeyAt(generation uint64) *EvsRepoKey {
	key, err := self.client.args.Gkm.RepoKey(self.ctx, self.repoId, generation)
	if err != nil {
		return nil
	}
	return key
}

// K_path of an epoch, nil where this device holds no key of it.
func (self *evsPrefixRepoKeys) PathKeyAt(epoch uint64) *EvsPathKey {
	repoKey := self.RepoKeyAt(epoch)
	if repoKey == nil {
		return nil
	}
	pathKey, err := NewEvsPathKey(repoKey)
	if err != nil {
		return nil
	}
	return pathKey
}

// When a generation's key was made, which a set's margin counts from; false for one this device does not hold.
func (self *evsPrefixRepoKeys) GenRotateTimeAt(generation uint64) (int64, bool) {
	repoKey := self.RepoKeyAt(generation)
	if repoKey == nil {
		return 0, false
	}
	return repoKey.Time().UnixMilli(), true
}

// The repo's sets for the rows state holds, and the once-a-set alarms a void or newer one raises.
func (self *evsPrefixJudge) setsOf(ctx context.Context, repoId Id, state GkmAuthView) ([]*AclPrefixRuleSet, error) {
	var sets []*AclPrefixRuleSet
	var err error
	if self.args.Sets != nil {
		sets, err = self.args.Sets(ctx, repoId)
	} else if configState, ok := state.(*ConfigState); ok {
		setsArgs := &AclPrefixSetsArgs{
			State:   configState,
			RepoId:  repoId,
			EntryAt: AclPrefixStateEntries(configState),
			Keys:    &evsPrefixRepoKeys{ctx: ctx, client: self.client, repoId: repoId},
		}
		if self.args.Heads != nil {
			setsArgs.Heads = self.args.Heads()
		}
		if self.args.Generations != nil {
			setsArgs.Generations = self.args.Generations(repoId)
		}
		sets, err = self.sets.Sets(ctx, setsArgs)
	}
	if err != nil {
		return nil, err
	}
	self.alarmSets(repoId, sets)
	return sets, nil
}

// Which of ur/index and ur/lfs a ref is, by name, nil for any other: what 16.2.4's line 1 reads of a shared ref.
func (self *evsPrefixJudge) refName(ctx context.Context, repo *EvsRepo, refId Id) ([]byte, error) {
	ids := func() *evsReservedRefIds {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.reserved[repo.repoId]
	}()
	if ids == nil {
		indexRefId, err := repo.resolveRefId(ctx, EvsIndexRefName, nil)
		if err != nil {
			return nil, err
		}
		lfsRefId, err := repo.resolveRefId(ctx, EvsLfsRefName, nil)
		if err != nil {
			return nil, err
		}
		ids = &evsReservedRefIds{indexRefId: indexRefId, lfsRefId: lfsRefId}
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			self.reserved[repo.repoId] = ids
		}()
	}
	switch refId {
	case ids.indexRefId:
		return EvsIndexRefName, nil
	case ids.lfsRefId:
		return EvsLfsRefName, nil
	}
	return nil, nil
}

// The token table of a set in one path epoch, built once: one HMAC per component of each rule's path (16.4).
func (self *evsPrefixJudge) tokenTable(ctx context.Context, repo *EvsRepo, epoch uint64) func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) {
	return func(set *AclPrefixRuleSet) (*AclPrefixTokenTable, error) {
		key := evsPrefixTableKey{repoId: repo.repoId, setAt: set.At, epoch: epoch}
		held := func() *AclPrefixTokenTable {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			return self.tables[key]
		}()
		if held != nil {
			return held, nil
		}
		repoKey, err := self.client.args.Gkm.RepoKey(ctx, repo.repoId, epoch)
		if err != nil {
			return nil, err
		}
		pathKey, err := NewEvsPathKey(repoKey)
		if err != nil {
			return nil, err
		}
		table, err := NewAclPrefixTokenTable(set, pathKey)
		if err != nil {
			return nil, err
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.tables[key] = table
		return table, nil
	}
}

// 16.2.4's verdict on one change of a verified push of this repo; change nil for a push that carries none.
func (self *evsPrefixJudge) verdict(ctx context.Context, repo *EvsRepo, refId Id, statement *EvsStatement, change *AclPrefixChange) (AclPrefixVerdict, error) {
	state, err := self.client.verifier.config()
	if err != nil {
		return AclPrefixVerdict{}, err
	}
	repoRow := state.Repo(repo.repoId)
	if repoRow == nil || len(repoRow.GetPrefixRules()) == 0 {
		return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoSet}, nil
	}
	push := statement.Push
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return AclPrefixVerdict{}, fmt.Errorf("%w: a push with no signer", ErrEvsEntryRefused)
	}
	refName, err := self.refName(ctx, repo, refId)
	if err != nil {
		return AclPrefixVerdict{}, err
	}
	sets, err := self.setsOf(ctx, repo.repoId, state)
	if err != nil {
		return AclPrefixVerdict{}, err
	}
	return PrefixVerdict(&AclPrefixVerdictArgs{
		RepoKind:   repoRow.GetKind(),
		RefKind:    protocol.EvsRefKind(push.GetRefKind()),
		RefMode:    protocol.EvsRefMode(push.GetRefMode()),
		RefName:    refName,
		Flags:      push.GetFlags(),
		PinVersion: push.GetAuth().GetVersion(),
		Signer:     state.SidecarRow(signerId),
		Rows:       repoRow.GetPrefixRules(),
		Sets:       sets,
		TokenTable: self.tokenTable(ctx, repo, max(1, push.GetPathEpoch())),
		Change:     change,
	}), nil
}

// The change a verified version, removal or delta is, as line 5 judges it: its statement's own change at the
// change's own token path, which for a removal may be a directory's above the path (9.2.4's verifyPath), with the
// entry's rows where it is a directory's. held is the table a delta applies to, nil for none.
func evsPrefixChangeOf(verified *EvsVerifiedPath, held func(token EvsToken) (protocol.EvsEntryKind, bool)) *AclPrefixChange {
	change := &AclPrefixChange{TokenPath: verified.ChangePath, Removal: verified.Removal != nil}
	if entry := verified.Entry; entry != nil && verified.Removal == nil {
		change.Directory = entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		change.Creates = verified.Change.GetBaseEntryVersion() == 0
		change.Names = entry.GetNames()
		change.Table = held
	}
	return change
}

// The verdict on what a read verified of one path: allowed for a path evs holds no event of, or an overlay's base,
// which carry no statement to judge.
func (self *evsPrefixJudge) verdictOfPath(ctx context.Context, repo *EvsRepo, refId Id, verified *EvsVerifiedPath, held func(token EvsToken) (protocol.EvsEntryKind, bool)) (AclPrefixVerdict, error) {
	if verified.Statement == nil || verified.Change == nil || verified.Base != nil {
		return AclPrefixVerdict{Outcome: AclPrefixAllowed, Reason: AclPrefixReasonNoChange}, nil
	}
	return self.verdict(ctx, repo, refId, verified.Statement, evsPrefixChangeOf(verified, held))
}

// The path's version an event is: a version's own, or a removal's, one past the path's last.
func evsPrefixEventVersion(verified *EvsVerifiedPath) uint64 {
	if verified.Removal != nil {
		return verified.Removal.GetPathVersion()
	}
	return verified.Entry.GetVersion()
}

// EVS_PREFIX_RULE for a set this device cannot read: pending, or update for a later release's.
func evsPrefixUnreadError(verdict AclPrefixVerdict, path string) error {
	if verdict.Outcome == AclPrefixUpdate {
		return &EvsPrefixRuleError{Detail: EvsPrefixDetailUpdate, Path: path}
	}
	return &EvsPrefixRuleError{Detail: EvsPrefixDetailPending, Path: path}
}

// A read that shows the path as absent, in current's place: its head, keys and objects, which the caller closes.
func evsPrefixAbsentResult(current *evsReadResult) *evsReadResult {
	absent := &EvsVerifiedPath{TokenPath: current.replies[0].TokenPath, Absent: true}
	return &evsReadResult{
		refId: current.refId, head: current.head, keys: current.keys, paths: current.paths,
		replies: []*EvsVerifiedPath{absent}, objects: current.objects, receiptExempt: current.receiptExempt,
	}
}

// evsPrefixReader's effective: see the file header.
func (self *evsPrefixJudge) effective(ctx context.Context, repo *EvsRepo, path string, result *evsReadResult) (*evsReadResult, *evsPrefixRead, error) {
	read := &evsPrefixRead{}
	refId := result.refId
	newest := result.replies[0]
	if newest.Base != nil || newest.Statement == nil {
		// evs holds no event of the path on this ref: nothing to judge
		return result, read, nil
	}
	current := result
	fail := func(err error) (*evsReadResult, *evsPrefixRead, error) {
		current.objects.close()
		return nil, nil, err
	}
	newestVersion := evsPrefixEventVersion(newest)
	record, _, err := self.client.pins.ReadRecord(repo.repoId, refId, path)
	if err != nil {
		return fail(err)
	}
	if record != nil && record.Accepted != nil && newestVersion <= record.IgnoredThrough {
		// from the record: no walk and no alarm
		accepted, err := self.readAccepted(ctx, repo, refId, path, current, record.Accepted)
		if err != nil {
			return nil, nil, err
		}
		read.ignoredAbove = record.Accepted.IgnoredAbove
		return accepted, read, nil
	}
	signerOf := func(verified *EvsVerifiedPath) Id {
		signerId, _ := IdFromBytes(verified.Statement.Push.GetSignerSidecarId())
		return signerId
	}
	// what the walk ends on is kept in the record, so the next read of an unchanged path takes it from there
	note := func(accepted *EvsReadAccepted, ignoredThrough uint64) error {
		return self.client.pins.NoteAccepted(repo.repoId, refId, path, accepted, ignoredThrough)
	}
	ignoredCount := 0
	for {
		verified := current.replies[0]
		verdict, err := self.verdictOfPath(ctx, repo, refId, verified, nil)
		if err != nil {
			return fail(err)
		}
		switch verdict.Outcome {
		case AclPrefixAllowed:
			accepted := &EvsReadAccepted{IgnoredAbove: ignoredCount}
			if verified.Removal != nil {
				accepted.Absent = true
			} else {
				accepted.Version, accepted.CommitVersion = verified.Entry.GetVersion(), verified.CommitVersion
				accepted.PushId, _ = IdFromBytes(verified.Entry.GetPushId())
			}
			ignoredThrough := uint64(0)
			if 0 < ignoredCount {
				ignoredThrough = newestVersion
			}
			if err := note(accepted, ignoredThrough); err != nil {
				return fail(err)
			}
			read.ignoredAbove = ignoredCount
			return current, read, nil
		case AclPrefixIgnored:
		default:
			// a set this device cannot read: the record's accepted version, and nothing above it
			if record == nil || record.Accepted == nil {
				return fail(evsPrefixUnreadError(verdict, path))
			}
			accepted, err := self.readAccepted(ctx, repo, refId, path, current, record.Accepted)
			if err != nil {
				return nil, nil, err
			}
			read.ignoredAbove, read.state = record.Accepted.IgnoredAbove, "held"
			if verdict.Outcome == AclPrefixUpdate {
				read.state = "update"
			}
			return accepted, read, nil
		}
		pushId, _ := IdFromBytes(verified.Statement.Push.GetPushId())
		self.alarm(repo.repoId, refId, signerOf(verified), path, verified.CommitVersion, &pushId, SidecarEvsAlarmDetailIgnored, 1)
		ignoredCount += 1
		// what a write over it names (QD-833)
		read.ignored = append(read.ignored, evsPrefixIgnoredPush{commitVersion: verified.CommitVersion, pushId: pushId})
		if self.settings.WalkBackVersionCount < ignoredCount {
			self.alarm(repo.repoId, refId, signerOf(verified), path, verified.CommitVersion, &pushId, SidecarEvsAlarmDetailDepth, 1)
			return fail(&EvsPrefixRuleError{Detail: EvsPrefixDetailDepth, Path: path})
		}
		// the event the ignored one replaced
		below := &evsReadPath{path: path}
		var expectPushId []byte
		if verified.Removal != nil {
			if verified.Removal.GetPathVersion() <= 1 {
				return fail(fmt.Errorf("%w: a removal of no version", ErrEvsEntryRefused))
			}
			below.version = verified.Removal.GetPathVersion() - 1
		} else {
			entry := verified.Entry
			if len(entry.GetPrevPushId()) == 0 || entry.GetVersion() <= 1 {
				// the ignored version created the path: it is effectively absent
				if err := note(&EvsReadAccepted{Absent: true, IgnoredAbove: ignoredCount}, newestVersion); err != nil {
					return fail(err)
				}
				read.ignoredAbove = ignoredCount
				return evsPrefixAbsentResult(current), read, nil
			}
			below.version = entry.GetVersion() - 1
			below.commitVersion, below.prevPushId = entry.GetPrevCommitVersion(), entry.GetPrevPushId()
			expectPushId = entry.GetPrevPushId()
		}
		next, err := repo.readPaths(ctx, refId, []*evsReadPath{below}, false)
		if err != nil {
			return fail(err)
		}
		current.objects.close()
		current = next
		found := next.replies[0]
		switch {
		case found.Base != nil:
			return current, read, nil
		case found.Absent, found.Collected:
			// evs holds nothing below the ignored version, or collected it. A device that still held the accepted
			// version's content would serve it; a head reader holds none
			self.alarm(repo.repoId, refId, signerOf(verified), path, verified.CommitVersion, &pushId, SidecarEvsAlarmDetailUnavailable, 1)
			return fail(&EvsPrefixRuleError{Detail: EvsPrefixDetailUnavailable, Path: path})
		case below.version < evsPrefixEventVersion(found),
			found.Entry != nil && found.Removal == nil && expectPushId != nil &&
				(!bytes.Equal(found.Entry.GetPushId(), expectPushId) || found.CommitVersion != below.commitVersion):
			// a read by number answers that version or one below it, and the version its successor names
			self.client.alarm(repo.repoId, refId, SidecarEvsAlarmTamper, path, nil)
			return fail(fmt.Errorf("%w: a version its successor does not name", ErrEvsEntryRefused))
		}
	}
}

// The accepted version a record holds, read in current's place, which it closes: by number, and held to the push the
// record names; absent where the record holds the path absent. A version evs no longer serves as accepted is
// EVS_PREFIX_RULE with detail unavailable, a head reader holding no copy.
func (self *evsPrefixJudge) readAccepted(ctx context.Context, repo *EvsRepo, refId Id, path string, current *evsReadResult, accepted *EvsReadAccepted) (*evsReadResult, error) {
	if accepted.Absent {
		return evsPrefixAbsentResult(current), nil
	}
	if entry := current.replies[0].Entry; entry != nil && current.replies[0].Removal == nil &&
		entry.GetVersion() == accepted.Version && bytes.Equal(entry.GetPushId(), accepted.PushId.Bytes()) {
		// the newest version is the accepted one
		return current, nil
	}
	current.objects.close()
	result, err := repo.readPaths(ctx, refId, []*evsReadPath{{path: path, version: accepted.Version, commitVersion: accepted.CommitVersion}}, false)
	if err != nil {
		return nil, err
	}
	found := result.replies[0]
	if found.Entry == nil || found.Removal != nil || found.Collected || found.Entry.GetVersion() != accepted.Version ||
		!bytes.Equal(found.Entry.GetPushId(), accepted.PushId.Bytes()) {
		result.objects.close()
		return nil, &EvsPrefixRuleError{Detail: EvsPrefixDetailUnavailable, Path: path}
	}
	return result, nil
}

// evsPrefixReader's allowWrite: AllowPrefixWrite with the sets this device holds for its own state's rows.
func (self *evsPrefixJudge) allowWrite(ctx context.Context, repo *EvsRepo, ask *evsPrefixWriteAsk) error {
	if self.args.AllowWrite == nil {
		return &EvsPrefixRuleError{Detail: EvsPrefixDetailPending}
	}
	state, err := self.client.verifier.config()
	if err != nil {
		return err
	}
	sets, err := self.setsOf(ctx, repo.repoId, state)
	if err != nil {
		return err
	}
	paths := slices.Values(ask.paths)
	if ask.drawn != nil {
		paths = ask.drawn
	}
	decision := self.args.AllowWrite(&AclPrefixWrite{
		RepoId: repo.repoId, RefKind: ask.refKind, RefMode: ask.refMode, RefName: ask.refName, Flags: ask.flags,
		Paths: paths, Sets: sets,
	})
	if decision.Allowed {
		return nil
	}
	return &EvsPrefixRuleError{Detail: EvsPrefixDetail(decision.Detail.String()), Path: decision.Path}
}

// evsPrefixReader's writeBase: the walk runs on a read of the path alone, so the planner's own read keeps what it
// verified of evs's newest event, which the write's base_entry_version and prev_push_id name (16.2.7). The ignored
// events the repair writes over are the walk's, or, where the read record answered with no walk, the same events read
// again without its alarms (writtenOverEvents, evs_prefix_repair.go).
func (self *evsPrefixJudge) writeBase(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int) (*evsPrefixWriteBase, error) {
	verified := result.replies[index]
	if entry := verified.Entry; entry != nil && verified.Removal == nil && entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
		// a directory's removal goes on what evs holds of it: its deltas are a listing's to judge
		return nil, nil
	}
	path := result.paths[index].path
	verdict, err := self.verdictOfPath(ctx, repo, result.refId, verified, nil)
	if err != nil {
		return nil, err
	}
	switch verdict.Outcome {
	case AclPrefixAllowed:
		return nil, nil
	case AclPrefixIgnored:
	default:
		return nil, evsPrefixUnreadError(verdict, path)
	}
	own, err := repo.readPaths(ctx, result.refId, []*evsReadPath{{path: path}}, false)
	if err != nil {
		return nil, err
	}
	effective, read, err := self.effective(ctx, repo, path, own)
	if err != nil {
		return nil, err
	}
	defer effective.objects.close()
	base := &evsPrefixWriteBase{ignoredAbove: max(1, read.ignoredAbove), writtenOver: read.ignored}
	if found := effective.replies[0]; found.Entry != nil && found.Removal == nil && !found.Absent {
		base.version = found.Entry.GetVersion()
	}
	if len(base.writtenOver) == 0 {
		if base.writtenOver, err = self.writtenOverEvents(ctx, repo, result.refId, path, verified); err != nil {
			return nil, err
		}
	}
	return base, nil
}

// evsPrefixReader's ignored.
func (self *evsPrefixJudge) ignored(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int) (bool, error) {
	verdict, err := self.verdictOfPath(ctx, repo, result.refId, result.replies[index], nil)
	if err != nil {
		return false, err
	}
	return verdict.Outcome == AclPrefixIgnored, nil
}

// evsPrefixReader's deltaIgnored: an ignored delta alarms; one under a set this device cannot read refuses the
// listing, which would otherwise show rows nobody judged.
func (self *evsPrefixJudge) deltaIgnored(ctx context.Context, repo *EvsRepo, result *evsReadResult, index int, delta *EvsVerifiedPath, held func(token EvsToken) (protocol.EvsEntryKind, bool)) (bool, error) {
	verdict, err := self.verdictOfPath(ctx, repo, result.refId, delta, held)
	if err != nil {
		return false, err
	}
	path := result.paths[index].path
	switch verdict.Outcome {
	case AclPrefixAllowed:
		return false, nil
	case AclPrefixIgnored:
		signerId, _ := IdFromBytes(delta.Statement.Push.GetSignerSidecarId())
		pushId, _ := IdFromBytes(delta.Statement.Push.GetPushId())
		self.alarm(repo.repoId, result.refId, signerId, path, delta.CommitVersion, &pushId, SidecarEvsAlarmDetailIgnored, 1)
		return true, nil
	}
	return false, evsPrefixUnreadError(verdict, path)
}

// evsPrefixReader's rowAbsent.
func (self *evsPrefixJudge) rowAbsent(repo *EvsRepo, refId Id, path string, addedAt uint64) (bool, error) {
	record, ok, err := self.client.pins.ReadRecord(repo.repoId, refId, path)
	if err != nil || !ok {
		return false, err
	}
	return record.Accepted != nil && record.Accepted.Absent && record.IgnoredThrough != 0 && addedAt <= record.PinVersion, nil
}

// evsPrefixReader's followed. A statement's inline list carries no entry, so a change is judged by its own path
// alone: a design writer's delta on the way to its prefix reads as outside it here, and every such push also changes
// a path under the prefix, which is what its subscribers are touched by. Only a statement none of whose changes is
// followed is a breach for certain, and that one alarms; a list under changes_root names no change to judge.
func (self *evsPrefixJudge) followed(ctx context.Context, repo *EvsRepo, refId Id, verified *EvsVerifiedStatement) ([]EvsTokenPath, bool) {
	statement := verified.Statement
	if len(statement.Changes) == 0 {
		return evsStatementTokenPaths(statement), true
	}
	followed := []EvsTokenPath{}
	for _, change := range statement.Changes {
		verdict, err := self.verdict(ctx, repo, refId, statement, &AclPrefixChange{
			TokenPath: change.TokenPath,
			Removal:   !change.WritesEntry(),
			Creates:   change.Change.GetBaseEntryVersion() == 0,
		})
		if err != nil || verdict.Outcome != AclPrefixIgnored {
			// what this device cannot judge prompts a read, which judges it
			followed = append(followed, change.TokenPath)
		}
	}
	if len(followed) == 0 {
		signerId, _ := IdFromBytes(statement.Push.GetSignerSidecarId())
		pushId, _ := IdFromBytes(statement.Push.GetPushId())
		self.alarm(repo.repoId, refId, signerId, "", verified.Version, &pushId, SidecarEvsAlarmDetailIgnored, len(statement.Changes))
		return nil, false
	}
	return followed, true
}

// Raises evs_alarm with reason prefix_rule (16.2.10) for count changes of one signer on one ref, first of them at
// path: at once where no event of that (repo, ref, signer) was raised within AlarmInterval, carrying whatever was
// judged since the last one; else counted into the next. The path goes into the event, never the log (I-13).
func (self *evsPrefixJudge) alarm(repoId Id, refId Id, signerId Id, path string, version uint64, pushId *Id, detail SidecarEvsAlarmDetail, count int) {
	now := self.client.clock.Now()
	key := evsPrefixAlarmKey{repoId: repoId, refId: refId, signerId: signerId}
	event := func() *SidecarEvent {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		window := self.alarms[key]
		if window == nil {
			window = &evsPrefixAlarmWindow{}
			self.alarms[key] = window
		}
		if window.held == nil {
			// the first path judged since the last event names the next one
			window.held = &SidecarEvent{
				Kind: SidecarEventEvsAlarm, RepoId: &repoId, RefId: &refId, SidecarId: &signerId, Path: path,
				EvsAlarm: SidecarEvsAlarmPrefixRule, EvsAlarmDetail: detail, Version: version, PushId: pushId, Count: count,
			}
		} else {
			window.held.Count += count
		}
		if !window.raisedAt.IsZero() && 0 < self.settings.AlarmInterval && now.Sub(window.raisedAt) < self.settings.AlarmInterval {
			return nil
		}
		raised := window.held
		window.held, window.raisedAt = nil, now
		return raised
	}()
	if event == nil {
		return
	}
	self.client.log.Warningf("[evs]alarm %s (%s) on repo %s ref %s: %d changes", SidecarEvsAlarmPrefixRule, event.EvsAlarmDetail, repoId, refId, event.Count)
	self.client.emit(*event)
}

// Raises set_void and set_newer once a set a device (16.2.10), with the row's signer and position in place of a
// push: what was raised is kept in the sealed store, so a restart raises none again. A store that fails raises the
// alarm again later rather than never.
func (self *evsPrefixJudge) alarmSets(repoId Id, sets []*AclPrefixRuleSet) {
	due := []*AclPrefixRuleSet{}
	for _, set := range sets {
		if set.State == AclPrefixSetVoid || set.State == AclPrefixSetNewer {
			due = append(due, set)
		}
	}
	if len(due) == 0 {
		return
	}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	alarmed := func() map[uint64]bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.setAlarms[repoId]
	}()
	name := evsPrefixAlarmDirectory + repoId.String()
	if alarmed == nil {
		stored := &evsPrefixSetAlarms{}
		if _, err := aclPrefixReadStoreJson(self.client.args.Store, name, stored); err != nil {
			self.client.log.Warningf("[evs]the prefix alarms of repo %s do not read: %v", repoId, err)
		}
		alarmed = map[uint64]bool{}
		for _, at := range stored.Sets {
			alarmed[at] = true
		}
	}
	raise := []*AclPrefixRuleSet{}
	for _, set := range due {
		if !alarmed[set.At] {
			alarmed[set.At] = true
			raise = append(raise, set)
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.setAlarms[repoId] = alarmed
	}()
	if len(raise) == 0 {
		return
	}
	stored := &evsPrefixSetAlarms{}
	for at := range alarmed {
		stored.Sets = append(stored.Sets, at)
	}
	slices.Sort(stored.Sets)
	if data, err := json.Marshal(stored); err == nil {
		if err := aclPrefixWriteStoreFile(self.client.args.Store, name, data); err != nil {
			self.client.log.Warningf("[evs]the prefix alarms of repo %s do not store: %v", repoId, err)
		}
	}
	for _, set := range raise {
		detail := SidecarEvsAlarmDetailSetVoid
		if set.State == AclPrefixSetNewer {
			detail = SidecarEvsAlarmDetailSetNewer
		}
		signerId := set.Signer
		self.client.log.Warningf("[evs]alarm %s (%s) on repo %s: the set at %d", SidecarEvsAlarmPrefixRule, detail, repoId, set.At)
		self.client.emit(SidecarEvent{
			Kind: SidecarEventEvsAlarm, RepoId: &repoId, SidecarId: &signerId,
			EvsAlarm: SidecarEvsAlarmPrefixRule, EvsAlarmDetail: detail, Version: set.At, Count: 1,
		})
	}
}

// One change of a push a replay holds whole, its entry with it, judged (16.2.4): true where this device ignores it.
// held is the table a directory's delta applies to, as the replay's own fold holds it. A set this device cannot read
// leaves the replay waiting at the push, with EVS_PREFIX_RULE.
func (self *evsPrefixJudge) replayIgnored(ctx context.Context, repo *EvsRepo, refId Id, statement *EvsStatement, change *EvsCheckedChange, held func(token EvsToken) (protocol.EvsEntryKind, bool)) (bool, error) {
	judged := &AclPrefixChange{TokenPath: change.TokenPath, Removal: !change.WritesEntry()}
	if change.WritesEntry() {
		entry := &protocol.EvsEntryVersion{}
		if err := proto.Unmarshal(change.EntryVersion, entry); err != nil {
			return false, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
		}
		judged.Directory = entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		judged.Creates = change.Change.GetBaseEntryVersion() == 0
		judged.Names = entry.GetNames()
		judged.Table = held
	}
	verdict, err := self.verdict(ctx, repo, refId, statement, judged)
	if err != nil {
		return false, err
	}
	switch verdict.Outcome {
	case AclPrefixAllowed:
		return false, nil
	case AclPrefixIgnored:
		return true, nil
	}
	return false, evsPrefixUnreadError(verdict, "")
}

// The journal's file for a repo.
func evsPrefixJournalName(repoId Id) string {
	return evsPrefixJournalDirectory + repoId.String()
}

// A journal unit's identity: one change of one push at one path.
func evsPrefixIgnoredSame(a *EvsPrefixIgnored, b *EvsPrefixIgnored) bool {
	return a.RefId == b.RefId && a.PushId == b.PushId && a.Path == b.Path && a.Kind == b.Kind && a.Version == b.Version
}

// Reads a repo's journal, empty where none is stored.
func (self *evsPrefixJudge) journal(repoId Id) ([]*EvsPrefixIgnored, error) {
	units := []*EvsPrefixIgnored{}
	if _, err := aclPrefixReadStoreJson(self.client.args.Store, evsPrefixJournalName(repoId), &units); err != nil {
		return nil, err
	}
	return units, nil
}

// Adds ignored events to a repo's journal, each once, durably.
func (self *evsPrefixJudge) journalAdd(repoId Id, added []*EvsPrefixIgnored) error {
	if len(added) == 0 {
		return nil
	}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	units, err := self.journal(repoId)
	if err != nil {
		return err
	}
	changed := false
	for _, unit := range added {
		if !slices.ContainsFunc(units, func(held *EvsPrefixIgnored) bool { return evsPrefixIgnoredSame(held, unit) }) {
			units = append(units, unit)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return self.journalWrite(repoId, units)
}

// Drops the units a repair settled from a repo's journal.
func (self *evsPrefixJudge) journalRemove(repoId Id, settled []*EvsPrefixIgnored) error {
	if len(settled) == 0 {
		return nil
	}
	self.storeLock.Lock()
	defer self.storeLock.Unlock()
	units, err := self.journal(repoId)
	if err != nil {
		return err
	}
	kept := slices.DeleteFunc(units, func(held *EvsPrefixIgnored) bool {
		return slices.ContainsFunc(settled, func(unit *EvsPrefixIgnored) bool { return evsPrefixIgnoredSame(held, unit) })
	})
	return self.journalWrite(repoId, kept)
}

// Replaces a repo's journal, under storeLock: the file is removed with its last unit.
func (self *evsPrefixJudge) journalWrite(repoId Id, units []*EvsPrefixIgnored) error {
	key := repoId.String()
	testHookBarrier("evs.prefix.journal.before", key)
	defer testHookBarrier("evs.prefix.journal.after", key)
	if len(units) == 0 {
		return self.client.args.Store.Remove(evsPrefixJournalName(repoId))
	}
	data, err := json.Marshal(units)
	if err != nil {
		return err
	}
	return aclPrefixWriteStoreFile(self.client.args.Store, evsPrefixJournalName(repoId), data)
}

// The ignored events this device's mirrors journalled, of one repo or with nil of every repo, oldest first: what
// `ur status` lists and the repair runner consumes (DESIGN-DETAILS 16.2.5, 16.2.8). Empty for a client whose prefix
// rules are not enabled.
func (self *EvsClient) PrefixIgnored(repoId *Id) ([]*EvsPrefixIgnored, error) {
	judge := self.prefixJudge()
	if judge == nil {
		return []*EvsPrefixIgnored{}, nil
	}
	repoIds := []Id{}
	if repoId != nil {
		repoIds = append(repoIds, *repoId)
	} else {
		entries, err := self.args.Store.List(evsPrefixJournalDirectory)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if listed, err := ParseId(strings.TrimPrefix(entry.Name, evsPrefixJournalDirectory)); err == nil {
				repoIds = append(repoIds, listed)
			}
		}
	}
	all := []*EvsPrefixIgnored{}
	for _, listed := range repoIds {
		units, err := func() ([]*EvsPrefixIgnored, error) {
			judge.storeLock.Lock()
			defer judge.storeLock.Unlock()
			return judge.journal(listed)
		}()
		if err != nil {
			return nil, err
		}
		all = append(all, units...)
	}
	slices.SortStableFunc(all, func(a *EvsPrefixIgnored, b *EvsPrefixIgnored) int {
		if a.AtMs != b.AtMs {
			if a.AtMs < b.AtMs {
				return -1
			}
			return 1
		}
		return strings.Compare(a.Path, b.Path)
	})
	return all, nil
}

// One path of a file-mode ref as a replay's fold holds it: the raw names its rows gave it, its kind, and whether it
// stands in the table this device follows; a path only an ignored delta named does not.
type evsPrefixFoldNode struct {
	Names    [][]byte `json:"names"`
	Kind     uint32   `json:"kind"`
	Standing bool     `json:"standing"`
}

// A file-mode ref's names as a replay of its pushes from the first version holds them (16.2.5's mirror row): every
// path a directory's row named, by its path epoch and token path, with the rows this device follows marked standing.
// The mirror keeps one per ref in its sealed store, on disk between syncs and in memory during one.
type evsPrefixFold struct {
	// The ref version folded through: the next push folded is the one after it.
	Through uint64                        `json:"through"`
	Nodes   map[string]*evsPrefixFoldNode `json:"nodes"`
}

// A fold of a ref no push was folded into.
func newEvsPrefixFold() *evsPrefixFold {
	return &evsPrefixFold{Nodes: map[string]*evsPrefixFoldNode{}}
}

// A node's key: its path epoch and its token path's bytes, so a path's subtree shares its key as a prefix.
func evsPrefixFoldKey(epoch uint64, tokenPath EvsTokenPath) string {
	return fmt.Sprintf("%d/%s", epoch, hex.EncodeToString(tokenPath.Bytes()))
}

// Drops the nodes at and below key from the table this device follows.
func (self *evsPrefixFold) unstand(key string) {
	for nodeKey, node := range self.Nodes {
		if strings.HasPrefix(nodeKey, key) {
			node.Standing = false
		}
	}
}

// Folds one push of a file-mode ref, in its changes' order, each change judged with its entry against the table the
// fold holds (16.2.4, 16.2.5): the allowed changes applied, and for each ignored one a journal unit. A directory's
// rows are opened either way, so that an ignored change's path can still be named. A push that removes the ref
// empties the fold. A set this device cannot read answers EVS_PREFIX_RULE with nothing folded, and the push is folded
// at a later call.
func (self *evsPrefixJudge) foldPush(ctx context.Context, repo *EvsRepo, refId Id, keys *evsReadKeys, fold *evsPrefixFold, statement *EvsVerifiedStatement, payload *EvsCheckedPayload) ([]*EvsPrefixIgnored, error) {
	push := statement.Statement.Push
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) != 0 {
		fold.Nodes = map[string]*evsPrefixFoldNode{}
		fold.Through = statement.Version
		return nil, nil
	}
	epoch := max(1, push.GetPathEpoch())
	pushId, _ := IdFromBytes(push.GetPushId())
	signerId, _ := IdFromBytes(push.GetSignerSidecarId())
	// judged first, against the fold as it stands, so a refusal folds nothing
	type foldedChange struct {
		change  *EvsCheckedChange
		entry   *protocol.EvsEntryVersion
		ignored bool
	}
	staged := newEvsPrefixFold()
	for key, node := range fold.Nodes {
		copied := *node
		staged.Nodes[key] = &copied
	}
	ignoredUnits := []*EvsPrefixIgnored{}
	for _, change := range payload.Changes {
		folded := &foldedChange{change: change}
		if change.WritesEntry() {
			folded.entry = &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(change.EntryVersion, folded.entry); err != nil {
				return nil, fmt.Errorf("%w: an entry that does not parse", ErrEvsEntryRefused)
			}
		}
		key := evsPrefixFoldKey(epoch, change.TokenPath)
		held := func(token EvsToken) (protocol.EvsEntryKind, bool) {
			child := staged.Nodes[evsPrefixFoldKey(epoch, append(slices.Clone(change.TokenPath), token))]
			if child == nil || !child.Standing {
				return 0, false
			}
			return protocol.EvsEntryKind(child.Kind), true
		}
		ignored, err := self.replayIgnored(ctx, repo, refId, statement.Statement, change, held)
		if err != nil {
			return nil, err
		}
		folded.ignored = ignored
		node := staged.Nodes[key]
		var names [][]byte
		named := len(change.TokenPath) == 0
		if node != nil {
			names, named = node.Names, true
		}
		isDirectory := folded.entry != nil && folded.entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY)
		if isDirectory {
			if !ignored {
				for _, removed := range folded.entry.GetNames().GetRemovedTokens() {
					if child, err := EvsTokenFromBytes(removed); err == nil {
						staged.unstand(evsPrefixFoldKey(epoch, append(slices.Clone(change.TokenPath), child)))
					}
				}
			}
			if named {
				manifest, err := keys.manifest(ctx, epoch)
				if err != nil {
					return nil, err
				}
				pathKey, err := keys.path(ctx, epoch)
				if err != nil {
					return nil, err
				}
				for _, row := range folded.entry.GetNames().GetNames() {
					child, err := EvsTokenFromBytes(row.GetToken())
					if err != nil {
						continue
					}
					name, err := EvsNameOpen(manifest, pathKey, change.TokenPath.Last(), child, row.GetSealedName())
					if err != nil {
						// a row this device cannot open names nothing: its path is journalled unnamed
						continue
					}
					childKey := evsPrefixFoldKey(epoch, append(slices.Clone(change.TokenPath), child))
					standing := !ignored
					if existing := staged.Nodes[childKey]; existing != nil && existing.Standing && ignored {
						// an ignored row over a standing one leaves it as it stood
						continue
					}
					staged.Nodes[childKey] = &evsPrefixFoldNode{Names: append(slices.Clone(names), name), Kind: row.GetKind(), Standing: standing}
				}
			}
		}
		if !ignored {
			if !change.WritesEntry() {
				staged.unstand(key)
			} else if node != nil {
				node.Standing = true
			}
			continue
		}
		unit := &EvsPrefixIgnored{
			RepoId: repo.repoId, RefId: refId, Named: named, CommitVersion: statement.Version,
			PushId: pushId, SignerSidecarId: signerId, AtMs: self.client.clock.Now().UnixMilli(),
			Versionless: folded.entry != nil && folded.entry.GetVersioning() != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT),
		}
		pathNames := make([]string, 0, len(names))
		for _, name := range names {
			pathNames = append(pathNames, string(name))
		}
		unit.Path = strings.Join(pathNames, "/")
		switch {
		case !change.WritesEntry():
			unit.Kind, unit.Version = EvsPrefixIgnoredRemove, change.Change.GetBaseEntryVersion()+1
		case isDirectory:
			unit.Kind, unit.Version = EvsPrefixIgnoredNames, folded.entry.GetVersion()
		case change.Change.GetBaseEntryVersion() == 0:
			unit.Kind, unit.Version = EvsPrefixIgnoredCreate, folded.entry.GetVersion()
		default:
			unit.Kind, unit.Version = EvsPrefixIgnoredWrite, folded.entry.GetVersion()
		}
		ignoredUnits = append(ignoredUnits, unit)
	}
	fold.Nodes = staged.Nodes
	fold.Through = statement.Version
	if 0 < len(ignoredUnits) {
		self.alarm(repo.repoId, refId, signerId, ignoredUnits[0].Path, statement.Version, &pushId, SidecarEvsAlarmDetailIgnored, len(ignoredUnits))
	}
	return ignoredUnits, nil
}

// Whether err is EVS_PREFIX_RULE for a set this device cannot read yet, which a replay waits out.
func evsPrefixUnread(err error) bool {
	var ruleErr *EvsPrefixRuleError
	return errors.As(err, &ruleErr) && (ruleErr.Detail == EvsPrefixDetailPending || ruleErr.Detail == EvsPrefixDetailUpdate)
}
