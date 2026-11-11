//go:build !sidecar_http && !js && !ios && !android && !sdk_mobile_bind

// The desktop sync engine (DESIGN-DETAILS 8.2.7, 8.2.9, 8.5; EVS1-M2-35): a mount follows every git-mode ref of its
// repo it learns of (main; a ref a local push creates; a ref a hint names, whose name its creating push's sealed copy
// gives; a ref a push names as a base or a source, replayed for its objects even before its name is known) and
// replays each into the mount's bare repository, one replay at a time:
//
//	replay(r, upTo)   on a hint, the hourly resync, a push's answer and a start
//	  H = the verified head, read fresh; m = EvsGitRef.version
//	  statements m+1..min(H, upTo) from GET .../log, a page at a time, the verifier walking them (signatures, TIP,
//	  pins, §11.8's refs table)
//	  for u in order:
//	     PATH_EPOCH   the epoch state alone: no object, no tip moves
//	     else         the push's record and parts, the sealed metadata under manifest_g, check(u), objects into
//	                  the sink
//	     every ReplayBatchVersionCount versions, at ObjectSinkChunkByteCount, before a source's replay and at the
//	     end: the sink flushed, then under L_r: the tips log, the tip index, held, born and refs/ur/evs/<r>;
//	     EvsGitRef {version, chain, tip}; settle(r) (evs_local_apply.go)
//	  a refused u     evs_alarm (version_rule, or tamper for a hash); stuck_at = u; nothing past u-1 applied, the local
//	                  ref left alone; every later version is read only for the token paths it changes, which stay
//	                  tainted, until a DELETE, which carries nothing to check: it applies, the local ref is deleted, and
//	                  the push that re-creates the ref must write or remove each tainted token path (8.5)
//
//	check(u)  EvsGitCheckUpdate (evs_git_check.go), its sources replayed first: a source this mount cannot replay to the
//	          version named leaves r waiting with no alarm, and a cycle of waits refuses u; then the objects through the
//	          shared applier (export's, over the mount's store), each commit's tree rebuilt and held to the oid its
//	          commit names; then the changes held to the tree (G4): on a branch exactly 8.2.4's net change from the path
//	          state at E (a deleted ref's last tip, an overlay's base tip for its first push) to tree(peel(new_tip)),
//	          token path by token path in the push's epoch, each file entry's opened mode and oid the tree's, and beside
//	          it a write or removal of every tainted token path; on a tag ref none; a REKEY's entries each the mode and
//	          oid of tree(peel(E)) at its path; and §11.7's per-path version rules on what this replay holds
//
// An own push is replayed from evs like any other and checked like any other. SidecarCommitter refusing a committer
// refuses the version; it is no error to retry. The sync engine never takes P_r, so it never waits on a push.
//
// Desktop legs only. Safe for concurrent use: replays take turns in the mount.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A source a version names that this mount cannot replay to the version named: the dependent ref waits, with no
// alarm of its own (DESIGN-DETAILS 8.5's "a source ref cannot be replayed" row).
var errEvsGitWaitSource = errors.New("evs: a source the ref waits on")

// One mount's sync engine.
type EvsGitSyncEngine struct {
	client   *EvsClient
	repo     *EvsRepo
	mount    *EvsLocalRepo
	settings *EvsSettings
	clock    Clock
	state    *evsLocalState
	// one replay at a time in the mount, nested source replays riding the outer one's turn
	replaySlot chan struct{}

	stateLock sync.Mutex
	// the next applied order, 0 before the records were read
	appliedOrder uint64
	// refs asked a replay, and the channel that wakes the loop
	wakes  map[Id]bool
	wakeup chan struct{}
	// the replayed name index registered for each branch, its remover
	indexes map[Id]func()
	// the receive path's queue, woken for a conflict branch (evs_local_receive.go); nil until one runs
	queueWake func(refId Id)
	// when git gc last ran
	lastGc time.Time
}

// The engine of mount, on client's evs.
func newEvsGitSyncEngine(client *EvsClient, mount *EvsLocalRepo) *EvsGitSyncEngine {
	return &EvsGitSyncEngine{
		client: client, repo: client.Repo(mount.RepoId), mount: mount, settings: client.settings, clock: client.clock,
		state: &evsLocalState{store: client.args.Store, repoId: mount.RepoId}, replaySlot: make(chan struct{}, 1),
		wakes: map[Id]bool{}, wakeup: make(chan struct{}, 1), indexes: map[Id]func(){},
	}
}

// A ref's barrier key, <repo>:<ref>, as evsservice's barriers key a ref.
func (self *EvsGitSyncEngine) barrierKey(refId Id) string {
	return EvsKeyId(self.mount.RepoId) + ":" + EvsKeyId(refId)
}

// Asks a replay of refId, which the loop runs; it never blocks.
func (self *EvsGitSyncEngine) Wake(refId Id) {
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		self.wakes[refId] = true
	}()
	select {
	case self.wakeup <- struct{}{}:
	default:
	}
}

// The refs asked a replay since the last call.
func (self *EvsGitSyncEngine) takeWakes() []Id {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	refIds := make([]Id, 0, len(self.wakes))
	for refId := range self.wakes {
		refIds = append(refIds, refId)
	}
	clear(self.wakes)
	slices.SortFunc(refIds, func(a Id, b Id) int { return bytes.Compare(a[:], b[:]) })
	return refIds
}

// Registers the receive path's queue, woken for each conflict branch settle makes.
func (self *EvsGitSyncEngine) setQueueWake(wake func(refId Id)) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.queueWake = wake
}

// Wakes the queue for refId, when one runs.
func (self *EvsGitSyncEngine) wakeQueue(refId Id) {
	wake := func() func(refId Id) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.queueWake
	}()
	if wake != nil {
		wake(refId)
	}
}

// The refs a start and the resync replay: main, and every git-mode ref with a record.
func (self *EvsGitSyncEngine) followed(ctx context.Context) ([]Id, error) {
	mainId, err := self.repo.resolveRefId(ctx, EvsMainRefName, nil)
	if err != nil {
		return nil, err
	}
	refIds := []Id{mainId}
	refs, err := self.state.gitRefs()
	if err != nil {
		return nil, err
	}
	for _, ref := range refs {
		if ref.Mode == protocol.EvsRefMode_EVS_REF_GIT && ref.RefId != mainId {
			refIds = append(refIds, ref.RefId)
		}
	}
	return refIds, nil
}

// The test hook at the replay loop's start, nil outside tests: what a test replaces the wakes a store's listener
// would bring with.
var evsLocalSyncStartHook func(engine *EvsGitSyncEngine)

// Runs the engine until ctx ends (the externally driven loop): the restart steps, a replay of every followed ref, then
// a replay of each ref a change, a push's answer or a wake names, and of every followed ref each SyncResyncInterval;
// git gc between rounds when its thresholds pass. A replay's failure is logged and tried again at the next wake.
func (self *EvsGitSyncEngine) Run(ctx context.Context) error {
	repoId := self.mount.RepoId
	remove := self.client.AddRepoChangeListener(&repoId, func(change *EvsRepoChange) {
		self.Wake(change.RefId)
	})
	defer remove()
	if err := self.Start(ctx); err != nil {
		self.client.log.Warningf("[evs]the sync engine of repo %s did not start clean: %v", repoId, err)
	}
	if evsLocalSyncStartHook != nil {
		evsLocalSyncStartHook(self)
	}
	wakeAll := func() {
		refIds, err := self.followed(ctx)
		if err != nil {
			self.client.log.Warningf("[evs]repo %s's followed refs: %v", repoId, err)
			return
		}
		for _, refId := range refIds {
			self.Wake(refId)
		}
	}
	wakeAll()
	resync := self.clock.After(self.settings.SyncResyncInterval)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-self.wakeup:
		case <-resync:
			resync = self.clock.After(self.settings.SyncResyncInterval)
			wakeAll()
			continue
		}
		for _, refId := range self.takeWakes() {
			if err := self.Replay(ctx, refId); err != nil && ctx.Err() == nil {
				self.client.log.Warningf("[evs]replay of repo %s ref %s: %v", repoId, refId, err)
			}
		}
		if err := self.maybeGc(ctx); err != nil && ctx.Err() == nil {
			self.client.log.Warningf("[evs]git gc of repo %s: %v", repoId, err)
		}
	}
}

// The engine's restart steps (DESIGN-DETAILS 8.2.9's restart row, the parts that are the sync engine's): stale git
// lock files removed with no git child of this mount alive, settle for each ref whose applied_tip is not its tip, and
// each branch's name index registered. The receive path's steps (RECEIVED entries, resolve) are its own.
func (self *EvsGitSyncEngine) Start(ctx context.Context) error {
	if err := self.mount.removeStaleLocks(); err != nil {
		return err
	}
	refs, err := self.state.gitRefs()
	if err != nil {
		return err
	}
	for _, ref := range refs {
		if ref.Mode != protocol.EvsRefMode_EVS_REF_GIT {
			continue
		}
		self.registerIndex(ref)
		if evsOidEqual(ref.AppliedTip, ref.Tip) {
			continue
		}
		if err := self.settle(ctx, ref.RefId); err != nil {
			return err
		}
	}
	return nil
}

// Settles one ref under its L_r, then queues a conflict branch it made.
func (self *EvsGitSyncEngine) settle(ctx context.Context, refId Id) error {
	release, err := self.mount.locks.LockApply(ctx, refId)
	if err != nil {
		return err
	}
	settled, err := func() (*evsGitSettled, error) {
		defer release()
		ref, err := self.state.gitRef(refId)
		if err != nil {
			return nil, err
		}
		return self.settleWithLock(ctx, ref)
	}()
	if err != nil {
		return err
	}
	return self.queueConflict(ctx, settled)
}

// Deletes every *.lock under the bare repository's refs/ and its packed-refs.lock (DESIGN-DETAILS 8.2.11): what a git
// killed mid-update leaves, which would refuse every later update of that ref.
func (self *EvsLocalRepo) removeStaleLocks() error {
	if err := os.Remove(filepath.Join(self.BareDir, "packed-refs.lock")); err != nil && !os.IsNotExist(err) {
		return err
	}
	return filepath.WalkDir(filepath.Join(self.BareDir, "refs"), func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".lock") {
			return os.Remove(path)
		}
		return nil
	})
}

// Takes the mount's replay turn, waiting for the replay that holds it.
func (self *EvsGitSyncEngine) takeReplaySlot(ctx context.Context) (func(), error) {
	select {
	case self.replaySlot <- struct{}{}:
		return func() { <-self.replaySlot }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Replays refId to its head and settles it (EvsGitSync's Replay): see the file header.
func (self *EvsGitSyncEngine) Replay(ctx context.Context, refId Id) error {
	release, err := self.takeReplaySlot(ctx)
	if err != nil {
		return err
	}
	defer release()
	_, err = self.replayWithSlot(ctx, refId, 0, map[Id]bool{})
	return err
}

// One ref's replay to upTo, 0 for its head, inside the mount's replay turn: replaying holds the refs whose replays
// enclose this one, so a source naming one of them back is a cycle unless that ref has passed the version named.
func (self *EvsGitSyncEngine) replayWithSlot(ctx context.Context, refId Id, upTo uint64, replaying map[Id]bool) (*EvsGitRef, error) {
	ref, err := self.loadRef(ctx, refId)
	if err != nil {
		return nil, err
	}
	if ref.Mode == protocol.EvsRefMode_EVS_REF_FILE {
		return ref, nil
	}
	head, err := self.repo.pinnedHead(ctx, refId)
	if err != nil {
		return nil, err
	}
	if head.Version == 0 {
		return ref, nil
	}
	if protocol.EvsRefMode(head.Head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_GIT {
		// a file-mode ref has no git ref: recorded so it is not asked again
		ref.Mode = protocol.EvsRefMode_EVS_REF_FILE
		return ref, self.writeRef(ctx, ref)
	}
	if head.Version < ref.Version {
		return nil, fmt.Errorf("%w: evs's head of ref %s is below the version this mount applied (a re-seed's lowering is not built)", ErrEvsHeadForked, refId)
	}
	through := head.Version
	if upTo != 0 && upTo < through {
		through = upTo
	}
	if through <= ref.Version {
		return ref, self.reachedHead(ctx, ref, head)
	}
	replaying[refId] = true
	defer delete(replaying, refId)
	store, err := newEvsLocalReplayStore(ctx, self.mount, self.settings.ObjectSinkChunkByteCount)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	run := &evsGitReplayRun{
		engine: self, ref: ref.clone(), head: head, store: store, replayer: newEvsGitReplayer(self.repo, store),
		keys: newEvsReadKeys(self.repo), paths: NewEvsReplayPathsOfMode(ref.Version, protocol.EvsRefMode_EVS_REF_GIT),
		replaying: replaying,
	}
	if run.ref.WaitingSource != nil {
		// tried again now: a wait still owed is recorded again below
		run.ref.WaitingSource, run.ref.WaitingVersion, run.dirty = nil, 0, true
	}
	err = run.replay(ctx, through)
	if errors.Is(err, errEvsGitWaitSource) {
		// what applied before the wait stands; the ref waits, and its next wake tries again
		if flushErr := run.flush(ctx); flushErr != nil {
			return nil, flushErr
		}
		return run.ref, nil
	}
	if err != nil {
		// what applied before the failure stands, so the next replay goes on from it
		if flushErr := run.flush(ctx); flushErr != nil {
			return nil, errors.Join(err, flushErr)
		}
		return nil, err
	}
	if run.ref.Version == head.Version && run.ref.Chain == head.Chain {
		// the walk reached the head: pinned before what it backs is shown
		if err := self.client.verifier.Pin(head); err != nil {
			return nil, err
		}
		run.ref.PathEpoch = head.Head.GetPathEpoch()
		run.reachedHead = true
		run.dirty = true
	}
	if err := run.flush(ctx); err != nil {
		return nil, err
	}
	return run.ref, nil
}

// A ref already at the head read: its epoch state and the born journal's drop recorded when the head lists no
// source.
func (self *EvsGitSyncEngine) reachedHead(ctx context.Context, ref *EvsGitRef, head *EvsVerifiedHead) error {
	if ref.Version != head.Version {
		return nil
	}
	if evsSamePathEpoch(ref.PathEpoch, head.Head.GetPathEpoch()) {
		return nil
	}
	release, err := self.mount.locks.LockApply(ctx, ref.RefId)
	if err != nil {
		return err
	}
	defer release()
	stored, err := self.state.gitRef(ref.RefId)
	if err != nil {
		return err
	}
	stored.PathEpoch = head.Head.GetPathEpoch()
	if len(stored.PathEpoch.GetSources()) == 0 {
		if err := self.state.writeBorn(ref.RefId, map[string]uint64{}); err != nil {
			return err
		}
	}
	return self.state.writeGitRef(stored)
}

// The ref's record, read under its L_r.
func (self *EvsGitSyncEngine) loadRef(ctx context.Context, refId Id) (*EvsGitRef, error) {
	release, err := self.mount.locks.LockApply(ctx, refId)
	if err != nil {
		return nil, err
	}
	defer release()
	return self.state.gitRef(refId)
}

// Writes the ref's record under its L_r.
func (self *EvsGitSyncEngine) writeRef(ctx context.Context, ref *EvsGitRef) error {
	release, err := self.mount.locks.LockApply(ctx, ref.RefId)
	if err != nil {
		return err
	}
	defer release()
	return self.state.writeGitRef(ref)
}

// The next applied order, past every record's.
func (self *EvsGitSyncEngine) nextAppliedOrder() (uint64, error) {
	self.stateLock.Lock()
	loaded := self.appliedOrder != 0
	self.stateLock.Unlock()
	if !loaded {
		refs, err := self.state.gitRefs()
		if err != nil {
			return 0, err
		}
		highest := uint64(0)
		for _, ref := range refs {
			highest = max(highest, ref.AppliedOrder)
		}
		self.stateLock.Lock()
		self.appliedOrder = max(self.appliedOrder, highest+1)
		self.stateLock.Unlock()
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	order := self.appliedOrder
	self.appliedOrder += 1
	return order, nil
}

// One replay of one ref: its working record, the head it replays to, and what it applied since its last flush.
type evsGitReplayRun struct {
	engine   *EvsGitSyncEngine
	ref      *EvsGitRef
	head     *EvsVerifiedHead
	store    *evsLocalReplayStore
	replayer *evsGitExport
	keys     *evsReadKeys
	paths    *EvsReplayPaths
	// the refs whose replays enclose this one
	replaying map[Id]bool
	// since the last flush: the tips log's entries and the tip index's rows to add, the held set and born journal
	// once loaded and changed, the versions passed, and whether anything is owed a flush
	tips        []*evsGitTipEntry
	index       []*evsGitTipIndexRow
	held        evsGitHeldSet
	heldDirty   bool
	born        map[string]uint64
	bornDirty   bool
	applied     int
	dirty       bool
	reachedHead bool
}

// The statements through version through, a page at a time, each applied.
func (self *evsGitReplayRun) replay(ctx context.Context, through uint64) error {
	engine := self.engine
	client := engine.client
	pageCount := uint64(max(1, engine.settings.HistoryVersionCount))
	for self.ref.Version < through {
		last := min(through, self.ref.Version+pageCount)
		statements, err := client.readLog(ctx, engine.mount.RepoId, self.ref.RefId, self.ref.Version+1, last)
		if err != nil {
			return err
		}
		walked, err := client.verifier.walk(engine.mount.RepoId, self.ref.RefId, self.ref.Version, self.ref.Chain, statements, last)
		if err != nil {
			return err
		}
		if err := client.verifier.checkPinOnWalk(engine.mount.RepoId, self.ref.RefId, walked); err != nil {
			return err
		}
		for _, statement := range walked {
			if err := self.apply(ctx, statement); err != nil {
				return err
			}
			if engine.settings.ReplayBatchVersionCount <= self.applied {
				if err := self.flush(ctx); err != nil {
					return err
				}
			}
			if err := self.store.sink.FlushIfFull(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}

// Whether err is a version's own fault, which stops its ref, rather than the replay's.
func evsLocalRefusesVersion(err error) bool {
	return evsExportRefusesVersion(err) || errors.Is(err, ErrEvsVersionRule)
}

// Marks statement passed.
func (self *evsGitReplayRun) pass(statement *EvsVerifiedStatement) {
	self.ref.Version, self.ref.Chain = statement.Version, statement.Chain
	self.applied += 1
	self.dirty = true
}

// One version: see the file header's for-u rows.
func (self *evsGitReplayRun) apply(ctx context.Context, statement *EvsVerifiedStatement) error {
	engine := self.engine
	ref := self.ref
	push := statement.Statement.Push
	flags := push.GetFlags()
	ref.Kind = protocol.EvsRefKind(push.GetRefKind())
	if owner, err := IdFromBytes(push.GetOwnerSidecarId()); err == nil && owner != (Id{}) {
		ref.OwnerSidecarId = &owner
	}
	const (
		pathEpochFlag = uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH)
		deleteFlag    = uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE)
		forceFlag     = uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE)
	)
	if flags&pathEpochFlag != 0 {
		// the epoch state's alone: no object, and no tip moves
		self.pass(statement)
		return nil
	}
	payload, err := engine.repo.pushContent(ctx, self.head, statement)
	if err != nil {
		if evsLocalRefusesVersion(err) {
			return self.refuse(statement, nil, err)
		}
		return err
	}
	if ref.StuckAt != 0 && flags != deleteFlag {
		// a stopped ref reads past a refused version only for the token paths it changes (8.5)
		self.taint(payload, push)
		self.pass(statement)
		return nil
	}
	manifest, err := self.keys.manifest(ctx, push.GetGeneration())
	if err != nil {
		return err
	}
	metadata, err := EvsOpenMetadata(manifest, payload.SealedMetadata)
	if err != nil {
		engine.client.alarm(engine.mount.RepoId, ref.RefId, SidecarEvsAlarmTamper, "", evsSignerOf(statement.Statement.Bytes))
		return self.refuse(statement, payload, err)
	}
	creating := ref.Tip == nil && flags&deleteFlag == 0
	var sectionRefName []byte
	if creating && len(payload.RefName) != 0 {
		sectionRefName, err = EvsOpenRefName(manifest, ref.RefId, payload.RefName)
		if err != nil {
			engine.client.alarm(engine.mount.RepoId, ref.RefId, SidecarEvsAlarmTamper, "", evsSignerOf(statement.Statement.Bytes))
			return self.refuse(statement, payload, err)
		}
	}
	headBase := self.head.Head.GetBase()
	if creating && headBase != nil {
		// an overlay's readers hold what its base tip reaches (G2): the base ref first, as a source is
		if err := self.dependOn(ctx, []*protocol.EvsOverlay{headBase}); err != nil {
			if evsLocalRefusesVersion(err) {
				return self.refuse(statement, payload, err)
			}
			return err
		}
	}
	if err := self.store.learnReachable(ctx, evsGitMetadataCandidates(metadata)); err != nil {
		return err
	}
	checked, err := EvsGitCheckUpdate(ctx, &EvsGitUpdateArgs{
		RepoId: engine.mount.RepoId, RefId: ref.RefId, RefName: ref.Name, Statement: statement.Statement, Payload: payload,
		Metadata: metadata, PriorTip: ref.Tip, Creating: creating, SectionRefName: sectionRefName, HeadBase: headBase,
		RefIdOf: func(refName []byte) (Id, error) {
			return engine.repo.resolveRefId(ctx, refName, nil)
		},
		ReplaySources: self.dependOn,
		Held: func(oid EvsGitOid) bool {
			return self.store.heldCommit(ctx, oid)
		},
		Committer: engine.committer,
		Import: func(ctx context.Context, signed []byte, push *protocol.EvsPush) (*protocol.EvsImport, error) {
			return engine.client.verifier.verifyImport(signed, engine.mount.RepoId, push)
		},
		Parents: self.parents,
	})
	if err != nil {
		if evsLocalRefusesVersion(err) {
			return self.refuse(statement, payload, err)
		}
		return err
	}
	switch checked.Shape {
	case protocol.EvsGitShape_EVS_GIT_DELETE:
		if ref.StuckAt != 0 {
			ref.Stopped[len(ref.Stopped)-1][1] = statement.Version
			ref.StuckAt = 0
		}
		if ref.Tip != nil {
			ref.LastTip = ref.Tip
		}
		ref.Tip, ref.Peeled, ref.Deleted, ref.TipVersion = nil, nil, true, statement.Version
		self.tips = append(self.tips, &evsGitTipEntry{Version: statement.Version, Flags: flags})
		self.pass(statement)
		return nil
	case protocol.EvsGitShape_EVS_GIT_REKEY:
		written, err := self.replayer.applyUpdate(ctx, self.head, statement, payload, metadata, checked)
		if err == nil {
			err = self.checkRekey(ctx, push, payload, written)
		}
		if err != nil {
			if evsLocalRefusesVersion(err) {
				return self.refuse(statement, payload, err)
			}
			return err
		}
		self.pass(statement)
		return nil
	}
	written, err := self.replayer.applyUpdate(ctx, self.head, statement, payload, metadata, checked)
	if err == nil {
		err = self.checkChanges(ctx, push, payload, metadata, checked, written, creating)
	}
	if err == nil {
		entries := map[string][]byte{}
		for _, change := range payload.Changes {
			if change.WritesEntry() {
				entries[change.TokenPath.KeyString()] = change.EntryVersion
			}
		}
		err = self.paths.Apply(statement, payload.Changes, entries)
	}
	if err != nil {
		if evsLocalRefusesVersion(err) {
			return self.refuse(statement, payload, err)
		}
		return err
	}
	if creating {
		ref.Base = metadata.GetBase()
		if name := metadata.GetRefName(); 0 < len(name) {
			ref.Name = bytes.Clone(name)
		}
	}
	// the version's commits are held from here on, before the flush moves refs/ur/evs/ to them: the sink skips a commit
	// the repository holds already (a client's push, a restored state), which no evs tip reaches yet
	for _, commit := range checked.Commits {
		self.store.reachable[commit.Oid] = true
	}
	ref.Tip, ref.Peeled, ref.TipVersion, ref.Deleted, ref.Tainted = checked.NewTip, checked.Peeled, statement.Version, false, nil
	self.tips = append(self.tips, &evsGitTipEntry{Version: statement.Version, Tip: evsOidText(checked.NewTip), Flags: flags})
	self.index = append(self.index, &evsGitTipIndexRow{Oid: evsOidText(checked.Peeled), RefId: hex.EncodeToString(ref.RefId[:]), Version: statement.Version})
	self.pass(statement)
	if flags&forceFlag != 0 {
		// a FORCE moves evs's tip back: refs/ur/evs/ moves now, and what it reached is learned again
		if err := self.flush(ctx); err != nil {
			return err
		}
		self.store.forgetReachable()
	}
	return nil
}

// Every commit oid a version's check asks held of: each carried commit, its parents, the new tip and the last tag's
// object, so one rev-list answers them.
func evsGitMetadataCandidates(metadata *protocol.EvsSealedMetadata) []EvsGitOid {
	oids := []EvsGitOid{}
	for _, sealed := range metadata.GetCommits() {
		oids = append(oids, evsGitObjectOid(evsGitCommitKind, sealed.GetObject()))
		if _, parents, err := EvsGitCommitGraph(sealed.GetObject()); err == nil {
			oids = append(oids, parents...)
		}
	}
	git := metadata.GetGit()
	if len(git.GetNewTip()) == len(EvsGitOid{}) {
		oids = append(oids, EvsGitOid(git.GetNewTip()))
	}
	if tags := git.GetTags(); 0 < len(tags) {
		if tag, err := EvsGitTagDecode(tags[len(tags)-1]); err == nil {
			oids = append(oids, tag.ObjectOid)
		}
	}
	return oids
}

// A refused version: alarmed, the ref stopped at the version before it, its token paths tainted, and passed (8.5).
func (self *evsGitReplayRun) refuse(statement *EvsVerifiedStatement, payload *EvsCheckedPayload, reason error) error {
	engine := self.engine
	ref := self.ref
	engine.client.alarm(engine.mount.RepoId, ref.RefId, SidecarEvsAlarmVersionRule, "", evsSignerOf(statement.Statement.Bytes))
	// the reason names a rule, never a path or name (I-13)
	engine.client.log.Warningf("[evs]ref %s of repo %s refused at version %d: %v", ref.RefId, engine.mount.RepoId, statement.Version, reason)
	if ref.StuckAt == 0 {
		ref.StuckAt = statement.Version
		ref.Stopped = append(ref.Stopped, [2]uint64{statement.Version, 0})
	}
	if payload != nil {
		self.taint(payload, statement.Statement.Push)
	}
	self.pass(statement)
	return nil
}

// Notes the token paths a stopped version changes as tainted.
func (self *evsGitReplayRun) taint(payload *EvsCheckedPayload, push *protocol.EvsPush) {
	for _, change := range payload.Changes {
		tainted := EvsTaintedPath{Epoch: push.GetPathEpoch(), Key: change.TokenPath.KeyString()}
		if !slices.Contains(self.ref.Tainted, tainted) {
			self.ref.Tainted = append(self.ref.Tainted, tainted)
		}
	}
}

// Replays each named ref to its version first, this replay flushed before, so the nested replays and this one read
// one store's state: a ref that cannot reach the version leaves this one waiting (errEvsGitWaitSource), and one
// already enclosing this replay is held only past the version named, else a cycle refuses.
func (self *evsGitReplayRun) dependOn(ctx context.Context, sources []*protocol.EvsOverlay) error {
	if err := self.flush(ctx); err != nil {
		return err
	}
	engine := self.engine
	for _, source := range sources {
		refId, err := IdFromBytes(source.GetRefId())
		if err != nil {
			return fmt.Errorf("%w: a source that is no ref", ErrEvsGitUpdateRefused)
		}
		version := source.GetVersion()
		var sourceRef *EvsGitRef
		if self.replaying[refId] {
			sourceRef, err = engine.loadRef(ctx, refId)
			if err != nil {
				return err
			}
			if sourceRef.Version < version {
				return fmt.Errorf("%w: a cycle of sources", ErrEvsGitUpdateRefused)
			}
		} else {
			sourceRef, err = engine.replayWithSlot(ctx, refId, version, self.replaying)
			if err != nil {
				return err
			}
		}
		if sourceRef.Mode != protocol.EvsRefMode_EVS_REF_GIT {
			return fmt.Errorf("%w: a source that is no git-mode ref", ErrEvsGitUpdateRefused)
		}
		if sourceRef.Version < version || sourceRef.WaitingSource != nil {
			self.ref.WaitingSource, self.ref.WaitingVersion, self.dirty = &refId, version, true
			return errEvsGitWaitSource
		}
		tip, applied, err := engine.state.tipAt(sourceRef, version)
		if err != nil {
			return err
		}
		if !applied {
			// stopped at a refused version: the source cannot be replayed there, so this ref waits
			self.ref.WaitingSource, self.ref.WaitingVersion, self.dirty = &refId, version, true
			return errEvsGitWaitSource
		}
		if tip == nil {
			return fmt.Errorf("%w: a source with no tip at its version", ErrEvsGitUpdateRefused)
		}
	}
	// the sources' tips moved refs/ur/evs/: what they reach is learned again
	self.store.forgetReachable()
	return nil
}

// A held commit's parents, read back from the bare repository.
func (self *evsGitReplayRun) parents(ctx context.Context, oid EvsGitOid) ([]EvsGitOid, error) {
	kind, object, err := self.store.ReadGitObject(ctx, oid)
	if err != nil {
		return nil, err
	}
	if kind != evsGitCommitKind {
		return nil, ErrEvsGitObjectMissing
	}
	_, parentOids, err := EvsGitCommitGraph(object)
	return parentOids, err
}

// owner decision 81's rule for a new commit's committer: the client's check, else the push's own client alone.
func (self *EvsGitSyncEngine) committer(ctx context.Context, committer *EvsGitIdent, push *protocol.EvsPush) error {
	identityKey, err := self.client.verifier.signerIdentityKey(push)
	if err != nil {
		return err
	}
	clientId, err := IdFromBytes(push.GetClientId())
	if err != nil {
		return err
	}
	signerId, err := IdFromBytes(push.GetSignerSidecarId())
	if err != nil {
		return err
	}
	claim := &SidecarCommitterClaim{
		CommitterEmail: string(committer.Email), PushClientId: clientId, SignerSidecarId: signerId,
		SignerIdentityPublicKey: identityKey,
	}
	if check := self.client.args.Committer; check != nil {
		return check(ctx, claim)
	}
	return NewSidecarCommitter(&SidecarCommitterArgs{NetworkId: self.client.args.NetworkId}).Check(ctx, claim)
}

// The tree a commit names.
func (self *evsGitReplayRun) treeOf(ctx context.Context, commit EvsGitOid) (EvsGitOid, error) {
	return evsGitTreeOf(ctx, self.store, commit)
}

// The tree an UPDATE's net change starts from: the ref's tip's, a re-creation's last tip's, an overlay's base tip's
// for its first push, else none.
func (self *evsGitReplayRun) stoodTree(ctx context.Context, metadata *protocol.EvsSealedMetadata, creating bool) (*EvsGitOid, error) {
	ref := self.ref
	var commit *EvsGitOid
	switch {
	case !creating:
		commit = ref.Peeled
	case ref.Deleted && ref.LastTip != nil:
		peeled, err := self.engine.mount.peel(ctx, *ref.LastTip)
		if err != nil {
			return nil, err
		}
		commit = &peeled
	case metadata.GetBase() != nil:
		baseRefId, err := IdFromBytes(metadata.GetBase().GetRefId())
		if err != nil {
			return nil, fmt.Errorf("%w: an overlay base's ref id", ErrEvsGitUpdateRefused)
		}
		baseRef, err := self.engine.loadRef(ctx, baseRefId)
		if err != nil {
			return nil, err
		}
		tip, applied, err := self.engine.state.tipAt(baseRef, metadata.GetBase().GetVersion())
		if err != nil {
			return nil, err
		}
		if !applied || tip == nil {
			return nil, fmt.Errorf("%w: an overlay whose base version has no tip", ErrEvsGitUpdateRefused)
		}
		peeled, err := self.engine.mount.peel(ctx, *tip)
		if err != nil {
			return nil, err
		}
		commit = &peeled
	}
	if commit == nil {
		return nil, nil
	}
	tree, err := self.treeOf(ctx, *commit)
	if err != nil {
		return nil, err
	}
	return &tree, nil
}

// The overlay's held set, read once a run.
func (self *evsGitReplayRun) heldSet() (evsGitHeldSet, error) {
	if self.held == nil {
		held, err := self.engine.state.held(self.ref.RefId)
		if err != nil {
			return nil, err
		}
		self.held = held
	}
	return self.held, nil
}

// The ref's born journal, read once a run.
func (self *evsGitReplayRun) bornJournal() (map[string]uint64, error) {
	if self.born == nil {
		born, err := self.engine.state.born(self.ref.RefId)
		if err != nil {
			return nil, err
		}
		self.born = born
	}
	return self.born, nil
}

// G4 on an UPDATE (see the file header's check row): the push's changes exactly the net change, each file entry's mode
// and oid the tree's, every tainted token path written or removed; then an overlay's held set and the born journal
// take what the version changed.
func (self *evsGitReplayRun) checkChanges(ctx context.Context, push *protocol.EvsPush, payload *EvsCheckedPayload, metadata *protocol.EvsSealedMetadata, checked *EvsGitCheckedUpdate, written map[string]*evsGitWrittenFile, creating bool) error {
	refused := func(format string, values ...any) error {
		return fmt.Errorf("%w: %s", ErrEvsGitUpdateRefused, fmt.Sprintf(format, values...))
	}
	ref := self.ref
	tagRef := ref.tag() || bytes.HasPrefix(metadata.GetRefName(), []byte(evsGitTagRefPrefix))
	if tagRef {
		if len(payload.Changes) != 0 {
			return refused("a tag ref's push with a change")
		}
		return nil
	}
	base := ref.Base
	if creating {
		base = metadata.GetBase()
	}
	overlay := base != nil
	firstOverlayPush := overlay && creating && !ref.Deleted
	stood, err := self.stoodTree(ctx, metadata, creating)
	if err != nil {
		return err
	}
	next, err := self.treeOf(ctx, *checked.Peeled)
	if err != nil {
		return err
	}
	net, err := evsGitNetChange(ctx, self.store, stood, next)
	if err != nil {
		return err
	}
	var held evsGitHeldSet
	if overlay {
		if held, err = self.heldSet(); err != nil {
			return err
		}
	}
	epoch := push.GetPathEpoch()
	expected := map[string]*EvsGitPathChange{}
	for _, change := range net {
		if overlay && change.removes() {
			kind := held[change.Path]
			if firstOverlayPush || (kind != evsGitHeldFile && kind != evsGitHeldDirectory) {
				// an inherited path: its parent's table drops it (8.2.4's overlay row)
				continue
			}
		}
		names, err := evsPathNames(change.Path)
		if err != nil && change.Path != "" {
			return err
		}
		tokenPath, err := self.keys.tokenPathIn(ctx, names, epoch)
		if err != nil {
			return err
		}
		expected[tokenPath.KeyString()] = change
	}
	tainted := map[string]bool{}
	for _, path := range ref.Tainted {
		if path.Epoch != epoch {
			// a taint of another epoch cannot be matched here: the re-creation fails closed (incomplete)
			return refused("a tainted path of another path epoch")
		}
		tainted[path.Key] = true
	}
	for _, change := range payload.Changes {
		key := change.TokenPath.KeyString()
		pathChange := expected[key]
		if pathChange == nil {
			if tainted[key] {
				delete(tainted, key)
				continue
			}
			return refused("a change that is not the tree's")
		}
		if pathChange.removes() == change.WritesEntry() {
			return refused("a change whose write or removal is not the tree's")
		}
		if change.WritesEntry() {
			directory := evsEntryVersionIsDirectory(change.EntryVersion)
			if directory != (pathChange.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
				return refused("a change of a kind that is not the tree's")
			}
			if !directory {
				file := written[key]
				if file == nil || file.mode != pathChange.Mode || file.oid != pathChange.Oid {
					return refused("a file entry whose mode or oid is not the tree's")
				}
			}
		}
		delete(expected, key)
		delete(tainted, key)
	}
	if len(expected) != 0 {
		return refused("a path of the tree's change the push lacks")
	}
	if len(tainted) != 0 {
		return refused("a tainted token path the re-creating push neither writes nor removes")
	}
	// what the version changed: the held set and the born journal
	born, err := self.bornJournal()
	if err != nil {
		return err
	}
	for _, change := range net {
		if overlay && (change.removes() && (firstOverlayPush || (held[change.Path] != evsGitHeldFile && held[change.Path] != evsGitHeldDirectory))) {
			continue
		}
		switch {
		case change.removes():
			if overlay {
				held[change.Path] = evsGitHeldRemoved
			}
			for path := range born {
				if path == change.Path || strings.HasPrefix(path, change.Path+"/") || change.Path == "" {
					delete(born, path)
				}
			}
		default:
			if overlay {
				held[change.Path] = evsGitHeldFile
				if change.Kind == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY {
					held[change.Path] = evsGitHeldDirectory
				}
			}
			if change.Stood != change.Kind && change.Path != "" {
				born[change.Path] = epoch
			}
		}
	}
	self.heldDirty = self.heldDirty || overlay
	self.bornDirty = true
	return nil
}

// A REKEY's entries (8.2.10): each a file of tree(peel(E)) re-checkpointed with its mode and oid unchanged.
func (self *evsGitReplayRun) checkRekey(ctx context.Context, push *protocol.EvsPush, payload *EvsCheckedPayload, written map[string]*evsGitWrittenFile) error {
	refused := func(what string) error {
		return fmt.Errorf("%w: %s", ErrEvsGitUpdateRefused, what)
	}
	if self.ref.Peeled == nil {
		return refused("a REKEY of a ref with no tip")
	}
	tree, err := self.treeOf(ctx, *self.ref.Peeled)
	if err != nil {
		return err
	}
	files, err := self.engine.mount.treeFiles(ctx, tree)
	if err != nil {
		return err
	}
	byKey := map[string]*evsGitTreeFile{}
	for _, file := range files {
		tokenPath, err := self.keys.tokenPathIn(ctx, file.names, push.GetPathEpoch())
		if err != nil {
			return err
		}
		byKey[tokenPath.KeyString()] = file
	}
	for _, change := range payload.Changes {
		key := change.TokenPath.KeyString()
		file, stands := byKey[key]
		got := written[key]
		if !stands || got == nil || got.mode != file.mode || got.oid != file.oid {
			return refused("a REKEY entry that changes a mode or an oid, or names no file of the tree")
		}
	}
	return nil
}

// One file of a tree, as git ls-tree -r names it.
type evsGitTreeFile struct {
	names [][]byte
	mode  uint32
	oid   EvsGitOid
}

// Every file of tree, with its canon mode, by git ls-tree -r -z.
func (self *EvsLocalRepo) treeFiles(ctx context.Context, tree EvsGitOid) ([]*evsGitTreeFile, error) {
	out, err := self.Git(ctx, "ls-tree", "-r", "-z", "--full-tree", hex.EncodeToString(tree[:]))
	if err != nil {
		return nil, err
	}
	files := []*evsGitTreeFile{}
	for _, line := range bytes.Split(out, []byte{0}) {
		if len(line) == 0 {
			continue
		}
		meta, path, found := bytes.Cut(line, []byte{'\t'})
		fields := strings.Fields(string(meta))
		if !found || len(fields) != 3 {
			return nil, fmt.Errorf("%w: ls-tree answered no entry", ErrEvsGitFailed)
		}
		mode, err := strconv.ParseUint(fields[0], 8, 32)
		if err != nil {
			return nil, fmt.Errorf("%w: ls-tree answered no mode", ErrEvsGitFailed)
		}
		oid, err := evsGitOidDecodeHex([]byte(fields[2]))
		if err != nil {
			return nil, err
		}
		files = append(files, &evsGitTreeFile{names: bytes.Split(path, []byte{'/'}), mode: EvsGitCanonMode(uint32(mode)), oid: oid})
	}
	return files, nil
}

// Writes what the run applied since its last flush (the file header's every-batch row): the sink flushed, then under
// L_r the tips log, the tip index, held, born and refs/ur/evs/<r>, the record, and settle; a conflict branch settle
// made is queued after.
func (self *evsGitReplayRun) flush(ctx context.Context) error {
	if !self.dirty {
		return nil
	}
	engine := self.engine
	mount := engine.mount
	ref := self.ref
	if err := self.store.Flush(ctx); err != nil {
		return err
	}
	releaseUpkeep, err := mount.locks.LockUpkeepShared(ctx)
	if err != nil {
		return err
	}
	defer releaseUpkeep()
	order, err := engine.nextAppliedOrder()
	if err != nil {
		return err
	}
	release, err := mount.locks.LockApply(ctx, ref.RefId)
	if err != nil {
		return err
	}
	settled, err := func() (*evsGitSettled, error) {
		defer release()
		state := engine.state
		if 0 < len(self.tips) {
			if err := state.appendTips(ref.RefId, self.tips); err != nil {
				return nil, err
			}
		}
		if 0 < len(self.index) {
			if err := state.addTipIndexRows(self.index); err != nil {
				return nil, err
			}
		}
		if self.heldDirty {
			if err := state.writeHeld(ref.RefId, self.held); err != nil {
				return nil, err
			}
		}
		if self.reachedHead && len(ref.PathEpoch.GetSources()) == 0 {
			// the head lists no source: every path stood before, and the journal empties (8.2.10)
			self.born, self.bornDirty = map[string]uint64{}, true
		}
		if self.bornDirty {
			if err := state.writeBorn(ref.RefId, self.born); err != nil {
				return nil, err
			}
		}
		evsTip := ref.Tip
		if evsTip == nil {
			evsTip = ref.LastTip
		}
		if evsTip != nil {
			if err := mount.updateRefs(ctx, []string{"update " + evsLocalEvsRefPrefix + evsUrlId(ref.RefId) + " " + evsTip.String()}); err != nil {
				return nil, err
			}
		}
		// a receive may have settled since the run began, under this lock: its applied_tip stands
		stored, err := state.gitRef(ref.RefId)
		if err != nil {
			return nil, err
		}
		ref.AppliedTip, ref.SettleStopped = stored.AppliedTip, stored.SettleStopped
		ref.AppliedOrder = order
		if err := state.writeGitRef(ref); err != nil {
			return nil, err
		}
		testHookBarrier(evsLocalBarrierApplyState, engine.barrierKey(ref.RefId))
		if err := evsLocalKilled(evsLocalApplyKillHook, "state"); err != nil {
			return nil, err
		}
		return engine.settleWithLock(ctx, ref)
	}()
	if err != nil {
		return err
	}
	self.tips, self.index, self.heldDirty, self.bornDirty, self.applied, self.dirty = nil, nil, false, false, 0, false
	if err := engine.queueConflict(ctx, settled); err != nil {
		return err
	}
	engine.registerIndex(ref)
	return nil
}

// Runs git gc on the mount, M held exclusively, at most once each GcMinInterval, once its loose objects or packs
// pass their thresholds (DESIGN-DETAILS 8.2.11).
func (self *EvsGitSyncEngine) maybeGc(ctx context.Context) error {
	now := self.clock.Now()
	due := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.lastGc.IsZero() || self.settings.GcMinInterval <= now.Sub(self.lastGc)
	}()
	if !due {
		return nil
	}
	out, err := self.mount.Git(ctx, "count-objects", "-v")
	if err != nil {
		return err
	}
	counts := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		name, value, found := strings.Cut(line, ": ")
		if !found {
			continue
		}
		if count, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
			counts[name] = count
		}
	}
	if counts["count"] <= self.settings.GcLooseObjectCount && counts["packs"] <= self.settings.GcPackCount {
		return nil
	}
	release, err := self.mount.locks.LockUpkeepExclusive(ctx)
	if err != nil {
		return err
	}
	defer release()
	prune := "--prune=" + strconv.FormatInt(int64(self.settings.GcPruneAge/time.Second), 10) + ".seconds.ago"
	if _, err := self.mount.Git(ctx, "gc", "--quiet", prune); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.lastGc = now
	return nil
}

// EvsGitSourceState and EvsGitSync, which publish, the import and the receive path read (evs_local_commits.go,
// evs_local_import.go). Each reads the records under the refs' apply locks.

// The ref whose refs/ur/evs/ tip it is, at the version that set its tip: false for a ref with no tip.
func (self *EvsGitSyncEngine) SourceRef(ctx context.Context, refId Id) (*EvsGitSourceRef, bool, error) {
	ref, err := self.loadRef(ctx, refId)
	if err != nil {
		return nil, false, err
	}
	source := evsGitSourceRefOf(ref)
	return source, source != nil, nil
}

// A ref as a source, nil for one with no tip or no name.
func evsGitSourceRefOf(ref *EvsGitRef) *EvsGitSourceRef {
	if ref.Mode != protocol.EvsRefMode_EVS_REF_GIT || ref.Tip == nil || ref.TipVersion == 0 {
		return nil
	}
	return &EvsGitSourceRef{
		RefId: ref.RefId, Kind: ref.Kind, Version: ref.TipVersion, Tip: *ref.Tip, AppliedOrder: ref.AppliedOrder,
		Tag: ref.tag(),
	}
}

// Every git-mode ref with a tip, at the version that set it.
func (self *EvsGitSyncEngine) Refs(ctx context.Context) ([]*EvsGitSourceRef, error) {
	refs, err := self.state.gitRefs()
	if err != nil {
		return nil, err
	}
	sources := []*EvsGitSourceRef{}
	for _, ref := range refs {
		if source := evsGitSourceRefOf(ref); source != nil {
			sources = append(sources, source)
		}
	}
	return sources, nil
}

// Every ref version whose tip peeled to oid, from the tip index.
func (self *EvsGitSyncEngine) TipsOf(ctx context.Context, oid EvsGitOid) ([]*EvsGitSourceRef, error) {
	rows, err := self.state.tipIndexRows(oid)
	if err != nil {
		return nil, err
	}
	found := []*EvsGitSourceRef{}
	for _, row := range rows {
		decoded, err := hex.DecodeString(row.RefId)
		if err != nil || len(decoded) != 16 {
			continue
		}
		ref, err := self.loadRef(ctx, Id(decoded))
		if err != nil {
			return nil, err
		}
		tip, applied, err := self.state.tipAt(ref, row.Version)
		if err != nil {
			return nil, err
		}
		if !applied || tip == nil {
			continue
		}
		found = append(found, &EvsGitSourceRef{
			RefId: ref.RefId, Kind: ref.Kind, Version: row.Version, Tip: *tip, AppliedOrder: ref.AppliedOrder, Tag: ref.tag(),
		})
	}
	return found, nil
}

// The ref's tip at version, from its tips log: false for a version replay has not applied or that left no tip.
func (self *EvsGitSyncEngine) TipAt(ctx context.Context, refId Id, version uint64) (EvsGitOid, bool, error) {
	ref, err := self.loadRef(ctx, refId)
	if err != nil {
		return EvsGitOid{}, false, err
	}
	tip, applied, err := self.state.tipAt(ref, version)
	if err != nil || !applied || tip == nil {
		return EvsGitOid{}, false, err
	}
	return *tip, true, nil
}

// The ref as replay applied it, read under its apply lock.
func (self *EvsGitSyncEngine) Ref(ctx context.Context, refId Id) (*EvsGitRefState, error) {
	ref, err := self.loadRef(ctx, refId)
	if err != nil {
		return nil, err
	}
	return evsGitRefStateOf(ref), nil
}

// What publish reads of a record.
func evsGitRefStateOf(ref *EvsGitRef) *EvsGitRefState {
	return &EvsGitRefState{
		Version: ref.Version, Chain: ref.Chain, Tip: ref.Tip, LastTip: ref.LastTip, Deleted: ref.Deleted, Base: ref.Base,
		StuckAt: ref.StuckAt,
	}
}

// The ref's whole record, read under its apply lock: what `ur status` and the receive path show.
func (self *EvsGitSyncEngine) GitRef(ctx context.Context, refId Id) (*EvsGitRef, error) {
	return self.loadRef(ctx, refId)
}

// Every ref's record.
func (self *EvsGitSyncEngine) GitRefs() ([]*EvsGitRef, error) {
	return self.state.gitRefs()
}

// Takes P_r.
func (self *EvsGitSyncEngine) LockPublish(ctx context.Context, refId Id) (func(), error) {
	return self.mount.locks.LockPublish(ctx, refId)
}
