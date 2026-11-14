// FI-15, file-mode CAS (§22.8; I-EVS-8; D-TEST-10), as RESOLUTIONS' g0-density-text-alignments #7 reads it (QD-399):
// only git-mode refs take overlays, so on a file-mode ref the effective base version is base_version. An independent
// replay of each
// file-mode ref's head history, version by version, from §11.7's versions, newest and directory rows alone, on the
// store walk FI-1 makes (fi1.go): never evsservice's 5f or 5g, whose bugs it would share. Every change of version u
// is judged against its path as the history stands through u-1:
//
//   - a file write's base_entry_version equals the path's newest version, 0 naming it absent (never written or
//     removed); its version is base + 1, or for a creation max(b, m) + 1, b the push's base_version and m the path's
//     standing removal's version, 0 when it was never written;
//   - a removal's base equals the path's newest version, and its version, one past the path's last, is base + 1;
//     a removal of a directory D removes every path below it, each at one past its own last;
//   - a path's versions never restart: each version a path takes, a removal's included, is above every version it
//     held before, and none exceeds the ref version it commits at;
//   - a file is never written over a standing directory, nor a directory created over a standing path, on a file-mode
//     ref; a directory's creation follows the versions rule as a file's does;
//   - 11.7's two-way directory checks: a push removing D commits only if no creation of or delta to D committed after
//     its base, and a push changing D only if no removal of D, its own or a prefix's, committed after its base;
//   - a head read or listing at v serves each path's newest version through v and none newer: every read reply the
//     ledger holds (ledger.go) is held to the replay at the head version it was served at, a version, a removal, a
//     directory's table and deltas, and an absence.
//
// The replay carries a path across each committed PATH_EPOCH by its map's moves and tail, as FI-6's does. A
// directory's deltas merge with no CAS (§11.8's 5g), so their versions are not judged. Readings, held as the report
// names them: a removal's version is base + 1 for a directory too, as for a file; the version rule is not held to a
// path whose standing removal was a removed directory's below a removed prefix, since evs's fold gives such a marker
// a bound from the directory's table (evsservice's evsIndexEntryStanding), which §11.7 leaves to the fold, while its
// versions still never restart; a path the replay does not hold in a read's epoch is held only to none newer. A ref
// whose history could not be read whole is not judged and fails closed, as FI-6's does.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ = RegisterInvariant(15, func(ctx context.Context, oracle *Oracle) error {
	return checkFi15(ctx, oracle)
})

// What FI-15 keeps from one check to the next on one Net: each file-mode ref's replay as its last walk read it, and
// how many of the ledger's reads it has judged.
type fi15Memory struct {
	stateLock    sync.Mutex
	replays      map[HistoryRef]*fi15Replay
	readsChecked int
}

var fi15Memories sync.Map

func newFi15Memory() *fi15Memory {
	return &fi15Memory{replays: map[HistoryRef]*fi15Replay{}}
}

// One path of a file-mode ref through its replayed history.
type fi15Path struct {
	// its token path in each epoch it lived in
	tokenPaths map[uint64]sidecar.EvsTokenPath
	// where it stands after the versions replayed so far
	stands    bool
	directory bool
	// its newest version while it stands
	newest uint64
	// its standing removal's version while it does not stand, 0 when it was never written
	removal uint64
	// whether that removal was a prefix's of a path that stood as a directory (see the file header)
	removalUnruled bool
	// the ref versions of its newest removal, its own or a prefix's, and of its newest creation or delta
	removedAt uint64
	changedAt uint64
	// the highest version it ever held, a removal's included
	high uint64
	// its states, each from the ref version that made it
	states []*fi15State
}

// A path's state from ref version at on.
type fi15State struct {
	at        uint64
	stands    bool
	directory bool
	// the version written or removed past, and the push that did it
	version uint64
	pushId  sidecar.Id
	removal bool
}

// The newest state through ref version, nil while the path did not exist yet.
func (self *fi15Path) through(version uint64) *fi15State {
	var newest *fi15State
	for _, state := range self.states {
		if version < state.at {
			break
		}
		newest = state
	}
	return newest
}

// A ref's paths, replayed.
type fi15Replay struct {
	paths   []*fi15Path
	byToken map[uint64]map[string]*fi15Path
	// the head version replayed through
	version uint64
}

func (self *fi15Replay) path(epoch uint64, tokenPath sidecar.EvsTokenPath, create bool) *fi15Path {
	if self.byToken[epoch] == nil {
		self.byToken[epoch] = map[string]*fi15Path{}
	}
	key := string(tokenPath.Bytes())
	if path, ok := self.byToken[epoch][key]; ok || !create {
		return path
	}
	path := &fi15Path{tokenPaths: map[uint64]sidecar.EvsTokenPath{epoch: tokenPath}}
	self.byToken[epoch][key] = path
	self.paths = append(self.paths, path)
	return path
}

func checkFi15(ctx context.Context, oracle *Oracle) error {
	memory := netMemoryOf(&fi15Memories, oracle.Net, newFi15Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()

	repos, walkErrs := evsStoreWalkOf(ctx, oracle)
	errs := []error{}
	if 0 < len(walkErrs) {
		errs = append(errs, fmt.Errorf("the store walk could not read every repo, so FI-15 judges none of them whole: %w", walkErrs[0]))
	}
	for _, repo := range repos {
		for _, ref := range repo.refs {
			historyRef := HistoryRef{RepoId: repo.repoId, RefId: ref.refId}
			if ref.head.Head.GetVersion() == 0 {
				continue
			}
			if previous := memory.replays[historyRef]; previous != nil && repo.walkedBy != oracle {
				// a walk reused from an earlier check changed in nothing the replay reads, and it held then
				continue
			}
			if protocol.EvsRefMode(ref.head.Head.GetRefMode()) != protocol.EvsRefMode_EVS_REF_FILE {
				continue
			}
			if !ref.complete {
				errs = append(errs, fmt.Errorf("%s: its history could not be read whole, so its file-mode CAS cannot be judged", historyRef))
				delete(memory.replays, historyRef)
				continue
			}
			replay, replayErrs := fi15ReplayRef(ctx, oracle, repo, ref)
			errs = append(errs, replayErrs...)
			memory.replays[historyRef] = replay
		}
	}
	reads := LedgerOf(oracle.Net).Reads()
	for _, read := range reads[min(memory.readsChecked, len(reads)):] {
		errs = append(errs, fi15CheckRead(memory.replays[read.Ref], read)...)
	}
	memory.readsChecked = len(reads)
	return errors.Join(errs...)
}

// One file-mode ref's history replayed from version 1, every change judged on the way: see the file header.
func fi15ReplayRef(ctx context.Context, oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef) (*fi15Replay, []error) {
	replay := &fi15Replay{byToken: map[uint64]map[string]*fi15Path{}}
	memory := evsOracleMemoryOf(oracle.Net)
	errs := []error{}
	historyRef := HistoryRef{RepoId: repo.repoId, RefId: ref.refId}
	for _, version := range ref.versions {
		u := version.version
		push := version.statement.Push
		failf := func(format string, a ...any) {
			errs = append(errs, fmt.Errorf("%s v%d (push %s, based at %d): "+format, append([]any{historyRef, u, version.entry.PushId, push.GetBaseVersion()}, a...)...))
		}
		if protocol.EvsRefMode(push.GetRefMode()) != protocol.EvsRefMode_EVS_REF_FILE {
			failf("a push of ref mode %d on a file-mode ref", push.GetRefMode())
			continue
		}
		epoch := push.GetPathEpoch()
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
			if err := fi15Carry(ctx, oracle, memory, repo, ref, replay, version); err != nil {
				failf("%v", err)
			}
		}
		base := push.GetBaseVersion()
		changed := map[*fi15Path]bool{}
		type applied struct {
			path   *fi15Path
			change *sidecar.EvsCheckedChange
			entry  *protocol.EvsEntryVersion
		}
		applies := []*applied{}
		// every change against the history through u - 1
		for i, change := range version.payload.Changes {
			path := replay.path(epoch, change.TokenPath, true)
			if changed[path] {
				failf("%s changed twice in one push", fi15PathName(path, epoch))
				continue
			}
			changed[path] = true
			entry := version.entryVersions[i]
			fi15Judge(failf, path, fi15PathName(path, epoch), u, base, change.Change.GetBaseEntryVersion(), entry)
			applies = append(applies, &applied{path: path, change: change, entry: entry})
		}
		// then the push applied: its own changes, then what a removed directory takes with it
		removedDirectories := []sidecar.EvsTokenPath{}
		for _, each := range applies {
			path := each.path
			if each.entry == nil {
				wasDirectory := path.stands && path.directory
				removal := each.change.Change.GetBaseEntryVersion() + 1
				path.stands, path.removal, path.removalUnruled, path.removedAt = false, removal, false, u
				path.high = max(path.high, removal)
				path.states = append(path.states, &fi15State{at: u, version: removal, pushId: version.entry.PushId, removal: true})
				if wasDirectory {
					removedDirectories = append(removedDirectories, each.change.TokenPath)
				}
				continue
			}
			written := each.entry.GetVersion()
			directory := protocol.EvsEntryKind(each.entry.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
			if directory && path.stands && path.directory && 0 < each.change.Change.GetBaseEntryVersion() {
				path.newest = max(path.newest, written)
			} else {
				path.newest = written
			}
			path.stands, path.directory, path.removal, path.removalUnruled = true, directory, 0, false
			if directory {
				path.changedAt = u
			}
			path.high = max(path.high, written)
			path.states = append(path.states, &fi15State{at: u, stands: true, directory: directory, version: path.newest, pushId: version.entry.PushId})
		}
		for _, removed := range removedDirectories {
			for _, below := range replay.paths {
				belowPath, ok := below.tokenPaths[epoch]
				if !ok || changed[below] || !below.stands || len(belowPath) <= len(removed) || !belowPath.HasPrefix(removed) {
					continue
				}
				removal := below.newest + 1
				below.stands, below.removal, below.removalUnruled, below.removedAt = false, removal, below.directory, u
				below.high = max(below.high, removal)
				below.states = append(below.states, &fi15State{at: u, version: removal, pushId: version.entry.PushId, removal: true})
			}
		}
		replay.version = u
	}
	return replay, errs
}

// One change judged against its path through u - 1: see the file header. entry is nil for a removal.
func fi15Judge(failf func(format string, a ...any), path *fi15Path, name string, u uint64, base uint64, baseEntryVersion uint64, entry *protocol.EvsEntryVersion) {
	newest := uint64(0)
	if path.stands {
		newest = path.newest
	}
	if entry == nil {
		switch {
		case !path.stands:
			failf("%s removed on base %d while it is absent: a removal of an absent path", name, baseEntryVersion)
		case path.directory:
			if base < path.changedAt {
				failf("directory %s removed though it was created or changed at %d, after the push's base: 11.7's two-way check", name, path.changedAt)
			}
		case baseEntryVersion != newest:
			failf("%s removed on base %d, its newest version %d: the path-level CAS", name, baseEntryVersion, newest)
		}
		if removal := baseEntryVersion + 1; removal <= path.high {
			failf("%s's removal at version %d, at or below the %d it held: its versions restart", name, removal, path.high)
		}
		return
	}
	written := entry.GetVersion()
	directory := protocol.EvsEntryKind(entry.GetKind()) == protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY
	if directory && 0 < baseEntryVersion {
		switch {
		case !path.stands || !path.directory:
			failf("a delta to %s, which does not stand as a directory", name)
		case base < path.removedAt:
			failf("a delta to directory %s, though its removal committed at %d, after the push's base: 11.7's two-way check", name, path.removedAt)
		}
		return
	}
	switch {
	case directory && path.stands:
		failf("directory %s created over a standing path", name)
	case !directory && path.stands && path.directory:
		failf("file %s written over a standing directory", name)
	case !directory && baseEntryVersion != newest:
		failf("%s written on base %d, its newest version %d: the path-level CAS", name, baseEntryVersion, newest)
	}
	expected := baseEntryVersion + 1
	if baseEntryVersion == 0 {
		expected = max(base, path.removal) + 1
	}
	if written != expected && !(baseEntryVersion == 0 && path.removalUnruled) {
		failf("%s written at version %d, the versions rule's %d", name, written, expected)
	}
	if written <= path.high {
		failf("%s written at version %d, at or below the %d it held: its versions restart", name, written, path.high)
	}
	if u < written {
		failf("%s written at version %d, past the ref version it commits at", name, written)
	}
}

// A committed PATH_EPOCH's moves, its map's and its tail's, carrying each source path into the new epoch.
func fi15Carry(ctx context.Context, oracle *Oracle, memory *evsOracleMemory, repo *evsStoreRepo, ref *evsStoreRef, replay *fi15Replay, version *evsStoreVersion) error {
	push := version.statement.Push
	epoch := push.GetPathEpoch()
	moves, err := fi1MapMoves(ctx, oracle.View, memory, repo, ref.refId, epoch, push.GetPathMapSha256())
	if err != nil {
		return fmt.Errorf("the PATH_EPOCH's map: %w", err)
	}
	for _, moveBytes := range version.payload.TailMoves {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(moveBytes, move); err != nil {
			return fmt.Errorf("the PATH_EPOCH's tail: %w", err)
		}
		moves = append(moves, move)
	}
	for _, move := range moves {
		newPath, err := sidecar.ParseEvsTokenPath(move.GetNewTokenPath())
		if err != nil {
			return fmt.Errorf("the PATH_EPOCH moves to %w", err)
		}
		var path *fi15Path
		for _, source := range move.GetSources() {
			sourcePath, err := sidecar.ParseEvsTokenPath(source.GetTokenPath())
			if err != nil {
				continue
			}
			if path = replay.path(source.GetEpoch(), sourcePath, false); path != nil {
				break
			}
		}
		if path == nil {
			path = replay.path(epoch, newPath, true)
		}
		path.tokenPaths[epoch] = newPath
		if replay.byToken[epoch] == nil {
			replay.byToken[epoch] = map[string]*fi15Path{}
		}
		replay.byToken[epoch][string(newPath.Bytes())] = path
	}
	return nil
}

func fi15PathName(path *fi15Path, epoch uint64) string {
	if tokenPath, ok := path.tokenPaths[epoch]; ok {
		if len(tokenPath) == 0 {
			return "the root"
		}
		return tokenPath.KeyString()
	}
	return "a path"
}

// One read reply held to the replay at the head version it was served at: none newer, and each path's newest.
func fi15CheckRead(replay *fi15Replay, read *LedgerRead) []error {
	if read.RefMode != protocol.EvsRefMode_EVS_REF_FILE {
		return nil
	}
	v := read.HeadVersion
	errs := []error{}
	failf := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("%s's read of %s at head v%d from %s: "+format, append([]any{read.Actor, read.Ref, v, read.Instance}, a...)...))
	}
	for _, reply := range read.Paths {
		if reply.GetStaleEpoch() || reply.GetBase() != nil {
			continue
		}
		tokenPath, err := sidecar.ParseEvsTokenPath(reply.GetTokenPath())
		if err != nil {
			failf("a path reply naming no token path: %v", err)
			continue
		}
		name := tokenPath.KeyString()
		if len(tokenPath) == 0 {
			name = "the root"
		}
		// none newer, whatever the replay holds
		if served := reply.GetVersion(); served != nil && v < served.GetCommitVersion() {
			failf("%s served a version committed at %d, above the head: a version above its head", name, served.GetCommitVersion())
		}
		if removal := reply.GetRemoval(); removal != nil && v < removal.GetRemovalVersion() {
			failf("%s served a removal committed at %d, above the head", name, removal.GetRemovalVersion())
		}
		if v < reply.GetNamesThrough() {
			failf("%s served a name table through %d, above the head: a listing above its head", name, reply.GetNamesThrough())
		}
		for _, delta := range reply.GetDeltas() {
			if v < delta.GetCommitVersion() {
				failf("%s served a delta committed at %d, above the head: a listing showing a version above its head", name, delta.GetCommitVersion())
			}
		}
		if replay == nil || replay.version < v {
			// the replay has not reached that head: the walk of the step that served it will
			continue
		}
		path := replay.path(read.CurrentEpoch, tokenPath, false)
		if path == nil {
			continue
		}
		state := path.through(v)
		stands := state != nil && state.stands
		switch served := reply.GetVersion(); {
		case served != nil:
			entry := &protocol.EvsEntryVersion{}
			if err := proto.Unmarshal(served.GetEntryVersion(), entry); err != nil {
				failf("%s served entry version bytes that do not parse: %v", name, err)
				continue
			}
			if !stands {
				failf("%s served version %d (push %x at %d), and the head history holds it absent through v%d", name, entry.GetVersion(), served.GetPushId(), served.GetCommitVersion(), v)
				continue
			}
			if !state.directory && (state.at != served.GetCommitVersion() || state.version != entry.GetVersion() || !bytes.Equal(state.pushId.Bytes(), served.GetPushId())) {
				failf("%s served version %d of push %x at %d, and its newest through v%d is version %d of push %s at %d", name, entry.GetVersion(), served.GetPushId(), served.GetCommitVersion(), v, state.version, state.pushId, state.at)
			}
		case reply.GetRemoval() != nil:
			removal := reply.GetRemoval()
			if stands {
				failf("%s served a removal at %d, and it stands through v%d at version %d", name, removal.GetRemovalVersion(), v, state.version)
				continue
			}
			if state != nil && state.removal && (state.at != removal.GetRemovalVersion() || state.version != removal.GetPathVersion()) {
				failf("%s served the removal at %d of version %d, and its newest removal through v%d is at %d of version %d", name, removal.GetRemovalVersion(), removal.GetPathVersion(), v, state.at, state.version)
			}
		case reply.GetNames() != nil || 0 < len(reply.GetDeltas()):
			if !stands || !state.directory {
				failf("%s served a directory's table, and it does not stand as a directory through v%d", name, v)
			}
		default:
			if stands && !(len(tokenPath) == 0) {
				failf("%s served absent, and it stands through v%d at version %d", name, v, state.version)
			}
		}
	}
	return errs
}
