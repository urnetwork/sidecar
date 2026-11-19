// FI-17, versioning (§22.8; §11.6's format row, §11.7's setting, refused, kind 5, staged, cite, keys, off and on
// rows, §11.14's files and never rows, D-PHASE-9's reservation list; I-EVS-10, R-TEST-10, D-TEST-10; owner decision
// 168; TEST-M10-01), on fi16.go's reading of every committed version and the blob history:
//
//	setting   each file version's versioning is 0, 1 or 2; 1 or 2 never commits in a config or mailcfg repo, on a
//	          git-mode ref, or on a creates-only ref (a deposit or erasure ref, a record-class repo's owned ref); 1 never
//	          in a push whose authorization pin, as a named state (SetAuthorizationView) holds it, has the repo locked;
//	          2 only in a repo that may hold an index (not config, mailcfg or secret), on a file-mode ref, under an
//	          index root a schedule names (SetFi17IndexRoots): the names .ur-index/ and ur/index are sealed, so the
//	          oracle knows a root only as a schedule's world derived it, and a version 2 under no named root fails
//	cite      every segment a committed version names through a kind-5 locator is named only by the version that
//	          introduced it (its push lists it new, and its stored header, while stored, names that push) and then, in
//	          turn, by its path's next version on the same ref, its path's previous version naming it, or, in the push
//	          that removes a path, by a version that push creates, the removed path's newest version naming it; never by
//	          another path, ref or repo, nor through a reuse source; a staged one only by its introducing version
//	slots     a slot a versionless version introduced is named only by that path's versions in turn and, in turn, the
//	          rename target of the push that removes it
//	renames   each removed path's kind-5 segment or slot is named by at most one new version of the removing push
//	kept      no DELETE removes content a version written with versioning 0 names, whatever its path's later setting,
//	          unless an exact, uncancelled drop of the repo lists that version (FI-27 judges the rest of its going)
//	format    a repo whose repo/ stands below format 2 holds no format-2 construct (versioning 1 or 2, a kind-5 or staged
//	          locator, a DROP or CUT push), and on a Net whose evs world runs devices, none raised a missing_segment,
//	          tamper or version_rule alarm: format-1 code meets format 2 by refusing or ignoring it, never as a fork,
//	          tampering or a missing segment
//
// Readings and gaps, in TEST-M10-01's report: the lock clause runs only where a named authorization state carries the
// push's pin; the format clause's client half reads the evs world's device alarms, not each read's own answer, which
// FS-72's steps hold; a path followed across a cut-over uses its committed map and tail, and one it cannot follow
// fails closed.

package fault

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// A segment header's format byte for format 2 (EVS-FORMAT.md's segment header), which a kind-5 header carries.
const fi17SegmentFormat2 byte = 2

var _ = RegisterInvariant(17, func(ctx context.Context, oracle *Oracle) error {
	return checkFi17(ctx, oracle)
})

// Where a repo's search index lives, as a schedule's world names it: a ref that is the repo's ur/index, or the
// .ur-index/ directory on a file-mode ref, by its token path in one path epoch.
type Fi17IndexRoot struct {
	RefId sidecar.Id
	// Empty for a ref that is ur/index itself.
	TokenPath sidecar.EvsTokenPath
	PathEpoch uint64
}

var fi17Memories sync.Map

// What FI-17 keeps per Net: the index roots schedules named.
type fi17Memory struct {
	stateLock  sync.Mutex
	indexRoots map[sidecar.Id][]*Fi17IndexRoot
}

func fi17MemoryOf(net *Net) *fi17Memory {
	return netMemoryOf(&fi17Memories, net, func() *fi17Memory {
		return &fi17Memory{indexRoots: map[sidecar.Id][]*Fi17IndexRoot{}}
	})
}

// Names a repo's index roots for FI-17 on net. Roots add up.
func SetFi17IndexRoots(net *Net, repoId sidecar.Id, roots ...*Fi17IndexRoot) {
	memory := fi17MemoryOf(net)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	for _, root := range roots {
		rootCopy := *root
		memory.indexRoots[repoId] = append(memory.indexRoots[repoId], &rootCopy)
	}
}

// Whether a version at tokenPath of epoch on refId is under one of the repo's named index roots.
func (self *fi17Memory) underIndexRoot(repoId sidecar.Id, refId sidecar.Id, epoch uint64, tokenPath sidecar.EvsTokenPath) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, root := range self.indexRoots[repoId] {
		if root.RefId != refId {
			continue
		}
		if len(root.TokenPath) == 0 {
			return true
		}
		if root.PathEpoch == epoch && len(root.TokenPath) < len(tokenPath) && tokenPath.HasPrefix(root.TokenPath) {
			return true
		}
	}
	return false
}

func checkFi17(ctx context.Context, oracle *Oracle) error {
	check := evsFormat2Of(ctx, oracle)
	errs := slices.Clone(check.errs)
	memory := fi17MemoryOf(oracle.Net)
	evsMemory := evsOracleMemoryOf(oracle.Net)
	for _, repo := range check.repos {
		if !repo.store.complete() {
			if repo.store.object.GetFormat() >= sidecar.EvsRepoFormat2 {
				errs = append(errs, fmt.Errorf("repo %s's history was not read whole, so FI-17 cannot judge it", repo.store.repoId))
			}
			continue
		}
		errs = append(errs, check.fi17Settings(repo, memory, evsMemory)...)
		errs = append(errs, check.fi17Citations(ctx, repo)...)
	}
	errs = append(errs, check.fi17KeptContent()...)
	errs = append(errs, fi17DeviceAlarms(oracle.Net)...)
	return errors.Join(errs...)
}

// The setting and format clauses over every committed version of the repo.
func (self *evsFormat2Check) fi17Settings(repo *evsFormat2Repo, memory *fi17Memory, evsMemory *evsOracleMemory) []error {
	errs := []error{}
	repoKind := repo.store.object.GetKind()
	format := repo.store.object.GetFormat()
	for _, ref := range repo.store.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			push := version.statement.Push
			where := fmt.Sprintf("repo %s ref %s: version %d", repo.store.repoId, ref.refId, version.version)
			if format < sidecar.EvsRepoFormat2 && push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP|protocol.EvsPushFlag_EVS_PUSH_CUT) != 0 {
				errs = append(errs, fmt.Errorf("%s: a DROP or CUT committed while repo/ stands at format %d", where, format))
			}
			refMode := protocol.EvsRefMode(push.GetRefMode())
			refKind := protocol.EvsRefKind(push.GetRefKind())
			createsOnly := refKind == protocol.EvsRefKind_EVS_REF_DEPOSIT || refKind == protocol.EvsRefKind_EVS_REF_ERASURE ||
				(refKind == protocol.EvsRefKind_EVS_REF_OWNED && sidecar.EvsRepoKindRecordClass(repoKind))
			for i, entryVersion := range version.entryVersions {
				if entryVersion == nil {
					continue
				}
				tokenPath := version.payload.Changes[i].TokenPath
				at := fmt.Sprintf("%s of %s", where, tokenPath.KeyString())
				versioning := entryVersion.GetVersioning()
				if format < sidecar.EvsRepoFormat2 {
					for _, locator := range entryVersion.GetChain() {
						if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT || locator.GetStaged() {
							errs = append(errs, fmt.Errorf("%s: a kind-5 or staged locator committed while repo/ stands at format %d", at, format))
							break
						}
					}
					if versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
						errs = append(errs, fmt.Errorf("%s: versioning %d committed while repo/ stands at format %d", at, versioning, format))
					}
				}
				switch versioning {
				case uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT):
					continue
				case uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS), uint32(protocol.EvsVersioning_EVS_VERSIONING_INDEX):
				default:
					errs = append(errs, fmt.Errorf("%s: versioning %d, past 2, is malformed", at, versioning))
					continue
				}
				switch {
				case repoKind == protocol.RepoKind_REPO_KIND_CONFIG || repoKind == protocol.RepoKind_REPO_KIND_MAILCFG:
					errs = append(errs, fmt.Errorf("%s: versioning %d in a %s repo, whose replaying readers verify authority from every version", at, versioning, repoKind))
				case refMode == protocol.EvsRefMode_EVS_REF_GIT:
					errs = append(errs, fmt.Errorf("%s: versioning %d on a git-mode ref, which holds no versionless version", at, versioning))
				case createsOnly:
					errs = append(errs, fmt.Errorf("%s: versioning %d on a creates-only ref", at, versioning))
				}
				if versioning == uint32(protocol.EvsVersioning_EVS_VERSIONING_VERSIONLESS) {
					if locked, judged := fi17LockedAtPin(evsMemory, repo, push); judged && locked {
						errs = append(errs, fmt.Errorf("%s: versioning 1 in a push whose authorization pin holds the repo locked (owner decision 168)", at))
					}
					continue
				}
				switch {
				case repoKind == protocol.RepoKind_REPO_KIND_SECRET:
					errs = append(errs, fmt.Errorf("%s: versioning 2 in a secret repo, which never holds an index", at))
				case refMode != protocol.EvsRefMode_EVS_REF_FILE:
					errs = append(errs, fmt.Errorf("%s: versioning 2 off a file-mode ref", at))
				case !memory.underIndexRoot(repo.store.repoId, ref.refId, push.GetPathEpoch(), tokenPath):
					errs = append(errs, fmt.Errorf("%s: versioning 2 under no index root the schedule named (SetFi17IndexRoots): an index file lives only under .ur-index/ on a file-mode ref or on ur/index", at))
				}
			}
		}
	}
	return errs
}

// Whether the authorization state a schedule named at the push's pin holds the repo locked; judged is false when no
// named state carries that pin.
func fi17LockedAtPin(evsMemory *evsOracleMemory, repo *evsFormat2Repo, push *protocol.EvsPush) (locked bool, judged bool) {
	pin := push.GetAuth()
	if pin == nil {
		return false, false
	}
	for _, named := range evsMemory.authorizationHistoryOf(repo.networkId) {
		namedPin := named.view.Pin()
		if namedPin == nil || namedPin.GetVersion() != pin.GetVersion() || !bytes.Equal(namedPin.GetChain(), pin.GetChain()) {
			continue
		}
		row := named.view.Repo(repo.store.repoId)
		return row != nil && row.GetLock() == protocol.RepoVersioningLock_REPO_VERSIONING_LOCK_LOCKED, true
	}
	return false, false
}

// The cite, slots and renames clauses over every object some committed version of the repo names through a kind-5
// locator, and every slot a versionless version introduced.
func (self *evsFormat2Check) fi17Citations(ctx context.Context, repo *evsFormat2Repo) []error {
	errs := []error{}
	names := []string{}
	for name := range repo.namers {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		namers := repo.namers[name]
		_, key, _ := strings.Cut(name, " ")
		kind5 := false
		for _, namer := range namers {
			kind5 = kind5 || namer.kind == evsNameVersionless || namer.kind == evsNameStaged
		}
		isSlot := strings.HasPrefix(key, "slot/")
		// a slot a versionless version introduced binds every namer; one no namer introduced binds its versionless
		// namers; a kept path's slot follows §11.8's slot rule, which is not FI-17's
		versionlessOnly := false
		if isSlot {
			introducer := self.fi17Introducer(repo, namers, protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT, key)
			switch {
			case introducer == nil:
				versionlessOnly = true
			case introducer.versioning == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT):
				continue
			}
		} else if !kind5 {
			continue
		}
		for _, namer := range namers {
			if versionlessOnly && !namer.versionless() {
				continue
			}
			if namer.kind == evsNameGitObject {
				errs = append(errs, fmt.Errorf("repo %s: %s is named by a git-mode push's history, and versionless content never is", repo.store.repoId, key))
				continue
			}
			if err := self.fi17Cites(ctx, repo, key, namer, namers); err != nil {
				errs = append(errs, fmt.Errorf("repo %s: %s: %w", repo.store.repoId, key, err))
			}
		}
	}
	errs = append(errs, self.fi17Renames(repo)...)
	return errs
}

// The namer whose push lists the object new as kind, nil when none does.
func (self *evsFormat2Check) fi17Introducer(repo *evsFormat2Repo, namers []*evsNamer, kind protocol.EvsNewObjectKind, key string) *evsNamer {
	for _, namer := range namers {
		if self.fi17Introduces(repo, namer, kind, key) {
			return namer
		}
	}
	return nil
}

// Whether namer's push lists the object at key new as kind.
func (self *evsFormat2Check) fi17Introduces(repo *evsFormat2Repo, namer *evsNamer, kind protocol.EvsNewObjectKind, key string) bool {
	ref := repo.ref(namer.refId)
	if ref == nil {
		return false
	}
	version := ref.at(namer.version)
	if version == nil {
		return false
	}
	idHex := key[strings.LastIndex(key, "/")+1:]
	for _, newObject := range version.payload.NewObjects {
		if newObject.Kind == kind && hex.EncodeToString(newObject.Id) == idHex {
			return true
		}
	}
	return false
}

// Whether one namer of a versionless object may name it: its introducer, its path's next version in turn, or a
// rename target of the push removing a path whose newest version names it.
func (self *evsFormat2Check) fi17Cites(ctx context.Context, repo *evsFormat2Repo, key string, namer *evsNamer, namers []*evsNamer) error {
	isSlot := strings.HasPrefix(key, "slot/")
	if namer.kind == evsNameStaged {
		if self.fi17Introduces(repo, namer, protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT, key) {
			return nil
		}
		return fmt.Errorf("%s names a staged segment its push did not stage: a staged segment is named only by its introducing version", namer)
	}
	introducedKind := protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SEGMENT
	if isSlot {
		introducedKind = protocol.EvsNewObjectKind_EVS_NEW_OBJECT_SLOT
	}
	if self.fi17Introduces(repo, namer, introducedKind, key) {
		if !isSlot {
			if err := self.fi17HeaderNames(ctx, repo, key, namer); err != nil {
				return err
			}
		}
		return nil
	}
	ref := repo.ref(namer.refId)
	previous, err := self.fi17PreviousVersion(repo, ref, namer)
	if err != nil {
		return fmt.Errorf("%s: %w", namer, err)
	}
	if previous != nil && fi17EntryNames(previous, key) {
		return nil
	}
	if self.fi17RenameTarget(repo, ref, namer, key) {
		return nil
	}
	return fmt.Errorf("%s names it, and neither introduced it, nor follows a version of its path that names it, nor is a rename target of a path its push removes that names it: versionless content is never named by another path, ref or repo, nor through a reuse source", namer)
}

// The stored kind-5 segment's header names the push of its introducing version; a segment gone is not read.
func (self *evsFormat2Check) fi17HeaderNames(ctx context.Context, repo *evsFormat2Repo, key string, namer *evsNamer) error {
	object, err := self.oracle.View.Object(ctx, self.segmentClusterId, key)
	if err != nil {
		return err
	}
	if object == nil {
		return nil
	}
	if namer.kind == evsNameSegment {
		// a kind-1 locator naming it: the segment is kind 5 only when its header says so
		if len(object.Body) < 5 || object.Body[4] != fi17SegmentFormat2 {
			return nil
		}
	}
	header, err := sidecar.ParseEvsKind5SegmentHeader(object.Body)
	if err != nil {
		return fmt.Errorf("%s introduces it through a kind-5 locator, and its header is no kind-5 header: %w", namer, err)
	}
	version := repo.ref(namer.refId).at(namer.version)
	if !bytes.Equal(header.PushId.Bytes(), version.statement.Push.GetPushId()) || header.RepoId != repo.store.repoId {
		return fmt.Errorf("%s introduces it, and its kind-5 header names push %s of repo %s: a kind-5 segment names its introducing push", namer, header.PushId, header.RepoId)
	}
	return nil
}

// The entry version namer's path held just before namer's version on its ref, nil when none: a creation's, or a
// path removed before it. A cut-over between them is followed back through its moves.
func (self *evsFormat2Check) fi17PreviousVersion(repo *evsFormat2Repo, ref *evsStoreRef, namer *evsNamer) (*protocol.EvsEntryVersion, error) {
	tokenPath, epoch := namer.tokenPath, namer.pathEpoch
	for at := namer.version - 1; 0 < at; at -= 1 {
		version := ref.at(at)
		if version == nil {
			return nil, fmt.Errorf("version %d of ref %s was not read", at, ref.refId)
		}
		push := version.statement.Push
		if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 && push.GetPathEpoch() == epoch {
			source, sourceEpoch, err := self.fi17MoveSourceOf(repo, ref, version, tokenPath)
			if err != nil {
				return nil, err
			}
			if source == nil {
				// a path the cut-over created, which has no earlier version
				return nil, nil
			}
			tokenPath, epoch = source, sourceEpoch
			continue
		}
		if push.GetPathEpoch() != epoch {
			continue
		}
		for i, change := range version.payload.Changes {
			if change.TokenPath.Equal(tokenPath) {
				return version.entryVersions[i], nil
			}
			if !change.WritesEntry() && len(change.TokenPath) < len(tokenPath) && tokenPath.HasPrefix(change.TokenPath) {
				// a directory above it removed: what came after is a new life
				return nil, nil
			}
		}
	}
	return nil, nil
}

// The source a cut-over's move to tokenPath names in the epoch before, nil when no move lands on it.
func (self *evsFormat2Check) fi17MoveSourceOf(repo *evsFormat2Repo, ref *evsStoreRef, version *evsStoreVersion, tokenPath sidecar.EvsTokenPath) (sidecar.EvsTokenPath, uint64, error) {
	push := version.statement.Push
	moves, err := fi1MapMoves(self.ctx, self.oracle.View, evsOracleMemoryOf(self.oracle.Net), repo.store, ref.refId, push.GetPathEpoch(), push.GetPathMapSha256())
	if err != nil && len(push.GetPathMapSha256()) != 0 {
		return nil, 0, err
	}
	tailMoves, err := fi17TailMoves(version)
	if err != nil {
		return nil, 0, err
	}
	for _, move := range append(moves, tailMoves...) {
		target, err := sidecar.ParseEvsTokenPath(move.GetNewTokenPath())
		if err != nil || !target.Equal(tokenPath) {
			continue
		}
		for _, source := range move.GetSources() {
			if source.GetEpoch() < push.GetPathEpoch() {
				sourcePath, err := sidecar.ParseEvsTokenPath(source.GetTokenPath())
				if err != nil {
					return nil, 0, err
				}
				return sourcePath, source.GetEpoch(), nil
			}
		}
	}
	return nil, 0, nil
}

// A PATH_EPOCH version's tail moves.
func fi17TailMoves(version *evsStoreVersion) ([]*protocol.EvsPathMove, error) {
	moves := []*protocol.EvsPathMove{}
	for _, item := range version.payload.TailMoves {
		move := &protocol.EvsPathMove{}
		if err := proto.Unmarshal(item, move); err != nil {
			return nil, fmt.Errorf("a tail move: %w", err)
		}
		moves = append(moves, move)
	}
	return moves, nil
}

// Whether an entry version names the object at key: a segment by any locator, or a slot.
func fi17EntryNames(entryVersion *protocol.EvsEntryVersion, key string) bool {
	if entryVersion == nil {
		return false
	}
	idHex := key[strings.LastIndex(key, "/")+1:]
	if strings.HasPrefix(key, "slot/") {
		for _, slotId := range entryVersion.GetSlotIds() {
			if hex.EncodeToString(slotId) == idHex {
				return true
			}
		}
		return false
	}
	for _, locator := range entryVersion.GetChain() {
		switch protocol.EvsLocatorKind(locator.GetKind()) {
		case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT, protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT:
			if hex.EncodeToString(locator.GetId()) == idHex {
				return true
			}
		}
	}
	return false
}

// Whether namer's push removes a path whose newest version before it names the object, which namer's version, a
// creation of that push, may then take over as its rename target.
func (self *evsFormat2Check) fi17RenameTarget(repo *evsFormat2Repo, ref *evsStoreRef, namer *evsNamer, key string) bool {
	version := ref.at(namer.version)
	if version == nil || namer.changeIndex < 0 || version.payload.Changes[namer.changeIndex].Change.GetBaseEntryVersion() != 0 {
		// a rename target is a version the removing push creates
		return false
	}
	for i, change := range version.payload.Changes {
		if change.WritesEntry() || i == namer.changeIndex {
			continue
		}
		removed := &evsNamer{refId: namer.refId, version: namer.version, changeIndex: i, tokenPath: change.TokenPath, pathEpoch: namer.pathEpoch}
		previous, err := self.fi17PreviousVersion(repo, ref, removed)
		if err == nil && fi17EntryNames(previous, key) {
			return true
		}
	}
	return false
}

// Each removed path's kind-5 segment or slot is named by at most one new version of the push removing it.
func (self *evsFormat2Check) fi17Renames(repo *evsFormat2Repo) []error {
	errs := []error{}
	for _, ref := range repo.store.refs {
		for _, version := range ref.versions {
			if version == nil {
				continue
			}
			for i, change := range version.payload.Changes {
				if change.WritesEntry() {
					continue
				}
				removed := &evsNamer{refId: ref.refId, version: version.version, changeIndex: i, tokenPath: change.TokenPath, pathEpoch: version.statement.Push.GetPathEpoch()}
				previous, err := self.fi17PreviousVersion(repo, ref, removed)
				if err != nil || previous == nil || previous.GetVersioning() == uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
					continue
				}
				keys := []string{}
				for _, locator := range previous.GetChain() {
					if protocol.EvsLocatorKind(locator.GetKind()) == protocol.EvsLocatorKind_EVS_LOCATOR_VERSIONLESS_SEGMENT && !locator.GetStaged() {
						keys = append(keys, evsOracleSegmentKey(repo.store.repoId, locator.GetId()))
					}
				}
				for _, slotId := range previous.GetSlotIds() {
					keys = append(keys, evsOracleSlotKey(repo.store.repoId, slotId))
				}
				for _, key := range keys {
					count := 0
					for j, entryVersion := range version.entryVersions {
						if j != i && fi17EntryNames(entryVersion, key) {
							count += 1
						}
					}
					if 1 < count {
						errs = append(errs, fmt.Errorf("repo %s ref %s: version %d removes %s and names its %s in %d new versions, past one (I-EVS-10)", repo.store.repoId, ref.refId, version.version, change.TokenPath.KeyString(), key, count))
					}
				}
			}
		}
	}
	return errs
}

// No DELETE since the previous check removed content a version written with versioning 0 names, unless an exact,
// uncancelled drop of the repo lists that version.
func (self *evsFormat2Check) fi17KeptContent() []error {
	errs := []error{}
	for _, index := range self.dropDeletes {
		repo := self.deleteRepos[index]
		drops, _ := self.dropsOf(repo)
		for _, namer := range self.deleteNamers[index] {
			if namer.kind == evsNameGitObject || namer.versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
				continue
			}
			listed := false
			for _, drop := range drops {
				listed = listed || (drop.inexact == "" && !drop.cancelled && drop.lists(namer))
			}
			if !listed {
				errs = append(errs, fmt.Errorf("%s: %s, written with versioning 0, names it, which keeps its content for the repo's life unless an executed drop lists it", evsDeleteText(self.history[index]), namer))
			}
		}
	}
	return errs
}

// Every alarm an evs world's device raised that reads format 2 as a fork, tampering or a missing segment.
func fi17DeviceAlarms(net *Net) []error {
	world := EvsWorldOf(net)
	if world == nil {
		return nil
	}
	world.stateLock.Lock()
	defer world.stateLock.Unlock()
	errs := []error{}
	for _, name := range world.deviceNames {
		for _, alarm := range world.deviceAlarms[name] {
			for _, kind := range []sidecar.SidecarEvsAlarm{sidecar.SidecarEvsAlarmMissingSegment, sidecar.SidecarEvsAlarmTamper, sidecar.SidecarEvsAlarmVersionRule} {
				if strings.HasPrefix(alarm, string(kind)+" ") {
					errs = append(errs, fmt.Errorf("%s alarmed %s: format-1 and format-2 code meet format 2's constructs by refusing, ignoring or folding them, never as a fork, tampering or a missing segment", name, alarm))
				}
			}
		}
	}
	return errs
}
