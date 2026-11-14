// FI-3, commit-point authorization (§22.8; I-16; §8, §10.6, §11.8's 5d and linearization rows; D-TEST-10): every
// head transition carries, and the oracle re-verifies, the authorization pin, generation pin, path epoch and lifecycle
// state current at its head CAS, retries and seals included, and nothing committing later than §10.6's window after
// a gate closes uses an excluded generation. The oracle judges each committed version of every ref the store walk
// FI-1 makes reads (fi1.go), once, at the first check that reads it, at the moment of its CAS: the time of the step
// that committed it, which the clock holds still within a step, read from that step's successful head write.
//
//   - pins never fall: along a ref's history the auth pin's position and the generation never go down, and an equal
//     one names the same chain, or the same group and commitment;
//   - the auth pin is on the network's authorization chain as the state current at the CAS holds it (a pin before
//     what that state retains is not judged, as §10.6's gate does not), never above it or off it;
//   - the generation pin names gen/<g> of its group, of this repo, with the commitment pinned;
//   - the path epoch is the ref's current one through the version before, which only a PATH_EPOCH raises;
//   - the gate: against the newest state named at least the gate window before the CAS (Fi3Settings.GateWindow,
//     §10.6's window row), g's GenRotate covers the repo's holders_shrunk_at, and no reader of the repo at g's time
//     had stopped reading by the CAS less the window. A shrink or expiry younger than the window is within §11.8's
//     bound for a push validated before it, so it excludes nothing yet;
//   - the lifecycle: repo/ was active at the CAS, or left active less than the lifecycle window before it
//     (Fi3Settings.LifecycleWindow, §11.12's phase 1: a push validated before the CAS lands within it or never).
//
// The authorization states are the ones a schedule named with SetAuthorizationView (fi1.go), each when it was named;
// a repo of a network with none named is not judged and fails closed. Readings: a state is current from when it was
// named; holders are the readers §8.12's RepoReadersAt gives, so a live Delegation's key, which KeyHolders adds, is
// not read; the CAS time of a version committed in a step that also moved the clock is the step's time after the
// move, Advance running before a step's actions. Gaps, each failing closed or unjudged as it says: §8's other
// commit points (approval uses, FS-29's pin moves) and gkm's commits are not judged here, evs's heads alone.

package fault

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var _ = RegisterInvariant(3, func(ctx context.Context, oracle *Oracle) error {
	return checkFi3(ctx, oracle)
})

// The bounds FI-3 judges a commit by.
type Fi3Settings struct {
	// §10.6's window row: how long after a shrink or an expiry a push validated before it may still commit under the
	// generation it excludes: §11.8's bound, 5 min if api's notification is lost, plus §19.6's 10 s store request
	// deadline. Non-positive judges every commit against the state named at its own CAS.
	GateWindow time.Duration
	// §11.12's phase 1: how long after repo/ leaves active a push validated before the CAS may still land, two of
	// §11.8's 5 s validation windows plus §19.6's 10 s request deadline. Non-positive allows none.
	LifecycleWindow time.Duration
}

func DefaultFi3Settings() *Fi3Settings {
	return &Fi3Settings{
		GateWindow:      5*time.Minute + 10*time.Second,
		LifecycleWindow: 20 * time.Second,
	}
}

// What FI-3 keeps from one check to the next on one Net.
type fi3Memory struct {
	stateLock sync.Mutex
	settings  *Fi3Settings
	// each ref's versions judged, with the CAS time each was judged at
	judged map[HistoryRef]map[uint64]time.Time
	// each repo's repo/ state at the last check, and when it left active, once it did
	repoStates    map[sidecar.Id]protocol.EvsRepoState
	leftActiveAts map[sidecar.Id]time.Time
}

var fi3Memories sync.Map

func newFi3Memory() *fi3Memory {
	return &fi3Memory{
		settings:      DefaultFi3Settings(),
		judged:        map[HistoryRef]map[uint64]time.Time{},
		repoStates:    map[sidecar.Id]protocol.EvsRepoState{},
		leftActiveAts: map[sidecar.Id]time.Time{},
	}
}

// Sets the bounds net's FI-3 checks judge by; nil restores the defaults. A schedule that holds the gate's
// notification to its 10 s narrows GateWindow, so a commit the window's 5 min would excuse fails.
func SetFi3Settings(net *Net, settings *Fi3Settings) {
	memory := netMemoryOf(&fi3Memories, net, newFi3Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	if settings == nil {
		settings = DefaultFi3Settings()
	}
	memory.settings = settings
}

func checkFi3(ctx context.Context, oracle *Oracle) error {
	memory := netMemoryOf(&fi3Memories, oracle.Net, newFi3Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	evsMemory := evsOracleMemoryOf(oracle.Net)

	repos, walkErrs := evsStoreWalkOf(ctx, oracle)
	errs := []error{}
	if 0 < len(walkErrs) {
		errs = append(errs, fmt.Errorf("the store walk could not read every repo, so FI-3 judges none of their commits whole: %w", walkErrs[0]))
	}
	now := oracle.Net.Clock().Now()
	for _, repo := range repos {
		errs = append(errs, memory.noteLifecycle(repo, now)...)
		for _, ref := range repo.refs {
			if ref.head.Head.GetVersion() == 0 {
				continue
			}
			historyRef := HistoryRef{RepoId: repo.repoId, RefId: ref.refId}
			judged := memory.judged[historyRef]
			if judged == nil {
				judged = map[uint64]time.Time{}
				memory.judged[historyRef] = judged
			}
			fresh := false
			for _, version := range ref.versions {
				if version != nil {
					if _, ok := judged[version.version]; !ok {
						fresh = true
					}
				}
			}
			if !fresh {
				continue
			}
			casAt := fi3CasTime(oracle, repo, ref, now)
			errs = append(errs, memory.judgeRef(ctx, oracle, evsMemory, repo, ref, judged, casAt)...)
		}
	}
	return errors.Join(errs...)
}

// When this step's commits on the ref took effect: the time of its last successful head write in this step, which
// the clock holds still within a step, else the check's.
func fi3CasTime(oracle *Oracle, repo *evsStoreRepo, ref *evsStoreRef, now time.Time) time.Time {
	key := evsOracleRepoPrefix("head/", repo.repoId) + sidecar.EvsKeyId(ref.refId)
	casAt := now
	for _, entry := range oracle.Changed() {
		if entry.Key == key && entry.ClusterId == repo.clusterId && fi2IsWrite(entry.Op) &&
			(entry.Outcome == sidecartest.BlobOutcomeOk || entry.Outcome == sidecartest.BlobOutcomeUnknown) {
			casAt = entry.Invoked
		}
	}
	return casAt
}

// repo/'s state at this check, and when it first left active.
func (self *fi3Memory) noteLifecycle(repo *evsStoreRepo, now time.Time) []error {
	if repo.object == nil {
		return nil
	}
	state := repo.object.GetState()
	previous, seen := self.repoStates[repo.repoId]
	self.repoStates[repo.repoId] = state
	active := state == protocol.EvsRepoState_EVS_REPO_ACTIVE || state == protocol.EvsRepoState_EVS_REPO_KEYING
	switch {
	case active:
		delete(self.leftActiveAts, repo.repoId)
	case !seen || previous == protocol.EvsRepoState_EVS_REPO_ACTIVE || previous == protocol.EvsRepoState_EVS_REPO_KEYING:
		if _, left := self.leftActiveAts[repo.repoId]; !left {
			self.leftActiveAts[repo.repoId] = now
		}
	}
	return nil
}

// Every version of the ref not judged yet, judged at casAt, the ones before it read for its pins and epoch.
func (self *fi3Memory) judgeRef(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, repo *evsStoreRepo, ref *evsStoreRef, judged map[uint64]time.Time, casAt time.Time) []error {
	historyRef := HistoryRef{RepoId: repo.repoId, RefId: ref.refId}
	errs := []error{}
	history := evsMemory.authorizationHistoryOf(repo.networkId())
	currentEpoch := uint64(0)
	var previous *evsStoreVersion
	ladders := map[sidecar.Id][]*sidecar.GkmGeneration{}
	for _, version := range ref.versions {
		if version == nil {
			// a version the walk could not read, which FI-1 names: what follows is judged against what came before it
			previous = nil
			continue
		}
		push := version.statement.Push
		epoch := push.GetPathEpoch()
		pathEpoch := push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0
		_, done := judged[version.version]
		failf := func(format string, a ...any) {
			if !done {
				errs = append(errs, fmt.Errorf("%s v%d (push %s): "+format, append([]any{historyRef, version.version, version.entry.PushId}, a...)...))
			}
		}
		// the path epoch, against the history before it
		switch {
		case currentEpoch == 0:
		case pathEpoch && epoch <= currentEpoch:
			failf("a PATH_EPOCH to epoch %d on a ref at epoch %d", epoch, currentEpoch)
		case !pathEpoch && epoch != currentEpoch:
			failf("path epoch %d at its CAS, the ref's current %d: a stale path epoch", epoch, currentEpoch)
		}
		currentEpoch = max(currentEpoch, epoch)
		// pins never fall
		if previous != nil {
			prior := previous.statement.Push
			switch {
			case push.GetAuth().GetVersion() < prior.GetAuth().GetVersion():
				failf("auth pin %d below the head's %d: a pin fell", push.GetAuth().GetVersion(), prior.GetAuth().GetVersion())
			case push.GetAuth().GetVersion() == prior.GetAuth().GetVersion() && !bytes.Equal(push.GetAuth().GetChain(), prior.GetAuth().GetChain()):
				failf("auth pin %d under another chain than the head's", push.GetAuth().GetVersion())
			}
			switch {
			case push.GetGeneration() < prior.GetGeneration():
				failf("generation %d below the head's %d: a pin fell", push.GetGeneration(), prior.GetGeneration())
			case push.GetGeneration() == prior.GetGeneration() &&
				(!bytes.Equal(push.GetGroupId(), prior.GetGroupId()) || !bytes.Equal(push.GetGenerationCommitment(), prior.GetGenerationCommitment())):
				failf("generation %d under another group or commitment than the head's", push.GetGeneration())
			}
		}
		previous = version
		if done {
			continue
		}
		judged[version.version] = casAt
		// the generation pin
		groupId, err := sidecar.IdFromBytes(push.GetGroupId())
		if err != nil {
			failf("a generation pin naming no group")
			continue
		}
		ladder, ok := ladders[groupId]
		if !ok {
			ladder, err = oracle.View.Generations(ctx, groupId)
			if err != nil {
				failf("its group's generations: %v", err)
				continue
			}
			ladders[groupId] = ladder
		}
		index := slices.IndexFunc(ladder, func(generation *sidecar.GkmGeneration) bool {
			return generation.Rotate.GetGeneration() == push.GetGeneration()
		})
		if index < 0 {
			failf("generation %d of group %s, which no gen/ holds", push.GetGeneration(), groupId)
			continue
		}
		rotate := ladder[index].Rotate
		if !bytes.Equal(rotate.GetCommitment(), push.GetGenerationCommitment()) || !bytes.Equal(rotate.GetRepoId(), repo.repoId.Bytes()) {
			failf("generation %d pinned under a commitment or repo gen/%d does not hold", push.GetGeneration(), push.GetGeneration())
			continue
		}
		// the lifecycle at the CAS
		if leftAt, left := self.leftActiveAts[repo.repoId]; left && leftAt.Add(self.settings.LifecycleWindow).Before(casAt) {
			failf("committed at %s, %s after repo/ left active, past §11.12's %s", casAt.Format(time.RFC3339Nano), casAt.Sub(leftAt), self.settings.LifecycleWindow)
		}
		// the auth pin at the CAS, and the gate past its window
		if len(history) == 0 {
			failf("no authorization state is named for network %s, so its pins and gate cannot be judged at the CAS", repo.networkId())
			continue
		}
		var current, settled *evsAuthorizationAt
		for _, named := range history {
			if !named.at.After(casAt) {
				current = named
			}
			if !named.at.After(casAt.Add(-self.settings.GateWindow)) {
				settled = named
			}
		}
		if current == nil {
			failf("committed at %s, before any authorization state was named for network %s", casAt.Format(time.RFC3339Nano), repo.networkId())
			continue
		}
		if !current.view.OnChain(push.GetAuth()) {
			_, err := current.view.At(push.GetAuth())
			switch {
			case err == nil, errors.Is(err, sidecar.ErrGkmAuthNotRetained):
			case errors.Is(err, sidecar.ErrGkmAuthAhead):
				failf("auth pin %d above the state current at its CAS: a pin no state named yet", push.GetAuth().GetVersion())
			default:
				failf("auth pin %d off the authorization chain current at its CAS: %v", push.GetAuth().GetVersion(), err)
			}
		}
		if settled == nil {
			continue
		}
		if err := fi3Gate(settled.view, repo.repoId, rotate, casAt.Add(-self.settings.GateWindow)); err != nil {
			failf("generation %d, which the state named at %s excludes, past §10.6's window %s at its CAS at %s: %v", push.GetGeneration(), settled.at.Format(time.RFC3339Nano), self.settings.GateWindow, casAt.Format(time.RFC3339Nano), err)
		}
	}
	return errs
}

// §10.6's pass row from its text: the generation whose GenRotate is rotate covers the repo's holders_shrunk_at in
// state, and no reader of the repo at the generation's time had stopped reading by at. nil when it passes, or when
// the state holds no row of the repo.
func fi3Gate(state sidecar.GkmAuthView, repoId sidecar.Id, rotate *protocol.GenRotate, at time.Time) error {
	row := state.Repo(repoId)
	if row == nil {
		return nil
	}
	if shrunkAt := row.GetHoldersShrunkAt(); rotate.GetAuth().GetVersion() < shrunkAt {
		return fmt.Errorf("its pin %d does not cover holders_shrunk_at %d", rotate.GetAuth().GetVersion(), shrunkAt)
	}
	generationTime := time.UnixMilli(rotate.GetTimeMs())
	if !generationTime.Before(at) {
		return nil
	}
	readers := state.RepoReadersAt(repoId, at)
	for _, reader := range state.RepoReadersAt(repoId, generationTime) {
		if !slices.Contains(readers, reader) {
			return fmt.Errorf("reader %s of the generation's time had stopped reading by %s", reader, at.Format(time.RFC3339Nano))
		}
	}
	return nil
}
