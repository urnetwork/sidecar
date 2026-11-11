// A mirror's coverage, which mirrors this device keeps, and `ur status`'s coverage lines (§11.13's status row,
// D-EVS-17, R-EVS-17, owner decision 150; EVSB-M2-19).
//
//	full      every ref evs lists is mirrored: the mirror holds its head, or lacks only versions younger than
//	          HeadLag (1 h); no object or slot a mirrored push names is missing; every ERASE the mirror holds is
//	          applied, with no slot copy waiting to be read again; and a hash check found nothing within CheckMaxAge
//	          (7 days)
//	partial   anything else, each reason named: the refs behind and since when, the missing objects by family, a
//	          head evs answered below the mirror, ERASEs held but not applied, the generations gkm gave no key for,
//	          no hash check or a stale or failed one
//
// Who mirrors (§11.13's durability row, §3.6): indexers designated for `mirror` first, an IndexerSet whose sealed
// services name INDEXER_SERVICE_MIRROR. A member-scope indexer mirrors its member's owner-bound record-class repos
// (vault, mailbox, secret) that it reads; a network-scope one, designated by an Owner's or Admin's device, mirrors the
// config and every other record-class repo it reads (team records, ledgers, the directory, mailcfg). A device with no
// such designation mirrors nothing unasked. A phone-only user has no indexer (owner decisions 12, 197): its app's
// `mailcfg`, `vault/` and `i/` mirroring are §15.7's and §18's, not this file's.
//
// `ur status` names each repo this device mirrors with its coverage, each record-class repo and config no
// designated mirror indexer covers as unmirrored, a network no indexer mirrors, and each indexer with its services
// and the newest sign of it this device holds. Lines carry ids and counts, never a name or a path (I-13).

package sidecar

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// One ref's coverage.
type EvsMirrorRefCoverage struct {
	RefId Id
	// What evs answers as the head, and what the mirror holds of it.
	HeadVersion     uint64
	MirroredVersion uint64
	MirroredAt      time.Time
	// The oldest version the mirror lacks, zero when it holds the head.
	FirstMissingAt time.Time
	// The mirror holds the head, or lacks only versions under HeadLag old.
	Mirrored bool
	// evs answered a head below the mirror, or forking from it.
	Lower bool
}

// A repo's coverage as §11.13's status row reads it.
type EvsMirrorCoverage struct {
	RepoId Id
	Full   bool
	Refs   []*EvsMirrorRefCoverage
	// Objects a mirrored push names that the mirror does not hold, all told, and the first of them by name.
	MissingCount int
	Missing      []*EvsMirrorMissing
	// Slot copies an ERASE removed that a sync has not yet read again from evs.
	StaleSlotCount int
	// Generations a mirrored push names whose key gkm did not give.
	KeyGenerationsMissing []uint64
	// The newest hash check, zero for none, and what it found wrong.
	CheckedAt     time.Time
	CheckFailures []string
	SyncedAt      time.Time
	// Each reason the coverage is partial, as a person reads it: ids and counts only.
	Reasons []string
}

// The mirror's coverage now: evs's heads read fresh against what the mirror holds and its last sync and check found.
// A ref evs lists that the mirror holds nothing of is behind from its first version.
func (self *EvsMirror) Coverage(ctx context.Context) (*EvsMirrorCoverage, error) {
	self.runLock.Lock()
	state, err := self.loadState()
	self.runLock.Unlock()
	if err != nil {
		return nil, err
	}
	heads, err := self.listHeads(ctx)
	if err != nil {
		return nil, err
	}
	now := self.client.clock.Now()
	coverage := &EvsMirrorCoverage{
		RepoId:                self.repoId,
		MissingCount:          state.MissingCount,
		Missing:               state.Missing,
		StaleSlotCount:        len(state.StaleSlotIds),
		KeyGenerationsMissing: state.KeyGenerationsMissing,
		CheckFailures:         state.CheckFailures,
	}
	if state.CheckedMs != 0 {
		coverage.CheckedAt = time.UnixMilli(state.CheckedMs).UTC()
	}
	if state.SyncedMs != 0 {
		coverage.SyncedAt = time.UnixMilli(state.SyncedMs).UTC()
	}
	refStates := map[Id]*EvsMirrorRefState{}
	for _, refState := range state.Refs {
		refStates[refState.RefId] = refState
	}
	reasons := []string{}
	for _, head := range heads {
		refId, _ := IdFromBytes(head.GetRefId())
		refCoverage := &EvsMirrorRefCoverage{RefId: refId, HeadVersion: head.GetVersion()}
		held, ok, err := self.store.Ref(refId)
		if err != nil {
			return nil, err
		}
		if ok {
			refCoverage.MirroredVersion = held.Version
			refCoverage.MirroredAt = held.MirroredAt
		}
		refState := refStates[refId]
		if refState != nil && refState.Lower {
			refCoverage.Lower = true
		}
		headChain, _ := EvsChainFromBytes(head.GetChain())
		switch {
		case refCoverage.Lower || head.GetVersion() < refCoverage.MirroredVersion || (ok && head.GetVersion() == held.Version && headChain != held.Chain):
			refCoverage.Lower = true
			reasons = append(reasons, fmt.Sprintf("ref %s: evs answers a head below the mirror's version %d", refId, refCoverage.MirroredVersion))
		case head.GetVersion() == refCoverage.MirroredVersion:
			refCoverage.Mirrored = true
		default:
			// behind: how long, by the oldest version the mirror lacks
			firstMissing, known, err := self.firstMissingTime(ctx, refId, refCoverage.MirroredVersion+1, refState)
			if err != nil {
				return nil, err
			}
			if known {
				refCoverage.FirstMissingAt = firstMissing
				refCoverage.Mirrored = now.Sub(firstMissing) < self.settings.HeadLag
			}
			if !refCoverage.Mirrored {
				since := "an unknown time"
				if known {
					since = firstMissing.Format(time.RFC3339)
				}
				reasons = append(reasons, fmt.Sprintf("ref %s: %d versions behind its head, the oldest from %s", refId, head.GetVersion()-refCoverage.MirroredVersion, since))
			}
		}
		coverage.Refs = append(coverage.Refs, refCoverage)
	}
	if 0 < state.MissingCount {
		families := map[EvsMirrorFamily]int{}
		for _, missing := range state.Missing {
			families[missing.Family] += 1
		}
		named := []string{}
		for _, family := range []EvsMirrorFamily{EvsMirrorRecords, EvsMirrorSegments, EvsMirrorSlots, EvsMirrorMapParts} {
			if 0 < families[family] {
				named = append(named, fmt.Sprintf("%d %s", families[family], family))
			}
		}
		reasons = append(reasons, fmt.Sprintf("%d objects missing (%s)", state.MissingCount, strings.Join(named, ", ")))
	}
	if 0 < len(state.StaleSlotIds) {
		reasons = append(reasons, fmt.Sprintf("%d slot copies an ERASE removed not yet read again", len(state.StaleSlotIds)))
	}
	if 0 < len(state.KeyGenerationsMissing) {
		reasons = append(reasons, fmt.Sprintf("no key held for %d generations", len(state.KeyGenerationsMissing)))
	}
	switch {
	case state.CheckedMs == 0:
		reasons = append(reasons, "no hash check yet")
	case self.settings.CheckMaxAge < now.Sub(coverage.CheckedAt):
		reasons = append(reasons, "no hash check since "+coverage.CheckedAt.Format(time.RFC3339))
	}
	if 0 < len(state.CheckFailures) {
		reasons = append(reasons, fmt.Sprintf("the last hash check found %d objects wrong", len(state.CheckFailures)))
	}
	coverage.Reasons = reasons
	coverage.Full = len(reasons) == 0
	return coverage, nil
}

// The time of version, the oldest the mirror lacks of refId: its statement's time_ms, from the state's last sync when
// it saw it, else read from evs's log. False when evs serves no such statement.
func (self *EvsMirror) firstMissingTime(ctx context.Context, refId Id, version uint64, refState *EvsMirrorRefState) (time.Time, bool, error) {
	if refState != nil && refState.FirstMissingMs != 0 {
		return time.UnixMilli(refState.FirstMissingMs).UTC(), true, nil
	}
	statements, err := self.client.readLog(ctx, self.repoId, refId, version, version)
	if err != nil {
		return time.Time{}, false, err
	}
	for _, read := range statements {
		if read.GetVersion() != version {
			continue
		}
		statement, err := self.client.verifier.VerifyStatement(read.GetStatement(), self.repoId, refId)
		if err != nil {
			return time.Time{}, false, nil
		}
		return evsTime(statement.Push.GetTimeMs()), true, nil
	}
	return time.Time{}, false, nil
}

// A config indexer's services, opened with the config's generation key; false when the caller cannot open them.
type EvsMirrorServicesFunction func(indexer ConfigIndexer) ([]protocol.IndexerService, bool)

// Whether an indexer's services name the mirror.
func evsMirrorDesignated(indexer ConfigIndexer, services EvsMirrorServicesFunction) bool {
	if services == nil {
		return false
	}
	named, ok := services(indexer)
	return ok && slices.Contains(named, protocol.IndexerService_INDEXER_SERVICE_MIRROR)
}

// The repos the projection holds at state, by id.
func evsMirrorProjectedRepos(state *ConfigState) []*protocol.AclRepo {
	if state == nil || state.aclRows == nil {
		return nil
	}
	repos := slices.Clone(state.aclRows.GetRepos())
	slices.SortFunc(repos, func(a *protocol.AclRepo, b *protocol.AclRepo) int {
		return strings.Compare(string(a.GetRepoId()), string(b.GetRepoId()))
	})
	return repos
}

// Whether a repo of kind is one full mirrors keep: a record-class repo, or the config (§11.13's durability row).
func EvsMirrorKeptKind(kind protocol.RepoKind) bool {
	return kind == protocol.RepoKind_REPO_KIND_CONFIG || EvsRepoKindRecordClass(kind)
}

// The repos the indexer, designated for mirror at state, keeps full mirrors of: at member scope its member's
// owner-bound record-class repos it reads, at network scope the config and every other record-class repo it reads.
func evsMirrorIndexerRepos(state *ConfigState, indexer ConfigIndexer) []Id {
	row := state.SidecarRow(indexer.SidecarId)
	if row == nil {
		return nil
	}
	memberId, memberErr := IdFromBytes(row.GetMemberId())
	repoIds := []Id{}
	for _, repo := range evsMirrorProjectedRepos(state) {
		repoId, err := IdFromBytes(repo.GetRepoId())
		if err != nil || !EvsMirrorKeptKind(repo.GetKind()) {
			continue
		}
		if !slices.Contains(state.RepoReaders(repoId), indexer.SidecarId) {
			continue
		}
		ownerBound := aclRepoKindOwnerBound(repo.GetKind())
		switch indexer.Scope {
		case protocol.IndexerScope_INDEXER_SCOPE_MEMBER:
			ownerId, err := IdFromBytes(repo.GetOwnerMemberId())
			if !ownerBound || err != nil || memberErr != nil || ownerId != memberId {
				continue
			}
		case protocol.IndexerScope_INDEXER_SCOPE_NETWORK:
			if ownerBound {
				continue
			}
		default:
			continue
		}
		repoIds = append(repoIds, repoId)
	}
	return repoIds
}

// The repos this device keeps full mirrors of at state, by the designations naming it for mirror; empty for a device
// with none, which mirrors nothing unasked.
func EvsMirrorPlan(state *ConfigState, sidecarId Id, services EvsMirrorServicesFunction) []Id {
	if state == nil {
		return nil
	}
	repoIdSet := map[Id]bool{}
	for _, indexer := range state.Indexers() {
		if indexer.SidecarId != sidecarId || !evsMirrorDesignated(indexer, services) {
			continue
		}
		for _, repoId := range evsMirrorIndexerRepos(state, indexer) {
			repoIdSet[repoId] = true
		}
	}
	repoIds := make([]Id, 0, len(repoIdSet))
	for repoId := range repoIdSet {
		repoIds = append(repoIds, repoId)
	}
	slices.SortFunc(repoIds, func(a Id, b Id) int { return a.Cmp(b) })
	return repoIds
}

// What `ur status`'s coverage lines are built from.
type EvsMirrorStatusArgs struct {
	// The newest verified config state.
	State *ConfigState
	// This device.
	SidecarId Id
	// Opens an indexer's sealed services.
	Services EvsMirrorServicesFunction
	// The newest statement or witness of the sidecar this device holds; false for none.
	NewestSign func(sidecarId Id) (time.Time, bool)
	// The mirror this device keeps of a repo, nil for one it keeps none of.
	Mirror func(repoId Id) *EvsMirror
}

// `ur status`'s coverage lines for one network, in a fixed order: each repo this device mirrors with its coverage,
// each kept-kind repo no designated mirror indexer covers, a network no indexer mirrors, then each indexer. A
// coverage read that fails is named as such, never shown full.
func EvsMirrorStatusLines(ctx context.Context, args *EvsMirrorStatusArgs) ([]string, error) {
	if args == nil || args.State == nil {
		return nil, errors.New("evs: no verified config state for coverage")
	}
	state := args.State
	lines := []string{}
	for _, repoId := range EvsMirrorPlan(state, args.SidecarId, args.Services) {
		var mirror *EvsMirror
		if args.Mirror != nil {
			mirror = args.Mirror(repoId)
		}
		if mirror == nil {
			lines = append(lines, fmt.Sprintf("coverage:   repo %s none: this device is designated to mirror it and holds no mirror", repoId))
			continue
		}
		coverage, err := mirror.Coverage(ctx)
		if err != nil {
			lines = append(lines, fmt.Sprintf("coverage:   repo %s unknown: %s", repoId, err))
			continue
		}
		if coverage.Full {
			lines = append(lines, fmt.Sprintf("coverage:   repo %s full", repoId))
			continue
		}
		lines = append(lines, fmt.Sprintf("coverage:   repo %s partial: %s", repoId, strings.Join(coverage.Reasons, "; ")))
	}
	mirrorIndexers := []ConfigIndexer{}
	covered := map[Id]bool{}
	for _, indexer := range state.Indexers() {
		if !evsMirrorDesignated(indexer, args.Services) {
			continue
		}
		mirrorIndexers = append(mirrorIndexers, indexer)
		for _, repoId := range evsMirrorIndexerRepos(state, indexer) {
			covered[repoId] = true
		}
	}
	for _, repo := range evsMirrorProjectedRepos(state) {
		repoId, err := IdFromBytes(repo.GetRepoId())
		if err != nil || !EvsMirrorKeptKind(repo.GetKind()) || covered[repoId] {
			continue
		}
		lines = append(lines, fmt.Sprintf("unmirrored: repo %s (%s): no indexer designated for mirror keeps it", repoId, evsMirrorKindName(repo.GetKind())))
	}
	if len(mirrorIndexers) == 0 {
		lines = append(lines, fmt.Sprintf("unmirrored: network %s: no indexer is designated for mirror, so a site loss loses what no device holds", state.NetworkId()))
	}
	for _, indexer := range state.Indexers() {
		services := "services unreadable"
		if args.Services != nil {
			if named, ok := args.Services(indexer); ok {
				names := []string{}
				for _, service := range named {
					names = append(names, evsMirrorServiceName(service))
				}
				services = "services " + strings.Join(names, ", ")
				if len(names) == 0 {
					services = "no services"
				}
			}
		}
		sign := "no sign of it held"
		if args.NewestSign != nil {
			if at, ok := args.NewestSign(indexer.SidecarId); ok {
				sign = "newest sign " + at.UTC().Format(time.RFC3339)
			}
		}
		lines = append(lines, fmt.Sprintf("indexer:    %s (%s scope): %s; %s", indexer.SidecarId, evsMirrorScopeName(indexer.Scope), services, sign))
	}
	return lines, nil
}

func evsMirrorKindName(kind protocol.RepoKind) string {
	return strings.ToLower(strings.TrimPrefix(kind.String(), "REPO_KIND_"))
}

func evsMirrorServiceName(service protocol.IndexerService) string {
	return strings.ToLower(strings.TrimPrefix(service.String(), "INDEXER_SERVICE_"))
}

func evsMirrorScopeName(scope protocol.IndexerScope) string {
	return strings.ToLower(strings.TrimPrefix(scope.String(), "INDEXER_SCOPE_"))
}
