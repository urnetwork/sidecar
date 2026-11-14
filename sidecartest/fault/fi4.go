// FI-4, one ladder (§22.8; §10.5's generations, §10.6's gen/ and epoch objects, §10.8, I-16; D-TEST-10): each
// generation has one authenticated parent and commitment C_g, whichever path raised it (a leaf's commit or a wrapped
// rotation), every reader converges on it, and none regresses. Read from the store and the ledger (ledger.go):
//
//   - each group's gen/ objects on the first metadata cluster form one ladder: gen/1 to gen/n with none missing,
//     gen/1 naming no parent and each gen/g naming gen/(g-1)'s commitment, each a Signed GenRotate of this group,
//     generation and one repo, its signature verifying under the identity key the authorization state admits for its
//     signer (the state a schedule named for the repo's network with SetAuthorizationView, fi1.go);
//   - none changes or goes: a gen/<g> any check read keeps its bytes at every later check, so a generation never
//     takes a second parent or commitment, and none is deleted but by its repo's shred (repo/ shredding or shredded);
//   - each epoch object's commit header names a generation the group holds, at or above the header before it, but a
//     recovery self-join's generation 0 with no GenWrap (§10.8; FS-15, FS-20), the one permitted lower header;
//   - every key holding the ledger holds (Ledger.RecordKeyHolding) names a generation the group holds under gen/g's
//     commitment, and no holder's generation of a group falls from one report to the next.
//
// It reads gen/ straight from the store, never through gkm or a client, and shares no code with KEYS-M2-29's
// DeliveryOracle (FI-28). Readings: a group whose repo the store does not place is authenticated against every state
// named, any that admits the signer passing, since gkm's own worlds keep no repo/; a holder reports only what its
// client confirmed against gen/<g>, so a report of a generation no gen/ holds is two ladders, not a lost race.
// Gaps: holdings come only from schedules that record them, and none of KEYS's rows does yet; a holder's ReaderKeys
// and held RK_g (testHookSecret) are not read for convergence, since a held key names no group.

package fault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ = RegisterInvariant(4, func(ctx context.Context, oracle *Oracle) error {
	return checkFi4(ctx, oracle)
})

// What FI-4 keeps from one check to the next on one Net.
type fi4Memory struct {
	stateLock sync.Mutex
	// each group's generations as any check read them: their bytes' hash, by generation
	generations map[sidecar.Id]map[uint64][sha256.Size]byte
	// each holder's newest generation of each group, and how many of the ledger's holdings were judged
	holderGenerations map[string]map[sidecar.Id]uint64
	holdingsChecked   int
}

var fi4Memories sync.Map

func newFi4Memory() *fi4Memory {
	return &fi4Memory{
		generations:       map[sidecar.Id]map[uint64][sha256.Size]byte{},
		holderGenerations: map[string]map[sidecar.Id]uint64{},
	}
}

// One group's ladder as this check read it.
type fi4Ladder struct {
	groupId sidecar.Id
	// by generation, from 1
	generations map[uint64]*sidecar.GkmGeneration
	newest      uint64
}

func checkFi4(ctx context.Context, oracle *Oracle) error {
	memory := netMemoryOf(&fi4Memories, oracle.Net, newFi4Memory)
	memory.stateLock.Lock()
	defer memory.stateLock.Unlock()
	evsMemory := evsOracleMemoryOf(oracle.Net)

	clusterId, err := oracle.View.FirstClusterId()
	if err != nil {
		return err
	}
	groupIds, err := fi4Groups(ctx, oracle, clusterId)
	if err != nil {
		return err
	}
	for groupId := range memory.generations {
		groupIds[groupId] = true
	}
	errs := []error{}
	ladders := map[sidecar.Id]*fi4Ladder{}
	for groupId := range groupIds {
		ladder, ladderErrs := memory.readLadder(ctx, oracle, evsMemory, clusterId, groupId)
		errs = append(errs, ladderErrs...)
		ladders[groupId] = ladder
		errs = append(errs, fi4CheckHeaders(ctx, oracle, clusterId, ladder)...)
	}
	holdings := LedgerOf(oracle.Net).KeyHoldings()
	for _, holding := range holdings[min(memory.holdingsChecked, len(holdings)):] {
		errs = append(errs, memory.checkHolding(ladders[holding.GroupId], holding)...)
	}
	memory.holdingsChecked = len(holdings)
	return errors.Join(errs...)
}

// Every group the first cluster holds a gen/ of: gkm/<group_id>/gen/<g>.
func fi4Groups(ctx context.Context, oracle *Oracle, clusterId string) (map[sidecar.Id]bool, error) {
	infos, err := oracle.View.List(ctx, clusterId, "gkm/")
	if err != nil {
		return nil, err
	}
	groupIds := map[sidecar.Id]bool{}
	for _, info := range infos {
		rest, ok := strings.CutPrefix(info.Key, "gkm/")
		if !ok {
			continue
		}
		groupHex, after, ok := strings.Cut(rest, "/")
		if !ok || !strings.HasPrefix(after, "gen/") {
			continue
		}
		groupBytes, err := hex.DecodeString(groupHex)
		if err != nil {
			continue
		}
		groupId, err := sidecar.IdFromBytes(groupBytes)
		if err != nil {
			continue
		}
		groupIds[groupId] = true
	}
	return groupIds, nil
}

// One group's gen/ objects read, held to one ladder, authenticated, and to what earlier checks read of them.
func (self *fi4Memory) readLadder(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, clusterId string, groupId sidecar.Id) (*fi4Ladder, []error) {
	ladder := &fi4Ladder{groupId: groupId, generations: map[uint64]*sidecar.GkmGeneration{}}
	errs := []error{}
	failf := func(format string, a ...any) {
		errs = append(errs, fmt.Errorf("group %s: "+format, append([]any{groupId}, a...)...))
	}
	prefix := strings.TrimSuffix(sidecar.GkmGenerationPath(groupId, 0), storeKeyNumber(0))
	objects, err := oracle.View.Objects(ctx, clusterId, prefix)
	if err != nil {
		failf("its gen/: %v", err)
		return ladder, errs
	}
	seen := self.generations[groupId]
	if seen == nil {
		seen = map[uint64][sha256.Size]byte{}
		self.generations[groupId] = seen
	}
	bodies := map[uint64][]byte{}
	var repoId sidecar.Id
	for _, object := range objects {
		number, err := strconv.ParseUint(strings.TrimPrefix(object.Key, prefix), 10, 64)
		if err != nil {
			failf("%s names no generation", object.Key)
			continue
		}
		generation, err := DecodeStoreGeneration(object.Body)
		if err != nil {
			failf("gen/%d: %v", number, err)
			continue
		}
		rotate := generation.Rotate
		if !bytes.Equal(rotate.GetGroupId(), groupId.Bytes()) || rotate.GetGeneration() != number {
			failf("gen/%d holds generation %d of another group", number, rotate.GetGeneration())
			continue
		}
		rotateRepoId, err := sidecar.IdFromBytes(rotate.GetRepoId())
		switch {
		case err != nil:
			failf("gen/%d names no repo", number)
		case repoId == (sidecar.Id{}):
			repoId = rotateRepoId
		case repoId != rotateRepoId:
			failf("gen/%d names repo %s, and the group's other generations repo %s: two ladders", number, rotateRepoId, repoId)
		}
		ladder.generations[number] = generation
		ladder.newest = max(ladder.newest, number)
		bodies[number] = object.Body
		digest := sha256.Sum256(object.Body)
		if held, ok := seen[number]; ok && held != digest {
			failf("gen/%d changed since an earlier check read it: a generation took a second parent or commitment", number)
		}
		seen[number] = digest
	}
	// none goes but by a shred
	shredded := repoId != (sidecar.Id{}) && fi4RepoShredding(ctx, oracle, repoId)
	for number := range seen {
		if ladder.generations[number] == nil && !shredded {
			failf("gen/%d, which an earlier check read, is gone: a generation regressed", number)
		}
	}
	// one ladder
	for number := uint64(1); number <= ladder.newest; number += 1 {
		generation := ladder.generations[number]
		if generation == nil {
			if !shredded {
				failf("gen/%d is missing below gen/%d", number, ladder.newest)
			}
			continue
		}
		parent := generation.Rotate.GetParentCommitment()
		switch {
		case number == 1 && len(parent) != 0:
			failf("gen/1 names a parent")
		case 1 < number && ladder.generations[number-1] != nil && !bytes.Equal(parent, ladder.generations[number-1].Rotate.GetCommitment()):
			failf("gen/%d names another parent than gen/%d's commitment: two parents for one generation", number, number-1)
		}
	}
	// authenticated
	views := fi4ViewsOf(ctx, oracle, evsMemory, repoId)
	if len(views) == 0 && 0 < len(ladder.generations) {
		failf("no authorization state is named for its repo's network, so no gen/ signer can be authenticated")
		return ladder, errs
	}
	for number, body := range bodies {
		authenticated := false
		var lastErr error
		for _, view := range views {
			if _, err := sidecar.ParseGenRotate(body, groupId, number, sidecar.GkmIdentityKeys(view)); err != nil {
				lastErr = err
				continue
			}
			authenticated = true
			break
		}
		if !authenticated {
			failf("gen/%d is signed by %s, whom no named state admits, or does not verify: %v", number, ladder.generations[number].SignerId, lastErr)
		}
	}
	return ladder, errs
}

// The states a group's gen/ signers are authenticated against: its repo's network's newest, where the store places
// the repo and a state is named for that network; else every network's newest state named.
func fi4ViewsOf(ctx context.Context, oracle *Oracle, evsMemory *evsOracleMemory, repoId sidecar.Id) []sidecar.GkmAuthView {
	if repoId != (sidecar.Id{}) {
		if repo := fi4RepoObject(ctx, oracle, repoId); repo != nil {
			if networkId, err := sidecar.IdFromBytes(repo.GetNetworkId()); err == nil {
				if view := evsMemory.authorizationView(networkId); view != nil {
					return []sidecar.GkmAuthView{view}
				}
			}
		}
	}
	views := []sidecar.GkmAuthView{}
	for _, view := range evsMemory.authorizationViewsNamed() {
		views = append(views, view)
	}
	return views
}

// repo/ of a placed repo, nil where the store does not place it or holds none.
func fi4RepoObject(ctx context.Context, oracle *Oracle, repoId sidecar.Id) *protocol.EvsRepoObject {
	clusterId, err := oracle.View.RepoClusterId(ctx, repoId)
	if err != nil || clusterId == "" {
		return nil
	}
	object, err := oracle.View.Object(ctx, clusterId, sidecar.EvsRepoObjectKey(repoId))
	if err != nil || object == nil {
		return nil
	}
	repo := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(object.Body, repo); err != nil {
		return nil
	}
	return repo
}

// Whether the repo's shred began, after which its gkm objects go.
func fi4RepoShredding(ctx context.Context, oracle *Oracle, repoId sidecar.Id) bool {
	repo := fi4RepoObject(ctx, oracle, repoId)
	return repo != nil && (repo.GetState() == protocol.EvsRepoState_EVS_REPO_SHREDDING || repo.GetState() == protocol.EvsRepoState_EVS_REPO_SHREDDED)
}

// Each epoch object's commit header names a generation the ladder holds, at or above the one before it, but a
// recovery self-join's 0 with no GenWrap.
func fi4CheckHeaders(ctx context.Context, oracle *Oracle, clusterId string, ladder *fi4Ladder) []error {
	prefix := "gkm/" + sidecar.EvsKeyId(ladder.groupId) + "/epoch/"
	objects, err := oracle.View.Objects(ctx, clusterId, prefix)
	if err != nil {
		return []error{fmt.Errorf("group %s's epochs: %w", ladder.groupId, err)}
	}
	errs := []error{}
	floor := uint64(0)
	for _, object := range objects {
		epoch, err := strconv.ParseUint(strings.TrimPrefix(object.Key, prefix), 10, 64)
		if err != nil {
			continue
		}
		decoded := &protocol.GkmEpochObject{}
		if err := proto.Unmarshal(object.Body, decoded); err != nil {
			errs = append(errs, fmt.Errorf("group %s epoch %d: %w", ladder.groupId, epoch, err))
			continue
		}
		generation := decoded.GetHeader().GetGeneration()
		switch {
		case generation == 0 && 0 < epoch && len(decoded.GetGenWrap()) == 0:
			// a recovery self-join, the one permitted lower header
			continue
		case generation == 0:
			errs = append(errs, fmt.Errorf("group %s epoch %d names generation 0 with a GenWrap, or at the creation", ladder.groupId, epoch))
		case ladder.generations[generation] == nil:
			errs = append(errs, fmt.Errorf("group %s epoch %d names generation %d, which no gen/ holds", ladder.groupId, epoch, generation))
		case generation < floor:
			errs = append(errs, fmt.Errorf("group %s epoch %d names generation %d below the %d an earlier epoch named: a header regressed", ladder.groupId, epoch, generation, floor))
		}
		floor = max(floor, generation)
	}
	return errs
}

// One holder's report held to the ladder and to its own reports before it.
func (self *fi4Memory) checkHolding(ladder *fi4Ladder, holding *KeyHolding) []error {
	errs := []error{}
	if ladder == nil || ladder.generations[holding.Generation] == nil {
		errs = append(errs, fmt.Errorf("%s holds generation %d of group %s, which no gen/ holds: two ladders", holding.Holder, holding.Generation, holding.GroupId))
	} else if !bytes.Equal(ladder.generations[holding.Generation].Rotate.GetCommitment(), holding.Commitment) {
		errs = append(errs, fmt.Errorf("%s holds generation %d of group %s under another commitment than gen/%d's: it did not converge on the one ladder", holding.Holder, holding.Generation, holding.GroupId, holding.Generation))
	}
	groups := self.holderGenerations[holding.Holder]
	if groups == nil {
		groups = map[sidecar.Id]uint64{}
		self.holderGenerations[holding.Holder] = groups
	}
	if previous := groups[holding.GroupId]; holding.Generation < previous {
		errs = append(errs, fmt.Errorf("%s holds generation %d of group %s after %d: a reader regressed", holding.Holder, holding.Generation, holding.GroupId, previous))
	}
	groups[holding.GroupId] = max(groups[holding.GroupId], holding.Generation)
	return errs
}
