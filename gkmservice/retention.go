// The reconciler's sweeps (§10.6's retention and staged GC rows, §2.8's TTLs; Q-KEYS-11, D-KEYS-20, FI-6): a taskworker
// job that walks each metadata cluster's gkm/ keys from a cursor the task framework keeps between runs, a page of
// units a run, so the work one run examines is bounded however large gkm grows (connect/CODESTYLE.md's load rules).
// A unit is one group's objects, one sidecar's KeyPackages, ReaderKey or Welcome pointers, or one member's recovery
// wraps. In each:
//
//	epochs     epoch/<n> goes once it is EpochRetention (30 d) old and every ack written in the last 30 d has passed
//	           n, never the newest, and only while {gka_<group_id>} has existed 30 d, so a lost family deletes
//	           nothing for 30 d; before the epoch group-info names goes, the pointer moves to the newest epoch that
//	           carries a GroupInfo, or the epoch stays
//	staged     a delivery or recovery wrap whose c8 is not gen/<g>'s, or of a g gen/ never claimed, goes once 24 h
//	           old (a lost claim's)
//	wraps      a generation's deliveries go once gen/<g+1> exists, whose deliveries all precede its claim (gkm-7); a
//	           recipient's delivery of g to an older key goes 30 d after one to a newer key
//	Welcomes   a group's welcome/<n> goes at 90 d (gkm-5); a pointer once its recipient's ack has passed n, or at 90 d
//	KeyPackages a KeyPackage or claim goes at 90 d (gkm-4), a revoked sidecar's KeyPackages at once (§10.4), and a
//	           claimed one-time KeyPackage a failed delete left beside its claim
//	ReaderKeys a ReaderKey goes once past its not_after (gkm-4)
//
// A preservation hold covering a unit's repo, or its network for a sidecar's or member's objects, pauses every
// deletion in it (§21.9, owner decision 133), and so does anything whose network or repo the sweep cannot tell:
// every doubt keeps data. A user's shred is not a sweep and no hold pauses it (shred.go).
//
// Every delete and the pointer's move is §11.13's unfunded P2 (budget.go): epoch retention, the pointer and §2.8's
// TTLs at rank retention, a lost claim's staged deliveries and recovery wraps at rank GC. Each waits for its turn in
// the budget within the run's MaxTime, and when its turn comes it checks the unit's hold again (WriteP2Work.Recheck),
// so a hold placed while it waited still pauses it. While a page runs it declares SweepBacklogByteCount as its
// unfunded backlog on each metadata cluster, so the governor shares the unfunded allowance with it; the sweep cannot
// know its real backlog before it lists, so this is an estimate, cleared when the page ends.
//
// What this does not do yet: delete a Welcome before 90 d once every recipient has acked it, since gkm keeps no list
// of a Welcome's recipients beside their pointers (gkm-5's "until every recipient has acked"); pointers do go at their
// recipient's ack.

package gkmservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The sweep's job name in taskworker's queue, and its once key: one sweep at a time.
const GkmReconcilerSweepTaskName = "gkm_reconciler_sweep"

// The character past every character a gkm key holds, so <prefix>~ sorts after every key under <prefix>.
const gkmKeyPastSuffix = "~"

// Where a sweep resumes, which the task framework stores between runs: a metadata cluster by its index among
// MetadataClusterIds, and the last key the sweep passed there. Ids and positions only (§19.4's task args).
type GkmSweepCursor struct {
	ClusterIndex int    `json:"cluster"`
	After        string `json:"after"`
}

// Registers the sweep with host.Tasks and schedules its first run, a new pass from the start.
func (self *GkmReconciler) RegisterSweep(ctx context.Context) error {
	tasks := self.host.Tasks
	if tasks == nil {
		return errors.New("gkm's reconciler needs a host with Tasks to sweep")
	}
	tasks.Register(GkmReconcilerSweepTaskName, self.runSweepTask)
	return self.scheduleSweep(ctx, &GkmSweepCursor{}, time.Time{})
}

// Schedules the sweep's next run at runAt from cursor.
func (self *GkmReconciler) scheduleSweep(ctx context.Context, cursor *GkmSweepCursor, runAt time.Time) error {
	args, err := json.Marshal(cursor)
	if err != nil {
		return err
	}
	return self.host.Tasks.Schedule(ctx, &sidecar.TaskRequest{
		Name:    GkmReconcilerSweepTaskName,
		OnceKey: GkmReconcilerSweepTaskName,
		Args:    args,
		RunAt:   runAt,
		MaxTime: self.settings.SweepRunTime,
	})
}

// One run: a page from the cursor in args, then the next run, at once while the pass has more, else a new pass
// after SweepInterval. An error reruns this page after the host's backoff.
func (self *GkmReconciler) runSweepTask(ctx context.Context, args []byte) error {
	cursor := &GkmSweepCursor{}
	if 0 < len(args) {
		if err := json.Unmarshal(args, cursor); err != nil {
			// a cursor that does not parse starts the pass over, which deletes nothing early
			cursor = &GkmSweepCursor{}
		}
	}
	next, done, err := self.SweepPage(ctx, cursor)
	if err != nil {
		return err
	}
	if done {
		return self.scheduleSweep(ctx, &GkmSweepCursor{}, self.clock.Now().Add(self.settings.SweepInterval))
	}
	return self.scheduleSweep(ctx, next, time.Time{})
}

// One page of a pass: up to SweepUnitCount units from cursor. done is true once every cluster's gkm/ keys have been
// passed. An error leaves the cursor where it was, so the page runs again.
func (self *GkmReconciler) SweepPage(ctx context.Context, cursor *GkmSweepCursor) (*GkmSweepCursor, bool, error) {
	next := &GkmSweepCursor{ClusterIndex: cursor.ClusterIndex, After: cursor.After}
	clusterIds := self.blobs.MetadataClusterIds()
	budget := self.host.Budget
	for _, clusterId := range clusterIds {
		budget.DeclareP2Backlog(clusterId, gkmSweepBacklogOwner, sidecar.WriteP2RankRetention, false, self.settings.SweepBacklogByteCount)
	}
	defer func() {
		for _, clusterId := range clusterIds {
			budget.DeclareP2Backlog(clusterId, gkmSweepBacklogOwner, sidecar.WriteP2RankRetention, false, 0)
		}
	}()
	firstClusterId := ""
	if firstCluster, err := self.blobs.FirstCluster(); err == nil {
		firstClusterId = firstCluster.ClusterId()
	}
	for unitCount := 0; unitCount < self.settings.SweepUnitCount; {
		if len(clusterIds) <= next.ClusterIndex {
			return next, true, nil
		}
		cluster, err := self.blobs.Cluster(clusterIds[next.ClusterIndex])
		if err != nil {
			return cursor, false, err
		}
		infos, _, err := cluster.List(ctx, gkmKeyPrefix, next.After, 1)
		if err != nil {
			return cursor, false, err
		}
		if len(infos) == 0 {
			next = &GkmSweepCursor{ClusterIndex: next.ClusterIndex + 1}
			continue
		}
		key := infos[0].Key
		after, err := self.sweepUnit(ctx, cluster, cluster.ClusterId() == firstClusterId, key)
		if err != nil {
			return cursor, false, err
		}
		next.After = after
		unitCount += 1
	}
	return next, false, nil
}

// Sweeps the unit key opens and answers the key past it.
func (self *GkmReconciler) sweepUnit(ctx context.Context, cluster sidecar.BlobCluster, firstCluster bool, key string) (string, error) {
	rest := strings.TrimPrefix(key, gkmKeyPrefix)
	family, tail, _ := strings.Cut(rest, "/")
	idText, _, _ := strings.Cut(tail, "/")
	now := self.clock.Now()
	switch family {
	case "kp", "welcome", "rk":
		sidecarId, err := parseGkmHexId(idText)
		if err != nil {
			return key, nil
		}
		if !firstCluster {
			// per-sidecar objects live on the first cluster alone
			return gkmKeyPrefix + family + "/" + idText + "/" + gkmKeyPastSuffix, nil
		}
		switch family {
		case "kp":
			err = self.sweepKeyPackages(ctx, cluster, sidecarId, now)
		case "welcome":
			err = self.sweepWelcomePointers(ctx, cluster, sidecarId, now)
		default:
			err = self.sweepReaderKey(ctx, cluster, sidecarId, now)
			return key, err
		}
		return gkmKeyPrefix + family + "/" + idText + "/" + gkmKeyPastSuffix, err
	case "recovery":
		memberId, err := parseGkmHexId(idText)
		if err != nil {
			return key, nil
		}
		return GkmRecoveryMemberPrefix(memberId) + gkmKeyPastSuffix, self.sweepRecoveryWraps(ctx, cluster, memberId, now)
	case "repo":
		// forms live for the repo's life (gkm-1)
		return gkmFormKeyPrefix + idText + "/" + gkmKeyPastSuffix, nil
	}
	groupId, err := parseGkmHexId(family)
	if err != nil {
		return key, nil
	}
	return GkmGroupPrefix(groupId) + gkmKeyPastSuffix, self.sweepGroup(ctx, cluster, groupId, now)
}

// Whether a hold covers a repo, read through its repo/'s network: true too when the repo or its network cannot be
// read, since every doubt keeps data.
func (self *GkmReconciler) repoHeld(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) bool {
	objectBytes, _, err := readGkmObject(ctx, cluster, GkmEvsRepoKey(repoId), gkmEvsRepoMaxByteCount)
	if err != nil {
		return true
	}
	object, err := parseGkmEvsRepoObject(repoId, objectBytes)
	if err != nil {
		return true
	}
	networkId, err := sidecar.IdFromBytes(object.GetNetworkId())
	if err != nil {
		return true
	}
	cover, err := self.holds.Covering(ctx, networkId, repoId)
	return err != nil || cover.Covered()
}

// Whether a hold covers a sidecar's network, or its network is not known.
func (self *GkmReconciler) sidecarHeld(ctx context.Context, sidecarId sidecar.Id) (held bool, revoked bool, err error) {
	networkId, revoked, known, err := self.state.SidecarStanding(ctx, sidecarId)
	if err != nil {
		return true, false, err
	}
	if !known {
		return true, false, nil
	}
	cover, err := self.holds.Covering(ctx, networkId, sidecar.Id{})
	return err != nil || cover.Covered(), revoked, nil
}

// A hold that came to cover a unit while its delete waited for the budget: the delete is dropped, nothing deleted.
var errGkmSweepHeld = errors.New("gkm: a hold now covers what the sweep would delete")

// What a sweep unit's P2 work checks again when its turn comes: whether a hold now covers the unit.
type gkmSweepRecheckKey struct{}

// ctx carrying held, the unit's own hold check, for its deletes' rechecks.
func withGkmSweepHeld(ctx context.Context, held func(ctx context.Context) bool) context.Context {
	return context.WithValue(ctx, gkmSweepRecheckKey{}, held)
}

// Acquires byteCount priced bytes of unfunded P2 work at rank on cluster, waiting as long as ctx lasts, its recheck
// the unit's hold check from ctx.
func (self *GkmReconciler) acquireSweepWrite(ctx context.Context, cluster sidecar.BlobCluster, rank sidecar.WriteP2Rank, byteCount int64) (sidecar.WriteGrant, error) {
	work := &sidecar.WriteP2Work{Rank: rank, Due: self.clock.Now(), ByteCount: byteCount}
	if held, ok := ctx.Value(gkmSweepRecheckKey{}).(func(ctx context.Context) bool); ok {
		work.Recheck = func(ctx context.Context) error {
			if held(ctx) {
				return errGkmSweepHeld
			}
			return nil
		}
	}
	return self.host.Budget.AcquireP2(ctx, cluster.ClusterId(), work)
}

// Deletes key as unfunded P2 work at rank. A key already gone is no error, nor is a hold that came to cover it while
// it waited, which keeps it.
func (self *GkmReconciler) deleteKey(ctx context.Context, cluster sidecar.BlobCluster, key string, rank sidecar.WriteP2Rank) error {
	grant, err := self.acquireSweepWrite(ctx, cluster, rank, self.settings.Service.Prices.delete())
	if errors.Is(err, errGkmSweepHeld) {
		return nil
	}
	if err != nil {
		return err
	}
	defer grant.Close()
	return deleteGkmObject(grant.Context(), cluster, key)
}

// One group's objects as a LIST found them.
type gkmGroupListing struct {
	epochs      []*gkmListedEpoch
	generations map[uint64]bool
	wraps       []*gkmListedWrap
	welcomes    []*sidecar.BlobInfo
}

type gkmListedEpoch struct {
	epoch uint64
	info  *sidecar.BlobInfo
}

type gkmListedWrap struct {
	generation uint64
	c8         string
	recipient  string
	info       *sidecar.BlobInfo
}

// A group's keys, sorted into families. A key in no form gkm writes is left alone.
func (self *GkmReconciler) listGroup(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id) (*gkmGroupListing, error) {
	prefix := GkmGroupPrefix(groupId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.Service.ListPageCount, self.settings.UnitKeyMaxCount)
	if err != nil {
		return nil, err
	}
	listing := &gkmGroupListing{generations: map[uint64]bool{}}
	for _, info := range infos {
		parts := strings.Split(strings.TrimPrefix(info.Key, prefix), "/")
		switch {
		case len(parts) == 2 && parts[0] == "epoch":
			if epoch, ok := parseGkmKeyNumber(parts[1]); ok {
				listing.epochs = append(listing.epochs, &gkmListedEpoch{epoch: epoch, info: info})
			}
		case len(parts) == 2 && parts[0] == "welcome":
			listing.welcomes = append(listing.welcomes, info)
		case len(parts) == 5 && parts[0] == "wrap":
			if generation, ok := parseGkmKeyNumber(parts[1]); ok && gkmHexPrefixForm(parts[2]) {
				listing.wraps = append(listing.wraps, &gkmListedWrap{generation: generation, c8: parts[2], recipient: parts[3], info: info})
			}
		}
	}
	// gen/ through its one accessor, which a gen pack's fallback extends (§10.16)
	generations, err := listGkmGenerations(ctx, cluster, groupId, 0, self.settings.Service.ListPageCount)
	if err != nil {
		return nil, err
	}
	for _, generation := range generations {
		listing.generations[generation] = true
	}
	return listing, nil
}

// One group's unit: retention, staged GC, gkm-7's wraps and gkm-5's Welcomes, unless a hold covers its repo.
func (self *GkmReconciler) sweepGroup(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, now time.Time) error {
	listing, err := self.listGroup(ctx, cluster, groupId)
	if err != nil {
		return err
	}
	newestGeneration := uint64(0)
	for generation := range listing.generations {
		newestGeneration = max(newestGeneration, generation)
	}
	if newestGeneration == 0 {
		// no generation names the group's repo: keep everything
		return nil
	}
	newestFacts, err := self.generationFacts(ctx, cluster, groupId, newestGeneration)
	if err != nil {
		return nil
	}
	repoId, err := sidecar.IdFromBytes(newestFacts.repoId)
	if err != nil || self.repoHeld(ctx, cluster, repoId) {
		return nil
	}
	ctx = withGkmSweepHeld(ctx, func(ctx context.Context) bool { return self.repoHeld(ctx, cluster, repoId) })
	if err := self.retainEpochs(ctx, cluster, groupId, listing.epochs, now); err != nil {
		return err
	}
	if err := self.collectWraps(ctx, cluster, groupId, listing, now); err != nil {
		return err
	}
	for _, info := range listing.welcomes {
		if self.settings.WelcomeLifetime <= now.Sub(info.LastModified) {
			if err := self.deleteKey(ctx, cluster, info.Key, sidecar.WriteP2RankRetention); err != nil {
				return err
			}
		}
	}
	return nil
}

// gen/<g>'s facts on cluster, through the one gen accessor.
func (self *GkmReconciler) generationFacts(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) (*gkmGenerationFacts, error) {
	objectBytes, err := readGkmGeneration(ctx, cluster, groupId, generation)
	if err != nil {
		return nil, err
	}
	return parseGkmGenerationFacts(objectBytes)
}

// §10.6's retention of a group's epochs by its acks. A Redis that does not answer, a family younger than
// EpochRetention or lost, or an ack out of form deletes nothing.
func (self *GkmReconciler) retainEpochs(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, epochs []*gkmListedEpoch, now time.Time) error {
	redis := self.host.Redis
	if redis == nil || len(epochs) < 2 {
		return nil
	}
	fieldValues, err := redis.HashGetAll(ctx, GkmAckRedisKey(groupId))
	if err != nil {
		return nil
	}
	since, ok := parseGkmAckSince(fieldValues[gkmAckSinceField])
	if !ok || now.Sub(since) < self.settings.EpochRetention {
		return nil
	}
	floor := ^uint64(0)
	for field, value := range fieldValues {
		if field == gkmAckSinceField {
			continue
		}
		epoch, at, ok := parseGkmAckValue(value)
		if !ok {
			return nil
		}
		if now.Sub(at) <= self.settings.EpochRetention {
			floor = min(floor, epoch)
		}
	}
	newest := epochs[len(epochs)-1].epoch
	deletable := map[uint64]*gkmListedEpoch{}
	for _, listed := range epochs {
		if listed.epoch < newest && listed.epoch <= floor && self.settings.EpochRetention <= now.Sub(listed.info.LastModified) {
			deletable[listed.epoch] = listed
		}
	}
	if len(deletable) == 0 {
		return nil
	}
	pointerBytes, info, err := readGkmObject(ctx, cluster, GkmGroupInfoKey(groupId), self.settings.Service.ObjectMaxByteCount)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		return err
	default:
		pointer, err := parseGkmGroupInfoObject(pointerBytes)
		if err != nil {
			return nil
		}
		if _, named := deletable[pointer.GetEpoch()]; named && len(pointer.GetSealedGroupInfo()) == 0 {
			// before the epoch the pointer names goes, the pointer moves to the newest epoch carrying a GroupInfo,
			// which then stays however old it is
			moved, ok := self.movePointer(ctx, cluster, groupId, epochs, info.Etag)
			if ok {
				delete(deletable, moved)
			} else {
				delete(deletable, pointer.GetEpoch())
			}
		}
	}
	epochNumbers := []uint64{}
	for epoch := range deletable {
		epochNumbers = append(epochNumbers, epoch)
	}
	slices.Sort(epochNumbers)
	for _, epoch := range epochNumbers {
		if err := self.deleteKey(ctx, cluster, deletable[epoch].info.Key, sidecar.WriteP2RankRetention); err != nil {
			return err
		}
	}
	return nil
}

// Rewrites a group's pointer, If-Match on etag, to the newest of epochs whose object carries a sealed GroupInfo, and
// answers that epoch. false when none does, or the write did not land, so the epoch the pointer names stays.
func (self *GkmReconciler) movePointer(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, epochs []*gkmListedEpoch, etag string) (uint64, bool) {
	for i := len(epochs) - 1; 0 <= i; i -= 1 {
		objectBytes, _, err := readGkmObject(ctx, cluster, epochs[i].info.Key, self.settings.Service.ObjectMaxByteCount)
		if err != nil {
			return 0, false
		}
		object, err := parseGkmEpochObject(objectBytes)
		if err != nil {
			return 0, false
		}
		if len(object.GetSealedGroupInfo()) == 0 {
			continue
		}
		pointerBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmGroupInfoObject{Epoch: epochs[i].epoch})
		if err != nil {
			return 0, false
		}
		// retention's own work, priced as an overwrite
		grant, err := self.acquireSweepWrite(ctx, cluster, sidecar.WriteP2RankRetention, self.settings.Service.Prices.overwrite(len(pointerBytes)))
		if err != nil {
			return 0, false
		}
		defer grant.Close()
		barrierKey := gkmBarrierGroupKey(groupId)
		testHookBarrier(BarrierPointerPutBefore, barrierKey)
		err = replaceGkmObject(grant.Context(), cluster, GkmGroupInfoKey(groupId), etag, pointerBytes)
		testHookBarrier(BarrierPointerPutAfter, barrierKey)
		return epochs[i].epoch, err == nil
	}
	return 0, false
}

// gkm-7's deliveries and §10.6's staged GC for one group.
func (self *GkmReconciler) collectWraps(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, listing *gkmGroupListing, now time.Time) error {
	generationC8s := map[uint64]string{}
	for generation := range listing.generations {
		facts, err := self.generationFacts(ctx, cluster, groupId, generation)
		if err != nil {
			continue
		}
		if c8, ok := gkmDigestPrefix(facts.commitment); ok {
			generationC8s[generation] = c8
		}
	}
	// a recipient's newest delivery of a current generation, by when it was written
	type recipientKey struct {
		generation uint64
		recipient  string
	}
	newestWritten := map[recipientKey]time.Time{}
	for _, wrap := range listing.wraps {
		if c8, ok := generationC8s[wrap.generation]; ok && c8 == wrap.c8 {
			key := recipientKey{generation: wrap.generation, recipient: wrap.recipient}
			if wrap.info.LastModified.After(newestWritten[key]) {
				newestWritten[key] = wrap.info.LastModified
			}
		}
	}
	for _, wrap := range listing.wraps {
		c8, claimed := generationC8s[wrap.generation]
		remove := false
		rank := sidecar.WriteP2RankRetention
		switch {
		case listing.generations[wrap.generation+1]:
			// the next generation's deliveries all exist once it is claimed (gkm-7)
			remove = true
		case !claimed || c8 != wrap.c8:
			// a lost claim's staged delivery
			remove = self.settings.StagedGcAge <= now.Sub(wrap.info.LastModified)
			rank = sidecar.WriteP2RankGc
		default:
			newest := newestWritten[recipientKey{generation: wrap.generation, recipient: wrap.recipient}]
			remove = wrap.info.LastModified.Before(newest) && self.settings.OlderKeyDeliveryAge <= now.Sub(newest)
		}
		if remove {
			if err := self.deleteKey(ctx, cluster, wrap.info.Key, rank); err != nil {
				return err
			}
		}
	}
	return nil
}

// A member's recovery wraps on one cluster: a lost claim's staged ones go at 24 h, unless a hold covers their repo.
// Every other recovery wrap lives until a rebind replaces it or the repo is shredded (gkm-8).
func (self *GkmReconciler) sweepRecoveryWraps(ctx context.Context, cluster sidecar.BlobCluster, memberId sidecar.Id, now time.Time) error {
	prefix := GkmRecoveryMemberPrefix(memberId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.Service.ListPageCount, self.settings.UnitKeyMaxCount)
	if err != nil {
		return err
	}
	type groupHeld struct {
		known  bool
		held   bool
		repoId sidecar.Id
	}
	groupHelds := map[sidecar.Id]*groupHeld{}
	for _, info := range infos {
		groupId, generation, c8, _, ok := parseGkmRecoveryWrapKey(prefix, info.Key)
		if !ok || now.Sub(info.LastModified) < self.settings.StagedGcAge {
			continue
		}
		facts, err := self.generationFacts(ctx, cluster, groupId, generation)
		switch {
		case errors.Is(err, sidecar.ErrBlobNotFound):
		case err != nil:
			continue
		default:
			if generationC8, ok := gkmDigestPrefix(facts.commitment); ok && generationC8 == c8 {
				continue
			}
		}
		held, ok := groupHelds[groupId]
		if !ok {
			held = &groupHeld{}
			groupHelds[groupId] = held
			if newestFacts, found, err := gkmNewestGenerationFacts(ctx, cluster, groupId, self.settings.Service); err == nil && found {
				if repoId, err := sidecar.IdFromBytes(newestFacts.repoId); err == nil {
					held.known = true
					held.held = self.repoHeld(ctx, cluster, repoId)
					held.repoId = repoId
				}
			}
		}
		if !held.known || held.held {
			continue
		}
		repoId := held.repoId
		unitCtx := withGkmSweepHeld(ctx, func(ctx context.Context) bool { return self.repoHeld(ctx, cluster, repoId) })
		if err := self.deleteKey(unitCtx, cluster, info.Key, sidecar.WriteP2RankGc); err != nil {
			return err
		}
	}
	return nil
}

// One sidecar's KeyPackages and claims (gkm-4, §10.4).
func (self *GkmReconciler) sweepKeyPackages(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id, now time.Time) error {
	prefix := GkmKeyPackagePrefix(sidecarId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.Service.ListPageCount, self.settings.UnitKeyMaxCount)
	if err != nil {
		return err
	}
	held, revoked, err := self.sidecarHeld(ctx, sidecarId)
	if err != nil {
		return err
	}
	if held {
		return nil
	}
	ctx = withGkmSweepHeld(ctx, func(ctx context.Context) bool { return self.sidecarHeldNow(ctx, sidecarId) })
	claimedRefs := map[string]bool{}
	for _, info := range infos {
		if ref, claim, ok := parseGkmKeyPackageListKey(prefix, info.Key); ok && claim {
			claimedRefs[string(ref)] = true
		}
	}
	for _, info := range infos {
		ref, claim, ok := parseGkmKeyPackageListKey(prefix, info.Key)
		if !ok {
			continue
		}
		expired := self.settings.KeyPackageLifetime <= now.Sub(info.LastModified)
		remove := expired || (!claim && revoked)
		if !remove && !claim && claimedRefs[string(ref)] {
			// a claimed one-time KeyPackage whose delete failed; the last-resort one stays beside its claim
			objectBytes, _, err := readGkmObject(ctx, cluster, info.Key, self.settings.Service.ObjectMaxByteCount)
			if err == nil {
				if keyPackage, err := sidecar.ParseMlsKeyPackage(objectBytes); err == nil && !keyPackage.LastResort {
					remove = true
				}
			}
		}
		if remove {
			if err := self.deleteKey(ctx, cluster, info.Key, sidecar.WriteP2RankRetention); err != nil {
				return err
			}
		}
	}
	return nil
}

// Whether a hold covers a sidecar's network now, or anything about it cannot be told: the recheck of its unit's
// deletes.
func (self *GkmReconciler) sidecarHeldNow(ctx context.Context, sidecarId sidecar.Id) bool {
	held, _, err := self.sidecarHeld(ctx, sidecarId)
	return err != nil || held
}

// One sidecar's ReaderKey, which goes once past its not_after (gkm-4).
func (self *GkmReconciler) sweepReaderKey(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id, now time.Time) error {
	key := GkmReaderKeyKey(sidecarId)
	objectBytes, _, err := readGkmObject(ctx, cluster, key, gkmReaderKeyMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	signed := &bridge.Signed{}
	body := &protocol.ReaderKey{}
	if proto.Unmarshal(objectBytes, signed) != nil || proto.Unmarshal(signed.GetBody(), body) != nil || body.GetNotAfter() <= 0 {
		// a record gkm cannot read: kept, as every doubt is
		return nil
	}
	if now.Before(time.UnixMilli(body.GetNotAfter())) {
		return nil
	}
	held, _, err := self.sidecarHeld(ctx, sidecarId)
	if err != nil || held {
		return err
	}
	ctx = withGkmSweepHeld(ctx, func(ctx context.Context) bool { return self.sidecarHeldNow(ctx, sidecarId) })
	return self.deleteKey(ctx, cluster, key, sidecar.WriteP2RankRetention)
}

// One sidecar's Welcome pointers: one goes once its recipient's ack has passed its epoch, or at 90 d (gkm-5).
func (self *GkmReconciler) sweepWelcomePointers(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id, now time.Time) error {
	prefix := GkmWelcomePointerPrefix(sidecarId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.Service.ListPageCount, self.settings.UnitKeyMaxCount)
	if err != nil {
		return err
	}
	held, _, err := self.sidecarHeld(ctx, sidecarId)
	if err != nil || held {
		return err
	}
	ctx = withGkmSweepHeld(ctx, func(ctx context.Context) bool { return self.sidecarHeldNow(ctx, sidecarId) })
	field := sidecar.EvsKeyId(sidecarId)
	for _, info := range infos {
		remove := self.settings.WelcomeLifetime <= now.Sub(info.LastModified)
		if !remove && self.host.Redis != nil {
			pointerBytes, _, err := readGkmObject(ctx, cluster, info.Key, self.settings.Service.ObjectMaxByteCount)
			if err != nil {
				continue
			}
			pointer := &protocol.GkmWelcomePointer{}
			if proto.Unmarshal(pointerBytes, pointer) != nil {
				continue
			}
			groupId, err := sidecar.IdFromBytes(pointer.GetGroupId())
			if err != nil {
				continue
			}
			value, found, err := self.host.Redis.HashGet(ctx, GkmAckRedisKey(groupId), field)
			if err == nil && found {
				if epoch, _, ok := parseGkmAckValue(value); ok && pointer.GetEpoch() <= epoch {
					remove = true
				}
			}
		}
		if remove {
			if err := self.deleteKey(ctx, cluster, info.Key, sidecar.WriteP2RankRetention); err != nil {
				return err
			}
		}
	}
	return nil
}

// A cursor's text, for logs: ids and positions only.
func (self *GkmSweepCursor) String() string {
	return fmt.Sprintf("cluster %d after %q", self.ClusterIndex, self.After)
}
