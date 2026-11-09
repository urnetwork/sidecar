// §10.6's KeyPackages row (KF2, D-KEYS-26): POST /gkm/key-packages and POST /gkm/key-packages/claim, over
// gkm/kp/<sidecar_id>/<ref> and <ref>.claim on the first cluster.
//
//   - Up to 128 one-time KeyPackages and the last-resort one per sidecar, each valid 90 days, only from member
//     devices (untagged, not ephemeral), each under the uploader's own credential: the token's ur_sidecar_id must be
//     the credential's sidecar_id, and its identity key the one the log admits for that sidecar.
//   - A sidecar's first upload hints pending to the writers of each repo it reads, so a committer adds it (KF2).
//   - A claim creates <ref>.claim with If-None-Match and then deletes <ref>, so a one-time KeyPackage serves one
//     claim: of two racing claimers one wins, and the other takes the next. It serves only a target the newest state
//     lists as a reader of the group's repo, at 10 a minute per (claimer, target). A last-resort KeyPackage is
//     served only once no one-time one remains, is never deleted, and its claim is overwritten rather than created
//     (KEYS.md's reading 2). A claim that leaves fewer than 32 one-time KeyPackages hints key-packages-low to the
//     target.
//
// Which stored ref is the last-resort one, gkm cannot tell from its key, so a process remembers each ref's flag and
// expiry, read once from the object, since neither ever changes for a ref (it hashes the KeyPackage that carries
// them). gkm deletes nothing here but a claimed one-time KeyPackage: expiry is the reconciler's (gkm-4's 90 days,
// KEYS-M2-16).

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The most keys one sidecar's kp/ prefix may hold before a count of it alarms: its KeyPackages and 90 days of claims.
const gkmKeyPackageListMaxCount = 64 * 1024

// What a process knows of one stored KeyPackage, which never changes for its ref.
type gkmKeyPackageKind struct {
	lastResort bool
	notAfter   time.Time
}

// The refs whose kind this process has read. Bounded: an evicted ref costs only its next read. Safe for concurrent
// use.
type gkmKeyPackageKinds struct {
	maxCount int

	stateLock sync.Mutex
	refKinds  map[string]*gkmKeyPackageKind
}

// An empty cache of at most maxCount refs.
func newGkmKeyPackageKinds(maxCount int) *gkmKeyPackageKinds {
	return &gkmKeyPackageKinds{maxCount: maxCount, refKinds: map[string]*gkmKeyPackageKind{}}
}

// The kind of ref, if known.
func (self *gkmKeyPackageKinds) get(ref []byte) (*gkmKeyPackageKind, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	kind, ok := self.refKinds[string(ref)]
	return kind, ok
}

// Remembers ref's kind, evicting another first when full.
func (self *gkmKeyPackageKinds) put(ref []byte, kind *gkmKeyPackageKind) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.maxCount <= 0 {
		return
	}
	if _, ok := self.refKinds[string(ref)]; !ok && self.maxCount <= len(self.refKinds) {
		for evicted := range self.refKinds {
			delete(self.refKinds, evicted)
			break
		}
	}
	self.refKinds[string(ref)] = kind
}

// A last-resort KeyPackage's ref, ordered by its expiry, so the one that lasts longest serves first.
type gkmLastResortRef struct {
	ref      []byte
	notAfter time.Time
}

// One sidecar's KeyPackages as one LIST found them.
type gkmKeyPackageInventory struct {
	// Unclaimed one-time KeyPackages, unexpired, in key order: what a claim serves first and what the count is.
	oneTimeRefs [][]byte
	// Last-resort KeyPackages, claimed or not, unexpired, newest expiry first.
	lastResortRefs [][]byte
	// Every <ref> object, claimed or not, by its bytes.
	storedRefs map[string]bool
	// Whether the prefix held any key at all, a claim included: a sidecar with none has never uploaded.
	empty bool
}

// One LIST of a sidecar's kp/ prefix, each ref's kind from this process's cache or one GET of the object.
func (self *GkmEngine) keyPackageInventory(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id, now time.Time) (*gkmKeyPackageInventory, error) {
	prefix := GkmKeyPackagePrefix(sidecarId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.ListPageCount, gkmKeyPackageListMaxCount)
	if err != nil {
		return nil, err
	}
	inventory := &gkmKeyPackageInventory{storedRefs: map[string]bool{}, empty: len(infos) == 0}
	claimedRefs := map[string]bool{}
	refs := [][]byte{}
	for _, info := range infos {
		ref, claim, ok := parseGkmKeyPackageListKey(prefix, info.Key)
		if !ok {
			continue
		}
		if claim {
			claimedRefs[string(ref)] = true
			continue
		}
		inventory.storedRefs[string(ref)] = true
		refs = append(refs, ref)
	}
	lastResorts := []*gkmLastResortRef{}
	for _, ref := range refs {
		kind, ok := self.kinds.get(ref)
		if !ok {
			key, err := GkmKeyPackageKey(sidecarId, ref)
			if err != nil {
				return nil, err
			}
			objectBytes, _, err := readGkmObject(ctx, cluster, key, self.settings.ObjectMaxByteCount)
			if errors.Is(err, sidecar.ErrBlobNotFound) {
				// claimed and deleted since the LIST
				continue
			}
			if err != nil {
				return nil, err
			}
			info, err := sidecar.ParseMlsKeyPackage(objectBytes)
			if err != nil {
				return nil, errors.Join(errGkmStoreFault, err)
			}
			kind = &gkmKeyPackageKind{lastResort: info.LastResort, notAfter: info.NotAfter}
			self.kinds.put(ref, kind)
		}
		if !now.Before(kind.notAfter) {
			// expired: the reconciler deletes it, and nothing serves or counts it
			continue
		}
		switch {
		case kind.lastResort:
			lastResorts = append(lastResorts, &gkmLastResortRef{ref: ref, notAfter: kind.notAfter})
		case !claimedRefs[string(ref)]:
			inventory.oneTimeRefs = append(inventory.oneTimeRefs, ref)
		}
	}
	slices.SortStableFunc(lastResorts, func(a *gkmLastResortRef, b *gkmLastResortRef) int {
		return b.notAfter.Compare(a.notAfter)
	})
	for _, lastResort := range lastResorts {
		inventory.lastResortRefs = append(inventory.lastResortRefs, lastResort.ref)
	}
	return inventory, nil
}

// One KeyPackage of an upload, checked.
type gkmUploadedKeyPackage struct {
	encoded []byte
	info    *sidecar.MlsKeyPackageInfo
}

// POST /gkm/key-packages: a GkmKeyPackagesRequest of the token's own sidecar's KeyPackages.
func (self *GkmEngine) serveKeyPackagesUpload(request *GkmRequest) {
	if !request.Sidecar.MemberDevice {
		// agents and ephemeral sidecars hold wraps, never leaves (D-KEYS-11)
		request.Forbidden()
		return
	}
	upload := &protocol.GkmKeyPackagesRequest{}
	if !request.ReadMessage(upload, self.settings.RequestBodyMaxByteCount) {
		return
	}
	if len(upload.GetKeyPackages()) == 0 || self.settings.KeyPackageOneTimeMaxCount+1 < len(upload.GetKeyPackages()) {
		request.BadRequest()
		return
	}
	now := request.Now()
	uploaded := []*gkmUploadedKeyPackage{}
	uploadRefs := map[string]bool{}
	lastResortCount := 0
	for _, encoded := range upload.GetKeyPackages() {
		info, err := sidecar.ParseMlsKeyPackage(encoded)
		if err != nil {
			request.BadRequest()
			return
		}
		// the token's sidecar must be the credential's, under the identity key the log admits for it
		if !bytes.Equal(info.Credential.GetSidecarId(), request.SidecarId.Bytes()) ||
			!bytes.Equal(info.Credential.GetIdentityPublicKey(), request.Sidecar.IdentityPublicKey) {
			request.Forbidden()
			return
		}
		latest := now.Add(self.settings.KeyPackageMaxLifetime + sidecar.GkmClockSkew)
		if !now.Before(info.NotAfter) || latest.Before(info.NotAfter) || now.Add(sidecar.GkmClockSkew).Before(info.NotBefore) {
			request.BadRequest()
			return
		}
		if uploadRefs[string(info.Ref)] {
			request.BadRequest()
			return
		}
		uploadRefs[string(info.Ref)] = true
		if info.LastResort {
			lastResortCount += 1
		}
		uploaded = append(uploaded, &gkmUploadedKeyPackage{encoded: encoded, info: info})
	}
	if 1 < lastResortCount {
		request.BadRequest()
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	inventory, err := self.keyPackageInventory(request.Ctx, cluster, request.SidecarId, now)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	newOneTimeCount := 0
	for _, keyPackage := range uploaded {
		if !keyPackage.info.LastResort && !inventory.storedRefs[string(keyPackage.info.Ref)] {
			newOneTimeCount += 1
		}
	}
	if self.settings.KeyPackageOneTimeMaxCount < len(inventory.oneTimeRefs)+newOneTimeCount {
		// past the sidecar's count: its next refill, at a key-packages-low hint, fits
		request.TooManyRequests(0)
		return
	}
	for _, keyPackage := range uploaded {
		key, err := GkmKeyPackageKey(request.SidecarId, keyPackage.info.Ref)
		if err != nil {
			request.BadRequest()
			return
		}
		winner, err := createGkmObject(request.Ctx, cluster, key, keyPackage.encoded, self.settings.ObjectMaxByteCount)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if winner != nil {
			// a ref hashes its KeyPackage, so other bytes under it are a fault
			self.alarm("key_package_ref", errors.New("a KeyPackageRef holds other bytes"))
			request.Unavailable()
			return
		}
		self.kinds.put(keyPackage.info.Ref, &gkmKeyPackageKind{lastResort: keyPackage.info.LastResort, notAfter: keyPackage.info.NotAfter})
	}
	if inventory.empty {
		self.hintFirstUpload(request, now)
	}
	request.Reply(nil)
}

// A sidecar's first KeyPackage upload: pending to who adds it in each repo it reads (§10.6's KeyPackages row, KF2),
// each hint naming the repo's newest group. A repo whose group gkm cannot read now is passed over, as a lost hint
// is: its writers find the sidecar at their next resync.
func (self *GkmEngine) hintFirstUpload(request *GkmRequest, now time.Time) {
	targets, answer := self.deps.AuthState.PendingTargets(request.Principal, request.SidecarId, now)
	if answer != GkmAuthAllowed {
		return
	}
	for _, target := range targets {
		groupId, ok := self.newestGroup(request.Ctx, target.RepoId)
		if !ok {
			continue
		}
		self.hintWork(target.SidecarIds, protocol.GkmHintKind_GKM_HINT_PENDING, &groupId, 0, nil)
	}
}

// The group a repo's newest GroupForm names, or false when gkm cannot read one now.
func (self *GkmEngine) newestGroup(ctx context.Context, repoId sidecar.Id) (sidecar.Id, bool) {
	cluster, _, err := self.places.Cluster(ctx, repoId)
	if err != nil {
		return sidecar.Id{}, false
	}
	forms, err := self.forms.forms(ctx, cluster, repoId)
	if err != nil || len(forms) == 0 {
		return sidecar.Id{}, false
	}
	return forms[len(forms)-1].GroupId, true
}

// POST /gkm/key-packages/claim: a GkmKeyPackageClaimRequest, answered by the claimed KeyPackage.
func (self *GkmEngine) serveKeyPackageClaim(request *GkmRequest) {
	claimRequest := &protocol.GkmKeyPackageClaimRequest{}
	if !request.ReadMessage(claimRequest, self.settings.RequestBodyMaxByteCount) {
		return
	}
	groupId, err := sidecar.IdFromBytes(claimRequest.GetGroupId())
	if err != nil {
		request.BadRequest()
		return
	}
	targetSidecarId, err := sidecar.IdFromBytes(claimRequest.GetTarget())
	if err != nil || targetSidecarId == (sidecar.Id{}) {
		request.BadRequest()
		return
	}
	if !request.AuthorizeGroup(groupId) {
		return
	}
	now := request.Now()
	rateKey := "kp_claim:" + sidecar.EvsKeyId(request.SidecarId) + ":" + sidecar.EvsKeyId(targetSidecarId)
	if !self.rates.Allow(self.settings.KeyPackageClaimRate, rateKey, now) {
		request.TooManyRequests(self.settings.KeyPackageClaimRate.Interval / time.Duration(self.settings.KeyPackageClaimRate.Count))
		return
	}
	// only for a target the newest state lists as a reader of the group's repo
	switch self.deps.AuthState.Reads(request.Principal, request.RepoId, targetSidecarId, now) {
	case GkmAuthAllowed:
	case GkmAuthDenied:
		request.Forbidden()
		return
	default:
		request.Unavailable()
		return
	}
	cluster, err := self.firstCluster()
	if err != nil {
		request.Unavailable()
		return
	}
	inventory, err := self.keyPackageInventory(request.Ctx, cluster, targetSidecarId, now)
	if err != nil {
		self.answerStoreError(request, err)
		return
	}
	claimBody, err := proto.MarshalOptions{Deterministic: true}.Marshal(&protocol.GkmKeyPackageClaim{
		GroupId: groupId.Bytes(),
		Claimer: request.SidecarId.Bytes(),
	})
	if err != nil {
		request.Unavailable()
		return
	}
	for _, ref := range inventory.oneTimeRefs {
		keyPackage, claimed, err := self.claimOneTime(request.Ctx, cluster, targetSidecarId, ref, claimBody)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !claimed {
			// another claimer won this one: take the next
			continue
		}
		self.hintIfLow(request.Ctx, cluster, targetSidecarId, now)
		request.Reply(&protocol.GkmKeyPackageClaimReply{KeyPackageRef: ref, KeyPackage: keyPackage})
		return
	}
	for _, ref := range inventory.lastResortRefs {
		keyPackage, found, err := self.claimLastResort(request.Ctx, cluster, targetSidecarId, ref, claimBody)
		if err != nil {
			self.answerStoreError(request, err)
			return
		}
		if !found {
			continue
		}
		self.hintIfLow(request.Ctx, cluster, targetSidecarId, now)
		request.Reply(&protocol.GkmKeyPackageClaimReply{KeyPackageRef: ref, KeyPackage: keyPackage})
		return
	}
	request.NotFound()
}

// Claims a one-time KeyPackage: <ref>.claim If-None-Match, then <ref> deleted. claimed is false when another claim
// already holds it, or it was deleted since the LIST. A delete that fails leaves <ref> beside its claim, which no
// later claim serves and the reconciler removes.
func (self *GkmEngine) claimOneTime(ctx context.Context, cluster sidecar.BlobCluster, targetSidecarId sidecar.Id, ref []byte, claimBody []byte) (keyPackage []byte, claimed bool, err error) {
	key, err := GkmKeyPackageKey(targetSidecarId, ref)
	if err != nil {
		return nil, false, err
	}
	claimKey := key + gkmKeyPackageClaimKeySuffix
	keyPackage, _, err = readGkmObject(ctx, cluster, key, self.settings.ObjectMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	barrierKey := gkmBarrierClaimKey(targetSidecarId, ref)
	testHookBarrier(BarrierKeyPackageClaimBefore, barrierKey)
	winner, err := createGkmObject(ctx, cluster, claimKey, claimBody, self.settings.ObjectMaxByteCount)
	testHookBarrier(BarrierKeyPackageClaimAfter, barrierKey)
	if errors.Is(err, errGkmObjectGone) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if winner != nil {
		return nil, false, nil
	}
	if err := cluster.Delete(ctx, key); err != nil && self.log.V(1).Enabled() {
		self.log.Infof("[gkm] a claimed KeyPackage's delete failed: %v", err)
	}
	return keyPackage, true, nil
}

// Serves the last-resort KeyPackage and overwrites its claim, which records the newest claimer for gkm-4's 90 days.
// A claim another write moved between the read and this one stands as that write left it: either names a claim of
// this KeyPackage, which serves every claimer.
func (self *GkmEngine) claimLastResort(ctx context.Context, cluster sidecar.BlobCluster, targetSidecarId sidecar.Id, ref []byte, claimBody []byte) (keyPackage []byte, found bool, err error) {
	key, err := GkmKeyPackageKey(targetSidecarId, ref)
	if err != nil {
		return nil, false, err
	}
	claimKey := key + gkmKeyPackageClaimKeySuffix
	keyPackage, _, err = readGkmObject(ctx, cluster, key, self.settings.ObjectMaxByteCount)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	etag := ""
	held, info, err := readGkmObject(ctx, cluster, claimKey, self.settings.ObjectMaxByteCount)
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		return nil, false, err
	default:
		etag = info.Etag
	}
	if !bytes.Equal(held, claimBody) {
		barrierKey := gkmBarrierClaimKey(targetSidecarId, ref)
		testHookBarrier(BarrierKeyPackageClaimBefore, barrierKey)
		err = replaceGkmObject(ctx, cluster, claimKey, etag, claimBody)
		testHookBarrier(BarrierKeyPackageClaimAfter, barrierKey)
		if err != nil && !errors.Is(err, sidecar.ErrBlobPrecondition) {
			// an unknown outcome too: the client asks again, and the same KeyPackage serves it
			return nil, false, err
		}
	}
	return keyPackage, true, nil
}

// Hints key-packages-low to a sidecar a claim has left fewer than KeyPackageLowCount one-time KeyPackages, read
// again after the claim. A count that cannot be read now hints nothing: the next claim counts again.
func (self *GkmEngine) hintIfLow(ctx context.Context, cluster sidecar.BlobCluster, sidecarId sidecar.Id, now time.Time) {
	inventory, err := self.keyPackageInventory(ctx, cluster, sidecarId, now)
	if err != nil || self.settings.KeyPackageLowCount <= len(inventory.oneTimeRefs) {
		return
	}
	self.hintWork([]sidecar.Id{sidecarId}, protocol.GkmHintKind_GKM_HINT_KEY_PACKAGES_LOW, nil, 0, nil)
}

// Answers a store error: 503 for an outcome no read resolved or a store that did not answer, and an alarm besides
// for a stored object that breaks its form.
func (self *GkmEngine) answerStoreError(request *GkmRequest, err error) {
	if errors.Is(err, errGkmStoreFault) {
		self.alarm("store_fault", err)
	}
	request.Unavailable()
}
