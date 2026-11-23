// A statement's gen/<g> resolved through its repo's GroupForms (plan-KEYS-reform-ladder rules 3 and 8 as QD-074 decided
// them; §10.8's bytes and pins rows, §11.8's pins row: "evs and readers resolve a statement's gen/<g> through the
// repo's newest GroupForm"). A re-form draws a new group and carries the old ladder into it byte for byte, so
// gkm/<new>/gen/<k>, k at or below the form's generation, holds the Signed GenRotate of the group k was claimed in,
// naming that group; and after a site loss the old group's own gen/<k> is gone, its statement standing only in the
// newest group's ladder. GenerationRecords reads gen/<g> for a group as:
//
//	own      gkm/<group_id>/gen/<g> naming group_id: the group's own claim, as before any re-form
//	carried  gkm/<group_id>/gen/<g> naming another group: a ladder's, taken where one of the repo's GroupForms makes
//	         group_id by re-forming another group at a generation of g or more, and the statement names the repo
//	moved    no gkm/<group_id>/gen/<g>, as a site loss leaves the old group: gen/<g> of the group the repo's newest
//	         GroupForm makes, taken where that form re-forms another group at a generation of g or more and the
//	         statement there names group_id and the repo
//
// The own and carried rows are the root's GkmParseServedGeneration (gkm_served_generation.go), which a VPN
// component's Forwarder holds a re-formed config group's statements to as well. Every statement is verified under its
// signer's identity key in evs's newest state, as an own one is, and every form it rests on under its own signer's
// (sidecar.GkmVerifyGroupForm), each held to its shape; who may sign a form at its pin is the members' check (§10.8's
// members row), not evs's. A generation evs cannot resolve answers none, and one naming another group that no form
// carries answers ErrGkmMalformed, each 503 at the push route, which refuses nothing, since a form lands before its
// ladder and so a moment later may carry it.
//
// A writer seals to the generation's key, which names the group the generation was claimed in, so a push names the old
// group at each generation the ladder carried, and the new group only past the form's generation: own and moved stand
// for a push's own generation pin, and §11.8's gate holds a carried record to the push's group as it holds any other
// (check_gate.go), so a push naming the new group at a ladder generation is refused as a pin of another group, and no
// head's group changes at an equal generation. The crossing a push into the new group makes over the ladder's
// generations reads them carried, each as the group it was claimed in held it (§11.6's crossing, epoch_commit.go):
// before this, a re-form's first push in the new group from a head of the old group's below the form's generation was
// refused 503 for good (TestE2eGkmConcurrencyReform's resumed repo).
//
// The forms are read by one LIST of gkm/repo/<repo_id>/ (repo.go's evsGkmFormPrefix) and a GET of each form the
// resolution needs, newest first, and a repo's forms are kept for GroupFormCacheTtl: they are append-only, so a list
// read before a new form stands can only fail a resolution, which a retry within that time meets again.

package evsservice

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// One repo's GroupForms as a resolution read them, oldest first: each key, and its facts once a resolution verified
// it.
type generationFormList struct {
	keys      []string
	keyFacts  map[string]*sidecar.GkmGroupFormFacts
	expiresAt time.Time
}

// One form list's key: its cluster and repo.
type generationFormListKey struct {
	clusterId string
	repoId    sidecar.Id
}

// gen/<generation> of groupId in repoId on cluster, resolved through the repo's GroupForms (the file header): the
// GenRotate that stands for it, verified against view's identity keys, naming another group than groupId where a
// re-form's ladder carried it. Nil with no error when gkm holds no such generation, or none that resolves.
func (self *GenerationRecords) Read(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, groupId sidecar.Id, generation uint64, view sidecar.GkmAuthView) (*protocol.GenRotate, error) {
	key := generationRecordKey{clusterId: cluster.ClusterId(), repoId: repoId, groupId: groupId, generation: generation}
	if cached, ok := func() (*protocol.GenRotate, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached, ok := self.records[key]
		return cached, ok
	}(); ok {
		return cached, nil
	}
	objectBytes, err := self.readGenerationObject(ctx, cluster, groupId, generation)
	if err != nil {
		return nil, err
	}
	var resolved *protocol.GenRotate
	if objectBytes != nil {
		resolved, err = self.resolveStanding(ctx, cluster, repoId, groupId, generation, objectBytes, view)
	} else {
		resolved, err = self.resolveMoved(ctx, cluster, repoId, groupId, generation, view)
	}
	if err != nil || resolved == nil {
		return nil, err
	}
	self.keep(key, resolved)
	return resolved, nil
}

// The own and carried rows, for the object gkm holds at gkm/<groupId>/gen/<generation>: the root's
// GkmParseServedGeneration, the repo's forms read only for a statement of another group.
func (self *GenerationRecords) resolveStanding(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, groupId sidecar.Id, generation uint64, objectBytes []byte, view sidecar.GkmAuthView) (*protocol.GenRotate, error) {
	parsed, err := sidecar.GkmParseServedGeneration(objectBytes, repoId, groupId, generation, func() (*sidecar.GkmGroupFormFacts, error) {
		return self.formMaking(ctx, cluster, repoId, groupId, view)
	}, sidecar.GkmIdentityKeys(view))
	if err != nil {
		return nil, err
	}
	return parsed.Rotate, nil
}

// The moved row, for a statement whose own group holds no gen/<generation>.
func (self *GenerationRecords) resolveMoved(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, groupId sidecar.Id, generation uint64, view sidecar.GkmAuthView) (*protocol.GenRotate, error) {
	newest, err := self.newestForm(ctx, cluster, repoId, view)
	if err != nil || newest == nil {
		return nil, err
	}
	if newest.GroupId == groupId || newest.PreviousGroupId == (sidecar.Id{}) || newest.Generation < generation {
		return nil, nil
	}
	objectBytes, err := self.readGenerationObject(ctx, cluster, newest.GroupId, generation)
	if err != nil || objectBytes == nil {
		return nil, err
	}
	namedGroupId, err := sidecar.GkmGenerationNamedGroup(objectBytes)
	if err != nil {
		return nil, err
	}
	if namedGroupId != groupId {
		// the ladder holds another group's statement there: the statement's group never held gen/<generation>
		return nil, nil
	}
	// the newest group's ladder carried it, under that group's form
	parsed, err := sidecar.GkmParseServedGeneration(objectBytes, repoId, newest.GroupId, generation, func() (*sidecar.GkmGroupFormFacts, error) {
		return newest, nil
	}, sidecar.GkmIdentityKeys(view))
	if err != nil {
		return nil, err
	}
	return parsed.Rotate, nil
}

// Keeps a resolved record for the process's life, evicting one past GenerationCacheCount.
func (self *GenerationRecords) keep(key generationRecordKey, resolved *protocol.GenRotate) {
	if self.settings.GenerationCacheCount <= 0 {
		return
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.settings.GenerationCacheCount <= len(self.records) {
		for evicted := range self.records {
			delete(self.records, evicted)
			break
		}
	}
	self.records[key] = resolved
}

// gkm/<groupId>/gen/<generation>'s bytes on cluster, at most GenerationRecordMaxByteCount; nil for none.
func (self *GenerationRecords) readGenerationObject(ctx context.Context, cluster sidecar.BlobCluster, groupId sidecar.Id, generation uint64) ([]byte, error) {
	object, err := cluster.Get(ctx, sidecar.GkmGenerationPath(groupId, generation))
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	return readAllLimited(object, self.settings.GenerationRecordMaxByteCount)
}

// The repo's newest GroupForm, verified; nil for a repo with none.
func (self *GenerationRecords) newestForm(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, view sidecar.GkmAuthView) (*sidecar.GkmGroupFormFacts, error) {
	list, err := self.formList(ctx, cluster, repoId)
	if err != nil || len(list.keys) == 0 {
		return nil, err
	}
	return self.formAt(ctx, cluster, repoId, list, list.keys[len(list.keys)-1], view)
}

// The repo's GroupForm that makes groupId, verified, read newest first, since a re-formed group's form is near the
// end; nil when none does.
func (self *GenerationRecords) formMaking(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, groupId sidecar.Id, view sidecar.GkmAuthView) (*sidecar.GkmGroupFormFacts, error) {
	list, err := self.formList(ctx, cluster, repoId)
	if err != nil {
		return nil, err
	}
	for index := len(list.keys) - 1; 0 <= index; index -= 1 {
		form, err := self.formAt(ctx, cluster, repoId, list, list.keys[index], view)
		if err != nil {
			return nil, err
		}
		if form != nil && form.GroupId == groupId {
			return form, nil
		}
	}
	return nil, nil
}

// The form at key, verified, from the list's facts when a resolution already verified it; nil for one gone since the
// list, which only a shred deletes.
func (self *GenerationRecords) formAt(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id, list *generationFormList, key string, view sidecar.GkmAuthView) (*sidecar.GkmGroupFormFacts, error) {
	if facts, ok := func() (*sidecar.GkmGroupFormFacts, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		facts, ok := list.keyFacts[key]
		return facts, ok
	}(); ok {
		return facts, nil
	}
	object, err := cluster.Get(ctx, key)
	if errors.Is(err, sidecar.ErrBlobNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer object.Body.Close()
	formBytes, err := readAllLimited(object, self.settings.GroupFormMaxByteCount)
	if err != nil {
		return nil, err
	}
	facts, err := sidecar.GkmVerifyGroupForm(view, repoId, formBytes)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	list.keyFacts[key] = facts
	return facts, nil
}

// The keys of the repo's GroupForms, oldest first: from this process's cache while under GroupFormCacheTtl old, else
// one LIST of at most GroupFormMaxCount keys, a repo past it being a fault that answers 503.
func (self *GenerationRecords) formList(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*generationFormList, error) {
	key := generationFormListKey{clusterId: cluster.ClusterId(), repoId: repoId}
	now := self.clock.Now()
	if cached, ok := func() (*generationFormList, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cached, ok := self.formLists[key]
		if ok && !now.Before(cached.expiresAt) {
			delete(self.formLists, key)
			return nil, false
		}
		return cached, ok
	}(); ok {
		return cached, nil
	}
	infos, more, err := cluster.List(ctx, evsGkmFormPrefix(repoId), "", self.settings.GroupFormMaxCount)
	if err != nil {
		return nil, err
	}
	if more {
		return nil, fmt.Errorf("%w: a repo past %d GroupForms", sidecar.ErrGkmMalformed, self.settings.GroupFormMaxCount)
	}
	list := &generationFormList{keyFacts: map[string]*sidecar.GkmGroupFormFacts{}, expiresAt: now.Add(self.settings.GroupFormCacheTtl)}
	for _, info := range infos {
		list.keys = append(list.keys, info.Key)
	}
	// seq in 20 digits, so key order is the forms' order
	slices.Sort(list.keys)
	if 0 < self.settings.GroupFormCacheTtl && 0 < self.settings.GroupFormCacheCount {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.GroupFormCacheCount <= len(self.formLists) {
			for evicted := range self.formLists {
				delete(self.formLists, evicted)
				break
			}
		}
		self.formLists[key] = list
	}
	return list, nil
}
