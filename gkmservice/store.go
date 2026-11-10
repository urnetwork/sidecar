// Where gkm's objects live, and what gkm rereads before it writes (§10.6's placement and checks rows):
//
//   - placement: a group's objects live on the cluster place/<repo_id> names, which evs wrote once at the repo's
//     creation; gkm resolves it through the root's EvsRepoPlaceResolver, once per process, a 404 cached 5 s, and a
//     re-formed group stays on its repo's cluster. Per-sidecar objects live on the first cluster (FS-63);
//   - repo/<id>, reread as each write issues, cached at most 5 s: active, or keying for the group's creation or
//     re-forming, or deleted only for a re-seed's GroupForm and ladder. EVS1-M2-19 owns repo/'s state machine; gkm
//     only reads it, with the shape evs's codec holds it to;
//   - a repo's GroupForms, gkm/repo/<repo_id>/<seq>, which tie each group to its repo: a group route resolves its
//     group to one of the repos the token scopes, and a write needs the repo's newest form to name the group. A
//     group's repo never changes, so a process remembers it; the forms themselves are cached as repo/ is, so a
//     re-form is seen within 5 s.
//
// Writes go through createGkmObject, replaceGkmObject and deleteGkmObject. Every gkm write is a create
// (If-None-Match), an overwrite of a key that changes in place (If-Match) or a delete, since the store has no
// unconditional PUT, and a lost answer is resolved by reading the key back (§11.8's unknown row). Each refuses a ctx
// §11.13's write budget has not passed (budget.go), before anything is sent.
//
// Safe for concurrent use. No lock is held across I/O.

package gkmservice

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

var (
	// No repo/ object: a placed repo whose creation has not written it yet.
	errGkmRepoNotFound = errors.New("gkm: repo/ not found")
	// A stored object breaks its form, or a family holds more than gkm reads: a fault that alarms, never a state to
	// act on.
	errGkmStoreFault = errors.New("gkm: a stored object breaks its form")
	// A key that existed when a create found it, and is gone when read back: deleted whole, so nothing stands there.
	errGkmObjectGone = errors.New("gkm: an object existed and is gone")
)

// §11.8's bound on repo/'s bytes.
const gkmEvsRepoMaxByteCount = 4 * 1024

// The formats a repo may be in (§11.6).
const (
	gkmEvsRepoFormat1 = 1
	gkmEvsRepoFormat2 = 2
)

// repo/'s bytes held to their shape, as evs's codec holds them (evsservice.ParseEvsRepoObject): its bound, a 16-byte
// repo id equal to the key's, a kind acl.proto has, a state EvsRepoState has, format 1 or 2.
func parseGkmEvsRepoObject(repoId sidecar.Id, objectBytes []byte) (*protocol.EvsRepoObject, error) {
	if gkmEvsRepoMaxByteCount < len(objectBytes) {
		return nil, fmt.Errorf("%w: repo/ of %d bytes", errGkmStoreFault, len(objectBytes))
	}
	object := &protocol.EvsRepoObject{}
	if err := proto.Unmarshal(objectBytes, object); err != nil {
		return nil, fmt.Errorf("%w: repo/ does not parse", errGkmStoreFault)
	}
	if !bytes.Equal(object.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: repo/ holds another repo's id", errGkmStoreFault)
	}
	if _, ok := protocol.RepoKind_name[int32(object.GetKind())]; !ok || object.GetKind() == 0 {
		return nil, fmt.Errorf("%w: repo/ kind %d", errGkmStoreFault, object.GetKind())
	}
	if object.GetState() < protocol.EvsRepoState_EVS_REPO_KEYING || protocol.EvsRepoState_EVS_REPO_SHREDDED < object.GetState() {
		return nil, fmt.Errorf("%w: repo/ state %d", errGkmStoreFault, object.GetState())
	}
	if object.GetFormat() != gkmEvsRepoFormat1 && object.GetFormat() != gkmEvsRepoFormat2 {
		return nil, fmt.Errorf("%w: repo/ format %d", errGkmStoreFault, object.GetFormat())
	}
	return object, nil
}

// Reads key whole, at most maxByteCount bytes: sidecar.ErrBlobNotFound for none, and errGkmStoreFault for an object
// past the bound, which gkm never writes.
func readGkmObject(ctx context.Context, cluster sidecar.BlobCluster, key string, maxByteCount int64) ([]byte, *sidecar.BlobInfo, error) {
	object, err := cluster.Get(ctx, key)
	if err != nil {
		return nil, nil, err
	}
	defer object.Body.Close()
	objectBytes, err := io.ReadAll(io.LimitReader(object.Body, maxByteCount+1))
	if err != nil {
		return nil, nil, err
	}
	if maxByteCount < int64(len(objectBytes)) {
		return nil, nil, fmt.Errorf("%w: an object past %d bytes", errGkmStoreFault, maxByteCount)
	}
	return objectBytes, &object.BlobInfo, nil
}

// Every key under prefix, a page of pageCount at a time, at most maxCount of them: errGkmStoreFault past it, so a
// family that has grown past its bound alarms rather than costing unbounded work.
func listGkmKeys(ctx context.Context, cluster sidecar.BlobCluster, prefix string, pageCount int, maxCount int) ([]*sidecar.BlobInfo, error) {
	return listGkmKeysAfter(ctx, cluster, prefix, "", pageCount, maxCount)
}

// listGkmKeys from the first key past startAfter.
func listGkmKeysAfter(ctx context.Context, cluster sidecar.BlobCluster, prefix string, startAfter string, pageCount int, maxCount int) ([]*sidecar.BlobInfo, error) {
	infos := []*sidecar.BlobInfo{}
	for {
		page, more, err := cluster.List(ctx, prefix, startAfter, pageCount)
		if err != nil {
			return nil, err
		}
		infos = append(infos, page...)
		if maxCount < len(infos) {
			return nil, fmt.Errorf("%w: more than %d keys under a prefix", errGkmStoreFault, maxCount)
		}
		if !more || len(page) == 0 {
			return infos, nil
		}
		startAfter = page[len(page)-1].Key
	}
}

// How many times createGkmObject sends one create: once, and once more after a read shows an unknown outcome never
// landed (§11.8's write row). A protocol step and not a tunable.
const gkmCreateWriteCount = 2

// Creates key holding body, If-None-Match, and answers what stands there: winner nil when body does, whether this
// call or an earlier try of the same bytes wrote it, else the other bytes the key holds, which §10.6 answers as the
// winner (a 409's or 412's body). A lost answer is read back: by the settle rule a read then tells what happened
// (D-OPS-20), and a create that never landed goes once more. An outcome no read resolves comes back as the
// sidecar.BlobUnknownError, and the caller answers 503 so its client retries the same bytes.
func createGkmObject(ctx context.Context, cluster sidecar.BlobCluster, key string, body []byte, maxByteCount int64) (winner []byte, err error) {
	if err := checkGkmWriteClass(ctx); err != nil {
		return nil, err
	}
	readBack := func() (held []byte, found bool, err error) {
		held, _, err = readGkmObject(ctx, cluster, key, maxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		return held, true, nil
	}
	for writeCount := 1; ; writeCount += 1 {
		_, err := cluster.PutIfNoneMatch(ctx, key, body, nil)
		var unknown *sidecar.BlobUnknownError
		switch {
		case err == nil:
			return nil, nil
		case errors.Is(err, sidecar.ErrBlobPrecondition):
			held, found, readErr := readBack()
			if readErr != nil {
				return nil, readErr
			}
			if !found {
				return nil, errGkmObjectGone
			}
			if bytes.Equal(held, body) {
				return nil, nil
			}
			return held, nil
		case errors.As(err, &unknown):
			held, found, readErr := readBack()
			switch {
			case readErr != nil:
				return nil, err
			case found && bytes.Equal(held, body):
				return nil, nil
			case found:
				return held, nil
			case gkmCreateWriteCount <= writeCount:
				return nil, err
			}
			// it never landed, and by the settle rule it never will: send the same bytes again
		default:
			return nil, err
		}
	}
}

// Writes body at key, a key gkm changes in place (rk/, a last-resort KeyPackage's claim, group-info): If-Match on
// the etag a read found, or If-None-Match when the read found none. sidecar.ErrBlobPrecondition when another write
// moved the key between the read and this one, which the caller judges by reading again.
func replaceGkmObject(ctx context.Context, cluster sidecar.BlobCluster, key string, etag string, body []byte) error {
	if err := checkGkmWriteClass(ctx); err != nil {
		return err
	}
	if etag == "" {
		_, err := cluster.PutIfNoneMatch(ctx, key, body, nil)
		return err
	}
	_, err := cluster.PutIfMatch(ctx, key, etag, body, nil)
	return err
}

// Deletes key, once a write budget has passed ctx. A key already gone is no error.
func deleteGkmObject(ctx context.Context, cluster sidecar.BlobCluster, key string) error {
	if err := checkGkmWriteClass(ctx); err != nil {
		return err
	}
	return cluster.Delete(ctx, key)
}

// One repo/ answer: the object, or a 404, good until expiresAt.
type gkmRepoCacheEntry struct {
	object    *protocol.EvsRepoObject
	expiresAt time.Time
}

// repo/ as this process reads it, each answer good for RepoCacheTtl. See the file header.
type gkmRepoCache struct {
	clock    sidecar.Clock
	settings *GkmServiceSettings

	stateLock   sync.Mutex
	repoEntries map[sidecar.Id]*gkmRepoCacheEntry
}

// An empty cache on clock.
func newGkmRepoCache(clock sidecar.Clock, settings *GkmServiceSettings) *gkmRepoCache {
	return &gkmRepoCache{clock: clock, settings: settings, repoEntries: map[sidecar.Id]*gkmRepoCacheEntry{}}
}

// repo/ from this cache while its answer is under RepoCacheTtl old, else one GET on cluster: errGkmRepoNotFound for
// a 404, errGkmStoreFault for bytes that break its shape, which is not cached.
func (self *gkmRepoCache) read(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) (*protocol.EvsRepoObject, error) {
	var cached *gkmRepoCacheEntry
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.repoEntries[repoId]
		if !ok {
			return
		}
		if self.clock.Now().Before(entry.expiresAt) {
			cached = entry
			return
		}
		delete(self.repoEntries, repoId)
	}()
	if cached != nil {
		if cached.object == nil {
			return nil, errGkmRepoNotFound
		}
		return cached.object, nil
	}
	readAt := self.clock.Now()
	objectBytes, _, err := readGkmObject(ctx, cluster, GkmEvsRepoKey(repoId), gkmEvsRepoMaxByteCount)
	var object *protocol.EvsRepoObject
	switch {
	case errors.Is(err, sidecar.ErrBlobNotFound):
	case err != nil:
		return nil, err
	default:
		object, err = parseGkmEvsRepoObject(repoId, objectBytes)
		if err != nil {
			return nil, err
		}
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.settings.RepoCacheTtl <= 0 || self.settings.RepoCacheCount <= 0 {
			return
		}
		if self.settings.RepoCacheCount <= len(self.repoEntries) {
			for evictedRepoId := range self.repoEntries {
				delete(self.repoEntries, evictedRepoId)
				break
			}
		}
		self.repoEntries[repoId] = &gkmRepoCacheEntry{object: object, expiresAt: readAt.Add(self.settings.RepoCacheTtl)}
	}()
	if object == nil {
		return nil, errGkmRepoNotFound
	}
	return object, nil
}

// One GroupForm as gkm stored it: a Signed, purpose group-form, whose signer §10.6's form rule checked when it was
// filed (KEYS-M2-14).
type gkmForm struct {
	Seq    uint64
	Signed *bridge.Signed
	// The object's bytes as stored, which a creation's or re-form's retry repeats exactly.
	Raw     []byte
	Body    *protocol.GroupForm
	GroupId sidecar.Id
}

// A stored form's bytes, held to its shape: a Signed of type SIGNED_GROUP_FORM whose GroupForm names the repo its
// key does and a 16-byte group.
func parseGkmForm(repoId sidecar.Id, seq uint64, objectBytes []byte) (*gkmForm, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(objectBytes, signed); err != nil {
		return nil, fmt.Errorf("%w: a GroupForm that does not parse", errGkmStoreFault)
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_GROUP_FORM) {
		return nil, fmt.Errorf("%w: a GroupForm of type %d", errGkmStoreFault, signed.GetType())
	}
	body := &protocol.GroupForm{}
	if err := proto.Unmarshal(signed.GetBody(), body); err != nil {
		return nil, fmt.Errorf("%w: a GroupForm body that does not parse", errGkmStoreFault)
	}
	if !bytes.Equal(body.GetRepoId(), repoId.Bytes()) {
		return nil, fmt.Errorf("%w: a GroupForm of another repo", errGkmStoreFault)
	}
	groupId, err := sidecar.IdFromBytes(body.GetGroupId())
	if err != nil || groupId == (sidecar.Id{}) {
		return nil, fmt.Errorf("%w: a GroupForm's group of %d bytes", errGkmStoreFault, len(body.GetGroupId()))
	}
	return &gkmForm{Seq: seq, Signed: signed, Raw: objectBytes, Body: body, GroupId: groupId}, nil
}

// One repo's forms as a read found them, oldest first, good until expiresAt.
type gkmFormCacheEntry struct {
	forms     []*gkmForm
	expiresAt time.Time
}

// Each repo's GroupForms as this process reads them, and the group each form ties to its repo. See the file header.
type gkmFormCache struct {
	clock    sidecar.Clock
	settings *GkmServiceSettings

	stateLock    sync.Mutex
	repoEntries  map[sidecar.Id]*gkmFormCacheEntry
	groupRepoIds map[sidecar.Id]sidecar.Id
}

// An empty cache on clock.
func newGkmFormCache(clock sidecar.Clock, settings *GkmServiceSettings) *gkmFormCache {
	return &gkmFormCache{
		clock:        clock,
		settings:     settings,
		repoEntries:  map[sidecar.Id]*gkmFormCacheEntry{},
		groupRepoIds: map[sidecar.Id]sidecar.Id{},
	}
}

// A repo's forms, oldest first: from this cache while under FormCacheTtl old, else one LIST and a GET each on
// cluster. Each form's group is remembered as the repo's.
func (self *gkmFormCache) forms(ctx context.Context, cluster sidecar.BlobCluster, repoId sidecar.Id) ([]*gkmForm, error) {
	var cached []*gkmForm
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		entry, ok := self.repoEntries[repoId]
		if !ok {
			return
		}
		if self.clock.Now().Before(entry.expiresAt) {
			cached = entry.forms
			return
		}
		delete(self.repoEntries, repoId)
	}()
	if cached != nil {
		return cached, nil
	}
	readAt := self.clock.Now()
	prefix := GkmFormPrefix(repoId)
	infos, err := listGkmKeys(ctx, cluster, prefix, self.settings.ListPageCount, self.settings.FormMaxCount)
	if err != nil {
		return nil, err
	}
	forms := []*gkmForm{}
	for _, info := range infos {
		seq, ok := parseGkmKeyNumber(strings.TrimPrefix(info.Key, prefix))
		if !ok || seq == 0 {
			return nil, fmt.Errorf("%w: a GroupForm key out of form", errGkmStoreFault)
		}
		objectBytes, _, err := readGkmObject(ctx, cluster, info.Key, self.settings.ObjectMaxByteCount)
		if errors.Is(err, sidecar.ErrBlobNotFound) {
			// forms live for the repo's life (gkm-1), so only a shred removes one, and the repo goes with it
			continue
		}
		if err != nil {
			return nil, err
		}
		form, err := parseGkmForm(repoId, seq, objectBytes)
		if err != nil {
			return nil, err
		}
		forms = append(forms, form)
	}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, form := range forms {
			self.rememberGroupWithLock(form.GroupId, repoId)
		}
		if self.settings.FormCacheTtl <= 0 || self.settings.FormCacheCount <= 0 || len(forms) == 0 {
			// a repo with no form yet is asked again at once: KF1 files one moments after the repo's creation
			return
		}
		if self.settings.FormCacheCount <= len(self.repoEntries) {
			for evictedRepoId := range self.repoEntries {
				delete(self.repoEntries, evictedRepoId)
				break
			}
		}
		self.repoEntries[repoId] = &gkmFormCacheEntry{forms: forms, expiresAt: readAt.Add(self.settings.FormCacheTtl)}
	}()
	return forms, nil
}

// Keeps a group's repo, evicting another first when full: a group's repo never changes, so an evicted entry costs
// only its next resolution.
func (self *gkmFormCache) rememberGroupWithLock(groupId sidecar.Id, repoId sidecar.Id) {
	if self.settings.GroupRepoCacheCount <= 0 {
		return
	}
	if _, ok := self.groupRepoIds[groupId]; !ok && self.settings.GroupRepoCacheCount <= len(self.groupRepoIds) {
		for evictedGroupId := range self.groupRepoIds {
			delete(self.groupRepoIds, evictedGroupId)
			break
		}
	}
	self.groupRepoIds[groupId] = repoId
}

// The repo a form this process has read ties groupId to, if any.
func (self *gkmFormCache) groupRepo(groupId sidecar.Id) (sidecar.Id, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	repoId, ok := self.groupRepoIds[groupId]
	return repoId, ok
}

// Drops a repo's cached forms, so the next read lists them: what a handler that filed a form calls.
func (self *gkmFormCache) forget(repoId sidecar.Id) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.repoEntries, repoId)
}
